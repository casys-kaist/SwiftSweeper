#define _GNU_SOURCE
// FFMalloc - an experimental alternative memory allocator
// Unlike conventional allocators, maximizing space efficiency
// is not a design goal. Instead, FFMalloc makes exploiting
// use-after-free bugs in calling applications impossible
// because freed memory is never reused (only released back to
// the operating system when possible). FFMalloc depends on the
// extensive virtual address space available on 64-bit operating
// systems and is unsuitable for a 32-bit OS

/*** Compilation control ***/
// To include statistics collection in the library, define
// CONFIG_MEMORY_DEBUG. There is a small size and time cost to doing so
// #define CONFIG_MEMORY_DEBUG

// On x86_64 allocation alignment is usually 16-byte. However, this is only
// required to support certain SSE instructions. If those are not used then
// alignment can be 8-byte and therefore more efficient. Pointers don't seem
// to ever require 16-byte allignment and so 8-byte alignment will always be
// used for allocations of 8 bytes or less. This is backed up in practice by
// TCMalloc. To enable 8-byte alignment, define FF_EIGHTBYTEALIGN during
// library compilation
// #define FF_EIGHTBYTEALIGN

/*** Headers ***/
#include "ota.h"
#include "vmem.h"
#include "sbpf/bpf.h"
#include "syscall.h"
#include "gc.h"
#include "lib/list.h"
#include "kmalloc.h"
#include "spin_lock.h"

#ifndef CONFIG_MEMORY_DEBUG
#include "console.h"
#else
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sched.h>
#include <pthread.h>
#include <linux/bpf.h>
#include <signal.h>
#include <sys/mman.h>

/*** Library Globals ***/
static int isInit = 0;

// Number of pools currently allocated
// TODO: move this into future global profiling structure
static size_t poolCount = 0;

// The start of the global metadata allocation pool
static byte *metadataPool;

// The top of the metadata pool - i.e. the next unallocated block
static byte *metadataFree;

// The end of the currently available metadata address space
static byte *metadataEnd;

// Bin headers for the metadata pool
static byte *bins[256];
static byte *metadatabins[2];

// Lock that protects modifications to the pool radix tree
FFLOCKSTATIC(poolTreeLock)

// Locks that protect access to the metadata allocation bins
FFLOCKSTATIC(binLocks[256])
FFLOCKSTATIC(mdBinLocks[2])

// Lock that protects access to the metadata allocation pool
FFLOCKSTATIC(mdPoolLock)

FFLOCKSTATIC(poolAllocLock);

#ifdef CONFIG_MEMORY_DEBUG
// The interval (in calls to malloc) to print usage statistics
unsigned int usagePrintInterval;

// The file that interval usage statistics will be sent to
FILE *usagePrintFile;

// GC time check
struct timeval start, end;
#endif // CONFIG_MEMORY_DEBUG

#ifdef CONFIG_SECURITY_PKRU
int metadata_pkey;
atomic_int metadata_pkey_refcount = 0;
#endif

/*** Forward declarations ***/
static int create_pagepool(struct pagepool_t *newPool);
static int create_largepagepool(struct pagepool_t *newPool);
static void destroy_pool_list(struct poollistnode_t *node);
static void init_tcache(struct threadcache_t *tcache, struct arena_t *arena);
static void initialize();
static void init_threading();
static void *ffmetadata_alloc(size_t size);
static void ffmetadata_free(void *ptr, size_t size);
static void free_large_pointer(struct pagepool_t *pool, size_t index, size_t size);
void ffprint_stats_wrapper(void);
#ifdef CONFIG_MEMORY_DEBUG
static void print_current_usage();
#endif

static void cleanup_thread(void *ptr);

/*** OS compatibility functions ***/
static size_t os_alloc_total = 0;
static size_t os_alloc_count = 0;
static size_t os_free_count = 0;

/*static inline void* os_alloc(void* startAddress, size_t size) {
        int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
        if(startAddress != NULL) {
                flags |= MAP_FIXED_NOREPLACE | MAP_POPULATE;
        }
        return mmap(startAddress, size, PROT_READ | PROT_WRITE, flags, -1, 0);
}*/

static void *poolMaxWater = NULL;

static inline void *os_alloc_highwater(size_t size)
{
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE;
	void *result = NULL;
	void *localHigh = FFAtomicExchangeAdvancePtr(mm_get_active()->poolHighWater, size);

	if (localHigh >= poolMaxWater) {
		abort();
	}
	result = localHigh;

	return result;
}

static inline int os_decommit(void *startAddress, size_t size)
{
	// Surprisingly, benchmarking seems to suggest that unmapping is actually
	// faster than madvise. Revisit in the future
	void *flush_args[4] = { (void *)PTE_UNMAP, (void *)startAddress, (void *)((uint64_t)startAddress + size), mm_get_active() }; // flush args
	// flush_args returns 0 when successful and 1 when failed
	return sbpf_call_function(page_ops_bpf, &flush_args[0], sizeof(void *) * 4);
}

static inline int os_free(void *startAddress)
{
	// On Windows, this helper can only completely decommit and unreserve
	// an entire reservation, so no size parameter. Here, we'll look for
	// the pool getting the axe and figure out the size
	struct pagepool_t *pool = find_pool_for_ptr((const byte *)startAddress);
	if (pool != NULL) {
		void *flush_args[4] = { (void *)PTE_UNMAP, (void *)pool->start, (void *)pool->end, mm_get_active() };
		return sbpf_call_function(page_ops_bpf, &flush_args[0], sizeof(void *) * 4);
	} else {
		// Wasn't a pool - that shouldn't happen
		// Likely a bug if we get here
		abort();
	}

	errno = EINVAL;
	return -1;
}

/*** Dynamic metadata allocation ***/
// FFmalloc has several metadata structures that need to be dynamically allocated
// If we restricted usage to Windows or requiring use of the ff prefix on Linux
// then LocalAlloc or libc malloc respectively could be used. But, we'd like to
// allow non-prefixed usage via LD_PRELOAD on Linux (or static compilation so long
// as we're the first library). Therefore, we have a mini-allocator for metadata
// allocations. Because this should only be used internally, it does *not*
// implement the forward-only principal. Also note that the "free" equivalent
// requires a size parameter. This simplifies the amount of metadata for the
// metadata stored.
static void *ffpoolmetadata_alloc(int isSmallPool)
{
	byte *allocation;
	size_t size = isSmallPool ? (POOL_SIZE / PAGE_SIZE) * sizeof(struct pagemap_t) : (POOL_SIZE >> 20) * PAGE_SIZE;
	size = ALIGN_SIZE(size);

	FFEnterCriticalSection(&mdBinLocks[isSmallPool]);
	if (metadatabins[isSmallPool] == NULL) {
		FFEnterCriticalSection(&mdPoolLock);
		allocation = metadataFree;
		if (allocation + size > metadataEnd) {
			// Need to grow metadata pool space
			mprotect(metadataEnd, POOL_SIZE, PROT_READ | PROT_WRITE);
			madvise(metadataEnd, PAGE_SIZE * 16, MADV_WILLNEED);

			metadataEnd += POOL_SIZE;
#ifdef CONFIG_MEMORY_DEBUG
			FFAtomicAdd(arenas[0]->profile.currentOSBytesMapped, POOL_SIZE);
			if (arenas[0]->profile.currentOSBytesMapped > arenas[0]->profile.maxOSBytesMapped) {
				arenas[0]->profile.maxOSBytesMapped = arenas[0]->profile.currentOSBytesMapped;
			}
#endif
		}
		metadataFree += size;
		FFLeaveCriticalSection(&mdPoolLock);
	} else {
		allocation = metadatabins[isSmallPool];
		metadatabins[isSmallPool] = ((struct usedmd_t *)allocation)->next;
	}
	FFLeaveCriticalSection(&mdBinLocks[isSmallPool]);

	memset(allocation, 0, size);
	return allocation;
}

static void ffpoolmetadata_free(void *ptr, int isSmallPool)
{
	size_t size = isSmallPool ? (POOL_SIZE / PAGE_SIZE) * sizeof(struct pagemap_t) : (POOL_SIZE >> 20) * PAGE_SIZE;
	size = ALIGN_SIZE(size);

	if (ptr > (void *)metadataFree || ptr < (void *)metadataPool) {
		abort();
	}

	FFEnterCriticalSection(&mdBinLocks[isSmallPool]);

	// Put the freed block at the front of the list and have it point to
	// the former head of the line
	((struct usedmd_t *)ptr)->next = metadatabins[isSmallPool];
	metadatabins[isSmallPool] = (byte *)ptr;

	FFLeaveCriticalSection(&mdBinLocks[isSmallPool]);
}

static void *ffmetadata_alloc(size_t size)
{
	// Ensure 16 byte alignment
	size = ALIGN_TO(size, UINT64_C(16));

	// Making the assumption that the radix leaf nodes are the only metadata
	// structures that are bigger than a page. If that changes then we'll be
	// in a bit of a bind here. But for now, go with it
	size_t binID = size >= 4096 ? 255 : (size >> 4) - 1;

	byte *allocation;

	FFEnterCriticalSection(&binLocks[binID]);
	if (bins[binID] == NULL) {
		// No freed chunks of this size exist. Allocate space from the top
		// of the pool. Keeping things simple for now and not trying to
		// break a free 64-byte chunk into 4*16-byte chunks or whatever
		FFEnterCriticalSection(&mdPoolLock);
		allocation = metadataFree;
		if (allocation + size > metadataEnd) {
			// Need to grow metadata pool space
			mprotect(metadataEnd, POOL_SIZE, PROT_READ | PROT_WRITE);
			madvise(metadataEnd, PAGE_SIZE * 4, MADV_WILLNEED);

			metadataEnd += POOL_SIZE;
#ifdef CONFIG_MEMORY_DEBUG
			FFAtomicAdd(arenas[0]->profile.currentOSBytesMapped, POOL_SIZE);
			if (arenas[0]->profile.currentOSBytesMapped > arenas[0]->profile.maxOSBytesMapped) {
				arenas[0]->profile.maxOSBytesMapped = arenas[0]->profile.currentOSBytesMapped;
			}
#endif
		}
		metadataFree += size;
		FFLeaveCriticalSection(&mdPoolLock);
	} else {
		// Take the first available chunk from the front of the list
		// and the advance the header to the next chunk
		allocation = bins[binID];
		bins[binID] = ((struct usedmd_t *)allocation)->next;
	}

	FFLeaveCriticalSection(&binLocks[binID]);

	// Simplify logic elsewhere by guaranteeing zeroed blocks
	memset(allocation, 0, size);
	return allocation;
}

static void ffmetadata_free(void *ptr, size_t size)
{
	// Ensure 16 byte alignment to find right bin
	size = ALIGN_TO(size, UINT64_C(16));
	size_t binID = size >= 4096 ? 255 : (size >> 4) - 1;

	if (ptr > (void *)metadataFree || ptr < (void *)metadataPool) {
		abort();
	}

	FFEnterCriticalSection(&binLocks[binID]);

	// Put the freed block at the front of the list and have it point to
	// the former head of the line
	((struct usedmd_t *)ptr)->next = bins[binID];
	bins[binID] = (byte *)ptr;

	FFLeaveCriticalSection(&binLocks[binID]);
}

/*** Radix tree implementation ***/

// Gets the page pool that matches the page prefix. Returns NULL if no matching
// pool could be found
struct pagepool_t *find_pool_for_ptr(const byte *ptr)
{
	// Compute the index for each level
	size_t stemIndex = (uintptr_t)ptr >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leafIndex = ((uintptr_t)ptr >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);

	// Find the correct leaf node
	struct radixleaf_t *leaf = poolTree.stems[stemIndex] != NULL ? poolTree.stems[stemIndex]->leaves[leafIndex] : NULL;
	if (leaf != NULL) {
		// Check if there is a pool that starts or ends in this leaf
		// that could possibly contain the given pointer
		struct pagepool_t *pool = leaf->poolStart[((uintptr_t)ptr >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1)];
		if (pool != NULL && ptr >= pool->start) {
			return pool;
		}
		pool = leaf->poolEnd[((uintptr_t)ptr >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1)];
		if (pool != NULL && ptr < pool->end) {
			return pool;
		}
	}

	return NULL;
}

// Inserts a newly created page pool into the radix tree
void add_pool_to_tree(struct pagepool_t *pool)
{
	// Compute the level indexes for both the start and end addresses
	size_t startStemIndex = (uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t startLeafIndex = ((uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t startPoolIndex = ((uintptr_t)pool->start >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);
	size_t endStemIndex = (uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t endLeafIndex = ((uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t endPoolIndex = ((uintptr_t)pool->end >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);

	// Pool creation should be infrequent enough that trying to come up
	// with a fancy lock-free update structure probably isn't worth it
	FFEnterCriticalSection(&poolTreeLock);

	// Make sure that the nodes in the tree exist
	if (poolTree.stems[startStemIndex] == NULL) {
		poolTree.stems[startStemIndex] = (struct radixstem_t *)ffmetadata_alloc(sizeof(struct radixstem_t));
	}
	if (poolTree.stems[startStemIndex]->leaves[startLeafIndex] == NULL) {
		poolTree.stems[startStemIndex]->leaves[startLeafIndex] = (struct radixleaf_t *)ffmetadata_alloc(sizeof(struct radixleaf_t));
	}
	if (poolTree.stems[endStemIndex] == NULL) {
		poolTree.stems[endStemIndex] = (struct radixstem_t *)ffmetadata_alloc(sizeof(struct radixstem_t));
	}
	if (poolTree.stems[endStemIndex]->leaves[endLeafIndex] == NULL) {
		poolTree.stems[endStemIndex]->leaves[endLeafIndex] = (struct radixleaf_t *)ffmetadata_alloc(sizeof(struct radixleaf_t));
	}

	// Add the pool to the tree
	poolTree.stems[startStemIndex]->leaves[startLeafIndex]->poolStart[startPoolIndex] = pool;
	poolTree.stems[endStemIndex]->leaves[endLeafIndex]->poolEnd[endPoolIndex] = pool;

	poolCount++;
	FFLeaveCriticalSection(&poolTreeLock);
}

// Removes a page pool from the lookup tree
void remove_pool_from_tree(struct pagepool_t *pool)
{
	// Compute the level indexes for the start and end of the pool
	size_t startStemIndex = (uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t startLeafIndex = ((uintptr_t)pool->start >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t startPoolIndex = ((uintptr_t)pool->start >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);
	size_t endStemIndex = (uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t endLeafIndex = ((uintptr_t)pool->end >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);
	size_t endPoolIndex = ((uintptr_t)pool->end >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1);

	// Not checking path validity. Caller is responsible for calling only
	// if the pool has definitively been added the tree already
	FFEnterCriticalSection(&poolTreeLock);
	poolTree.stems[startStemIndex]->leaves[startLeafIndex]->poolStart[startPoolIndex] = NULL;
	poolTree.stems[endStemIndex]->leaves[endLeafIndex]->poolEnd[endPoolIndex] = NULL;

	poolCount--;
	FFLeaveCriticalSection(&poolTreeLock);
}

/*** Multi-threaded application support ***/
// Multi-threaded but OS neutral code
// TODO: this should be updated to be null-op for non-default arenas
void destroy_tcache(struct threadcache_t *tcache)
{
	if (tcache->nextUnusedPage != NULL && (tcache->nextUnusedPage < tcache->endUnusedPage)) {
		// While it would be better to return unused pages to the pool of origin, that's more
		// complicated than I want to handle right now. So, just give them back to the OS
		os_decommit(tcache->nextUnusedPage->start, (tcache->endUnusedPage - tcache->nextUnusedPage) * PAGE_SIZE);
	}
}
// End OS neutral multi-threaded

// Start Linux specific threading

// Key that retrieves the pointer to the per-thread cache
// pthread_key_t threadKey;

void ota_init()
{
	initialize();
}

// One time initialization of the per-thread local storage
static void init_threading()
{
	//	pthread_key_create(&threadKey, cleanup_thread);
}

// Thread exit cleanup
static void cleanup_thread(void *ptr)
{
	if (ptr != NULL) {
		destroy_tcache((struct threadcache_t *)ptr);
		ffmetadata_free(ptr, sizeof(struct threadcache_t));
	}
}

// Retrieves the specific cache for the currently running thread
struct threadcache_t *get_threadcache(struct arena_t *arena)
{
	struct threadcache_t *tcache = (struct threadcache_t *)pthread_getspecific(arena->tlsIndex);
	if (tcache == NULL) {
		// No thread cache found so create one
		tcache = (struct threadcache_t *)ffmetadata_alloc(sizeof(struct threadcache_t));
		init_tcache(tcache, arena);

		// Save the pointer in the thread local storage
		pthread_setspecific(arena->tlsIndex, tcache);
	}

	return tcache;
}

// Returns the index of the large list index to use based on the current CPU
unsigned int get_large_list_index()
{
	int cpuId = sched_getcpu();
	return cpuId < 0 ? 0 : (unsigned int)cpuId % MAX_LARGE_LISTS;
}

// End Linux specific threading

/*** Page allocation ***/

// Called when a thread cache is out of pages and needs to be assigned
// more from a pool. The active small pool for the arena is out of pages
// then a new small pool is created
static void assign_pages_to_tcache(struct threadcache_t *tcache)
{
	size_t nextFreePageMapIndex;
	byte *nextFreePage;

	// First, select which pool to assign pages from
	struct pagepool_t *pool = tcache->arena->smallPoolList->pool;

	// Advance the free page pointer atomically so that concurrent threads
	// get distinct ranges
	nextFreePage = (byte *)FFAtomicExchangeAdvancePtr(pool->nextFreePage, (PAGES_PER_REFILL * PAGE_SIZE));

	nextFreePageMapIndex = (nextFreePage - pool->start) / PAGE_SIZE;

	// Make sure that the range of pages selected from the pool are
	// actually within the pool. If not, then the pool is full and needs to
	// be retired and a new one created.
	// Counting on PAGES_PER_REFILL to evenly divide POOL_SIZE
	while (nextFreePage + (PAGES_PER_REFILL * PAGE_SIZE) > pool->end) {
		FFEnterCriticalSection(&tcache->arena->smallListLock);
		// Check that while waiting for the lock that the pool wasn't already
		// replaced. If it wasn't, then we can create the new pool
		if (pool == tcache->arena->smallPoolList->pool) {
			struct poollistnode_t *newListHeader = (struct poollistnode_t *)ffmetadata_alloc(sizeof(struct poollistnode_t));
			newListHeader->pool = (struct pagepool_t *)ffmetadata_alloc(sizeof(struct pagepool_t));
			newListHeader->pool->arena = tcache->arena;
			if (create_pagepool(newListHeader->pool) == -1) {
				ffmetadata_free(newListHeader->pool, sizeof(struct pagepool_t));
				ffmetadata_free(newListHeader, sizeof(struct poollistnode_t));
				// TODO: handle failure more gracefully
				abort();
			}
			add_pool_to_tree(newListHeader->pool);
			newListHeader->next = tcache->arena->smallPoolList;
			tcache->arena->smallPoolList = newListHeader;
		}
		pool = tcache->arena->smallPoolList->pool;
		FFLeaveCriticalSection(&tcache->arena->smallListLock);

		nextFreePage = (byte *)FFAtomicExchangeAdvancePtr(pool->nextFreePage, (PAGES_PER_REFILL * PAGE_SIZE));
		nextFreePageMapIndex = (nextFreePage - pool->start) / PAGE_SIZE;
	}

	// Create new page maps
	for (size_t i = 0; i < PAGES_PER_REFILL; i++) {
		pool->tracking.pageMaps[nextFreePageMapIndex + i].start = nextFreePage + (i * PAGE_SIZE);
	}

	// Assign the new page maps to the thread cache
	tcache->nextUnusedPage = pool->tracking.pageMaps + nextFreePageMapIndex;
	tcache->endUnusedPage = tcache->nextUnusedPage + PAGES_PER_REFILL;
}

/*** Initialization functions ***/

// Creates a new arena. Applications do not call this directly but rather
// through the public ffcreate_arena function
static ffresult_t create_arena(struct arena_t *newArena)
{
	if (newArena == NULL) {
		return FFBAD_PARAM;
	}

	// Each arena has a unique TLS index that allows the correct arena
	// specific thread cache to be retrieved. Each OS has a unique
	// initialization required before use
	if (!FFTlsAlloc(newArena->tlsIndex, TLS_CLEANUP_CALLBACK)) {
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFSYS_LIMIT;
	}

	// Create the small pool list header
	newArena->smallPoolList = (struct poollistnode_t *)ffmetadata_alloc(sizeof(struct poollistnode_t));
	if (newArena->smallPoolList == NULL) {
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFSYS_LIMIT;
	}

	// Create the first small pool and put it in the header node
	newArena->smallPoolList->pool = (struct pagepool_t *)ffmetadata_alloc(sizeof(struct pagepool_t));
	if (newArena->smallPoolList->pool == NULL) {
		ffmetadata_free(newArena->smallPoolList, sizeof(struct poollistnode_t));
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFSYS_LIMIT;
	}

	// Initialize the first small pool
	newArena->smallPoolList->pool->arena = newArena;
	if (create_pagepool(newArena->smallPoolList->pool) != 0) {
		ffmetadata_free(newArena->smallPoolList->pool, sizeof(struct pagepool_t));
		ffmetadata_free(newArena->smallPoolList, sizeof(struct poollistnode_t));
		ffmetadata_free(newArena, sizeof(struct arena_t));
		return FFNOMEM;
	}
	add_pool_to_tree(newArena->smallPoolList->pool);

	// Initialize the lock that protects the small list header
	FFInitializeCriticalSection(&newArena->smallListLock);

	// Create the large pool lists
	// TODO: limit to lesser of MAX_LARGE_LISTS and actual CPU count
	for (int i = 0; i < MAX_LARGE_LISTS; i++) {
		struct pagepool_t *pool = (struct pagepool_t *)ffmetadata_alloc(sizeof(struct pagepool_t));
		pool->arena = newArena;
		if (pool == NULL || create_largepagepool(pool) == -1) {
			destroy_pool_list(newArena->smallPoolList);
			// TODO: deconstruct any
			// successfully created large pools
			ffmetadata_free(newArena, sizeof(struct arena_t));
			return FFNOMEM;
		}
		add_pool_to_tree(pool);
		newArena->largePoolList[i] = (struct poollistnode_t *)ffmetadata_alloc(sizeof(struct poollistnode_t));
		newArena->largePoolList[i]->pool = pool;
	}

	return FFSUCCESS;
}

// Creates a new page pool by asking the OS for a block of memory
static int create_pagepool(struct pagepool_t *newPool)
{
	// Get an initial range of virtual address space to hold the page maps and bitmaps
	void *metadata = ffpoolmetadata_alloc(1);
	if (metadata == NULL) {
		fprintf(stderr, "create_pagepool metadata alloc failed: %d\n", errno);
		return -1;
	}

	// Get the virtual address space block for the pool itself
	void *poolReserve = os_alloc_highwater(POOL_SIZE);
	if (poolReserve == MAP_FAILED) {
		ffpoolmetadata_free(metadata, 1);
		return -1;
	}
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicAdd(newPool->arena->profile.currentOSBytesMapped, POOL_SIZE);
	if (newPool->arena->profile.currentOSBytesMapped > newPool->arena->profile.maxOSBytesMapped) {
		// TODO: need thread safety
		newPool->arena->profile.maxOSBytesMapped = newPool->arena->profile.currentOSBytesMapped;
	}
#endif
	newPool->tracking.pageMaps = (struct pagemap_t *)metadata;
	newPool->start = (byte *)poolReserve;
	newPool->nextFreePage = newPool->start;
	newPool->end = newPool->start + POOL_SIZE;
	newPool->startInUse = newPool->start;
	newPool->endInUse = newPool->end;

	// Since nextFreeIndex isn't used by a small pool, we'll set it to SIZE_MAX
	// as a flag to distinguish between the two types of pools in the find
	// pointer code
	newPool->nextFreeIndex = SIZE_MAX;

	FFInitializeCriticalSection(&newPool->poolLock);

	update_allocated_small_memory(POOL_SIZE);

	return 0;
}

// Creates a new large allocation pool
static int create_largepagepool(struct pagepool_t *newPool)
{
	// Reserve an address range for the metadata
	// Metadata should max out at about a page per 1MB of actual data:
	// (1MB / 2048 bytes/allocations) * (8 bytes/allocation) = 4096 bytes
	void *metadata = ffpoolmetadata_alloc(0);
	if (metadata == NULL) {
		return -1;
	}

	// Reserve an address range for the large pool itself
	void *storage = os_alloc_highwater(POOL_SIZE);
	if (storage == MAP_FAILED) {
		ffpoolmetadata_free(metadata, 0);
		return -1;
	}
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicAdd(newPool->arena->profile.currentOSBytesMapped, POOL_SIZE);
	while (newPool->arena->profile.currentOSBytesMapped > newPool->arena->profile.maxOSBytesMapped) {
		// TODO: need thread safety
		newPool->arena->profile.maxOSBytesMapped = newPool->arena->profile.currentOSBytesMapped;
	}
#endif

	// Add the metadata to the pool
	newPool->tracking.allocations = (uintptr_t *)metadata;

	// Add the storage to the pool
	newPool->start = (byte *)storage;
	newPool->end = (byte *)storage + POOL_SIZE;
	newPool->nextFreePage = (byte *)storage;
	newPool->startInUse = newPool->start;
	newPool->endInUse = newPool->end;

	// There is always one more metadata entry than allocations so that size can
	// be computed by subtracting the pointers. Record the first dummy entry now
	newPool->tracking.allocations[0] = (uintptr_t)storage;

	FFInitializeCriticalSection(&newPool->poolLock);

	update_allocated_large_memory(POOL_SIZE);

	return 0;
}

// Helper function to initialize a new jumbo page
static inline int create_jumbopool(struct pagepool_t *newPool, size_t size)
{
	// The only metadata required for a jumbo pool is just the size since
	// there will only ever just be the one allocation. Therefore don't
	// allocate a metadata block. Mark it NULL here just to make the point
	newPool->tracking.allocations = NULL;

	// Just like the small pool we'll recycle the nextFreeIndex field as
	// a flag that this isn't a normal pool
	newPool->nextFreeIndex = SIZE_MAX - 1;

	// Since this allocation is coming straight from the OS it needs to be
	// page aligned
	size = ALIGN_TO(size, PAGE_SIZE);

	// Ask the OS for memory
	void *storage;
	storage = os_alloc_highwater(size);
	if (storage == MAP_FAILED) {
		return -1;
	}

#ifdef CONFIG_MEMORY_DEBUG
	// Update statistics
	FFAtomicAdd(newPool->arena->profile.totalBytesAllocated, size);
	FFAtomicAdd(newPool->arena->profile.jumbo.BytesAllocated, size);
	FFAtomicAdd(newPool->arena->profile.currentBytesAllocated, size);
	FFAtomicAdd(newPool->arena->profile.currentOSBytesMapped, size);
	if (newPool->arena->profile.currentBytesAllocated > newPool->arena->profile.maxBytesAllocated) {
		// TODO: thread safety
		newPool->arena->profile.maxBytesAllocated = newPool->arena->profile.currentBytesAllocated;
	}
	if (newPool->arena->profile.currentOSBytesMapped > newPool->arena->profile.maxOSBytesMapped) {
		// TODO: need thread safety
		newPool->arena->profile.maxOSBytesMapped = newPool->arena->profile.currentOSBytesMapped;
	}
#endif

	// Record the size of this oddball
	newPool->start = (byte *)storage;
	newPool->end = (byte *)storage + size;

	update_allocated_large_memory(newPool->end - newPool->start);

	// Return success
	return 0;
}

// Initializes a new thread cache by constructing the bins
static void init_tcache(struct threadcache_t *tcache, struct arena_t *arena)
{
	// Initialize all of the bin headers
	// First, the very small bins that are consecutive multiples of 8
	// 8, 16, 24, 32, ... 192, 200, 208
	// Or consecutive multiples of 16 after 16 when using 16 byte alignment
	// 8, 16, 32, 48, ... 272, 288, 304
	for (size_t b = 1; b <= (BIN_COUNT - BIN_INFLECTION); b++) {
		tcache->bins[BIN_COUNT - b].allocSize = b * MIN_ALIGNMENT;
		tcache->bins[BIN_COUNT - b].maxAlloc = PAGE_SIZE / (b * MIN_ALIGNMENT);

		// Set allocCount equal to maxAlloc and not 0 even though its
		// empty so that the first allocation from bin will actually trigger
		// allocating a page instead of pre-emptively doing that now and
		// wasting it on a bin that might not get used
		tcache->bins[BIN_COUNT - b].allocCount = tcache->bins[BIN_COUNT - b].maxAlloc;
		tcache->bins[BIN_COUNT - b].page = NULL;
#ifdef CONFIG_MEMORY_DEBUG
		tcache->bins[BIN_COUNT - b].totalAllocCount = 0;
#endif
	}

	// Next, the bins that are consecutive in max allocation per page
	// 336, 368, 400, ... 816, 1024, 1360, 2048, 4096+ when 16-byte aligned
	// Note that additional bins in between wouldn't be any more space
	// efficient. For example, you can get 3 * 1360 per page and 2 * 2048
	// but also only 2 * 1536 so having a bin for that size is no more
	// efficient than just dumping it into the 2048 bin
	for (size_t b = 1; b < BIN_INFLECTION; b++) {
		// Bin sizes need to be rounded down to correct alignment
		tcache->bins[b].allocSize = ((PAGE_SIZE / b) & ~(MIN_ALIGNMENT - 1));
		tcache->bins[b].maxAlloc = b;
		tcache->bins[b].allocCount = b;
		tcache->bins[b].page = NULL;
#ifdef CONFIG_MEMORY_DEBUG
		tcache->bins[b].totalAllocCount = 0;
#endif
	}

#ifndef FF_EIGHTBYTEALIGN
	// The bin for 8 byte allocations doesn't fit the pattern when doing
	// 16-byte alignment
	tcache->bins[0].allocSize = 8;
	tcache->bins[0].maxAlloc = PAGE_SIZE / 8;
	tcache->bins[0].allocCount = PAGE_SIZE / 8;
	tcache->bins[0].page = NULL;
#ifdef CONFIG_MEMORY_DEBUG
	tcache->bins[0].totalAllocCount = 0;
#endif
#endif

	// Remember which arena this cache is connected to
	tcache->arena = arena;

	// Get some pages for this new cache to use
	assign_pages_to_tcache(tcache);
}

// Performs one-time setup of metadata structures
static void initialize()
{
	isInit = 2;

	// Set up lock that protects modifications to the pool radix tree
	FFInitializeCriticalSection(&poolTreeLock);

	FFInitializeCriticalSection(&poolAllocLock);

	// Initialize metadata pool locks
	FFInitializeCriticalSection(&mdPoolLock);
	for (int i = 0; i < 256; i++) {
		FFInitializeCriticalSection(&binLocks[i]);
	}
	FFInitializeCriticalSection(&mdBinLocks[0]);
	FFInitializeCriticalSection(&mdBinLocks[1]);

	// Find the top of the heap on Linux then add 1GB so that there is
	// no contention with small mallocs from libc when used side-by-side
	mm_get_active()->poolHighWater = (byte *)sbrk(0) + 0x40000000;
	mm_get_active()->poolLowWater = mm_get_active()->poolHighWater;

	void *ret = mmap(mm_get_active()->poolHighWater, FFMMAP_LENGTH, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | 0x400000, -1, 0);
	poolMaxWater = ret + FFMMAP_LENGTH;

	// Create a large contiguous range of virtual address space but don't
	// actually map the addresses to pages just yet
#ifdef CONFIG_BPF_ARENA
	void *arena_args[3] = { (void *)PTE_MAP_ARENA, (void *)(1024UL * 1048576UL), (void *)&metadataPool }; // arena args
	// flush_args returns 0 when successful and 1 when failed
	if (sbpf_call_function(page_ops_bpf, &arena_args[0], sizeof(void *) * 3)) {
		fprintf(stderr, "cannot get arena memory!\n");
		abort();
	}
#else
	metadataPool = (byte *)mmap(NULL, 1024UL * 1048576UL, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	mprotect(metadataPool, POOL_SIZE, PROT_READ | PROT_WRITE);
#endif

	metadataFree = metadataPool;
	metadataEnd = metadataPool + POOL_SIZE;

	// Create the default arena used to handle standard malloc API calls
	// arenas[0] = (struct arena_t*)ffmetadata_alloc(sizeof(struct arena_t));
	// Manually allocate initial arena to prevent segfault since ffmetadata_alloc
	// relies on arenas[0] to be initialized when profiling is enabled
	arenas[0] = (struct arena_t *)metadataPool;
	metadataFree += ALIGN_TO(sizeof(struct arena_t), UINT64_C(16));
#ifdef CONFIG_MEMORY_DEBUG
	arenas[0]->profile.currentOSBytesMapped = POOL_SIZE;
#endif
	if (create_arena(arenas[0]) != FFSUCCESS) {
		// Bad news, not much to do except quit
		abort();
	}

	// Initialize OS threading support
	init_threading();

#ifdef CONFIG_MEMORY_DEBUG
	atexit(ffprint_stats_wrapper);
#ifdef FF_INSTRUMENTED
	ffprint_usage_on_interval(stderr, FF_INTERVAL);
#endif
#endif

	for (int i = 0; i < BIN_COUNT; i++) {
		arenas[0]->gc_lock[i] = kmalloc(sizeof(spinlock_t));
		spin_lock_init(arenas[0]->gc_lock[i]);
		arenas[0]->gc_start_free_pointers[i] = NULL;
	}

	isInit = 1;

#ifdef CONFIG_SECURITY_PKRU
	metadata_pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
	int status = pkey_mprotect(metadataPool, POOL_SIZE, PROT_READ | PROT_WRITE, metadata_pkey);
	if (status) {
		fprintf(stderr, "pkey_mprotect failed: %d\n", status);
		abort();
	}
#endif
}

#ifdef CONFIG_BPF_ARENA
void free_arena_map(void)
{
	void *arena_args[2] = { (void *)PTE_UNMAP_ARENA, (void *)&metadataPool }; // arena args
	if (sbpf_call_function(page_ops_bpf, &arena_args[0], sizeof(void *) * 2)) {
		fprintf(stderr, "BPF error at free arena\n");
		abort();
	}
}
#endif

// Destroys a page pool returning all memory to the OS
static void destroy_pool(struct pagepool_t *pool)
{
	// Return the metadata depending on the pool type
	if (pool->nextFreeIndex == SIZE_MAX) {
		// Small pool
		// Free bitmaps back to the internal allocator. That requires
		// checking every page map for bitmaps
		update_allocated_small_memory(-(pool->end - pool->start));
		if (os_free(pool->start) != 0)
			abort();

		byte *lastPage = pool->nextFreePage < pool->end ? pool->nextFreePage : pool->end;
		for (size_t i = 0; i < (lastPage - pool->start) / PAGE_SIZE; i++) {
			size_t allocSize = pool->tracking.pageMaps[i].allocSize & ~SEVEN64;
			if (allocSize > 0 && allocSize < 64) {
				size_t bitmapCount =
					((PAGE_SIZE / allocSize) & SIXTYTHREE64) != 0 ? ((PAGE_SIZE / allocSize) >> 6) + 1 : ((PAGE_SIZE / allocSize) >> 6);
				ffmetadata_free(pool->tracking.pageMaps[i].bitmap.array, bitmapCount * 8);
#ifdef CONFIG_ENABLE_GC
				ffmetadata_free(pool->tracking.pageMaps[i].markmap.array, bitmapCount * 8);
#endif
			}
		}
		// Now free all of the page maps
		ffpoolmetadata_free(pool->tracking.pageMaps, 1);
	} else if (pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo pool
		// Nothing else to do here since a jumbo pool has no additional
		// metadata to clean up
		update_allocated_large_memory(-(pool->end - pool->start));
		if (os_free(pool->start) != 0)
			abort();
	} else {
		// Large pool
		update_allocated_large_memory(-(pool->end - pool->start));
		if (os_free(pool->start) != 0)
			abort();
		ffpoolmetadata_free(pool->tracking.allocations, 0);
	}

	remove_pool_from_tree(pool);
	FFDeleteCriticalSection(&pool->poolLock);
}

// Destroys each pool in a pool list as well as the list itself
static void destroy_pool_list(struct poollistnode_t *node)
{
	struct poollistnode_t *lastNode;

	while (node != NULL) {
		destroy_pool(node->pool);
		lastNode = node;
		node = node->next;
		ffmetadata_free(lastNode, sizeof(struct poollistnode_t));
	}
}

// Destroys an arena by freeing all pools and associated metadata
static void destroy_arena(struct arena_t *arena)
{
	destroy_pool_list(arena->smallPoolList);
	destroy_pool_list(arena->jumboPoolList);
	for (int i = 0; i < MAX_LARGE_LISTS; i++) {
		if (arena->largePoolList[i] != NULL) {
			destroy_pool_list(arena->largePoolList[i]);
		}
		FFDeleteCriticalSection(&arena->largeListLock[i]);
	}

	// TODO: When a thread ends before the arena is destroyed, the
	// appropriate OS specific handler will clean up its thread cache
	// Here, we need to find a way to delete any thread caches for
	// threads that haven't yet exited (but hopefully know not to
	// allocate from this arena anymore)

	FFTlsFree(arena->tlsIndex);

	FFDeleteCriticalSection(&arena->smallListLock);

	ffmetadata_free(arena, sizeof(struct arena_t));
}

/*** Search functions ***/

// Helper function to find the page within a pool that a small pointer was
// allocated from. On success, the function will return the index within the
// page where the pointer is located and pagemap will point to the pointer to
// the pagemap. The return value will be less than 0 on failure
int64_t find_small_ptr_allocated(const byte *ptr, const struct pagepool_t *pool, struct pagemap_t **pageMap)
{
	// Find the location in the metadata where the page for this pointer is tracked
	size_t mapIndex = (ptr - pool->start) / PAGE_SIZE;
	struct pagemap_t *page = pool->tracking.pageMaps + mapIndex;
	*pageMap = page;

	if (page->allocSize == 0)
		return -3;

	// Found the page. Find the allocation's place in the bitmap
	uint64_t index = (ptr - page->start) / (page->allocSize & ~SEVEN64);

	// Validate that this is a potentially valid address - i.e. not an
	// address in the middle of an allocation. Trusting compiler optimizations
	// to not issue two divisions to keep things quick
	if ((ptr - page->start) % (page->allocSize & ~SEVEN64) != 0) {
		return -2;
	}

	// Is the pointer actually allocated?
	if (page->allocSize < 64) {
		uint64_t array = index >> 6;
		uint64_t pos = index - (array << 6);
		if (!(page->bitmap.array[array] & (ONE64 << pos))) {
			return -1;
		}
	} else {
		if (!(page->bitmap.single & (ONE64 << index))) {
			return -1;
		}
	}

	return index;
}

// Given an index within a page, and if unallocated, return the index.
int64_t find_small_ptr_unallocated(const byte *ptr, const struct pagepool_t *pool, struct pagemap_t **pageMap)
{
	// Find the location in the metadata where the page for this pointer is tracked
	size_t mapIndex = (ptr - pool->start) / PAGE_SIZE;
	struct pagemap_t *page = pool->tracking.pageMaps + mapIndex;
	*pageMap = page;

	if (page->allocSize == 0)
		return -3;

	// Found the page. Find the allocation's place in the bitmap
	uint64_t index = (ptr - page->start) / (page->allocSize & ~SEVEN64);

	// Validate that this is a potentially valid address - i.e. not an
	// address in the middle of an allocation. Trusting compiler optimizations
	// to not issue two divisions to keep things quick
	if ((ptr - page->start) % (page->allocSize & ~SEVEN64) != 0) {
		return -2;
	}

	// Is the pointer actually allocated?
	if (page->allocSize < 64) {
		uint64_t array = index >> 6;
		uint64_t pos = index - (array << 6);
		if (!(page->bitmap.array[array] & (ONE64 << pos))) {
			return index;
		}
	} else {
		if (!(page->bitmap.single & (ONE64 << index))) {
			return index;
		}
	}

	return -1;
}

int64_t find_small_ptr_index(const byte *ptr, const struct pagepool_t *pool, struct pagemap_t **pageMap, bool *allocated)
{
	// Find the location in the metadata where the page for this pointer is tracked
	size_t mapIndex = (ptr - pool->start) / PAGE_SIZE;
	struct pagemap_t *page = pool->tracking.pageMaps + mapIndex;
	*pageMap = page;

	if (page->allocSize == 0)
		return -3;

	// Found the page. Find the allocation's place in the bitmap
	uint64_t index = (ptr - page->start) / (page->allocSize & ~SEVEN64);

	// Validate that this is a potentially valid address - i.e. not an
	// address in the middle of an allocation. Trusting compiler optimizations
	// to not issue two divisions to keep things quick
	if ((ptr - page->start) % (page->allocSize & ~SEVEN64) != 0) {
		return -2;
	}

	// Is the pointer actually allocated?
	if (page->allocSize < 64) {
		uint64_t array = index >> 6;
		uint64_t pos = index - (array << 6);
		if (!(page->bitmap.array[array] & (ONE64 << pos))) {
			*allocated = false;
			return index;
		}
	} else {
		if (!(page->bitmap.single & (ONE64 << index))) {
			*allocated = false;
			return index;
		}
	}

	*allocated = true;
	return index;
}

// Helper function to find the location within a large allocation pool of a
// specific allocation. Returns the size of the allocation on success or 0 if
// the allocation is not found. Also, if the allocation is found then the
// index of the allocation in the metadata array is copied to the location
// pointed to by metadataIndex
size_t find_large_ptr(const byte *ptr, struct pagepool_t *pool, size_t *metadataIndex)
{
	size_t left = 0;
	size_t right = pool->nextFreeIndex;
	size_t current = (right - left) / 2;

	// The metadata array is guaranteed to be sorted, so we can treat it like
	// a binary search tree.
	while (left != right) {
		// Remove GC mark
		uintptr_t current_ptr = pool->tracking.allocations[current];
		current_ptr = current_ptr & ~EIGHT64;
		if (current_ptr == (uintptr_t)ptr) {
			if (current == pool->nextFreeIndex) {
				// The final entry in the metadata is not an actual allocation
				return 0;
			}
			// Found the pointer
			*metadataIndex = current;
			return ((pool->tracking.allocations[current + 1] & ~FIFTEEN64) - current_ptr);
		} else if ((uintptr_t)ptr < current_ptr) {
			// Search left
			right = current;
		} else {
			// Search right
			left = current + 1;
		}
		current = left + ((right - left) / 2);
	}

	// The allocation was not found
	return 0;
}

int find_large_ptr_unallocated(const byte *ptr, struct pagepool_t *pool)
{
	size_t left = 0;
	size_t right = pool->nextFreeIndex;
	size_t current = (right - left) / 2;

	// The metadata array is guaranteed to be sorted, so we can treat it like
	// a binary search tree.
	while (left != right) {
		// Remove GC mark
		uintptr_t current_ptr = pool->tracking.allocations[current] & ~EIGHT64;
		if (current_ptr == (uintptr_t)ptr) {
			if (current == pool->nextFreeIndex) {
				// The final entry in the metadata is not an actual allocation
				return -2;
			}
			// Found the pointer
			return -1;
		} else if ((current_ptr & ~SEVEN64) == (uintptr_t)ptr) {
			if (current == pool->nextFreeIndex) {
				// The final entry in the metadata is not an actual allocation
				return -2;
			}
			// Found the pointer, but freed
			return (int)current;
		} else if ((uintptr_t)ptr < current_ptr) {
			// Search left
			right = current;
		} else {
			// Search right
			left = current + 1;
		}
		current = left + ((right - left) / 2);
	}

	// The allocation was not found
	return -1;
}

/*** Malloc helper functions ***/

// Actual implementation of malloc for small sizes
static void *ffmalloc_small(size_t size, struct arena_t *arena)
{
	struct bin_t *bin;

	// Get the correct thread cache. By allocating
	// from a per-thread cache, we don't have to
	// acquire and release locks
	struct threadcache_t *tcache = get_threadcache(arena);

	// Select the correct bin based on size and alignment
	bin = &tcache->bins[GET_BIN(size)];

#ifdef CONFIG_MEMORY_DEBUG
	bin->totalAllocCount++;
#endif

	// If the bin is full or first allocation then get a new page
	if (bin->allocCount == bin->maxAlloc) {
		// Do we have any pages left in the local free page cache?
		if (tcache->nextUnusedPage >= tcache->endUnusedPage) {
			// Local cache is empty. Need to go refresh from a page pool
			assign_pages_to_tcache(tcache);
		}

		// Connect the bin to the page map
		bin->page = tcache->nextUnusedPage;

		// Remove the page map from the local free cache
		tcache->nextUnusedPage++;

		// Update the size record on the page map
		bin->page->allocSize = bin->allocSize;

		// Reset the allocation pointers for the bin
		bin->allocCount = 0;
		bin->nextAlloc = bin->page->start;

		// If the bin holds more than 64 allocations, then point
		// the page map to a new bitmap array
		if (bin->maxAlloc > 64) {
			size_t bitmapCount = (bin->maxAlloc & SIXTYTHREE64) ? (bin->maxAlloc >> 6) + 1 : (bin->maxAlloc >> 6);
			bin->page->bitmap.array = (uint64_t *)ffmetadata_alloc(bitmapCount * 8);
#ifdef CONFIG_ENABLE_GC
			bin->page->markmap.array = (uint64_t *)ffmetadata_alloc(bitmapCount * 8);
			memset(bin->page->markmap.array, 0xff, bitmapCount * 8);
		} else {
			bin->page->markmap.single = -1;
		}
#else
		}
#endif
	}

	// Mark the next allocation on the page as in use on the bitmap.
	// Must use atomic operations to mark the bitmap because even though this is
	// the only cache that can allocate from here, any thread could be freeing a
	// previous allocation
	if (bin->maxAlloc <= 64) {
		FFAtomicOr(bin->page->bitmap.single, (ONE64 << bin->allocCount));
	} else {
		FFAtomicOr(bin->page->bitmap.array[bin->allocCount >> 6], (ONE64 << (bin->allocCount & SIXTYTHREE64)));
	}

	// Save pointer to allocation. Advance bin to next allocation
	byte *thisAlloc = bin->nextAlloc;
	bin->nextAlloc += bin->allocSize;
	bin->allocCount++;

	// Mark the page as full if so
	if (bin->allocCount == bin->maxAlloc) {
		bin->page->allocSize |= 4UL;
	}

#ifdef CONFIG_MEMORY_DEBUG
	// Final statistics update
	FFAtomicAdd(arena->profile.totalBytesAllocated, bin->allocSize);
	FFAtomicAdd(arena->profile.currentBytesAllocated, bin->allocSize);
	FFAtomicAdd(arena->profile.small.BytesAllocated, bin->allocSize);
	// TODO: thread safe update
	if (arena->profile.currentBytesAllocated > arena->profile.maxBytesAllocated)
		arena->profile.maxBytesAllocated = arena->profile.currentBytesAllocated;
#endif

	update_used_small_memory(bin->allocSize);

	// Return successfully allocated buffer
	return thisAlloc;
}

// Helper to actually implement a large allocation from a specific pool
// Note: caller is responsible for acquiring/releasing pool lock if needed
// before calling this function
static inline void *ffmalloc_large_from_pool(size_t size, size_t alignment, struct pagepool_t *pool)
{
	uintptr_t alignedNext = ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);

	// Record the metadata
	// For a standard 8 or 16 byte allignment we just record the address of
	// the next allocation to the end of the list. This allocation was already
	// recorded on the previous call. The reason is that size is stored
	// implicitly as the difference between consecutive pointers therefore,
	// for N allocations we need N+1 pointers in the metadata.
	// When the alignment is greater than 8/16, the returned pointer could
	// be greater than what was recorded last time so we also have to
	// update that pointer - effectively growing the previous allocation.
	// The alternative would be to create and immediately mark free the
	// little spacer allocation in between but there isn't any obvious
	// benefit to doing so
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicAdd(pool->arena->profile.totalBytesAllocated, size + ((byte *)alignedNext - pool->nextFreePage));
	FFAtomicAdd(pool->arena->profile.currentBytesAllocated, size + ((byte *)alignedNext - pool->nextFreePage));
	FFAtomicAdd(pool->arena->profile.large.BytesAllocated, size + ((byte *)alignedNext - pool->nextFreePage));
	if (pool->arena->profile.currentBytesAllocated > pool->arena->profile.maxBytesAllocated) {
		// TODO: need thread safe update here
		pool->arena->profile.maxBytesAllocated = pool->arena->profile.currentBytesAllocated;
	}
#endif

	pool->nextFreePage = ((byte *)alignedNext + size);
	if (alignment > MIN_ALIGNMENT) {
		pool->tracking.allocations[pool->nextFreeIndex] = alignedNext;
	}
	pool->tracking.allocations[++pool->nextFreeIndex] = (uintptr_t)pool->nextFreePage;

	// If there is less than the minimum large size allocation left, then
	// change the last metadata entry so that this allocation gets the remaining
	// space
	if (pool->end - pool->nextFreePage < (ptrdiff_t)(HALF_PAGE + MIN_ALIGNMENT)) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(pool->arena->profile.currentBytesAllocated, pool->end - pool->nextFreePage);
		FFAtomicAdd(pool->arena->profile.totalBytesAllocated, pool->end - pool->nextFreePage);
		FFAtomicAdd(pool->arena->profile.large.BytesAllocated, pool->end - pool->nextFreePage);
#endif

		pool->tracking.allocations[pool->nextFreeIndex] = (uintptr_t)pool->end;
		pool->nextFreePage = pool->end;
	}

	update_used_large_memory(pool->tracking.allocations[pool->nextFreeIndex] - (uintptr_t)alignedNext);

	// Return the allocation
	return (void *)alignedNext;
}

// Release any remaining unallocated space in the pool when the pool is being
// removed from the active allocation list. The pool may be destroyed if all
// allocations have also already been freed
static inline void trim_large_pool(struct pagepool_t *pool)
{
	if (pool->tracking.allocations[pool->nextFreeIndex] < (uintptr_t)pool->end) {
		size_t remainingSize = (uintptr_t)pool->end - pool->tracking.allocations[pool->nextFreeIndex];
#ifdef CONFIG_MEMORY_DEBUG
		// Must update counter here because it will be decremented
		// inside call to free
		FFAtomicAdd(pool->arena->profile.currentBytesAllocated, remainingSize);
#endif
		// Mark the balance of free space as a single allocation
		pool->nextFreeIndex++;
		pool->tracking.allocations[pool->nextFreeIndex] = (uintptr_t)pool->end;
		pool->nextFreePage = pool->end;

		// Release the slack space
		free_large_pointer(pool, pool->nextFreeIndex - 1, remainingSize);
	}

	// Mark the pool as no longer being allocated from
	pool->tracking.allocations[pool->nextFreeIndex] |= FOUR64;

	// Destroy the pool if completely released
	if (pool->startInUse >= pool->endInUse) {
		destroy_pool(pool);
	}
}

// Finds a suitable large pool to allocate from, or creates a new pool
// if neccessary
static void *ffmalloc_large(size_t size, size_t alignment, struct arena_t *arena)
{
	struct poollistnode_t *node;
	struct poollistnode_t *tailNode;
	struct pagepool_t *pool = NULL;
	byte *alignedNext;
	unsigned int loopCount = 0;
	const unsigned int listId = get_large_list_index();

	node = arena->largePoolList[listId];
	tailNode = node;

	// Loop through the large pools assigned to this processor looking for one
	// that has space. There may be pools on other CPUs that would be a better
	// fit but we don't check those
	while (node != NULL) {
		pool = node->pool;
		alignedNext = (byte *)ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);
		if (alignedNext + size > pool->end) {
			// No space in this pool, advance to the next one
			tailNode = node;
			node = node->next;
			loopCount++;
		} else {
			// Space available allocate from here if possible
			FFEnterCriticalSection(&pool->poolLock);
			void *allocation;

			// Since we don't lock before checking the size (to avoid a lock pileup)
			// we have to check the size again here inside the lock to make sure that
			// there is still space available
			alignedNext = (byte *)ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);
			if (alignedNext + size <= pool->end) {
				allocation = ffmalloc_large_from_pool(size, alignment, pool);
				FFLeaveCriticalSection(&pool->poolLock);
				return allocation;
			} else {
				// Lost the race, try the next bin
				node = node->next;
			}
			FFLeaveCriticalSection(&pool->poolLock);
		}
	}

	// None of the current pools on this CPU have space
	FFEnterCriticalSection(&arena->largeListLock[listId]);

	// While waiting for the lock, was a new pool created?
	if (tailNode->next != NULL) {
		pool = tailNode->next->pool;
		FFEnterCriticalSection(&pool->poolLock);
		alignedNext = (byte *)ALIGN_TO((uintptr_t)pool->nextFreePage, alignment);

		// Does the new pool have enough space to service this request? If so,
		// allocate and be done
		if (alignedNext + size <= pool->end) {
			void *allocation = ffmalloc_large_from_pool(size, alignment, pool);
			FFLeaveCriticalSection(&pool->poolLock);
			FFLeaveCriticalSection(&arena->largeListLock[listId]);
			return allocation;
		}
		FFLeaveCriticalSection(&pool->poolLock);

		while (tailNode->next != NULL) {
			tailNode = tailNode->next;
		}
	}

	// If we get here, either we entered the lock straight away or another pool
	// was created while waiting for the lock, but we must have been in the back
	// of the line because its already too small. Either way, create a new large
	// allocation pool
	pool = (struct pagepool_t *)ffmetadata_alloc(sizeof(struct pagepool_t));
	if (pool == NULL) {
		fprintf(stderr, "Out of metadata space creating large pool\n");
		FFLeaveCriticalSection(&arena->largeListLock[listId]);
		return NULL;
	}
	pool->arena = arena;
	if (create_largepagepool(pool) == -1) {
		// Maybe there is a way to recover here, but for the moment
		// the caller is just all out of luck
		ffmetadata_free(pool, sizeof(struct pagepool_t));
		FFLeaveCriticalSection(&arena->largeListLock[listId]);
		return NULL;
	}

	// Pool creation successful so add it to the tree for later pointer lookup
	add_pool_to_tree(pool);

	// Finally allocate the block requested
	// No need for locks here because nobody else can see this until
	// it's added to the list
	void *allocation = ffmalloc_large_from_pool(size, alignment, pool);

	node = (struct poollistnode_t *)ffmetadata_alloc(sizeof(struct poollistnode_t));
	node->pool = pool;

	tailNode->next = node;

	if (loopCount >= MAX_POOLS_PER_LIST) {
		node = arena->largePoolList[listId];
		arena->largePoolList[listId] = arena->largePoolList[listId]->next;
		trim_large_pool(node->pool);
		// TODO: Pool needs to be held onto for destroy arena. Save it where?
	}
	FFLeaveCriticalSection(&arena->largeListLock[listId]);

	return allocation;
}

// Helper function to allocate larger than POOL_SIZE requests
static void *ffmalloc_jumbo(size_t size, struct arena_t *arena)
{
	// A larger than POOL_SIZE request will require its own oddly sized pool
	// Start by creating the pool object
	struct pagepool_t *jumboPool = (struct pagepool_t *)ffmetadata_alloc(sizeof(struct pagepool_t));

	if (jumboPool == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	struct poollistnode_t *newNode = (struct poollistnode_t *)ffmetadata_alloc(sizeof(struct poollistnode_t));
	if (newNode == NULL) {
		ffmetadata_free(jumboPool, sizeof(struct pagepool_t));
		errno = ENOMEM;
		return NULL;
	}

	// Connect page to caller's arena and initialize
	jumboPool->arena = arena;
	if (create_jumbopool(jumboPool, size) == -1) {
		ffmetadata_free(jumboPool, sizeof(struct pagepool_t));
		ffmetadata_free(newNode, sizeof(struct poollistnode_t));
		errno = ENOMEM;
		return NULL;
	}

	// Record the pool in the global pool tree
	add_pool_to_tree(jumboPool);

	// Add to the list of jumbo pools in this arena
	newNode->pool = jumboPool;
	struct poollistnode_t *currenthead;
	do {
		currenthead = arena->jumboPoolList;
		newNode->next = currenthead;
	} while (!FFAtomicCompareExchangePtr(&arena->jumboPoolList, newNode, currenthead));

	update_used_large_memory(jumboPool->end - jumboPool->start);

	// Return the start of the pool as the new allocation
	return jumboPool->start;
}

/*** Free helper functions ***/

// Helper function to return a small pool page back to the OS
static void free_page(struct pagepool_t *pool, struct pagemap_t *pageMap)
{
	byte *startAddress = pageMap->start;
	byte *endAddress = startAddress + PAGE_SIZE;
	unsigned int leftIsFreed = 0;
	unsigned int rightIsFreed = 0;
	struct pagemap_t *currentPage = pageMap;
	struct pagemap_t *leftmostPage = pageMap;
	struct pagemap_t *rightmostPage = pageMap;

	FFEnterCriticalSection(&pool->poolLock);

	// Check earlier pages to see if they are also unused but not yet returned
	// to the OS. Stop when the beginning of the pool, an in use page, or a
	// released page is reached
	while (startAddress > pool->start) {
		currentPage--;
		if ((currentPage->allocSize & SEVEN64) == 5) {
			// Page is no longer actively being allocated from, all allocations
			// have been freed, but page has not been returned to OS
			startAddress -= PAGE_SIZE;
			leftmostPage = currentPage;
		} else if ((currentPage->allocSize & SEVEN64) == 7) {
			// Page has been returned to the OS
			leftIsFreed++;
			break;
		} else {
			break;
		}
	}

	if (startAddress == pool->start) {
		leftIsFreed++;
	}

	// Same as above, except now check following pages
	currentPage = pageMap;
	while (endAddress < pool->end) {
		currentPage++;
		if ((currentPage->allocSize & SEVEN64) == 5) {
			// Page is no longer actively being allocated from, all allocations
			// have been freed, but page has not been returned to OS
			endAddress += PAGE_SIZE;
			rightmostPage = currentPage;
		} else if ((currentPage->allocSize & SEVEN64) == 7) {
			// Page has been returned to the OS
			rightIsFreed++;
			break;
		} else {
			break;
		}
	}

	if (endAddress == pool->end) {
		rightIsFreed++;
	}

	// Check if the computed range of pages meets either the minimum size
	// threshold or if the range constitutes an "island" connecting two
	// freed regions. If so, then return the pages to the OS
	if ((endAddress - startAddress >= (ptrdiff_t)(PAGE_SIZE * MIN_PAGES_TO_FREE)) || (leftIsFreed != 0 && rightIsFreed != 0)) {
		if (os_decommit((void *)startAddress, endAddress - startAddress)) {
			if (errno == ENOMEM) {
				// Likely out of VMAs. Don't die here - continue on in the hopes that
				// more frees will allow VMAs to retire completely
				FFLeaveCriticalSection(&pool->poolLock);
				return;
			}
			fprintf(stderr, "Error: %d Couldn't unmap %p to %p\n", errno, startAddress, endAddress);
			fflush(stderr);
			abort();
		}
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicSub(pool->arena->profile.currentOSBytesMapped, endAddress - startAddress);
#endif

		// Mark all of the pages as returned to the OS
		for (currentPage = leftmostPage; currentPage <= rightmostPage; currentPage++) {
			currentPage->allocSize |= 2UL;
		}

		// Update the "in use" pointers which measure the earliest and latest address
		// not yet freed in the pool. When those meet or cross then the whole pool is
		// completely freed and its metadata data can be freed
		if (startAddress <= pool->startInUse) {
			for (currentPage = rightmostPage;
			     ((currentPage->allocSize & TWO64) != 0) && (currentPage->start < pool->endInUse) && (currentPage->start + PAGE_SIZE < pool->end);
			     currentPage++) {
			}
			if (currentPage->start > pool->start) {
				pool->startInUse = currentPage->start;
			}
		}
		if (endAddress >= pool->endInUse) {
			for (currentPage = leftmostPage;
			     ((currentPage->allocSize & TWO64) != 0) && currentPage->start >= pool->startInUse && (currentPage->start > pool->start);
			     currentPage--) {
				if (currentPage->start > pool->start) {
					if ((currentPage - 1)->start == NULL) {
						currentPage--;
						break;
					}
				}
			}
			pool->endInUse = currentPage->start + PAGE_SIZE;
		}
		if (pool->startInUse >= pool->endInUse) {
			// All space in the pool has been allocated and subsequently freed. Destroy
			// this pool to free up metadata resources
			FFLeaveCriticalSection(&pool->poolLock);
			destroy_pool(pool);
			return;
		}
	}
	FFLeaveCriticalSection(&pool->poolLock);
}

// // Helper function to mark a small allocation freed
void free_small_ptr(struct pagepool_t *pool, struct pagemap_t *pagemap, size_t index)
{
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicSub(pool->arena->profile.currentBytesAllocated, (pagemap->allocSize & ~SEVEN64));
#endif
	update_used_small_memory(-(pagemap->allocSize & ~SEVEN64));

#ifdef CONFIG_GC_DELTA_MARKING
	if (mm_get_active()->is_gc_run)
		pagemap->delta = 1;
#endif

	if (pagemap->allocSize < 64) {
		// Find the right bitmap and location
		size_t array = (index >> 6);
		size_t pos = index - (array << 6);

		FFAtomicAnd(pagemap->bitmap.array[array], ~(ONE64 << pos));
		// Clear the "marked" flag
#ifdef CONFIG_ENABLE_GC
		FFAtomicAnd(pagemap->markmap.array[array], ~(ONE64 << pos));
#endif

		// Check if the page can be released to the OS
		if (pagemap->allocSize & 4UL) {
			uint64_t result = 0;
			size_t bitmaps = (PAGE_SIZE / (pagemap->allocSize & ~SEVEN64)) >> 6;
			if ((PAGE_SIZE / (pagemap->allocSize & ~SEVEN64)) & SIXTYTHREE64) {
				bitmaps++;
			}
			for (size_t i = 0; i < bitmaps; i++)
				result |= pagemap->bitmap.array[i];

			if (result == 0) {
				// All allocations are now freed
				// Mark page as ready to be released
				pagemap->allocSize |= 1;
				free_page(pool, pagemap);
			}
		}
	} else {
		// Clear the "allocated" flag in the bitmap
		FFAtomicAnd(pagemap->bitmap.single, ~(ONE64 << index));
		// Clear the "marked" flag in the bitmap
#ifdef CONFIG_ENABLE_GC
		FFAtomicAnd(pagemap->markmap.single, ~(ONE64 << index));
#endif

		// Check if the page can be released to the OS
		if ((pagemap->allocSize & 4UL) && (pagemap->bitmap.single == 0)) {
			pagemap->allocSize |= 1;
			free_page(pool, pagemap);
		}
	}
}

// Helper function that frees a large pointer
static void free_large_pointer(struct pagepool_t *pool, size_t index, __attrUnusedParam size_t size)
{
	size_t firstFreeIndex;
	size_t lastFreeIndex;

	// Lock this pool while the free happens
	FFEnterCriticalSection(&pool->poolLock);

	// Mark the allocation as freed in the metadata
	pool->tracking.allocations[index] |= ONE64;

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicSub(pool->arena->profile.currentBytesAllocated, size);
#endif
	update_used_large_memory(-size);

	// Start searching for the start of the contiguous free region. The search ends when
	// the beginning of the list is reached, an in use block is found, or a block that
	// has already at least partially been unmapped
	firstFreeIndex = index;
	while ((firstFreeIndex > 0) && ((pool->tracking.allocations[firstFreeIndex - 1] & THREE64) == 1)) {
		firstFreeIndex--;
	}

	unsigned int leftIsFreed = 0;
	unsigned int rightIsFreed = 0;

	// This is potentially the location to start unmapping from. However, it might need to
	// be adjusted forward or backwards depending on what the previous block was marked as
	uintptr_t startFreeAddr = (pool->tracking.allocations[firstFreeIndex] & ~THREE64);
	if ((startFreeAddr & (PAGE_SIZE - 1)) != 0) {
		if ((pool->tracking.allocations[firstFreeIndex - 1] & TWO64) != 0) {
			// The previous allocation has been at least partially unmapped
			// but there is still the remaining bit in this page. So, adjust
			// the start address backwards to the start of this frame
			startFreeAddr = (startFreeAddr & ~(PAGE_SIZE - 1));
			leftIsFreed++;
		} else {
			// The previous allocation is still in use, so this page cannot
			// be unmapped. Adjust the start address forward to the start
			// of the next page
			startFreeAddr = ((startFreeAddr + PAGE_SIZE) & ~(PAGE_SIZE - 1));
		}
	} else if (firstFreeIndex == 0 || (pool->tracking.allocations[firstFreeIndex - 1] & TWO64)) {
		leftIsFreed++;
	}

	// Now start searching for the end of the contiguous free region. As before, stop when
	// the end of the list is reached, an allocated block is reached, or a partially
	// unmapped allocation is found
	lastFreeIndex = index;
	while ((lastFreeIndex < pool->nextFreeIndex) && ((pool->tracking.allocations[lastFreeIndex + 1] & THREE64) == 1)) {
		lastFreeIndex++;
	}

	// Potentially the end of the region to unmap. If it doesn't fall on a page boundary
	// it will need to be adjusted forward or backwards
	uintptr_t endFreeAddr = (pool->tracking.allocations[lastFreeIndex + 1] & ~SEVEN64);
	if (endFreeAddr == 0) {
		fprintf(stderr, "endFreeAddr == 0 test 1\n");
		fflush(stderr);
		abort();
	}

	if ((endFreeAddr & (PAGE_SIZE - 1)) != 0) {
		if ((pool->tracking.allocations[lastFreeIndex + 1] & TWO64) != 0) {
			// The allocation following the region to be freed has already
			// been partially freed, but the portion on this same page also
			// needs to be freed so adjust the end address to the end of the page
			endFreeAddr = ((endFreeAddr + PAGE_SIZE) & ~(PAGE_SIZE - 1));
			if (endFreeAddr == 0) {
				fprintf(stderr, "endFreeAddr == 0 test 2\n");
				fflush(stderr);
				abort();
			}
			rightIsFreed++;
		} else {
			// The next allocation is still in use, so nothing on this page can
			// be freed yet. Move the end address back to the start of the page
			endFreeAddr = (endFreeAddr & ~(PAGE_SIZE - 1));
		}
	} else {
		if ((byte *)endFreeAddr >= pool->end || (pool->tracking.allocations[lastFreeIndex + 1] & TWO64)) {
			rightIsFreed++;
		}
	}

	if ((byte *)startFreeAddr <= pool->startInUse) {
		if ((byte *)endFreeAddr < pool->end) {
			size_t contFreeIndex = lastFreeIndex;
			while (contFreeIndex < pool->nextFreeIndex && ((pool->tracking.allocations[contFreeIndex + 1] & TWO64) != 0)) {
				contFreeIndex++;
			}
			pool->startInUse = (byte *)(pool->tracking.allocations[contFreeIndex + 1] & ~SEVEN64);
		} else {
			pool->startInUse = pool->end;
		}
	}

	// The whole pool is now empty, destroy it (which will also finish freeing up the indicated allocation)
	if ((pool->startInUse >= pool->endInUse) && (pool->tracking.allocations[pool->nextFreeIndex] >= (uintptr_t)pool->end + FOUR64)) {
		FFLeaveCriticalSection(&pool->poolLock);
		destroy_pool(pool);
#ifdef CONFIG_MEMORY_DEBUG
		// Update the physical memory statistics
		FFAtomicSub(pool->arena->profile.currentOSBytesMapped, (size_t)(endFreeAddr - startFreeAddr));
#endif

	} else if (endFreeAddr > startFreeAddr) {
		// Set a minimum number of pages before actually returning them to the OS
		// On Linux, this helps reduce fragmentation which results in VMA bloat which
		// can wrek our ability to request new pages. Alternately, if this is an island
		// between two free regions, return it regardless of size so that 1) it doesn't
		// get orphaned and 2) eliminates a VMA on Linux
		if ((endFreeAddr - startFreeAddr >= (PAGE_SIZE * MIN_PAGES_TO_FREE)) || (leftIsFreed != 0 && rightIsFreed != 0)) {
			if (os_decommit((void *)startFreeAddr, endFreeAddr - startFreeAddr)) {
				if (errno == ENOMEM) {
					// Likely ran out of VMAs. Just continue without marking anything as
					// being cleaned up, that way a future fffree can try again and hopefully
					// make progress
					FFLeaveCriticalSection(&pool->poolLock);
					return;
				}

				fprintf(stderr, "Large pool decommit fail: %d, %p size: %ld\n", errno, (void *)startFreeAddr, endFreeAddr - startFreeAddr);
				fflush(stderr);
				abort();
			}
#ifdef CONFIG_MEMORY_DEBUG
			// Update the physical memory statistics
			FFAtomicSub(pool->arena->profile.currentOSBytesMapped, (size_t)(endFreeAddr - startFreeAddr));
#endif

			// Lastly, mark all the pointers as unmapped
			for (size_t i = firstFreeIndex; i <= lastFreeIndex; i++) {
				pool->tracking.allocations[i] |= THREE64;
			}
		}
	}
	FFLeaveCriticalSection(&pool->poolLock);
}

// Frees a jumbo allocation by deleting the associated pool
static inline void free_jumbo(struct pagepool_t *pool)
{
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicSub(pool->arena->profile.currentBytesAllocated, (size_t)(pool->end - pool->start));
	FFAtomicSub(pool->arena->profile.currentOSBytesMapped, (size_t)(pool->end - pool->start));
#endif
	update_used_large_memory(-(pool->end - pool->start));

	destroy_pool(pool);
}

/*** Public API functions ***/

// Replacement for malloc. Returns a pointer to an available
// memory region >= size or NULL upon failure
void *ota_malloc(size_t size)
{
	void *allocation;

	if (isInit == 2) {
		abort();
	}
	if (!isInit) {
		initialize();
	}

#ifdef CONFIG_ENABLE_GC
	gc_run_mark();
#endif

	// Returning NULL when size==0 would be legal according to the man
	// pages. This would be the preferred behavior because an allocation
	// of zero is almost certain to turn into a call to realloc and that's
	// expensive for this library. However, at least one of the PARSEC
	// benchmarks won't run if we do that so begrudingly return a minimum
	// allocation for size 0
	if (size == 0) {
		size = 8;
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.mallocCount);
	FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size);
#endif
	// If size is very close to SIZE_MAX, the ALIGN_SIZE macro will
	// return 0
	if (size > SIZE_MAX - MIN_ALIGNMENT) {
		errno = ENOMEM;
		return NULL;
	}

	// All allocations are at least 8 byte aligned. Round up if needed
	size = ALIGN_SIZE(size);

#ifdef CONFIG_ENABLE_GC
	if (size <= HALF_PAGE) {
		void *ptr = gc_pop_free_list(arenas[0], size);
		if (ptr)
			return ptr;
	}
#endif

	// Small (less than half page size) allocations are allocated
	// in matching sized bins per thread. Large allocations come
	// out of a single central pool. Allocations larger than a single
	// pool become their own pool
	if (size <= (HALF_PAGE)) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicIncrement(arenas[0]->profile.small.allocCount);
		FFAtomicAdd(arenas[0]->profile.small.BytesRequested, size);
#endif
		allocation = ffmalloc_small(size, arenas[0]);
	} else if (size < (POOL_SIZE - HALF_PAGE)) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicIncrement(arenas[0]->profile.large.allocCount);
		FFAtomicAdd(arenas[0]->profile.large.BytesRequested, size);
#endif
		allocation = ffmalloc_large(size, MIN_ALIGNMENT, arenas[0]);
	} else {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicIncrement(arenas[0]->profile.jumbo.allocCount);
		FFAtomicAdd(arenas[0]->profile.jumbo.BytesRequested, size);
#endif
		allocation = ffmalloc_jumbo(size, arenas[0]);
	}

#ifdef CONFIG_MEMORY_DEBUG
	print_current_usage();
#endif
	if (allocation == NULL) {
		errno = ENOMEM;
	}

	return allocation;
}

// Replacement for realloc. Returns a pointer to a memory region
// that is >= size and also contains the contents pointed to by ptr
// if ptr is not NULL. The return value may be equal to ptr and will
// be NULL on error.
void *ota_realloc(void *ptr, size_t size)
{
	// Per the man page for realloc, calling with ptr == NULL is
	// equal to malloc(size). When ptr isn't NULL, calling
	// realloc with size == 0 is the same as free(ptr)
	if (ptr == NULL) {
		return ota_malloc(size);
	} else if (size == 0) {
		ota_free(ptr);
		return NULL;
	}

	struct pagepool_t *pool = find_pool_for_ptr((const byte *)ptr);
	if (pool == NULL) {
		// Program is trying to free a bad pointer
		// Or more likely there is a bug in this library
		fprintf(stderr, "Attempt to realloc %p but no matching pool\n", ptr);
		fflush(stderr);
		abort();
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.reallocCount);
#endif

	// Was this a large or small allocation pool?
	if (pool->nextFreeIndex < SIZE_MAX - 1) {
		// Large allocation
		size_t index = 0;
		size_t oldSize = find_large_ptr((const byte *)ptr, pool, &index);

		// Pointer not found - abort with extreme prejudice
		// Likely a bug that needs cleaning up
		if (oldSize == 0) {
			fprintf(stderr, "realloc bad large ptr: %p\n", ptr);
			fprintf(stderr, "pool:    %p\n", pool);
			fprintf(stderr, "pool st: %p\n", pool->start);
			fflush(stderr);
			abort();
		}

		// When the reallocation size isn't bigger than the current size
		// just quit and tell the app to keep using the same allocation
		if (size <= oldSize) {
			return ptr;
		}

#ifdef FF_GROWLARGEREALLOC
		// Check if the allocation happens to be at the end of the large
		// pool and thus can be grown without extending into previously
		// allocated space. It seems like this would be uncommon but
		// profiling the SPECint PerlBench test says that its at least
		// occassionally very common

		// Potential integer overflow issue below. Since inplace resize
		// is only possible if the new size would still fit within the
		// pool, checking that size < POOL_SIZE should be sufficient
		if (size < POOL_SIZE) {
			FFEnterCriticalSection(&pool->poolLock);
			size_t additionalSize = ALIGN_SIZE(size) - oldSize;
			if (index == pool->nextFreeIndex - 1 && (pool->nextFreePage + additionalSize <= pool->end)) {
#ifdef CONFIG_MEMORY_DEBUG
				FFAtomicIncrement(arenas[0]->profile.reallocCouldGrow);
				FFAtomicAdd(arenas[0]->profile.currentBytesAllocated, additionalSize);
				FFAtomicAdd(arenas[0]->profile.totalBytesAllocated, additionalSize);
				FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size - oldSize);
				FFAtomicAdd(arenas[0]->profile.large.BytesAllocated, additionalSize);
				FFAtomicAdd(arenas[0]->profile.large.BytesRequested, size - oldSize);
#endif
				pool->nextFreePage += additionalSize;
				pool->tracking.allocations[pool->nextFreeIndex] += additionalSize;
				FFLeaveCriticalSection(&pool->poolLock);
				return ptr;
			}
			FFLeaveCriticalSection(&pool->poolLock);
		}
#endif

		// A bigger reallocation size requires copying the old data to
		// the new location and then freeing the old allocation
		void *temp = ota_malloc(size);
		memcpy(temp, ptr, oldSize);
		free_large_pointer(pool, index, oldSize);
		return temp;
	} else if (pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo allocation - the pool is the allocation
		// How big was it?
		size_t jumboSize = pool->end - pool->start;

		// Is it still big enough?
		// TODO: Add code to trim pages from the end if the size is
		// sufficiently smaller
		// Also consider expansion if possible in the single threaded
		// case
		if (size <= jumboSize) {
			return pool->start;
		}

		// Not big enough so we'll have to create a new allocation
		void *newJumbo = ota_malloc(size);
		if (newJumbo == NULL) {
			errno = ENOMEM;
			return NULL;
		}

		// Copy into the new buffer
		memcpy(newJumbo, ptr, jumboSize);

		// Release memory associated with the old allocation and cleanup metadata
		free_jumbo(pool);

		// Return success
		return newJumbo;
	} else {
		// Small allocation
		struct pagemap_t *pageMap = NULL;

		// Find the specific page and index of this allocation
		int64_t index = find_small_ptr_allocated((const byte *)ptr, pool, &pageMap);

		// For now, fail violently if we can't find the pointer
		// (likely a bug in the library somewhere)
		if (index < 0) {
			// Not a valid pointer
			fprintf(stderr, "realloc bad small ptr: %p\n", ptr);
			fprintf(stderr, "pool: %p\n", pool);
			fprintf(stderr, "pageMap: %p\n", pageMap);
			fflush(stderr);
			abort();
		}

		if (size <= (pageMap->allocSize & ~SEVEN64)) {
			return ptr;
		}

		void *temp = ota_malloc(size);
		memcpy(temp, ptr, (pageMap->allocSize & ~SEVEN64));
		free_small_ptr(pool, pageMap, index);
		return temp;
	}
}

// Replacement for reallocarray. Equivalent to realloc(ptr, nmemb * size)
// but will return NULL and signal ENOMEM if the multiplication overflows
void *ota_reallocarray(void *ptr, size_t nmemb, size_t size)
{
	// Overflow check. Existing allocation remains unaltered if there is overflow
	if (nmemb && size > (SIZE_MAX / nmemb)) {
		errno = ENOMEM;
		return NULL;
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.reallocarrayCount);
#endif

	return ota_realloc(ptr, nmemb * size);
}

// Replacement for calloc. Returns a pointer to a memory region
// that is >= nmemb * size and is guaranteed to be zeroed out.
// Returns NULL on error
void *ota_calloc(size_t nmemb, size_t size)
{
	void *ptr;
	// Don't bother with size 0 allocations
	if (nmemb == 0 || size == 0)
		nmemb = size = 1;

	// Ensure multiplication won't overflow
	if (size > (SIZE_MAX / nmemb)) {
		return NULL;
	}

	if (isInit == 2) {
		abort();
	}
	if (!isInit) {
		initialize();
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.callocCount);
#endif

	// Possible dirty page from gc free list.
	// TODO! Implement conditional zeroing.
	ptr = ota_malloc(nmemb * size);

	return ptr;
}

// Replacment for free. Marks an allocation previously returned by
// ffmalloc, ffrealloc, or ffcalloc as no longer in use. The memory
// page might be returned to the OS depending on the status of other
// allocations from the same page
void ota_free(void *ptr)
{
	// Per the specification for free, calling with ptr == NULL is
	// legal and is a no-oop
	if (ptr == NULL)
		return;

	struct pagepool_t *pool = find_pool_for_ptr((const byte *)ptr);
	if (unlikely(pool == NULL)) {
		if (kvalid(ptr)) {
			kfree(ptr);
			return;
		}

		// Program is trying to free a bad pointer
		// Or more likely there is a bug in this library
		fprintf(stderr, "Attempt to free %p but no matching pool\n", ptr);
		fflush(stderr);
		abort();
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.freeCount);
#endif

	// Was this a large or small allocation pool?
	if (pool->nextFreeIndex < SIZE_MAX - 1) {
		// Large allocation
		size_t index = 0;
		size_t size = find_large_ptr((const byte *)ptr, pool, &index);

		// Pointer not found - abort with extreme prejudice
		// Likely a bug that needs cleaning up
		if (size == 0) {
			fprintf(stderr, "free bad large ptr: %p\n", ptr);
			fprintf(stderr, "pool:    %p\n", pool);
			fprintf(stderr, "pool st: %p\n", pool->start);
			fflush(stderr);
			abort();
		}
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicIncrement(arenas[0]->profile.large.freeCount);
#endif
		free_large_pointer(pool, index, size);
	} else if (pool->nextFreeIndex == SIZE_MAX - 1) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicIncrement(arenas[0]->profile.jumbo.freeCount);
#endif
		// Jumbo allocation
		// Jumbo pages are immediately returned to the OS, so no need to zero it.
		free_jumbo(pool);
	} else {
		// Small allocation
		struct pagemap_t *pageMap = NULL;

		// Find the specific page and index of this allocation
		int64_t index = find_small_ptr_allocated((const byte *)ptr, pool, &pageMap);

		// For now, fail violently if we can't find the pointer
		if (index < 0) {
			// Not a valid pointer
			printk("index %d\n", index);
			fprintf(stderr, "free bad ptr: %p\n", ptr);
			fprintf(stderr, "ptr size:     %ld\n", pageMap->allocSize & ~SEVEN64);
			fprintf(stderr, "pool start:   %p\n", pool->start);
			fprintf(stderr, "page start:   %p\n", pageMap->start);
			fflush(stderr);
			abort();
		}
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicIncrement(arenas[0]->profile.small.freeCount);
#endif
		memset(ptr, 0, pageMap->allocSize & ~SEVEN64);
		free_small_ptr(pool, pageMap, index);
	}
}

static inline void *ffmemalign_internal(size_t alignment, size_t size)
{
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.posixAlignCount);
	FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size);
#endif

	// Allocation can be serviced from the small bin only if both the size
	// and the alignment fit into the small bin
	if (size <= HALF_PAGE && alignment <= HALF_PAGE) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arenas[0]->profile.small.BytesRequested, size);
#endif
		if (size <= alignment) {
			// When size is less than alignment, just returning an
			// allocation of size == alignment will guarantee the
			// requested alignment
			return ffmalloc_small(alignment, arenas[0]);
		} else {
			// When size is greater than alignment, rounding size
			// up to the next power of two will ensure alignment
			return ffmalloc_small(ONE64 << (64 - FFCOUNTLEADINGZEROS64(size - 1)), arenas[0]);
		}
	}

	// Either size or alignment won't fit into the normal small bins so
	// even if the size is small, it will have to come out of the large
	// allocation bin to get the requested alignment

	// Round size up to a multiple of base alignment if needed
	size = ALIGN_SIZE(size);

	if (size >= POOL_SIZE) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arenas[0]->profile.jumbo.BytesRequested, size);
#endif
		return ffmalloc_jumbo(size, arenas[0]);
	} else {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arenas[0]->profile.large.BytesRequested, size);
#endif
		return ffmalloc_large(size, alignment, arenas[0]);
	}

	return NULL;
}

// Replacement for posix_memalign. Returns a pointer to a block of memory that
// is >= size and that has at least the specified alignment, which must be a
// power of two
int ota_posix_memalign(void **ptr, size_t alignment, size_t size)
{
	// Don't bother with zero byte allocations
	// Also check against overflow below
	if (size == 0 || (size >= SIZE_MAX - PAGE_SIZE)) {
		*ptr = NULL;
		return EINVAL;
	}

	// Alignment must be at least sizeof(void*) and alignment must be a
	// power of two
	if (alignment < 8 || FFPOPCOUNT64(alignment) != 1) {
		*ptr = NULL;
		return EINVAL;
	}

	// Current jumbo allocation code is missing alignment support but all
	// jumbo allocations will be at least page aligned. For now it is an
	// error to request more than page alignment for a jumbo allocation
	if (size + PAGE_SIZE >= POOL_SIZE && alignment > PAGE_SIZE) {
		*ptr = NULL;
		return EINVAL;
	}

	*ptr = ffmemalign_internal(alignment, size);
	if (*ptr == NULL) {
		return ENOMEM;
	}

	return 0;
}

// Replacement for memalign. The man page says this is obsolete but it turns
// up in PARSEC benchmark so here it is. The address of the returned allocation
// will be a multiple of alignment and alignment must be a power of two.
void *ota_memalign(size_t alignment, size_t size)
{
	// Forbid zero byte allocations
	// Protect against integer overflow later
	if (size == 0 || (size >= SIZE_MAX - PAGE_SIZE)) {
		return NULL;
	}

	// Verify that alignment is a power of two
	if (FFPOPCOUNT64(alignment) != 1) {
		errno = EINVAL;
		return NULL;
	}

	// The man page is silent on whether a minimum value for alignment is
	// enforced (compare to posix_memalign). Since none is mentioned,
	// allow all values but anything less than pointer size will just be
	// handled as a regular malloc
	if (alignment <= sizeof(void *)) {
		return ota_malloc(size);
	}

	// The jumbo allocation code doesn't support custom alignment right now
	// but any jumbo alignment will be page aligned. So, error out if the
	// request is bigger than page size otherwise carry on
	if (size + PAGE_SIZE >= POOL_SIZE && alignment > PAGE_SIZE) {
		errno = EINVAL;
		return NULL;
	}

	return ffmemalign_internal(alignment, size);
}

// Replacment for aligned_alloc. Alignment must be a power of two and size
// must be a multiple of alignment. Returned pointer will point to a region
// that is >= size and at least alignment aligned or NULL on failure
void *ota_aligned_alloc(size_t alignment, size_t size)
{
	// Don't allow zero byte allocations
	// Protect against integer overflow
	if (size == 0 || (size >= SIZE_MAX - PAGE_SIZE)) {
		return NULL;
	}

	// Alignment must be at least sizeof(void*) and alignment must be a
	// power of two
	if (alignment < 8 || FFPOPCOUNT64(alignment) != 1) {
		errno = EINVAL;
		return NULL;
	}

	// Description of aligned_alloc says that size must be a multiple of
	// alignment
	if (size < alignment || (size % alignment != 0)) {
		errno = EINVAL;
		return NULL;
	}

	// Missing alignment support in jumbo code so forbid greater than page
	// alignment for jumbo allocations until that's fixed. All jumbo
	// allocations will be page aligned anyways
	if (size + PAGE_SIZE >= POOL_SIZE && alignment > PAGE_SIZE) {
		errno = EINVAL;
		return NULL;
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.allocAlignCount);
	FFAtomicAdd(arenas[0]->profile.totalBytesRequested, size);
#endif

	if (size >= POOL_SIZE) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arenas[0]->profile.jumbo.BytesRequested, size);
#endif
		return ffmalloc_jumbo(size, arenas[0]);
	}
	// Allocation can be serviced from the small bin only if both the size
	// and the alignment fit into the small bin
	else if (size <= HALF_PAGE && alignment <= HALF_PAGE) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arenas[0]->profile.small.BytesRequested, size);
#endif
		return ffmalloc_small(ONE64 << (64 - FFCOUNTLEADINGZEROS64(size - 1)), arenas[0]);
	} else {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arenas[0]->profile.large.BytesRequested, size);
#endif
		// Either size or alignment won't fit into the normal small bins so
		// even if the size is small, it will have to come out of the large
		// allocation bin to get the requested alignment
		return ffmalloc_large(size, alignment, arenas[0]);
	}
}

// Replacement for malloc_usable_size. Returns the actual amount of space
// allocated to a given pointer which could be greater than the requested size
size_t ota_malloc_usable_size(const void *ptr)
{
	// The man page for this function is vague on how this function handles
	// errors other than being explicit that a NULL value for ptr should
	// return zero
	if (ptr == NULL) {
		return 0;
	}

	// Follow above logic and any invalid pointer will result in size of
	// zero and errno will not be set
	struct pagepool_t *pool = find_pool_for_ptr((const byte *)ptr);
	if (pool == NULL) {
		return 0;
	}

	// Was this a large or small allocation pool?
	if (pool->nextFreeIndex < SIZE_MAX - 1) {
		// Large allocation
		size_t index = 0;
		return find_large_ptr((const byte *)ptr, pool, &index);
	} else if (pool->nextFreeIndex == SIZE_MAX - 1) {
		// Jumbo allocation
		return pool->end - pool->start;
	} else {
		// Small allocation
		struct pagemap_t *pageMap = NULL;

		// Find the specific page and index of this allocation
		int64_t index = find_small_ptr_allocated((const byte *)ptr, pool, &pageMap);

		if (index < 0) {
			// Not a valid pointer
			return 0;
		}

		// Mask out the low order status bits before returning size
		return (pageMap->allocSize & ~SEVEN64);
	}
}

/*** FFMalloc extended API ***/

// Duplicates the string into memory allocated by ffmalloc. The caller is
// responsible for calling fffree
char *ffstrdup(const char *s)
{
	if (s == NULL) {
		return NULL;
	}

	size_t length = strlen(s) + 1;
	char *newString = (char *)ota_malloc(length);
	if (newString != NULL) {
		// Visual C does *not* like strcpy, but we need to be portable so get the
		// compiler to quit complaining just this one time
#pragma warning(push)
#pragma warning(disable : 4996)
		strcpy(newString, s);
#pragma warning(pop)
		return newString;
	}

	errno = ENOMEM;
	return NULL;
}

// Duplicates the first n characters of the string into memory allocated by
// ffmalloc. The caller is responsible for calling fffree
char *ffstrndup(const char *s, size_t n)
{
	if (s == NULL || n == SIZE_MAX) {
		return NULL;
	}

	char *newString = (char *)ota_malloc(n + 1);
	if (newString != NULL) {
#pragma warning(push)
#pragma warning(disable : 4996)
		strncpy(newString, s, n);
#pragma warning(pop)

		// strncpy may not null terminate the string if there is no
		// null byte in the first n characters of s
		newString[n] = '\0';
		return newString;
	}

	errno = ENOMEM;
	return NULL;
}

#ifdef CONFIG_MEMORY_DEBUG
// Gets usage statistics for ffmalloc excluding custom arenas
ffresult_t ffget_statistics(ffprofile_t *profile)
{
	if (profile == NULL) {
		return FFBAD_PARAM;
	}

	memcpy(profile, &arenas[0]->profile, sizeof(ffprofile_t));

	return FFSUCCESS;
}

// Gets usage statistics for a custom arena
ffresult_t ffget_arena_statistics(ffprofile_t *profile, ffarena_t arenaKey)
{
	// Ensure that the arena key is in range and exists
	if (arenaKey == 0 || arenaKey >= MAX_ARENAS || arenas[arenaKey] == NULL) {
		return FFBAD_ARENA;
	}

	if (profile == NULL) {
		return FFBAD_PARAM;
	}

	memcpy(profile, &arenas[arenaKey]->profile, sizeof(ffprofile_t));

	return FFSUCCESS;
}

// Gets combined usage statistics for all arenas active or destroyed plus the
// default allocation arena. Caller is responsible for freeing the returned
// structure
/* Not yet implemented. Need destroy_arena to save results to new global counter
ffresult_t ffget_global_statistics(ffprofile_t* profile) {
        if(profile == NULL) {
                return FFBAD_PARAM;
        }

        return FFSUCCESS;
}*/
#endif

// Creates a new allocation arena
ffresult_t ffcreate_arena(ffarena_t *newArenaKey)
{
	// First make sure we've got some place to return this arena to
	if (newArenaKey == NULL) {
		return FFBAD_PARAM;
	}

	// Reserve metadata space for the arena
	struct arena_t *newArena = (struct arena_t *)ffmetadata_alloc(sizeof(struct arena_t));

	// Find a free slot in the arena array
	for (ffarena_t i = 1; i < MAX_ARENAS; i++) {
		if (arenas[i] == NULL) {
			// Found a slot, try and claim it
			if (FFAtomicCompareExchangePtr(&arenas[i], newArena, NULL)) {
				// Slot succesfully claimed
				ffresult_t result = create_arena(arenas[i]);
				if (result == FFSUCCESS) {
					*newArenaKey = i;
				}
				return result;
			}
		}
	}

	// No free slots left to put a new arena in
	ffmetadata_free(newArena, sizeof(struct arena_t));
	return FFMAX_ARENAS;
}

// Frees all memory allocated from a specific arena and then destroys the arena
ffresult_t ffdestroy_arena(ffarena_t arena)
{
	// Ensure that the arena key is in range and exists. Also note that
	// destroying the default arena is not allowed
	if (arena == 0 || arena >= MAX_ARENAS || arenas[arena] == NULL) {
		return FFBAD_ARENA;
	}

	// No attempt at thread safety - caller is responsible for ensuring
	// this is called only once when finished
	destroy_arena(arenas[arena]);
	arenas[arena] = NULL;

	return FFSUCCESS;
}

// Allocates memory with the same algorithm as ffmalloc but from a custom arena
ffresult_t ffmalloc_arena(ffarena_t arenaKey, void **ptr, size_t size)
{
	struct arena_t *arena = NULL;

	// Ensure the out pointer parameter is valid
	if (ptr == NULL) {
		return FFBAD_PARAM;
	}

	// Check that the arena key is in range and exists. Technically,
	// nothing bad would happen by allowing allocation out of the default
	// arena here. However, it would violate the spirit of the API which is
	// that the arena key should be generated by ffcreate_arena. Second,
	// the caller should not depend on the default arena being zero since
	// that's an internal implementation detail. Lastly, it would violate
	// principle of least surprise since zero definitely can't be used with
	// ffdestroy_arena and the caller may be confused that zero can be
	// allocated from but not destroyed
	if (arenaKey == 0 || arenaKey >= MAX_ARENAS || arenas[arenaKey] == NULL) {
		return FFBAD_ARENA;
	} else {
		arena = arenas[arenaKey];
	}

	// Prohibit zero byte allocations. It can't be realloc'ed to bigger
	// than 8 anyways without a copy so just ask for what you need to start
	// Also protect against overflow due to alignment below
	if (size == 0 || size > SIZE_MAX - MIN_ALIGNMENT) {
		return FFBAD_PARAM;
	}

#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arena->profile.mallocCount);
	FFAtomicAdd(arena->profile.totalBytesRequested, size);
#endif
	// Round size up to a multiple of 8 if needed
	size = ALIGN_SIZE(size);

	// Allocate from the right pool in the requested arena
	if (size <= HALF_PAGE) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arena->profile.small.BytesRequested, size);
#endif
		*ptr = ffmalloc_small(size, arena);
	} else if (size < (POOL_SIZE - HALF_PAGE)) {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arena->profile.large.BytesRequested, size);
#endif
		*ptr = ffmalloc_large(size, MIN_ALIGNMENT, arena);
	} else {
#ifdef CONFIG_MEMORY_DEBUG
		FFAtomicAdd(arena->profile.jumbo.BytesRequested, size);
#endif
		*ptr = ffmalloc_jumbo(size, arena);
	}

	return *ptr == NULL ? FFNOMEM : FFSUCCESS;
}

/**
 Frees all data and metadata allocated by an ffmalloc family function
 */
void fffree_all()
{
	// for (size_t l1 = 0; l1 < STEM_COUNT; l1++) {
	// 	if (poolTree.stems[l1] != NULL) {
	// 		for (size_t l2 = 0; l2 < LEAVES_PER_STEM; l2++) {
	// 			struct radixleaf_t *leaf = poolTree.stems[l1]->leaves[l2];
	// 			if (leaf != NULL) {
	// 				for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
	// 					if (leaf->poolStart[l3] != NULL) {
	// 						os_free(leaf->poolStart[l3]->start);
	// 						os_free(leaf->poolStart[l3]->tracking.pageMaps);
	// 					}
	// 				}
	// 			}
	// 		}
	// 	}
	// }
}

void ffdump_pool_details()
{
	printf("alloc count: %ld\n", os_alloc_count);
	printf("alloc amount %ld\n", os_alloc_total);
	printf("free count %ld\n", os_free_count);
	for (size_t l1 = 0; l1 < STEM_COUNT; l1++) {
		if (poolTree.stems[l1] != NULL) {
			for (size_t l2 = 0; l2 < LEAVES_PER_STEM; l2++) {
				struct radixleaf_t *leaf = poolTree.stems[l1]->leaves[l2];
				if (leaf != NULL) {
					for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
						if (leaf->poolStart[l3] != NULL) {
							size_t released = 0;
							size_t pending = 0;
							size_t inuse = 0;
							size_t tcache = 0;
							struct pagepool_t *pool = leaf->poolStart[l3];
							// printf("Pool start: %p ", pool->start);
							if (pool->nextFreeIndex == SIZE_MAX) {
								byte *lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
								for (size_t x = 0; x < (lastFreePage - pool->start) / PAGE_SIZE; x++) {
									if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 3) {
										released++;
									} else if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 1) {
										pending++;
									} else if (pool->tracking.pageMaps[x].allocSize == 0) {
										tcache++;
									} else {
										inuse++;
									}
								}
								size_t unassigned = (pool->end - lastFreePage) / PAGE_SIZE;
								// if (pending > 0 || inuse > 0 || unassigned > 0 || tcache > 0) {
								printf("Small pool addr: %p with %ld pages unassigned, ", pool->start, unassigned);
								printf("%ld pending free, ", pending);
								printf("%ld freed, ", released);
								printf("%ld in tcache reserve, ", tcache);
								printf("%ld in use\n", inuse);
								//}
								if (released == 1024) {
									printf("startInUse: %p endInUse: %p\n", pool->startInUse, pool->endInUse);
								}
							} else if (pool->nextFreeIndex == SIZE_MAX - 1) {
								printf("Jumbo pool start: %p\n", pool->start);
							} else {
								printf("Large pool start: %p with %ld bytes free\n", pool->start,
								       (uintptr_t)pool->end - pool->tracking.allocations[pool->nextFreeIndex]);
							}
						}
					}
				}
			}
		}
	}
}

/**
 Gets the number of pools currently active
 @return The number of pools ffmalloc has currently in use
 */
size_t ffget_pool_count()
{
	return poolCount;
}

#ifdef CONFIG_MEMORY_DEBUG
void ffprint_stats_wrapper(void)
{
	ffprint_statistics(stderr);
}

void ffprint_statistics(FILE *const dest)
{
	ffprofile_t *stats = &arenas[0]->profile;
	fprintf(dest, "*** FFMalloc Stats Count ***\n");
	fprintf(dest, "Malloc:               %ld\n", stats->mallocCount);
	fprintf(dest, "  small_alloc:        %ld\n", stats->small.allocCount);
	fprintf(dest, "  large_alloc:        %ld\n", stats->large.allocCount);
	fprintf(dest, "  jumbo_alloc:        %ld\n", stats->jumbo.allocCount);
	fprintf(dest, "Realloc:              %ld\n", stats->reallocCount);
#ifdef FF_GROWLARGEREALLOC
	fprintf(dest, "Realloc Grow:         %ld\n", stats->reallocCouldGrow);
#endif
	fprintf(dest, "Calloc:               %ld\n", stats->callocCount);
	fprintf(dest, "Free:                 %ld\n", stats->freeCount);
	fprintf(dest, "  small_free:         %ld\n", stats->small.freeCount);
	fprintf(dest, "  large_free:         %ld\n", stats->large.freeCount);
	fprintf(dest, "  jumbo_free:         %ld\n", stats->jumbo.freeCount);
	fprintf(dest, "Realloc:              %ld\n", stats->reallocCount);
	fprintf(dest, "POSIX Align:          %ld\n", stats->posixAlignCount);
	fprintf(dest, "Alloc Align:          %ld\n", stats->allocAlignCount);

	fprintf(dest, "\n*** FFMalloc Stats Mem***\n");
	fprintf(dest, "TotBytes Reqst:       0x%lx\n", stats->totalBytesRequested);
	fprintf(dest, "  Small_Bytes Req:    0x%lx\n", stats->small.BytesRequested);
	fprintf(dest, "  large_Bytes Req:    0x%lx\n", stats->large.BytesRequested);
	fprintf(dest, "  jumbo_Bytes Req:    0x%lx\n", stats->jumbo.BytesRequested);
	fprintf(dest, "TotBytes Alloc:       0x%lx\n", stats->totalBytesAllocated);
	fprintf(dest, "  Small_Bytes Alloc:  0x%lx\n", stats->small.BytesAllocated);
	fprintf(dest, "  large_Bytes Alloc:  0x%lx\n", stats->large.BytesAllocated);
	fprintf(dest, "  jumbo_Bytes Alloc:  0x%lx\n", stats->jumbo.BytesAllocated);
	fprintf(dest, "CurBytes Alloc:       0x%lx\n", stats->currentBytesAllocated);
	fprintf(dest, "MaxBytes Alloc:       0x%lx\n", stats->maxBytesAllocated);
	fprintf(dest, "CurOSBytes Map:       0x%lx\n", stats->currentOSBytesMapped);
	fprintf(dest, "MaxOSBytes Map:       0x%lx\n", stats->maxOSBytesMapped);
	struct rusage usage;
	getrusage(RUSAGE_SELF, &usage);
	fprintf(dest, "Linux MaxRSS:         0x%lx\n\n", usage.ru_maxrss * 1024L);

	fprintf(dest, "\n*** FFMAlloc Stats GC ***\n");
	// TODO : Support floating point in console.c
	fprintf(dest, "Mark Count:             %ld\n", stats->markCount);
	fprintf(dest, "Mark Time:            %ld ms\n", stats->mark_time / 1000);
	fprintf(dest, "Sweep Count:              %ld\n", stats->sweepCount);
	fprintf(dest, "Sweep Time:           %ld ms\n", stats->sweep_time / 1000);
}

// Prints current usage statistics to the specified file each time the cummulative
// number of calls to malloc/calloc/realloc (that caused a malloc) is a multiple
// of interval
void ffprint_usage_on_interval(FILE *const dest, unsigned int interval)
{
	usagePrintFile = dest;
	if (interval == 0) {
		usagePrintInterval = INT_MAX;
	} else {
		usagePrintInterval = interval;
	}
}

static void print_current_usage()
{
	// Should print: OS mem, current physical bytes, current alloc bytes, free bytes need release
	// free bytes awaiting assign
	size_t releasedPages = 0;
	size_t pendingReleasePages = 0;
	size_t pendingReleaseLargeBytes = 0;
	size_t tcachePages = 0;
	size_t inusePages = 0;
	size_t unassignedPages = 0;
	size_t unassignedLargeBytes = 0;
	size_t currentOSReported = 0;
	size_t smallFreeOnInUsePage = 0;
	size_t poolMetadata = 0;
	size_t smallPageWaste = 0;
	size_t smallPoolCount = 0;
	size_t largePoolCount = 0;
	size_t jumboPoolCount = 0;
	size_t largePoolAssigned = 0;
	size_t numEmptyLargePool = 0;

	if (usagePrintFile != NULL && (arenas[0]->profile.mallocCount % usagePrintInterval == 0)) {
		for (size_t l1 = 0; l1 < STEM_COUNT; l1++) {
			if (poolTree.stems[l1] != NULL) {
				for (size_t l2 = 0; l2 < LEAVES_PER_STEM; l2++) {
					struct radixleaf_t *leaf = poolTree.stems[l1]->leaves[l2];
					if (leaf != NULL) {
						for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
							if (leaf->poolStart[l3] != NULL) {
								struct pagepool_t *pool = leaf->poolStart[l3];
								if (pool->nextFreeIndex == SIZE_MAX) {
									// Small pool
									size_t poolInUsePages = 0;
									size_t smallNeedsReleasePages = 0;
									smallPoolCount++;
									poolMetadata += POOL_SIZE / PAGE_SIZE * sizeof(struct pagemap_t);
									byte *lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
									for (size_t x = 0; x < (lastFreePage - pool->start) / PAGE_SIZE; x++) {
										if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 3) {
											releasedPages++;
										} else if ((pool->tracking.pageMaps[x].allocSize & THREE64) == 1) {
											pendingReleasePages++;
										} else if (pool->tracking.pageMaps[x].allocSize == 0) {
											tcachePages++;
										} else {
											inusePages++;
											poolInUsePages++;
											size_t allocSize = (pool->tracking.pageMaps[x].allocSize & ~SEVEN64);
											size_t maxAlloc = PAGE_SIZE / allocSize;
											smallPageWaste += PAGE_SIZE - (maxAlloc * allocSize);
											if (allocSize >= 64) {
												size_t count =
													FFPOPCOUNT64(pool->tracking.pageMaps[x].bitmap.single);
												smallFreeOnInUsePage += ((maxAlloc - count) * allocSize);
												if (count == 0) {
													smallNeedsReleasePages++;
												}
											} else {
												size_t bitmapCount = (maxAlloc & SIXTYTHREE64) ?
															     (maxAlloc >> 6) + 1 :
															     (maxAlloc >> 6);
												size_t totalCount = 0;
												for (size_t index = 0; index < bitmapCount; index++) {
													size_t count = FFPOPCOUNT64(
														pool->tracking.pageMaps[x].bitmap.array[index]);
													totalCount += count;
													if (index != (bitmapCount - 1)) {
														smallFreeOnInUsePage +=
															(64 - count) * allocSize;
													} else {
														size_t lastBitmapMax =
															maxAlloc - ((bitmapCount - 1) * 64);
														smallFreeOnInUsePage +=
															(lastBitmapMax - count) * allocSize;
													}
												}
												if (totalCount == 0) {
													smallNeedsReleasePages++;
												}
											}
										}
									}
									unassignedPages += (pool->end - lastFreePage) / PAGE_SIZE;
									/*if(unassignedPages == 0 && smallNeedsReleasePages >= 1024) {
                                                                                fprintf(stderr, "Small pool empty: %p\n", pool);
                                                                                abort();
                                                                        }*/
								} else if (pool->nextFreeIndex == SIZE_MAX - 1) {
									// Jumbo pool
									jumboPoolCount++;
								} else {
									// Large pool
									largePoolCount++;
									poolMetadata += (POOL_SIZE >> 20) * PAGE_SIZE;
									size_t thisPoolInUse = 0;
									for (size_t index = 0; index < pool->nextFreeIndex; index++) {
										if ((pool->tracking.allocations[index] & 2) == 2) {
											// Freed and (at least partially) returned
										} else if ((pool->tracking.allocations[index] & 3) == 1) {
											// Freed pending return
											pendingReleaseLargeBytes +=
												((pool->tracking.allocations[index + 1] & ~SEVEN64) -
												 (pool->tracking.allocations[index] & ~SEVEN64));
										} else {
											thisPoolInUse += (pool->tracking.allocations[index + 1] & ~SEVEN64) -
													 pool->tracking.allocations[index];
										}
									}
									if (thisPoolInUse == 0) {
										numEmptyLargePool++;
										/*fprintf(stderr, "Empty pool: %p\n", pool);
                                                                                if(numEmptyLargePool > 4) {
                                                                                        abort();
                                                                                }*/
									}
									largePoolAssigned += thisPoolInUse;

									if ((uintptr_t)pool->end > pool->tracking.allocations[pool->nextFreeIndex]) {
										unassignedLargeBytes +=
											((uintptr_t)pool->end -
											 (pool->tracking.allocations[pool->nextFreeIndex] & ~SEVEN64));
									}
								}
							}
						}
					}
				}
			}
		}

		// This all is only valid so long as large OS pages are not supported
		FILE *stat = fopen("/proc/self/statm", "r");
		if (stat) {
			fscanf(stat, "%lu ", &currentOSReported);
			fclose(stat);
			currentOSReported *= 4096;
		}
		char *fmtString = "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n";

		fprintf(usagePrintFile, fmtString, // peakOSReported,
			arenas[0]->profile.mallocCount, arenas[0]->profile.reallocCount, currentOSReported, arenas[0]->profile.currentOSBytesMapped,
			arenas[0]->profile.currentBytesAllocated, poolMetadata, smallPageWaste, smallFreeOnInUsePage, pendingReleasePages * PAGE_SIZE,
			pendingReleaseLargeBytes, (unassignedPages + tcachePages) * PAGE_SIZE, unassignedLargeBytes, largePoolAssigned, smallPoolCount,
			largePoolCount, jumboPoolCount, numEmptyLargePool);
	}
}
#endif
