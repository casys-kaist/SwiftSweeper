#include <stdatomic.h>
#define _GNU_SOURCE
#include "kconfig.h"
#include "lib/list.h"
#include "lib/stddef.h"
#include "lib/types.h"
#include "memory.h"
#include "spin_lock.h"
#include "pthread.h"
#include <stddef.h>
#include <stdbool.h>
#include <sys/mman.h>

// Header file for FFMalloc

#pragma once
// Need size_t
#include <sys/types.h>

#ifdef CONFIG_MEMORY_DEBUG
// Need FILE
#include <stdio.h>
#endif

typedef unsigned char byte;

/*** Library Constants ***/
// GCC and Visual C++ disagree on how many bits "long" is. Define
// key constants to make sure bitwise operations aren't truncated
#define ONE64 UINT64_C(1)
#define TWO64 UINT64_C(2)
#define THREE64 UINT64_C(3)
#define FOUR64 UINT64_C(4)
#define SEVEN64 UINT64_C(7)
#define EIGHT64 UINT64_C(8)
#define FIFTEEN64 UINT64_C(15)
#define SIXTYTHREE64 UINT64_C(63)

// The maximum size of a single memory pool. Must be a power of
// two greater than or equal to either 1MB or the size of a page if
// large (2MB or 1GB) pages are used instead of 4KB
#define POOL_SIZE_BITS 22
#define POOL_SIZE (ONE64 << POOL_SIZE_BITS)

// The size of a single page of memory from the OS
// #define PAGE_SIZE UINT64_C(4096)

// Half of an OS memory page
#define HALF_PAGE UINT64_C(2048)

// The number of pages to assign from a pool to a thread cache
// when a thread cache is out of free pages. Must be an integral
// divisor of (POOL_SIZE / PAGE_SIZE)
#define PAGES_PER_REFILL 128

// The minimum number of consecutive pages ready to return to the
// OS required before calling munmap/VirtualFree. Higher values
// help mitigate against VMA growth on Linux and reduce expensive
// system calls on either OS at the cost of holding onto unneeded
// pages longer than strictly necessary.
#define MIN_PAGES_TO_FREE 1

// The maximum number of arenas allowed to exist at the same time
#define MAX_ARENAS 256

// The maximum number of large allocation pool lists allowed per
// arena regardless of processor count
#define MAX_LARGE_LISTS 8

// The maximum number of large allocation pools per each arena per
// CPU list. In other words, each arena including the default will
// have at most MAX_LARGE_LISTS * MAX_POOLS_PER_LIST large pools in
// use at any one time
#define MAX_POOLS_PER_LIST 3

// The number of bits matched at the root level of
// the page pool radix tree. Current x86_64 hardware supports only
// 48-bits in a pointer. Assuming POOL_SIZE is kept at its default
// value of 4MB then 26 bits total need to be tracked.
// Depending on build and processor, Windows might only supports 44-bit
// pointers, but go ahead and pretend it will always use 48 too
#define ROOT_BITS 8
#define STEM_COUNT (ONE64 << ROOT_BITS)

// The number of bits matched at the intermediate level of the page pool
// radix tree
#define STEM_BITS 8
#define LEAVES_PER_STEM (ONE64 << STEM_BITS)

// The number of bits matched at the leaf level of the page pool radix tree
#define LEAF_BITS (48 - ROOT_BITS - STEM_BITS - POOL_SIZE_BITS)
#define POOLS_PER_LEAF (ONE64 << LEAF_BITS)

/*** Compiler compatibility ***/
// Disable warning about unused size parameter in non-profiling mode
#define __attrUnusedParam __attribute__((unused))

/*** Alignment control constants and macros ***/

#ifdef FF_EIGHTBYTEALIGN
// Defines the minimum alignment
#define MIN_ALIGNMENT 8

// The number of small allocation bins in a thread cache when using 8-byte
// alignment
#define BIN_COUNT 45

// Used by init_tcache to indicate the inflection point between evenly spaced
// bins and bins spaced by maximum packing
#define BIN_INFLECTION 19

// Rounds requested allocation size up to the next multiple of 8
#define ALIGN_SIZE(SIZE) ((SIZE + SEVEN64) & ~SEVEN64)

// Select the bin to allocate from based on the size. Below 208 bytes, bins are
// every 8 bytes. Above 208, bins are unevenly spaced based on the maximal size
// that divides into PAGE_SIZE for a given number of slots then rounded down to
// the nearest multiple of 8
#define GET_BIN(SIZE) (SIZE <= 208 ? BIN_COUNT - (SIZE >> 3) : PAGE_SIZE / SIZE)

#else
// Defines the minimum alignment
#define MIN_ALIGNMENT 16

// The number of small allocation bins in a thread cache when using 16-byte
// alignment
#define BIN_COUNT 32

// Used by init_tcache to indicate the inflection point between evenly spaced
// bins and bins spaced by maximum packing
#define BIN_INFLECTION 13

// Rounds requested allocation size up to the next multiple of 16
#define ALIGN_SIZE(SIZE) (SIZE <= 8 ? 8 : ((SIZE + FIFTEEN64) & ~FIFTEEN64))

// Select the bin to allocate from based on the size. Allocations smaller than
// eight bytes always come from the eight byte bin. Otherwise, below 304 bytes,
// bins are every 16 bytes. Above 304, bins are unevenly spaced based on the
// maximal size that divides into PAGE_SIZE for a given number of slots then
// rounded down to the nearest multiple of 16
#define GET_BIN(SIZE) (SIZE <= 8 ? 0 : SIZE <= 304 ? BIN_COUNT - (SIZE >> 4) : PAGE_SIZE / SIZE)
#endif

#define ALIGN_TO(VALUE, ALIGNMENT) ((VALUE + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

/*** OS Intrinsic Translation Macros ***/
#define FFPOPCOUNT64 __builtin_popcountl
#define FFCOUNTLEADINGZEROS64 __builtin_clzl

/*** OS Threading Translation Macros ***/

// These macros substitute in the correct OS specific synchronization
// functions. Or when the library is being compiled for single threading,
// the macros disable the synchronization calls entirely eliminating the
// need for repetative #ifdefs

// Synchronization functions on Linux
#define FFEnterCriticalSection(LOCK) pthread_mutex_lock(LOCK)
#define FFLeaveCriticalSection(LOCK) pthread_mutex_unlock(LOCK)
#define FFTryEnterCriticalSection(LOCK) (pthread_mutex_trylock(LOCK) == 0)
#define FFInitializeCriticalSection(LOCK) pthread_mutex_init(LOCK, NULL)
#define FFDeleteCriticalSection(LOCK) pthread_mutex_destroy(LOCK)

// Atomic Operations
#define FFAtomicAnd(DEST, VALUE) __sync_and_and_fetch(&DEST, VALUE)
#define FFAtomicOr(DEST, VALUE) __sync_or_and_fetch(&DEST, VALUE)
#define FFAtomicAdd(DEST, VALUE) __sync_add_and_fetch(&DEST, VALUE)
#define FFAtomicSub(DEST, VALUE) __sync_sub_and_fetch(&DEST, VALUE)
#define FFAtomicIncrement(DEST) __sync_add_and_fetch(&DEST, 1)
#define FFAtomicDecrement(DEST) __sync_sub_and_fetch(&DEST, 1)
#define FFAtomicExchangeAdvancePtr(DEST, VALUE) __sync_fetch_and_add(&(DEST), (byte *)VALUE)
#define FFAtomicCompareExchangePtr(DEST, NEW, OLD) __sync_bool_compare_and_swap(DEST, OLD, NEW)

// Thread local storage functions
#define FFTlsAlloc(INDEX, FUNC) (pthread_key_create(&INDEX, FUNC) == 0)
#define FFTlsFree(INDEX) pthread_key_delete(INDEX)
#define TLS_CLEANUP_CALLBACK cleanup_thread

// Synchronization types
#define FFLOCK(NAME) pthread_mutex_t NAME;
#define FFLOCKSTATIC(NAME) static pthread_mutex_t NAME;

// Thread local storage key type
#define FFTLSINDEX pthread_key_t

#define FFMMAP_LENGTH (1024UL * 1024UL * 1024UL * 1024UL * 10)

#ifdef CONFIG_SECURITY_PKRU
extern int metadata_pkey;
extern atomic_int metadata_pkey_refcount;
#define ENTER_METADATA_REGION()                                                                                                                                \
	do {                                                                                                                                                   \
		atomic_fetch_add_explicit(&metadata_pkey_refcount, 1, memory_order_relaxed);                                                                   \
		pkey_set(metadata_pkey, 0);                                                                                                                    \
	} while (0)
#define EXIT_METADATA_REGION()                                                                                                                                 \
	do {                                                                                                                                                   \
		if (atomic_fetch_sub_explicit(&metadata_pkey_refcount, 1, memory_order_relaxed) == 1) {                                                        \
			pkey_set(metadata_pkey, PKEY_DISABLE_WRITE);                                                                                           \
		}                                                                                                                                              \
	} while (0)
#else
#define ENTER_METADATA_REGION() ((void)0)
#define EXIT_METADATA_REGION() ((void)0)
#endif

/*** Metadata Structures ***/

// When a page allocates objects smaller than 64 bytes, interpret the
// bitmap field in the page map as a pointer to an array of bitmaps.
// Otherwise, the field is the bitmap
union bitmap_t {
	uint64_t single;
	uint64_t *array;
};

// A page map holds the metadata about a page that has been
// allocated from a small allocation page pool
struct pagemap_t {
	// The starting address of the page. Guaranteed to be page aligned
	byte *start;

	// The size of allocations on this page; always a multiple of 8
	size_t allocSize;

	// Individual allocations on the page are tracked by setting
	// or clearing the corresponding bit in the bitmap
	union bitmap_t bitmap;
#ifdef CONFIG_ENABLE_GC
	union bitmap_t markmap;
	char delta;
#endif
};

// Interprets the metadata allocation for a pool as either and array
// of page maps (small allocation pools) or an array of pointers to
// the allocations (large allocation pools)
union tracking_t {
	struct pagemap_t *pageMaps;
	uintptr_t *allocations;
};

// A page pool is an initially contiguous region of memory
// from which individual pages are assigned to the thread
// cache's bins. "Holes" in the pool will develop over time
// when enough allocations have been freed that entire pages
// can be returned to the OS
struct pagepool_t {
	// The starting address of the pool. This value is constant
	// and is not incremented even if the initial page is freed
	byte *start;

	// The final address (exclusive) of the pool
	byte *end;

	// The starting address of the next unallocated page in the pool
	byte *nextFreePage;

	// Pool metadata - either an array of page maps or of allocation pointers
	union tracking_t tracking;

	// The index of the next pointer in a large pool to be allocated.
	// The pointer in this slot is not yet allocated, but it
	// is needed so that the size of the last allocated
	// pointer can still be computed
	size_t nextFreeIndex;

	// The address of the first page not yet freed
	byte *startInUse;

	// The address of the free page block that is continguous to the end of the
	// pool
	byte *endInUse;

	// The arena this pool is a part of
	struct arena_t *arena;

	// Critical section used to lock certain updates on the pool
	FFLOCK(poolLock)
};

// All small (less than half a page) allocations are assigned to a
// size bin based on maximum packing of similar sizes. All allocations
// on a single page are in the same bin.
struct bin_t {
	// Pointer to the next free slot for allocation
	byte *nextAlloc;

	// The size of allocations in this bin. Always a multiple of 8
	size_t allocSize;

	// The number of allocations made so far in this bin. It is
	// reset to 0 when the page is filled and a new page is
	// assigned to the bin
	size_t allocCount;

	// The maximum number of allocations that can be made on one
	// page in this bin
	size_t maxAlloc;

	// Points to the page map object with the tracking bitmap
	struct pagemap_t *page;

#ifdef CONFIG_MEMORY_DEBUG
	// The cummulative number of allocations made from this bin
	// across all pages
	size_t totalAllocCount;
#endif
};

// Each thread is given its own cache of pages to allocate from
struct threadcache_t {
	// The array of small allocation bins for this thread
	struct bin_t bins[BIN_COUNT];

	// To reduce round trips to the page pool, a small number of
	// blank pages are assigned to the thread cache to add to a
	// bin when it gets full. This points to the next available
	// free page
	struct pagemap_t *nextUnusedPage;

	// The end address (exclusive) of the range of free pages
	// available to the cache
	struct pagemap_t *endUnusedPage;

	// The arena this thread cache allocates from and the source of
	// its free pages
	struct arena_t *arena;
};

// A leaf node in a radix tree that points to a page pool
struct radixleaf_t {
	// Radix leaf node has two arrays, one for start and one for end.
	// The reason is that we can't assume that each pool allocation
	// will be POOL_SIZE aligned (and in fact for ASLR purposes it's
	// better that they aren't). Therefore, looking only at the high
	// order bits of a pointer, we can't tell if its from a pool that
	// starts in the middle of the prefix or ends there

	// Pointers to pools that start on the matching prefix
	struct pagepool_t *poolStart[POOLS_PER_LEAF];

	// Pointers to pools that end on the matching prefix
	struct pagepool_t *poolEnd[POOLS_PER_LEAF];
};

// Intermediate node in a radix tree
struct radixstem_t {
	struct radixleaf_t *leaves[LEAVES_PER_STEM];
};

// Root node of the page pool radix tree
struct radixroot_t {
	struct radixstem_t *stems[STEM_COUNT];
};

// Node in a list of allocation pools
struct poollistnode_t {
	// Pointer to the next node in the list
	struct poollistnode_t *next;

	// Pointer to an allocation page pool
	struct pagepool_t *pool;
};

#ifdef CONFIG_MEMORY_DEBUG
struct ffprofiling_struct_per_size {
	size_t allocCount;
	size_t freeCount;
	size_t BytesRequested;
	size_t BytesAllocated;
};

typedef struct ffprofiling_struct {
	// The number of times that ffmalloc has been called including
	// indirectly through ffrealloc, ffcalloc, or similar
	size_t mallocCount;

	// The number of times that ffrealloc has been called
	size_t reallocCount;

	// The number of times that ffreallocarray has been called
	size_t reallocarrayCount;

	// The number of times that ffcalloc has been called
	size_t callocCount;

	// The number of times that fffree has been called including
	// indirectly through ffrealloc
	size_t freeCount;

	// The number of times that ffposix_memalign has been called
	size_t posixAlignCount;

	// The number of times that ffallign_alloc has been called
	size_t allocAlignCount;

	// The number of times that mark has been run
	size_t markCount;

	// The number of times that sweep has been run
	size_t sweepCount;

	// The total number of bytes requested by as measured by ffmalloc
	// This will exclude whenever ffrealloc is called with a size less
	// than the current allocation size
	size_t totalBytesRequested;

	// The total number of bytes in memory consumed by allocations after
	// adjusting requested sizes upwards for required alignments
	size_t totalBytesAllocated;

	// The number of bytes in memory associated with unfreed allocations
	// at this point in time. This does not include "lost" bytes that have
	// been fffree'd but whose pages have not yet been returned to the OS
	size_t currentBytesAllocated;

	// The highest seen value for currentBytesAllocated
	size_t maxBytesAllocated;

	// The sum of the sizes of all allocation ranges currently in use even
	// if not yet faulted and mapped. Excludes pages mapped for metadata
	size_t currentOSBytesMapped;

	// The highest value for currentOSBytesMapped seen
	size_t maxOSBytesMapped;
	size_t reallocCouldGrow;

	// profile per size
	struct ffprofiling_struct_per_size small;
	struct ffprofiling_struct_per_size large;
	struct ffprofiling_struct_per_size jumbo;

	// profile GC time
	unsigned long long mark_time;
	unsigned long long sweep_time;

} ffprofile_t;
#endif

// An arena is a collection of large and small pools that allocations can be
// specifically drawn from using the ffmalloc extended API. Arenas allow the
// calling application to free all allocations from that arena with one call
// which benefits performance through fewer system calls to VirtualFree or
// munmap and simplifies memory management since each allocation doesn't have
// to be individually freed. Allocations from the standard malloc API come
// from a default arena, but that arena is persistent and allocations need to
// be individually freed.
struct arena_t {
	// List of small pools created in this arena. The head of the list is
	// the pool currently being allocated from
	struct poollistnode_t *volatile smallPoolList;

	// Array of lists of large pools created in this arena. Typically one
	// list per CPU in the system. The head of the list is usually where
	// allocations come from but pools further down will be searched for
	// available space if the first node is locked by another thread
	struct poollistnode_t *volatile largePoolList[MAX_LARGE_LISTS];

	// List of jumbo allocation pools create in this arena
	struct poollistnode_t *volatile jumboPoolList;

	void *gc_start_free_pointers[BIN_COUNT];
	spinlock_t *gc_lock[BIN_COUNT];

	// Index to get the correct thread local storage value for this arena
	// which holds the pointer to the thread cache for invoking thread
	FFTLSINDEX tlsIndex;

	// Lock that protects modifying the small pool list header
	FFLOCK(smallListLock)

	// Locks that protect each large list
	FFLOCK(largeListLock[MAX_LARGE_LISTS])

#ifdef CONFIG_MEMORY_DEBUG
	// Structure to hold arena usage statistics
	ffprofile_t profile;
#endif
};

// Reinterprets freed metadata allocations as a pointer to the next
// available free block
struct usedmd_t {
	byte *next;
};

// When USE_FF_PREFIX is not defined, the public API will match the names
// of the standard allocation functions. Useful when using LD_PRELOAD to
// force an existing binary on Linux to use this allocator
#define ffmalloc malloc
#define ffrealloc realloc
#define ffreallocarray reallocarray
#define ffcalloc calloc
#define fffree free
#define ffmemalign memalign
#define ffposix_memalign posix_memalign
#define ffaligned_alloc aligned_alloc
#define ffmalloc_usable_size malloc_usable_size
#ifdef FF_WRAP_MMAP
#define ffmmap mmap
#define ffmunmap munmap
#endif

/*** Custom types for the extended API functions ***/

// The returned success or error message from an extended API function
typedef unsigned int ffresult_t;

// Handle to a custom arena
typedef unsigned int ffarena_t;

/*** Extended API error codes ***/

// Returned when the function completed successfully. Any out parameters will
// have valid values
#define FFSUCCESS 0

// The supplied arena key was not created by ffcreate_arena or has already
// been destroyed
#define FFBAD_ARENA 1U

// No additional arenas can be created because the limit has been reached
#define FFMAX_ARENAS 2U

// An additional arena could not be created because FFMalloc could not
// get the required pages allocated from the OS
#define FFNOMEM 3U

// An additional arena could not be created because a system limitation
// other than memory was reached, probably thread local storage indexes
#define FFSYS_LIMIT 4U

// A supplied parameter could not be validated, usually an out parameter
// pointer that is NULL
#define FFBAD_PARAM 5U

// Declare standard malloc API functions
// Inside the alloc_alias.c
#define PREALLOC(func) ota_##func
void *PREALLOC(malloc)(size_t size);
void *PREALLOC(realloc)(void *ptr, size_t size);
void *PREALLOC(reallocarray)(void *ptr, size_t nmemb, size_t size);
void *PREALLOC(calloc)(size_t nmemb, size_t size);
void PREALLOC(free)(void *ptr);
void *PREALLOC(memalign)(size_t alignment, size_t size);
int PREALLOC(posix_memalign)(void **ptr, size_t alignment, size_t size);
void *PREALLOC(aligned_alloc)(size_t alignment, size_t size);
size_t PREALLOC(malloc_usable_size)(const void *ptr);

// libc malloc API functions
// Inside the alloc_entry.c
void *(*libc_malloc)(size_t);
void (*libc_free)(void *);
void *(*libc_realloc)(void *, size_t);
void *(*libc_reallocarray)(void *, size_t, size_t);
void *(*libc_calloc)(size_t, size_t);
void *(*libc_aligned_alloc)(size_t, size_t);
void *(*libc_memalign)(size_t, size_t);
int (*libc_posix_memalign)(void **, size_t, size_t);
size_t (*libc_malloc_usable_size)(const void *ptr);

/*** Optionally wrap mmap ***/
#ifdef FF_WRAP_MMAP
void *ffmmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int ffmunmap(void *addr, size_t length);
#endif

/*** Declare FFMalloc extended API ***/

// Duplicates a string. Memory is allocated from ffmalloc so the caller is
// responsible for fffreeing the string
char *ffstrdup(const char *s);

// Duplicates the first n characters of a string. Memory is allocated
// from ffmalloc so the caller must fffree the string when finished
char *ffstrndup(const char *s, size_t n);

// Creates a new allocation arena
ffresult_t ffcreate_arena(ffarena_t *newArena);

// Destroys an allocation arena and frees all memory allocated from it
ffresult_t ffdestroy_arena(ffarena_t arenaKey);

// Allocates memory in the same manner as ffmalloc except from a specific arena
ffresult_t ffmalloc_arena(ffarena_t arenaKey, void **ptr, size_t size);

#ifdef CONFIG_MEMORY_DEBUG
// Gets usage statistics for ffmalloc excluding custom arenas
ffresult_t ffget_statistics(ffprofile_t *profileDestination);

// Gets usage statistics for a custom arena
ffresult_t ffget_arena_statistics(ffprofile_t *profileDestination, ffarena_t arenaKey);

// Outputs the same statistics as ffget_statistics to the supplied file
void ffprint_statistics(FILE *const dest);

// Prints current usage statistics to the specified file each time the
// cummulative number of calls to malloc/calloc/realloc (that caused a malloc)
// is a multiple of interval
void ffprint_usage_on_interval(FILE *const dest, unsigned int interval);
#endif

void fffree_all();
void ffdump_pool_details();
size_t ffget_pool_count();
void free_arena_map(void);

// Root node of radix tree containing all pools
struct radixroot_t poolTree;

// Array of arenas. The default arena used by the standard malloc API is
// at index 0
struct arena_t *volatile arenas[MAX_ARENAS];

// Search functions which are used in the garbage collections
struct threadcache_t *get_threadcache(struct arena_t *arena);
unsigned int get_large_list_index();
struct pagepool_t *find_pool_for_ptr(const byte *ptr);
int64_t find_small_ptr_allocated(const byte *ptr, const struct pagepool_t *pool, struct pagemap_t **pageMap);
int64_t find_small_ptr_unallocated(const byte *ptr, const struct pagepool_t *pool, struct pagemap_t **pageMap);
int64_t find_small_ptr_index(const byte *ptr, const struct pagepool_t *pool, struct pagemap_t **pageMap, bool *allocated);
size_t find_large_ptr(const byte *ptr, struct pagepool_t *pool, size_t *metadataIndex);
int find_large_ptr_unallocated(const byte *ptr, struct pagepool_t *pool);

void ota_init();
