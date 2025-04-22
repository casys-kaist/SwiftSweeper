#include "gc.h"
#include "debug.h"
#include "kmalloc.h"
#include "ota.h"
#include "sbpf/bpf.h"
#include "spin_lock.h"
#include "vmem.h"
#include <pthread.h>
#include "kthread.h"
#include <errno.h>
#include <linux/bpf.h>
#include <memory.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/mman.h>

#ifdef CONFIG_MEMORY_DEBUG
struct timeval start, end;
#endif // CONFIG_MEMORY_DEBUG

static uint64_t prev_gc_time = 0;
uint64_t total_large_allocated_memory = 0;
uint64_t total_large_used_memory = 0;
uint64_t total_small_allocated_memory = 0;
uint64_t total_small_used_memory = 0;
uint64_t total_dangling_pointer = 0;

static void gc_sweep(void *from, void *to);

#if defined(CONFIG_ENABLE_CONCURRENT_GC) || defined(CONFIG_CONCURRENT_GC_PREFETCH_SIZE)
#ifndef CONFIG_ENABLE_GC
#error "Please disable the GC configurations at the kconfig.h"
#endif
#endif

static bool gc_mark_conservative_linear_posix(void *from, void *to, bool update_low_water);
static bool gc_mark_conservative_linear(void *from, void *to);

static __attribute__((noinline)) void *gc_stacktop(void)
{
	void *stacktop;
	asm("movq %%rsp, %0" : "=r"(stacktop));
	return stacktop;
}

static void *gc_stackbottom(void)
{
	void *stackbottom;
	stackbottom = (void *)gc_stacktop();
	stackbottom = (void *)(((uintptr_t)(stackbottom + PAGE_SIZE) / PAGE_SIZE) * PAGE_SIZE);
	unsigned char vec;
	while (mincore(stackbottom, PAGE_SIZE, &vec) == 0)
		stackbottom += PAGE_SIZE;
	if (errno != ENOMEM)
		return false;
	stackbottom -= sizeof(void *);
	return stackbottom;
}

// flush_args returns 0 when successful and 1 when failed
static inline int sbpf_mprotect(void *from, size_t len, int prot)
{
	void *flush_args[4] = { (void *)PTE_SET_PROT, from, (void *)len, (void *)(uint64_t)prot };
	return sbpf_call_function(page_ops_bpf, &flush_args[0], sizeof(void *) * 4);
}

static int fine_grained_pgprot(void *from, void *to, int pgprot)
{
	size_t stem_index_from = (uintptr_t)from >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leaf_index_from = ((uintptr_t)from >> (POOL_SIZE_BITS + LEAF_BITS) & (LEAVES_PER_STEM - 1));
	size_t l3_index_from = ((uintptr_t)from >> (POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1));
	size_t stem_index_to = (uintptr_t)to >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leaf_index_to = ((uintptr_t)to >> (POOL_SIZE_BITS + LEAF_BITS) & (LEAVES_PER_STEM - 1));
	int err = 0;

	for (size_t l1 = stem_index_from; l1 <= stem_index_to; l1++) {
		if (poolTree.stems[l1] != NULL) {
			size_t l2_index_start = l1 == stem_index_from ? leaf_index_from : 0;
			size_t l2_index_end = l1 == stem_index_to ? leaf_index_to : LEAVES_PER_STEM;
			for (size_t l2 = l2_index_start; l2 <= l2_index_end; l2++) {
				struct radixleaf_t *leaf = poolTree.stems[l1]->leaves[l2];
				if (leaf != NULL) {
					for (size_t l3 = l3_index_from; l3 < POOLS_PER_LEAF; l3++) {
						if (leaf->poolStart[l3] != NULL) {
							struct pagepool_t *pool = leaf->poolStart[l3];
							if (pool->nextFreeIndex == SIZE_MAX) {
								// Small page
								byte *lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
								for (size_t x = 0; x < (lastFreePage - pool->start) / PAGE_SIZE; x++) {
									// Ptr has pool (not inside the freed pool). Check allocation.
									struct pagemap_t *pageMap = &pool->tracking.pageMaps[x];
									size_t alloc_size = pageMap->allocSize;
									if (alloc_size == 0)
										continue;
									// Page is already returned to the OS.
									if ((alloc_size & SEVEN64) == 7)
										continue;
									alloc_size &= ~SEVEN64;
									void *ptr = (void *)(pageMap->start);
									err = sbpf_mprotect(ptr, PAGE_SIZE, BPF_SBPF_PROT_EXEC);
									if (err != 0)
										goto ret;
								}
							} else {
								// Large and Jumbo.
								err = sbpf_mprotect(pool->start, (unsigned long)pool->end - (unsigned long)pool->start,
										    BPF_SBPF_PROT_EXEC);
								if (err != 0)
									goto ret;
							}
						}
					}
					l3_index_from = 0;
				}
			}
		}
	}

ret:
	return err;
}

static int gc_set_pgprot(void *from, void *to, unsigned long pgprot)
{
	from = (void *)PAGE_ALIGN_DOWN((unsigned long)from);
	to = (void *)PAGE_ALIGN((unsigned long)to);

	ASSERT(from < to);

	return sbpf_mprotect(from, (byte *)to - (byte *)from, pgprot);
}

// Determines if garbage collection should run based on memory fragmentation.
// Returns 1 if GC should run, 0 otherwise.
#ifdef CONFIG_ENABLE_GC
static inline uint64_t rdtsc()
{
	uint32_t lo, hi;
	// Use the RDTSC instruction to read the current value of the time-stamp counter
	__asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
	return ((uint64_t)hi << 32) | lo;
}

static bool gc_should_run(void)
{
	clock_t current_time = rdtsc();
	double elapsed_time = (double)(current_time - prev_gc_time);
	double cur_frag_rate = 0;
	uint64_t total_allocated_memory = total_large_allocated_memory + total_small_allocated_memory;
	uint64_t total_used_memory = total_small_used_memory + total_small_used_memory;

	static double prev_frag_rate = 0;
	static uint64_t prev_total_allocated_memory = 0;
	static bool first_run = 1;
	static uint64_t sleep_time = CONFIG_GC_SLEEP_TIME_INTERVAL_MIN;

// If we enable the GC thread, we should consider that, GC thread execute GC more faster than piggyback GC.
// Thus to consider the malloc frequency, we should have to consider it manually.
#ifdef CONFIG_GC_THREAD
	static uint64_t gc_heap_size = 0;
	static uint64_t gc_run_count = 0;

	if (gc_run_count >= gc_heap_size) {
		gc_heap_size = total_allocated_memory / PAGE_SIZE;
		gc_run_count = 0;
	} else {
		gc_run_count++;
		return false;
	}
#endif

	if (likely(elapsed_time < sleep_time))
		return false;

	// Do not run GC if not enough memory is allocated or if the sleep time has not elapsed
	if (unlikely(total_allocated_memory < CONFIG_GC_SLEEP_MINIMUM_THRESHOLD))
		return false;

#ifdef CONFIG_FORCE_GC
	if (elapsed_time >= CONFIG_GC_SLEEP_TIME_INTERVAL_MIN) {
		if (unlikely(first_run)) {
			first_run = 0;
			prev_gc_time = current_time;
			return false;
		}

		goto mark;
	}
#endif

	// Calculate current fragmentation rate
	// cur_frag_rate = (double)(total_allocated_memory - total_used_memory) / total_allocated_memory;
	cur_frag_rate = (double)(total_small_allocated_memory - total_small_used_memory) / total_allocated_memory;

	/* Uncomments this sections, for the debugging. */
	// char buf[10];
	// gcvt(cur_frag_rate, 5, buf);
	// printk("gc start: total_allocated_large_memory %lu total_used_memory %lu\n", total_allocated_memory, total_small_used_memory);
	// printk("gc start: sleep time 0x%lx, ", sleep_time / CONFIG_GC_SLEEP_TIME_INTERVAL_MIN);
	// printk("fragmentation rate cur %s, ", buf);
	// gcvt(prev_frag_rate, 5, buf);
	// printk("prev %s\n", buf);

	if (cur_frag_rate >= CONFIG_GC_SLEEP_FORCE_THRESHOLD) {
		goto mark;
	}

	// Check if current fragmentation rate exceeds the threshold
	if (cur_frag_rate >= CONFIG_GC_SLEEP_FRAG_INTERVAL && cur_frag_rate - prev_frag_rate >= CONFIG_GC_SLEEP_FRAG_CHANGE_THRESHOLD) {
		// We consider the first GC as a special case.
		// The first GC is triggered when the memory is allocated for the initial application load.
		// Usually, fragmentation is high at the first GC, so we should not consider it as a significant change.
		if (unlikely(first_run)) {
			first_run = 0;
			prev_gc_time = current_time;
			return false;
		}

		goto mark;
		// printk("gc should be run\n");
	}

	// Perhaps an initially very large prev_frag_rate slows down the GC.
	// We should gently throttle the GC, but do not consider it a serious issue.
	// This is a heuristic to prevent the GC from running too frequently.
	if (total_allocated_memory > prev_total_allocated_memory) {
		prev_frag_rate -= CONFIG_GC_SLEEP_FRAG_CHANGE_THRESHOLD * (0.2);
	}

	prev_gc_time = current_time;
	sleep_time *= 2;
	sleep_time = sleep_time > CONFIG_GC_SLEEP_TIME_INTERVAL_MAX ? CONFIG_GC_SLEEP_TIME_INTERVAL_MAX : sleep_time;

	return false;

mark:
	prev_frag_rate = cur_frag_rate;
	prev_gc_time = current_time;
	prev_total_allocated_memory = total_allocated_memory;
	sleep_time = CONFIG_GC_SLEEP_TIME_INTERVAL_MIN;

#ifdef CONFIG_GC_DELTA_MARKING
	if (total_dangling_pointer > (total_small_allocated_memory * CONFIG_GC_DELTA_FULL_PATH_THRESHOLD)) {
		mm_get_active()->run_full_path = true;
	}
#endif

	return true;
}

static void gc_should_run_reset(void)
{
	prev_gc_time = rdtsc();
	mm_get_active()->run_full_path = false;
}

#ifdef CONFIG_TIME_BREAKDOWN
static struct timeval start, end1, end2;
static int count = 0;
static unsigned long total_mark_time, total_sweep_time;
#endif

static void *gc_run_mark_thread(void *data)
{
#ifdef CONFIG_TIME_BREAKDOWN
	gettimeofday(&start, NULL);
#endif
	struct mm_struct *mm = mm_get_active();
	static size_t count = 0;
	int ret = 0;
	bool force_full_path = false;
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.markCount);
#endif

	printk("gc mark start: from = %p, to = %p\n", mm->poolLowWater, mm->poolHighWater);

	gc_set_pgprot(mm->gc.from, mm->gc.to, BPF_SBPF_PROT_EXEC);
	gc_set_pgprot(mm->stacktop, mm->stackbottom, BPF_SBPF_PROT_EXEC);

	ret += gc_mark_conservative_linear(mm->stacktop, mm->stackbottom);
	ret += gc_mark_conservative_linear(mm->gc.from, mm->gc.to);

	ASSERT(!ret);

	gc_set_pgprot(mm->stacktop, mm->stackbottom, BPF_SBPF_PROT_RDWR);
	gc_set_pgprot(mm->gc.from, mm->gc.to, BPF_SBPF_PROT_RDWR);
	
#ifdef CONFIG_TIME_BREAKDOWN
	gettimeofday(&end1, NULL);
#endif

	gc_sweep(mm->gc.from, mm->gc.to);

#ifdef CONFIG_TIME_BREAKDOWN
	gettimeofday(&end2, NULL);
	count++;

	unsigned int marktime = (end1.tv_sec - start.tv_sec) * 1000 + (end1.tv_usec - start.tv_usec) / 1000;
	unsigned int sweeptime = (end2.tv_sec - end1.tv_sec) * 1000 + (end2.tv_usec - end1.tv_usec) / 1000;

	total_mark_time += marktime;
	total_sweep_time += sweeptime;

	printk("Total Mark time: %ld ms,  Mark time: %ld ms,  Total Sweep time: %ld ms,  Sweep time: %ld, count: %d\n", total_mark_time, total_mark_time / count, total_sweep_time, total_sweep_time / count, count);
#endif

	gc_should_run_reset();
	mm->is_gc_run = false;
#ifdef CONFIG_GC_DELTA_MARKING
	mm->gc.prev_hot_page = mm->gc.hot_page;
	mm->gc.hot_page = mm->gc.to;
#endif

	debug_printk("gc mark end: from = %p, to = %p %d\n", mm->poolLowWater, mm->poolHighWater, count);

	return NULL;
}

void gc_run_mark()
{
	struct mm_struct *mm = mm_get_active();

#ifdef CONFIG_ENABLE_GC
	spin_lock(&mm->mm_lock);
	if (gc_should_run() && !mm->is_gc_run) {
		mm->is_gc_run = true;
		spin_unlock(&mm->mm_lock);
		mm->gc.from = mm_get_active()->poolLowWater;
		mm->gc.to = mm_get_active()->poolHighWater;
		mm->gc.hot_page = mm->gc.hot_page < mm->gc.from ? mm->gc.from : mm->gc.hot_page;
		mm->gc.offset = 0;
		mm->stackbottom = gc_stackbottom();
		mm->stacktop = gc_stacktop();
#if defined(CONFIG_ENABLE_CONCURRENT_GC) && !defined(CONFIG_GC_THREAD)
		gc_set_pgprot(mm->gc.from, mm->gc.to, BPF_SBPF_PROT_EXEC);
#endif

#ifdef CONFIG_GC_THREAD
		kthread_create(gc_run_mark_thread, NULL, "mark_thread");
#endif
	} else {
		spin_unlock(&mm->mm_lock);
	}

#ifdef CONFIG_GC_THREAD
#else
	if (!sleep_gc) {
		sleep_gc = gc_run_mark_piggyback();
	}
#endif
#endif
}

static void gc_push_free_list(struct arena_t *arena, void *ptr, size_t size, struct pagemap_t *pagemap)
{
	struct bin_t *bin;
	struct free_list_entry *entry = ptr;

	size = ALIGN_SIZE(size);
	ASSERT(size >= sizeof(struct free_list_entry));
	ASSERT(size <= HALF_PAGE);

	spin_lock(arena->gc_lock[GET_BIN(size)]);
	entry->next_ptr = arena->gc_start_free_pointers[GET_BIN(size)];
	entry->pagemap = pagemap;
	arena->gc_start_free_pointers[GET_BIN(size)] = entry;
	spin_unlock(arena->gc_lock[GET_BIN(size)]);

	update_used_small_memory(size);
}

void *gc_pop_free_list(struct arena_t *arena, size_t size)
{
#ifdef CONFIG_MEMORY_DEBUG
	gettimeofday(&start, NULL);
#endif
	struct free_list_entry *entry;
	struct bin_t *bin;
	void *ptr = NULL;
	struct pagemap_t *pagemap;

	size = ALIGN_SIZE(size);

	if (size <= HALF_PAGE) {
		spin_lock(arena->gc_lock[GET_BIN(size)]);
	retry:
		entry = arena->gc_start_free_pointers[GET_BIN(size)];
		if (entry == NULL) {
			spin_unlock(arena->gc_lock[GET_BIN(size)]);
			goto done;
		}

		pagemap = entry->pagemap;
		ASSERT(entry->next_ptr != entry);
		ASSERT(pagemap != NULL);
		ASSERT(((byte *)entry - pagemap->start) % (pagemap->allocSize & ~SEVEN64) == 0);
		ASSERT(size <= (pagemap->allocSize & ~SEVEN64));
		ASSERT((pagemap->allocSize & ~SEVEN64) <= HALF_PAGE);

		uint64_t index = ((byte *)entry - pagemap->start) / (pagemap->allocSize & ~SEVEN64);
		ASSERT(index >= 0);

		// Page is freed page.
		if (pagemap->allocSize & 1) {
			arena->gc_start_free_pointers[GET_BIN(size)] = entry->next_ptr;
			goto retry;
		}

#ifndef CONFIG_NDEBUG
		if (size < 64) {
			uint64_t array = (index >> 6);
			uint64_t pos = index - (array << 6);
			uint64_t *bitmap = pagemap->bitmap.array;
			ASSERT(bitmap[array] & (ONE64 << pos));
		} else {
			ASSERT(pagemap->bitmap.single & (ONE64 << index));
		}
#endif

		ptr = entry;
		arena->gc_start_free_pointers[GET_BIN(size)] = entry->next_ptr;
		spin_unlock(arena->gc_lock[GET_BIN(size)]);

		// Clear the metadata at the entry.
		memset(ptr, 0, sizeof(struct free_list_entry));
	}

done:
#ifdef CONFIG_MEMORY_DEBUG
	gettimeofday(&end, NULL);
	FFAtomicAdd(arena->profile.sweep_time, (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
#endif

	return ptr;
}

static inline void trigger_gc(unsigned long start, unsigned long end)
{
#ifdef CONFIG_DEBUG_GC
	printk("trigger gc start 0x%lx end 0x%lx\n", start, end);
#endif
	if (start == end)
		return;

	void *flush_args[5] = {
		(void *)PTE_GC, (void *)start, (void *)(end - start), &poolTree, (void *)mm_get_active(),
	};
	sbpf_call_function(page_ops_bpf, &flush_args[0], sizeof(void *) * 5);
}

static bool gc_mark_conservative_linear(void *from, void *to)
{
	trigger_gc((unsigned long)from, (unsigned long)to);
	return true;
}

/* 
 * Mark the pointers in the range [from, to) as reachable.
* This function is conservative, and linear. May be slow than the recurive, but more resilient to stack overflow and time.
* Argument bytes should be equal or greater than the POOL_SIZE.
*/
static bool gc_mark_conservative_linear_posix(void *from, void *to, bool update_low_water)
{
#ifdef CONFIG_DEBUG_GC
	size_t mark_cnt = 0;
	size_t total_mark_cnt = 0;
	printk("gc_mark: from = %p, to = %p\n", from, to);
#endif
#ifdef CONFIG_MEMORY_DEBUG
	gettimeofday(&start, NULL);
#endif
	bool ret = false;

	size_t stem_index_from = ((uintptr_t)from >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS));
	size_t leaf_index_from = ((uintptr_t)from >> (POOL_SIZE_BITS + LEAF_BITS) & (LEAVES_PER_STEM - 1));
	size_t l3_index_from = ((uintptr_t)from >> (POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1));
	size_t stem_index_to = (uintptr_t)to >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leaf_index_to = ((uintptr_t)to >> (POOL_SIZE_BITS + LEAF_BITS) & (LEAVES_PER_STEM - 1));
	bool is_first = update_low_water;
	size_t search_bytes = 0;

	// printk("gc_mark: stem_index_from = %lu, leaf_index_from = %lu, l3_index_from = %lu\n", stem_index_from, leaf_index_from, l3_index_from);
	// printk("gc_mark: stem_index_to = %lu, leaf_index_to = %lu\n", stem_index_to, leaf_index_to);

	for (size_t l1 = stem_index_from; l1 <= stem_index_to; l1++) {
		if (poolTree.stems[l1] == NULL) {
			search_bytes += LEAVES_PER_STEM * POOLS_PER_LEAF * POOL_SIZE;
			l3_index_from = 0;
			continue;
		}

		size_t l2_index_start = l1 == stem_index_from ? leaf_index_from : 0;
		size_t l2_index_end = l1 == stem_index_to ? leaf_index_to : LEAVES_PER_STEM;
		for (size_t l2 = l2_index_start; l2 <= l2_index_end; l2++) {
			struct radixleaf_t *leaf = poolTree.stems[l1]->leaves[l2];
			if (leaf == NULL) {
				search_bytes += POOLS_PER_LEAF * POOL_SIZE;
				l3_index_from = 0;
				continue;
			}

			for (size_t l3 = l3_index_from; l3 < POOLS_PER_LEAF; l3++) {
				search_bytes += POOL_SIZE;
				if (search_bytes > ((uint64_t)to - (uint64_t)from))
					goto done;
				if (leaf->poolStart[l3] == NULL)
					continue;

				struct pagepool_t *pool = leaf->poolStart[l3];
				FFEnterCriticalSection(&pool->poolLock);
				if (pool->nextFreeIndex == SIZE_MAX) {
					// Small allocation
					byte *lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
					byte *prev_page = pool->start;
					if (is_first) {
						is_first = false;
						mm_get_active()->poolLowWater = prev_page;
					}
					trigger_gc((unsigned long)prev_page, (unsigned long)lastFreePage);
				} else {
					// Large and Jumbo.
					if (is_first) {
						is_first = false;
						mm_get_active()->poolLowWater = pool->start;
					}
					trigger_gc((unsigned long)pool->start, (unsigned long)pool->end);
				}
				FFLeaveCriticalSection(&pool->poolLock);
			}
			l3_index_from = 0;
		}
	}

	ret = true;
done:
#ifdef CONFIG_MEMORY_DEBUG
	gettimeofday(&end, NULL);
	FFAtomicAdd(arenas[0]->profile.mark_time, (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
#endif
#ifdef CONFIG_DEBUG_GC
	printk("gc_mark: total mark cnt = %lu, marked cnt = %lu\n", total_mark_cnt, mark_cnt);
#endif

	return ret;
}

/* 
 * Sweep the pointers in the range [from, to) as reachable.
*/
static void gc_sweep(void *from, void *to)
{
#ifdef CONFIG_DEBUG_GC
	uint64_t total_sweep_cnt = 0;
	uint64_t sweep_cnt = 0;
	printk("gc_sweep: from = 0x%lx, to = 0x%lx\n", from, to);
#endif
#ifdef CONFIG_MEMORY_DEBUG
	FFAtomicIncrement(arenas[0]->profile.sweepCount);
	gettimeofday(&start, NULL);
#endif

	size_t stem_index_from = (uintptr_t)from >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leaf_index_from = ((uintptr_t)from >> (POOL_SIZE_BITS + LEAF_BITS) & (LEAVES_PER_STEM - 1));
	size_t stem_index_to = (uintptr_t)to >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS);
	size_t leaf_index_to = ((uintptr_t)to >> (POOL_SIZE_BITS + LEAF_BITS) & (LEAVES_PER_STEM - 1));
	bool is_first = true;

	total_dangling_pointer = 0;

	for (size_t l1 = stem_index_from; l1 <= stem_index_to; l1++) {
		if (poolTree.stems[l1] != NULL) {
			size_t l2_index_start = l1 == stem_index_from ? leaf_index_from : 0;
			size_t l2_index_end = l1 == stem_index_to ? leaf_index_to : LEAVES_PER_STEM;
			for (size_t l2 = l2_index_start; l2 <= l2_index_end; l2++) {
				struct radixleaf_t *leaf = poolTree.stems[l1]->leaves[l2];
				if (leaf != NULL) {
					for (size_t l3 = 0; l3 < POOLS_PER_LEAF; l3++) {
						if (leaf->poolStart[l3] != NULL) {
							struct pagepool_t *pool = leaf->poolStart[l3];
							ENTER_METADATA_REGION();
							FFEnterCriticalSection(&pool->poolLock);

							// if (is_first) {
							// 	is_first = false;
							// 	mm_get_active()->poolLowWater = pool->start;
							// }

							if (pool->nextFreeIndex == SIZE_MAX) {
								// Small page
								byte *lastFreePage = pool->end < pool->nextFreePage ? pool->end : pool->nextFreePage;
								for (size_t x = 0; x < (lastFreePage - pool->start) / PAGE_SIZE; x++) {
									// Ptr has pool (not inside the freed pool). Check allocation.
									struct pagemap_t *pageMap = &pool->tracking.pageMaps[x];
									size_t alloc_size = pageMap->allocSize;
#ifdef CONFIG_GC_DELTA_MARKING
									if (pageMap->delta == 1) {
										pageMap->delta = 0;
										continue;
									}
#endif
									// Skip if the page is already freed or returned to the OS.
									// Skip if the page is not marked as full.
									if (alloc_size == 0 || ((alloc_size & SEVEN64) != 4))
										continue;

									alloc_size &= ~SEVEN64;
#ifdef CONFIG_DEBUG_GC
									total_sweep_cnt += PAGE_SIZE / sizeof(void *);
#endif
									// Now pointer is allocated.
									if (alloc_size < 64) {
										size_t bitmaps = (PAGE_SIZE / (alloc_size & ~SEVEN64)) >> 6;
										for (size_t index = 0; index < bitmaps * 64; index++) {
											uint64_t array = index >> 6;
											uint64_t pos = index - (array << 6);
											bool marked = pageMap->markmap.array[array] & (ONE64 << pos);
											bool allocated = pageMap->bitmap.array[array] & (ONE64 << pos);
											if (marked || allocated) {
												if (!allocated)
													total_dangling_pointer++;
												continue;
											}
											// We found the valid pointer. Sweep it as free.
											void *ptr = (void *)(pageMap->start + index * (alloc_size & ~SEVEN64));
#ifdef CONFIG_DEBUG_GC
											sweep_cnt += alloc_size / sizeof(void *);
#endif
											// TODO! Temporary disable 8 byte for sweeping due to SPEC CPU 2017.
											// Possible leak of the memory.
											if (alloc_size >= sizeof(struct free_list_entry)) {
												pageMap->bitmap.array[array] |= (ONE64 << pos);
												gc_push_free_list(arenas[0], ptr, alloc_size, pageMap);
											}
#ifdef CONFIG_GC_DELTA_MARKING
											// Reset markmap.
											if (mm_get_active()->run_full_path) {
												pageMap->markmap.array[array] = 0;
											}
#else
											pageMap->markmap.array[array] = 0;
#endif
										}
									} else {
										size_t singles = PAGE_SIZE / (alloc_size & ~SEVEN64);
										for (size_t index = 0; index < singles; index++) {
											// Ptr has pool (not inside the freed pool). Check allocation.
											// We found the valid pointer. Sweep it as free.
											bool marked = pageMap->markmap.single & (ONE64 << index);
											bool allocated = pageMap->bitmap.single & (ONE64 << index);
											if (marked || allocated) {
												if (!allocated)
													total_dangling_pointer++;
												continue;
											}
											void *ptr = (void *)(pageMap->start + index * (alloc_size & ~SEVEN64));
#ifdef CONFIG_DEBUG_GC
											sweep_cnt += alloc_size / sizeof(void *);
#endif
											pageMap->bitmap.single |= (ONE64 << index);
											gc_push_free_list(arenas[0], ptr, alloc_size, pageMap);
										}
#ifdef CONFIG_GC_DELTA_MARKING
										// Reset markmap.
										if (mm_get_active()->run_full_path) {
											pageMap->markmap.single = 0;
										}
#else
										pageMap->markmap.single = 0;
#endif
									}
								}
							} else if (pool->nextFreeIndex < SIZE_MAX - 1) {
#ifndef CONFIG_GC_ALLOW_CYCLIC
								for (size_t index = 0; index < pool->nextFreeIndex; index++) {
									if ((pool->tracking.allocations[index] & 3) == 1) {
										// Freed, but not returend to the OS.
										// We lazily zeroing large pages in the gc_sweep,
										// instead of zeroing it in the free function.
										// This is because zeroing large pages in the free function
										// can cause a performance issue (E.g., GCC in SPEC CPU 2006).
										size_t alloc_size = ((pool->tracking.allocations[index + 1] & ~SEVEN64) -
												     (pool->tracking.allocations[index] & ~SEVEN64));
										memset((void *)pool->tracking.allocations[index], 0,
										       alloc_size / sizeof(void *));
									}
								}
#endif
							}
							FFLeaveCriticalSection(&pool->poolLock);
							EXIT_METADATA_REGION();
						}
					}
				}
			}
		}
	}

#ifdef CONFIG_MEMORY_DEBUG
	gettimeofday(&end, NULL);
	FFAtomicAdd(arenas[0]->profile.sweep_time, (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));
#endif
#ifdef CONFIG_DEBUG_GC
	printk("gc_sweep: total sweep cnt = %lu, sweeped cnt = %lu\n", total_sweep_cnt, sweep_cnt);
#endif

	return;
}
#endif
