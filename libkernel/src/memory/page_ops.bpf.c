#include "gc.h"
#include "kconfig.h"
#include "lib/list.h"
#include "lib/stddef.h"
#include "lib/types.h"
#include "memory.h"
#include "ota.h"
#include "rwlock.h"
#include "spin_lock.h"
#include "vmem.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <errno.h>
#include "bpf_arena_common.h"

#if defined(CONFIG_DEBUG_GC)
#define bpf_debug(...) bpf_printk(__VA_ARGS__)
#define ASSERT_BPF(x)                                                                                                                                          \
	if (!(x)) {                                                                                                                                            \
		bpf_printk("assertion failed: 0x%lx", x);                                                                                                      \
		return 1;                                                                                                                                      \
	}
#else
#define bpf_debug(...)
#define ASSERT_BPF(x)
#endif

#ifdef CONFIG_BPF_ARENA
struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1024 * 1024);
} arena SEC(".maps");

static long bpf_arena_alloc(unsigned long size, void **ptr);
static int bpf_arena_free(void *addr);
void *bpf_arena_alloc_pages(void *p__map, void *addr__ign, u32 page_cnt, int node_id, u64 flags) __ksym;
void bpf_arena_free_pages(void *p__map, void *ptr__ign, u32 page_cnt) __ksym;
bool init = false;
#define cast_kern_size(addr, size) cast_kern(addr)
#else
#define cast_kern_size(addr, size) addr = bpf_uaddr_to_kaddr(addr, size)
#endif // CONFIG_BPF_ARENA

static long map_page(void *alias, void *canonical);
static long prot_page(uint64_t vaddr, uint64_t size, unsigned long pgprot);
static int unmap_page(unsigned long start_u, unsigned long end_u, struct mm_struct *mm);
static int pte_gc(unsigned long start, size_t len, struct radixroot_t *root, struct mm_struct *mm);

#define WINDOW_SIZE (CONFIG_ON_DEMAND_GC_BATCH_SIZE * PAGE_SIZE)

#if defined(CONFIG_ENABLE_GC) && defined(CONFIG_ENABLE_CONCURRENT_GC)
__always_inline struct pagepool_t *pf_find_pool_for_ptr(void *vaddr, struct radixroot_t *root)
{
	size_t stemIndex = ((unsigned long)vaddr >> (POOL_SIZE_BITS + LEAF_BITS + STEM_BITS)) & 0xff;
	size_t leafIndex = ((unsigned long)vaddr >> (POOL_SIZE_BITS + LEAF_BITS)) & (LEAVES_PER_STEM - 1);

	struct radixstem_t *stems = root->stems[stemIndex];
	cast_kern_size(stems, sizeof(struct radixstem_t));
	if (stems == NULL) {
		bpf_debug("pf_find_pool_for_ptr: stem is NULL\n");
		return NULL;
	}

	struct radixleaf_t *leaf = stems->leaves[leafIndex];
	cast_kern_size(leaf, sizeof(struct radixleaf_t));
	if (leaf == NULL) {
		bpf_debug("pf_find_pool_for_ptr: leaf is NULL\n");
		return NULL;
	}

	// Check if there is a pool that starts or ends in this leaf
	// that could possibly contain the given pointer
	struct pagepool_t *pool = leaf->poolStart[((unsigned long)vaddr >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1)];
	cast_kern_size(pool, sizeof(struct pagepool_t));
	if (pool != NULL && (unsigned long)vaddr >= (unsigned long)pool->start) {
		return pool;
	}

	pool = leaf->poolEnd[((unsigned long)vaddr >> POOL_SIZE_BITS) & (POOLS_PER_LEAF - 1)];
	cast_kern_size(pool, sizeof(struct pagepool_t));
	if (pool != NULL && (unsigned long)vaddr < (unsigned long)pool->end) {
		return pool;
	}

	bpf_debug("pf_find_pool_for_ptr: pool is NULL 0x%lx\n", pool);
	return NULL;
}

__always_inline bool pf_mark_pointer(struct pagepool_t *pool, void *ptr, bool is_hot)
{
	size_t mapIndex = ((byte *)ptr - pool->start) / (unsigned long)PAGE_SIZE;
	struct pagemap_t *page = pool->tracking.pageMaps + mapIndex;

	// TO mitigate the false alarm, we have to use the `bpf_uaddr_to_kaddr`.
	// instead of `cast_kern_size(page, sizeof(struct pagemap_t))`;
	page = bpf_uaddr_to_kaddr(page, sizeof(struct pagemap_t));
	// cast_kern_size(page, sizeof(struct pagemap_t));
	if (page == NULL || page->allocSize == 0 || page->allocSize < sizeof(struct free_list_entry)) {
		bpf_debug("pf_find_small_ptr_index: page is NULL or size is less than 16 byte\n");
		return false;
	}

	// Validate that this is a potentially valid address - i.e. not an
	// address in the middle of an allocation. Trusting compiler optimizations
	// to not issue two divisions to keep things quick
	if (((byte *)ptr - page->start) % (page->allocSize & ~SEVEN64) != 0) {
		return false;
	}

	// Found the page. Find the allocation's place in the bitmap
	uint64_t index = ((byte *)ptr - page->start) / (page->allocSize & ~SEVEN64);
	if (index < 0)
		return false;

	// Is the pointer actually allocated?
	if (page->allocSize < 64) {
		uint64_t array = (index >> 6) % 8;
		uint64_t pos = index - (array << 6);
		uint64_t *markmap = page->markmap.array;
		uint64_t *bitmap = page->bitmap.array;

		markmap = bpf_uaddr_to_kaddr(markmap, sizeof(uint64_t) * (8));
#ifdef CONFIG_GC_DELTA_MARKING
		cast_kern_size(bitmap, sizeof(uint64_t) * (8));
		if (bitmap == NULL) {
			bpf_debug("pf_find_small_ptr_index: bitmap is NULL\n");
			return false;
		}
#endif
		if (markmap == NULL) {
			bpf_debug("pf_find_small_ptr_index: bitmap is NULL\n");
			return false;
		}
#ifdef CONFIG_GC_DELTA_MARKING
		if (is_hot) {
			// Skip if the pointer is allocated and from the stack (delta marking).
			if (bitmap[array] & (ONE64 << pos)) {
				return true;
			}
		}
#endif
		markmap[array] |= (ONE64 << pos);
		return true;
	} else {
		// Skip if the pointer is allocated and from the stack (delta marking).
#ifdef CONFIG_GC_DELTA_MARKING
		if (is_hot && (page->bitmap.single & (ONE64 << index))) {
			return true;
		}
#endif
		page->markmap.single |= (ONE64 << index);
		return true;
	}
}

struct pte_gc_ctx {
	struct radixroot_t *root;
	unsigned long lowWater;
	unsigned long highWater;
	struct mm_struct *mm;
};

static int pte_gc_loop(void **kaddr, unsigned long vaddr, void *ctx, unsigned long flag)
{
	struct pte_gc_ctx *gc_ctx = (struct pte_gc_ctx *)ctx;
	struct radixroot_t *root = gc_ctx->root;
	bool is_hot = false;
	bool full_path = true;

#ifdef CONFIG_GC_DELTA_MARKING
	full_path = false;
	if (vaddr >= (unsigned long)gc_ctx->mm->stacktop && vaddr < (unsigned long)gc_ctx->mm->stackbottom) {
		is_hot = true;
		full_path = true;
	}
	if (vaddr >= (unsigned long)gc_ctx->mm->gc.hot_page && vaddr < (unsigned long)gc_ctx->mm->gc.to) {
		is_hot = true;
		full_path = false;
	}
	if (vaddr >= (unsigned long)gc_ctx->mm->gc.prev_hot_page && vaddr < (unsigned long)gc_ctx->mm->gc.hot_page) {
		is_hot = false;
		full_path = true;
	}

	if (gc_ctx->mm->run_full_path) {
		is_hot = false;
		full_path = true;
	}

	if (!(flag & (1 << _PAGE_BIT_DIRTY)) && !full_path) {
		bpf_debug("on-demand marking: skip clean page 0x%lx", vaddr);
		return BPF_SBPF_ITER_TOUCH_RDWR;
	}

	if ((flag & _PAGE_PKEY_MASK)) {
		bpf_debug("delta marking: skip writable page 0x%lx", vaddr);
		return BPF_SBPF_ITER_TOUCH_RDWR;
	}
#endif

	// // Mark the pointer inside this ptr.
	int index;
	struct pagepool_t *free_pool = NULL;
#ifdef CONFIG_BPF_ARENA
	bpf_for(index, 0, PAGE_SIZE / sizeof(void *))
#else
	for (index = 0; index < PAGE_SIZE / sizeof(void *); index++)
#endif
	{
		// Find the location in the metadata where the page for this pointer is tracked
		if (kaddr[index] < (void *)gc_ctx->lowWater || kaddr[index] >= (void *)gc_ctx->highWater)
			continue;
		free_pool = pf_find_pool_for_ptr(kaddr[index], root);
		if (free_pool == NULL || free_pool->nextFreeIndex != -1)
			continue;

		pf_mark_pointer(free_pool, kaddr[index], is_hot);
	}

	return BPF_SBPF_ITER_TOUCH_RDWR;
}
#endif

SEC("sbpf/function")
int page_ops(void *args[])
{
	void *op = args[0];

	switch ((unsigned long)op) {
	case PTE_MAP:
		return map_page(args[1], args[2]);
	case PTE_UNMAP:
		return unmap_page((unsigned long)args[1], (unsigned long)args[2], args[3]);
	case PTE_SET_PROT:
		return prot_page((uint64_t)args[1], (uint64_t)args[2], (uint64_t)args[3]);
#ifdef CONFIG_ENABLE_GC
	case PTE_GC:
		return pte_gc((unsigned long)args[1], (unsigned long)args[2], (struct radixroot_t *)args[3], (struct mm_struct *)args[4]);
#endif
#ifdef CONFIG_BPF_ARENA
	case PTE_MAP_ARENA:
		return bpf_arena_alloc((unsigned long)args[1], (void **)args[2]);
	case PTE_UNMAP_ARENA:
		return bpf_arena_free(args[1]);
#endif
	default:
		return 1;
	}
}

static long map_page(void *alias, void *canonical)
{
	bpf_debug("map page 0x%lx to 0x%lx", (uint64_t)alias, (uint64_t)canonical);
	if (bpf_set_page_table((void *)PAGE_ALIGN_DOWN((uint64_t)alias), PAGE_SIZE, (void *)PAGE_ALIGN_DOWN((uint64_t)canonical), 0, PAGE_SHARED_EXEC) != 0) {
		bpf_printk("bpf_set_page_table(0x%lx, 0x%lx, 0x%lx) failed with in map_page", (void *)PAGE_ALIGN_DOWN((uint64_t)alias), PAGE_SIZE,
			   (void *)PAGE_ALIGN_DOWN((uint64_t)canonical));
		return 1;
	}

	return 1;
}

static long prot_page(uint64_t vaddr, uint64_t size, unsigned long pgprot)
{
	bpf_debug("set protection 0x%lx with size 0x%lx", vaddr, size);
	if (bpf_touch_page_table((void *)vaddr, size, NULL, 0, pgprot)) {
		bpf_printk("bpf_touch_page_table(0x%lx, 0x%lx) failed in set_protection", vaddr, size);
		return 1;
	}

	return 0;
}

static int unmap_page(unsigned long start_u, unsigned long end_u, struct mm_struct *mm)
{
	ASSERT_BPF(PAGE_ALIGNED(start_u));
	ASSERT_BPF(PAGE_ALIGNED(end_u));
	ASSERT_BPF(start_u < end_u);

	bpf_debug("demand free with prev alias 0x%lx with len : 0x%lx", start_u, end_u - start_u);
	if (bpf_unset_page_table((void *)start_u, end_u - start_u) != 0) {
		bpf_printk("bpf_unset_page_table(0x%lx, 0x%lx) failed in clear", (void *)start_u, end_u - start_u);
		return 1;
	}

	return 0;
}

#ifdef CONFIG_ENABLE_GC
static int pte_gc(unsigned long start, size_t len, struct radixroot_t *root, struct mm_struct *mm)
{
	bool is_hot = false;
	bool full_path = false;

	len = PAGE_ALIGN(len);
	start = PAGE_ALIGN_DOWN(start);

	root = bpf_uaddr_to_kaddr(root, sizeof(struct radixroot_t));
	if (root == NULL) {
		bpf_debug("pf_find_pool_for_ptr: poolTree (0x%lx) is NULL\n", root);
		return BPF_SBPF_ITER_TOUCH_RDWR;
	}

	mm = bpf_uaddr_to_kaddr(mm, sizeof(struct mm_struct));
	if (mm == NULL) {
		bpf_debug("pte_gc: mm is NULL\n");
		return BPF_SBPF_ITER_TOUCH_RDWR;
	}

	// Mark the pointer inside this ptr.
	struct pte_gc_ctx gc_ctx = {
		.root = root,
		.lowWater = (unsigned long)mm->poolLowWater,
		.highWater = (unsigned long)mm->poolHighWater,
		.mm = mm,
	};

	return (u64)bpf_iter_pte_touch((void *)start, len, pte_gc_loop, &gc_ctx, BPF_SBPF_ITER_FLAG_NONE);
}
#endif

#ifdef CONFIG_BPF_ARENA
static long bpf_arena_alloc(unsigned long size, void **ptr)
{
	uint64_t page;

	size = PAGE_ALIGN(size);
	page = (uint64_t)bpf_arena_alloc_pages(&arena, NULL, size / PAGE_SIZE, -1, 0);
	if (!page)
		return 1;

	// TODO : should make sharing path
	ptr = bpf_uaddr_to_kaddr(ptr, sizeof(void **));
	if (ptr == NULL)
		return 1;

	*ptr = (void *)page;
	init = true;

	return 0;
}

static int bpf_arena_free(void *addr)
{
	// Will never be called, because metadata is not freed in FFmalloc
	cast_kern(addr);
	bpf_arena_free_pages(&arena, addr, 1);

	return 0;
}
#endif

char _license[] SEC("license") = "GPL";
