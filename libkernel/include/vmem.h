#include "debug.h"
#include "lib/list.h"
#include "memory.h"
#include "kconfig.h"
#include "ota.h"
#include "spin_lock.h"
#include "rwlock.h"
#define VADDR_MAX -1UL
/** Invalid virtual addres. **/
#define VADDR_INV -1UL
#define MAX_PER_THREAD_NUM 64
#define VADDR_BASE 0x100000000

struct contiguous_alias {
	uint64_t start;
	uint64_t len;
};

#define FREE_ALIAS_BUF_SIZE (PAGE_SIZE / sizeof(struct contiguous_alias))

#ifdef CONFIG_MEMORY_DEBUG
struct page_fault_stats {
	// get actual page_fault size
	long long total_alloc;
	long long current_alloc;
	long long max_alloc;
};
#define DEBUG_INC_MM_VAL(field, value) __atomic_fetch_add(field, value, __ATOMIC_RELAXED)
#define DEBUG_DEC_MM_VAL(field, value) __atomic_fetch_sub(field, value, __ATOMIC_RELAXED)
#define DEBUG_CMP_INC_MM_VAL(tar_field, src_field)                                                                                                             \
	do {                                                                                                                                                   \
		long long current_value = *tar_field;                                                                                                          \
		long long new_value = *src_field;                                                                                                              \
		if ((new_value) > (current_value)) {                                                                                                           \
			__atomic_compare_exchange_n(tar_field, &(current_value), (new_value), false, __ATOMIC_RELAXED, __ATOMIC_RELAXED);                      \
		}                                                                                                                                              \
	} while (0)
#else
#define DEBUG_INC_MM_VAL(field, value)
#define DEBUG_DEC_MM_VAL(field, value)
#define DEBUG_CMP_INC_MM_VAL(tar_field, src_field)
#endif

struct garbage_collection {
	void *from;
	void *to;
	void *prev_hot_page;
	void *hot_page;
	size_t offset;
	int gc_count;
};

struct mm_per_thread {
	bool val;
};

struct mm_struct {
#ifdef CONFIG_MEMORY_DEBUG
	struct page_fault_stats stats;
	uint64_t hit_cnt, total_cnt, on_demand_cnt, n_prefetches;
#endif
	struct mm_per_thread perthread[MAX_PER_THREAD_NUM];
	size_t max_perthread_num;
	spinlock_t mm_lock;
	bool is_gc_run;
	bool run_full_path;
	struct garbage_collection gc;
	struct radixroot_t *poolTree;
	byte* volatile poolLowWater;
	byte* volatile poolHighWater;
	byte* volatile stacktop;
	byte* volatile stackbottom;
	vaddr_t vma_base;
	struct list_head vma_list;
	unsigned long flags;
} __attribute__((aligned(64)));

void debug_mm_struct(struct mm_struct *mm);

struct vm_area_struct {
	vaddr_t vm_start;
	vaddr_t vm_end;

	struct list_head list;

	const struct vm_operation_struct *vm_ops;

	struct mm_struct *vm_mm; /* The address space we belongs to. */
	unsigned long vm_page_prot; /* Access permissions of this VMA. */
	unsigned long vm_flags;

	void *aux; /* Optional field for the VMA used for custom allocator. */

	const char *name; /* Optional field for the VMA. */
};

/**
 * Returns the length of a VMA in bytes.
 */
static inline size_t vmem_vma_len(struct vm_area_struct *vma)
{
	ASSERT(vma->vm_end > vma->vm_start);

	return vma->vm_end - vma->vm_start;
}

/*
 * vm_fault is filled by the pagefault handler and passed to the vma's
 * ->fault function. The vma's ->fault is responsible for returning a bitmask
 * of VM_FAULT_xxx flags that give details about how the fault was handled.
 *
 * MM layer fills up gfp_mask for page allocations but fault handler might
 * alter it if its implementation requires a different allocation context.
 *
 * pgoff should be used in favour of virtual_address, if possible.
 */
struct vm_fault {
	vaddr_t vaddr;
	size_t len;
	unsigned int flags;
	struct mm_struct *mm;
};

struct vm_operation_struct {
	void (*open)(struct vm_area_struct *area);
	/**
	 * @close: Called when the VMA is being removed from the MM.
	 */
	void (*close)(struct vm_area_struct *vma);
	/**
	 * @mmap: Called when the VMA is being mapped to the MM.
	 *
	 * @param vma
	 *	 The VMA in which a range should be mapped. 
	*/
	int (*mmap)(struct vm_area_struct *vma);
	/**
	 * Unmaps a range of the VMA. It is the handler's responsibily to
	 * perform the actual unmap in the page table and potentially release
	 * the physical memory.
	 *
	 * @param vma
	 *   The VMA in which a range should be unmapped
	 * @param vaddr
	 *   The base address of the range which should be unmapped
	 * @param len
	 *   The length of the range in bytes
	 *
	 * @return
	 *   0 on success, a negative errno error otherwise
	 */
	int (*unmap)(struct vm_area_struct *vma, vaddr_t vaddr, size_t len);
	/*
	 * Called by mprotect() to make driver-specific permission
	 * checks before mprotect() is finalised.   The VMA must not
	 * be modified.  Returns 0 if mprotect() can proceed.
	 */
	int (*mprotect)(struct vm_area_struct *vma, unsigned long newflags);

	int (*madvise)(struct vm_area_struct *vma, vaddr_t vaddr, size_t len, unsigned long advice);

	int (*fault)(struct vm_area_struct *vma, struct vm_fault *vmf);
	/* Called by the /proc/PID/maps code to ask the vma whether it
	 * has a special name.  Returning non-NULL will also cause this
	 * vma to be dumped unconditionally. */
	const char *(*name)(struct vm_area_struct *vma);
};

/* Platform vm_operation_struct handlers */
int vma_op_plat_unmap(struct vm_area_struct *vma, vaddr_t vaddr, size_t len);
int vma_op_plat_mmap(struct vm_area_struct *vma);
int vma_op_plat_set_prot(struct vm_area_struct *vma, unsigned long prot);

const struct vm_operation_struct vma_anon_ops;

int do_mmap(void **addr, size_t len, int prot, int flags, int fd, off_t offset, void *aux);

int vma_map(struct mm_struct *mm, vaddr_t *vaddr, size_t len, unsigned long prot, unsigned long flags, const char *name, void *aux);
int vma_unmap(struct mm_struct *mm, vaddr_t vaddr, size_t len);
int vma_set_prot(struct mm_struct *mm, vaddr_t vaddr, size_t len, unsigned long prot);
int vma_advise(struct mm_struct *mm, vaddr_t vaddr, size_t len, unsigned long advice);
struct mm_struct *mm_get_active(void);
struct mm_per_thread *mm_get_per_thread(void);
int mm_init(struct mm_struct *vas);
void mm_destory(struct mm_struct *mm);

extern struct sbpf *page_ops_bpf;
