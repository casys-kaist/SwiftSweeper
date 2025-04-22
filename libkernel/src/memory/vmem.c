#include "vmem.h"
#include "debug.h"
#include "errno.h"
#include "kmalloc.h"
#include "kconfig.h"
#include "lib/compiler.h"
#include "lib/list.h"
#include "lib/minmax.h"
#include "lib/string.h"
#include "ota.h"
#include "spin_lock.h"
#include "rwlock.h"
#include "memory.h"
#include <pthread.h>
/*
 * Pointer to currently active virtual address space.
 * TODO: This should move to a CPU-local variable
 */
static struct mm_struct *vmem_active_mm = NULL;
struct sbpf *page_ops_bpf;

inline struct mm_struct *mm_get_active(void)
{
	return vmem_active_mm;
}

int vas_set_active(struct mm_struct *mm)
{
	vmem_active_mm = mm;

	return 0;
}

int mm_init(struct mm_struct *mm)
{
	ASSERT(mm != NULL);

	mm->vma_base = PAGE_ALIGN(VADDR_BASE);
	mm->flags = 0;
	INIT_LIST_HEAD(&mm->vma_list);
	mm->poolTree = &poolTree;
	vas_set_active(mm);
	spin_lock_init(&mm->mm_lock);

	return 0;
}

void mm_destory(struct mm_struct *mm)
{
	struct vm_area_struct *vma, *next;

	ASSERT(list_empty(&mm->vma_list));

	if (vmem_active_mm == mm) {
		vmem_active_mm = NULL;
	}
}