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

#if defined(CONFIG_DEBUG_ALLOC)
#define bpf_debug(...) bpf_printk(__VA_ARGS__)
#else
#define bpf_debug(...)
#endif

static int combo = 1;

static int pte_page_fault(void *kaddr, unsigned long vaddr, void *ctx)
{
	return BPF_SBPF_ITER_TOUCH_NONE;
}

SEC("sbpf/page_fault")
int page_fault(struct vm_fault *fault)
{
	int ret;
	static unsigned long prev_vaddr = 0;

	if ((prev_vaddr + PAGE_SIZE * combo) == fault->vaddr) {
		combo *= 2;
	} else {
		combo = 1;
	}
	combo = combo > CONFIG_PF_PREFETCH_MAX ? CONFIG_PF_PREFETCH_MAX : combo;
	prev_vaddr = fault->vaddr;

	bpf_iter_pte_touch((void *)fault->vaddr, PAGE_SIZE * combo, &pte_page_fault, NULL, BPF_SBPF_ITER_FLAG_CREATE);

	return 0;
}

char _license[] SEC("license") = "GPL";
