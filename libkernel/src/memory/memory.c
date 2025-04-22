#include "memory.h"
#include "debug.h"
#include "kmalloc.h"
#include "kthread.h"
#include "lib/err.h"
#include "ota.h"
#include "sbpf/bpf.h"
#include "vmem.h"
#include "gc.h"
#include <linux/bpf.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int memory_init()
{
	struct mm_struct *mm = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	struct sbpf *bpf;
#ifdef CONFIG_BPF_ARENA
	int map_fd;
#endif

	mm_init(mm);

	bpf = sbpf_create_program("/lib/sbpf/page_fault.bpf.o");
	sbpf_launch_program(bpf, "page_fault", mm, sizeof(struct mm_struct), 0);
	kfree(bpf);

	page_ops_bpf = sbpf_create_program("/lib/sbpf/page_ops.bpf.o");
	sbpf_launch_program(page_ops_bpf, "page_ops", mm, sizeof(struct mm_struct), 0);

#ifdef CONFIG_ENABLE_CONCURRENT_GC
	bpf = sbpf_create_program("/lib/sbpf/wp_page_fault.bpf.o");

#ifdef CONFIG_BPF_ARENA
	// Creating a shared map for the arena between the page ops and write protect page faults.
	map_fd = sbpf_get_map_fd(page_ops_bpf, "arena");
	sbpf_set_map_by_fd(bpf, "arena", map_fd);
#endif

	sbpf_launch_program(bpf, "wp_page_fault", mm, sizeof(struct mm_struct), 0);
#endif // Enable Concurrent GC

	kfree(bpf);

	ota_init();

	return 0;
}
