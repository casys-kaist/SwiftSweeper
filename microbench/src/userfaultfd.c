#define _GNU_SOURCE
#include "../lib/time_stat.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

/** #define DEBUG */

#define errExit(msg)                                                                                                                                           \
	do {                                                                                                                                                   \
		perror(msg);                                                                                                                                   \
		exit(EXIT_FAILURE);                                                                                                                            \
	} while (0)

static int page_size;

static void *fault_handler_thread(void *arg)
{
	static struct uffd_msg msg; /* Data read from userfaultfd */
	// static int fault_cnt = 0; /* Number of faults so far handled */
	long uffd; /* userfaultfd file descriptor */
	static char *page = NULL;
	struct uffdio_copy uffdio_copy;
	ssize_t nread;

	uffd = (long)arg;

	/* Create a page that will be copied into the faulting region. */

	if (page == NULL) {
		page = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (page == MAP_FAILED)
			errExit("mmap");
	}

	/* Loop, handling incoming events on the userfaultfd
        file descriptor. */

	for (;;) {
		/* See what poll() tells us about the userfaultfd. */

		struct pollfd pollfd;
		int nready;
		pollfd.fd = uffd;
		pollfd.events = POLLIN;
		nready = poll(&pollfd, 1, -1);
		if (nready == -1)
			errExit("poll");

#ifdef DEBUG
		printf("\nfault_handler_thread():\n");
		printf("    poll() returns: nready = %d; "
		       "POLLIN = %d; POLLERR = %d\n",
		       nready, (pollfd.revents & POLLIN) != 0, (pollfd.revents & POLLERR) != 0);
#endif

		/* Read an event from the userfaultfd. */

		nread = read(uffd, &msg, sizeof(msg));
		if (nread == 0) {
			printf("EOF on userfaultfd!\n");
			exit(EXIT_FAILURE);
		}

		if (nread == -1)
			errExit("read");

		/* We expect only one kind of event; verify that assumption. */

		if (msg.event != UFFD_EVENT_PAGEFAULT) {
			fprintf(stderr, "Unexpected event on userfaultfd\n");
			exit(EXIT_FAILURE);
		}

		/* Display info about the page-fault event. */

#ifdef DEBUG
		printf("    UFFD_EVENT_PAGEFAULT event: ");
		printf("flags = %" PRIx64 "; ", msg.arg.pagefault.flags);
		printf("address = %" PRIx64 "\n", msg.arg.pagefault.address);
#endif

		/* Copy the page pointed to by 'page' into the faulting
      region. Vary the contents that are copied in, so that it
      is more obvious that each fault is handled separately. */

		/** memset(page, 'A' + fault_cnt % 20, page_size); */
		uffdio_copy.src = (unsigned long)page;

		/* We need to handle page faults in units of pages(!).
      So, round faulting address down to page boundary. */

		uffdio_copy.dst = (unsigned long)msg.arg.pagefault.address & ~(page_size - 1);
		uffdio_copy.len = page_size;
		uffdio_copy.mode = 0;
		uffdio_copy.copy = 0;
		if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
			errExit("ioctl-UFFDIO_COPY");

#ifdef DEBUG
		printf("        (uffdio_copy.copy returned %" PRId64 ")\n", uffdio_copy.copy);
#endif
	}
}

void sigsegv_handler(int signum, siginfo_t *info, void *context)
{
	void *fault_addr = info->si_addr;
	void *page_start = (void *)((unsigned long)fault_addr & ~(4096 - 1));
	mprotect(page_start, 4096, PROT_READ | PROT_WRITE);
	memset(page_start, 0, 4096);
}

static int launch_bpf(void)
{
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;
	int prog_fd;

	// BPF object file is parsed.
	bpf_obj = bpf_object__open("/lib/sbpf/page_fault.bpf.o");
	if (libbpf_get_error(bpf_obj)) {
		fprintf(stderr, "ERROR: opening eBPF program failed\n");
		return -1;
	}

	// BPF maps are creased, various relocations are resolved and BPF programs are
	// loaded into the kernel and verfied. But BPF program is yet executed.
	bpf_object__load(bpf_obj);
	if (libbpf_get_error(bpf_obj)) {
		fprintf(stderr, "ERROR: loading eBPF program failed\n");
		return -1;
	}

	bpf_prog = bpf_object__find_program_by_name(bpf_obj, "page_fault");
	bpf_program__attach(bpf_prog);

	prog_fd = bpf_program__fd(bpf_prog);
	printf("bpf prog fd %d\n", prog_fd);
	// After return his program, fd will be free with eBPF unloading.
	return prog_fd;
}

struct writer_arg {
	void *addr;
	uint64_t len;
	struct time_stats *ts;
};

void *writer(void *arg)
{
	struct writer_arg *wa = (struct writer_arg *)arg;
	void *addr = wa->addr;
	uint64_t len = wa->len;
	int l = 0xf;
#ifdef DEBUG
	printf("writer %p %lu\n", addr, len);
#endif

	while (l < len) {
		if (wa->ts)
			time_stats_start(wa->ts);
		char __attribute__((unused)) c = ((char *)addr)[l];

#ifdef DEBUG
		printf("Read address %p in main(): ", addr + l);
		printf("%c\n", c);
#endif
		((char *)addr)[l] = 1;
		l += page_size;
		if (wa->ts)
			time_stats_stop(wa->ts);
	}

	return NULL;
}

enum BENCH_MODE {
	MODE_LINUX = 0,
	MODE_BUD = 1,
	MODE_UFFD = 2,
	MODE_SIG = 3,
};

struct time_stats *benchmark(int mode, size_t len, size_t num_threads)
{
	long uffd; /* userfaultfd file descriptor */
	char *addr; /* Start of region handled by userfaultfd */
	pthread_t thr; /* ID of thread that handles page faults */
	pthread_t *writers;
	struct uffdio_api uffdio_api;
	struct uffdio_register uffdio_register;
	int s;
	struct time_stats local_ts;
	struct time_stats *total_ts;
	page_size = sysconf(_SC_PAGE_SIZE);
	len = len * page_size;

	if (mode == MODE_BUD) {
		addr = (void *)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | 0x400000, -1, 0);
		if (addr == MAP_FAILED)
			errExit("mmap");
#ifdef DEBUG
		printf("Address returned by mmap() = %p\n", addr);
#endif
	} else if (mode == MODE_UFFD) {
		addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED)
			errExit("mmap");
#ifdef DEBUG
		printf("Address returned by mmap() = %p\n", addr);
#endif
		uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
		if (uffd == -1)
			errExit("userfaultfd");

		uffdio_api.api = UFFD_API;
		uffdio_api.features = 0;
		if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
			errExit("ioctl-UFFDIO_API");

		/* Register the memory range of the mapping we just created for
        handling by the userfaultfd object. In mode, we request to track
        missing pages (i.e., pages that have not yet been faulted in). */

		uffdio_register.range.start = (unsigned long)addr;
		uffdio_register.range.len = len;
		uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;

		s = pthread_create(&thr, NULL, fault_handler_thread, (void *)uffd);
		if (s != 0) {
			errno = s;
			errExit("pthread_create");
		}

		if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
			errExit("ioctl-UFFDIO_REGISTER");
	} else if (mode == MODE_SIG) {
		struct sigaction sa;
		addr = (void *)mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED)
			errExit("mmap");

		memset(&sa, 0, sizeof(struct sigaction));
		sa.sa_flags = SA_SIGINFO;
		sa.sa_sigaction = sigsegv_handler;
		sigaction(SIGSEGV, &sa, NULL);
	} else {
		addr = (void *)mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED)
			errExit("mmap");
	}

	total_ts = malloc(sizeof(struct time_stats));
	writers = malloc(num_threads * sizeof(pthread_t));

	time_stats_init(&local_ts, len / page_size);
	time_stats_init(total_ts, 1);
	time_stats_start(total_ts);
	for (int i = 0; i < num_threads; i++) {
		struct writer_arg *wa = malloc(sizeof(struct writer_arg));
		wa->addr = addr + i * (len / num_threads);
		wa->len = len / num_threads;
		wa->ts = num_threads == 1 ? &local_ts : NULL;
		pthread_create(&writers[i], NULL, writer, wa);
	}
	for (int i = 0; i < num_threads; i++) {
		pthread_join(writers[i], NULL);
	}
	time_stats_stop(total_ts);
	if (num_threads == 1)
		time_stats_print(&local_ts, "Local executed time");

	free(writers);
	munmap(addr, len);

	return total_ts;
}

int main(int argc, char *argv[])
{
	size_t num_threads = 1;
	size_t len;
	int mode;

	for (int i = 0; i < argc; i++) {
		if (strncmp("--length", argv[i], 8) == 0) {
			int parsed_arg = atoi(argv[i + 1]);
			if (parsed_arg > 0)
				len = parsed_arg;
		}
		if (strncmp("--thread", argv[i], 8) == 0) {
			int parsed_arg = atoi(argv[i + 1]);
			if (parsed_arg > 0)
				num_threads = parsed_arg;
		}
		if (strncmp("--bud", argv[i], 5) == 0) {
			mode = MODE_BUD;
			launch_bpf();
		}
		if (strncmp("--uffd", argv[i], 6) == 0) {
			mode = MODE_UFFD;
		}
		if (strncmp("--sig", argv[i], 6) == 0) {
			mode = MODE_SIG;
		}
	}

	if (argc == 1) {
		fprintf(stderr,
			"Usage: %s --length N --threads N --bud (for using bud) --uffd (for using userfaultfd) --sig (for using signal handler) (none for using linux default #PF)\n",
			argv[0]);
		exit(EXIT_FAILURE);
	}

	for (int i = 1; i <= num_threads; i *= 2) {
		struct time_stats *ts = benchmark(mode, len, i);
		char *mode_str = mode == MODE_BUD ? "BUD" : mode == MODE_UFFD ? "UFFD" : mode == MODE_SIG ? "SIG" : "LINUX";
		printf("%s, %d, %f\n", mode_str, i, time_stats_get_avg(ts));
		free(ts);
	}

	exit(EXIT_SUCCESS);
}
