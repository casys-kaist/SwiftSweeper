#pragma once

#include <pthread.h>
#include "lib/list.h"

#define KTHREAD_STACK_SIZE 4096 * 16
#define KTHREAD_STACK_ALIGN 16

struct kthread {
	pthread_t thread;
	void *(*threadfn)(void *);
	char *full_name;
	int pid;
	struct list_head list;
};

struct kthread *kthread_create(void *(*threadfn)(void *data), void *data, char *fnname);
void exit_kthread(void);

// TLS overhead occupies 6% of user execution time in perlbench diffmail
#define __TLS __thread
