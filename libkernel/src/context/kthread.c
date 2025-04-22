#include "kthread.h"
#include "kmalloc.h"
#include "lib/err.h"
#include "lib/list.h"
#include "memory.h"
#include "debug.h"

static LIST_HEAD(kthread_list);

struct kthread *kthread_create(void *(*threadfn)(void *data), void *data, char *fnname)
{
	struct kthread *kt;
	int pid;

	kt = kmalloc(sizeof(struct kthread));
	kt->full_name = fnname;
	kt->threadfn = threadfn;

	kt->pid = pthread_create(&kt->thread, NULL, threadfn, data);

	if (pid < 0) {
		kfree(kt);
		return ERR_PTR(pid);
	}

	list_add_tail(&kt->list, &kthread_list);

	return kt;
}

void exit_kthread(void)
{
	struct kthread *cur;

	list_for_each_entry(cur, &kthread_list, list) {
		pthread_cancel(cur->thread);
	}
}
