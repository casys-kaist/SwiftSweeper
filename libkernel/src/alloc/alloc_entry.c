#define _GNU_SOURCE
#include "boot.h"
#include "debug.h"
#include "kmalloc.h"
#include "kthread.h"
#include "lib/stddef.h"
#include "memory.h"
#include "ota.h"
#include "syscall.h"
#include "vmem.h"
#include "gc.h"
#include "spin_lock.h"
#include <string.h>
#include <dlfcn.h>

/** #define DEBUG_MALLOC 1 */
/** #define LIBC_MALLOC 1 */

static int init_libc_done = 0;
static int init_kernel_done = 0;

static void init_mm();
static int (*main_orig)(int, char **, char **);

static int dup_stderr;

static __TLS int init_thread_done = 0;
static __TLS int thread_index = -1;

int __attribute__((visibility("default"))) __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv, int (*init)(int, char **, char **),
							     void (*fini)(void), void (*rtld_fini)(void), void *stack_end)
{
	main_orig = main;
	typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");
	init_mm();
	return orig(main_orig, argc, argv, init, fini, rtld_fini, stack_end);
}

static void thread_init()
{
	static int thread_idx = -1;
	static int thread_idx_ = 0;
	size_t local_thread_index;
	struct mm_per_thread *mpt;

	if (init_thread_done)
		return;

	spin_lock(&mm_get_active()->mm_lock);
	if (thread_idx > MAX_PER_THREAD_NUM) {
		thread_index = thread_idx_;
		thread_idx_ = (thread_idx_ + 1) % MAX_PER_THREAD_NUM;
		spin_unlock(&mm_get_active()->mm_lock);
		init_thread_done = 1;
		return;
	}

	thread_index = local_thread_index = (++thread_idx) % MAX_PER_THREAD_NUM;
	mpt = &mm_get_active()->perthread[local_thread_index];
	mm_get_active()->max_perthread_num = thread_idx + 1;
	spin_unlock(&mm_get_active()->mm_lock);

	init_thread_done = 1;
}

static void init_mm()
{
	if (init_libc_done)
		return;

	stack_top = get_stack_pointer();

	libc_malloc = dlsym(RTLD_NEXT, "malloc");
	libc_free = dlsym(RTLD_NEXT, "free");
	libc_realloc = dlsym(RTLD_NEXT, "realloc");
	libc_reallocarray = dlsym(RTLD_NEXT, "reallocarray");
	libc_calloc = dlsym(RTLD_NEXT, "calloc");
	libc_malloc_usable_size = dlsym(RTLD_NEXT, "malloc_usable_size");
	libc_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
	libc_memalign = dlsym(RTLD_NEXT, "memalign");
	libc_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");

	if (!libc_malloc || !libc_free || !libc_realloc || !libc_reallocarray || !libc_calloc || !libc_malloc_usable_size || !libc_aligned_alloc ||
	    !libc_memalign || !libc_posix_memalign)
		TODO("UNREACHABLE");

	init_libc_done = 1;
#ifndef LIBC_MALLOC
	kernel_entry();
	init_kernel_done = 1;
#endif

	ASSERT(!init_thread_done);
	thread_init();
}

struct mm_per_thread *mm_get_per_thread(void)
{
	ASSERT(init_thread_done);
	return &mm_get_active()->perthread[thread_index];
}

void __attribute__((visibility("default"))) * malloc(size_t size)
{
	void *ret;

	if (unlikely(!init_libc_done))
		return kcalloc(1, size);
	if (unlikely(!init_kernel_done))
		return libc_malloc(size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_malloc(size);
#else
	ENTER_METADATA_REGION();
	ret = ota_malloc(size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("malloc(%zu) = %p\n", size, ret);
	return ret;
}

void __attribute__((visibility("default"))) free(void *ptr)
{
	if (unlikely(!init_libc_done)) {
		kfree(ptr);
		return;
	}
	if (unlikely(!init_kernel_done)) {
		libc_free(ptr);
		return;
	}
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	libc_free(ptr);
#else
	ENTER_METADATA_REGION();
	ota_free(ptr);
	EXIT_METADATA_REGION();
#endif
	debug_printk("free(%p)\n", ptr);
}

void __attribute__((visibility("default"))) * realloc(void *ptr, size_t size)
{
	void *ret;

	ASSERT(init_libc_done);
	if (unlikely(!init_kernel_done))
		return libc_realloc(ptr, size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_realloc(ptr, size);
#else
	ENTER_METADATA_REGION();
	ret = ota_realloc(ptr, size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("realloc(%p, %zu) = %p\n", ptr, size, ret);
	return ret;
}

void __attribute__((visibility("default"))) * reallocarray(void *ptr, size_t nmemb, size_t size)
{
	void *ret;

	ASSERT(init_libc_done);
	if (unlikely(!init_kernel_done))
		return libc_reallocarray(ptr, nmemb, size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_reallocarray(ptr, nmemb, size);
#else
	ENTER_METADATA_REGION();
	ret = ota_reallocarray(ptr, nmemb, size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("reallocarray(%p, %zu, %zu) = %p\n", ptr, nmemb, size, ret);
	return ret;
}

void __attribute__((visibility("default"))) * calloc(size_t nmemb, size_t size)
{
	// dlysm internally uses calloc.
	// However, dlysm could accept the NULL return value of the calloc.
	// Thus, we have to use kcalloc in the calloc.
	void *ret;

	if (unlikely(!init_libc_done))
		return kcalloc(nmemb, size);
	if (unlikely(!init_kernel_done))
		return libc_calloc(nmemb, size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_calloc(nmemb, size);
#else
	ENTER_METADATA_REGION();
	ret = ota_calloc(nmemb, size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("calloc(%zu, %zu) = %p\n", nmemb, size, ret);
	return ret;
}

void __attribute__((visibility("default"))) * memalign(size_t alignment, size_t size)
{
	void *ret;

	if (unlikely(!init_libc_done))
		return NULL;
	if (unlikely(!init_kernel_done))
		return libc_memalign(alignment, size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_memalign(alignment, size);
#else
	ENTER_METADATA_REGION();
	ret = ota_memalign(alignment, size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("memalign(%zu, %zu) = %p\n", alignment, size, ret);
	return ret;
}

int __attribute__((visibility("default"))) posix_memalign(void **ptr, size_t alignment, size_t size)
{
	int ret;

	if (unlikely(!init_libc_done))
		return EINVAL;
	if (unlikely(!init_kernel_done))
		return libc_posix_memalign(ptr, alignment, size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_posix_memalign(ptr, alignment, size);
#else
	ENTER_METADATA_REGION();
	ret = ota_posix_memalign(ptr, alignment, size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("posix_memalign(%p, %zu, %zu) = %d\n", *ptr, alignment, size, ret);
	return ret;
}

void __attribute__((visibility("default"))) * aligned_alloc(size_t alignment, size_t size)
{
	void *ret;

	if (unlikely(!init_libc_done))
		return NULL;
	if (unlikely(!init_kernel_done))
		return libc_aligned_alloc(alignment, size);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_aligned_alloc(alignment, size);
#else
	ENTER_METADATA_REGION();
	ret = ota_aligned_alloc(alignment, size);
	EXIT_METADATA_REGION();
#endif
	debug_printk("aligned_alloc(%zu, %zu) = %p\n", alignment, size, ret);
	return ret;
}

size_t __attribute__((visibility("default"))) malloc_usable_size(const void *ptr)
{
	size_t ret;

	ASSERT(init_libc_done);
	if (unlikely(!init_kernel_done))
		return libc_malloc_usable_size(ptr);
	if (unlikely(!init_thread_done))
		thread_init();

#ifdef LIBC_MALLOC
	ret = libc_malloc_usable_size(ptr);
#else
	ENTER_METADATA_REGION();
	ret = ota_malloc_usable_size(ptr);
	EXIT_METADATA_REGION();
#endif
	debug_printk("malloc_usable_size(%p) = %zu\n", ptr, ret);
	return ret;
}

// void __attribute__((visibility("default"))) malloc_stats(void)
// {
// 	ota_malloc_stats();
// }

/** char __attribute__((visibility("default"))) * strdup(const char *s) */
/** { */
/** #ifdef LIBC_MALLOC */
/**     return strdup(s); */
/** #else */
/**     return ota_strdup(s); */
/** #endif */
/** } */
/**  */
/** char __attribute__((visibility("default"))) * strndup(const char *s, size_t n) */
/** { */
/** #ifdef LIBC_MALLOC */
/**     return strndup(s, n); */
/** #else */
/**     return ota_strndup(s, n); */
/** #endif */
/** } */
