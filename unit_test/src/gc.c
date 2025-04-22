#include "unit_test/debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SIZE 4096
#define POOL_SIZE (1 << 22)
#define MIN_ALLOCATION_SIZE 8
#define MAX_ALLOCATION_SIZE 2097152
#define HALF_PAGE 2048

int test_gc_small_marked()
{
	printf("test_gc_small_marked: ");
	size_t alloc_size = 32;
	int hole_idx = 10;
	void *ptrs[PAGE_SIZE / alloc_size];
	// Get dummy from different pool
	void *dummy_ptr = malloc(alloc_size * 2);

	for (int j = 0; j < PAGE_SIZE / alloc_size; j++) {
		ptrs[j] = malloc(alloc_size);
	}

	for (int i = 0; i < hole_idx; i++) {
		// Link ptrs
		for (int j = 1; j < PAGE_SIZE / alloc_size; j++)
			*(void **)ptrs[j] = (void *)ptrs[j - 1];
		*(void **)dummy_ptr = ptrs[(PAGE_SIZE / alloc_size) - 1];

		for (int j = 0; j < PAGE_SIZE / alloc_size; j++) {
			void *prev_ptr = ptrs[j];

			free(ptrs[j]);
			ptrs[j] = malloc(alloc_size);
			if (prev_ptr == ptrs[j]) {
				printf("GC not work!: prev_ptr = %p, ptrs[%d] = %p\n", prev_ptr, j, ptrs[j]);
				return -1;
			}
		}
	}
	return 0;
}

int test_gc_large_marked()
{
	printf("test_gc_large_marked: ");
	size_t alloc_size = (1 << 18);
	int hole_idx = 10;
	void *ptrs[POOL_SIZE / alloc_size];
	// Get dummy from different pool
	void *dummy_ptr = malloc(POOL_SIZE - PAGE_SIZE);

	for (int j = 0; j < POOL_SIZE / alloc_size; j++) {
		ptrs[j] = malloc(alloc_size);
	}

	for (int i = 0; i < hole_idx; i++) {
		// Link ptrs
		for (int j = 1; j < POOL_SIZE / alloc_size; j++)
			*(void **)ptrs[j] = (void *)ptrs[j - 1];
		*(void **)dummy_ptr = ptrs[(POOL_SIZE / alloc_size) - 1];

		for (int j = 0; j < POOL_SIZE / alloc_size; j++) {
			void *prev_ptr = ptrs[j];
			free(ptrs[j]);
			ptrs[j] = malloc(alloc_size);
			if (prev_ptr == ptrs[j]) {
				printf("GC not work!: prev_ptr = %p, ptrs[%d] = %p\n", prev_ptr, j, ptrs[j]);
				return -1;
			}
		}
	}
	return 0;
}

int test_gc_jumbo_unmarked()
{
	printf("test_gc_jumbo_unmarked: ");
	return 0;
}

int test_gc_jumbo_marked()
{
	printf("test_g_jumbo_marked: ");
	return 0;
}

int run_tests(int c)
{
	char test_failed = 0;

	int (*tests[])() = { test_gc_small_marked, test_gc_large_marked, test_gc_jumbo_unmarked, test_gc_jumbo_marked };

	int num_tests = sizeof(tests) / sizeof(tests[0]);

	if (c == 0) {
		for (int i = 0; i < num_tests; ++i) {
			if (tests[i]()) {
				printf("failed\n");
				test_failed = 1;
			} else {
				printf("passed\n");
			}
		}
	} else if (c >= 1 && c <= num_tests) {
		if (tests[c - 1]()) {
			printf("failed\n");
			test_failed = 1;
		} else {
			printf("passed\n");
		}
	} else {
		printf("Invalid test case\n");
		test_failed = 1;
	}

	return -test_failed;
}

int main(int argc, char **argv, char **envp)
{
	int c = argc > 1 ? atoi(argv[1]) : 0;
	return run_tests(c);
}