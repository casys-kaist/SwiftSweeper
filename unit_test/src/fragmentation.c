#include "unit_test/debug.h"
#include "gc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Test small pool behavior with full page allocation and deallocation
// Using BIN 31: allocSize = 16, maxAlloc = 256
void test_full_page()
{
	void *allocations[256];
	int num_allocation = 256;
	size_t allocation_size = 16;
	size_t total_allocated = 0;
	size_t total_used = 0;

	// Allocate memory to fill up a page
	for (int i = 0; i < num_allocation; i++) {
		allocations[i] = malloc(allocation_size);
		ASSERT(allocations[i] != NULL);
		total_allocated += allocation_size;
		total_used += allocation_size;
	}

	// TODO: Add assertion to check fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	// Create 50% fragmentation by freeing every other allocation
	for (int i = 1; i < num_allocation; i += 2) {
		free(allocations[i]);
		allocations[i] = NULL;
		total_used -= allocation_size;
	}

	// TODO: Add assertion to check fragmentation rate matches expected value
	// ASSERT(check_fragmentation() == calculate_fragmentation_rate(total_allocated, total_used));

	// Increase fragmentation to ~99% by freeing remaining half, leaving index 0
	for (int i = 2; i < num_allocation; i += 2) {
		free(allocations[i]);
		allocations[i] = NULL;
		total_used -= allocation_size;
	}

	// TODO: Add assertion to check updated fragmentation rate
	// ASSERT(check_fragmentation() == calculate_fragmentation_rate(total_allocated, total_used));

	// Free the last allocation, which should trigger page deallocation
	free(allocations[0]);
	allocations[0] = NULL;
	total_used -= allocation_size;
	total_allocated = 0;

	ASSERT(total_used == 0);

	// After page deallocation, fragmentation should return to 0%
	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	return;
}

// Test small pool behavior with partial page allocation and deallocation
// Using BIN 16: allocSize = 256, maxAlloc = 16
void test_partial_page()
{
	void *allocations[15];
	int num_allocation = 15;
	size_t allocation_size = 256;

	// Allocate memory to fill 15/16 of a page
	for (int i = 0; i < num_allocation; i++) {
		allocations[i] = malloc(allocation_size);
		ASSERT(allocations[i] != NULL);
	}

	// Free every allocation, creating fragmentation
	for (int i = 0; i < num_allocation; i++) {
		free(allocations[i]);
		allocations[i] = NULL;
	}

	// At this point, the page should be fully fragmented, but not eligible for deallocation
	// TODO: Add assertion to verify fragmentation rate is 100%
	// ASSERT(check_fragmentation() == 100);

	// Allocate and immediately free one more chunk
	// This should trigger the page to become eligible for deallocation
	void *ptr = malloc(allocation_size);
	free(ptr);

	// After this operation, the page should be fully deallocated
	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	return;
}

// Test basic functionality of large pool allocations and deallocations
void test_large_pool_basic()
{
	void *allocations[100];
	int num_allocation = 100;
	size_t allocation_size = 10000; // Large enough to use the large pool
	size_t total_allocated = 0;
	size_t total_used = 0;

	// Allocate multiple large chunks of memory
	for (int i = 0; i < num_allocation; i++) {
		allocations[i] = malloc(allocation_size);
		ASSERT(allocations[i] != NULL);
		total_allocated += allocation_size;
		total_used += allocation_size;
	}

	// At this point, all allocations should be in use with no fragmentation
	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	// Create fragmentation by freeing every 4th allocation
	for (int i = 0; i < num_allocation; i += 4) {
		free(allocations[i]);
		allocations[i] = NULL;
		total_used -= allocation_size;
	}

	// TODO: Add assertion to check if actual fragmentation rate matches expected value
	// ASSERT(check_fragmentation() == calculate_fragmentation_rate(total_allocated, total_used));

	// Free all remaining allocations
	for (int i = 0; i < num_allocation; i++) {
		if (allocations[i] != NULL) {
			free(allocations[i]);
			allocations[i] = NULL;
			total_used -= allocation_size;
		}
	}
	ASSERT(total_used == 0);
	total_allocated = 0;

	// After freeing all allocations, fragmentation should return to 0%
	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	return;
}

// Test edge case behavior of large pool allocations
// This test checks the scenario where the remaining bytes in the large pool
// are less than (HALF_PAGE + MIN_ALIGNMENT) after multiple allocations
void test_large_pool_edge()
{
	void *allocations[4];
	int num_allocation = 4;
	size_t allocation_size = 1048400; // Chosen to leave 704 bytes in a 4MB pool after 4 allocations
	size_t total_allocated = 0;
	size_t total_used = 0;

	// Allocate 1,048,400 bytes 3 times
	for (int i = 0; i < num_allocation - 1; i++) {
		allocations[i] = malloc(allocation_size);
		ASSERT(allocations[i] != NULL);
		total_allocated += allocation_size;
		total_used += allocation_size;
	}

	// Perform the 4th allocation
	// This should trigger the edge case where the remaining 704 bytes are also allocated
	allocations[3] = malloc(allocation_size);
	ASSERT(allocations[3] != NULL);
	total_allocated += (allocation_size + 704); // Account for the extra 704 bytes
	total_used += (allocation_size + 704);

	// Free one of the standard-sized allocations
	free(allocations[0]);
	total_used -= allocation_size;

	// At this point, we expect some fragmentation
	// TODO: Add assertion to check if actual fragmentation rate matches expected value
	// ASSERT(check_fragmentation() == calculate_fragmentation_rate(total_allocated, total_used));

	// Free the special allocation that includes the extra 704 bytes
	free(allocations[3]);
	total_used -= (allocation_size + 704);

	// TODO: Add assertion to check if actual fragmentation rate matches expected value
	// ASSERT(check_fragmentation() == calculate_fragmentation_rate(total_allocated, total_used));

	// Clean up remaining allocations
	for (int i = 1; i < num_allocation - 1; i++) {
		free(allocations[i]);
		total_used -= allocation_size;
	}
	ASSERT(total_used == 0);
	total_allocated = 0;

	return;
}

void test_jumbo_pool()
{
	void *allocations[5];
	int num_allocations = 5;
	size_t allocation_size = 5000000;

	// Allocate jumbo chunks
	for (int i = 0; i < num_allocations; i++) {
		allocations[i] = malloc(allocation_size);
		ASSERT(allocations[i] != NULL);
	}

	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	// Free one of the allocation
	free(allocations[2]);
	allocations[2] = NULL;

	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);

	// Clean up
	for (int i = 0; i < num_allocations; i++) {
		if (allocations[i] != NULL) {
			free(allocations[i]);
		}
	}

	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(check_fragmentation() == 0);
	return;
}

// Test mixed allocations across small, large, and jumbo pools
void test_mixed_pool()
{
	void *small_allocs[50];
	void *large_allocs[20];
	void *jumbo_allocs[2];
	size_t small_size = 16; // Small allocation size (BIN 31)
	size_t large_size = 10000; // Large allocation size
	size_t jumbo_size = 5000000; // Jumbo allocation size (> POOL_SIZE)
	size_t total_allocated = 0;
	size_t total_used = 0;

	// Allocate mixed sizes
	for (int i = 0; i < 50; i++) {
		small_allocs[i] = malloc(small_size);
		ASSERT(small_allocs[i] != NULL);
		total_allocated += small_size;
		total_used += small_size;
	}
	for (int i = 0; i < 20; i++) {
		large_allocs[i] = malloc(large_size);
		ASSERT(large_allocs[i] != NULL);
		total_allocated += large_size;
		total_used += large_size;
	}
	for (int i = 0; i < 2; i++) {
		jumbo_allocs[i] = malloc(jumbo_size);
		ASSERT(jumbo_allocs[i] != NULL);
		total_allocated += jumbo_size;
		total_used += jumbo_size;
	}

	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(fragmentation == 0);

	// Free some allocations to create fragmentation
	for (int i = 0; i < 50; i += 2) {
		free(small_allocs[i]);
		small_allocs[i] = NULL;
		total_used -= small_size;
	}
	for (int i = 0; i < 20; i += 3) {
		free(large_allocs[i]);
		large_allocs[i] = NULL;
		total_used -= large_size;
	}
	free(jumbo_allocs[0]);
	jumbo_allocs[0] = NULL;
	total_used -= jumbo_size;

	// TODO: Add assertion to check if actual fragmentation rate matches expected value
	// ASSERT(fragmentation == calculate_fragmentation_rate(total_allocated, total_used));

	// Free all remaining allocations
	for (int i = 0; i < 50; i++) {
		if (small_allocs[i] != NULL) {
			free(small_allocs[i]);
			total_used -= small_size;
		}
	}
	for (int i = 0; i < 20; i++) {
		if (large_allocs[i] != NULL) {
			free(large_allocs[i]);
			total_used -= large_size;
		}
	}
	if (jumbo_allocs[1] != NULL) {
		free(jumbo_allocs[1]);
		total_used -= jumbo_size;
	}
	ASSERT(total_used == 0);
	total_allocated = 0;

	// After freeing all allocations, fragmentation should return to 0%
	// TODO: Add assertion to verify fragmentation rate is 0%
	// ASSERT(fragmentation == 0);

	return;
}

int main()
{
	// Test1: small pool only
	test_partial_page();
	test_full_page();

	// Test2: large pool only
	test_large_pool_basic();
	test_large_pool_edge();

	// Test3: jumbo pool only
	test_jumbo_pool();

	// Test4: mixed pool
	test_mixed_pool();

	return 0;
}
