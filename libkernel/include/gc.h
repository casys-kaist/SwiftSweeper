#pragma once

#include "ota.h"
#include <stddef.h>
#include <stdint.h>
#include <signal.h>

void *stack_bottom;
void *stack_top;

extern uint64_t total_large_allocated_memory;
extern uint64_t total_large_used_memory;
extern uint64_t total_small_allocated_memory;
extern uint64_t total_small_used_memory;
extern uint64_t total_dangling_pointer;

struct free_list_entry {
	void *next_ptr;
	struct pagemap_t *pagemap;
};

void gc_run_mark();
void *gc_pop_free_list(struct arena_t *arena, size_t size);

static inline void *get_stack_pointer()
{
	void *stack_ptr;
	asm("movq %%rsp, %0" : "=r"(stack_ptr));
	return stack_ptr;
}

#ifdef CONFIG_ENABLE_GC
// Updates the total_allocated_memory counter atomically.
// Adds size_change if positive, subtracts its absolute value if negative.
#define update_allocated_large_memory(size_change) FFAtomicAdd(total_large_allocated_memory, size_change)
#define update_used_large_memory(size_change) FFAtomicAdd(total_large_used_memory, size_change)
#define update_allocated_small_memory(size_change) FFAtomicAdd(total_small_allocated_memory, size_change)
#define update_used_small_memory(size_change) FFAtomicAdd(total_small_used_memory, size_change)
#else
#define update_allocated_large_memory(size_change) ((void)0)
#define update_used_large_memory(size_change) ((void)0)
#define update_allocated_small_memory(size_change) ((void)0)
#define update_used_small_memory(size_change) ((void)0)
#endif
