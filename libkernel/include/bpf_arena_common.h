/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#pragma once

#ifndef bpf_addr_space_cast
#define bpf_addr_space_cast(var, dst_as, src_as)\
	asm volatile(".byte 0xBF;		\
		     .ifc %[reg], r0;		\
		     .byte 0x00;		\
		     .endif;			\
		     .ifc %[reg], r1;		\
		     .byte 0x11;		\
		     .endif;			\
		     .ifc %[reg], r2;		\
		     .byte 0x22;		\
		     .endif;			\
		     .ifc %[reg], r3;		\
		     .byte 0x33;		\
		     .endif;			\
		     .ifc %[reg], r4;		\
		     .byte 0x44;		\
		     .endif;			\
		     .ifc %[reg], r5;		\
		     .byte 0x55;		\
		     .endif;			\
		     .ifc %[reg], r6;		\
		     .byte 0x66;		\
		     .endif;			\
		     .ifc %[reg], r7;		\
		     .byte 0x77;		\
		     .endif;			\
		     .ifc %[reg], r8;		\
		     .byte 0x88;		\
		     .endif;			\
		     .ifc %[reg], r9;		\
		     .byte 0x99;		\
		     .endif;			\
		     .short %[off];		\
		     .long %[as]"		\
		     : [reg]"+r"(var)		\
		     : [off]"i"(BPF_ADDR_SPACE_CAST) \
		     , [as]"i"((dst_as << 16) | src_as));
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *) &(x)) = (val))
#endif

#ifndef NUMA_NO_NODE
#define	NUMA_NO_NODE	(-1)
#endif

#ifndef arena_container_of
#define arena_container_of(ptr, type, member)			\
	({							\
		void __arena *__mptr = (void __arena *)(ptr);	\
		((type *)(__mptr - offsetof(type, member)));	\
	})
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE __PAGE_SIZE
/*
 * for older kernels try sizeof(struct genradix_node)
 * or flexible:
 * static inline long __bpf_page_size(void) {
 *   return bpf_core_enum_value(enum page_size_enum___l, __PAGE_SIZE___l) ?: sizeof(struct genradix_node);
 * }
 * but generated code is not great.
 */
#endif

#define __arena
#define cast_kern(ptr) bpf_addr_space_cast(ptr, 0, 1)
#define cast_user(ptr) bpf_addr_space_cast(ptr, 1, 0)

// void __arena* bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
// 				    int node_id, __u64 flags) __ksym __weak;
// void bpf_arena_free_pages(void *map, void __arena *ptr, __u32 page_cnt) __ksym __weak;