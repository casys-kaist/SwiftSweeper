#include "sbpf/bpf.h"
#include "debug.h"
#include "kmalloc.h"
#include "lib/errno.h"
#include "lib/list.h"
#include "lib/stddef.h"
#include "lib/string.h"
#include "lib/types.h"
#include "stdarg.h"
#include <linux/bpf.h>
#include <bpf/bpf.h>

void sbpf_dump(struct sbpf *bpf)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	if (bpf == NULL) {
		printk("bpf is NULL\n");
		return;
	}

	int err = bpf_obj_get_info_by_fd(bpf->bpf_fd, &info, &info_len);
	if (err) {
		printk("bpf_obj_get_info_by_fd failed: %s\n", strerror(errno));
	}

	printk("Program name: %s\n", info.name);
	printk("Program xlated code size: %u bytes\n", info.xlated_prog_len);
	printk("Program jited code size:  %u bytes\n", info.jited_prog_len);
}

struct sbpf *sbpf_create_program(char *prog_path)
{
	struct bpf_object *bpf_obj = NULL;
	struct sbpf *bpf = kmalloc(sizeof(struct sbpf));
	INIT_LIST_HEAD(&bpf->maps);

	// BPF object file is parsed.
	bpf_obj = bpf_object__open(prog_path);
	if (bpf_obj == NULL) {
		PANIC("Opening eBPF program failed\n");
	}

	bpf->prog_obj = bpf_obj;

	return bpf;
}

int __attach_pinned_program(int prog_fd, enum bpf_attach_type attach_type, void *aux_ptr, size_t aux_len)
{
	DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_create_opts);
	struct bpf_link *link;
	int link_fd;

	link_create_opts.sbpf.aux_ptr = aux_ptr;
	link_create_opts.sbpf.aux_len = aux_len;

	link_fd = bpf_link_create(prog_fd, -1, attach_type, &link_create_opts);

	return link_fd;
}

struct sbpf *sbpf_attach_pinned_program(char *prog_path, enum bpf_attach_type attach_type, void *aux_ptr, size_t aux_len)
{
	struct bpf_object *bpf_obj = NULL;
	struct bpf_program *bpf_prog;
	struct sbpf *bpf = kmalloc(sizeof(struct sbpf));
	INIT_LIST_HEAD(&bpf->maps);

	// BPF object file is parsed.
	int prog_fd = bpf_obj_get(prog_path);
	int link_fd = __attach_pinned_program(prog_fd, attach_type, aux_ptr, aux_len);

	printk("prog_fd: %s %d link fd %d\n", prog_path, prog_fd, link_fd);

	// bpf->bpf_fd = bpf_program__fd(bpf_prog);
	// bpf->prog_obj = bpf_obj;
	bpf->bpf_fd = link_fd;
	bpf->prog_obj = NULL;

	return bpf;
}

bool sbpf_launch_program(struct sbpf *bpf, char *prog_name, void *aux_ptr, size_t aux_len, int map_cnt, ...)
{
	struct bpf_object *bpf_obj = NULL;
	struct bpf_program *bpf_prog;
	struct bpf_map *bpf_map;
	va_list maps;
	char *cursor_map_name;

	if (bpf == NULL || bpf->prog_obj == NULL) {
		return false;
	}

	bpf_obj = bpf->prog_obj;

	// BPF maps are created, various relocations are resolved and BPF programs are
	// loaded into the kernel and verfied. But BPF program is yet executed.
	if (bpf_object__load(bpf_obj)) {
		PANIC("Loading eBPF program failed\n");
	}

	va_start(maps, map_cnt);
	for (int i = 0; i < map_cnt; i++) {
		struct sbpf_map *map = kmalloc(sizeof(struct sbpf_map));
		cursor_map_name = va_arg(maps, char *);

		bpf_map = bpf_object__find_map_by_name(bpf_obj, cursor_map_name);
		if (bpf_map == NULL) {
			PANIC("Loading eBPF map failed\n");
		}

		map->name = cursor_map_name;
		map->map_fd = bpf_map__fd(bpf_map);
		list_add_tail(&map->list, &bpf->maps);
	}
	va_end(maps);

	// Attachment phase, This is the phase for BPF program attached to various BPF
	// hook such as tracepoints, kprobes, cgroup hooks and network packet pipeline
	// etc.

	bpf_prog = bpf_object__find_program_by_name(bpf_obj, prog_name);
	if (aux_ptr != NULL) {
		if (bpf_program__set_aux(bpf_prog, aux_ptr, aux_len))
			PANIC("Loading aux ptr failed\n");
	}

	if (bpf_program__attach(bpf_prog) == NULL) {
		PANIC("Attaching eBPF link failed\n");
	}
	bpf->bpf_fd = bpf_program__fd(bpf_prog);
	bpf->prog_obj = bpf_obj;

	return bpf;
}

int sbpf_call_function(struct sbpf *bpf, void *arg_ptr, size_t arg_len)
{
	ASSERT(bpf);

	return bpf_sbpf_call_function(bpf->bpf_fd, arg_ptr, arg_len);
}

static int get_map_fd(struct sbpf *bpf, char *map_name)
{
	struct bpf_map *bpf_map;
	bpf_map = bpf_object__find_map_by_name(bpf->prog_obj, map_name);

	return bpf_map__fd(bpf_map);
}

int sbpf_get_map_fd(struct sbpf *bpf, char *map_name)
{
	return get_map_fd(bpf, map_name);
}

int sbpf_set_map_by_fd(struct sbpf *bpf, char *map_name, int map_fd)
{
	struct sbpf_map *cur;
	struct bpf_map *map;

	if (bpf->prog_obj == NULL) {
		return -EINVAL;
	}

	map = bpf_object__find_map_by_name(bpf->prog_obj, map_name);
	if (map == NULL) {
		return -EINVAL;
	}

	int err = bpf_map__reuse_fd(map, map_fd);
	if (err) {
		printk("bpf_map__reuse_fd failed %d\n", map_fd);
		return err;
	}

	return 0;
}

long sbpf_map_lookup_elem(struct sbpf *bpf, char *map_name, long key)
{
	int map_fd;
	long value;

	ASSERT(bpf);
	ASSERT(map_name);

	map_fd = get_map_fd(bpf, map_name);
	if (map_fd < 0) {
		return -EINVAL;
	}

	if (bpf_map_lookup_elem(map_fd, &key, &value)) {
		return -EINVAL;
	}

	return value;
}

int sbpf_map_update_elem(struct sbpf *bpf, char *map_name, long key, long value)
{
	int map_fd;

	ASSERT(bpf);
	ASSERT(map_name);

	map_fd = get_map_fd(bpf, map_name);
	if (map_fd < 0) {
		return -EINVAL;
	}

	bpf_map_update_elem(map_fd, &key, &value, 0);

	return 0;
}
