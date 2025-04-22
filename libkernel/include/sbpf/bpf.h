#pragma once

#include "lib/list.h"
#include "lib/types.h"
#include <linux/bpf.h>

struct sbpf_map {
	char *name;
	int map_fd;
	struct list_head list;
};

struct sbpf {
	int bpf_fd;
	int map_fd;
	struct bpf_object *prog_obj;
	struct list_head maps;
};

// Forward declaration of the libbpf
struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;

// Libbpf APIs
struct bpf_object *bpf_object__open(const char *path);
int bpf_object__load(struct bpf_object *obj);
struct bpf_map *bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name);
int bpf_map__fd(const struct bpf_map *map);
struct bpf_program *bpf_object__find_program_by_name(const struct bpf_object *obj, const char *name);
int bpf_program__set_aux(struct bpf_program *prog, void *aux_ptr, size_t len);
struct bpf_link *bpf_program__attach(const struct bpf_program *prog);
int bpf_program__fd(const struct bpf_program *prog);
int bpf_map_lookup_elem(int fd, const void *key, void *value);
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags);
int bpf_sbpf_call_function(int fd, void *arg_ptr, size_t arg_len);
int bpf_map__reuse_fd(struct bpf_map *map, int fd);
int bpf_obj_get_info_by_fd(int bpf_fd, void *info, __u32 *info_len);
int bpf_program__pin(struct bpf_program *prog, const char *path);
int bpf_obj_get(const char *pathname);

// sBPF APIs
struct sbpf *sbpf_create_program(char *prog_path);
bool sbpf_launch_program(struct sbpf *bpf, char *prog_name, void *aux_ptr, size_t aux_len, int map_cnt, ...);
int sbpf_call_function(struct sbpf *bpf, void *arg_ptr, size_t arg_len);
long sbpf_map_lookup_elem(struct sbpf *bpf, char *map_name, long key);
int sbpf_map_update_elem(struct sbpf *bpf, char *map_name, long key, long value);
int sbpf_get_map_fd(struct sbpf *bpf, char *map_name);
int sbpf_set_map_by_fd(struct sbpf *bpf, char *map_name, int map_fd);
struct sbpf *sbpf_attach_pinned_program(char *prog_path, enum bpf_attach_type type, void *aux_ptr, size_t aux_len);
void sbpf_dump(struct sbpf *bpf);
