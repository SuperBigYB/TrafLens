/* SPDX-License-Identifier: Apache-2.0 */
#ifndef DF_USER_SOCKET_SCOPE_H
#define DF_USER_SOCKET_SCOPE_H
#include "../kernel/include/socket_scope.h"
#include <bcc/linux/btf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

struct btf;
extern void btf__free(struct btf *);
extern const char *btf__name_by_offset(const struct btf *, __u32);
extern const struct btf_type *btf__type_by_id(const struct btf *, __u32);
extern __s32 btf__find_by_name_kind(const struct btf *, const char *, __u32);

/* The caller serializes these state operations with its private mutex. */
struct socket_scope_state {
	__u32 netns_id;
	bool frozen;
};
static inline int socket_scope_set(struct socket_scope_state *state, uint64_t inode)
{
	if (inode > UINT32_MAX)
		return -EINVAL;
	if (state->frozen)
		return -EBUSY;
	state->netns_id = (__u32)inode;
	return 0;
}
static inline __u32 socket_scope_freeze(struct socket_scope_state *state)
{
	state->frozen = true;
	return state->netns_id;
}

/* Scoped retries need a fresh process: failed loads can retain owned BPF
 * resources. Keep the preexisting unscoped retry behavior unchanged. */
static inline int socket_scope_begin(struct socket_scope_state *state, __u32 *target)
{
	if (state->frozen && state->netns_id != 0)
		return -EALREADY;
	*target = socket_scope_freeze(state);
	return 0;
}

static inline const struct btf_type *socket_scope_type(const struct btf *btf, __u32 id)
{
	for (int i = 0; i < 32; i++) {
		const struct btf_type *type = btf__type_by_id(btf, id);
		if (!type)
			return NULL;
		unsigned kind = BTF_INFO_KIND(type->info);
		if (kind != BTF_KIND_TYPEDEF && kind != BTF_KIND_CONST &&
		    kind != BTF_KIND_VOLATILE && kind != BTF_KIND_RESTRICT)
			return type;
		id = type->type;
	}
	return NULL;
}

/* Only exact named fields, byte-aligned non-bitfields, and expected types.
 * No inferred offsets, hardcoded kernel layouts or anonymous-field guessing. */
static inline bool socket_scope_member(const struct btf *btf, const char *parent_name,
				       const char *field_name, const char *struct_name,
				       bool pointer, __u32 *offset)
{
	int id = btf__find_by_name_kind(btf, parent_name, BTF_KIND_STRUCT);
	if (id <= 0)
		return false;
	const struct btf_type *parent = btf__type_by_id(btf, id);
	if (!parent || BTF_INFO_KIND(parent->info) != BTF_KIND_STRUCT)
		return false;
	const struct btf_member *members = (const void *)(parent + 1), *found = NULL;
	for (unsigned i = 0; i < BTF_INFO_VLEN(parent->info); i++) {
		const char *name = btf__name_by_offset(btf, members[i].name_off);
		if (name && strcmp(name, field_name) == 0) {
			if (found)
				return false;
			found = &members[i];
		}
	}
	if (!found)
		return false;
	__u32 bits = found->offset;
	if (parent->info >> 31) {
		if (bits >> 24)
			return false;
		bits &= 0xffffff;
	}
	if (bits % 8 || bits / 8 > SOCKET_SCOPE_OFFSET_MAX)
		return false;
	const struct btf_type *type = socket_scope_type(btf, found->type);
	if (!type)
		return false;
	__u32 width;
	if (pointer) {
		if (BTF_INFO_KIND(type->info) != BTF_KIND_PTR)
			return false;
		width = sizeof(void *);
		type = socket_scope_type(btf, type->type);
		if (!type)
			return false;
	} else {
		width = type->size;
	}
	if (struct_name) {
		const char *name = btf__name_by_offset(btf, type->name_off);
		if (BTF_INFO_KIND(type->info) != BTF_KIND_STRUCT || !name ||
		    strcmp(name, struct_name))
			return false;
	} else {
		if (BTF_INFO_KIND(type->info) != BTF_KIND_INT || width != sizeof(__u32))
			return false;
		__u32 encoding = *(const __u32 *)(type + 1);
		if (BTF_INT_ENCODING(encoding) != 0 || BTF_INT_OFFSET(encoding) != 0 ||
		    BTF_INT_BITS(encoding) != 32)
			return false;
	}
	__u32 bytes = bits / 8;
	if (width == 0 || bytes > parent->size || width > parent->size - bytes)
		return false;
	*offset = bytes;
	return true;
}

static inline int socket_scope_resolve(const struct btf *btf, __u32 target,
				       struct socket_scope_config *result)
{
	memset(result, 0, sizeof(*result));
	if (!target)
		return 0;
	if (!btf || (uintptr_t)btf >= (uintptr_t)-4095)
		return -ENOTSUP;
	struct socket_scope_config scope = {.netns_id = target, .validated = 1};
	if (!socket_scope_member(btf, "task_struct", "nsproxy", "nsproxy", true,
				 &scope.task_nsproxy_offset) ||
	    !socket_scope_member(btf, "nsproxy", "net_ns", "net", true,
				 &scope.nsproxy_net_offset) ||
	    !socket_scope_member(btf, "net", "ns", "ns_common", false, &scope.net_ns_offset) ||
	    !socket_scope_member(btf, "ns_common", "inum", NULL, false, &scope.ns_inum_offset) ||
	    scope.net_ns_offset > SOCKET_SCOPE_OFFSET_MAX - scope.ns_inum_offset)
		return -ENOTSUP;
	*result = scope;
	return 0;
}
#endif
