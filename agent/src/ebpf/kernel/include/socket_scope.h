/* SPDX-License-Identifier: GPL-2.0
 * Optional current-task network namespace scope for socket-tracer records.
 * Namespace lifetime must be pinned by the caller; this is not socket ownership.
 */
#ifndef DF_SOCKET_SCOPE_H
#define DF_SOCKET_SCOPE_H
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#define SOCKET_SCOPE_OFFSET_MAX 65535U
struct socket_scope_config {
	__u32 netns_id; /* zero preserves legacy, unscoped behavior */
	__u32 validated;
	__u32 task_nsproxy_offset;
	__u32 nsproxy_net_offset;
	__u32 net_ns_offset;
	__u32 ns_inum_offset;
};
#ifdef __BPF_TRACING__
static __inline bool socket_scope_allows_task(const struct socket_scope_config *scope, void *task)
{
	if (!scope)
		return false;
	if (scope->netns_id == 0)
		return true;
	if (scope->validated != 1 || !task ||
	    scope->task_nsproxy_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->nsproxy_net_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->net_ns_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->ns_inum_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->net_ns_offset > SOCKET_SCOPE_OFFSET_MAX - scope->ns_inum_offset)
		return false;
	union {
		void *pointer;
		__u64 alignment;
		__u32 inum;
	} cursor = {.pointer = task};
	/* Reuse one eight-byte stack slot across the pointer chain. The inode
	 * shares its address, not a numeric low-half cast, on either endianness.
	 * Helper 4 also works in legacy objects; every failed/partial read denies. */
	if (bpf_probe_read(&cursor.pointer, sizeof(cursor.pointer),
			   (char *)cursor.pointer + scope->task_nsproxy_offset) ||
	    !cursor.pointer)
		return false;
	if (bpf_probe_read(&cursor.pointer, sizeof(cursor.pointer),
			   (char *)cursor.pointer + scope->nsproxy_net_offset) ||
	    !cursor.pointer)
		return false;
	if (bpf_probe_read(&cursor.inum, sizeof(cursor.inum),
			   (char *)cursor.pointer + scope->net_ns_offset + scope->ns_inum_offset))
		return false;
	return cursor.inum != 0 && cursor.inum == scope->netns_id;
}
#endif
#endif
