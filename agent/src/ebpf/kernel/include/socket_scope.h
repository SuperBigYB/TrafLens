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
union socket_scope_cursor {
	void *pointer;
	__u64 alignment;
	__u32 inum;
};
struct socket_scope_scratch {
	union socket_scope_cursor cursor;
	volatile __u64 depth;
};
#ifdef __BPF_TRACING__
static __inline bool socket_scope_allows_task(const struct socket_scope_config *scope, void *task,
                                              struct socket_scope_scratch *scratch)
{
	if (!scope)
		return false;
	if (scope->netns_id == 0)
		return true;
	if (scope->validated != 1 || !task || !scratch ||
	    scope->task_nsproxy_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->nsproxy_net_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->net_ns_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->ns_inum_offset > SOCKET_SCOPE_OFFSET_MAX ||
	    scope->net_ns_offset > SOCKET_SCOPE_OFFSET_MAX - scope->ns_inum_offset)
		return false;
	/* Legacy XADD with the returned value unused. CPU migration is disabled
	 * by these non-sleepable tracing entrypoints, but task preemption need
	 * not be. Every entrant owns one depth contribution. Only depth==1 can
	 * touch the cursor; others release their own contribution and deny. */
	__sync_fetch_and_add(&scratch->depth, 1);
	asm volatile("" ::: "memory");
	__u32 allowed = 0;
	if (scratch->depth != 1)
		goto out;
	scratch->cursor.pointer = task;
	if (bpf_probe_read(&scratch->cursor.pointer, sizeof(scratch->cursor.pointer),
			   (char *)scratch->cursor.pointer + scope->task_nsproxy_offset) ||
	    !scratch->cursor.pointer)
		goto out;
	if (bpf_probe_read(&scratch->cursor.pointer, sizeof(scratch->cursor.pointer),
			   (char *)scratch->cursor.pointer + scope->nsproxy_net_offset) ||
	    !scratch->cursor.pointer)
		goto out;
	if (bpf_probe_read(&scratch->cursor.inum, sizeof(scratch->cursor.inum),
			   (char *)scratch->cursor.pointer + scope->net_ns_offset + scope->ns_inum_offset))
		goto out;
	allowed = scratch->cursor.inum != 0 && scratch->cursor.inum == scope->netns_id;
out:
	/* Force the decision into a scalar before another caller can reuse the
	 * map cursor. Every entrant releases exactly its own depth contribution. */
	asm volatile("" : "+r"(allowed) :: "memory");
	__sync_fetch_and_add(&scratch->depth, (__u64)-1);
	return allowed;
}
#endif
#endif
