// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2026 Alexandre Boutrik
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The restricted in-kernel eBPF program.
 * We hook into the 'sys_enter_write' tracepoint because it guarantees
 * stable Kernel ABI compatibility across Linux versions (unlike kprobes
 * which are susceptible to internal signature changes, such as tty_write).
 *
 * Intercepted data is filtered by PID, checked against a heuristic pipe
 * filter to eliminate subshell noise, and pushed asynchronously to
 * user-space via a BPF ring buffer.
 */

// clang-format off
#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
// clang-format on

#define PAYLOAD_SIZE 256

/*
 * Structure must exactly match the memory layout defined in loader.h
 * and the Haskell Storable instance.
 * Total size: 260 bytes (4-byte alignment).
 */
struct ebpf_event {
	__u32 root_pid;
	__u32 actual_pid;
	__u32 fd;
	__u8 payload[PAYLOAD_SIZE];
};

/*
 * The eBPF Ring Buffer map used to stream captured terminal chunks
 * to the Haskell user-space polling thread. Configured for
 * 256 KB capacity.
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256 KB buffer capacity
} events SEC(".maps");

/*
 * Represents the memory layout of the kernel's native 'iovec' structure.
 * Utilized to safely boundary-check and extract memory pointers from
 * vectorized I/O payloads passed by user-space applications.
 */
struct user_iovec {
	const char *iov_base;
	unsigned long iov_len;
};

/*
 * A Hash Map populated initially by Haskell with the root SSH Bash PIDs.
 * It is dynamically maintained by the kernel (via fork/exit tracepoints)
 * to track all child processes spawned within those monitored sessions.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);	  // Current active PID
	__type(value, __u32); // Root Bash PID (Session leader)
} monitored_pids SEC(".maps");

struct trace_event_raw_sys_enter {
	__u64 unused_ent;
	long int id;
	unsigned long args[6];
};

struct trace_event_raw_sched_process_fork {
	__u64 unused_ent;
	char parent_comm[16];
	__u32 parent_pid;
	char child_comm[16];
	__u32 child_pid;
};

struct trace_event_raw_sched_process_exit {
	__u64 unused_ent;
	char comm[16];
	__u32 pid;
	int prio;
};

/*
 * Automatically tracks child processes spawned by monitored SSH sessions.
 * If a monitored parent forks, we map the new child PID back to the
 * root session.
 */
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx) {
	__u32 parent_pid = ctx->parent_pid;
	__u32 child_pid = ctx->child_pid;

	__u32 *root_pid = bpf_map_lookup_elem(&monitored_pids, &parent_pid);
	if (root_pid) {
		// Parent is monitored, so track the child and map it to the root PID
		bpf_map_update_elem(&monitored_pids, &child_pid, root_pid, BPF_ANY);
	}
	return 0;
}

/*
 * Cleans up the tracking map when processes die.
 * This is critical to prevent memory exhaustion in the kernel map
 * over time.
 */
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx) {
	__u32 pid = ctx->pid;
	bpf_map_delete_elem(&monitored_pids, &pid);
	return 0;
}

/*
 * The primary terminal capture hook.
 * Intercepts user-space writes, validates the process, applies heuristic
 * file descriptor filters, and copies the data to the ring buffer.
 */
SEC("tracepoint/syscalls/sys_enter_write")
int handle_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
	// Extract Process ID
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;

	__u32 *root_pid = bpf_map_lookup_elem(&monitored_pids, &pid);
	if (!root_pid) {
		return 0; // Ignore writes from unmonitored system processes
	}

	int fd = ctx->args[0];

	if (*root_pid == pid) {
		if (fd != 1 && fd != 2)
			return 0;
	} else {
		// This is a child process spawned within the session.
		// VFS-Free Pipe Filter: Autocomplete scripts rely on 'bash'
		// subshells. By ignoring stdout writes from processes named
		// 'bash', we prevent internal pipe garbage from leaking into
		// the UI without needing complex kernel VFS structure traversal.
		char comm[16];
		bpf_get_current_comm(&comm, sizeof(comm));
		if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' &&
			comm[3] == 'h' && comm[4] == '\0') {
			return 0;
		}

		// Normal child process (e.g. ls, grep): capture stdout/stderr
		if (fd != 1 && fd != 2)
			return 0;
	}

	const char *buf = (const char *)ctx->args[1];
	unsigned long count = ctx->args[2];

	// Reserve space in the ring buffer
	struct ebpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0; // Buffer is full; gracefully drop the event to avoid crashes

	e->root_pid = *root_pid;
	e->actual_pid = pid;
	e->fd = fd;

	// Bound the read size to our payload limit
	if (count > PAYLOAD_SIZE - 1) {
		count = PAYLOAD_SIZE - 1;
	}

	// Safely read the memory from the user-space process into our kernel map
	bpf_probe_read_user(e->payload, count, buf);

	// Null-terminate the string chunk to prevent reading garbage memory later
	e->payload[count] = '\0';

	// Submit the populated struct to user-space
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Secondary terminal capture hook targeting vectorized writes (writev).
 *
 * Modernized terminal applications (e.g., Neovim, Tmux) and asynchronous
 * runtimes (e.g., Node.js via libuv) bypass standard 'write' syscalls.
 * They utilize 'writev' to flush multiple UI rendering buffers to the
 * pseudo-terminal (PTY) in a single, zero-copy kernel context switch.
 */
SEC("tracepoint/syscalls/sys_enter_writev")
int handle_sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;

	__u32 *root_pid = bpf_map_lookup_elem(&monitored_pids, &pid);
	if (!root_pid) {
		return 0;
	}

	int fd = ctx->args[0];

	/*
	 * Note: We explicitly do NOT filter by standard file descriptors
	 * (fd == 1 || fd == 2) here. Advanced TUI applications open the
	 * assigned TTY device directly (e.g., fd 19) to assert raw control
	 * over terminal emulation, bypassing stdout/stderr entirely.
	 */

	if (*root_pid != pid) {
		char comm[16];
		bpf_get_current_comm(&comm, sizeof(comm));
		// Still drop bash internal pipe noise
		if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' &&
			comm[3] == 'h' && comm[4] == '\0') {
			return 0;
		}
	}

	const struct user_iovec *iov = (const struct user_iovec *)ctx->args[1];
	unsigned long iovcnt = ctx->args[2];

	if (iovcnt == 0)
		return 0;

	struct user_iovec vec;

	/*
	 * Vector Array Traversal & Emisson:
	 * Optimized runtimes frequently fragment sequences (e.g., placing
	 * an empty string in iov[0] and the ANSI payload in iov[1]).
	 *
	 * Rather than performing unsafe pointer arithmetic to concatenate these
	 * vectors in kernel-space—which triggers eBPF verifier rejections due
	 * to unprovable memory bounds - we iterate through the array and emit
	 * each valid vector as a discrete ring buffer event. The user-space
	 * Haskell daemon handles the reassembly seamlessly.
	 */
#pragma unroll
	for (int i = 0; i < 4; i++) {
		if (i >= iovcnt)
			break;

		// Safely probe the user-space iovec array index
		if (bpf_probe_read_user(&vec, sizeof(vec), &iov[i]) == 0) {
			unsigned long chunk_len = vec.iov_len;

			if (chunk_len > 0) {
				// Bound the read to our maximum fixed payload capacity
				if (chunk_len > PAYLOAD_SIZE - 1) {
					chunk_len = PAYLOAD_SIZE - 1;
				}

				// The kernel's static eBPF verifier requires mathematical
				// proof that 'chunk_len' cannot exceed 255 before invoking
				// bpf_probe_read_user. A bitwise AND securely enforces
				// this boundary constraint.
				chunk_len &= 0xFF;

				struct ebpf_event *e =
					bpf_ringbuf_reserve(&events, sizeof(*e), 0);
				if (e) {
					e->root_pid = *root_pid;
					e->actual_pid = pid;
					e->fd = fd;

					bpf_probe_read_user(e->payload, chunk_len, vec.iov_base);
					e->payload[chunk_len] = '\0';

					bpf_ringbuf_submit(e, 0);
				}
			}
		}
	}

	return 0;
}

// Required by the Linux kernel to load eBPF programs
char LICENSE[] SEC("license") = "GPL";
