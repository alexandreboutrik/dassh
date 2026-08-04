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
#include "syscalls.h"
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

/*
 * Helper: Safely reads data from user-space memory into a newly reserved
 * ring buffer event. Enforces static boundary constraints to satisfy the
 * eBPF verifier.
 */
static __always_inline void emit_event(__u32 root_pid, __u32 actual_pid, int fd,
									   const char *buf, unsigned long count) {
	if (count == 0)
		return;

	// Bound the read size to our payload limit
	if (count > PAYLOAD_SIZE - 1) {
		count = PAYLOAD_SIZE - 1;
	}

	// The kernel's static eBPF verifier requires mathematical proof that
	// 'count' cannot exceed 255. A bitwise AND securely enforces
	// this boundary.
	count &= 0xFF;

	struct ebpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return; // Buffer is full; gracefully drop the event

	e->root_pid = root_pid;
	e->actual_pid = actual_pid;
	e->fd = fd;

	// Safely read the memory from the user-space process into our kernel map
	bpf_probe_read_user(e->payload, count, buf);
	e->payload[count] = '\0';

	bpf_ringbuf_submit(e, 0);
}

/*
 * BPF CO-RE (Compile Once - Run Everywhere) struct.
 * We target 'tgid' (Thread Group ID), because in the Linux kernel, the TGID
 * is what user-space applications recognize as the Process ID (PID).
 */
struct task_struct {
	int tgid;
} __attribute__((preserve_access_index));

/*
 * Automatically tracks child processes spawned by monitored SSH sessions.
 * If a monitored parent forks, we map the new child PID back to the
 * root session.
 */
SEC("raw_tp/sched_process_fork")
int handle_fork(struct bpf_raw_tracepoint_args *ctx) {
	struct task_struct *child = (struct task_struct *)ctx->args[1];

	__u32 parent_pid = bpf_get_current_pid_tgid() >> 32;
	__u32 child_pid = BPF_CORE_READ(child, tgid);

	__u32 *root_pid = bpf_map_lookup_elem(&monitored_pids, &parent_pid);
	if (root_pid) {
		bpf_map_update_elem(&monitored_pids, &child_pid, root_pid, BPF_ANY);
	}
	return 0;
}

/*
 * Cleans up the tracking map when processes die to prevent memory leaks.
 */
SEC("raw_tp/sched_process_exit")
int handle_exit(struct bpf_raw_tracepoint_args *ctx) {
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	bpf_map_delete_elem(&monitored_pids, &pid);
	return 0;
}

/*
 * The primary terminal capture hook.
 * Combines sys_enter_write and sys_enter_writev into a single raw tracepoint.
 * Bypasses the blocked perf_event tracing subsystem.
 */
SEC("raw_tp/sys_enter")
int handle_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
	long syscall_id = ctx->args[1];

	// Filter for architecture-specific write/writev and zero-copy syscalls
	if (syscall_id != SYS_WRITE && syscall_id != SYS_WRITEV &&
		syscall_id != SYS_SPLICE && syscall_id != SYS_SENDFILE64)
		return 0;

	// Extract Process ID
	__u64 id = bpf_get_current_pid_tgid();
	__u32 pid = id >> 32;

	__u32 *root_pid = bpf_map_lookup_elem(&monitored_pids, &pid);
	if (!root_pid)
		return 0;

	/*
	 * Kernel Memory Copy & AppArmor Bypass:
	 * We copy the architecture registers from kernel memory into the BPF
	 * stack. This satisfies the eBPF verifier (bypassing scalar memory
	 * access blocks) and avoids BTF register name mismatches (e.g. rdi vs
	 * di).
	 */
	struct pt_regs regs;
	if (bpf_probe_read_kernel(&regs, sizeof(regs), (void *)ctx->args[0]) != 0)
		return 0;

	// Use standard macros on our stack copy to extract the file descriptor
	int fd = PT_REGS_PARM1(&regs);

	if (*root_pid != pid) {
		// VFS-Free Pipe Filter: Autocomplete scripts rely on 'bash'
		// subshells. By ignoring stdout writes from processes named
		// 'bash', we prevent internal pipe garbage from leaking into
		// the UI.
		char comm[16];
		bpf_get_current_comm(&comm, sizeof(comm));
		if (comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' &&
			comm[3] == 'h' && comm[4] == '\0') {
			return 0;
		}

		// Block systemd/vte prompt hook utilities writing to background pipes
		if (comm[0] == 's' && comm[1] == 'e' && comm[2] == 'd' &&
			comm[3] == '\0')
			return 0;
	}

	// Route 1: Standard sys_write
	if (syscall_id == SYS_WRITE) {
		if (fd != 1 && fd != 2)
			return 0; // Only capture stdout/stderr

		const char *buf = (const char *)PT_REGS_PARM2(&regs);
		unsigned long count = PT_REGS_PARM3(&regs);

		/*
		 * Chunked Write Traversal:
		 * Large write() syscalls (like those from `cat`) must be
		 * chunked to fit within the 255-byte payload limit. We loop
		 * to process up to ~4KB (16 * 255 bytes) per syscall.
		 */
#pragma unroll
		for (int i = 0; i < 16; i++) {
			unsigned long offset = i * (PAYLOAD_SIZE - 1);

			// If our offset has reached or exceeded the total count,
			// we're done
			if (offset >= count)
				break;

			// Calculate how many bytes are left to process
			unsigned long remaining = count - offset;
			unsigned long chunk =
				(remaining > PAYLOAD_SIZE - 1) ? (PAYLOAD_SIZE - 1) : remaining;

			// Emit the event using purely derived offsets
			emit_event(*root_pid, pid, fd, buf + offset, chunk);
		}

		// Route 2: Vectorized sys_writev (Neovim, Tmux, Node.js)
	} else if (syscall_id == SYS_WRITEV) {
		const struct user_iovec *iov =
			(const struct user_iovec *)PT_REGS_PARM2(&regs);
		unsigned long iovcnt = PT_REGS_PARM3(&regs);

		if (iovcnt == 0)
			return 0;

		/*
		 * Vector Array Traversal:
		 * Optimized runtimes frequently fragment sequences. We iterate
		 * through the array and emit each valid vector as a discrete event.
		 */
		struct user_iovec vec;
#pragma unroll
		for (int i = 0; i < 4; i++) {
			if (i >= iovcnt)
				break;

			if (bpf_probe_read_user(&vec, sizeof(vec), &iov[i]) == 0) {
				emit_event(*root_pid, pid, fd, vec.iov_base, vec.iov_len);
			}
		}

		// Route 3: Zero-Copy System Calls (splice, sendfile64)
	} else if (syscall_id == SYS_SPLICE || syscall_id == SYS_SENDFILE64) {
		int out_fd;

		// The target file descriptor is located at different arguments
		// depending on the syscall.
		// fd_out is the 3rd argument in splice and the 1st in sendfile
		(syscall_id == SYS_SPLICE) ? (out_fd = PT_REGS_PARM3(&regs))
								   : (out_fd = PT_REGS_PARM1(&regs));

		// Only inject the placeholder if the data is actually being sent
		// to stdout or stderr
		if (out_fd != 1 && out_fd != 2)
			return 0;

		/*
		 * Zero-copy transfers move data directly between kernel buffers
		 * (e.g., from the disk page cache to the output pipe/TTY). There
		 * is no user-space buffer to intercept via bpf_probe_read_user.
		 * We emit a 1D placeholder to alert the dashboard user that an
		 * unreadable file transfer occurred.
		 */
		const char placeholder[] =
			"\n[ Zero-Copy Transfer Intercepted - Output Hidden ]\n\n";
		unsigned long count = sizeof(placeholder) - 1;

		struct ebpf_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->root_pid = *root_pid;
			e->actual_pid = pid;
			e->fd = out_fd;

			/*
			 * Because 'placeholder' is allocated on the kernel's BPF stack,
			 * we MUST use bpf_probe_read_kernel. bpf_probe_read_user will
			 * fail and result in empty/null payloads.
			 */
			bpf_probe_read_kernel(e->payload, count, placeholder);
			e->payload[count] = '\0';

			bpf_ringbuf_submit(e, 0);
		}
	}

	return 0;
}

// Required by the Linux kernel to load eBPF programs
char LICENSE[] SEC("license") = "GPL";
