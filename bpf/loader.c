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
 * User-space C shim utilizing libbpf to manage the eBPF object.
 * It handles loading the bytecode into the kernel, attaching
 * tracepoints, and exposing a polling mechanism for Haskell to read
 * the ring buffer.
 */
#include "loader.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>

// Global state for the libbpf object and ring buffer
static struct bpf_object *obj = NULL;
static struct ring_buffer *rb = NULL;
static dassh_event_cb user_cb = NULL;

/*
 * Internal libbpf callback triggered for every event in the ring buffer.
 * It validates the memory size and passes the struct pointer to the
 * Haskell FFI callback.
 */
static int handle_event(void *ctx, void *data, size_t data_sz) {
	// Sanity check: ensure the kernel passed us the correctly sized struct
	// to prevent out-of-bounds reads in the Haskell Storable parser.
	if (data_sz < sizeof(struct ebpf_event)) {
		return 0;
	}

	const struct ebpf_event *e = data;

	// Push the event up to the Haskell worker thread
	if (user_cb) {
		user_cb(e);
	}

	return 0;
}

/*
 * Initializes the eBPF program lifecycle:
 * 1. Opens the compiled bytecode object.
 * 2. Loads it into kernel memory.
 * 3. Dynamically discovers and attaches all defined tracepoints.
 */
int dassh_bpf_init(void) {
	int err;

	obj = bpf_object__open_file("bpf/dassh.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "[C-SHIM] Error: Could not open bpf/dassh.bpf.o\n");
		return -1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr,
				"[C-SHIM] Error: Failed to load BPF object into kernel.\n");
		return err;
	}

	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr,
					"[C-SHIM] Error: Failed to attach tracepoint hook.\n");
			return -1;
		}
	}

	return 0;
}

/*
 * Polls the eBPF ring buffer for incoming terminal chunks.
 * This function is called in a continuous loop by a Haskell green thread.
 * It blocks the calling thread for 'timeout_ms' to prevent CPU thrashing.
 */
int dassh_bpf_poll(dassh_event_cb cb, int timeout_ms) {
	user_cb = cb; // Store the Haskell FFI callback pointer

	// Lazy-initialize the ring buffer polling struct on the very first call
	if (!rb) {
		int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
		if (map_fd < 0) {
			fprintf(stderr, "[C-SHIM] Error: Failed to find 'events' map.\n");
			return -1;
		}

		rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
		if (!rb) {
			fprintf(stderr,
					"[C-SHIM] Error: Failed to allocate ring buffer.\n");
			return -1;
		}
	}

	// Poll the ring buffer for incoming events
	// This will block the calling thread for 'timeout_ms'
	return ring_buffer__poll(rb, timeout_ms);
}

/*
 * Safely tears down the eBPF hooks and frees kernel memory.
 */
void dassh_bpf_cleanup(void) {
	if (rb) {
		ring_buffer__free(rb);
		rb = NULL;
	}
	if (obj) {
		// bpf_object__close automatically detaches hooks and frees memory
		bpf_object__close(obj);
		obj = NULL;
	}
}

/*
 * Registers a new Root Session PID (discovered by Haskell) into the
 * kernel's tracking map, allowing the tracepoints to monitor it.
 */
int dassh_track_pid(uint32_t pid) {
	if (!obj)
		return -1;

	int map_fd = bpf_object__find_map_fd_by_name(obj, "monitored_pids");
	if (map_fd < 0)
		return -1;

	// Insert the Bash PID mapping to itself as the root session leader
	uint32_t root_pid = pid;
	return bpf_map_update_elem(map_fd, &pid, &root_pid, BPF_ANY);
}
