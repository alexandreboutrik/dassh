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
 * User-space C definitions and function prototypes for the eBPF shim.
 * This header is exposed to Haskell via FFI to safely manage the eBPF
 * lifecycle and consume events from the ring buffer.
 */
#ifndef DASSH_LOADER_H
#define DASSH_LOADER_H

#include <stddef.h>
#include <stdint.h>

#define PAYLOAD_SIZE 256

/*
 * The core event payload transferred from kernel to user-space.
 * It is structured to mirror the 'EbpfEvent' Haskell Storable type.
 * Memory Footprint: 4 (root) + 4 (actual) + 4 (fd) + 256 (payload) = 268 bytes.
 * It relies on 4-byte alignment.
 */
struct ebpf_event {
	uint32_t root_pid;
	uint32_t actual_pid;
	uint32_t fd;
	uint8_t payload[PAYLOAD_SIZE];
};

/*
 * Callback signature for Haskell to asynchronously consume ring
 * buffer events.
 */
typedef void (*dassh_event_cb)(const struct ebpf_event *event);

/*
 * Opens the eBPF object, loads it into the kernel, and globally attaches
 * all defined tracepoints.
 */
int dassh_bpf_init(void);

/*
 * Polls the eBPF ring buffer. Blocks the calling thread for 'timeout_ms'.
 * Executes the provided Haskell callback for every intercepted event.
 */
int dassh_bpf_poll(dassh_event_cb cb, int timeout_ms);

/*
 * Detaches the eBPF program and cleans up kernel resources.
 */
void dassh_bpf_cleanup(void);

/*
 * Adds a new root PID to the eBPF tracking map to begin capturing
 * its output.
 */
int dassh_track_pid(uint32_t pid);

#endif // DASSH_LOADER_H
