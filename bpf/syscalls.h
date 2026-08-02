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

#ifndef DASSH_SYSCALLS_H
#define DASSH_SYSCALLS_H

/*
 * Architecture-specific system call numbers.
 * Required to support multi-arch builds (x86_64, ARM64, RISC-V) when
 * intercepting raw syscall entry tracepoints.
 */

#if defined(__TARGET_ARCH_x86)
// x86_64 Syscall IDs
#define SYS_WRITE 1
#define SYS_WRITEV 20
#elif defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_arm)
// ARM64 Syscall IDs (AArch64)
#define SYS_WRITE 64
#define SYS_WRITEV 66
#elif defined(__TARGET_ARCH_riscv)
// RISC-V / asm-generic Syscall IDs
#define SYS_WRITE 64
#define SYS_WRITEV 66
#else
#error "Unsupported target architecture for syscall definitions."
#endif

#endif // DASSH_SYSCALLS_H
