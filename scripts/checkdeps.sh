#!/usr/bin/env bash
# SPDX-License-Identifier: EUPL-1.2
#
# Copyright 2026 Alexandre Boutrik
#
# Licensed under the EUPL, Version 1.2 or - as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Licence is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the Licence for the specific language governing permissions and
# limitations under the Licence.

# Exit immediately on uninitialized variables or pipe failures
set -uo pipefail

: "${DASSH_HELP:=0}"
: "${MISSING_DEPS:=0}"
: "${MISSING_OPT_DEPS:=0}"

while [ $# -ne 0 ]; do
	case "${1}" in
	"-help" | "-h" | "help")
		DASSH_HELP=1
		;;
	*)
		echo "Error: Unknown argument '${1}'"
		echo
		DASSH_HELP=1
		;;
	esac
	shift
done

function print_help() {
	if [ "${DASSH_HELP}" != "1" ]; then return; fi

	echo "USAGE:"
	echo "  ./scripts/checkdeps.sh [OPTIONS]"
	echo
	echo "DESCRIPTION:"
	echo "  Checks the system for required build and runtime dependencies for dassh."
	echo "  This script only lists the presence of dependencies; it does not install anything."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	exit 0
}

function check_cmd() {
	local cmd="${1}"
	local type="${2:-required}"

	if command -v "${cmd}" >/dev/null 2>&1; then
		echo "  [+] ${cmd} is available."
	else
		if [ "${type}" == "required" ]; then
			echo "  [-] Error: '${cmd}' is missing."
			MISSING_DEPS=$((MISSING_DEPS + 1))
		else
			echo "  [~] Warning: '${cmd}' is missing. (Optional)"
			MISSING_OPT_DEPS=$((MISSING_OPT_DEPS + 1))
		fi
	fi
}

function check_lib() {
	local lib="${1}"
	local type="${2:-required}"

	if command -v pkg-config >/dev/null 2>&1; then
		if pkg-config --exists "${lib}" >/dev/null 2>&1; then
			echo "  [+] Library ${lib} is available."
		else
			if [ "${type}" == "required" ]; then
				echo "  [-] Error: Library '${lib}' is missing."
				MISSING_DEPS=$((MISSING_DEPS + 1))
			else
				echo "  [~] Warning: Library '${lib}' is missing. (Optional)"
				MISSING_OPT_DEPS=$((MISSING_OPT_DEPS + 1))
			fi
		fi
	else
		echo "  [-] Error: Cannot check library '${lib}' (pkg-config missing)."
		if [ "${type}" == "required" ]; then
			MISSING_DEPS=$((MISSING_DEPS + 1))
		else
			MISSING_OPT_DEPS=$((MISSING_OPT_DEPS + 1))
		fi
	fi
}

function check_kernel_btf() {
	echo -e "\n➤ Checking Kernel Configuration..."
	local btf_found=0

	# Check if BTF is exposed via sysfs (most reliable for running kernel)
	if [ -f "/sys/kernel/btf/vmlinux" ]; then
		btf_found=1
	# Check boot config
	elif [ -f "/boot/config-$(uname -r)" ] && grep -q "^CONFIG_DEBUG_INFO_BTF=y" "/boot/config-$(uname -r)"; then
		btf_found=1
	# Check proc config if available
	elif [ -f "/proc/config.gz" ] && zcat "/proc/config.gz" 2>/dev/null | grep -q "^CONFIG_DEBUG_INFO_BTF=y"; then
		btf_found=1
	fi

	if [ "${btf_found}" -eq 1 ]; then
		echo "  [+] Kernel BTF debug data (CONFIG_DEBUG_INFO_BTF=y) is available."
	else
		echo "  [-] Error: Kernel BTF debug data (CONFIG_DEBUG_INFO_BTF=y) is missing."
		MISSING_DEPS=$((MISSING_DEPS + 1))
	fi
}

function check_base_utils() {
	echo -e "\n➤ Checking Base Utilities..."
	check_cmd "make" "required"
	check_cmd "patchelf" "optional"
	check_cmd "git" "optional"
	check_cmd "nix-shell" "optional"
}

function check_haskell_toolchain() {
	echo -e "\n➤ Checking Haskell Toolchain..."
	check_cmd "ghc" "required"
	check_cmd "cabal" "required"
	check_cmd "haskell-language-server" "optional"
	check_cmd "hlint" "optional"
	check_cmd "shfmt" "optional"
	check_cmd "upx" "optional"
}

function check_c_ebpf_toolchain() {
	echo -e "\n➤ Checking C/eBPF Toolchain..."
	check_cmd "bpftool" "required"
	check_cmd "clang" "required"
	check_cmd "llc" "required"
	check_cmd "pkg-config" "required"
}

function check_c_libraries() {
	echo -e "\n➤ Checking C Libraries..."
	check_lib "libbpf" "required"
	check_lib "libelf" "required"
	check_lib "zlib" "required"
}

# Print help and exit if triggered
print_help

echo "Starting dependency check for dassh..."

# Standard execution flow
check_kernel_btf
check_base_utils
check_haskell_toolchain
check_c_ebpf_toolchain
check_c_libraries

echo

if [ "${MISSING_DEPS}" -eq 0 ]; then
	echo "Dependency check finished successfully! All required dependencies are present."
	if [ "${MISSING_OPT_DEPS}" -gt 0 ]; then
		echo "Note: ${MISSING_OPT_DEPS} optional dependencies are missing."
	fi
	exit 0
else
	echo "Dependency check finished with errors: ${MISSING_DEPS} missing required dependencies found."
	if [ "${MISSING_OPT_DEPS}" -gt 0 ]; then
		echo "Additionally, ${MISSING_OPT_DEPS} optional dependencies are missing."
	fi
	exit 1
fi
