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

# ==========================================
# DEFAULT VARIABLES & OPTIONS
# ==========================================
: "${DASSH_HELP:=0}"
: "${MISSING_DEPS:=0}"

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

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
	if command -v "${cmd}" >/dev/null 2>&1; then
		echo "  [+] ${cmd} is available."
	else
		echo "  [-] Error: '${cmd}' is missing."
		MISSING_DEPS=$((MISSING_DEPS + 1))
	fi
}

function check_lib() {
	local lib="${1}"
	if command -v pkg-config >/dev/null 2>&1; then
		if pkg-config --exists "${lib}" >/dev/null 2>&1; then
			echo "  [+] Library ${lib} is available."
		else
			echo "  [-] Warning: Library '${lib}' is missing."
			MISSING_DEPS=$((MISSING_DEPS + 1))
		fi
	else
		echo "  [-] Warning: Cannot check library '${lib}' (pkg-config missing)."
	fi
}

function check_base_utils() {
	echo -e "\n➤ Checking Base Utilities..."
	check_cmd "git"
	check_cmd "make"
	check_cmd "nix-shell"
}

function check_haskell_toolchain() {
	echo -e "\n➤ Checking Haskell Toolchain..."
	check_cmd "ghc"
	check_cmd "cabal"
	check_cmd "haskell-language-server"
	check_cmd "hlint"
	check_cmd "shfmt"
	check_cmd "upx"
}

function check_c_ebpf_toolchain() {
	echo -e "\n➤ Checking C/eBPF Toolchain..."
	check_cmd "bpftool"
	check_cmd "clang"
	check_cmd "llc"
	check_cmd "pkg-config"
}

function check_c_libraries() {
	echo -e "\n➤ Checking C Libraries..."
	check_lib "libbpf"
	check_lib "libelf"
	check_lib "zlib"
}

# Print help and exit if triggered
print_help

echo "Starting dependency check for dassh..."

# Standard execution flow
check_base_utils
check_haskell_toolchain
check_c_ebpf_toolchain
check_c_libraries

echo

if [ "${MISSING_DEPS}" -eq 0 ]; then
	echo "Dependency check finished successfully! All required dependencies are present."
	exit 0
else
	echo "Dependency check finished with errors: ${MISSING_DEPS} missing dependencies found."
	exit 1
fi
