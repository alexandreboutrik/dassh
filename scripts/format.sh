#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Proprietary
#
# Copyright (c) 2026 Alexandre Boutrik. All Rights Reserved.
#
# CONFIDENTIAL AND PROPRIETARY.
#
# The intellectual and technical concepts contained herein are proprietary
# to Alexandre Boutrik and are protected by trade secret, copyright and
# patent law. Dissemination of this information or reproduction of this
# material is strictly forbidden unless prior written permission is obtained.
#
# Unauthorized access, use, reproduction, or distribution of this file is
# strictly prohibited.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
# NON-INFRINGEMENT ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# Exit immediately on uninitialized variables or pipe failures
set -uo pipefail

# ==========================================
# DEFAULT VARIABLES & OPTIONS
# ==========================================
: "${DASSH_HELP:=0}"
: "${DASSH_MODE:=""}"
: "${DASSH_LINT:=0}"

# Resolve the absolute path of the project root
# Assumes this script is placed in a scripts/ directory, e.g., scripts/format.sh
: "${SCRIPT_DIR:="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"}"
: "${MAIN_DIR:="$(dirname "${SCRIPT_DIR}")"}"

# Formatting rules (4-width tabs for Bash and C)
: "${BASH_INDENT:=0}"
CLANG_STYLE="{BasedOnStyle: LLVM, UseTab: Always, IndentWidth: 4, TabWidth: 4}"

# Tool flags (populated based on mode)
FOURMOLU_FLAGS=""
CLANG_FLAGS=""
SHFMT_FLAGS=""

# ==========================================
# COMMAND LINE ARGUMENT PARSING
# ==========================================

# If no arguments are passed, trigger the help menu
if [ $# -eq 0 ]; then
	DASSH_HELP=1
fi

while [ $# -ne 0 ]; do
	case "${1}" in
	"-help" | "-h" | "help")
		DASSH_HELP=1
		;;
	"-lint" | "-l" | "lint")
		DASSH_LINT=1
		;;
	"apply")
		DASSH_MODE="apply"
		;;
	"check")
		DASSH_MODE="check"
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
	echo "  ./scripts/format.sh [MODE] [OPTIONS]"
	echo
	echo "MODES:"
	echo "  apply                   Format files in-place."
	echo "  check                   Check if files are formatted correctly (for CI/CD)."
	echo
	echo "OPTIONS:"
	echo "  -help, -h               Display this help message and exit."
	echo "  -lint, -l               Run hlint to check for Haskell logic/style issues."
	echo
	echo "EXAMPLES:"
	echo "  $ ./scripts/format.sh apply"
	echo "  $ ./scripts/format.sh check"
	echo "  $ ./scripts/format.sh check -lint"
	exit 0
}

function init_env() {
	if [ -z "${DASSH_MODE}" ]; then
		echo "Error: Mode not specified. Use 'apply' or 'check'. Exiting."
		echo
		DASSH_HELP=1 print_help
		exit 1
	fi

	echo "Starting code formatter for dassh..."

	if [ "${DASSH_MODE}" == "check" ]; then
		echo "Mode: CHECK (No files will be modified)"
		FOURMOLU_FLAGS="--mode check"
		CLANG_FLAGS="--dry-run -Werror"
		SHFMT_FLAGS="-d"
	else
		echo "Mode: APPLY (Files will be modified in-place)"
		FOURMOLU_FLAGS="--mode inplace"
		CLANG_FLAGS="-i"
		SHFMT_FLAGS="-w"
	fi

	if [ "${DASSH_LINT}" -eq 1 ]; then
		echo "Option: LINT (hlint will be executed)"
	fi
}

function format_haskell() {
	echo -e "\n➤ Processing Haskell files..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if command -v fourmolu >/dev/null 2>&1; then
		# Find all .hs files in src and app, passing them to fourmolu
		find "src" "app" -type f -name '*.hs' \
			-exec fourmolu ${FOURMOLU_FLAGS} {} + ||
			{
				echo "Haskell formatting failed. Exiting."
				exit 1
			}
		echo "  [+] Haskell formatting complete."
	else
		echo "  [-] Warning: fourmolu is not installed. Skipping Haskell formatting."
	fi

	popd >/dev/null || exit 1
}

function format_c() {
	echo -e "\n➤ Processing C and eBPF files..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if command -v clang-format >/dev/null 2>&1; then
		# Target the bpf directory specifically
		find "bpf" -type f \( -name '*.c' -o -name '*.h' \) \
			-exec clang-format -style="${CLANG_STYLE}" ${CLANG_FLAGS} {} + ||
			{
				echo "C/eBPF formatting failed. Exiting."
				exit 1
			}

		echo "  [+] C formatting complete."
	else
		echo "  [-] Warning: clang-format is not installed. Skipping C formatting."
	fi

	popd >/dev/null || exit 1
}

function format_bash() {
	echo -e "\n➤ Processing Bash scripts..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if command -v shfmt >/dev/null 2>&1; then
		find . -type f -name '*.sh' ! -path "*/target/*" ! -path "*/dist-newstyle/*" ! -path "*/.git/*" \
			-exec shfmt ${SHFMT_FLAGS} -i "${BASH_INDENT}" {} + ||
			{
				echo "Bash formatting failed. Exiting."
				exit 1
			}

		echo "  [+] Bash formatting complete."
	else
		echo "  [-] Warning: shfmt is not installed. Skipping Bash formatting."
	fi

	popd >/dev/null || exit 1
}

function run_hlint() {
	if [ "${DASSH_LINT}" != "1" ]; then return; fi

	echo -e "\n➤ Running HLint..."

	pushd "${MAIN_DIR}" >/dev/null || exit 1

	if command -v hlint >/dev/null 2>&1; then
		# Run hlint on the Haskell source directories
		hlint src app ||
			{
				echo -e "\n[-] HLint found issues. Please fix the warnings above. Exiting."
				exit 1
			}

		echo "  [+] HLint checks passed successfully. Your code is clean!"

	else
		echo "  [-] Error: hlint is not installed or not in your PATH."
		exit 1
	fi

	popd >/dev/null || exit 1
}

# Print help and exit if triggered
print_help

# Standard execution flow
init_env
format_haskell
format_c
format_bash
run_hlint

echo -e "\nFormatting process finished successfully!"
