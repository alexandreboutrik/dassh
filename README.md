# dassh

<!--
![Version](https://img.shields.io/github/v/tag/alexandreboutrik/dassh?label=Version&color=blue)
![CI](https://img.shields.io/github/actions/workflow/status/alexandreboutrik/dassh/tests.yml?label=CI&logo=github)
-->

`dassh` is a live SSH monitoring dashboard that watches user commands and program output across multiple SSH sessions in a real-time terminal interface.

## Architecture Overview

`dassh` monitors active `sshd` sessions on a system using an in-kernel eBPF program. It first scans `/proc` to discover active SSH sessions, reading the `SSH_TTY` environment variable of each shell to identify existing users before the monitoring begins.

To capture terminal traffic, `dassh` loads a custom eBPF bytecode object into the Linux kernel via a user-space C shim using the `libbpf` library. This in-kernel program safely hooks into global terminal events to intercept keystrokes and interactive program outputs with zero overhead. Every intercepted byte stream is actively filtered for SSH traffic, paired with its associated process ID, and pushed asynchronously into an eBPF Ring Buffer.

A dedicated Haskell worker thread continually polls this ring buffer from user space to ingest the terminal data. These captured byte streams are lightly sanitized of common ANSI escape sequences to prevent visual corruption, and then forwarded inside the dashboard process. The dashboard itself uses the `brick` library to draw separate terminal panes for each monitored session, refreshing in real time as data arrives.

## Installation

Execute the script to check if the dependencies are available on your system :

```bash
./scripts/checkdeps.sh
```

Then clone and build the repository :

```bash
git clone git@github.com:alexandreboutrik/dassh
cd dassh

# If using NixOS, load the shell first
nix-shell

make all
```

After a successful build, you can also copy the executable to a directory on your `$PATH`:

```bash
sudo install -m 755 "$(cabal list-bin dassh)" /usr/local/bin/dassh
```

## Usage

From within the project directory, to launch the dashboard :

```bash
make exec
```

The dashboard automatically discovers active SSH sessions and opens a live view for each.

Press `Tab` to move focus between session windows.  
Press `Enter` on a selected session to expand it into a full-screen detail view with scrollback of all captured lines.  
Press `q` to exit.

## Security

If you discover a security vulnerability, please check out our [Security Policy](SECURITY.md) for more details. All security vulnerabilities will be promply addressed.

## LICENSE

This project is proprietary. All rights are reserved by the copyright holder. The intellectual and technical concepts contained in this codebase are protected by trade secret, copyright, and patent law. Unauthorized access, use, reproduction, or distribution is strictly prohibited. A permissive open-source license is planned for a future release.

<!-- This project is licensed under the European Union Public License, Version 1.2 or later (EUPL-1.2). It is a copyleft license: you may use, modify, and distribute this software, but any derivative works must be released under the same license terms. See the [LICENSE](LICENSE) file for more information. -->
