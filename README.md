# dassh

![Version](https://img.shields.io/github/v/tag/alexandreboutrik/dassh?label=Version&color=blue)
<!--[CI](https://img.shields.io/github/actions/workflow/status/alexandreboutrik/dassh/tests.yml?label=CI&logo=github)-->

`dassh` is a live SSH monitoring dashboard that watches user commands and program output across multiple SSH sessions in a real-time terminal interface.

## Architecture Overview

`dassh` monitors active `sshd` sessions on a system using an in-kernel eBPF program. It first scans `/proc` to discover active SSH sessions, reading the `SSH_TTY` environment variable of each shell to identify existing users before the monitoring begins.

To capture terminal traffic, `dassh` loads a custom eBPF bytecode object into the Linux kernel via a user-space C shim using the `libbpf` library. This in-kernel program safely hooks into global terminal events to intercept keystrokes and interactive program outputs with zero overhead. Every intercepted byte stream is actively filtered for SSH traffic, paired with its associated process ID, and pushed asynchronously into an eBPF Ring Buffer.

A dedicated Haskell worker thread continually polls this ring buffer from user space to ingest the terminal data. These captured byte streams are lightly sanitized of common ANSI escape sequences to prevent visual corruption, and then forwarded inside the dashboard process. The dashboard itself uses the `brick` library to draw separate terminal panes for each monitored session, refreshing in real time as data arrives.

## Installation

First clone the repository:

```
git clone git@github.com:alexandreboutrik/dassh
cd dassh

# If using NixOS, load the shell first
nix-shell
```

We recommend you to execute the `checkdeps` script to check if all the dependencies are indeed available on your system:

```bash
./scripts/checkdeps.sh
```

To build the application:

```bash
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

## Limitations

To maintain zero-overhead performance and a simple architecture (KISS), `dassh` handles terminal output as a 1D byte stream instead of a 2D grid. Because complex escape sequences from full-screen applications (like Vim or Tmux) would irreversibly corrupt this buffer, they are not natively mirrored. Instead, `dassh` automatically detects when an interactive application starts, safely pauses the output, and displays a placeholder message.

```
[ Interactive TUI Active - Output Paused ]
```

A future release may or may not introduce a fully featured 2D virtual terminal emulator, enabling interactive applications to be mirrored directly inside the dashboard panes.

## Security

If you discover a security vulnerability, please check out our [Security Policy](SECURITY.md) for more details. All security vulnerabilities will be promply addressed.

## LICENSE

This project is dual-licensed under copyleft terms. The Haskell userland code (`src/` and `app/` directories) is licensed under the [European Union Public License, Version 1.2](LICENSE) (EUPL-1.2). The C and eBPF code located in the `bpf/` directory is [GPL-2.0](bpf/LICENSE) compliant due to Linux kernel API requirements. You may freely use, modify, and distribute this software, provided that any derivative works are released under these exact same license terms. See the root [LICENSE](LICENSE) file and the [bpf/LICENSE](bpf/LICENSE) file for more information.
