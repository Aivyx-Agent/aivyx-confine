# aivyx-confine

[![CI](https://github.com/Aivyx-Agent/aivyx-confine/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Aivyx-Agent/aivyx-confine/actions/workflows/ci.yml)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue.svg)](LICENSE)

OS-level process confinement (Landlock + seccomp-bpf) for spawned command
execution.

An `ExecutionConfiner` trait (`fn confine(&self, command:
tokio::process::Command) -> tokio::process::Command`) plus two
implementations: `NoopConfiner` (identity passthrough — the fallback on
platforms/kernels without Landlock, or with the `sandbox-backend` feature
disabled) and `LandlockConfiner` (the real backend — Landlock ABI V7
filesystem scoping plus a seccomp-bpf syscall denylist, applied to a
forked child's `pre_exec` before it execs). `default_confiner(cwd,
extra_read_paths, deny_paths, require_enforcement)` picks the right one
for the current build automatically.

## What `LandlockConfiner` enforces

Grants are recomputed from the filesystem on every `confine()` call, so a
denied file that appears later is still denied.

- **Reads:** `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc`, the
  toolchain bits of `$HOME` (`.cargo`, `.rustup`, `.gitconfig`,
  `.config/git`), `cwd`, and each `extra_read_paths` entry.
- **Writes:** `cwd` and a private temp directory, created per confiner,
  exported as `TMPDIR`, and removed when the confiner is dropped. The
  shared `/tmp` is not writable unless `ConfineOptions::share_system_tmp`
  is set. `/dev/{null,zero,urandom,random}` are readable and writable.
- **`deny_paths`:** absolute paths, paths relative to `cwd`, and bare
  basename globs (`.env`, `*.pem`, matched anywhere under `cwd` and
  `extra_read_paths`) are carved out of every grant. Roots and entries are
  compared in canonical form. Hard-link aliases of a denied file under
  those roots are denied too. `~/.cargo/credentials(.toml)` and
  `~/.config/git/credentials` are always denied. A directory that had to
  be carved keeps directory-level rights (list, create, delete, rename),
  so `ls`, `touch`, `mkdir`, `rm` and `mv` work in it. A denied entry
  can still be deleted or renamed in place; its contents stay unreadable.
- **Seccomp:** a denylist (`ptrace`, `io_uring_*`, `mount` and the new
  mount API, `bpf`, `unshare`, `setns`, `clone` with any `CLONE_NEW*` flag,
  `perf_event_open`, the keyring, ...) returns `EPERM`. `clone3` returns
  `ENOSYS` so libc falls back to the filtered `clone`. On x86_64, x32
  syscall numbers are rejected. `socket(AF_UNIX)` returns `EPERM` unless
  `ConfineOptions::allow_unix_sockets` is set, because Landlock does not
  gate `connect()` to an existing Unix socket: the D-Bus session bus alone
  (`systemd-run --user`) would be unconfined code execution.
  `socketpair()` keeps working.
- **Landlock scopes (kernel ABI 6+):** no signals to processes outside the
  sandbox, and no connections to abstract Unix sockets outside it.
- **Environment:** `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`,
  `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, `WAYLAND_DISPLAY` and `DISPLAY` are
  removed. A consumer that opts into Unix sockets and needs one of them can
  set it on the `Command` after `confine()`.
- **Process group:** each confined command leads a new process group.
  Callers own its lifetime: record `Child::id()` at spawn and call
  `kill_process_group` when the call ends, times out or is cancelled.

Known limits: the network is not restricted. A process that calls
`setsid`/`setpgid` leaves the group and is not reached by
`kill_process_group`. On kernels whose Landlock ABI is older than V7
(`PartiallyEnforced`), the rights and scopes they lack are not enforced,
even with `require_enforcement`. A file created directly in a carved-out
directory gets file rights only from the next spawn on. Hard links to
files *inside* a denied directory are not searched for. With bare-pattern
denies, each spawn does one `stat` per directory under the scanned roots
(cached by mtime), synchronously.

Config-agnostic by design: every constructor takes plain primitives, no
config-file parsing of its own. Each consumer's own config crate resolves
`deny_paths`/`extra_read_paths`/`require_enforcement` from whatever
config format it uses and passes the resolved values in.

Extracted 2026-08-16 from `aivyx-coder`'s own `aivyx-sandbox` crate, which
now depends on this crate (a pinned `git` dependency) instead of
maintaining its own copy — migrated the same day, verified by
`aivyx-coder`'s full existing test suite passing unchanged. **`aivyx`
(the flagship Personal Assistant) adopted this crate 2026-08-17/18** —
its `ShellExecTool` and `git.rs`'s three tools now have default-on
Landlock+seccomp confinement, closing the gap its own
`docs/THREAT_MODEL.md` used to state outright. Both consumers now depend
on this crate.

See `docs/superpowers/specs/2026-08-16-aivyx-confine-design.md` in the
`aivyx-ecosystem` repo for the full design rationale.
