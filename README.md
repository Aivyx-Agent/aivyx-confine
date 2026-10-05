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
  be carved keeps only list and create rights, so `ls`, `touch` and
  `mkdir` work in it, but `rm` and `mv` of its direct entries do not (see
  the limits below).
- **Seccomp:** a denylist (`ptrace`, `io_uring_*`, `mount` and the new
  mount API, `bpf`, `unshare`, `setns`, `clone` with any `CLONE_NEW*` flag,
  `perf_event_open`, the keyring, ...) returns `EPERM`. `clone3` returns
  `ENOSYS` so libc falls back to the filtered `clone`. On x86_64, x32
  syscall numbers are rejected. `socket(AF_UNIX)` returns `EPERM` unless
  `ConfineOptions::allow_unix_sockets` is set, because Landlock does not
  gate `connect()` to an existing Unix socket: the D-Bus session bus alone
  (`systemd-run --user`) would be unconfined code execution.
  Stream and seqpacket `socketpair()` keep working; a `SOCK_DGRAM`
  `socketpair()` is refused too (unless opted out), since an unconnected
  datagram end can `sendto()` any pathname datagram socket (`/dev/log`).
- **Landlock scopes (kernel ABI 6+):** no signals to processes outside the
  sandbox, and no connections to abstract Unix sockets outside it. Each
  `confine()` call creates its own Landlock domain, so "outside" includes
  the caller and processes started by *earlier* confined spawns: a command
  cannot kill a dev server a previous tool call started.
- **Environment:** `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR`,
  `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, `WAYLAND_DISPLAY` and `DISPLAY` are
  removed. A consumer that opts into Unix sockets and needs one of them can
  set it on the `Command` after `confine()`.
- **Process group:** each confined command leads a new process group, and
  `setsid`/`setpgid` return `EPERM` unless
  `ConfineOptions::allow_leaving_process_group` is set, so nothing it
  starts can leave the group. Callers own the group's lifetime: record
  `Child::id()` at spawn and call `kill_process_group` when the call ends,
  times out or is cancelled.

### Known limits

- The network is not restricted.
- **Carved-out directories (I1).** A directory that holds a denied entry
  (often the project root, for `.env`) gets list and create rights only.
  Within one spawn, a file or directory created directly in it has no
  file rights yet: `echo a > new.txt` leaves an empty `new.txt` and fails,
  `git init` leaves a partial `.git`, and a first `cargo build` cannot
  write `Cargo.lock` or populate `target/`. The next spawn covers the new
  entries, so a retry works. `rm`/`mv` of entries directly in such a
  directory always fail; deeper, fully granted subdirectories are
  unaffected. That includes litter the agent made itself: after
  `ln .env y` in the root, `y` is denied (a hard-link alias) and can never
  be deleted from inside the sandbox.
- **Descriptors and depth.** Building the ruleset holds one descriptor
  per directory level it descends into. A repository with a denied file
  nested about a thousand directories deep can therefore exhaust a 1024
  soft `RLIMIT_NOFILE`, and every confined spawn in it is refused with
  `EMFILE`. This fails closed, so only the repository's own author is
  affected; raising the limit fixes it.
- **Refused spawns.** `spawn()` fails with `EACCES` when Landlock can't
  be applied under `require_enforcement`, `EMFILE` when the ruleset build
  ran out of descriptors, and `EPERM` when applying the ruleset or a
  seccomp filter fails in the child. The parent also logs the cause at
  warn level.
- **Symlinked home toolchain dirs** (`~/.cargo -> /data/cargo`). When
  `$HOME` is outside `cwd`, they are resolved when the confiner is built
  and granted at their real location (re-pointing one later takes effect
  only for a new confiner). When `cwd` is `$HOME` or an ancestor of it,
  they are not followed at all — an earlier confined command could have
  planted `~/.cargo -> /` — so a symlinked toolchain dir is not granted;
  tools needing it fail with `EACCES`. Real (non-symlink) toolchain dirs
  are unaffected.
- **Grant roots inside a denied path** (an `extra_read_paths` entry, a
  toolchain dir, or `cwd` itself, under a `deny_paths` directory) are never
  granted — a `cwd` inside a denied directory gets no read or write access
  at all.
- **Kernel ABI.** On kernels whose Landlock ABI is older than V7
  (`PartiallyEnforced`), the rights and scopes they lack are not enforced,
  even with `require_enforcement`: below ABI 6 there are no signal or
  abstract-socket scopes, below 3 `truncate()` outside the grants works.
- Hard links to files *inside* a denied directory are not searched for.
- With bare-pattern denies, each spawn does one `fstat` per directory under
  the scanned roots (cached by mtime and ctime), synchronously; call
  `confine()` from a blocking-capable context for very large trees. While
  any denied file has more than one hard link, each spawn also does an
  uncached walk of every file under those roots.
- The private `TMPDIR` is shared by every spawn of one confiner, and it is
  deleted when the confiner is dropped, even if a child is still running.
  If the parent dies abnormally (`SIGKILL`, `panic = "abort"`) it is left
  behind in the system temp dir as `aivyx-confine-*`.
- With `allow_leaving_process_group`, a process that calls
  `setsid`/`setpgid` is not reached by `kill_process_group`.
- On 32-bit targets with the multiplexed `socketcall` syscall (i686), the
  `socket(AF_UNIX)` rule can be bypassed through `socketcall`. No consumer
  builds for such a target today; don't rely on the AF_UNIX block there.

## Upgrading from `fd9f1b4`

The existing API (`LandlockConfiner::new`, `default_confiner`) is
unchanged; everything below is behaviour a consumer will notice.

- **No local daemons.** `socket(AF_UNIX)` and AF_UNIX datagram
  `socketpair()` fail with `EPERM`, and the session IPC variables are
  removed. This breaks ssh-agent use (`git push` over ssh with an agent),
  gpg signing (`git commit -S`), `docker`, `psql`/`mysql` over their
  default sockets, git `credential-cache`/libsecret helpers, `systemctl
  --user`, and any confined MCP server or tool that talks over a Unix
  socket. Opt out per confiner with `allow_unix_sockets` (and accept that
  the sandbox no longer contains code execution).
- **No shared `/tmp`.** Writes go to a private `TMPDIR` instead; tools
  that hard-code `/tmp` fail. Opt out with `share_system_tmp`.
- **Process groups.** Confined commands lead their own process group, no
  longer receive terminal signals (Ctrl-C) aimed at the caller's group,
  and cannot `setsid`/`setpgid` unless `allow_leaving_process_group` is
  set. That breaks Python `start_new_session=True`, the `setsid` tool,
  interactive job control, and test runners or supervisors that put their
  own children into process groups (per-test process groups, likely
  including cargo-nextest; `posix_spawn` with `POSIX_SPAWN_SETPGROUP`).
  Git's background auto-maintenance (`gc --auto` detaching after a commit)
  prints `fatal: setsid failed` and skips that run; the command that
  triggered it still succeeds. Callers should call
  `kill_process_group(pgid)` when a tool call ends, times out or is
  cancelled; neither consumer does yet.
- **Signals.** Confined commands cannot signal the caller or processes
  from earlier confined spawns (Landlock ABI 6+).
- **No namespaces.** `clone` with `CLONE_NEW*` fails, `clone3` returns
  `ENOSYS`, and the new mount API is blocked: rootless containers,
  `bwrap` and Chromium's namespace sandbox don't work when confined.
- **`deny_paths`.** Matched on every spawn (not once at construction),
  relative multi-component entries resolve against `cwd`, hard-link
  aliases are denied, symlinks in carved directories are never granted,
  and carved directories lose remove/rename rights (see the I1 limit).
- **Credential stores.** `~/.cargo/credentials(.toml)` and
  `~/.config/git/credentials` are unreadable even with no `deny_paths`.
- **Cost.** `confine()` now does filesystem work on every call when
  bare-pattern denies are configured. It holds at most one descriptor
  per directory level while doing so, and if the process is out of
  descriptors anyway (`EMFILE`/`ENFILE`) the spawn is refused, even with
  `require_enforcement` off.
- **`extra_read_paths` inside `cwd`.** Opened without following
  symlinks: if one is (or is replaced by) a symlink, nothing is granted
  for it.
- **New API.** `ConfineOptions` (fails closed by default:
  `require_enforcement` is `true`), `LandlockConfiner::with_options`,
  `default_confiner_with_options`, `kill_process_group`.

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
