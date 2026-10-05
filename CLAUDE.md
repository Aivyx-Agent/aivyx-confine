# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## What this is

`aivyx-confine` is a small, config-agnostic OS-level process confinement
crate: an `ExecutionConfiner` trait plus `NoopConfiner` (passthrough) and
`LandlockConfiner` (real — Landlock ABI V7 + a seccomp-bpf syscall
denylist). It exists so `aivyx-coder` and `aivyx` (the flagship Personal
Assistant) can share one implementation of the same OS-level confinement
primitive for spawned command execution, rather than each maintaining —
and potentially drifting on — its own copy. See `README.md` and
`aivyx-ecosystem/docs/superpowers/specs/2026-08-16-aivyx-confine-design.md`
for the full rationale — this file only covers what's specific to working
in this repo's code.

`aivyx-coder`'s own `aivyx-sandbox` crate depends on this crate today
(migrated 2026-08-16, the same day this crate was extracted) — see that
repo's own `CLAUDE.md` "Sandbox internals" section. **`aivyx` (the
flagship Personal Assistant) also depends on this crate**, adopted
2026-08-17/18 — `ShellExecTool` (one persistent confiner) and `git.rs`'s
three tools (a fresh, per-call confiner scoped to whichever repo the
call resolves) both route through it, target-gated to Linux only (see
`aivyx-ecosystem/ROADMAP.md`'s `aivyx-confine` entry for the platform-gate
fix a final review caught). Both real consumers now depend on this crate.

## Build, test, lint

```sh
cargo build
cargo test
cargo clippy --all-targets
cargo fmt
```

Single crate, no workspace — no `-p` flag needed. Single test:
`cargo test <test_name>`. Test fixtures live under
`target/test-fixtures`, never `/tmp`. Syscall-level tests re-exec the test
binary as a confined helper (`helper_entry`, selected via
`AIVYX_CONFINE_TEST_HELPER`). To build/test without the real
Landlock/seccomp backend (e.g. on a non-Linux platform, or a kernel without Landlock):
`cargo build --no-default-features` / `cargo test --no-default-features`
— `NoopConfiner`/`default_confiner`'s no-op arm are what's left.

## Architecture

- `lib.rs` — the trait (`ExecutionConfiner`, including the
  process-group contract), `NoopConfiner`, `ConfineOptions` (the opt-outs:
  `allow_unix_sockets`, `share_system_tmp`), `default_confiner` /
  `default_confiner_with_options` (feature-gated: `LandlockConfiner` when
  `sandbox-backend` is on, `NoopConfiner` otherwise), and the two shared
  path-classification helpers (`is_bare_pattern`, `is_basename_glob_match`)
  — `is_bare_pattern` is used by `LandlockConfiner` (splitting
  `deny_paths` into bare patterns and real paths; the patterns are then
  compiled into one `GlobSet` with the same semantics as
  `is_basename_glob_match`), and both are used, in `aivyx-coder`, by
  `aivyx-sandbox`'s unrelated `ConfirmationGate::is_denied`
  / `path_is_denied`. That second consumer is *not* about process
  confinement at all (it gates permission decisions) — it just happens to
  need the identical "is this a basename-glob pattern or a real path"
  classification, which is why these two small functions are `pub` here
  rather than private to `confiner.rs`.
- `confiner.rs` — `LandlockConfiner`, the real backend, and
  `kill_process_group`. Grants are computed in `compute_grants` on every
  `confine()` call: fixed system/toolchain read grants plus `cwd` and
  `extra_read_paths` (read-only); write grants on `cwd` and a private,
  per-confiner `TMPDIR` only; `/dev/{null,zero,urandom,random}`.
  `deny_paths` carve-outs: Landlock has no negative/deny rule, so a denied
  path nested inside a granted root is excluded by enumerating and
  re-granting only its unaffected siblings, never symlinks, while the
  enumerated directory itself keeps directory-only rights (see `Grants`
  and `grant_paths_excluding`). Bare patterns are found by a walk cached
  per directory mtime; hard-link aliases and home credential stores are
  added to the deny list. Seccomp is three stacked filters
  (`build_seccomp_filters`): the `EPERM` denylist (incl. namespace
  `clone` flags, the new mount API and, by default, `socket(AF_UNIX)`),
  `clone3` → `ENOSYS`, and an x86_64 x32-number guard. The ruleset also
  requests Landlock's signal and abstract-socket scopes.

### The `ExecutionConfiner` contract

`fn confine(&self, command: tokio::process::Command) ->
tokio::process::Command` — takes ownership of a not-yet-spawned `Command`
and returns it, possibly wrapped with a `pre_exec` hook (`LandlockConfiner`)
or unchanged (`NoopConfiner`). Callers apply this immediately before
`.spawn()`. `LandlockConfiner::confine`'s `pre_exec` closure runs
post-fork, pre-exec, under async-signal-safety constraints (no
allocation, no locks) — every error path inside it uses an
`ErrorKind`-based `io::Error`, never `.to_string()`/`io::Error::other`
(both allocate). All ruleset/filter construction happens in the parent,
before fork, for exactly this reason — including the per-spawn grant
computation, which walks the filesystem when bare-pattern denies are
configured, so `confine()` itself can block briefly. `confine()` also
scrubs session-IPC env vars, sets `TMPDIR` to the private temp dir and
puts the command in a new process group (see the trait doc for what that
asks of callers).

## Where to look next

- `README.md` — quick orientation and the design-doc pointer.
- `aivyx-ecosystem/docs/superpowers/specs/2026-08-16-aivyx-confine-design.md`
  — the full design: why this was extracted, and why `aivyx-coder`'s
  migration was part of the same project (unlike `aivyx-recall`/
  `aivyx-kvcache`, which shipped standalone with no consumer yet).
  `aivyx`'s own adoption (2026-08-17/18) has its own design docs in that
  repo — see `aivyx-ecosystem/ROADMAP.md`'s `aivyx-confine` entry.
