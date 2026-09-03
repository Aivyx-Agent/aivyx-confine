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
`cargo test <test_name>`. To build/test without the real Landlock/seccomp
backend (e.g. on a non-Linux platform, or a kernel without Landlock):
`cargo build --no-default-features` / `cargo test --no-default-features`
— `NoopConfiner`/`default_confiner`'s no-op arm are what's left.

## Architecture

- `lib.rs` — the trait (`ExecutionConfiner`), `NoopConfiner`,
  `default_confiner` (feature-gated: `LandlockConfiner` when
  `sandbox-backend` is on, `NoopConfiner` otherwise), and the two shared
  path-classification helpers (`is_bare_pattern`, `is_basename_glob_match`)
  — used by both `confiner.rs`'s own `find_basename_glob_matches` and, in
  `aivyx-coder`, `aivyx-sandbox`'s unrelated `ConfirmationGate::is_denied`
  / `path_is_denied`. That second consumer is *not* about process
  confinement at all (it gates permission decisions) — it just happens to
  need the identical "is this a basename-glob pattern or a real path"
  classification, which is why these two small functions are `pub` here
  rather than private to `confiner.rs`.
- `confiner.rs` — `LandlockConfiner`, the real backend: fixed
  system/toolchain read grants, cwd + `extra_read_paths` write grants, a
  handful of `/dev/{null,zero,urandom,random}` device grants, `deny_paths`
  carve-outs (Landlock has no negative/deny rule, so a denied path nested
  inside a granted root is excluded by enumerating and re-granting only
  its unaffected siblings — see `grant_paths_excluding`'s own doc
  comment), and a seccomp-bpf denylist (`ptrace`, `io_uring_*`, `mount`,
  `bpf`, `unshare`, `setns`, `perf_event_open`, etc. — defense-in-depth
  compensating for not using Linux namespaces).

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
before fork, for exactly this reason.

## Where to look next

- `README.md` — quick orientation and the design-doc pointer.
- `aivyx-ecosystem/docs/superpowers/specs/2026-08-16-aivyx-confine-design.md`
  — the full design: why this was extracted, and why `aivyx-coder`'s
  migration was part of the same project (unlike `aivyx-recall`/
  `aivyx-kvcache`, which shipped standalone with no consumer yet).
  `aivyx`'s own adoption (2026-08-17/18) has its own design docs in that
  repo — see `aivyx-ecosystem/ROADMAP.md`'s `aivyx-confine` entry.
