# aivyx-confine

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

Config-agnostic by design: every constructor takes plain primitives, no
config-file parsing of its own. Each consumer's own config crate resolves
`deny_paths`/`extra_read_paths`/`require_enforcement` from whatever
config format it uses and passes the resolved values in.

Extracted 2026-08-16 from `aivyx-coder`'s own `aivyx-sandbox` crate, which
now depends on this crate instead of maintaining its own copy (see that
repo's `CLAUDE.md` for the migration). Built so `aivyx` (the flagship
Personal Assistant, whose own `ShellExecTool` currently has no OS-level
confinement — a gap its own `docs/THREAT_MODEL.md` states outright) could
adopt the same primitive — not yet done; that integration is separate,
explicit follow-on work, not assumed here.

See `docs/superpowers/specs/2026-08-16-aivyx-confine-design.md` in the
`aivyx-ecosystem` repo for the full design rationale.
