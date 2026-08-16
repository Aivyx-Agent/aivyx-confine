//! OS-level process confinement for spawned command execution: Landlock
//! (filesystem scoping) + a seccomp-bpf syscall denylist. See
//! `ExecutionConfiner`'s own doc comment (added in a later commit) for
//! the contract every implementation must satisfy.
