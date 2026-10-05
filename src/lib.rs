//! OS-level process confinement for spawned command execution: Landlock
//! (filesystem scoping) + a seccomp-bpf syscall denylist. See
//! `ExecutionConfiner`'s own doc comment for the contract every
//! implementation must satisfy.

use std::path::{Path, PathBuf};

#[cfg(feature = "sandbox-backend")]
mod confiner;
#[cfg(feature = "sandbox-backend")]
pub use confiner::{LandlockConfiner, kill_process_group};

/// Without the `sandbox-backend` feature only `NoopConfiner` exists, and it
/// never creates a process group, so there is never a group to kill: this
/// does nothing and returns `Ok(())`. It exists so consumers can call
/// `kill_process_group` unconditionally instead of `cfg`-gating the call.
#[cfg(not(feature = "sandbox-backend"))]
pub fn kill_process_group(_pgid: u32) -> std::io::Result<()> {
    Ok(())
}

/// Wraps/restricts an about-to-spawn process before it execs.
/// `NoopConfiner` is the identity fallback (for platforms/kernels without
/// Landlock, or with `sandbox-backend` disabled at build time);
/// `LandlockConfiner` (behind the `sandbox-backend` feature, on by
/// default) is the real Landlock + seccomp-bpf backend. Swapping between
/// them never touches any tool implementation — consumers depend on this
/// trait, not on which backend is active.
///
/// Process-group contract: `LandlockConfiner` puts every confined command
/// in a new process group it leads (`process_group(0)`), so terminal
/// signals aimed at the caller's group no longer reach it and the caller
/// is responsible for its lifetime. To make sure nothing it started keeps
/// running after the tool call (a background `cmd &`, a daemonised
/// grandchild), record `Child::id()` right after `spawn()` and call
/// `kill_process_group` with it when the call finishes, times out or is
/// cancelled — `kill_on_drop` alone kills only the direct child.
/// `setsid`/`setpgid` are refused by seccomp, so nothing can leave the
/// group unless `ConfineOptions::allow_leaving_process_group` is set; with
/// it set, a process that leaves is not reached (containing those would
/// need a cgroup, which this crate does not manage). `NoopConfiner` changes nothing, so never call
/// `kill_process_group` for a command it "confined".
pub trait ExecutionConfiner: Send + Sync {
    fn confine(&self, command: tokio::process::Command) -> tokio::process::Command;
}

pub struct NoopConfiner;

impl ExecutionConfiner for NoopConfiner {
    fn confine(&self, command: tokio::process::Command) -> tokio::process::Command {
        command
    }
}

/// A `deny_paths` entry with a single path component (e.g. `.env`,
/// `*.pem`) is a basename-glob pattern, not a real filesystem location to
/// resolve. `pub` because two independent consumers need to classify a
/// `deny_paths` entry identically rather than each re-deriving the same
/// check on their own: this crate's own `LandlockConfiner` (when it
/// splits `deny_paths` into bare patterns and real paths), and
/// `aivyx-sandbox`'s `path_is_denied` (in `aivyx-coder`) — a distinct,
/// cross-crate consumer
/// unrelated to process confinement (it gates `ConfirmationGate`'s
/// permission decisions), found by reading `aivyx-sandbox`'s actual
/// current code before this crate was designed, not assumed.
pub fn is_bare_pattern(path: &Path) -> bool {
    path.parent() == Some(Path::new(""))
}

pub fn is_basename_glob_match(path: &Path, pattern: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(pattern) = pattern.to_str() else {
        return false;
    };
    globset::Glob::new(pattern)
        .map(|glob| glob.compile_matcher().is_match(name))
        .unwrap_or(false)
}

/// Policy knobs for `LandlockConfiner::with_options` /
/// `default_confiner_with_options`. `ConfineOptions::default()` (same as
/// `new()`) is the strict policy: `require_enforcement` is `true`, and
/// every other `bool` is `false`, an explicit opt-out a consumer must
/// choose.
/// `#[non_exhaustive]` so new knobs can be added without breaking
/// consumers: build one with `ConfineOptions::new()` and the setters.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ConfineOptions {
    /// Refuse to spawn (rather than run without filesystem confinement)
    /// when Landlock cannot be applied at all. Same meaning as the
    /// `require_enforcement` argument of `LandlockConfiner::new`. Defaults
    /// to `true` (fail closed); set `false` only for kernels known to lack
    /// Landlock.
    pub require_enforcement: bool,
    /// Opt out of the seccomp rule that makes `socket(AF_UNIX, ...)` fail
    /// with `EPERM`. Landlock does not gate `connect()` to an existing
    /// pathname Unix socket, so without that rule a confined command can
    /// reach any local daemon the user can — including the D-Bus session
    /// bus (`systemd-run --user` = unconfined code execution), gpg-agent,
    /// ssh-agent, Wayland/X11 and `docker.sock`. Only set this when the
    /// confined commands genuinely need a local daemon, and accept that
    /// the sandbox no longer contains code execution in that case.
    /// Also opts out of the matching rule for `socketpair(AF_UNIX,
    /// SOCK_DGRAM)` (an unconnected datagram end can `sendto()` any
    /// pathname datagram socket, e.g. `/dev/log`). Stream and seqpacket
    /// `socketpair()` keep working either way.
    pub allow_unix_sockets: bool,
    /// Opt back into the old temp-dir policy: read+write on the whole
    /// system temp directory (`/tmp`, and `$TMPDIR` if set). By default a
    /// confined command instead gets a private temp directory, created
    /// per confiner under the system temp dir, exported as `TMPDIR`, and
    /// removed when the confiner is dropped — so it cannot read or modify
    /// other same-user files in `/tmp` (temp files the unconfined parent
    /// later consumes, other agents' scratch dirs, `/tmp/.X11-unix`).
    /// Tools that ignore `TMPDIR` and hard-code `/tmp` fail under the
    /// default; set this only if a consumer depends on such tools.
    pub share_system_tmp: bool,
    /// Opt out of the seccomp rule that makes `setsid()` and `setpgid()`
    /// fail with `EPERM`. Every confined command leads its own process
    /// group so the caller can end everything it started with
    /// `kill_process_group`; these two syscalls are the only way out of
    /// that group, so with this set a command can leave processes running
    /// after the tool call (`setsid cmd &`). Non-interactive shells don't
    /// need them and coreutils `timeout` ignores a failing `setpgid`;
    /// interactive job control (`bash -i`, `set -m`), the `setsid` tool and
    /// Python's `start_new_session=True` do.
    pub allow_leaving_process_group: bool,
}

impl Default for ConfineOptions {
    fn default() -> Self {
        Self {
            require_enforcement: true,
            allow_unix_sockets: false,
            share_system_tmp: false,
            allow_leaving_process_group: false,
        }
    }
}

impl ConfineOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn require_enforcement(mut self, value: bool) -> Self {
        self.require_enforcement = value;
        self
    }

    pub fn allow_unix_sockets(mut self, value: bool) -> Self {
        self.allow_unix_sockets = value;
        self
    }

    pub fn allow_leaving_process_group(mut self, value: bool) -> Self {
        self.allow_leaving_process_group = value;
        self
    }

    pub fn share_system_tmp(mut self, value: bool) -> Self {
        self.share_system_tmp = value;
        self
    }
}

/// Builds the best confiner available for this build: `LandlockConfiner`
/// when the `sandbox-backend` feature is enabled (the default), otherwise
/// `NoopConfiner` — keeps the `#[cfg]` branching in one place rather than
/// in every caller. Equivalent to `default_confiner_with_options` with
/// `ConfineOptions::new().require_enforcement(require_enforcement)`.
pub fn default_confiner(
    cwd: &Path,
    extra_read_paths: &[PathBuf],
    deny_paths: &[PathBuf],
    require_enforcement: bool,
) -> std::sync::Arc<dyn ExecutionConfiner> {
    default_confiner_with_options(
        cwd,
        extra_read_paths,
        deny_paths,
        ConfineOptions::new().require_enforcement(require_enforcement),
    )
}

/// `default_confiner` with every policy knob exposed — see
/// `ConfineOptions`.
#[cfg(feature = "sandbox-backend")]
pub fn default_confiner_with_options(
    cwd: &Path,
    extra_read_paths: &[PathBuf],
    deny_paths: &[PathBuf],
    options: ConfineOptions,
) -> std::sync::Arc<dyn ExecutionConfiner> {
    std::sync::Arc::new(LandlockConfiner::with_options(
        cwd,
        extra_read_paths,
        deny_paths,
        options,
    ))
}

#[cfg(not(feature = "sandbox-backend"))]
pub fn default_confiner_with_options(
    _cwd: &Path,
    _extra_read_paths: &[PathBuf],
    _deny_paths: &[PathBuf],
    _options: ConfineOptions,
) -> std::sync::Arc<dyn ExecutionConfiner> {
    std::sync::Arc::new(NoopConfiner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_process_group_is_available_in_every_build() {
        // Built either way: with the backend it targets a real group,
        // without it there is never a group to kill. A pgid that can't
        // exist must not be an error in either build.
        assert!(kill_process_group(i32::MAX as u32).is_ok());
    }

    #[test]
    fn confine_options_default_to_the_strict_policy() {
        for options in [ConfineOptions::new(), ConfineOptions::default()] {
            assert!(options.require_enforcement, "must fail closed by default");
            assert!(!options.allow_unix_sockets);
            assert!(!options.share_system_tmp);
            assert!(!options.allow_leaving_process_group);
        }
    }

    #[test]
    fn noop_confiner_returns_the_command_unchanged() {
        let confiner = NoopConfiner;
        let command = tokio::process::Command::new("echo");
        let confined = confiner.confine(command);
        assert_eq!(confined.as_std().get_program(), "echo");
    }

    #[test]
    fn is_bare_pattern_is_true_for_a_single_component_entry() {
        assert!(is_bare_pattern(Path::new(".env")));
        assert!(is_bare_pattern(Path::new("*.pem")));
    }

    #[test]
    fn is_bare_pattern_is_false_for_a_path_separator_entry() {
        assert!(!is_bare_pattern(Path::new("/home/user/.ssh")));
        assert!(!is_bare_pattern(Path::new("relative/two/parts")));
    }

    #[test]
    fn is_basename_glob_match_matches_by_basename_wildcard() {
        assert!(is_basename_glob_match(
            Path::new("/any/dir/server.pem"),
            Path::new("*.pem")
        ));
        assert!(!is_basename_glob_match(
            Path::new("/any/dir/server.pem"),
            Path::new("*.env")
        ));
    }
}
