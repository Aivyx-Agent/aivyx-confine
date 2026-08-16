//! OS-level process confinement for spawned command execution: Landlock
//! (filesystem scoping) + a seccomp-bpf syscall denylist. See
//! `ExecutionConfiner`'s own doc comment for the contract every
//! implementation must satisfy.

use std::path::{Path, PathBuf};

#[cfg(feature = "sandbox-backend")]
mod confiner;
#[cfg(feature = "sandbox-backend")]
pub use confiner::LandlockConfiner;

/// Wraps/restricts an about-to-spawn process before it execs.
/// `NoopConfiner` is the identity fallback (for platforms/kernels without
/// Landlock, or with `sandbox-backend` disabled at build time);
/// `LandlockConfiner` (behind the `sandbox-backend` feature, on by
/// default) is the real Landlock + seccomp-bpf backend. Swapping between
/// them never touches any tool implementation — consumers depend on this
/// trait, not on which backend is active.
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
/// check on their own: this crate's own `LandlockConfiner` (via
/// `find_basename_glob_matches`), and `aivyx-sandbox`'s `path_is_denied`
/// (in `aivyx-coder`) — a distinct, cross-crate consumer
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

/// Builds the best confiner available for this build: `LandlockConfiner`
/// when the `sandbox-backend` feature is enabled (the default), otherwise
/// `NoopConfiner` — keeps the `#[cfg]` branching in one place rather than
/// in every caller.
#[cfg(feature = "sandbox-backend")]
pub fn default_confiner(
    cwd: &Path,
    extra_read_paths: &[PathBuf],
    deny_paths: &[PathBuf],
    require_enforcement: bool,
) -> std::sync::Arc<dyn ExecutionConfiner> {
    std::sync::Arc::new(LandlockConfiner::new(
        cwd,
        extra_read_paths,
        deny_paths,
        require_enforcement,
    ))
}

#[cfg(not(feature = "sandbox-backend"))]
pub fn default_confiner(
    _cwd: &Path,
    _extra_read_paths: &[PathBuf],
    _deny_paths: &[PathBuf],
    _require_enforcement: bool,
) -> std::sync::Arc<dyn ExecutionConfiner> {
    std::sync::Arc::new(NoopConfiner)
}

#[cfg(test)]
mod tests {
    use super::*;

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
