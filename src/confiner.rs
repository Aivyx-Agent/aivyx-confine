//! Real OS-level process confinement, replacing `NoopConfiner`: Landlock
//! (filesystem scoping) + a seccomp-bpf syscall denylist. See
//! `aivyx-ecosystem/docs/superpowers/specs/2026-08-16-aivyx-confine-design.md`
//! and this crate's own `CLAUDE.md` ("The `ExecutionConfiner` contract")
//! for the policy rationale (informed by, but deliberately not identical
//! to, Codex CLI's current bubblewrap-based sandbox).

use std::io;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    path_beneath_rules,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};

use crate::ExecutionConfiner;

const LANDLOCK_ABI: ABI = ABI::V7;

/// `LANDLOCK_CREATE_RULESET_VERSION` from the kernel's landlock UAPI header
/// — not re-exported by the `landlock` crate (its `uapi` module is
/// private), but stable and simple enough to inline directly rather than
/// pull in a second crate for one flag value.
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

/// Common system/toolchain read paths granted by default, in addition to
/// the working directory and any configured `extra_read_paths`. Scoping
/// reads to just the working directory breaks real toolchains (compilers,
/// package managers reading outside the project) — deliberately not Codex
/// CLI's "read everything" default, though: Landlock has no negative/deny
/// rule, so excluding `deny_paths` entries from a broad `/` grant would
/// require enumerating and re-granting every sibling directory except the
/// denied ones. A bounded, explicit list mostly sidesteps that — and for
/// the one grant that can't stay narrow (the working directory, which must
/// be granted wholesale to be useful), `grant_paths_excluding` below does
/// the carve-out properly instead of ignoring the problem.
/// Nonexistent paths are silently skipped by `path_beneath_rules`, so it's
/// safe to list toolchain paths that may not exist on a given system.
const DEFAULT_READ_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Home-relative toolchain paths, joined against `$HOME` when set.
/// `.gitconfig`/`.config/git` matter beyond convenience: `git commit` needs
/// the user's identity from global config, and git treats an *unreadable*
/// (EACCES) existing config file as fatal — so without these grants every
/// confined `git` invocation on a machine with a global config would die.
const DEFAULT_HOME_READ_PATHS: &[&str] = &[".cargo", ".rustup", ".gitconfig", ".config/git"];

/// Harmless character devices granted read+write. `/dev` is deliberately
/// NOT granted wholesale (block devices, other users' ttys); but without at
/// least `/dev/null` every shell construct like `2>/dev/null` dies with
/// EACCES under the sandbox — a live-E2E finding, not a hypothetical.
const DEVICE_RW_PATHS: &[&str] = &["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random"];

/// Syscalls with no legitimate use in a coding agent's shell commands,
/// blocked regardless of what Landlock's filesystem scoping already
/// prevents — defense in depth against confinement-escape/introspection
/// primitives (`ptrace`, `io_uring`, `perf_event_open`, the kernel keyring,
/// `userfaultfd`) and privileged operations that a namespace-based sandbox
/// (like Codex CLI's bubblewrap) would otherwise block for free via
/// capability dropping. This design doesn't use namespaces, so those need
/// to be explicit here instead. `unshare`/`setns` are blocked outright since
/// a coding agent's tools never need to create or join namespaces.
// `libc::SYS_kexec_file_load` is genuinely absent from this crate's musl
// bindings for aarch64 and riscv64 (confirmed directly against
// libc-0.2.189's source: present for musl x86_64/loongarch64/s390x/
// powerpc64, absent for musl aarch64/riscv64 — an upstream musl libc
// binding gap, not something this crate can paper over with a cfg on a
// single array element, since `cfg` doesn't apply to individual
// expressions inside an array literal). Two full `cfg`-gated versions of
// the same const, rather than a fallible numeric fallback per
// architecture, keeps every entry auditable as a real `libc::SYS_*`
// constant. `SYS_kexec_load` (the non-file variant) is unaffected and
// stays blocked on every target either way.
#[cfg(not(any(
    all(target_arch = "aarch64", target_env = "musl"),
    all(target_arch = "riscv64", target_env = "musl"),
)))]
const BLOCKED_SYSCALLS: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_reboot,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_pivot_root,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_userfaultfd,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_personality,
];

/// Syscalls with no legitimate use in a coding agent's shell commands,
/// blocked regardless of what Landlock's filesystem scoping already
/// prevents — defense in depth against confinement-escape/introspection
/// primitives (`ptrace`, `io_uring`, `perf_event_open`, the kernel keyring,
/// `userfaultfd`) and privileged operations that a namespace-based sandbox
/// (like Codex CLI's bubblewrap) would otherwise block for free via
/// capability dropping. This design doesn't use namespaces, so those need
/// to be explicit here instead. `unshare`/`setns` are blocked outright since
/// a coding agent's tools never need to create or join namespaces.
///
/// Identical to the list above minus `SYS_kexec_file_load`, which this
/// crate's musl bindings don't define on aarch64/riscv64 — see that
/// item's own comment above.
#[cfg(any(
    all(target_arch = "aarch64", target_env = "musl"),
    all(target_arch = "riscv64", target_env = "musl"),
))]
const BLOCKED_SYSCALLS: &[i64] = &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_reboot,
    libc::SYS_kexec_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_pivot_root,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_userfaultfd,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_personality,
];

/// Read-only probe of kernel Landlock support, safe to call from the parent
/// at any time — mirrors the `landlock` crate's own internal ABI-detection
/// logic (`landlock-0.4.5/src/compat.rs`, `LandlockStatus::current`): a
/// null ruleset-attr pointer and zero size, which the kernel documents as
/// just reporting the ABI version rather than creating a real ruleset.
/// Returns the raw syscall result: non-negative is the supported ABI
/// version, negative means unsupported (`ENOSYS`) or disabled (`EOPNOTSUPP`).
fn detect_landlock_abi() -> i64 {
    // SAFETY: read-only syscall with a null pointer and zero length, per the
    // kernel's own documented probing convention (see comment above).
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    }
}

/// Environment variables that point a process at a session-level IPC
/// endpoint (D-Bus, ssh-agent, gpg-agent, Wayland, X11, the user runtime
/// dir that holds most of their sockets). Removed from every confined
/// command — see `ConfineOptions::allow_unix_sockets` for why reaching
/// those endpoints is an escape, not just an information leak.
pub(crate) const SCRUBBED_ENV_VARS: &[&str] = &[
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
    "WAYLAND_DISPLAY",
    "DISPLAY",
];

pub struct LandlockConfiner {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    seccomp_program: BpfProgram,
    require_enforcement: bool,
}

impl LandlockConfiner {
    /// The default policy (`ConfineOptions::new()`) plus
    /// `require_enforcement` — kept as the original, stable constructor.
    pub fn new(
        cwd: &Path,
        extra_read_paths: &[PathBuf],
        deny_paths: &[PathBuf],
        require_enforcement: bool,
    ) -> Self {
        Self::with_options(
            cwd,
            extra_read_paths,
            deny_paths,
            crate::ConfineOptions::new().require_enforcement(require_enforcement),
        )
    }

    pub fn with_options(
        cwd: &Path,
        extra_read_paths: &[PathBuf],
        deny_paths: &[PathBuf],
        options: crate::ConfineOptions,
    ) -> Self {
        let require_enforcement = options.require_enforcement;
        if detect_landlock_abi() < 0 {
            tracing::warn!(
                require_enforcement,
                "Landlock is not supported or not enabled on this kernel; process-execution \
                 tools will {} until this is resolved",
                if require_enforcement {
                    "refuse to run (sandbox.require_enforcement is true)"
                } else {
                    "run unconfined (sandbox.require_enforcement is false)"
                }
            );
        }

        // Bare deny_paths patterns (e.g. `.env`) are resolved into
        // concrete file paths, once, by scanning every project-relevant
        // root — `cwd` and each `extra_read_paths` entry, the roots a
        // project's own secrets could plausibly live under. The combined
        // result is reused for *every* grant computation below,
        // including the fixed system paths and the OS temp directory:
        // any of them could, in principle, be an ancestor of a
        // project-relevant root (an `/etc/nixos`-style system-config-as-
        // project-repo, or `cwd` nested inside the system temp dir in
        // tests/scratch directories) and would otherwise silently
        // re-grant whatever that root's own narrower carve-out just
        // excluded. Passing the same fully-resolved list to every
        // `grant_paths_excluding` call is safe, not overly permissive —
        // that function only ever acts on entries actually nested under
        // the specific root it's given — and reusing the already-computed
        // matches this way costs nothing extra; `find_basename_glob_matches`
        // itself is a no-op whenever `deny_paths` has no bare entries at
        // all.
        let mut resolved_deny_paths = deny_paths.to_vec();
        resolved_deny_paths.extend(find_basename_glob_matches(cwd, deny_paths));
        for extra_root in extra_read_paths {
            resolved_deny_paths.extend(find_basename_glob_matches(extra_root, deny_paths));
        }

        // `grant_paths_excluding` is applied uniformly to every candidate
        // root — any of them could, in principle, contain a nested
        // `deny_paths` entry (see the comment above for why the resolved
        // bare-pattern matches specifically need this uniform treatment,
        // beyond the original reasoning about absolute nested entries).
        // It's a no-op (returns the root unchanged) whenever nothing is
        // actually nested underneath, so this costs nothing extra in the
        // common case.
        let mut read_candidates: Vec<PathBuf> =
            DEFAULT_READ_PATHS.iter().map(PathBuf::from).collect();
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            read_candidates.extend(DEFAULT_HOME_READ_PATHS.iter().map(|p| home.join(p)));
        }
        read_candidates.push(cwd.to_path_buf());
        read_candidates.extend(extra_read_paths.iter().cloned());
        let mut read_paths: Vec<PathBuf> = read_candidates
            .iter()
            .flat_map(|root| grant_paths_excluding(root, &resolved_deny_paths))
            .collect();
        // Read side of the device grants below (read and write rules are
        // separate Landlock rule sets, so both lists need the entries).
        read_paths.extend(DEVICE_RW_PATHS.iter().map(PathBuf::from));

        let mut write_candidates = vec![cwd.to_path_buf(), std::env::temp_dir()];
        if let Some(tmpdir) = std::env::var_os("TMPDIR") {
            write_candidates.push(PathBuf::from(tmpdir));
        }
        let mut write_paths: Vec<PathBuf> = write_candidates
            .iter()
            .flat_map(|root| grant_paths_excluding(root, &resolved_deny_paths))
            .collect();
        // Individual device files, not subject to deny_paths carve-outs
        // (they're fixed, well-known, and content-free); `path_beneath_rules`
        // silently skips any that don't exist.
        write_paths.extend(DEVICE_RW_PATHS.iter().map(PathBuf::from));

        let seccomp_program = build_seccomp_filter(&options);

        Self {
            read_paths,
            write_paths,
            seccomp_program,
            require_enforcement,
        }
    }

    /// Builds the full ruleset here, in the parent process, before `fork()`
    /// — all allocation (rule construction, path resolution) must happen
    /// before the `pre_exec` hook runs, since that closure executes in the
    /// forked child under async-signal-safety constraints (no allocation,
    /// no locks). `RulesetCreated::restrict_self()` itself is verified to
    /// be a thin syscall wrapper over this already-built state.
    fn build_ruleset(&self) -> Result<RulesetCreated, landlock::RulesetError> {
        Ruleset::default()
            .handle_access(AccessFs::from_all(LANDLOCK_ABI))?
            .create()?
            .add_rules(path_beneath_rules(
                &self.read_paths,
                AccessFs::from_read(LANDLOCK_ABI),
            ))?
            .add_rules(path_beneath_rules(
                &self.write_paths,
                AccessFs::from_all(LANDLOCK_ABI),
            ))
    }
}

/// Landlock has no negative/deny rule — a domain can only ever be *more*
/// restricted than ambient, never "grant X except Y". To grant `root`
/// wholesale while still excluding a `deny_paths` entry nested somewhere
/// inside it, enumerate `root`'s direct children and grant each
/// individually: recurse into any child that itself contains a denial
/// further down, and skip entirely any child that *is* a denial. When
/// nothing under `root` is denied (the common case), this returns `root`
/// unchanged with no extra filesystem work.
fn grant_paths_excluding(root: &Path, deny_paths: &[PathBuf]) -> Vec<PathBuf> {
    if deny_paths.iter().any(|denied| denied == root) {
        return Vec::new();
    }
    let relevant: Vec<&PathBuf> = deny_paths
        .iter()
        .filter(|denied| denied.starts_with(root))
        .collect();
    if relevant.is_empty() {
        return vec![root.to_path_buf()];
    }

    // Can't enumerate what's inside `root` — fail toward less access, not
    // more, rather than granting a directory whose contents are unknown.
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut grants = Vec::new();
    for entry in entries.flatten() {
        let child = entry.path();
        if relevant.iter().any(|denied| **denied == child) {
            continue;
        }
        // Never grant a symlink entry. `path_beneath_rules` opens each
        // grant following symlinks and Landlock attaches the rule to the
        // *target* inode, so granting `docs -> /` here would hand out
        // read+write on the whole filesystem. Skipping costs nothing
        // legitimate: Landlock checks the resolved path, so a symlink
        // whose target is inside some other grant still works through
        // that grant. An entry whose type can't be read is skipped too
        // (fail toward less access).
        match entry.file_type() {
            Ok(file_type) if !file_type.is_symlink() => {}
            _ => continue,
        }
        if relevant.iter().any(|denied| denied.starts_with(&child)) {
            grants.extend(grant_paths_excluding(&child, deny_paths));
        } else {
            grants.push(child);
        }
    }
    grants
}

/// Recursively finds every path under `root` whose basename matches a
/// bare (single-component) `deny_paths` pattern — the concrete
/// file-level exclusions `LandlockConfiner::new` needs before granting
/// `root`, since `grant_paths_excluding` only understands specific
/// absolute paths to carve out, not "matches anywhere" patterns. Returns
/// immediately without touching the filesystem if `deny_paths` has no
/// bare entries at all.
///
/// Each match found here forces `grant_paths_excluding` to enumerate its
/// containing directory child-by-child instead of granting it wholesale
/// (see that function's own doc comment) — a project with many matching
/// files (e.g. a `node_modules` tree containing numerous test `*.pem`
/// fixtures) will produce a larger Landlock ruleset, rebuilt on every
/// command spawn via `LandlockConfiner::confine`. This is a real,
/// match-count-proportional cost, accepted as the price of closing the
/// security gap this function exists for — not a bug, but worth knowing
/// if a project's grant construction becomes noticeably slower after
/// adding a broad bare pattern.
fn find_basename_glob_matches(root: &Path, deny_paths: &[PathBuf]) -> Vec<PathBuf> {
    let bare_patterns: Vec<PathBuf> = deny_paths
        .iter()
        .filter(|p| crate::is_bare_pattern(p))
        .cloned()
        .collect();
    if bare_patterns.is_empty() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    walk_for_basename_matches(root, &bare_patterns, &mut matches);
    matches
}

fn walk_for_basename_matches(dir: &Path, bare_patterns: &[PathBuf], matches: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if bare_patterns
            .iter()
            .any(|pattern| crate::is_basename_glob_match(&path, pattern))
        {
            matches.push(path);
            continue; // matched — no need to recurse further into it
        }
        // `file_type()` reflects the entry itself, not a symlink's
        // target, so a symlinked directory is never recursed into —
        // this is what keeps a symlink cycle from causing unbounded
        // recursion here (unlike `grant_paths_excluding`, this function
        // recurses into *every* subdirectory by default, so this guard
        // matters more here).
        if entry.file_type().is_ok_and(|ft| ft.is_dir()) {
            // `.git` directories never legitimately hold a project's own
            // secrets — they hold git's own internal object database and
            // refs — so skipping them cuts real walk cost (a `.git`
            // directory can be large) without weakening the security
            // guarantee this scan exists for.
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            walk_for_basename_matches(&path, bare_patterns, matches);
        }
    }
}

fn build_seccomp_filter(options: &crate::ConfineOptions) -> BpfProgram {
    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> = BLOCKED_SYSCALLS
        .iter()
        .map(|&syscall| (syscall, vec![]))
        .collect();
    if !options.allow_unix_sockets {
        // `socket(AF_UNIX, ...)` → EPERM: Landlock does not gate
        // `connect()` to an existing pathname Unix socket, so this is the
        // only thing standing between a confined command and the user's
        // D-Bus session bus (`systemd-run --user` runs arbitrary code
        // unconfined), gpg-agent, ssh-agent, Wayland/X11 and docker.sock.
        // `socketpair()` is a different syscall and stays allowed.
        rules.insert(
            libc::SYS_socket,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        libc::AF_UNIX as u64,
                    )
                    .expect("static seccomp condition is well-formed"),
                ])
                .expect("static seccomp rule is well-formed"),
            ],
        );
    }

    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into().expect("known arch"),
    )
    .expect("static seccomp policy is well-formed")
    .try_into()
    .expect("seccomp policy compiles to BPF")
}

impl ExecutionConfiner for LandlockConfiner {
    fn confine(&self, mut command: tokio::process::Command) -> tokio::process::Command {
        let require_enforcement = self.require_enforcement;
        for var in SCRUBBED_ENV_VARS {
            command.env_remove(var);
        }

        let ruleset = match self.build_ruleset() {
            Ok(ruleset) => ruleset,
            Err(err) => {
                if require_enforcement {
                    // Fail closed: make the spawn itself fail rather than
                    // running unconfined. This closure runs in the parent
                    // (we haven't forked yet), so a detailed, allocated
                    // error message is fine here — the async-signal-safety
                    // constraint only applies inside `pre_exec` below.
                    tracing::warn!(
                        error = %err,
                        "failed to build Landlock ruleset; refusing to run unconfined \
                         (sandbox.require_enforcement is true)"
                    );
                    unsafe {
                        command.pre_exec(|| Err(io::Error::from(io::ErrorKind::PermissionDenied)));
                    }
                } else {
                    tracing::warn!(
                        error = %err,
                        "failed to build Landlock ruleset; running unconfined \
                         (sandbox.require_enforcement is false)"
                    );
                }
                return command;
            }
        };
        let mut ruleset = Some(ruleset);
        let seccomp_program = self.seccomp_program.clone();
        let mut seccomp_program = Some(seccomp_program);

        // SAFETY: every error path inside this closure uses an
        // `ErrorKind`-based `io::Error` (std's allocation-free "simple"
        // repr), never `io::Error::other`/`.to_string()` — both allocate,
        // which is unsound inside a forked, single-threaded child where
        // another thread's held malloc-arena lock at fork time can leave
        // the allocator permanently wedged from this process's point of
        // view. The tradeoff is losing the detailed underlying error
        // message from inside the child; that's the correct, honest
        // price of fork-safety here. All allocation (ruleset/filter
        // construction) already happened above, in the parent.
        unsafe {
            command.pre_exec(move || {
                if let Some(ruleset) = ruleset.take() {
                    let status = ruleset
                        .restrict_self()
                        .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
                    // `PartiallyEnforced` means the kernel supports Landlock
                    // but not every requested restriction at `LANDLOCK_ABI`
                    // — Landlock's own designed graceful-degradation
                    // behavior (older kernel, newer ABI requested), not an
                    // absence of enforcement. Only `NotEnforced` (no real
                    // restriction applied at all) should trip
                    // `require_enforcement`'s fail-closed policy; refusing
                    // on `PartiallyEnforced` too was stricter than intended
                    // and broke real confined execution on any kernel that
                    // doesn't yet support the full `LANDLOCK_ABI` level —
                    // found via CI failing outright on GitHub's runner
                    // kernel, which lands on `PartiallyEnforced` for this
                    // ABI target.
                    if require_enforcement && status.ruleset == RulesetStatus::NotEnforced {
                        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                    }
                }
                if let Some(program) = seccomp_program.take() {
                    seccompiler::apply_filter(&program)
                        .map_err(|_| io::Error::from(io::ErrorKind::Other))?;
                }
                Ok(())
            });
        }
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// Every test fixture lives under this crate's own `target/` directory,
    /// never under `/tmp`: the system temp directory has historically been
    /// write-granted to confined commands, so a fixture there could land
    /// inside a grant by accident and make an "outside the sandbox"
    /// assertion vacuous. Two fixture dirs from here are siblings, and
    /// neither is inside any default grant.
    fn fixture_root() -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-fixtures");
        std::fs::create_dir_all(&root).unwrap();
        root.canonicalize().unwrap()
    }

    fn fixture_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("fx-")
            .tempdir_in(fixture_root())
            .unwrap()
    }

    fn confiner_for(dir: &Path) -> LandlockConfiner {
        LandlockConfiner::new(dir, &[], &[], true)
    }

    async fn run(mut command: tokio::process::Command) -> (bool, String) {
        let output = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("failed to run command");
        (
            output.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )
    }

    // --- Re-exec helper -------------------------------------------------
    //
    // Syscall-level properties (socket families, clone flags, signals) are
    // tested by re-running this very test binary, confined, with only
    // `helper_entry` selected and an action named in `HELPER_ENV`. The
    // helper performs exactly one raw syscall and prints its return value
    // and errno, so no external tool (python, socat, ...) is needed.

    const HELPER_ENV: &str = "AIVYX_CONFINE_TEST_HELPER";
    const HELPER_ARG_ENV: &str = "AIVYX_CONFINE_TEST_HELPER_ARG";

    fn last_errno() -> i32 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    /// Runs one raw syscall-ish action and returns `(ret, errno)`; errno
    /// is only meaningful when `ret < 0`.
    fn helper_action(action: &str, arg: &str) -> (i64, i32) {
        // SAFETY: each arm is a single raw libc call on locally owned
        // buffers; this runs only in the re-exec'd helper process.
        unsafe {
            match action {
                "unix_socket" => {
                    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                    let errno = last_errno();
                    if fd >= 0 {
                        libc::close(fd);
                    }
                    (fd as i64, errno)
                }
                "unix_connect" => {
                    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                    if fd < 0 {
                        return (fd as i64, last_errno());
                    }
                    let mut addr: libc::sockaddr_un = std::mem::zeroed();
                    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                    let abstract_name = arg.strip_prefix('@');
                    let bytes = abstract_name.unwrap_or(arg).as_bytes();
                    let offset = usize::from(abstract_name.is_some());
                    for (i, b) in bytes.iter().enumerate() {
                        addr.sun_path[i + offset] = *b as libc::c_char;
                    }
                    let len = std::mem::size_of::<libc::sa_family_t>() + offset + bytes.len();
                    let ret = libc::connect(
                        fd,
                        &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                        len as libc::socklen_t,
                    );
                    let errno = last_errno();
                    libc::close(fd);
                    (ret as i64, errno)
                }
                "socketpair" => {
                    let mut fds = [0; 2];
                    let ret =
                        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr());
                    (ret as i64, last_errno())
                }
                other => panic!("unknown helper action {other}"),
            }
        }
    }

    /// Not a real test: a no-op unless re-exec'd by `run_helper`.
    #[test]
    fn helper_entry() {
        let Ok(action) = std::env::var(HELPER_ENV) else {
            return;
        };
        let arg = std::env::var(HELPER_ARG_ENV).unwrap_or_default();
        let (ret, errno) = helper_action(&action, &arg);
        println!("HELPER_RESULT ret={ret} errno={errno}");
    }

    fn test_exe() -> PathBuf {
        std::env::current_exe().unwrap()
    }

    /// The read grant the re-exec'd helper needs for its own binary.
    fn helper_read_paths() -> Vec<PathBuf> {
        vec![test_exe().parent().unwrap().to_path_buf()]
    }

    fn helper_command(action: &str, arg: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(test_exe());
        command
            .args([
                "--exact",
                "confiner::tests::helper_entry",
                "--nocapture",
                "--test-threads=1",
                "-q",
            ])
            .env(HELPER_ENV, action)
            .env(HELPER_ARG_ENV, arg);
        command
    }

    async fn run_helper(confiner: &LandlockConfiner, action: &str, arg: &str) -> (i64, i32) {
        let (_, output) = run(confiner.confine(helper_command(action, arg))).await;
        let line = output
            .lines()
            .find_map(|l| l.strip_prefix("HELPER_RESULT "))
            .unwrap_or_else(|| panic!("helper produced no result: {output}"));
        let mut ret = None;
        let mut errno = None;
        for field in line.split_whitespace() {
            if let Some(v) = field.strip_prefix("ret=") {
                ret = Some(v.parse().unwrap());
            } else if let Some(v) = field.strip_prefix("errno=") {
                errno = Some(v.parse().unwrap());
            }
        }
        (ret.unwrap(), errno.unwrap())
    }

    // --- Unix-socket escape (audit C1) -----------------------------------

    #[tokio::test]
    async fn connecting_to_an_outside_unix_socket_is_blocked_by_default() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        let socket_path = outside.path().join("bus.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &helper_read_paths(), &[], true);

        let (ret, errno) =
            run_helper(&confiner, "unix_connect", socket_path.to_str().unwrap()).await;

        assert!(ret < 0, "connect to an outside Unix socket must fail");
        assert_eq!(errno, libc::EPERM, "blocked at socket(AF_UNIX) by seccomp");
    }

    #[tokio::test]
    async fn socketpair_still_works_when_unix_sockets_are_blocked() {
        let dir = fixture_dir();
        let confiner = LandlockConfiner::new(dir.path(), &helper_read_paths(), &[], true);

        let (ret, errno) = run_helper(&confiner, "socketpair", "").await;

        assert_eq!(ret, 0, "socketpair failed with errno {errno}");
    }

    #[tokio::test]
    async fn allow_unix_sockets_opts_out_of_the_block() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        let socket_path = outside.path().join("bus.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let options = crate::ConfineOptions::new()
            .require_enforcement(true)
            .allow_unix_sockets(true);
        let confiner =
            LandlockConfiner::with_options(dir.path(), &helper_read_paths(), &[], options);

        let (ret, errno) =
            run_helper(&confiner, "unix_connect", socket_path.to_str().unwrap()).await;

        assert_eq!(ret, 0, "opted-out connect failed with errno {errno}");
    }

    #[tokio::test]
    async fn session_ipc_environment_variables_are_scrubbed() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let mut command = tokio::process::Command::new("sh");
        command.args([
            "-c",
            "echo \"[$DBUS_SESSION_BUS_ADDRESS$XDG_RUNTIME_DIR$SSH_AUTH_SOCK\
             $GPG_AGENT_INFO$WAYLAND_DISPLAY$DISPLAY]\"",
        ]);
        for var in SCRUBBED_ENV_VARS {
            command.env(var, "leaked");
        }

        let (success, output) = run(confiner.confine(command)).await;

        assert!(success, "command failed: {output}");
        assert_eq!(output.trim(), "[]");
    }

    // --- Symlinks in an enumerated (carved-out) directory (audit C2) -----

    #[tokio::test]
    async fn a_symlink_next_to_a_denied_file_does_not_grant_its_target() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        std::fs::write(outside.path().join("secret.txt"), "top secret").unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("docs")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join("docs/secret.txt"));
        let (success, output) = run(confiner.confine(command)).await;
        assert!(!success, "read through the symlink must fail: {output}");
        assert!(!output.contains("top secret"));

        let written = outside.path().join("w.txt");
        let mut command = tokio::process::Command::new("sh");
        command.args([
            "-c",
            &format!("echo pwn > {}", dir.path().join("docs/w.txt").display()),
        ]);
        let (success, _) = run(confiner.confine(command)).await;
        assert!(!success, "write through the symlink must fail");
        assert!(!written.exists());
    }

    #[tokio::test]
    async fn a_symlink_to_root_in_a_carved_out_subdirectory_grants_nothing() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        std::fs::write(outside.path().join("secret.txt"), "top secret").unwrap();
        let certs = dir.path().join("certs");
        std::fs::create_dir(&certs).unwrap();
        std::fs::write(certs.join("test.pem"), "KEY").unwrap();
        std::os::unix::fs::symlink("/", certs.join("root")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from("*.pem")], true);

        let mut command = tokio::process::Command::new("cat");
        command.arg(
            certs
                .join("root")
                .join(outside.path().strip_prefix("/").unwrap())
                .join("secret.txt"),
        );
        let (success, output) = run(confiner.confine(command)).await;
        assert!(!success, "read through certs/root must fail: {output}");
        assert!(!output.contains("top secret"));
    }

    #[tokio::test]
    async fn write_inside_the_granted_root_succeeds() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let target = dir.path().join("ok.txt");

        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", &format!("echo hi > {}", target.display())]);
        let command = confiner.confine(command);

        let (success, output) = run(command).await;
        assert!(success, "command failed: {output}");
        assert_eq!(std::fs::read_to_string(&target).unwrap().trim(), "hi");
    }

    #[tokio::test]
    async fn write_outside_the_granted_root_fails() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        let confiner = confiner_for(dir.path());
        let target = outside.path().join("should-not-exist.txt");

        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", &format!("echo hi > {}", target.display())]);
        let command = confiner.confine(command);

        let (success, _output) = run(command).await;
        assert!(
            !success,
            "write outside the granted root should have failed"
        );
        assert!(!target.exists());
    }

    #[tokio::test]
    async fn read_outside_the_allowlist_fails() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "top secret").unwrap();
        let confiner = confiner_for(dir.path());

        let mut command = tokio::process::Command::new("cat");
        command.arg(&secret);
        let command = confiner.confine(command);

        let (success, output) = run(command).await;
        assert!(!success, "read outside the allowlist should have failed");
        assert!(!output.contains("top secret"));
    }

    #[tokio::test]
    async fn read_of_an_allowlisted_path_succeeds() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join("readable.txt"), "hello").unwrap();
        let confiner = confiner_for(dir.path());

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join("readable.txt"));
        let command = confiner.confine(command);

        let (success, output) = run(command).await;
        assert!(success, "read of an allowlisted path should have succeeded");
        assert!(output.contains("hello"));
    }

    #[tokio::test]
    async fn a_normal_command_still_works_under_the_seccomp_filter() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());

        let mut command = tokio::process::Command::new("echo");
        command.arg("still works");
        let command = confiner.confine(command);

        let (success, output) = run(command).await;
        assert!(
            success,
            "a normal command should not be broken by the seccomp filter"
        );
        assert!(output.contains("still works"));
    }

    #[tokio::test]
    async fn deny_paths_entry_nested_inside_cwd_is_excluded_from_the_grant() {
        let dir = fixture_dir();
        let secret_dir = dir.path().join("secret");
        std::fs::create_dir(&secret_dir).unwrap();
        std::fs::write(secret_dir.join("id_rsa"), "top secret").unwrap();
        std::fs::write(dir.path().join("public.txt"), "hello").unwrap();

        let confiner =
            LandlockConfiner::new(dir.path(), &[], std::slice::from_ref(&secret_dir), true);

        let mut command = tokio::process::Command::new("cat");
        command.arg(secret_dir.join("id_rsa"));
        let command = confiner.confine(command);
        let (success, output) = run(command).await;
        assert!(!success, "denied subdirectory should not be readable");
        assert!(!output.contains("top secret"));

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join("public.txt"));
        let command = confiner.confine(command);
        let (success, output) = run(command).await;
        assert!(
            success,
            "sibling of the denied subdirectory should still be readable"
        );
        assert!(output.contains("hello"));
    }

    #[test]
    fn grant_paths_excluding_returns_root_unchanged_when_nothing_is_denied() {
        let dir = fixture_dir();
        let grants = grant_paths_excluding(dir.path(), &[]);
        assert_eq!(grants, vec![dir.path().to_path_buf()]);
    }

    #[test]
    fn grant_paths_excluding_returns_empty_when_root_itself_is_denied() {
        let dir = fixture_dir();
        let grants = grant_paths_excluding(dir.path(), &[dir.path().to_path_buf()]);
        assert!(grants.is_empty());
    }

    #[test]
    fn find_basename_glob_matches_finds_a_nested_match() {
        let dir = fixture_dir();
        std::fs::create_dir(dir.path().join("nested")).unwrap();
        std::fs::write(dir.path().join("nested/.env"), "SECRET=1").unwrap();
        std::fs::write(dir.path().join("public.txt"), "hello").unwrap();

        let matches = find_basename_glob_matches(dir.path(), &[PathBuf::from(".env")]);

        assert_eq!(matches, vec![dir.path().join("nested/.env")]);
    }

    #[test]
    fn a_deny_paths_list_with_no_bare_entries_produces_no_matches() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();

        // Every entry here has a path separator, so `deny_paths` has no
        // bare patterns at all — the real `.env` file present must not
        // be reported as a match, whether or not the fast-path
        // short-circuit itself is exercised (a separate, harder-to-
        // black-box-test performance property, not asserted here).
        let matches = find_basename_glob_matches(dir.path(), &[PathBuf::from("/some/abs/path")]);

        assert!(matches.is_empty());
    }

    #[test]
    fn find_basename_glob_matches_does_not_follow_a_symlinked_directory() {
        let dir = fixture_dir();
        let real_target = fixture_dir();
        std::fs::write(real_target.path().join(".env"), "SECRET=1").unwrap();
        std::os::unix::fs::symlink(real_target.path(), dir.path().join("link")).unwrap();

        let matches = find_basename_glob_matches(dir.path(), &[PathBuf::from(".env")]);

        assert!(matches.is_empty(), "must not follow symlinked directories");
    }

    #[test]
    fn find_basename_glob_matches_does_not_descend_into_a_git_directory() {
        let dir = fixture_dir();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        std::fs::write(dir.path().join(".git/.env"), "SECRET=1").unwrap();

        let matches = find_basename_glob_matches(dir.path(), &[PathBuf::from(".env")]);

        assert!(matches.is_empty(), "must not descend into .git directories");
    }

    #[tokio::test]
    async fn a_bare_basename_pattern_nested_inside_cwd_is_excluded_from_the_grant() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::write(dir.path().join("public.txt"), "hello").unwrap();

        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join(".env"));
        let command = confiner.confine(command);
        let (success, output) = run(command).await;
        assert!(!success, "bare-pattern-matched file should not be readable");
        assert!(!output.contains("SECRET"));

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join("public.txt"));
        let command = confiner.confine(command);
        let (success, output) = run(command).await;
        assert!(success, "non-matching sibling should still be readable");
        assert!(output.contains("hello"));
    }

    #[tokio::test]
    async fn a_bare_basename_pattern_nested_inside_cwd_cannot_be_written_either() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();

        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let mut command = tokio::process::Command::new("sh");
        command.args([
            "-c",
            &format!("echo overwritten > {}", dir.path().join(".env").display()),
        ]);
        let command = confiner.confine(command);
        let (success, _output) = run(command).await;
        assert!(
            !success,
            "writing to a bare-pattern-matched file should fail"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join(".env")).unwrap(),
            "SECRET=1",
            "the original content must be untouched"
        );
    }
}
