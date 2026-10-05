//! Real OS-level process confinement, replacing `NoopConfiner`: Landlock
//! (filesystem scoping) + a seccomp-bpf syscall denylist. See
//! `aivyx-ecosystem/docs/superpowers/specs/2026-08-16-aivyx-confine-design.md`
//! and this crate's own `CLAUDE.md` ("The `ExecutionConfiner` contract")
//! for the policy rationale (informed by, but deliberately not identical
//! to, Codex CLI's current bubblewrap-based sandbox).

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, PathBeneath, Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr,
    RulesetStatus, Scope,
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
/// Nonexistent paths are silently skipped by `Grants::push_root`, so it's
/// safe to list toolchain paths that may not exist on a given system.
const DEFAULT_READ_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Home-relative toolchain paths, joined against `$HOME` when set.
/// `.gitconfig`/`.config/git` matter beyond convenience: `git commit` needs
/// the user's identity from global config, and git treats an *unreadable*
/// (EACCES) existing config file as fatal — so without these grants every
/// confined `git` invocation on a machine with a global config would die.
const DEFAULT_HOME_READ_PATHS: &[&str] = &[".cargo", ".rustup", ".gitconfig", ".config/git"];

/// Plaintext credential stores that live inside `DEFAULT_HOME_READ_PATHS`:
/// the crates.io token (current and legacy file names) and git's XDG
/// credential-store file. Never readable by a confined command — see
/// `compute_grants`.
const HOME_CREDENTIAL_PATHS: &[&str] = &[
    ".cargo/credentials.toml",
    ".cargo/credentials",
    ".config/git/credentials",
];

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
/// a coding agent's tools never need to create or join namespaces; `clone`
/// with a namespace flag and `clone3` are handled separately in
/// `build_seccomp_filters`. The new mount API (`fsopen` .. `mount_setattr`)
/// is blocked alongside `mount`.
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
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
];

/// Syscalls with no legitimate use in a coding agent's shell commands,
/// blocked regardless of what Landlock's filesystem scoping already
/// prevents — defense in depth against confinement-escape/introspection
/// primitives (`ptrace`, `io_uring`, `perf_event_open`, the kernel keyring,
/// `userfaultfd`) and privileged operations that a namespace-based sandbox
/// (like Codex CLI's bubblewrap) would otherwise block for free via
/// capability dropping. This design doesn't use namespaces, so those need
/// to be explicit here instead. `unshare`/`setns` are blocked outright since
/// a coding agent's tools never need to create or join namespaces; `clone`
/// with a namespace flag and `clone3` are handled separately in
/// `build_seccomp_filters`. The new mount API (`fsopen` .. `mount_setattr`)
/// is blocked alongside `mount`.
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
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
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

/// `__X32_SYSCALL_BIT`: x86_64 syscall numbers with this bit set select
/// the x32 ABI, which shares `AUDIT_ARCH_X86_64` with native calls.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

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

enum TmpPolicy {
    Shared,
    Private(Option<tempfile::TempDir>),
}

impl TmpPolicy {
    fn new(share_system_tmp: bool) -> Self {
        if share_system_tmp {
            return Self::Shared;
        }
        match tempfile::Builder::new().prefix("aivyx-confine-").tempdir() {
            Ok(dir) => Self::Private(Some(dir)),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "could not create a private temp directory; confined commands will have \
                     no writable temp directory"
                );
                Self::Private(None)
            }
        }
    }
}

/// Sends `SIGKILL` to the process group `pgid` — every process a
/// confined command left behind (nothing can leave the group unless
/// `ConfineOptions::allow_leaving_process_group` is set; see the
/// process-group contract on `ExecutionConfiner`). `LandlockConfiner`
/// makes each confined command the leader of a new group, so `pgid` is
/// the `Child::id()` recorded right after `spawn()` — record it then,
/// since `id()` returns `None` once the child has been reaped. A group
/// that no longer exists is not an error. `pgid` 0 (which would mean
/// "the caller's own group") and values beyond `pid_t` are rejected.
///
/// Call it promptly. The kernel never hands out a pid that is still in
/// use as a process-group id, but once *every* member of the group has
/// exited the number is free again, so a much later call could hit an
/// unrelated group. Killing as soon as the tool call ends (or right after
/// the leader is reaped) keeps that window negligible.
pub fn kill_process_group(pgid: u32) -> io::Result<()> {
    let pgid = libc::pid_t::try_from(pgid)
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: plain syscall with a validated, positive group id.
    if unsafe { libc::killpg(pgid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err)
}

pub struct LandlockConfiner {
    cwd: PathBuf,
    extra_read_paths: Vec<PathBuf>,
    /// The non-bare `deny_paths` entries, used as-is.
    deny_paths: Vec<PathBuf>,
    /// The bare (single-component) `deny_paths` entries, compiled once.
    /// `None` when there are none, so no filesystem walk ever happens.
    bare_patterns: Option<globset::GlobSet>,
    /// The previous bare-pattern walk, so unchanged directories are not
    /// re-read on every spawn. See `walk_for_basename_matches`.
    scan_cache: std::sync::Mutex<ScanCache>,
    home: Option<PathBuf>,
    /// `SCAN_CACHE_SETTLE_SECS`, as a field so tests can exercise the
    /// cache without waiting.
    scan_settle_secs: i64,
    /// The temp-dir policy: `Shared` with `share_system_tmp`, otherwise the
    /// private directory (`None` if it could not be created, in which case
    /// no temp directory is writable at all).
    tmp: TmpPolicy,
    /// Installed in order in the child; see `build_seccomp_filters`.
    seccomp_programs: Vec<BpfProgram>,
    require_enforcement: bool,
    /// Test hook: behave as if the Landlock ruleset could not be built.
    #[cfg(test)]
    force_ruleset_failure: bool,
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

    /// Cheap: records the policy and compiles the seccomp filter. The
    /// filesystem grants (including the `deny_paths` carve-outs) are
    /// computed afresh on every `confine()` call, so a denied file that
    /// appears after construction is still denied to later spawns.
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

        let (bare, non_bare): (Vec<&PathBuf>, Vec<&PathBuf>) =
            deny_paths.iter().partition(|p| crate::is_bare_pattern(p));

        Self {
            cwd: cwd.to_path_buf(),
            extra_read_paths: extra_read_paths.to_vec(),
            deny_paths: non_bare.into_iter().cloned().collect(),
            bare_patterns: compile_bare_patterns(&bare),
            scan_cache: std::sync::Mutex::new(ScanCache::new()),
            home: std::env::var_os("HOME").map(PathBuf::from),
            scan_settle_secs: SCAN_CACHE_SETTLE_SECS,
            tmp: TmpPolicy::new(options.share_system_tmp),
            seccomp_programs: build_seccomp_filters(&options),
            require_enforcement,
            #[cfg(test)]
            force_ruleset_failure: false,
        }
    }

    /// Computes the read and write grants from the current filesystem
    /// state. Runs in the parent, before fork, on every `confine()`.
    fn compute_grants(&self) -> (Grants, Grants) {
        // Bare deny_paths patterns (e.g. `.env`) are resolved into
        // concrete file paths by scanning every project-relevant root —
        // `cwd` and each `extra_read_paths` entry, the roots a project's
        // own secrets could plausibly live under. The combined result is
        // reused for *every* grant computation below, including the fixed
        // system paths and the temp directory: any of them could, in
        // principle, be an ancestor of a project-relevant root (an
        // `/etc/nixos`-style system-config-as-project-repo, or `cwd`
        // nested inside the system temp dir) and would otherwise silently
        // re-grant whatever that root's own narrower carve-out just
        // excluded. Passing the same fully-resolved list to every
        // `grant_paths_excluding` call is safe, not overly permissive —
        // that function only ever acts on entries actually nested under
        // the specific root it's given.
        // Carve-outs match lexically (`Path::starts_with`), so roots and
        // deny entries are compared in canonical form: a non-canonical
        // `cwd` (reached through a symlink) or a deny entry given through
        // a symlink would otherwise silently match nothing. Relative
        // multi-component entries (`config/secrets.json`) are taken
        // relative to `cwd`. Both the given and the canonical form of each
        // entry are kept; the extra one is harmless.
        let cwd = canonical_or_given(&self.cwd);
        let extra_read_paths: Vec<PathBuf> = self
            .extra_read_paths
            .iter()
            .map(|p| canonical_or_given(p))
            .collect();
        let mut resolved_deny_paths = Vec::with_capacity(self.deny_paths.len() * 2);
        for entry in &self.deny_paths {
            let absolute = if entry.is_relative() {
                cwd.join(entry)
            } else {
                entry.clone()
            };
            let canonical = canonical_or_given(&absolute);
            if canonical != absolute {
                resolved_deny_paths.push(canonical);
            }
            resolved_deny_paths.push(absolute);
        }
        // Credential stores inside the home read grants are always carved
        // out, whatever the consumer's own deny list says. Only existing
        // ones: a missing one needs no carve-out, and if it appears later
        // the next spawn's computation picks it up.
        if let Some(home) = &self.home {
            resolved_deny_paths.extend(
                HOME_CREDENTIAL_PATHS
                    .iter()
                    .map(|p| home.join(p))
                    .filter(|p| p.symlink_metadata().is_ok()),
            );
        }
        if let Some(patterns) = &self.bare_patterns {
            // A poisoned lock only means another spawn panicked mid-walk;
            // the cache is advisory, so start from whatever it holds.
            let mut cache = self
                .scan_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut next = ScanCache::new();
            for root in std::iter::once(&cwd).chain(&extra_read_paths) {
                walk_for_basename_matches(
                    root,
                    self.scan_settle_secs,
                    patterns,
                    &mut cache,
                    &mut next,
                    &mut resolved_deny_paths,
                );
            }
            *cache = next;
        }

        // Landlock rules are inode-based but denies are path-based, so a
        // second hard link to a denied file would be readable through its
        // other name. Find every such alias under the project roots and
        // deny it too. Only runs when a denied file actually has more
        // than one link, which is rare.
        let linked_inodes = multiply_linked_inodes(&resolved_deny_paths);
        if !linked_inodes.is_empty() {
            for root in std::iter::once(&cwd).chain(&extra_read_paths) {
                find_hardlink_aliases(root, &linked_inodes, &mut resolved_deny_paths);
            }
        }

        // `grant_paths_excluding` is applied uniformly to every candidate
        // root. It grants the root whole whenever nothing is nested
        // underneath, so this costs nothing extra in the common case.
        let mut read_candidates: Vec<PathBuf> =
            DEFAULT_READ_PATHS.iter().map(PathBuf::from).collect();
        if let Some(home) = &self.home {
            read_candidates.extend(DEFAULT_HOME_READ_PATHS.iter().map(|p| home.join(p)));
        }
        read_candidates.push(cwd.clone());
        read_candidates.extend(extra_read_paths.iter().cloned());
        let mut read_grants = Grants::default();
        for root in &read_candidates {
            grant_paths_excluding(root, &resolved_deny_paths, &mut read_grants);
        }
        // Read side of the device grants below (read and write rules are
        // separate Landlock rule sets, so both lists need the entries).
        for device in DEVICE_RW_PATHS {
            read_grants.push_root(Path::new(device));
        }

        let mut write_candidates = vec![cwd.clone()];
        match &self.tmp {
            TmpPolicy::Shared => {
                write_candidates.push(std::env::temp_dir());
                if let Some(tmpdir) = std::env::var_os("TMPDIR") {
                    write_candidates.push(PathBuf::from(tmpdir));
                }
            }
            TmpPolicy::Private(Some(dir)) => write_candidates.push(dir.path().to_path_buf()),
            TmpPolicy::Private(None) => {}
        }
        let mut write_grants = Grants::default();
        for root in &write_candidates {
            grant_paths_excluding(root, &resolved_deny_paths, &mut write_grants);
        }
        // Individual device files, not subject to deny_paths carve-outs
        // (they're fixed, well-known, and content-free); `push_root` silently
        // skips any that don't exist.
        for device in DEVICE_RW_PATHS {
            write_grants.push_root(Path::new(device));
        }

        (read_grants, write_grants)
    }

    /// Builds the full ruleset here, in the parent process, before `fork()`
    /// — all allocation (rule construction, path resolution) must happen
    /// before the `pre_exec` hook runs, since that closure executes in the
    /// forked child under async-signal-safety constraints (no allocation,
    /// no locks). `RulesetCreated::restrict_self()` itself is verified to
    /// be a thin syscall wrapper over this already-built state.
    fn build_ruleset(
        read_grants: &Grants,
        write_grants: &Grants,
    ) -> Result<RulesetCreated, landlock::RulesetError> {
        Ruleset::default()
            .handle_access(AccessFs::from_all(LANDLOCK_ABI))?
            // Signals and abstract Unix sockets may not cross the sandbox
            // boundary: without this a confined command can kill any of
            // the user's processes and reach abstract-namespace sockets
            // (e.g. X11's `@/tmp/.X11-unix/X0`), which no filesystem rule
            // covers. Needs ABI 6; silently skipped on older kernels
            // (best-effort compatibility, as for every other right).
            .scope(Scope::from_all(LANDLOCK_ABI))?
            .create()?
            .add_rules(fd_rules(
                &read_grants.full,
                AccessFs::from_read(LANDLOCK_ABI),
            ))?
            .add_rules(fd_rules(&read_grants.dir_only, AccessFs::ReadDir.into()))?
            .add_rules(fd_rules(
                &write_grants.full,
                AccessFs::from_all(LANDLOCK_ABI),
            ))?
            .add_rules(fd_rules(
                &write_grants.dir_only,
                carved_out_dir_write_access(),
            ))
    }
}

/// Landlock rules for `grants`, built from their already-open fds.
/// Non-directories get only the file subset of `access` (Landlock rejects
/// directory rights on a file).
fn fd_rules(
    grants: &[Grant],
    access: landlock::BitFlags<AccessFs>,
) -> impl Iterator<Item = Result<PathBeneath<BorrowedFd<'_>>, landlock::RulesetError>> {
    grants.iter().map(move |grant| {
        let access = if grant.is_dir {
            access
        } else {
            access & AccessFs::from_file(LANDLOCK_ABI)
        };
        Ok(PathBeneath::new(grant.fd.as_fd(), access))
    })
}

/// Grants computed for one access level (read, or read+write).
/// `full` paths get that level's whole access set beneath them.
/// `dir_only` paths are directories that had to be enumerated to carve a
/// denied entry out of them: they get only directory-level rights (list,
/// create entries), never file rights, because file rights
/// on a directory would apply to every file beneath it — including the
/// denied one.
///
/// Every grant holds the fd it was opened through, and the ruleset is
/// built from those fds (`PathBeneath::new(fd, ..)`), never by resolving
/// `path` again: a confined racer can swap an entry for a symlink between
/// enumeration and ruleset construction, and a by-path reopen would then
/// attach the rule to the symlink's target. `path` is only a label (for
/// deny matching and tests).
#[derive(Debug, Default)]
struct Grants {
    full: Vec<Grant>,
    dir_only: Vec<Grant>,
}

#[derive(Debug)]
struct Grant {
    /// A label only (see `Grants`); read by `Debug` output and tests.
    #[cfg_attr(not(test), allow(dead_code))]
    path: PathBuf,
    fd: OwnedFd,
    is_dir: bool,
}

impl Grants {
    /// Grants `path` whole, resolving it (following symlinks) — only for
    /// the fixed roots handed in by the consumer or this crate, never for
    /// an enumerated child.
    fn push_root(&mut self, path: &Path) {
        if let Some(fd) = open_path(path, libc::O_PATH | libc::O_CLOEXEC) {
            let is_dir = fd_is_dir(fd.as_fd());
            self.full.push(Grant {
                path: path.to_path_buf(),
                fd,
                is_dir,
            });
        }
    }

    #[cfg(test)]
    fn full_paths(&self) -> Vec<PathBuf> {
        self.full.iter().map(|g| g.path.clone()).collect()
    }
}

fn cstring(bytes: &[u8]) -> Option<std::ffi::CString> {
    std::ffi::CString::new(bytes).ok()
}

/// `open(path, flags)`; `None` on any failure.
fn open_path(path: &Path, flags: libc::c_int) -> Option<OwnedFd> {
    let path = cstring(path.as_os_str().as_bytes())?;
    // SAFETY: valid NUL-terminated path; the returned fd is owned below.
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    // SAFETY: `fd` is a freshly opened descriptor nobody else owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `openat(dir, name, flags)` for a single path component; `None` on any
/// failure. With `O_NOFOLLOW` nothing is resolved through a symlink.
fn open_at(dir: BorrowedFd<'_>, name: &OsStr, flags: libc::c_int) -> Option<OwnedFd> {
    let name = cstring(name.as_bytes())?;
    // SAFETY: valid dirfd and NUL-terminated name; the fd is owned below.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    // SAFETY: `fd` is a freshly opened descriptor nobody else owns.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Opens a directory entry of `dir` as a directory to read, refusing
/// symlinks.
fn open_subdir(dir: BorrowedFd<'_>, name: &OsStr) -> Option<OwnedFd> {
    open_at(
        dir,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

fn fd_stat(fd: BorrowedFd<'_>) -> Option<libc::stat> {
    // SAFETY: `stat` is plain old data and fully written on success.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid fd and out-pointer.
    (unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0).then_some(st)
}

fn fd_is_dir(fd: BorrowedFd<'_>) -> bool {
    fd_stat(fd).is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// The entries of the directory open on `dir` (minus `.`/`..`), with
/// their `d_type` (`DT_UNKNOWN` on filesystems that don't report it).
fn dir_entries(dir: BorrowedFd<'_>) -> Vec<(OsString, u8)> {
    // SAFETY: duplicating a valid fd; ownership passes to `fdopendir`.
    let dup = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Vec::new();
    }
    // SAFETY: `dup` is a valid directory fd we own.
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        // SAFETY: `fdopendir` failed, so `dup` is still ours to close.
        unsafe { libc::close(dup) };
        return Vec::new();
    }
    let mut entries = Vec::new();
    // SAFETY: `stream` is a valid DIR*; the dup shares its offset with
    // `dir`, so start from the beginning explicitly.
    unsafe { libc::rewinddir(stream) };
    loop {
        // SAFETY: `stream` is valid; the entry is copied out before the
        // next `readdir` call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        // SAFETY: `d_name` is NUL-terminated per readdir(3).
        let (name, d_type) = unsafe {
            (
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()),
                (*entry).d_type,
            )
        };
        let name = name.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        entries.push((OsStr::from_bytes(name).to_os_string(), d_type));
    }
    // SAFETY: closes the stream and `dup` with it.
    unsafe { libc::closedir(stream) };
    entries
}

/// Directory-level rights for a carved-out directory in the write set:
/// list it and create new entries in it — nothing else. None of these
/// reads or writes file *contents*, so the denied entry stays unreadable
/// and unwritable.
///
/// Deliberately *no* `RemoveFile`/`RemoveDir`/`Refer`: deny matching is
/// by path, so a denied entry renamed in place (`mv .env x`, or
/// `ln .env y && rm .env`) would no longer match at the next spawn's
/// grant computation and would be granted in full. Without them, entries
/// directly in a carved-out directory cannot be removed, renamed or moved
/// out, and the swap a symlink race needs is impossible there.
///
/// The accepted cost (documented as the I1 limit in the README): `rm`
/// and `mv` of entries directly in a carved-out directory fail, and a
/// file or directory *newly created* directly in it has no file rights
/// for the rest of that spawn, because no rule covers its inode yet —
/// `echo a > new` leaves an empty `new`, `git init` leaves a partial
/// `.git`. The next `confine()` re-computes the grants and covers it.
fn carved_out_dir_write_access() -> landlock::BitFlags<AccessFs> {
    AccessFs::ReadDir
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSym
        | AccessFs::MakeFifo
        | AccessFs::MakeSock
}

/// Landlock has no negative/deny rule — a domain can only ever be *more*
/// restricted than ambient, never "grant X except Y". To grant `root`
/// wholesale while still excluding a `deny_paths` entry nested somewhere
/// inside it, enumerate `root`'s direct children and grant each
/// individually: recurse into any child that itself contains a denial
/// further down, and skip entirely any child that *is* a denial. The
/// enumerated directory itself goes into `grants.dir_only` (see `Grants`).
/// When nothing under `root` is denied (the common case), `root` is
/// granted whole with no extra filesystem work.
fn grant_paths_excluding(root: &Path, deny_paths: &[PathBuf], grants: &mut Grants) {
    if deny_paths.iter().any(|denied| denied == root) {
        return;
    }
    if !deny_paths.iter().any(|denied| denied.starts_with(root)) {
        grants.push_root(root);
        return;
    }
    // Can't enumerate what's inside `root` — fail toward less access, not
    // more, rather than granting a directory whose contents are unknown.
    let Some(dir) = open_path(root, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) else {
        return;
    };
    grant_dir_excluding(root, dir, deny_paths, grants);
}

/// The enumerating half of `grant_paths_excluding`, for a directory
/// already open on `dir`. Every child is opened relative to `dir` with
/// `O_NOFOLLOW`, so no path is resolved twice and no symlink is followed:
/// a symlink entry is never granted (granting `docs -> /` would hand out
/// the whole filesystem, because Landlock attaches the rule to the
/// target), and an entry swapped for a symlink mid-walk is either seen as
/// the symlink (skipped) or as the original inode (granted as that
/// inode). Skipping symlinks costs nothing legitimate: Landlock checks the
/// resolved path, so a symlink whose target is inside some other grant
/// still works through that grant. An entry that can't be opened or
/// stat'ed is skipped (fail toward less access).
fn grant_dir_excluding(path: &Path, dir: OwnedFd, deny_paths: &[PathBuf], grants: &mut Grants) {
    let relevant: Vec<&PathBuf> = deny_paths
        .iter()
        .filter(|denied| denied.starts_with(path))
        .collect();
    for (name, _) in dir_entries(dir.as_fd()) {
        let child = path.join(&name);
        if relevant.iter().any(|denied| **denied == child) {
            continue;
        }
        if relevant.iter().any(|denied| denied.starts_with(&child)) {
            if let Some(subdir) = open_subdir(dir.as_fd(), &name) {
                grant_dir_excluding(&child, subdir, deny_paths, grants);
            }
            continue;
        }
        let Some(fd) = open_at(
            dir.as_fd(),
            &name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        ) else {
            continue;
        };
        let Some(st) = fd_stat(fd.as_fd()) else {
            continue;
        };
        let kind = st.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            continue;
        }
        grants.full.push(Grant {
            path: child,
            fd,
            is_dir: kind == libc::S_IFDIR,
        });
    }
    grants.dir_only.push(Grant {
        path: path.to_path_buf(),
        fd: dir,
        is_dir: true,
    });
}

fn canonical_or_given(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// `(dev, ino)` of every denied regular file that has more than one hard
/// link.
fn multiply_linked_inodes(deny_paths: &[PathBuf]) -> std::collections::HashSet<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    deny_paths
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .filter(|meta| meta.is_file() && meta.nlink() > 1)
        .map(|meta| (meta.dev(), meta.ino()))
        .collect()
}

/// Appends every regular file under `root` (not following symlinks, and
/// including `.git`) whose `(dev, ino)` is in `inodes`. Paths already in
/// `out` are appended again harmlessly. Uncached: a full walk of the root
/// on every spawn, but only while some denied file has more than one
/// link.
fn find_hardlink_aliases(
    root: &Path,
    inodes: &std::collections::HashSet<(u64, u64)>,
    out: &mut Vec<PathBuf>,
) {
    if let Some(dir) = open_path(root, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) {
        find_hardlink_aliases_in(root, dir.as_fd(), inodes, out);
    }
}

fn find_hardlink_aliases_in(
    path: &Path,
    dir: BorrowedFd<'_>,
    inodes: &std::collections::HashSet<(u64, u64)>,
    out: &mut Vec<PathBuf>,
) {
    for (name, d_type) in dir_entries(dir) {
        if matches!(d_type, libc::DT_DIR | libc::DT_UNKNOWN)
            && let Some(subdir) = open_subdir(dir, &name)
        {
            find_hardlink_aliases_in(&path.join(&name), subdir.as_fd(), inodes, out);
            continue;
        }
        if !matches!(d_type, libc::DT_REG | libc::DT_UNKNOWN) {
            continue;
        }
        let Some(fd) = open_at(
            dir,
            &name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        ) else {
            continue;
        };
        if let Some(st) = fd_stat(fd.as_fd())
            && st.st_mode & libc::S_IFMT == libc::S_IFREG
            && st.st_nlink > 1
            && inodes.contains(&(st.st_dev, st.st_ino))
        {
            out.push(path.join(&name));
        }
    }
}

/// Compiles the bare (single-component) `deny_paths` patterns into one
/// matcher, once, at construction — matching every directory entry
/// against a freshly compiled glob per pattern was the dominant cost of
/// the walk. An entry that is not a valid glob is dropped with a warning,
/// matching `crate::is_basename_glob_match`, which treats it as matching
/// nothing.
fn compile_bare_patterns(patterns: &[&PathBuf]) -> Option<globset::GlobSet> {
    let mut builder = globset::GlobSetBuilder::new();
    let mut any = false;
    for pattern in patterns {
        let Some(text) = pattern.to_str() else {
            continue;
        };
        match globset::Glob::new(text) {
            Ok(glob) => {
                builder.add(glob);
                any = true;
            }
            Err(err) => {
                tracing::warn!(pattern = text, error = %err, "ignoring invalid deny_paths pattern");
            }
        }
    }
    if !any {
        return None;
    }
    builder.build().ok()
}

/// What one directory contributed to the last bare-pattern walk, keyed
/// by the directory's identity, mtime and ctime. Creating, deleting or
/// renaming an entry updates both; userspace can set the mtime back
/// (`touch -d`, `tar`, `rsync -a`, `cp -a`) but not the ctime, so an
/// unchanged pair means the cached entry lists are still exact and the
/// directory need not be re-read — one `fstat` per directory instead of a
/// `readdir` plus a glob match per entry.
struct DirScan {
    dev: u64,
    ino: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    matches: Vec<PathBuf>,
    /// Names of entries that may be directories to descend into.
    subdirs: Vec<OsString>,
}

type ScanCache = std::collections::HashMap<PathBuf, DirScan>;

/// A directory modified (mtime or ctime) this recently is never cached:
/// filesystem timestamps come from a coarse clock, so an entry created in the same
/// tick as the scan could leave the mtime unchanged ("racy git" problem).
const SCAN_CACHE_SETTLE_SECS: i64 = 2;

/// Recursively finds every path under `dir` whose basename matches a
/// bare `deny_paths` pattern — the concrete file-level exclusions
/// `grant_paths_excluding` needs, since it only understands specific
/// absolute paths to carve out, not "matches anywhere" patterns.
///
/// Runs on every `confine()` call when bare patterns are configured, so a
/// match that appears after construction is still denied. `prev` is the
/// previous walk's cache (entries are moved out of it as they are
/// visited); every directory visited is recorded in `next`, which
/// replaces it (so directories that disappeared drop out). Even
/// fully cached, the walk is one `stat` per directory in the tree (minus
/// `.git`), synchronously — callers on an async runtime should call
/// `confine()` from a blocking-capable context for very large trees.
/// Each match also forces `grant_paths_excluding` to enumerate its
/// containing directory child-by-child, so a project with many matching
/// files produces a larger Landlock ruleset.
fn walk_for_basename_matches(
    root: &Path,
    settle_secs: i64,
    patterns: &globset::GlobSet,
    prev: &mut ScanCache,
    next: &mut ScanCache,
    matches: &mut Vec<PathBuf>,
) {
    if let Some(dir) = open_path(root, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) {
        walk_dir_for_basename_matches(
            root,
            dir.as_fd(),
            settle_secs,
            patterns,
            prev,
            next,
            matches,
        );
    }
}

fn walk_dir_for_basename_matches(
    path: &Path,
    dir: BorrowedFd<'_>,
    settle_secs: i64,
    patterns: &globset::GlobSet,
    prev: &mut ScanCache,
    next: &mut ScanCache,
    matches: &mut Vec<PathBuf>,
) {
    let Some(st) = fd_stat(dir) else {
        return;
    };
    let mtime = (st.st_mtime, st.st_mtime_nsec);
    let ctime = (st.st_ctime, st.st_ctime_nsec);
    let scan = match prev.remove(path) {
        Some(cached)
            if cached.dev == st.st_dev
                && cached.ino == st.st_ino
                && cached.mtime == mtime
                && cached.ctime == ctime =>
        {
            cached
        }
        _ => {
            let mut scan = DirScan {
                dev: st.st_dev,
                ino: st.st_ino,
                mtime,
                ctime,
                matches: Vec::new(),
                subdirs: Vec::new(),
            };
            for (name, d_type) in dir_entries(dir) {
                if patterns.is_match(Path::new(&name)) {
                    scan.matches.push(path.join(&name));
                    continue; // matched — no need to recurse further into it
                }
                // `.git` directories never legitimately hold a project's
                // own secrets — they hold git's object database and refs —
                // so skipping them cuts real walk cost without weakening
                // the guarantee this scan exists for.
                if matches!(d_type, libc::DT_DIR | libc::DT_UNKNOWN) && name != ".git" {
                    scan.subdirs.push(name);
                }
            }
            scan
        }
    };
    matches.extend(scan.matches.iter().cloned());
    // Subdirectories are opened relative to `dir` with `O_NOFOLLOW`, so a
    // symlinked directory (or one swapped in mid-walk) is never followed —
    // which also keeps a symlink cycle from causing unbounded recursion.
    for name in &scan.subdirs {
        if let Some(subdir) = open_subdir(dir, name) {
            walk_dir_for_basename_matches(
                &path.join(name),
                subdir.as_fd(),
                settle_secs,
                patterns,
                prev,
                next,
                matches,
            );
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    if now - mtime.0.max(ctime.0) >= settle_secs {
        next.insert(path.to_path_buf(), scan);
    }
}

/// `SOCK_TYPE_MASK` from the kernel's `linux/net.h` (not in `libc`).
const SOCK_TYPE_MASK: u64 = 0xf;

/// `clone` flags that create a namespace. `unshare` is blocked outright,
/// but `clone(CLONE_NEWUSER | SIGCHLD)` reaches the same kernel surface.
const NAMESPACE_CLONE_FLAGS: &[libc::c_int] = &[
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWNS,
    libc::CLONE_NEWNET,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWCGROUP,
];

/// Index of `clone`'s flags argument: s390x swaps the first two.
#[cfg(target_arch = "s390x")]
const CLONE_FLAGS_ARG: u8 = 1;
#[cfg(not(target_arch = "s390x"))]
const CLONE_FLAGS_ARG: u8 = 0;

/// The seccomp filters, installed in this order. Each one is a separate
/// kernel filter; for any syscall the most restrictive verdict wins, and
/// each filter only ever answers `Allow` or one errno, so they compose
/// without interfering:
///
/// 1. The denylist (`BLOCKED_SYSCALLS`, namespace-creating `clone`,
///    `setsid`/`setpgid`, and `socket(AF_UNIX)` plus
///    `socketpair(AF_UNIX, SOCK_DGRAM)` unless opted out) → `EPERM`.
/// 2. `clone3` → `ENOSYS`. Its flags live in a user-memory struct seccomp
///    cannot inspect, so it can't be filtered like `clone`; `ENOSYS` makes
///    glibc and others fall back to plain `clone`, which is filtered.
/// 3. x86_64 only: any syscall number with the x32 bit set → `EPERM`.
///    seccompiler's arch check accepts x32 numbers (they share
///    `AUDIT_ARCH_X86_64`), so on a kernel built with x32 support every
///    denylisted syscall would otherwise be reachable by its x32 number.
fn build_seccomp_filters(options: &crate::ConfineOptions) -> Vec<BpfProgram> {
    #[allow(unused_mut)]
    let mut programs = vec![build_denylist_filter(options), build_clone3_filter()];
    #[cfg(target_arch = "x86_64")]
    programs.push(build_x32_filter());
    programs
}

fn build_clone3_filter() -> BpfProgram {
    let rules = std::iter::once((libc::SYS_clone3, vec![])).collect();
    SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        std::env::consts::ARCH.try_into().expect("known arch"),
    )
    .expect("static seccomp policy is well-formed")
    .try_into()
    .expect("seccomp policy compiles to BPF")
}

/// Hand-written because seccompiler only matches individual syscall
/// numbers, not ranges.
#[cfg(target_arch = "x86_64")]
fn build_x32_filter() -> BpfProgram {
    use seccompiler::sock_filter;
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    // Offsets into `struct seccomp_data`.
    const NR_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;
    const LD_W_ABS: u16 = 0x20; // BPF_LD (0) | BPF_W (0) | BPF_ABS
    const JEQ_K: u16 = 0x05 | 0x10; // BPF_JMP | BPF_JEQ | BPF_K (0)
    const JGE_K: u16 = 0x05 | 0x30; // BPF_JMP | BPF_JGE | BPF_K (0)
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K (0)
    let ins = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    vec![
        // 0: A = arch; 1: not x86_64 → allow (index 5)
        ins(LD_W_ABS, 0, 0, ARCH_OFFSET),
        ins(JEQ_K, 0, 3, AUDIT_ARCH_X86_64),
        // 2: A = nr; 3: nr >= x32 bit → errno (4), else allow (5)
        ins(LD_W_ABS, 0, 0, NR_OFFSET),
        ins(JGE_K, 0, 1, X32_SYSCALL_BIT),
        ins(RET_K, 0, 0, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32),
        ins(RET_K, 0, 0, libc::SECCOMP_RET_ALLOW),
    ]
}

fn build_denylist_filter(options: &crate::ConfineOptions) -> BpfProgram {
    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> = BLOCKED_SYSCALLS
        .iter()
        .map(|&syscall| (syscall, vec![]))
        .collect();
    rules.insert(
        libc::SYS_clone,
        NAMESPACE_CLONE_FLAGS
            .iter()
            .map(|&flag| {
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        CLONE_FLAGS_ARG,
                        SeccompCmpArgLen::Qword,
                        SeccompCmpOp::MaskedEq(flag as u64),
                        flag as u64,
                    )
                    .expect("static seccomp condition is well-formed"),
                ])
                .expect("static seccomp rule is well-formed")
            })
            .collect(),
    );
    if !options.allow_leaving_process_group {
        // A confined command leads its own process group (set before this
        // filter is installed), and `kill_process_group` is how callers
        // end everything it started. `setsid`/`setpgid` are the only ways
        // out of that group, so they are refused.
        rules.insert(libc::SYS_setsid, vec![]);
        rules.insert(libc::SYS_setpgid, vec![]);
    }
    if !options.allow_unix_sockets {
        // `socket(AF_UNIX, ...)` → EPERM: Landlock does not gate
        // `connect()` to an existing pathname Unix socket, so this is the
        // only thing standing between a confined command and the user's
        // D-Bus session bus (`systemd-run --user` runs arbitrary code
        // unconfined), gpg-agent, ssh-agent, Wayland/X11 and docker.sock.
        // `socketpair()` is a different syscall and stays allowed.
        // An unconnected datagram `socketpair` end can still `sendto()`
        // any pathname datagram socket (journald, `/dev/log`), so the
        // `SOCK_DGRAM` variant is refused too. Stream and seqpacket pairs
        // are connection-oriented and stay allowed.
        rules.insert(
            libc::SYS_socketpair,
            vec![
                SeccompRule::new(vec![
                    SeccompCondition::new(
                        0,
                        SeccompCmpArgLen::Dword,
                        SeccompCmpOp::Eq,
                        libc::AF_UNIX as u64,
                    )
                    .expect("static seccomp condition is well-formed"),
                    SeccompCondition::new(
                        1,
                        SeccompCmpArgLen::Dword,
                        // The low bits are the type; the rest are
                        // SOCK_CLOEXEC/SOCK_NONBLOCK flags.
                        SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                        libc::SOCK_DGRAM as u64,
                    )
                    .expect("static seccomp condition is well-formed"),
                ])
                .expect("static seccomp rule is well-formed"),
            ],
        );
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
    fn confine(&self, command: tokio::process::Command) -> tokio::process::Command {
        let (read_grants, write_grants) = self.compute_grants();
        self.confine_with_grants(command, &read_grants, &write_grants)
    }
}

impl LandlockConfiner {
    /// `confine` with the grants already computed — split out so tests
    /// can change the filesystem between computing and applying them.
    fn confine_with_grants(
        &self,
        mut command: tokio::process::Command,
        read_grants: &Grants,
        write_grants: &Grants,
    ) -> tokio::process::Command {
        let require_enforcement = self.require_enforcement;
        for var in SCRUBBED_ENV_VARS {
            command.env_remove(var);
        }
        // Its own process group, so the caller can kill everything the
        // command leaves running (`kill_process_group`) — a lingering
        // confined process could otherwise rewrite files the caller's
        // next unconfined step reads.
        command.process_group(0);
        if let TmpPolicy::Private(dir) = &self.tmp {
            match dir {
                Some(dir) => command.env("TMPDIR", dir.path()),
                None => command.env_remove("TMPDIR"),
            };
        }

        let built = Self::build_ruleset(read_grants, write_grants).map_err(|err| err.to_string());
        #[cfg(test)]
        let built = if self.force_ruleset_failure {
            Err("forced by test".to_string())
        } else {
            built
        };
        let mut ruleset = match built {
            Ok(ruleset) => Some(ruleset),
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
                    return command;
                }
                // Optional enforcement: run without Landlock, but still
                // under the seccomp filters below — they don't depend on
                // the ruleset and lose nothing by being applied alone.
                tracing::warn!(
                    error = %err,
                    "failed to build Landlock ruleset; running without filesystem confinement \
                     (sandbox.require_enforcement is false), seccomp filters still apply"
                );
                None
            }
        };
        // Cloned here, in the parent, and only *borrowed* in the child:
        // the closure owns it, so it is freed by the parent when the
        // `Command` is dropped, never by the forked child (freeing after
        // fork is as unsafe as allocating). `RulesetCreated` owns no heap
        // memory, so moving it into `restrict_self` in the child is fine.
        let seccomp_programs = self.seccomp_programs.clone();

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
                    //
                    // This is a real, accepted weakening: every right or
                    // scope the kernel doesn't know is simply not
                    // enforced. On ABI < 3 `truncate()` outside the grants
                    // is unrestricted; < 4 has no network rules (unused
                    // here anyway); < 5 leaves device ioctls open; < 6
                    // drops the signal and abstract-socket scopes. The
                    // seccomp layer does not depend on the ABI.
                    if require_enforcement && status.ruleset == RulesetStatus::NotEnforced {
                        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                    }
                }
                for program in &seccomp_programs {
                    seccompiler::apply_filter(program)
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

    fn find_basename_glob_matches(root: &Path, deny_paths: &[PathBuf]) -> Vec<PathBuf> {
        let bare: Vec<&PathBuf> = deny_paths
            .iter()
            .filter(|p| crate::is_bare_pattern(p))
            .collect();
        let mut matches = Vec::new();
        if let Some(patterns) = compile_bare_patterns(&bare) {
            walk_for_basename_matches(
                root,
                SCAN_CACHE_SETTLE_SECS,
                &patterns,
                &mut ScanCache::new(),
                &mut ScanCache::new(),
                &mut matches,
            );
        }
        matches
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
                "dgram_sendto" => {
                    let mut fds = [0; 2];
                    let ret = libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                        0,
                        fds.as_mut_ptr(),
                    );
                    if ret < 0 {
                        return (ret as i64, last_errno());
                    }
                    let mut addr: libc::sockaddr_un = std::mem::zeroed();
                    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
                    for (i, b) in arg.as_bytes().iter().enumerate() {
                        addr.sun_path[i] = *b as libc::c_char;
                    }
                    let len = std::mem::size_of::<libc::sa_family_t>() + arg.len();
                    let msg = b"from-sandbox";
                    let ret = libc::sendto(
                        fds[0],
                        msg.as_ptr().cast(),
                        msg.len(),
                        0,
                        &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                        len as libc::socklen_t,
                    );
                    (ret as i64, last_errno())
                }
                "socketpair" => {
                    let mut fds = [0; 2];
                    let ret =
                        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr());
                    (ret as i64, last_errno())
                }
                "setpgid_child" | "setsid_child" => {
                    // In a forked child, which is not a group leader, so
                    // only seccomp can make these fail.
                    let pid = libc::fork();
                    if pid == 0 {
                        let ret = if action == "setsid_child" {
                            libc::setsid()
                        } else {
                            libc::setpgid(0, 0)
                        };
                        libc::_exit(if ret < 0 { last_errno() } else { 0 });
                    }
                    let mut status = 0;
                    libc::waitpid(pid, &mut status, 0);
                    let code = libc::WEXITSTATUS(status);
                    (if code == 0 { 0 } else { -1 }, code)
                }
                "kill" => {
                    let pid: libc::pid_t = arg.parse().unwrap();
                    let ret = libc::kill(pid, libc::SIGTERM);
                    (ret as i64, last_errno())
                }
                "clone_newuser" => {
                    let flags = (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong;
                    let ret = libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize);
                    if ret == 0 {
                        libc::_exit(0);
                    }
                    let errno = last_errno();
                    if ret > 0 {
                        libc::waitpid(ret as libc::pid_t, std::ptr::null_mut(), 0);
                    }
                    (ret, errno)
                }
                "clone3" => {
                    // Deliberately invalid args: an unfiltered kernel says
                    // EINVAL, the filter says ENOSYS before the kernel looks.
                    let ret = libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0usize);
                    (ret, last_errno())
                }
                "fsopen" => {
                    let ret = libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), 0u32);
                    (ret, last_errno())
                }
                "open_tree" => {
                    let ret =
                        libc::syscall(libc::SYS_open_tree, libc::AT_FDCWD, c"/".as_ptr(), 0u32);
                    (ret, last_errno())
                }
                #[cfg(target_arch = "x86_64")]
                "x32_getpid" => {
                    let ret = libc::syscall(X32_SYSCALL_BIT as libc::c_long | libc::SYS_getpid);
                    (ret, last_errno())
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
    async fn an_unconnected_datagram_socketpair_cannot_reach_an_outside_socket() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        let socket_path = outside.path().join("log.sock");
        let listener = std::os::unix::net::UnixDatagram::bind(&socket_path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &helper_read_paths(), &[], true);

        let (ret, errno) =
            run_helper(&confiner, "dgram_sendto", socket_path.to_str().unwrap()).await;

        let mut buf = [0u8; 64];
        assert!(
            listener.recv(&mut buf).is_err(),
            "datagram reached the outside socket"
        );
        assert!(ret < 0);
        assert_eq!(errno, libc::EPERM);
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

    // --- Grants are bound to inodes, not re-resolved paths (review C2) --

    #[tokio::test]
    async fn swapping_a_granted_entry_for_a_symlink_after_grant_computation_grants_nothing() {
        let dir = fixture_dir();
        let outside = fixture_dir();
        std::fs::write(outside.path().join("secret.txt"), "top secret").unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir(dir.path().join("docs")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        // Grants are computed while `docs` is a real directory; a racer
        // then swaps it for a symlink before the ruleset is built.
        let (read_grants, write_grants) = confiner.compute_grants();
        std::fs::rename(dir.path().join("docs"), dir.path().join("docs_real")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("docs")).unwrap();

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join("docs/secret.txt"));
        let command = confiner.confine_with_grants(command, &read_grants, &write_grants);
        let (success, output) = run(command).await;

        assert!(!success, "read through the swapped-in symlink must fail");
        assert!(!output.contains("top secret"));
    }

    // --- Directory operations in a carved-out directory (audit I1) ------

    #[tokio::test]
    async fn a_carved_out_root_stays_listable_and_extendable() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]").unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let mut command = tokio::process::Command::new("sh");
        command
            .current_dir(dir.path())
            .args(["-c", "ls . && touch newfile && mkdir newdir"]);
        let (success, output) = run(confiner.confine(command)).await;
        assert!(success, "directory operations in the root failed: {output}");
        assert!(dir.path().join("newfile").exists());
        assert!(dir.path().join("newdir").is_dir());

        // Removing or renaming entries directly in a carved-out directory
        // is refused (see `carved_out_dir_write_access`).
        let mut command = tokio::process::Command::new("sh");
        command
            .current_dir(dir.path())
            .args(["-c", "rm Cargo.toml; mv src src2; true"]);
        run(confiner.confine(command)).await;
        assert!(dir.path().join("Cargo.toml").exists());
        assert!(dir.path().join("src").is_dir());

        // A later spawn re-computes the grants, so the file `touch`ed above
        // is now writable like any other non-denied entry.
        let mut command = tokio::process::Command::new("sh");
        command
            .current_dir(dir.path())
            .args(["-c", "echo content > newfile"]);
        let (success, output) = run(confiner.confine(command)).await;
        assert!(
            success,
            "writing the new file in a later spawn failed: {output}"
        );

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join(".env"));
        let (success, output) = run(confiner.confine(command)).await;
        assert!(!success, "the denied file must stay unreadable");
        assert!(!output.contains("SECRET"));
    }

    /// Runs `script` in `dir` under `confiner` in one spawn, then `cat`s
    /// each of `reads` in a *later* spawn (fresh grants) and returns the
    /// combined output of the reads.
    async fn act_then_read(
        confiner: &LandlockConfiner,
        dir: &Path,
        script: &str,
        reads: &[&str],
    ) -> String {
        let mut command = tokio::process::Command::new("sh");
        command.current_dir(dir).args(["-c", script]);
        run(confiner.confine(command)).await;
        let mut out = String::new();
        for read in reads {
            let mut command = tokio::process::Command::new("cat");
            command.current_dir(dir).arg(read);
            out.push_str(&run(confiner.confine(command)).await.1);
        }
        out
    }

    #[tokio::test]
    async fn renaming_a_denied_file_in_place_does_not_expose_it_to_a_later_spawn() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let out = act_then_read(&confiner, dir.path(), "mv .env x", &["x", ".env"]).await;

        assert!(!out.contains("SECRET"), "renamed denied file leaked: {out}");
    }

    #[tokio::test]
    async fn linking_then_removing_a_denied_file_does_not_expose_it() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let out = act_then_read(&confiner, dir.path(), "ln .env y; rm .env", &["y"]).await;

        assert!(!out.contains("SECRET"), "linked denied file leaked: {out}");
    }

    #[tokio::test]
    async fn renaming_a_denied_directory_does_not_expose_its_contents() {
        let dir = fixture_dir();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::write(secrets.join("key"), "KEY=2").unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], std::slice::from_ref(&secrets), true);

        let out = act_then_read(&confiner, dir.path(), "mv secrets s2", &["s2/key"]).await;

        assert!(
            !out.contains("KEY=2"),
            "renamed denied directory leaked: {out}"
        );
    }

    #[tokio::test]
    async fn a_denied_file_cannot_be_moved_into_a_granted_subdirectory() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        let mut command = tokio::process::Command::new("sh");
        command
            .current_dir(dir.path())
            .args(["-c", "mv .env src/x || ln .env src/y; cat src/x src/y"]);
        let (_, output) = run(confiner.confine(command)).await;
        assert!(
            !output.contains("SECRET"),
            "denied content leaked: {output}"
        );
    }

    // --- Deny matches appearing after construction (audit I2) ----------

    #[tokio::test]
    async fn a_bare_pattern_match_created_after_construction_is_still_denied() {
        let dir = fixture_dir();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);
        std::fs::write(dir.path().join("sub/.env"), "LATE=1").unwrap();

        let mut command = tokio::process::Command::new("cat");
        command.arg(dir.path().join("sub/.env"));
        let (success, output) = run(confiner.confine(command)).await;
        assert!(!success, "late .env must not be readable: {output}");
        assert!(!output.contains("LATE"));
    }

    async fn cat_succeeds(confiner: &LandlockConfiner, path: &Path) -> bool {
        let mut command = tokio::process::Command::new("cat");
        command.arg(path);
        run(confiner.confine(command)).await.0
    }

    #[tokio::test]
    async fn the_scan_cache_keeps_denying_and_notices_new_matches() {
        let dir = fixture_dir();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        let mut confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);
        confiner.scan_settle_secs = 0;

        // First spawn populates the cache.
        assert!(!cat_succeeds(&confiner, &dir.path().join(".env")).await);
        // Second spawn is served from the cache and must still deny.
        assert!(!cat_succeeds(&confiner, &dir.path().join(".env")).await);
        // A new match bumps `sub`'s mtime and ctime, invalidating its
        // cache entry (after a pause, so the coarse clock has moved on).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::fs::write(sub.join(".env"), "LATE=1").unwrap();
        assert!(!cat_succeeds(&confiner, &sub.join(".env")).await);
    }

    #[tokio::test]
    async fn the_scan_cache_is_not_fooled_by_a_restored_mtime() {
        let dir = fixture_dir();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let old_mtime = std::fs::metadata(&sub).unwrap().modified().unwrap();
        let mut confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);
        confiner.scan_settle_secs = 0;

        // Populate the cache, then add a match and put `sub`'s mtime back,
        // as `tar`, `rsync -a` or `cp -a` would.
        assert!(!cat_succeeds(&confiner, &sub.join("missing")).await);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        std::fs::write(sub.join(".env"), "LATE=1").unwrap();
        std::fs::File::open(&sub)
            .unwrap()
            .set_modified(old_mtime)
            .unwrap();

        assert!(!cat_succeeds(&confiner, &sub.join(".env")).await);
    }

    // --- Hardlinks to denied files (audit I3) ---------------------------

    #[tokio::test]
    async fn a_hardlink_to_a_denied_file_is_denied_too() {
        let dir = fixture_dir();
        std::fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::hard_link(dir.path().join(".env"), dir.path().join("notsecret")).unwrap();
        std::fs::hard_link(dir.path().join(".env"), dir.path().join("sub/alias")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[PathBuf::from(".env")], true);

        assert!(!cat_succeeds(&confiner, &dir.path().join("notsecret")).await);
        assert!(!cat_succeeds(&confiner, &dir.path().join("sub/alias")).await);
    }

    #[tokio::test]
    async fn a_hardlink_to_an_absolute_denied_file_is_denied_too() {
        let dir = fixture_dir();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, "SECRET=1").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::hard_link(&secret, dir.path().join("sub/alias")).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], std::slice::from_ref(&secret), true);

        assert!(!cat_succeeds(&confiner, &dir.path().join("sub/alias")).await);
    }

    // --- Credential stores inside the home grants (audit I6) -----------

    #[tokio::test]
    async fn credential_stores_inside_home_grants_are_never_readable() {
        let home = fixture_dir();
        let cargo = home.path().join(".cargo");
        let git = home.path().join(".config/git");
        std::fs::create_dir_all(cargo.join("bin")).unwrap();
        std::fs::create_dir_all(&git).unwrap();
        std::fs::write(cargo.join("credentials.toml"), "token = \"cio-secret\"").unwrap();
        std::fs::write(cargo.join("credentials"), "token = \"cio-legacy\"").unwrap();
        std::fs::write(git.join("credentials"), "https://u:ghp-secret@github.com").unwrap();
        std::fs::write(cargo.join("bin/tool"), "fine").unwrap();
        std::fs::write(git.join("config"), "[user]").unwrap();
        let dir = fixture_dir();
        let mut confiner = confiner_for(dir.path());
        confiner.home = Some(home.path().to_path_buf());

        for secret in [
            cargo.join("credentials.toml"),
            cargo.join("credentials"),
            git.join("credentials"),
        ] {
            assert!(
                !cat_succeeds(&confiner, &secret).await,
                "{} must not be readable",
                secret.display()
            );
        }
        assert!(cat_succeeds(&confiner, &cargo.join("bin/tool")).await);
        assert!(cat_succeeds(&confiner, &git.join("config")).await);
    }

    // --- Private temp directory (audit I7) ------------------------------

    fn unique_system_tmp_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aivyx-confine-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[tokio::test]
    async fn confined_commands_get_a_private_writable_tmpdir() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let mut command = tokio::process::Command::new("sh");
        command.args([
            "-c",
            "echo x > \"$TMPDIR/f\" && cat \"$TMPDIR/f\" && echo \"$TMPDIR\"",
        ]);

        let (success, output) = run(confiner.confine(command)).await;

        assert!(success, "private TMPDIR not writable: {output}");
        let tmpdir = PathBuf::from(output.lines().last().unwrap());
        assert_ne!(tmpdir, std::env::temp_dir());
        assert!(tmpdir.starts_with(std::env::temp_dir()));
        drop(confiner);
        assert!(
            !tmpdir.exists(),
            "private TMPDIR must be removed with the confiner"
        );
    }

    #[tokio::test]
    async fn the_shared_system_tmp_is_not_writable_by_default() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let target = unique_system_tmp_path();
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", &format!("echo x > {}", target.display())]);

        let (success, _) = run(confiner.confine(command)).await;
        let existed = target.exists();
        std::fs::remove_file(&target).ok();

        assert!(!success && !existed, "shared /tmp must not be writable");
    }

    #[tokio::test]
    async fn share_system_tmp_opts_back_into_the_shared_tmp() {
        let dir = fixture_dir();
        let options = crate::ConfineOptions::new()
            .require_enforcement(true)
            .share_system_tmp(true);
        let confiner = LandlockConfiner::with_options(dir.path(), &[], &[], options);
        let target = unique_system_tmp_path();
        let mut command = tokio::process::Command::new("sh");
        command.args(["-c", &format!("echo x > {}", target.display())]);

        let (success, output) = run(confiner.confine(command)).await;
        let existed = target.exists();
        std::fs::remove_file(&target).ok();

        assert!(
            success && existed,
            "opted-in shared tmp write failed: {output}"
        );
    }

    // --- Process-group containment (audit I8) ---------------------------

    #[tokio::test]
    async fn a_confined_command_leads_its_own_process_group() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let mut command = tokio::process::Command::new("sleep");
        command.arg("5").kill_on_drop(true);
        let child = confiner.confine(command).spawn().unwrap();
        let pid = child.id().unwrap() as libc::pid_t;

        // SAFETY: plain query syscall.
        let pgid = unsafe { libc::getpgid(pid) };

        assert_eq!(pgid, pid);
    }

    #[tokio::test]
    async fn leaving_the_process_group_is_blocked_by_default() {
        for action in ["setpgid_child", "setsid_child"] {
            let (ret, errno) = helper_on_default_confiner(action).await;
            assert!(ret < 0, "{action} must fail");
            assert_eq!(errno, libc::EPERM, "{action}");
        }
    }

    #[tokio::test]
    async fn allow_leaving_process_group_opts_out_of_the_block() {
        let dir = fixture_dir();
        let options = crate::ConfineOptions::new()
            .require_enforcement(true)
            .allow_leaving_process_group(true);
        let confiner =
            LandlockConfiner::with_options(dir.path(), &helper_read_paths(), &[], options);
        for action in ["setpgid_child", "setsid_child"] {
            let (ret, errno) = run_helper(&confiner, action, "").await;
            assert_eq!(ret, 0, "{action} failed with errno {errno}");
        }
    }

    #[tokio::test]
    async fn a_setsid_background_job_cannot_outlive_kill_process_group() {
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let late = dir.path().join("late.txt");
        let mut command = tokio::process::Command::new("sh");
        command.current_dir(dir.path()).args([
            "-c",
            "setsid sh -c 'sleep 1; echo late > late.txt' 2>/dev/null & echo started",
        ]);
        let child = confiner
            .confine(command)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pgid = child.id().unwrap();
        child.wait_with_output().await.unwrap();

        crate::kill_process_group(pgid).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1800)).await;

        assert!(
            !late.exists(),
            "a setsid'd job escaped the group and wrote late.txt"
        );
    }

    #[test]
    fn kill_process_group_rejects_the_callers_own_group() {
        assert_eq!(
            crate::kill_process_group(0).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn kill_process_group_reaches_background_descendants() {
        use tokio::io::AsyncBufReadExt;
        let dir = fixture_dir();
        let confiner = confiner_for(dir.path());
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        let mut child = confiner.confine(command).spawn().unwrap();
        let pgid = child.id().unwrap();
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let background: libc::pid_t = lines.next_line().await.unwrap().unwrap().parse().unwrap();

        crate::kill_process_group(pgid).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .expect("the group leader survived kill_process_group")
            .unwrap();

        let mut gone = false;
        for _ in 0..200 {
            // SAFETY: signal 0 only probes for existence.
            if unsafe { libc::kill(background, 0) } != 0 {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(gone, "background sleep survived kill_process_group");
    }

    // --- Deny-path normalisation (audit M3) -----------------------------

    #[tokio::test]
    async fn a_relative_multi_component_deny_entry_is_resolved_against_cwd() {
        let dir = fixture_dir();
        std::fs::create_dir(dir.path().join("config")).unwrap();
        std::fs::write(dir.path().join("config/secrets.json"), "{}").unwrap();
        let confiner = LandlockConfiner::new(
            dir.path(),
            &[],
            &[PathBuf::from("config/secrets.json")],
            true,
        );

        assert!(!cat_succeeds(&confiner, &dir.path().join("config/secrets.json")).await);
    }

    #[tokio::test]
    async fn a_symlinked_cwd_still_honours_a_canonical_deny_entry() {
        let dir = fixture_dir();
        let links = fixture_dir();
        let secret = dir.path().join("secret.txt");
        std::fs::write(&secret, "SECRET").unwrap();
        let link = links.path().join("project");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        let confiner = LandlockConfiner::new(&link, &[], std::slice::from_ref(&secret), true);

        assert!(!cat_succeeds(&confiner, &secret).await);
        assert!(!cat_succeeds(&confiner, &link.join("secret.txt")).await);
    }

    #[tokio::test]
    async fn a_deny_entry_given_through_a_symlink_is_honoured() {
        let dir = fixture_dir();
        let links = fixture_dir();
        std::fs::write(dir.path().join("secret.txt"), "SECRET").unwrap();
        let link = links.path().join("project");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        let confiner = LandlockConfiner::new(dir.path(), &[], &[link.join("secret.txt")], true);

        assert!(!cat_succeeds(&confiner, &dir.path().join("secret.txt")).await);
    }

    // --- Seccomp without Landlock (audit M2) ----------------------------

    #[tokio::test]
    async fn seccomp_still_applies_when_landlock_cannot_be_built_and_is_optional() {
        let dir = fixture_dir();
        let mut confiner = LandlockConfiner::new(dir.path(), &helper_read_paths(), &[], false);
        confiner.force_ruleset_failure = true;

        let (ret, errno) = run_helper(&confiner, "unix_socket", "").await;

        assert!(ret < 0, "seccomp must still block AF_UNIX");
        assert_eq!(errno, libc::EPERM);
    }

    #[tokio::test]
    async fn a_ruleset_failure_refuses_to_spawn_when_enforcement_is_required() {
        let dir = fixture_dir();
        let mut confiner = confiner_for(dir.path());
        confiner.force_ruleset_failure = true;

        let result = confiner
            .confine(tokio::process::Command::new("true"))
            .status()
            .await;

        assert!(result.is_err(), "spawn must fail closed");
    }

    // --- Signal and abstract-socket scoping (audit I5) -------------------

    /// Landlock scopes need ABI 6 (Linux 6.12); on older kernels they are
    /// skipped best-effort, so these tests only assert where they can hold.
    fn kernel_supports_landlock_scopes() -> bool {
        detect_landlock_abi() >= 6
    }

    #[tokio::test]
    async fn signalling_a_process_outside_the_sandbox_is_blocked() {
        if !kernel_supports_landlock_scopes() {
            eprintln!("skipped: Landlock ABI < 6");
            return;
        }
        let mut victim = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let dir = fixture_dir();
        let confiner = LandlockConfiner::new(dir.path(), &helper_read_paths(), &[], true);

        let (ret, errno) = run_helper(&confiner, "kill", &victim.id().to_string()).await;
        let still_running = victim.try_wait().unwrap().is_none();
        victim.kill().ok();
        victim.wait().ok();

        assert!(ret < 0, "kill of an outside process must fail");
        assert_eq!(errno, libc::EPERM);
        assert!(still_running);
    }

    #[tokio::test]
    async fn connecting_to_an_outside_abstract_socket_is_blocked_even_when_opted_out() {
        use std::os::linux::net::SocketAddrExt;
        if !kernel_supports_landlock_scopes() {
            eprintln!("skipped: Landlock ABI < 6");
            return;
        }
        let name = format!(
            "aivyx-confine-test-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        );
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind_addr(&addr).unwrap();
        let dir = fixture_dir();
        let options = crate::ConfineOptions::new()
            .require_enforcement(true)
            .allow_unix_sockets(true);
        let confiner =
            LandlockConfiner::with_options(dir.path(), &helper_read_paths(), &[], options);

        let (ret, errno) = run_helper(&confiner, "unix_connect", &format!("@{name}")).await;

        assert!(ret < 0, "connect to an outside abstract socket must fail");
        assert_eq!(errno, libc::EPERM);
    }

    // --- Namespace creation and the new mount API (audit I4, M6) --------

    async fn helper_on_default_confiner(action: &str) -> (i64, i32) {
        let dir = fixture_dir();
        let confiner = LandlockConfiner::new(dir.path(), &helper_read_paths(), &[], true);
        run_helper(&confiner, action, "").await
    }

    #[tokio::test]
    async fn clone_with_a_new_user_namespace_is_blocked() {
        let (ret, errno) = helper_on_default_confiner("clone_newuser").await;
        assert!(ret < 0, "clone(CLONE_NEWUSER) must fail");
        assert_eq!(errno, libc::EPERM);
    }

    #[tokio::test]
    async fn clone3_reports_enosys_so_libc_falls_back_to_clone() {
        let (ret, errno) = helper_on_default_confiner("clone3").await;
        assert!(ret < 0);
        assert_eq!(errno, libc::ENOSYS);
    }

    #[tokio::test]
    async fn the_new_mount_api_is_blocked() {
        for action in ["fsopen", "open_tree"] {
            let (ret, errno) = helper_on_default_confiner(action).await;
            assert!(ret < 0, "{action} must fail");
            assert_eq!(errno, libc::EPERM, "{action}");
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[tokio::test]
    async fn x32_syscall_numbers_are_rejected() {
        // Without the filter this kernel answers ENOSYS (no x32 support)
        // or runs getpid (x32 support) — either way, not EPERM.
        let (ret, errno) = helper_on_default_confiner("x32_getpid").await;
        assert!(ret < 0);
        assert_eq!(errno, libc::EPERM);
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
        let mut grants = Grants::default();
        grant_paths_excluding(dir.path(), &[], &mut grants);
        assert_eq!(grants.full_paths(), vec![dir.path().to_path_buf()]);
        assert!(grants.dir_only.is_empty());
    }

    #[test]
    fn grant_paths_excluding_returns_empty_when_root_itself_is_denied() {
        let dir = fixture_dir();
        let mut grants = Grants::default();
        grant_paths_excluding(dir.path(), &[dir.path().to_path_buf()], &mut grants);
        assert!(grants.full.is_empty() && grants.dir_only.is_empty());
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
