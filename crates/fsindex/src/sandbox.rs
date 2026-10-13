//! Self-confinement of the helper before it reads any guest byte: no new
//! privileges, rlimits (memory, CPU time, no files, no processes, no core),
//! every file descriptor above stderr closed, then a seccomp allowlist of the
//! few system calls a pipe-driven parser needs (no open, no socket, no exec).
//! The SELinux domain `nexus_fsindex_t` (os/selinux/nexus.te) confines it as
//! well, independently of this.

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;
use std::io;

const ALLOWED: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_writev,
    libc::SYS_close,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_mprotect,
    libc::SYS_futex,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigaction,
    libc::SYS_sigaltstack,
    libc::SYS_clock_gettime,
    libc::SYS_getrandom,
    libc::SYS_sched_yield,
    libc::SYS_getpid,
    libc::SYS_gettid,
    libc::SYS_tgkill,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_lseek,
    libc::SYS_sched_getaffinity,
];

fn rlimit(res: libc::__rlimit_resource_t, v: u64) -> io::Result<()> {
    let l = libc::rlimit {
        rlim_cur: v,
        rlim_max: v,
    };
    // SAFETY: plain system call with a valid pointer
    if unsafe { libc::setrlimit(res, &l) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The compiled allowlist (everything else fails with EPERM).
pub fn program() -> io::Result<BpfProgram> {
    let e = |e: seccompiler::BackendError| io::Error::other(format!("seccomp: {e}"));
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|e| io::Error::other(format!("seccomp: {e}")))?;
    let rules: BTreeMap<i64, Vec<SeccompRule>> = ALLOWED.iter().map(|s| (*s, Vec::new())).collect();
    SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(e)?
    .try_into()
    .map_err(e)
}

/// Confines the current process. `mem_mb`: address space; `cpu_secs`: CPU time.
pub fn confine(mem_mb: u64, cpu_secs: u64) -> io::Result<()> {
    let prog = program()?;
    // SAFETY: plain system calls
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(io::Error::last_os_error());
        }
        libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32);
    }
    rlimit(libc::RLIMIT_AS, mem_mb.max(64) << 20)?;
    rlimit(libc::RLIMIT_CPU, cpu_secs.max(10))?;
    rlimit(libc::RLIMIT_FSIZE, 0)?;
    rlimit(libc::RLIMIT_NOFILE, 4)?;
    rlimit(libc::RLIMIT_NPROC, 0)?;
    rlimit(libc::RLIMIT_CORE, 0)?;
    seccompiler::apply_filter(&prog).map_err(|e| io::Error::other(format!("seccomp: {e}")))
}
