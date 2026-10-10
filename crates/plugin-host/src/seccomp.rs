//! Seccomp allowlist for plugin processes (docs/plugin-system.md "Sandbox"):
//! roughly systemd's `@system-service` minus `@privileged @mount @module @raw-io`
//! (and minus `@clock @reboot @swap @debug @cpu-emulation @obsolete`, io_uring and
//! the set*id family). Everything else fails with EPERM.
//!
//! Argument filters: `socket()` only for AF_INET / AF_INET6 and AF_NETLINK
//! (NETLINK_ROUTE, glibc's getaddrinfo) — no AF_UNIX sockets that could reach the
//! appliance's daemons (keyd!); `clone()` without namespace flags; `clone3` returns
//! ENOSYS (its flags live in memory a filter cannot read) so libc falls back to clone.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;

const COMMON: &[i64] = &[
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwrite64,
    libc::SYS_preadv,
    libc::SYS_pwritev,
    libc::SYS_preadv2,
    libc::SYS_pwritev2,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_close,
    libc::SYS_close_range,
    libc::SYS_lseek,
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_statfs,
    libc::SYS_fstatfs,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_readlinkat,
    libc::SYS_getdents64,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_mkdirat,
    libc::SYS_mknodat,
    libc::SYS_unlinkat,
    libc::SYS_renameat2,
    libc::SYS_linkat,
    libc::SYS_symlinkat,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_fchown,
    libc::SYS_fchownat,
    libc::SYS_utimensat,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    libc::SYS_fallocate,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_sync_file_range,
    libc::SYS_flock,
    libc::SYS_fcntl,
    libc::SYS_ioctl,
    libc::SYS_dup,
    libc::SYS_dup3,
    libc::SYS_pipe2,
    libc::SYS_umask,
    libc::SYS_fadvise64,
    libc::SYS_copy_file_range,
    libc::SYS_sendfile,
    libc::SYS_splice,
    libc::SYS_tee,
    libc::SYS_getxattr,
    libc::SYS_lgetxattr,
    libc::SYS_fgetxattr,
    libc::SYS_listxattr,
    libc::SYS_llistxattr,
    libc::SYS_flistxattr,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_fsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_fremovexattr,
    libc::SYS_inotify_init1,
    libc::SYS_inotify_add_watch,
    libc::SYS_inotify_rm_watch,
    libc::SYS_memfd_create,
    // memory
    libc::SYS_brk,
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_msync,
    libc::SYS_mincore,
    libc::SYS_mlock,
    libc::SYS_mlock2,
    libc::SYS_munlock,
    libc::SYS_membarrier,
    // process / threads
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_gettid,
    libc::SYS_getuid,
    libc::SYS_geteuid,
    libc::SYS_getgid,
    libc::SYS_getegid,
    libc::SYS_getresuid,
    libc::SYS_getresgid,
    libc::SYS_getgroups,
    libc::SYS_getpgid,
    libc::SYS_setpgid,
    libc::SYS_getsid,
    libc::SYS_setsid,
    libc::SYS_capget,
    libc::SYS_prctl,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_rseq,
    libc::SYS_futex,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_getparam,
    libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max,
    libc::SYS_sched_get_priority_min,
    libc::SYS_getpriority,
    libc::SYS_getrlimit,
    libc::SYS_setrlimit,
    libc::SYS_prlimit64,
    libc::SYS_getrusage,
    libc::SYS_sysinfo,
    libc::SYS_times,
    libc::SYS_uname,
    libc::SYS_getrandom,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_send_signal,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigsuspend,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigqueueinfo,
    libc::SYS_sigaltstack,
    libc::SYS_restart_syscall,
    // time
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_getitimer,
    libc::SYS_setitimer,
    libc::SYS_timer_create,
    libc::SYS_timer_settime,
    libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun,
    libc::SYS_timer_delete,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    // events
    libc::SYS_ppoll,
    libc::SYS_pselect6,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    libc::SYS_epoll_pwait2,
    libc::SYS_eventfd2,
    libc::SYS_signalfd4,
    // network (socket() itself is argument-filtered below)
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_sendmmsg,
    libc::SYS_recvmmsg,
    libc::SYS_shutdown,
    // clone3: listed so the second filter decides (ENOSYS)
    libc::SYS_clone3,
];

#[cfg(target_arch = "x86_64")]
const ARCH: &[i64] = &[
    libc::SYS_open,
    libc::SYS_creat,
    libc::SYS_stat,
    libc::SYS_lstat,
    libc::SYS_access,
    libc::SYS_readlink,
    libc::SYS_getdents,
    libc::SYS_mkdir,
    libc::SYS_rmdir,
    libc::SYS_unlink,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_link,
    libc::SYS_symlink,
    libc::SYS_chmod,
    libc::SYS_chown,
    libc::SYS_lchown,
    libc::SYS_mknod,
    libc::SYS_utime,
    libc::SYS_utimes,
    libc::SYS_futimesat,
    libc::SYS_pipe,
    libc::SYS_dup2,
    libc::SYS_poll,
    libc::SYS_select,
    libc::SYS_epoll_create,
    libc::SYS_epoll_wait,
    libc::SYS_eventfd,
    libc::SYS_signalfd,
    libc::SYS_inotify_init,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_alarm,
    libc::SYS_pause,
    libc::SYS_time,
    libc::SYS_getpgrp,
    libc::SYS_arch_prctl,
];

#[cfg(target_arch = "aarch64")]
const ARCH: &[i64] = &[libc::SYS_renameat];

/// Namespace flags `clone()` must not carry.
const CLONE_NS: u64 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWCGROUP) as u64;

fn arch() -> Result<TargetArch, String> {
    TargetArch::try_from(std::env::consts::ARCH).map_err(|e| format!("seccomp: {e}"))
}

/// The two filters (allowlist, clone3 → ENOSYS), compiled in the host before `fork`.
pub fn programs() -> Result<Vec<BpfProgram>, String> {
    let arch = arch()?;
    let e = |e: seccompiler::BackendError| format!("seccomp: {e}");
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for s in COMMON.iter().chain(ARCH) {
        rules.insert(*s, Vec::new());
    }
    let eq = |arg: u8, v: u64| Cond::new(arg, Len::Dword, Op::Eq, v).map_err(e);
    rules.insert(
        libc::SYS_socket,
        vec![
            SeccompRule::new(vec![eq(0, libc::AF_INET as u64)?]).map_err(e)?,
            SeccompRule::new(vec![eq(0, libc::AF_INET6 as u64)?]).map_err(e)?,
            SeccompRule::new(vec![
                eq(0, libc::AF_NETLINK as u64)?,
                eq(2, libc::NETLINK_ROUTE as u64)?,
            ])
            .map_err(e)?,
        ],
    );
    // x86_64 clone(flags, …), aarch64 clone(flags, …): flags are argument 0 on both
    rules.insert(
        libc::SYS_clone,
        vec![SeccompRule::new(vec![Cond::new(0, Len::Qword, Op::MaskedEq(CLONE_NS), 0).map_err(e)?]).map_err(e)?],
    );
    let allow: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(e)?
    .try_into()
    .map_err(e)?;
    let mut c3 = BTreeMap::new();
    c3.insert(libc::SYS_clone3, Vec::new());
    let clone3: BpfProgram = SeccompFilter::new(
        c3,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(e)?
    .try_into()
    .map_err(e)?;
    // clone3 filter first: once the allowlist is in place, seccomp() itself is refused
    Ok(vec![clone3, allow])
}

/// In the child (after NO_NEW_PRIVS): installs the compiled filters. Only system calls.
pub fn apply(progs: &[BpfProgram]) -> std::io::Result<()> {
    for p in progs {
        seccompiler::apply_filter(p).map_err(|_| std::io::Error::from_raw_os_error(libc::EPERM))?;
    }
    Ok(())
}
