//! File descriptor passing over a Unix stream socket (`SCM_RIGHTS`): the
//! helper sends `ok\n` together with the mount fd; the connector receives it.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Sends `data` (non-empty) with `fd` attached.
pub fn send_fd(sock: &impl AsRawFd, data: &[u8], fd: RawFd) -> io::Result<()> {
    assert!(!data.is_empty());
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr, then pointers to live buffers of the given sizes.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer holds exactly one cmsg with one fd.
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd);
    }
    // SAFETY: msg points to valid buffers for the duration of the call.
    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != data.len() {
        return Err(io::Error::other("short sendmsg"));
    }
    Ok(())
}

/// Receives up to `max` bytes and at most one fd (others are closed). Returns
/// (bytes, fd). The fd is close-on-exec (`MSG_CMSG_CLOEXEC`).
pub fn recv_fd(sock: &impl AsRawFd, max: usize) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
    let mut buf = vec![0u8; max];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // room for a few fds: a hostile sender's extra fds are closed below
    // SAFETY: pure size computation.
    let space = unsafe { libc::CMSG_SPACE((4 * std::mem::size_of::<RawFd>()) as u32) } as usize;
    let mut cbuf = vec![0u8; space];
    // SAFETY: zeroed msghdr, pointers to live buffers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = space as _;
    let n = loop {
        // SAFETY: as above.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        break n as usize;
    };
    let mut fds: Vec<OwnedFd> = Vec::new();
    // SAFETY: walking the control messages the kernel wrote into cbuf.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let data = libc::CMSG_DATA(c);
                let len = (*c).cmsg_len as usize - (data as usize - c as usize);
                for i in 0..len / std::mem::size_of::<RawFd>() {
                    let fd = std::ptr::read_unaligned(data.cast::<RawFd>().add(i));
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("control data truncated (too many fds)"));
    }
    buf.truncate(n);
    let fd = if fds.len() == 1 { fds.pop() } else { None };
    Ok((buf, fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek};
    use std::os::unix::net::UnixStream;

    #[test]
    fn passes_an_fd() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut f = tempfile::tempfile().unwrap();
        std::io::Write::write_all(&mut f, b"hello").unwrap();
        send_fd(&a, b"ok\n", f.as_raw_fd()).unwrap();
        drop(f);
        let (data, fd) = recv_fd(&b, 64).unwrap();
        assert_eq!(data, b"ok\n");
        let mut f = std::fs::File::from(fd.unwrap());
        f.rewind().unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello");
        // plain data without fd
        std::io::Write::write_all(&mut &a, b"error x\n").unwrap();
        let (data, fd) = recv_fd(&b, 64).unwrap();
        assert_eq!((data.as_slice(), fd.is_none()), (&b"error x\n"[..], true));
    }
}
