//! Mark sockets of an attached process so connections opened before the
//! attach follow the profile's route or filter.
//!
//! A socket's cgroup is fixed when the socket is created. Moving the process
//! into a profile cgroup therefore does not cover sockets it already holds.
//! Setting `SO_MARK` on those sockets changes their route on the next packet
//! (the kernel resets the cached destination when the mark changes) and lets
//! nftables match them through `socket mark`.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use thiserror::Error;

/// Failure to reach or mark the sockets of one process.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SocketMarkError {
    /// The process exited before its file descriptors could be read.
    #[error("process {0} is gone")]
    ProcessGone(u32),
    /// The process file descriptor table could not be read.
    #[error("cannot read file descriptors of process {pid}: {source}")]
    Inspect {
        /// Process that could not be inspected.
        pid: u32,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// The process could not be opened for socket duplication.
    #[error("cannot open process {pid}: {source}")]
    Open {
        /// Process that could not be opened.
        pid: u32,
        /// Underlying error.
        source: io::Error,
    },
    /// A socket could not be duplicated for marking.
    #[error("cannot duplicate fd {fd} of process {pid}: {source}")]
    Duplicate {
        /// File descriptor number in the target process.
        fd: i32,
        /// Process that owns the descriptor.
        pid: u32,
        /// Underlying error.
        source: io::Error,
    },
    /// `SO_MARK` could not be read or written.
    #[error("cannot mark fd {fd} of process {pid}: {source}")]
    Mark {
        /// File descriptor number in the target process.
        fd: i32,
        /// Process that owns the descriptor.
        pid: u32,
        /// Underlying error.
        source: io::Error,
    },
    /// The running kernel has no `pidfd_getfd` support.
    #[error("pidfd_getfd is unavailable on this kernel")]
    Unsupported,
}

/// Marks every IPv4 and IPv6 socket currently held by `pid`.
///
/// [`set_mark_datagram`] restricts marking to datagram (UDP) sockets. [`SO_MARK`] is
/// protocol-agnostic, so a marked TCP socket would take the same fwmark into a
/// UDP-only route — its handshake would be swallowed by the tunnel. A
/// UDP-only profile therefore marks only UDP sockets.
///
/// Returns the number of sockets that now carry `mark`. Sockets that already
/// carry it are counted. Failure to reach one descriptor is reported rather
/// than skipped, because a partial mark would leave the profile silently
/// incomplete.
///
/// [`SO_MARK`]: https://man7.org/linux/man-pages/man7/socket.7.html
///
/// # Errors
///
/// Returns [`SocketMarkError`] when the process is gone, its descriptor table
/// cannot be read, or a socket exists but cannot be marked. A kernel without
/// `pidfd_getfd` returns [`SocketMarkError::Unsupported`].
pub fn set_mark(pid: u32, mark: u32) -> Result<usize, SocketMarkError> {
    mark_scope(pid, mark, Scope::All, &[])
}

/// Marks the datagram (UDP) sockets held by `pid` and leaves every stream
/// socket untouched.
///
/// A UDP-only route carries datagrams only: a marked TCP socket would send its
/// handshake into that route and lose it.
///
/// # Errors
///
/// Returns [`SocketMarkError`] under the same conditions as [`set_mark`].
pub fn set_mark_datagram(pid: u32, mark: u32, pinned: &[u16]) -> Result<usize, SocketMarkError> {
    mark_scope(pid, mark, Scope::Datagram, pinned)
}

/// Which sockets a mark applies to.
#[derive(Clone, Copy)]
enum Scope {
    /// Every IPv4/IPv6 socket, the default for a route that carries all traffic.
    All,
    /// Datagram sockets only, for a route scoped to UDP.
    Datagram,
}

fn mark_scope(pid: u32, mark: u32, scope: Scope, pinned: &[u16]) -> Result<usize, SocketMarkError> {
    let pidfd = open_pidfd(pid)?;
    let mut marked = 0;
    for fd in process_fds(pid)? {
        let Some(socket) = duplicate_socket(pidfd.as_raw_fd(), pid, fd)? else {
            continue;
        };
        if matches!(scope, Scope::Datagram) {
            if socket_type(socket.as_raw_fd()).map_err(|source| SocketMarkError::Mark {
                fd,
                pid,
                source,
            })? != Some(libc::SOCK_DGRAM)
            {
                continue;
            }
            // A pinned source port is a socket that already existed when the
            // route opened. Its mark would route the live flow into the tunnel
            // (the fwmark ip rule reads sk_mark directly), changing the
            // game-visible source under the game's feet.
            let local = socket_local_port(socket.as_raw_fd())
                .map_err(|source| SocketMarkError::Mark { fd, pid, source })?;
            if local.is_some_and(|port| pinned.contains(&port)) {
                continue;
            }
        }
        let current = socket_mark(socket.as_raw_fd()).map_err(|source| SocketMarkError::Mark {
            fd,
            pid,
            source,
        })?;
        if current == Some(mark) {
            marked += 1;
            continue;
        }
        if current.is_none() {
            continue;
        }
        set_socket_mark(socket.as_raw_fd(), mark).map_err(|source| SocketMarkError::Mark {
            fd,
            pid,
            source,
        })?;
        marked += 1;
    }
    Ok(marked)
}

/// Clears `mark` from every socket held by `pid` that still carries it.
///
/// This is used when a profile is removed so a later profile that reuses the
/// same mark cannot inherit sockets from the old one. Sockets carrying a
/// different mark are left alone.
///
/// # Errors
///
/// Returns [`SocketMarkError`] under the same conditions as [`set_mark`].
pub fn clear_mark(pid: u32, mark: u32) -> Result<usize, SocketMarkError> {
    let pidfd = open_pidfd(pid)?;
    let mut cleared = 0;
    for fd in process_fds(pid)? {
        let Some(socket) = duplicate_socket(pidfd.as_raw_fd(), pid, fd)? else {
            continue;
        };
        let current = socket_mark(socket.as_raw_fd()).map_err(|source| SocketMarkError::Mark {
            fd,
            pid,
            source,
        })?;
        if current != Some(mark) {
            continue;
        }
        set_socket_mark(socket.as_raw_fd(), 0).map_err(|source| SocketMarkError::Mark {
            fd,
            pid,
            source,
        })?;
        cleared += 1;
    }
    Ok(cleared)
}

/// Clears `mark` from every process on the system that still carries it.
///
/// Profile ids are reusable, so a mark caught by a process that escaped the
/// profile cgroup must not survive the profile. Scanning `/proc` is
/// expensive; call this only when a profile is removed or disabled.
///
/// # Errors
///
/// Returns [`SocketMarkError::Inspect`] only when `/proc` cannot be read.
/// Processes that vanish or cannot be inspected are skipped.
pub fn clear_mark_all(mark: u32) -> Result<usize, SocketMarkError> {
    let entries =
        fs::read_dir("/proc").map_err(|source| SocketMarkError::Inspect { pid: 0, source })?;
    let mut cleared = 0;
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        match clear_mark(pid, mark) {
            Ok(count) => cleared += count,
            Err(SocketMarkError::ProcessGone(_)) => {}
            Err(err) => {
                tracing::debug!("clear mark {mark:#x} pid={pid} error={err}");
            }
        }
    }
    Ok(cleared)
}

/// Lists the marks currently set on the IPv4 and IPv6 sockets of `pid`.
///
/// Returns `(fd, mark)` pairs. Non-socket descriptors are skipped. This is a
/// read-only diagnostic; [`set_mark`] changes the sockets.
///
/// # Errors
///
/// Returns [`SocketMarkError`] under the same conditions as [`set_mark`].
pub fn marks(pid: u32) -> Result<Vec<(i32, u32)>, SocketMarkError> {
    let pidfd = open_pidfd(pid)?;
    let mut marks = Vec::new();
    for fd in process_fds(pid)? {
        let Some(socket) = duplicate_socket(pidfd.as_raw_fd(), pid, fd)? else {
            continue;
        };
        let current = socket_mark(socket.as_raw_fd()).map_err(|source| SocketMarkError::Mark {
            fd,
            pid,
            source,
        })?;
        if let Some(mark) = current {
            marks.push((fd, mark));
        }
    }
    Ok(marks)
}

fn open_pidfd(pid: u32) -> Result<OwnedFd, SocketMarkError> {
    // SAFETY: pidfd_open takes only scalar arguments and returns a new fd or -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::ESRCH) {
            return Err(SocketMarkError::ProcessGone(pid));
        }
        if source.raw_os_error() == Some(libc::ENOSYS) {
            return Err(SocketMarkError::Unsupported);
        }
        return Err(SocketMarkError::Open { pid, source });
    }
    let raw = i32::try_from(raw).map_err(|_| SocketMarkError::Open {
        pid,
        source: io::Error::other("pidfd does not fit in i32"),
    })?;
    // SAFETY: the successful pidfd_open returned a fresh fd that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn process_fds(pid: u32) -> Result<Vec<i32>, SocketMarkError> {
    let entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(SocketMarkError::ProcessGone(pid));
        }
        Err(source) => return Err(SocketMarkError::Inspect { pid, source }),
    };
    let mut fds = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) => return Err(SocketMarkError::Inspect { pid, source }),
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(fd) = name.parse::<i32>() else {
            continue;
        };
        if fd < 0 {
            continue;
        }
        // Only sockets are ever marked; skipping the rest avoids a
        // pidfd_getfd round trip for every file the process holds.
        let is_socket = fs::read_link(entry.path())
            .is_ok_and(|target| target.to_string_lossy().starts_with("socket:["));
        if is_socket {
            fds.push(fd);
        }
    }
    Ok(fds)
}

fn duplicate_socket(pidfd: RawFd, pid: u32, fd: i32) -> Result<Option<OwnedFd>, SocketMarkError> {
    // SAFETY: pidfd_getfd takes a pidfd, a target fd number, and flags; no user pointers.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) };
    if raw < 0 {
        let source = io::Error::last_os_error();
        return match source.raw_os_error() {
            Some(libc::ESRCH) => Err(SocketMarkError::ProcessGone(pid)),
            Some(libc::ENOSYS) => Err(SocketMarkError::Unsupported),
            Some(libc::EBADF | libc::ENOENT | libc::EINVAL) => Ok(None),
            _ => Err(SocketMarkError::Duplicate { fd, pid, source }),
        };
    }
    let raw = i32::try_from(raw).map_err(|_| SocketMarkError::Duplicate {
        fd,
        pid,
        source: io::Error::other("socket fd does not fit in i32"),
    })?;
    // SAFETY: the successful pidfd_getfd returned a fresh fd that nothing else owns.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(raw) }))
}

/// Returns the socket's `SO_TYPE` (`SOCK_DGRAM`, `SOCK_STREAM`, …), or `None`
/// when the descriptor is not a socket.
fn socket_type(fd: RawFd) -> io::Result<Option<i32>> {
    let mut kind: libc::c_int = 0;
    let mut len = socklen::<libc::c_int>();
    // SAFETY: `fd` is an open descriptor and the kernel writes one c_int into
    // `kind`; `len` is its exact size and is updated by the call.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::addr_of_mut!(kind).cast(),
            &raw mut len,
        )
    };
    if rc == 0 {
        return Ok(Some(kind));
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ENOTSOCK) {
        Ok(None)
    } else {
        Err(err)
    }
}

/// Returns `Some(mark)` for an IPv4/IPv6 socket, `None` for any other fd.
/// The local port a socket is bound to, if it has one. A UDP socket keeps it
/// for its whole life, so it identifies the socket across polls.
fn socket_local_port(fd: RawFd) -> io::Result<Option<u16>> {
    // SAFETY: `storage` is a plain byte buffer sized for any address family and
    // `len` names its size; only the first two bytes of a sockaddr are read,
    // after the kernel reports a length that covers them.
    unsafe {
        let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let rc = libc::getsockname(fd, storage.as_mut_ptr().cast(), &mut len);
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let bytes = storage.assume_init_ref();
        let raw =
            std::slice::from_raw_parts((bytes as *const libc::sockaddr_storage).cast::<u8>(), 4);
        Ok(Some(u16::from_be_bytes([raw[2], raw[3]])))
    }
}

fn socket_mark(fd: RawFd) -> io::Result<Option<u32>> {
    if !is_inet_socket(fd)? {
        return Ok(None);
    }
    let mut mark = 0_u32;
    let mut len = socklen::<u32>();
    // SAFETY: fd is an open socket; mark and len point to writable values of the
    // size the kernel is told through len.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_mut(&mut mark).cast(),
            std::ptr::from_mut(&mut len),
        )
    };
    if result == 0 {
        Ok(Some(mark))
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_inet_socket(fd: RawFd) -> io::Result<bool> {
    let mut domain = 0_i32;
    let mut len = socklen::<i32>();
    // SAFETY: fd came from a successful pidfd_getfd; domain and len are writable
    // and len carries the buffer size.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            std::ptr::from_mut(&mut domain).cast(),
            std::ptr::from_mut(&mut len),
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOTSOCK) {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(domain == libc::AF_INET || domain == libc::AF_INET6)
}

fn set_socket_mark(fd: RawFd, mark: u32) -> io::Result<()> {
    let len = socklen::<u32>();
    // SAFETY: fd is an open socket and mark/len describe a readable u32 buffer.
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::from_ref(&mark).cast(),
            len,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn socklen<T>() -> libc::socklen_t {
    libc::socklen_t::try_from(std::mem::size_of::<T>()).expect("socket option size fits socklen_t")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const MARK: u32 = 0x4e71;

    /// The datagram filter a UDP-only route depends on: a mark on the stream
    /// socket would take its handshake into a tunnel that only carries UDP, and
    /// a mark on a pre-existing datagram socket would reroute a live flow.
    ///
    /// `sudo cargo test -p netscope-linux --lib -- --ignored udp_only_marks_only_datagram_sockets`
    #[test]
    #[ignore = "requires root: CAP_NET_ADMIN for SO_MARK, pidfd_getfd for the child's fds"]
    fn udp_only_marks_only_datagram_sockets() {
        use std::io::{BufRead, BufReader};

        let euid = {
            // SAFETY: geteuid takes no arguments and cannot fail.
            unsafe { libc::geteuid() }
        };
        assert_eq!(
            euid, 0,
            "socket marking needs CAP_NET_ADMIN; run this test as root"
        );

        // One TCP listener and one UDP socket, both held open by the child. The
        // child reports the UDP port so the pin can name exactly that socket.
        let mut child = Command::new("python3")
            .args([
                "-c",
                "import socket, time, sys\n\
                 t = socket.socket()\n\
                 t.bind(('127.0.0.1', 0)); t.listen()\n\
                 d = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
                 d.bind(('127.0.0.1', 0))\n\
                 print(d.getsockname()[1], flush=True)\n\
                 time.sleep(60)",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn socket holder");
        let pid = child.id();
        let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));
        let mut port_line = String::new();
        stdout.read_line(&mut port_line).expect("child port");
        let udp_port: u16 = port_line.trim().parse().expect("a UDP port");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marks(pid).is_ok_and(|found| found.len() >= 2) {
            assert!(
                Instant::now() < deadline,
                "the holder never opened both sockets"
            );
            thread::sleep(Duration::from_millis(50));
        }

        assert_eq!(
            set_mark_datagram(pid, MARK, &[udp_port]).expect("pinned mark"),
            0,
            "a socket pinned at route open must stay unmarked and direct"
        );
        assert!(marks(pid)
            .expect("read marks")
            .iter()
            .all(|(_, mark)| *mark == 0));

        assert_eq!(
            set_mark_datagram(pid, MARK, &[]).expect("mark datagram sockets"),
            1,
            "an unpinned UDP-only route marks the datagram socket"
        );
        assert_eq!(
            marks(pid)
                .expect("read marks")
                .into_iter()
                .filter(|(_, mark)| *mark == MARK)
                .count(),
            1,
            "no stream socket may carry a UDP-only route mark"
        );

        assert_eq!(
            set_mark(pid, MARK).expect("mark every socket"),
            2,
            "a route that is not UDP-only marks both sockets"
        );

        let _ = child.kill();
        let _ = child.wait();
    }
}
