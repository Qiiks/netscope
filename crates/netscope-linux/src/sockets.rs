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
/// Returns the number of sockets that now carry `mark`. Sockets that already
/// carry it are counted. Failure to reach one descriptor is reported rather
/// than skipped, because a partial mark would leave the profile silently
/// incomplete.
///
/// # Errors
///
/// Returns [`SocketMarkError`] when the process is gone, its descriptor table
/// cannot be read, or a socket exists but cannot be marked. A kernel without
/// `pidfd_getfd` returns [`SocketMarkError::Unsupported`].
pub fn set_mark(pid: u32, mark: u32) -> Result<usize, SocketMarkError> {
    let pidfd = open_pidfd(pid)?;
    let mut marked = 0;
    for fd in process_fds(pid)? {
        let Some(socket) = duplicate_socket(pidfd.as_raw_fd(), pid, fd)? else {
            continue;
        };
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
        if fd >= 0 {
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

/// Returns `Some(mark)` for an IPv4/IPv6 socket, `None` for any other fd.
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
