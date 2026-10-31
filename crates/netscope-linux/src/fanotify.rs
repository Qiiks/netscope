//! fanotify permission events that hold an `exec` until the daemon replies.

use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::sync::oneshot;

/// Metadata header is fixed-size and followed by zero or more info records.
const METADATA_SIZE: usize = 24;
const EVENT_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum FanotifyError {
    #[error("fanotify requires CAP_SYS_ADMIN")]
    PermissionDenied,
    #[error("fanotify io: {0}")]
    Io(#[from] std::io::Error),
    #[error("fanotify poll: {0}")]
    Poll(std::io::Error),
    #[error("invalid fanotify event: {0}")]
    Invalid(String),
}

/// One exec permission event. `overflow` is set when the kernel dropped
/// events; pid/dev/ino/path are then placeholders and the daemon must rescan.
pub struct ExecEvent {
    pub pid: u32,
    pub pidfd: Option<OwnedFd>,
    pub event_fd: OwnedFd,
    pub mask: u64,
    pub dev: u64,
    pub ino: u64,
    pub path: PathBuf,
    pub reply: oneshot::Sender<bool>,
    pub overflow: bool,
}

impl fmt::Debug for ExecEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecEvent")
            .field("pid", &self.pid)
            .field("pidfd", &self.pidfd)
            .field("event_fd", &self.event_fd)
            .field("mask", &self.mask)
            .field("dev", &self.dev)
            .field("ino", &self.ino)
            .field("path", &self.path)
            .field("overflow", &self.overflow)
            .finish_non_exhaustive()
    }
}

pub struct Fanotify {
    fd: OwnedFd,
    stop: OwnedFd,
}

impl Fanotify {
    pub fn new() -> Result<Self, FanotifyError> {
        let stop = eventfd()?;
        let full = libc::FAN_CLASS_CONTENT
            | libc::FAN_CLOEXEC
            | libc::FAN_NONBLOCK
            | libc::FAN_REPORT_PIDFD
            | libc::FAN_UNLIMITED_QUEUE
            | libc::FAN_UNLIMITED_MARKS;
        let attempts = [
            full,
            full & !libc::FAN_REPORT_PIDFD,
            full & !libc::FAN_REPORT_PIDFD
                & !libc::FAN_UNLIMITED_QUEUE
                & !libc::FAN_UNLIMITED_MARKS,
            libc::FAN_CLASS_CONTENT,
        ];
        let event_f_flags = (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint;

        let mut fd = None;
        for flags in attempts {
            let raw = unsafe { libc::fanotify_init(flags, event_f_flags) };
            if raw >= 0 {
                fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM) {
                return Err(FanotifyError::Io(error));
            }
        }
        let fd = fd.ok_or(FanotifyError::PermissionDenied)?;

        // The bare ladder rung omits FAN_CLOEXEC/FAN_NONBLOCK; enforce both
        // so the event descriptor never leaks into a gated exec and drains
        // cannot block after poll reports readable.
        let raw = fd.as_raw_fd();
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(FanotifyError::Io(std::io::Error::last_os_error()));
        }
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(FanotifyError::Io(std::io::Error::last_os_error()));
        }

        Ok(Self { fd, stop })
    }

    pub fn add_exec_mark(&self, path: &Path) -> Result<(), FanotifyError> {
        self.mark(path, libc::FAN_MARK_ADD, libc::FAN_OPEN_EXEC_PERM)
    }

    pub fn remove_exec_mark(&self, path: &Path) -> Result<(), FanotifyError> {
        self.mark(path, libc::FAN_MARK_REMOVE, libc::FAN_OPEN_EXEC_PERM)
    }

    pub fn add_open_mark(&self, path: &Path) -> Result<(), FanotifyError> {
        self.mark(path, libc::FAN_MARK_ADD, libc::FAN_OPEN_PERM)
    }

    pub fn remove_open_mark(&self, path: &Path) -> Result<(), FanotifyError> {
        self.mark(path, libc::FAN_MARK_REMOVE, libc::FAN_OPEN_PERM)
    }

    fn mark(&self, path: &Path, operation: libc::c_uint, mask: u64) -> Result<(), FanotifyError> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| FanotifyError::Invalid("mark path contains NUL".into()))?;
        let result = unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                operation | libc::FAN_MARK_INODE,
                mask,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            // A mark that already exists is already doing its job; a mark
            // that is already gone needs no removal.
            Some(libc::EEXIST) if operation == libc::FAN_MARK_ADD => Ok(()),
            Some(libc::ENOENT) if operation == libc::FAN_MARK_REMOVE => Ok(()),
            Some(libc::EPERM) | Some(libc::EACCES) => Err(FanotifyError::PermissionDenied),
            _ => Err(FanotifyError::Io(error)),
        }
    }

    pub fn read_events(&self) -> Result<Option<Vec<ExecEvent>>, FanotifyError> {
        let mut fds = [
            libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        loop {
            let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
            if ready > 0 {
                break;
            }
            if ready == 0 {
                continue;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(FanotifyError::Poll(error));
        }

        if fds[1].revents != 0 {
            let mut value = 0_u64;
            unsafe {
                libc::read(
                    self.stop.as_raw_fd(),
                    (&mut value as *mut u64).cast(),
                    std::mem::size_of::<u64>(),
                );
            }
            return Ok(None);
        }

        if fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(FanotifyError::Poll(std::io::Error::other(
                "fanotify descriptor reported an error",
            )));
        }

        let mut events = Vec::new();
        let mut buffer = [0_u8; EVENT_BUFFER_SIZE];
        loop {
            let count = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if count == 0 {
                break;
            }
            if count < 0 {
                let error = std::io::Error::last_os_error();
                match error.kind() {
                    std::io::ErrorKind::WouldBlock => break,
                    std::io::ErrorKind::Interrupted => continue,
                    _ => return Err(FanotifyError::Io(error)),
                }
            }
            parse_events(&buffer[..count as usize], &mut events)?;
        }
        Ok(Some(events))
    }

    pub fn respond(&self, event_fd: OwnedFd, allow: bool) -> Result<(), FanotifyError> {
        let response = libc::fanotify_response {
            fd: event_fd.as_raw_fd(),
            response: if allow {
                libc::FAN_ALLOW
            } else {
                libc::FAN_DENY
            },
        };
        let result = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                (&response as *const libc::fanotify_response).cast(),
                std::mem::size_of::<libc::fanotify_response>(),
            )
        };
        // The kernel requires the event fd to stay open until the response
        // is written, then closed; dropping here closes it on every path.
        drop(event_fd);
        if result < 0 {
            return Err(FanotifyError::Io(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn stop(&self) {
        let value = 1_u64;
        unsafe {
            libc::write(
                self.stop.as_raw_fd(),
                (&value as *const u64).cast(),
                std::mem::size_of::<u64>(),
            );
        }
    }
}

fn eventfd() -> Result<OwnedFd, FanotifyError> {
    let raw = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if raw < 0 {
        return Err(FanotifyError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn null_fd() -> Result<OwnedFd, FanotifyError> {
    let raw = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if raw < 0 {
        return Err(FanotifyError::Io(std::io::Error::last_os_error()));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn parse_events(bytes: &[u8], events: &mut Vec<ExecEvent>) -> Result<(), FanotifyError> {
    let mut offset = 0;
    while offset < bytes.len() {
        let event_len = u32_at(bytes, offset)
            .ok_or_else(|| FanotifyError::Invalid("truncated event header".into()))?
            as usize;
        if event_len < METADATA_SIZE || offset + event_len > bytes.len() {
            return Err(FanotifyError::Invalid(format!(
                "bad event length {event_len} at offset {offset}"
            )));
        }
        let event = &bytes[offset..offset + event_len];
        let mask = u64_at(event, 8)
            .ok_or_else(|| FanotifyError::Invalid("truncated event mask".into()))?;
        let metadata_len = u16_at(event, 6)
            .ok_or_else(|| FanotifyError::Invalid("truncated metadata length".into()))?
            as usize;

        if mask & libc::FAN_Q_OVERFLOW != 0 {
            let (reply, _receiver) = oneshot::channel();
            events.push(ExecEvent {
                pid: 0,
                pidfd: None,
                event_fd: null_fd()?,
                mask: 0,
                dev: 0,
                ino: 0,
                path: PathBuf::new(),
                reply,
                overflow: true,
            });
            offset += event_len;
            continue;
        }

        if metadata_len < METADATA_SIZE || metadata_len > event_len {
            return Err(FanotifyError::Invalid(format!(
                "bad metadata length {metadata_len}"
            )));
        }

        let raw_event_fd =
            i32_at(event, 16).ok_or_else(|| FanotifyError::Invalid("truncated event fd".into()))?;
        if raw_event_fd < 0 {
            // Not a permission event we can answer (e.g. FAN_NOFD).
            offset += event_len;
            continue;
        }
        let raw_pid = i32_at(event, 20)
            .ok_or_else(|| FanotifyError::Invalid("truncated event pid".into()))?;

        let mut raw_pidfd = None;
        let mut info_offset = metadata_len;
        while info_offset + 4 <= event_len {
            let info_type = event[info_offset];
            let info_len = u16_at(event, info_offset + 2)
                .ok_or_else(|| FanotifyError::Invalid("truncated info record".into()))?
                as usize;
            if info_len < 4 || info_offset + info_len > event_len {
                return Err(FanotifyError::Invalid(format!(
                    "bad info record length {info_len}"
                )));
            }
            if info_type == libc::FAN_EVENT_INFO_TYPE_PIDFD && info_len >= 8 {
                let pidfd = i32_at(event, info_offset + 4)
                    .ok_or_else(|| FanotifyError::Invalid("truncated pidfd".into()))?;
                if pidfd >= 0 {
                    raw_pidfd = Some(pidfd);
                }
            }
            info_offset += info_len;
        }

        let pidfd = raw_pidfd.map(|pidfd| unsafe { OwnedFd::from_raw_fd(pidfd) });
        let pid = if raw_pid > 0 {
            raw_pid as u32
        } else {
            pidfd
                .as_ref()
                .and_then(|fd| pidfd_pid(fd.as_raw_fd()))
                .unwrap_or(0)
        };
        let event_fd = unsafe { OwnedFd::from_raw_fd(raw_event_fd) };
        let (dev, ino) = fstat_ids(raw_event_fd)?;
        let path = std::fs::read_link(format!("/proc/self/fd/{raw_event_fd}")).unwrap_or_default();
        let (reply, _receiver) = oneshot::channel();
        events.push(ExecEvent {
            pid,
            pidfd,
            event_fd,
            mask,
            dev,
            ino,
            path,
            reply,
            overflow: false,
        });
        offset += event_len;
    }
    Ok(())
}

// dev_t/ino_t are u64 on 64-bit Linux but narrower on some 32-bit targets;
// keep the widening explicit without tripping clippy on 64-bit.
#[allow(clippy::unnecessary_cast)]
fn fstat_ids(fd: RawFd) -> Result<(u64, u64), FanotifyError> {
    let mut status: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut status) } != 0 {
        return Err(FanotifyError::Io(std::io::Error::last_os_error()));
    }
    Ok((status.st_dev as u64, status.st_ino as u64))
}

fn pidfd_pid(fd: RawFd) -> Option<u32> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}")).ok()?;
    info.lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse().ok())
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn i32_at(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
