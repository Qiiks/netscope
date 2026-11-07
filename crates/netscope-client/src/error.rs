//! Errors returned by the `netscope` client.

use thiserror::Error;

/// A failure while talking to the `netscope` daemon.
///
/// The variants separate the four states a caller normally reacts to: the
/// daemon is not running, the caller may not use it, the daemon refused the
/// request, or the wire data was unusable. Everything else is an [`std::io::Error`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The control socket is missing or nothing is listening on it.
    #[error("netscope daemon unavailable: {0}")]
    Unavailable(String),

    /// The control socket rejected the connection because of its permissions.
    ///
    /// The message carries the usual fix: add the user to the `netscope` group.
    #[error("{0}")]
    Permission(String),

    /// The daemon answered with `ok: false`.
    #[error("daemon error: {0}")]
    Daemon(String),

    /// The daemon reply was not valid NDJSON or did not match the request.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// The socket failed while connecting, sending, or reading.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
