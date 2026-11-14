//! Typed Rust client for the `netscope` daemon.
//!
//! `netscoped` listens on a Unix domain socket and speaks newline-delimited
//! JSON: one `Request` per line, one `Response` back, matched by an
//! incrementing `id`. This crate wraps that wire protocol in typed methods and
//! maps failures onto [`ClientError`].
//!
//! The default socket is [`DEFAULT_SOCKET_PATH`]. A client that uses
//! [`Hold::Peer`] ties its claim to the connection, so keep the [`Client`]
//! alive for as long as the scope must stay open.
//!
//! # Example
//!
//! ```no_run
//! use netscope_client::{
//!     Client, ClientError, FilterDefault, Hold, PolicySpec,
//! };
//!
//! fn main() -> Result<(), ClientError> {
//!     let mut client = Client::connect()?;
//!     let status = client.status()?;
//!     println!("netscoped {} at pid {}", status.daemon_version, status.pid);
//!
//!     let scope = client.open_process("exitlink", "Overwatch.exe", 1000, Hold::Persistent)?;
//!     client.set_policy(
//!         &scope.profile,
//!         "exitlink",
//!         PolicySpec::Filter {
//!             default: FilterDefault::Drop,
//!             allow_cidrs: vec!["10.0.0.0/8".to_string()],
//!             deny_cidrs: Vec::new(),
//!         },
//!     )?;
//!
//!     let closed = client.close_scope(&scope.profile, "exitlink")?;
//!     println!("released={} removed={}", closed.released, closed.removed);
//!     Ok(())
//! }
//! ```
//!
//! # Failure mapping
//!
//! A missing or dead daemon is [`ClientError::Unavailable`], a socket the
//! caller cannot open is [`ClientError::Permission`], an `ok: false` reply is
//! [`ClientError::Daemon`] carrying the daemon's message, and malformed or
//! oversized wire data is [`ClientError::Protocol`]. Everything else surfaces
//! as [`ClientError::Io`].

pub mod client;
pub mod error;

pub use client::{Client, DEFAULT_SOCKET_PATH};
pub use error::ClientError;
pub use netscope_linux::protocol::{
    CloseResult, OpenScope, ProfileStats, ProfileStatus, RequestOp, ScopeHandle, StatusData,
};
pub use netscope_linux::types::{
    FilterDefault, Hold, LinkPhase, LinkStatus, PolicySpec, RouteLink, TargetSpec,
};
