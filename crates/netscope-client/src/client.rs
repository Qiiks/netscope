//! The control-socket client and its typed request methods.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use netscope_linux::protocol::{
    CloseResult, OpenScope, ProfileStatus, Request, RequestOp, Response, ScopeHandle, StatusData,
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use netscope_linux::types::{Hold, PolicySpec, TargetSpec};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::error::ClientError;

/// Default control socket used by `netscoped`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/netscope/control.sock";

const UNAVAILABLE: &str = "daemon not running; start with: sudo systemctl start netscoped";
const GROUP_HINT: &str =
    "permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER";
const TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to the `netscope` daemon.
///
/// Requests are sent one at a time; `&mut self` guarantees they stay ordered,
/// and every request carries a fresh `id` that the reply must echo. One
/// [`Client`] owns one socket connection, which matters for [`Hold::Peer`]:
/// the daemon drops a peer claim when the connection closes.
///
/// # Example
///
/// ```no_run
/// use netscope_client::{Client, ClientError};
///
/// fn main() -> Result<(), ClientError> {
///     let mut client = Client::connect()?;
///     for profile in client.list()? {
///         println!("{} {:?}", profile.id, profile.pids);
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    socket_path: PathBuf,
    next_id: u64,
}

impl Client {
    /// Connects to the default control socket.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Unavailable`] when the socket is missing or
    /// nothing is listening, [`ClientError::Permission`] when the socket
    /// rejects the caller, and [`ClientError::Io`] for other socket failures.
    pub fn connect() -> Result<Self, ClientError> {
        Self::connect_at(DEFAULT_SOCKET_PATH)
    }

    /// Connects to the control socket at `path`.
    ///
    /// Read and write timeouts are set to 10 seconds, so a wedged daemon
    /// surfaces as [`ClientError::Io`] instead of blocking the caller forever.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Unavailable`] when the socket is missing or
    /// nothing is listening, [`ClientError::Permission`] when the socket
    /// rejects the caller, and [`ClientError::Io`] for other socket failures.
    pub fn connect_at(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path).map_err(|err| connect_error(path, err))?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .map_err(ClientError::Io)?;
        stream
            .set_write_timeout(Some(TIMEOUT))
            .map_err(ClientError::Io)?;
        let writer = stream.try_clone().map_err(ClientError::Io)?;
        Ok(Self {
            reader: BufReader::new(stream),
            writer,
            socket_path: path.to_path_buf(),
            next_id: 0,
        })
    }

    /// Reports whether the default socket exists and accepts connections.
    pub fn is_available() -> bool {
        Self::is_available_at(DEFAULT_SOCKET_PATH)
    }

    /// Reports whether `path` exists and accepts connections.
    ///
    /// This only proves a listener is present; it sends no request.
    pub fn is_available_at(path: impl AsRef<Path>) -> bool {
        let path = path.as_ref();
        path.exists() && UnixStream::connect(path).is_ok()
    }

    /// Returns the daemon status, including every profile it manages.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the daemon refuses the request and
    /// [`ClientError::Protocol`] when the reply does not match [`StatusData`].
    pub fn status(&mut self) -> Result<StatusData, ClientError> {
        let data = self.raw_request(RequestOp::Status)?;
        decode(data, "status")
    }

    /// Opens or joins the shared profile described by `open`.
    ///
    /// Opening is idempotent per `(target, target_uid, consumer)`: a second
    /// call for the same identity returns the existing handle.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the daemon refuses the scope (for
    /// example another UID, an unsupported target, or the profile ceiling) and
    /// [`ClientError::Protocol`] when the reply does not match [`ScopeHandle`].
    pub fn open_scope(&mut self, open: OpenScope) -> Result<ScopeHandle, ClientError> {
        let data = self.raw_request(RequestOp::Open(open))?;
        decode(data, "scope")
    }

    /// Opens or joins a scope for a process-name target.
    ///
    /// `process_name` is matched case-insensitively against a process's `comm`
    /// or an argv basename. A Wine PE and a bare process name unify on that
    /// basename, so `"Overwatch.exe"` and `"Overwatch"` reach one profile.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the daemon refuses the scope and
    /// [`ClientError::Protocol`] when the reply does not match [`ScopeHandle`].
    pub fn open_process(
        &mut self,
        consumer: &str,
        process_name: &str,
        target_uid: u32,
        hold: Hold,
    ) -> Result<ScopeHandle, ClientError> {
        self.open_scope(OpenScope {
            consumer: consumer.to_string(),
            target: TargetSpec::Name {
                name: process_name.to_string(),
            },
            target_uid,
            name: None,
            hold,
        })
    }

    /// Replaces one consumer's policy on an existing profile.
    ///
    /// Filter policies from different consumers compose; a route policy can
    /// only be held by one consumer at a time.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the profile is missing, the
    /// consumer holds no claim, or the policy is invalid.
    pub fn set_policy(
        &mut self,
        profile: &str,
        consumer: &str,
        policy: PolicySpec,
    ) -> Result<(), ClientError> {
        self.raw_request(RequestOp::SetPolicy {
            profile: profile.to_string(),
            consumer: consumer.to_string(),
            policy,
        })
        .map(|_| ())
    }

    /// Removes one consumer's policy without releasing its claim.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the profile is missing or the
    /// consumer holds no claim.
    pub fn clear_policy(&mut self, profile: &str, consumer: &str) -> Result<(), ClientError> {
        self.raw_request(RequestOp::ClearPolicy {
            profile: profile.to_string(),
            consumer: consumer.to_string(),
        })
        .map(|_| ())
    }

    /// Releases one consumer's claim and reports the profile's fate.
    ///
    /// The daemon removes the profile when this was its last claim.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the profile is missing or the
    /// consumer holds no claim and [`ClientError::Protocol`] when the reply
    /// does not match [`CloseResult`].
    pub fn close_scope(
        &mut self,
        profile: &str,
        consumer: &str,
    ) -> Result<CloseResult, ClientError> {
        let data = self.raw_request(RequestOp::Close {
            profile: profile.to_string(),
            consumer: consumer.to_string(),
        })?;
        decode(data, "close")
    }

    /// Looks up a profile by id or by its shared identity.
    ///
    /// Pass `Some(profile)` or `Some(target)`; the daemon requires
    /// `target_uid` alongside a target. Returns `None` only for a `null` reply
    /// payload; a missing profile is normally a [`ClientError::Daemon`] error.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when nothing matches or the arguments
    /// are incomplete, and [`ClientError::Protocol`] when the reply does not
    /// match [`ProfileStatus`].
    pub fn resolve(
        &mut self,
        profile: Option<&str>,
        target: Option<TargetSpec>,
        target_uid: Option<u32>,
    ) -> Result<Option<ProfileStatus>, ClientError> {
        let data = self.raw_request(RequestOp::Resolve {
            profile: profile.map(str::to_string),
            target,
            target_uid,
        })?;
        match data {
            None | Some(Value::Null) => Ok(None),
            Some(value) => serde_json::from_value(value)
                .map(Some)
                .map_err(|err| ClientError::Protocol(format!("invalid resolve response: {err}"))),
        }
    }

    /// Lists every profile the daemon currently manages.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Protocol`] when the reply is not a profile list.
    pub fn list(&mut self) -> Result<Vec<ProfileStatus>, ClientError> {
        let data = self.raw_request(RequestOp::List)?;
        decode(data, "profile list")
    }

    /// Forces an immediate target re-stat and attach pass.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the daemon cannot run the pass.
    pub fn refresh(&mut self) -> Result<(), ClientError> {
        self.raw_request(RequestOp::Refresh).map(|_| ())
    }

    /// Re-enables a disabled profile.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the profile is missing or the
    /// caller may not modify it.
    pub fn enable(&mut self, profile: &str) -> Result<(), ClientError> {
        self.raw_request(RequestOp::Enable {
            name: profile.to_string(),
        })
        .map(|_| ())
    }

    /// Disables a profile without removing its definition.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the profile is missing or the
    /// caller may not modify it.
    pub fn disable(&mut self, profile: &str) -> Result<(), ClientError> {
        self.raw_request(RequestOp::Disable {
            name: profile.to_string(),
        })
        .map(|_| ())
    }

    /// Removes a profile, including its rules and routes.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Daemon`] when the profile is missing or the
    /// caller may not modify it.
    pub fn remove(&mut self, profile: &str) -> Result<(), ClientError> {
        self.raw_request(RequestOp::Remove {
            name: profile.to_string(),
        })
        .map(|_| ())
    }

    /// Sends one raw request and returns its raw `data` payload.
    ///
    /// This is the only method that does not interpret the reply, so it is the
    /// escape hatch for protocol operations without a typed method.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Unavailable`] when the daemon closes the
    /// connection before replying, [`ClientError::Daemon`] when the reply is
    /// `ok: false`, and [`ClientError::Protocol`] for a malformed, oversized,
    /// or mismatched-id reply. A protocol error leaves the stream's framing
    /// unknown; create a new client before sending another request.
    pub fn raw_request(&mut self, op: RequestOp) -> Result<Option<Value>, ClientError> {
        let id = self.next_id.wrapping_add(1);
        self.next_id = id;

        let request = Request { id, op };
        let mut line = serde_json::to_vec(&request)
            .map_err(|err| ClientError::Protocol(format!("encode request: {err}")))?;
        if line.len() > MAX_REQUEST_BYTES {
            return Err(ClientError::Protocol(format!(
                "request exceeds {MAX_REQUEST_BYTES} bytes"
            )));
        }
        line.push(b'\n');

        self.writer.write_all(&line).map_err(ClientError::Io)?;
        self.writer.flush().map_err(ClientError::Io)?;

        let mut response = String::new();
        let read = self
            .reader
            .read_line(&mut response)
            .map_err(response_error)?;
        if read == 0 {
            return Err(ClientError::Unavailable(format!(
                "daemon at {} closed the connection without replying",
                self.socket_path.display()
            )));
        }

        let payload = response.strip_suffix('\n').unwrap_or(&response);
        if payload.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::Protocol(format!(
                "response exceeds {MAX_RESPONSE_BYTES} bytes"
            )));
        }

        let response: Response = serde_json::from_str(payload)
            .map_err(|err| ClientError::Protocol(format!("invalid response (id {id}): {err}")))?;
        if response.id != id {
            return Err(ClientError::Protocol(format!(
                "response id {} does not match request id {id}",
                response.id
            )));
        }
        if !response.ok {
            return Err(ClientError::Daemon(response.error.unwrap_or_else(|| {
                "daemon returned an error without a message".to_string()
            })));
        }
        Ok(response.data)
    }
}

fn connect_error(socket: &Path, err: io::Error) -> ClientError {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            ClientError::Unavailable(format!("{UNAVAILABLE} (socket {})", socket.display()))
        }
        io::ErrorKind::PermissionDenied => ClientError::Permission(GROUP_HINT.to_string()),
        _ => ClientError::Io(err),
    }
}

fn response_error(err: io::Error) -> ClientError {
    if err.kind() == io::ErrorKind::InvalidData {
        ClientError::Protocol(format!("response is not UTF-8: {err}"))
    } else {
        ClientError::Io(err)
    }
}

fn decode<T: DeserializeOwned>(data: Option<Value>, what: &str) -> Result<T, ClientError> {
    let value = data.ok_or_else(|| ClientError::Protocol(format!("daemon returned no {what}")))?;
    serde_json::from_value(value)
        .map_err(|err| ClientError::Protocol(format!("invalid {what} response: {err}")))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::thread::JoinHandle;

    use netscope_linux::protocol::ProfileStats;
    use serde_json::json;

    use super::*;

    struct MockSocket {
        path: PathBuf,
    }

    impl Drop for MockSocket {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn mock(name: &str) -> (MockSocket, UnixListener) {
        let path = std::env::temp_dir().join(format!(
            "netscope-client-{}-{name}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind mock control socket");
        (MockSocket { path }, listener)
    }

    fn responder(
        listener: UnixListener,
        respond: impl FnOnce(&Request) -> String + Send + 'static,
    ) -> JoinHandle<Request> {
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone mock stream"))
                .read_line(&mut line)
                .expect("read request");
            let request: Request = serde_json::from_str(line.trim_end()).expect("decode request");
            stream
                .write_all(respond(&request).as_bytes())
                .expect("write response");
            request
        })
    }

    fn ok(id: u64, data: Value) -> String {
        format!(
            "{}\n",
            serde_json::to_string(&Response::ok(id, data)).expect("encode response")
        )
    }

    fn err(id: u64, message: &str) -> String {
        format!(
            "{}\n",
            serde_json::to_string(&Response::err(id, message)).expect("encode response")
        )
    }

    fn status_fixture() -> StatusData {
        StatusData {
            api_version: 2,
            daemon_version: "0.2.1-test".to_string(),
            pid: 42,
            kernel: "test".to_string(),
            cgroup_root: "/sys/fs/cgroup/netscope".to_string(),
            state_path: "/var/lib/netscope/state.json".to_string(),
            config_path: "/etc/netscope/config.toml".to_string(),
            profiles: Vec::new(),
        }
    }

    fn profile_fixture() -> ProfileStatus {
        ProfileStatus {
            id: "overwatch".to_string(),
            mode: "filter".to_string(),
            enabled: true,
            target: "name:Overwatch.exe".to_string(),
            cgroup: "/sys/fs/cgroup/netscope/overwatch".to_string(),
            cgroup_level: 4,
            pids: vec![123],
            nft_table: "netscope_overwatch".to_string(),
            mark: "0x4e53".to_string(),
            table: 20_000,
            rule_priority: 1_000,
            attached: "exec".to_string(),
            healthy: true,
            warnings: Vec::new(),
            consumers: vec!["exitlink".to_string()],
            policies: vec!["filter".to_string()],
            generation: 7,
            links: Vec::new(),
            stats: Some(ProfileStats {
                tx_bytes: 1_024,
                rx_bytes: 512,
                tx_packets: 8,
                rx_packets: 4,
                tx_rate_bps: 4_096,
                rx_rate_bps: 2_048,
                dropped_bytes: 0,
                dropped_packets: 0,
                since_unix: 1_700_000_000,
            }),
        }
    }

    #[test]
    fn missing_socket_is_unavailable() {
        let path = std::env::temp_dir().join(format!(
            "netscope-client-{}-missing.sock",
            std::process::id()
        ));
        let error = Client::connect_at(&path).expect_err("connect must fail");
        assert!(
            matches!(&error, ClientError::Unavailable(message) if message.contains("daemon not running")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn permission_denied_carries_group_hint() {
        let error = connect_error(
            Path::new(DEFAULT_SOCKET_PATH),
            io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(
            matches!(&error, ClientError::Permission(message) if message.contains("netscope group")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn availability_tracks_the_socket() {
        let missing = std::env::temp_dir().join(format!(
            "netscope-client-{}-unavailable.sock",
            std::process::id()
        ));
        assert!(!Client::is_available_at(&missing), "missing socket");

        let (socket, listener) = mock("available");
        assert!(Client::is_available_at(&socket.path), "listening socket");
        drop(listener);
    }

    #[test]
    fn request_is_one_ndjson_line() {
        let (socket, listener) = mock("framing");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone mock stream"))
                .read_line(&mut line)
                .expect("read request");
            assert!(line.ends_with('\n'), "request must end with a newline");
            assert_eq!(line.lines().count(), 1, "exactly one NDJSON line");
            let request: Value = serde_json::from_str(line.trim_end()).expect("request is JSON");
            assert_eq!(request, json!({"id": 1, "op": "status"}));
            stream
                .write_all(ok(1, json!({})).as_bytes())
                .expect("write response");
        });

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let data = client.raw_request(RequestOp::Status).expect("status");
        assert_eq!(data, Some(json!({})));
        handle.join().expect("mock responder");
    }

    #[test]
    fn status_round_trips() {
        let (socket, listener) = mock("status");
        let expected = status_fixture();
        let sent = expected.clone();
        let handle = responder(listener, move |_| {
            ok(1, serde_json::to_value(&sent).expect("encode status"))
        });

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let status = client.status().expect("status");
        assert_eq!(status, expected);

        let request = handle.join().expect("mock responder");
        assert_eq!(request.id, 1);
        assert_eq!(request.op, RequestOp::Status);
    }

    #[test]
    fn open_process_sends_name_target_and_hold() {
        let (socket, listener) = mock("open-process");
        let expected = ScopeHandle {
            profile: "overwatch".to_string(),
            generation: 3,
            target: "name:Overwatch.exe".to_string(),
            target_uid: 1000,
            state: "attached".to_string(),
            attached: "exec".to_string(),
            pids: vec![123],
            consumers: vec!["exitlink".to_string()],
        };
        let sent = expected.clone();
        let handle = responder(listener, move |_| {
            ok(1, serde_json::to_value(&sent).expect("encode scope"))
        });

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let scope = client
            .open_process("exitlink", "Overwatch.exe", 1000, Hold::Persistent)
            .expect("open scope");
        assert_eq!(scope, expected);

        let request = handle.join().expect("mock responder");
        assert_eq!(
            request.op,
            RequestOp::Open(OpenScope {
                consumer: "exitlink".to_string(),
                target: TargetSpec::Name {
                    name: "Overwatch.exe".to_string(),
                },
                target_uid: 1000,
                name: None,
                hold: Hold::Persistent,
            })
        );
    }

    #[test]
    fn resolve_null_is_none() {
        let (socket, listener) = mock("resolve-null");
        let handle = responder(listener, |_| ok(1, Value::Null));

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let resolved = client
            .resolve(Some("missing"), None, None)
            .expect("resolve");
        assert_eq!(resolved, None);

        let request = handle.join().expect("mock responder");
        assert_eq!(
            request.op,
            RequestOp::Resolve {
                profile: Some("missing".to_string()),
                target: None,
                target_uid: None,
            }
        );
    }

    #[test]
    fn resolve_returns_profile_status() {
        let (socket, listener) = mock("resolve-status");
        let expected = profile_fixture();
        let sent = expected.clone();
        let handle = responder(listener, move |_| {
            ok(1, serde_json::to_value(&sent).expect("encode profile"))
        });

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let resolved = client
            .resolve(
                None,
                Some(TargetSpec::Name {
                    name: "Overwatch.exe".to_string(),
                }),
                Some(1000),
            )
            .expect("resolve");
        assert_eq!(resolved, Some(expected));

        let request = handle.join().expect("mock responder");
        assert_eq!(request.id, 1);
    }

    #[test]
    fn lifecycle_helpers_send_their_ops() {
        let cases: [(&str, RequestOp, fn(&mut Client) -> Result<(), ClientError>); 3] = [
            (
                "enable",
                RequestOp::Enable {
                    name: "game".to_string(),
                },
                |client| client.enable("game"),
            ),
            (
                "disable",
                RequestOp::Disable {
                    name: "game".to_string(),
                },
                |client| client.disable("game"),
            ),
            (
                "remove",
                RequestOp::Remove {
                    name: "game".to_string(),
                },
                |client| client.remove("game"),
            ),
        ];
        for (name, expected, call) in cases {
            let (socket, listener) = mock(name);
            let handle = responder(listener, |_| ok(1, json!({})));
            let mut client = Client::connect_at(&socket.path).expect("connect mock");
            call(&mut client).expect(name);
            assert_eq!(handle.join().expect("mock responder").op, expected);
        }
    }

    #[test]
    fn daemon_error_becomes_daemon_variant() {
        let (socket, listener) = mock("daemon-error");
        let handle = responder(listener, |_| err(1, "profile not found"));

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let error = client.status().expect_err("status must fail");
        assert!(
            matches!(&error, ClientError::Daemon(message) if message == "profile not found"),
            "unexpected error: {error:?}"
        );
        handle.join().expect("mock responder");
    }

    #[test]
    fn mismatched_id_is_a_protocol_error() {
        let (socket, listener) = mock("mismatched-id");
        let handle = responder(listener, |_| ok(99, json!({})));

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let error = client.status().expect_err("status must fail");
        assert!(
            matches!(&error, ClientError::Protocol(message) if message.contains("does not match")),
            "unexpected error: {error:?}"
        );
        handle.join().expect("mock responder");
    }

    #[test]
    fn malformed_json_is_a_protocol_error() {
        let (socket, listener) = mock("malformed");
        let handle = responder(listener, |_| "not json\n".to_string());

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let error = client.status().expect_err("status must fail");
        assert!(
            matches!(&error, ClientError::Protocol(_)),
            "unexpected error: {error:?}"
        );
        handle.join().expect("mock responder");
    }

    #[test]
    fn oversized_response_is_rejected() {
        let (socket, listener) = mock("oversized");
        let handle = responder(listener, |_| {
            format!("{}\n", "x".repeat(MAX_RESPONSE_BYTES + 1))
        });

        let mut client = Client::connect_at(&socket.path).expect("connect mock");
        let error = client.status().expect_err("status must fail");
        assert!(
            matches!(&error, ClientError::Protocol(message) if message.contains("exceeds")),
            "unexpected error: {error:?}"
        );
        handle.join().expect("mock responder");
    }
}
