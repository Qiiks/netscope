use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use netscope_client::Client;
use netscope_linux::protocol::RequestOp;
use netscope_linux::types::Config;
use serde_json::Value;

pub const CONFIG_PATH: &str = "/etc/netscope/config.toml";
pub const UNAVAILABLE: &str = "daemon not running; start with: sudo systemctl start netscoped";
pub const GROUP_HINT: &str =
    "permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER";

#[derive(Debug)]
pub enum ClientError {
    Unavailable(String),
    Permission(String),
    Failed(String),
    Protocol(String),
}

impl ClientError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Unavailable(_) => 3,
            Self::Permission(_) => 4,
            Self::Failed(_) | Self::Protocol(_) => 1,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Unavailable(message)
            | Self::Permission(message)
            | Self::Failed(message)
            | Self::Protocol(message) => message,
        }
    }
}

impl From<netscope_client::ClientError> for ClientError {
    fn from(err: netscope_client::ClientError) -> Self {
        use netscope_client::ClientError as Upstream;
        match err {
            Upstream::Unavailable(message) => Self::Unavailable(message),
            Upstream::Permission(message) => Self::Permission(message),
            Upstream::Daemon(message) if message.starts_with("permission denied") => {
                Self::Permission(message)
            }
            Upstream::Daemon(message) => Self::Failed(message),
            Upstream::Protocol(message) => Self::Protocol(message),
            Upstream::Io(err) => io_error(err),
            other => Self::Failed(other.to_string()),
        }
    }
}

pub fn load_config() -> Config {
    load_config_from(Path::new(CONFIG_PATH))
}

pub fn load_config_from(path: &Path) -> Config {
    let mut config = Config::default();
    let Ok(text) = fs::read_to_string(path) else {
        return config;
    };
    let Ok(value) = text.parse::<toml::Value>() else {
        return config;
    };
    let Some(daemon) = value.get("daemon").and_then(toml::Value::as_table) else {
        return config;
    };
    if let Some(value) = daemon.get("socket_path").and_then(toml::Value::as_str) {
        config.daemon.socket_path = PathBuf::from(value);
    }
    if let Some(value) = daemon.get("state_path").and_then(toml::Value::as_str) {
        config.daemon.state_path = PathBuf::from(value);
    }
    if let Some(value) = daemon.get("cgroup_root").and_then(toml::Value::as_str) {
        config.daemon.cgroup_root = PathBuf::from(value);
    }
    config
}

pub fn socket_path(override_path: Option<&Path>) -> PathBuf {
    match override_path {
        Some(path) => path.to_path_buf(),
        None => load_config().daemon.socket_path,
    }
}

pub fn send(socket: &Path, op: RequestOp) -> Result<Option<Value>, ClientError> {
    let mut client = Client::connect_at(socket)?;
    client.raw_request(op).map_err(ClientError::from)
}

fn io_error(err: io::Error) -> ClientError {
    match err.kind() {
        io::ErrorKind::NotFound
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => ClientError::Unavailable(UNAVAILABLE.to_string()),
        io::ErrorKind::PermissionDenied => ClientError::Permission(GROUP_HINT.to_string()),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            ClientError::Failed("daemon did not reply within 10 seconds".to_string())
        }
        _ => ClientError::Failed(format!("daemon connection: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(name: &str, body: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "netscope-cli-config-{}-{name}.toml",
            std::process::id()
        ));
        fs::write(&path, body).expect("write temp config");
        path
    }

    #[test]
    fn partial_config_keeps_every_other_default() {
        let path = temp_config(
            "partial",
            "[daemon]\nsocket_path = \"/tmp/netscope-test.sock\"\n",
        );
        let config = load_config_from(&path);
        let defaults = Config::default();
        fs::remove_file(&path).expect("remove temp config");
        assert_eq!(
            config.daemon.socket_path,
            PathBuf::from("/tmp/netscope-test.sock")
        );
        assert_eq!(config.daemon.state_path, defaults.daemon.state_path);
        assert_eq!(config.daemon.cgroup_root, defaults.daemon.cgroup_root);
        assert_eq!(
            config.daemon.poll_interval_ms,
            defaults.daemon.poll_interval_ms
        );
    }

    #[test]
    fn malformed_config_falls_back_to_defaults() {
        let path = temp_config("malformed", "not = [valid");
        let config = load_config_from(&path);
        let defaults = Config::default();
        fs::remove_file(&path).expect("remove temp config");
        assert_eq!(config.daemon.socket_path, defaults.daemon.socket_path);
        assert_eq!(config.daemon.max_profiles, defaults.daemon.max_profiles);
    }

    fn temp_socket(name: &str) -> (PathBuf, std::os::unix::net::UnixListener) {
        let path = std::env::temp_dir().join(format!(
            "netscope-cli-socket-{}-{name}.sock",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind mock socket");
        (path, listener)
    }

    #[test]
    fn send_round_trips_through_the_sdk() {
        use std::io::{BufRead, BufReader, Write};

        let (path, listener) = temp_socket("send");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut line = String::new();
            BufReader::new(stream.try_clone().expect("clone mock stream"))
                .read_line(&mut line)
                .expect("read request");
            let request: netscope_linux::protocol::Request =
                serde_json::from_str(line.trim_end()).expect("decode request");
            assert_eq!(request.op, RequestOp::Status);
            let response = netscope_linux::protocol::Response::ok(
                request.id,
                serde_json::json!({"api_version": 2}),
            );
            let line = serde_json::to_string(&response).expect("encode response");
            stream
                .write_all(format!("{line}\n").as_bytes())
                .expect("write response");
        });

        let data = send(&path, RequestOp::Status).expect("send status");
        handle.join().expect("mock responder");
        fs::remove_file(&path).expect("remove mock socket");
        assert_eq!(
            data.expect("status data")["api_version"],
            serde_json::json!(2)
        );
    }

    #[test]
    fn daemon_permission_error_keeps_exit_code_four() {
        let err = ClientError::from(netscope_client::ClientError::Daemon(
            "permission denied: profile owned by uid 0".to_string(),
        ));
        assert_eq!(err.exit_code(), 4);
        assert_eq!(err.message(), "permission denied: profile owned by uid 0");
    }
}
