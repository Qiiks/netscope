use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use netscope_linux::protocol::{
    Request, RequestOp, Response, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};
use netscope_linux::types::Config;
use serde_json::Value;

pub const CONFIG_PATH: &str = "/etc/netscope/config.toml";
pub const UNAVAILABLE: &str = "daemon not running; start with: sudo systemctl start netscoped";
pub const GROUP_HINT: &str =
    "permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER";

const REQUEST_ID: u64 = 1;
const TIMEOUT: Duration = Duration::from_secs(10);

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
    let request = Request { id: REQUEST_ID, op };
    let mut line = serde_json::to_vec(&request)
        .map_err(|err| ClientError::Failed(format!("encode request: {err}")))?;
    if line.len() > MAX_REQUEST_BYTES {
        return Err(ClientError::Failed(format!(
            "request exceeds {MAX_REQUEST_BYTES} bytes"
        )));
    }
    line.push(b'\n');

    let mut stream = UnixStream::connect(socket).map_err(|err| connect_error(socket, err))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|err| ClientError::Failed(format!("set read timeout: {err}")))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|err| ClientError::Failed(format!("set write timeout: {err}")))?;
    stream
        .write_all(&line)
        .and_then(|()| stream.flush())
        .map_err(io_error)?;

    let mut response = Vec::new();
    let mut reader = BufReader::new(&stream).take((MAX_RESPONSE_BYTES + 1) as u64);
    reader.read_until(b'\n', &mut response).map_err(io_error)?;
    if response.is_empty() {
        return Err(ClientError::Failed(
            "daemon closed the connection without a response".to_string(),
        ));
    }
    if response.last() == Some(&b'\n') {
        response.pop();
    }
    if response.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError::Protocol(format!(
            "response exceeds {MAX_RESPONSE_BYTES} bytes"
        )));
    }

    let response: Response = serde_json::from_slice(&response).map_err(|err| {
        ClientError::Protocol(format!("invalid response from daemon (id 0): {err}"))
    })?;
    if !response.ok {
        let error = response
            .error
            .unwrap_or_else(|| "daemon returned an error without a message".to_string());
        return Err(if error.starts_with("permission denied") {
            ClientError::Permission(error)
        } else {
            ClientError::Failed(error)
        });
    }
    Ok(response.data)
}

fn connect_error(socket: &Path, err: io::Error) -> ClientError {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            ClientError::Unavailable(UNAVAILABLE.to_string())
        }
        io::ErrorKind::PermissionDenied => ClientError::Permission(GROUP_HINT.to_string()),
        _ => ClientError::Failed(format!("connect {}: {err}", socket.display())),
    }
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
}
