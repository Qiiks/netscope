mod bundle;
mod doctor;
mod redact;

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// `support_bundle_with`/`BundleOptions` are the flag-aware entry point used by main.
#[allow(unused_imports)]
pub use bundle::{support_bundle, support_bundle_with, BundleOptions};
pub use doctor::doctor;

pub(crate) const RUN_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const RUN_CAP: usize = 256 * 1024;

pub(crate) struct Capped {
    pub status: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
}

/// Run a command with a hard deadline and per-stream output caps.
pub(crate) fn run_capped(program: &str, args: &[&str]) -> anyhow::Result<Capped> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let out_reader = drain(stdout);
    let err_reader = drain(stderr);

    let deadline = Instant::now() + RUN_TIMEOUT;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    };

    // Readers hit EOF when the child (or the killed process) closes its pipes.
    let (stdout, out_truncated) = out_reader.join().unwrap_or_default();
    let (stderr, err_truncated) = err_reader.join().unwrap_or_default();
    Ok(Capped {
        status: status.and_then(|status| status.code()),
        timed_out,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: out_truncated || err_truncated,
    })
}

fn drain<R: Read + Send + 'static>(mut reader: R) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut truncated = false;
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let room = RUN_CAP.saturating_sub(kept.len());
                    let take = room.min(read);
                    kept.extend_from_slice(&buffer[..take]);
                    if take < read {
                        truncated = true;
                    }
                }
            }
        }
        (kept, truncated)
    })
}
