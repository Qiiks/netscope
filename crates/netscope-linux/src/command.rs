use std::io::Write;
use std::process::{Command, Output, Stdio};

use anyhow::{bail, Context, Result};

pub fn run(program: &str, args: &[&str], stdin: Option<&[u8]>) -> Result<Output> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("spawn {program}"))?;

    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().context("open child stdin")?;
        pipe.write_all(input)
            .with_context(|| format!("write stdin to {program}"))?;
    }

    let output = child
        .wait_with_output()
        .with_context(|| format!("wait for {program}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{program} exited with {}: {}", output.status, stderr.trim());
    }

    Ok(output)
}

pub fn run_output(program: &str, args: &[&str]) -> Result<String> {
    let output = run(program, args, None)?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}
