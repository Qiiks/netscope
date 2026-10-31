use std::io::{Read, Write};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use netscope_linux::cgroup::{AttachSource, CgroupManager};
use netscope_linux::nft::NftManager;
use netscope_linux::types::{FilterDefault, Mode, Profile, Target};

fn main() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("prove_filter requires root: sudo target/debug/examples/prove_filter");
    }

    if let Some(value) = std::env::args().nth(1) {
        match value.as_str() {
            "--receive" => return receive(),
            "--send" => return send(),
            other => bail!("unknown helper mode {other}"),
        }
    }

    let pid = std::process::id();
    let ns = format!("netscope-prove-{pid}");
    let root = PathBuf::from(format!("/sys/fs/cgroup/netscope-prove-{pid}"));
    let profile_id = format!("scoped-{pid}");
    let cgroup = Rc::new(CgroupManager::new(root.clone())?);
    cgroup.ensure_root()?;
    cgroup.ensure_profile(&profile_id)?;
    let nft = NftManager::new(&root)?;
    let profile = Profile {
        id: profile_id.clone(),
        target: Target::Native {
            path: "/bin/true".to_string(),
            dev: 0,
            ino: 0,
        },
        target_uid: unsafe { libc::geteuid() },
        owner_uid: unsafe { libc::geteuid() },
        mode: Mode::Filter {
            default: FilterDefault::Drop,
            exceptions: vec![],
        },
        index: 0,
        mark: netscope_linux::types::mark(0),
        table: netscope_linux::types::table(0),
        rule_priority: netscope_linux::types::rule_priority(0),
        enabled: true,
        created_at: "2026-10-30T00:00:00Z".to_string(),
        updated_at: "2026-10-30T00:00:00Z".to_string(),
    };
    nft.apply(&profile)?;
    let _cleanup = Cleanup {
        ns: ns.clone(),
        root,
        nft: Some((nft, profile)),
        cgroup: Rc::clone(&cgroup),
        profile_id: profile_id.clone(),
    };

    let port = 30456 + (pid % 1000) as u16;
    setup_netns(&ns)?;

    let exe = std::env::current_exe().context("resolve example path")?;
    let receiver = Command::new("ip")
        .args(["netns", "exec", &ns])
        .arg(&exe)
        .args(["--receive", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start receiver")?;
    thread::sleep(Duration::from_millis(300));

    let mut scoped = spawn_sender(&exe, port)?;
    let scoped_pid = scoped.id();
    cgroup.attach_pid(&profile_id, scoped_pid, AttachSource::PreExec)?;
    scoped
        .stdin
        .as_mut()
        .context("scoped sender stdin")?
        .write_all(b"x")?;
    let scoped_status = scoped.wait()?;
    if !scoped_status.success() {
        bail!("scoped sender failed: {scoped_status}");
    }
    thread::sleep(Duration::from_millis(200));

    let mut unscoped = spawn_sender(&exe, port)?;
    unscoped
        .stdin
        .as_mut()
        .context("unscoped sender stdin")?
        .write_all(b"x")?;
    let unscoped_status = unscoped.wait()?;
    if !unscoped_status.success() {
        bail!("unscoped sender failed: {unscoped_status}");
    }

    let output = receiver.wait_with_output()?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        eprintln!(
            "receiver stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        bail!("receiver failed: {}", output.status);
    }
    if !text.contains("received=1") {
        bail!("expected exactly one packet, got: {text}");
    }
    println!("prove_filter: scoped packet dropped, unscoped packet delivered ({text})");
    Ok(())
}

fn spawn_sender(exe: &PathBuf, port: u16) -> Result<std::process::Child> {
    Command::new(exe)
        .args(["--send", &port.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start sender")
}

fn receive() -> Result<()> {
    let port: u16 = std::env::args()
        .nth(2)
        .context("receiver port")?
        .parse()
        .context("receiver port number")?;
    let socket = UdpSocket::bind(("0.0.0.0", port)).context("bind receiver")?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .context("set receiver timeout")?;
    let mut count = 0;
    let mut buffer = [0u8; 2048];
    while socket.recv_from(&mut buffer).is_ok() {
        count += 1;
    }
    println!("received={count}");
    Ok(())
}

fn send() -> Result<()> {
    let port: u16 = std::env::args()
        .nth(2)
        .context("sender port")?
        .parse()
        .context("sender port number")?;
    let mut byte = [0u8; 1];
    std::io::stdin()
        .read_exact(&mut byte)
        .context("wait for sender start")?;
    let socket = UdpSocket::bind(("0.0.0.0", 0)).context("bind sender")?;
    socket
        .send_to(b"probe", ("10.200.0.2", port))
        .context("send probe")?;
    Ok(())
}

fn setup_netns(ns: &str) -> Result<()> {
    run_ip(&["netns", "add", ns])?;
    run_ip(&[
        "link", "add", "nsv0", "type", "veth", "peer", "name", "nsv1",
    ])?;
    run_ip(&["link", "set", "nsv1", "netns", ns])?;
    run_ip(&["addr", "add", "10.200.0.1/24", "dev", "nsv0"])?;
    run_ip(&["link", "set", "nsv0", "up"])?;
    run_ip(&[
        "netns",
        "exec",
        ns,
        "ip",
        "addr",
        "add",
        "10.200.0.2/24",
        "dev",
        "nsv1",
    ])?;
    run_ip(&["netns", "exec", ns, "ip", "link", "set", "nsv1", "up"])?;
    run_ip(&["netns", "exec", ns, "ip", "link", "set", "lo", "up"])?;
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .with_context(|| format!("run ip {}", args.join(" ")))?;
    if !status.success() {
        bail!("ip {} failed: {status}", args.join(" "));
    }
    Ok(())
}

struct Cleanup {
    ns: String,
    root: PathBuf,
    nft: Option<(NftManager, Profile)>,
    cgroup: Rc<CgroupManager>,
    profile_id: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", "nsv0"]).status();
        let _ = Command::new("ip").args(["netns", "del", &self.ns]).status();
        if let Some((nft, profile)) = self.nft.take() {
            let _ = nft.remove(&profile);
        }
        let _ = self.cgroup.remove(&self.profile_id);
        let _ = std::fs::remove_dir(&self.root);
    }
}
