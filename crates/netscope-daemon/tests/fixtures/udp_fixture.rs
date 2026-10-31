//! Minimal UDP fixture for the privileged integration tests.
//!
//! Compiled at test time with `rustc` into a unique path so the daemon can
//! scope exactly one inode without matching any system binary. `send` waits
//! for one byte on stdin so the test can attach the process before it emits
//! its probe; `recv` counts packets until the read timeout expires.

use std::io::Read;
use std::net::UdpSocket;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("send") => send(args.get(2).expect("destination")),
        Some("recv") => recv(args.get(2).expect("port")),
        _ => std::process::exit(2),
    }
}

fn send(dst: &str) {
    let mut gate = [0u8; 1];
    if std::io::stdin().read_exact(&mut gate).is_err() {
        std::process::exit(3);
    }
    let socket = UdpSocket::bind("0.0.0.0:0").expect("bind sender");
    // A scoped filter profile rejects the send with EPERM; that is the drop.
    match socket.send_to(b"netscope-probe", dst) {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(err) => panic!("send probe: {err:?}"),
    }
}

fn recv(port: &str) {
    let port: u16 = port.parse().expect("receiver port");
    let socket = UdpSocket::bind(("0.0.0.0", port)).expect("bind receiver");
    socket
        .set_read_timeout(Some(Duration::from_secs(4)))
        .expect("receiver timeout");
    let mut count = 0u32;
    let mut buffer = [0u8; 2048];
    while socket.recv_from(&mut buffer).is_ok() {
        count += 1;
    }
    println!("received={count}");
}
