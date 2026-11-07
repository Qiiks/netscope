# netscope-linux

[![Crates.io](https://img.shields.io/crates/v/netscope-linux.svg)](https://crates.io/crates/netscope-linux)
[![Documentation](https://docs.rs/netscope-linux/badge.svg)](https://docs.rs/netscope-linux)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/Qiiks/netscope)

Core Linux networking and process isolation primitives for [Netscope](https://github.com/Qiiks/netscope).

Provides programmatic cgroup v2 subtree lifecycle management, nftables socket matching, fanotify `FAN_OPEN_PERM` process interception, socket marking via `pidfd_getfd` (`SO_MARK`), and Linux policy routing (`ip rule` + route tables).

## Usage

This crate contains the low-level Linux kernel primitives used by the `netscoped` daemon.

- For controlling Netscope from Rust applications without root privileges, use the client SDK: [`netscope-client`](https://crates.io/crates/netscope-client).
- For daemon and CLI tools, see the [Netscope Repository](https://github.com/Qiiks/netscope).
