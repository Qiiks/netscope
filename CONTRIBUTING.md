# Contributing

## Build and test

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
mdbook build docs
```

Privileged tests are not run in CI:

```sh
sudo cargo test -p netscope-daemon --test privileged -- --ignored --test-threads=1
```

They create temporary cgroups, nftables tables, routing rules, and network namespaces under unique names and remove them in `Drop` guards. Do not run them on a host with a live netscope service; stop the service first.

## Architecture

- `crates/netscope-linux` — reusable engine: cgroup, nftables, policy routing, fanotify, process scanning.
- `crates/netscope-daemon` — root daemon: JSON-lines socket, reconciliation, health loop, attach provenance.
- `crates/netscope-cli` — unprivileged CLI and diagnostics.

The public types live in `crates/netscope-linux/src/types.rs` and `protocol.rs`. Keep them stable; Dropship and ExitLink are intended consumers.

## Pull requests

- Keep changes focused and include the command you ran to verify them.
- Add a test for a behavior change, or explain why the behavior cannot be tested without root.
- Sign off commits with `git commit -s` (Developer Certificate of Origin).
- Do not add telemetry, remote analytics, a hosted dashboard, or a network listener to v0.1.x.
- Dual licensing is MIT OR Apache-2.0. Contributions are accepted under the same terms.
