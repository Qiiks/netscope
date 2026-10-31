# Contributing

Contributions are welcome. netscope is alpha software with a deliberately small scope: per-application filtering and routing on Linux with cgroups, nftables, and policy routing.

## Licensing and sign-off

netscope is dual-licensed under MIT OR Apache-2.0. Contributions are accepted under the same terms.

Every commit must carry a Developer Certificate of Origin sign-off:

```sh
git commit -s
```

The sign-off certifies the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Use your real name and an email address you can receive mail at. A pull request with unsigned commits is not merged.

## Set up

You need a Linux host with kernel 5.13 or newer, cgroup v2, nftables, iproute2, systemd, and a Rust toolchain. The repository's `rust-toolchain.toml` selects the toolchain; `rustup` honors it automatically.

```sh
git clone https://github.com/Qiiks/netscope
cd netscope
cargo build --workspace
mdbook build docs
```

The workspace has three crates:

- `crates/netscope-linux` — the reusable engine: cgroups, nftables, policy routing, fanotify, and process scanning.
- `crates/netscope-daemon` — the root daemon: JSON-lines socket, reconciliation, health loop, attach provenance.
- `crates/netscope-cli` — the unprivileged CLI and diagnostics.

The public types live in `crates/netscope-linux/src/types.rs` and `protocol.rs`. They are a stable interface for downstream consumers; change them deliberately.

## Checks

Run the same checks CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --workspace
mdbook build docs
```

Clippy warnings are errors. A change that adds a warning is not merged.

## Privileged changes

Some behavior can only be verified as root: cgroup attachment, nftables rule installation, policy routing, and the fanotify exec hook. CI runs unprivileged, so a change that touches those paths needs a manual verification note in the pull request: the commands you ran, the kernel and distribution, and the observed result. The integration suite is:

```sh
sudo cargo test -p netscope-daemon --test privileged -- --ignored --test-threads=1
```

Do not run privileged tests on a host with a live netscope service; stop it first, and inspect `netscope_*` nftables tables, `20000`–`20031` route tables, and the profile cgroups afterward.

## Pull requests

- Keep the change focused. Separate refactors from behavior changes.
- Add a test for a behavior change, or explain why it cannot be tested without root.
- Include the commands you ran to verify the change.
- Update the docs in `docs/src` when behavior or the CLI changes. The docs are part of the change.
- Do not add telemetry, remote analytics, a hosted dashboard, or a network listener to v0.1.x.
- Do not add a wrapper, `LD_PRELOAD` shim, or proxy auto-configuration. The no-wrapper property is a design constraint.
- Keep error messages actionable and free of secrets. UI text must not expose tokens or internal paths.

## Commit messages

Use the imperative mood and a short subject:

```text
Add IPv6 blackhole check to route reconciliation

Explain why the check is needed and what changed. Wrap the body at 72
columns. Reference an issue with "Fixes #123" when applicable.
```

Sign off with `git commit -s`.

## Reporting bugs and security issues

- Bugs: use the [bug report form](https://github.com/Qiiks/netscope/issues/new?template=bug.yml) and attach a reviewed [support bundle](support-bundle.md).
- Features: use the [feature request form](https://github.com/Qiiks/netscope/issues/new?template=feature.yml).
- Vulnerabilities: do not open a public issue. Use [GitHub Security Advisories](https://github.com/Qiiks/netscope/security/advisories/new).
