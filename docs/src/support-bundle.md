# Support bundle

`netscope support-bundle` collects the diagnostics needed to investigate a bug into one archive. It is the fastest way to give a maintainer the daemon's view of the host without a screen-sharing session.

```sh
sudo netscope support-bundle
sudo netscope support-bundle --include-logs --include-config
```

`support-bundle` is root-only; a non-root run exits `4` with `netscope: support-bundle requires root: sudo netscope support-bundle`. The one exception is `--no-redact` without `--acknowledge`, which exits `2` before the root check runs. Without `--output`, it writes:

```text
/tmp/netscope-support-<UTC>.tar.zst
```

For example `/tmp/netscope-support-20261030T221500Z.tar.zst`. On success it prints the path and a reminder:

```text
support bundle: /tmp/netscope-support-20261030T221500Z.tar.zst
review before uploading
```

The archive is mode `0600`. When run through `sudo`, it is chowned back to `SUDO_UID:SUDO_GID` so your normal user can read it. With `--output <path>`, the same permissions apply at the path you choose.

## Options

| Option | Effect |
|---|---|
| `--output <path>` | Write the archive here instead of `/tmp/netscope-support-<UTC>.tar.zst`. |
| `--include-logs` | Include `logs.txt` with recent `netscoped` journal lines. Omitted by default. |
| `--include-config` | Include `config.toml`. Omitted by default. |
| `--no-redact` | Disable redaction. Refused unless `--acknowledge` is also given. |
| `--acknowledge` | Confirm that an unredacted bundle may contain sensitive system information. |

Redaction is on by default. `--no-redact` without `--acknowledge` exits `2` before writing anything; that validation runs before the root check, so a non-root `--no-redact` run also exits `2`, not `4`.

## Contents

The archive contains one top-level directory, `netscope-support-<UTC>/`. All members are inside it.

| Member | Contents |
|---|---|
| `README.txt` | Review-before-upload warning and a statement that the bundle is never uploaded automatically. |
| `manifest.json` | Machine-readable manifest: `generated_by`, `generated_at`, `files`, redaction settings and labels, and excluded categories. |
| `version.txt` | `netscope` and `netscoped` versions, API version, and build identity. |
| `doctor.txt` | The human-readable `netscope doctor` report. |
| `doctor.json` | The same report as JSON. |
| `status.json` | Daemon status and profile status, including attach source and PIDs. Present when the daemon is reachable. |
| `list.json` | The daemon's profile list response. Present when the daemon is reachable. |
| `system.txt` | Kernel, distribution, architecture, cgroup mode, and tool versions. |
| `service.txt` | `systemctl status netscoped` and the unit's effective state. |
| `logs.txt` | Recent journal lines for `netscoped`. Present only with `--include-logs`. |
| `nft.txt` | The `netscope_*` nftables tables only, not your full ruleset. |
| `ip.txt` | `ip rule` and the netscope route tables. |
| `cgroups.txt` | The netscope cgroup hierarchy and profile membership. |
| `config.toml` | The daemon configuration. Present only with `--include-config`. |
| `state.json` | The profile state file, when it exists. |
| `profiles/` | Report files under the state directory's `profiles/` tree, when present. |
| `late/` | Report files under the state directory's `late/` tree, when present. |
| `errors.txt` | Present only if a collection step failed or reported a warning; lists which step and why. |

## What is deliberately excluded

The bundle does **not** include:

- `/proc` contents, shell history, and arbitrary home-directory files;
- `/etc/passwd`, `/etc/shadow`, or any account database;
- SSH keys or other private keys;
- environment dumps;
- packet captures;
- browser data;
- core dumps;
- your complete nftables ruleset or complete routing table.

## Redaction

Before writing the archive, the collector replaces sensitive values:

| Value | Replaced with |
|---|---|
| Your home directory (`$HOME`, `/home/<user>`, `/root`) | `<home>` |
| Username | `<user>` |
| Hostname | `<host>` |
| Profile names | `<profile-1>`, `<profile-2>`, … |
| Secret-key values in config or state | `[REDACTED]` |
| JWT and long hexadecimal/base64-looking tokens | `<redacted>` |
| MAC addresses | `[MAC]` |
| Link-local IPv6 addresses | `<link-local>` |

Redaction is best effort. Paths outside your home directory, interface names, and most IPv4 and IPv6 addresses remain because they are usually necessary to diagnose routing and attachment problems. Profile names are replaced with numbered placeholders. **Review the archive before uploading it.**

## Review before uploading

Extract to a temporary directory and read the text files:

```sh
mkdir -p /tmp/netscope-review
tar --zstd -xf /tmp/netscope-support-*.tar.zst -C /tmp/netscope-review
ls -la /tmp/netscope-review/netscope-support-*/
```

Check at least:

- `README.txt`, `manifest.json`, and `errors.txt` for what was collected or failed;
- `state.json` and `config.toml` for paths or names you do not want public;
- `logs.txt` for unrelated messages from other services;
- `ip.txt` and `nft.txt` for addresses or interface names you consider private.

`config.toml` and `logs.txt` are absent unless you passed `--include-config` and `--include-logs`.

Remove the archive and the extracted directory when you are done:

```sh
rm -rf /tmp/netscope-review /tmp/netscope-support-*.tar.zst
```

## Attaching to an issue

Attach the `.tar.zst` file to the bug report. Include:

- the exact command that failed, copied verbatim;
- what you expected and what happened;
- whether the profile used filter or route mode;
- whether the app was already running when the profile was added.

The [bug report form](https://github.com/Qiiks/netscope/issues/new?template=bug.yml) asks for these. For a security issue, do not attach the bundle to a public issue; use the private advisory link in [Security](security.md).

## If collection fails

`errors.txt` names the step that failed. Common causes:

- the daemon is not running, so status and logs are incomplete;
- `/tmp` is full or mounted noexec;
- the journal is not readable.

The archive is still written with whatever was collected. Fix the cause and rerun if the missing part matters.
