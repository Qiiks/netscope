# Configuration

The daemon reads one TOML file, `/etc/netscope/config.toml`. It is root-owned and intended to be edited only by an administrator.

The shipped default is:

```toml
[daemon]
socket_path = "/run/netscope/control.sock"
state_path = "/var/lib/netscope/state.json"
cgroup_root = "/sys/fs/cgroup/netscope"
poll_interval_ms = 1000
refresh_interval_secs = 5
max_profiles = 32
log_level = "info"
```

## Keys

| Key | Default | Meaning |
|---|---|---|
| `socket_path` | `/run/netscope/control.sock` | Unix socket for CLI requests. Root-owned, group `netscope`, mode `0660`. |
| `state_path` | `/var/lib/netscope/state.json` | Persistent profile state. Do not edit it by hand. |
| `cgroup_root` | `/sys/fs/cgroup/netscope` | Parent cgroup for profiles. It must be an absolute path inside `/sys/fs/cgroup`. |
| `poll_interval_ms` | `1000` | How often the late-attach scanner looks for matching processes. Bounded to 100–10000 ms. |
| `refresh_interval_secs` | `5` | How often targets are re-resolved and matching processes are attached. Bounded to 1–300. |
| `max_profiles` | `32` | Profile ceiling, 1–32. Lowering it prevents new profiles above the new limit. |
| `log_level` | `info` | `error`, `warn`, `info`, `debug`, or `trace`. |

Unknown keys are rejected. The file is parsed with `deny_unknown_fields`, so a typo such as `poll_interval` stops the daemon instead of being silently ignored. Check the journal after editing:

```sh
sudo systemctl restart netscoped
systemctl status netscoped
journalctl -u netscoped -n 50 --no-pager
```

`systemctl reload` is not used. Editing the file requires a restart, which also re-reads the profile state.

## Changing the socket or state path

Both paths are created and owned by the daemon. If you move `socket_path`, update the directory's permissions so the `netscope` group can reach it, and restart the daemon. If you move `state_path`, move the existing state file first or the daemon starts with no profiles.

The CLI accepts a hidden `--socket <path>` override. It exists for tests and for a daemon started with a non-default path; it is not needed in normal use.

## Changing the cgroup root

`cgroup_root` must remain under `/sys/fs/cgroup`, because the nftables selector is built from the path relative to the cgroup mount. A value outside the cgroup2 hierarchy is rejected at startup. If you change the cgroup root while profiles are active, the old directory is left behind; stop the daemon, remove the old directory, and start it again.

## State file

`state_path` holds a versioned JSON document with one entry per profile. It stores the target path and inode identity, the mode, the profile's mark, table, priority, and index, and timestamps. The daemon owns it:

- Do not edit it while `netscoped` is running.
- Back it up before an upgrade if you have profiles you cannot recreate easily.
- A state version newer than the daemon is rejected rather than partially loaded.
- Deleting it while the daemon is stopped removes all profile definitions. The host rules can be cleaned with `sudo netscope cleanup --all` before starting the daemon again.

## Limits

- At most 32 profiles, regardless of `max_profiles`. Lowering `max_profiles` does not delete existing profiles, but adding beyond the limit fails.
- Profile IDs are 1–32 characters: `[a-z0-9][a-z0-9-]*`.
- Marks, tables, and rule priorities are allocated from fixed ranges. Exhausting the 32 indexes fails the add. A route table already in use is refused rather than shared.
- One profile has one mode. Editing a profile means remove and add.

## Logging

Runtime logs go to the journal:

```sh
journalctl -u netscoped -f
netscope logs -n 100
```

`netscope logs` is a bounded view (default 50 lines, `-n` to change it). It does not follow. Raw daemon logs may include profile paths and interface names but never packet contents.

## Example: quieter polling

For a machine with many processes, reduce wakeups by polling less often. Pre-exec attachment is unaffected; only late attachment gets slower.

```toml
[daemon]
poll_interval_ms = 2000
refresh_interval_secs = 10
log_level = "warn"
```

Restart after the change and confirm with `sudo netscope doctor`.
