//! Fallback process discovery for fanotify-less environments and rescan.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;

use crate::types::{Profile, Target};

const ENVIRON_LIMIT: u64 = 64 * 1024;

/// Native targets currently running under their configured executable.
pub fn scan_native(profiles: &[Profile]) -> Vec<(String, u32)> {
    let mut found = Vec::new();
    for pid in pids() {
        if pid == 1 || pid == std::process::id() {
            continue;
        }
        let Some((dev, ino)) = exe_ids(pid) else {
            continue;
        };
        let Some(uid) = crate::cgroup::read_uid(pid) else {
            continue;
        };
        for profile in profiles {
            if matches_native(&profile.target, profile.target_uid, uid, dev, ino) {
                found.push((profile.id.clone(), pid));
            }
        }
    }
    found
}

/// Steam targets currently running with a matching app/game id in `/proc`.
pub fn scan_steam(profiles: &[Profile]) -> Vec<(String, u32)> {
    let mut found = Vec::new();
    for pid in pids() {
        if pid == 1 || pid == std::process::id() {
            continue;
        }
        let Some(ids) = steam_ids_of(pid) else {
            continue;
        };
        let Some(uid) = crate::cgroup::read_uid(pid) else {
            continue;
        };
        for profile in profiles {
            if matches_steam(&profile.target, profile.target_uid, uid, &ids) {
                found.push((profile.id.clone(), pid));
            }
        }
    }
    found
}

pub fn start_time(pid: u32) -> Option<u64> {
    crate::cgroup::read_start_time(pid)
}

fn matches_native(target: &Target, target_uid: u32, uid: u32, dev: u64, ino: u64) -> bool {
    target_uid == uid
        && matches!(
            target,
            Target::Native { dev: target_dev, ino: target_ino, .. }
                if *target_dev == dev && *target_ino == ino
        )
}

fn matches_steam(target: &Target, target_uid: u32, uid: u32, ids: &[u32]) -> bool {
    target_uid == uid
        && matches!(
            target,
            Target::Steam { app_id } if ids.contains(app_id)
        )
}

fn pids() -> Vec<u32> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse().ok())
        .collect()
}

fn exe_ids(pid: u32) -> Option<(u64, u64)> {
    // Opening the symlink pins the inode, so metadata cannot race a later exec.
    let file = fs::File::open(format!("/proc/{pid}/exe")).ok()?;
    let metadata = file.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

fn steam_ids_of(pid: u32) -> Option<Vec<u32>> {
    let file = fs::File::open(format!("/proc/{pid}/environ")).ok()?;
    let mut environ = Vec::new();
    file.take(ENVIRON_LIMIT).read_to_end(&mut environ).ok()?;
    Some(steam_ids(&environ))
}

fn steam_ids(environ: &[u8]) -> Vec<u32> {
    let mut ids = Vec::new();
    for entry in environ.split(|byte| *byte == 0) {
        let value = entry
            .strip_prefix(b"SteamAppId=")
            .or_else(|| entry.strip_prefix(b"SteamGameId="));
        let Some(value) = value else {
            continue;
        };
        if let Ok(id) = std::str::from_utf8(value).unwrap_or_default().parse() {
            ids.push(id);
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steam_env_parses_nul_delimited_ids() {
        let environ = b"PATH=/usr/bin\0SteamAppId=480\0SteamGameId=730\0";
        assert_eq!(steam_ids(environ), vec![480, 730]);
    }

    #[test]
    fn steam_env_ignores_prefixed_and_invalid_tokens() {
        let environ = b"XSteamAppId=1\0SteamAppId=abc\0SteamGameId=570\0";
        assert_eq!(steam_ids(environ), vec![570]);
    }

    #[test]
    fn current_process_has_start_time() {
        assert!(start_time(std::process::id()).is_some_and(|time| time > 0));
    }

    #[test]
    fn target_matching_respects_uid_and_identity() {
        let native = Target::Native {
            path: "/bin/true".into(),
            dev: 42,
            ino: 7,
        };
        assert!(matches_native(&native, 1000, 1000, 42, 7));
        assert!(!matches_native(&native, 1000, 1001, 42, 7));
        assert!(!matches_native(&native, 1000, 1000, 42, 8));

        let steam = Target::Steam { app_id: 480 };
        assert!(matches_steam(&steam, 1000, 1000, &[480]));
        assert!(!matches_steam(&steam, 1000, 1001, &[480]));
        assert!(!matches_steam(&steam, 1000, 1000, &[730]));
        assert!(!matches_native(&steam, 1000, 1000, 42, 7));
        assert!(!matches_steam(&native, 1000, 1000, &[42]));
    }
}
