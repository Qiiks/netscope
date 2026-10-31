//! Fallback process discovery for fanotify-less environments and rescan.

use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

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

/// Wine targets whose PE path appears in a running Wine process's cmdline.
pub fn scan_wine(profiles: &[Profile]) -> Vec<(String, u32)> {
    let mut found = Vec::new();
    for pid in pids() {
        if pid == 1 || pid == std::process::id() {
            continue;
        }
        for profile in profiles {
            if wine_pid_matches(profile, pid) {
                found.push((profile.id.clone(), pid));
            }
        }
    }
    found
}

/// True when `pid` is a Wine process running the profile's PE.
pub fn wine_pid_matches(profile: &Profile, pid: u32) -> bool {
    let Target::Wine { path, .. } = &profile.target else {
        return false;
    };
    if !is_wine_process(pid) {
        return false;
    }
    let Some(uid) = crate::cgroup::read_uid(pid) else {
        return false;
    };
    if uid != profile.target_uid {
        return false;
    }
    let Some(args) = cmdline(pid) else {
        return false;
    };
    args.iter().any(|arg| wine_arg_matches(path, arg))
}

/// Name targets currently running with a matching process name or argv basename.
///
/// This is the target kind for a running app whose install path the operator
/// does not want to store: a native process matches its `comm` or argv[0]
/// basename, and a Wine/Proton game matches the PE basename in its argv.
pub fn scan_name(profiles: &[Profile]) -> Vec<(String, u32)> {
    let mut found = Vec::new();
    for pid in pids() {
        if pid == 1 || pid == std::process::id() {
            continue;
        }
        let Some(uid) = crate::cgroup::read_uid(pid) else {
            continue;
        };
        for profile in profiles {
            if name_pid_matches(profile, uid, pid) {
                found.push((profile.id.clone(), pid));
            }
        }
    }
    found
}

/// True when `pid` is a process the name target selects.
pub fn name_pid_matches(profile: &Profile, uid: u32, pid: u32) -> bool {
    let Target::Name { name } = &profile.target else {
        return false;
    };
    profile.target_uid == uid && process_name_matches(name, pid)
}

fn process_name_matches(name: &str, pid: u32) -> bool {
    let needle = norm_name(name);
    if needle.is_empty() {
        return false;
    }
    let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|text| norm_name(text.trim()))
        .unwrap_or_default();
    if comm == needle {
        return true;
    }
    let args = cmdline(pid).unwrap_or_default();
    if args
        .first()
        .is_some_and(|arg| arg_name_matches(&needle, arg))
    {
        return true;
    }
    // Wine carries the PE in argv, not as its own executable name. Only a
    // Wine loader may match an argument beyond argv[0]; otherwise a command
    // line that merely mentions the game name would be attached. Check the
    // cheap argv match first: reading /proc/PID/exe for every process on the
    // system is what made the poll expensive.
    args.iter().any(|arg| arg_name_matches(&needle, arg)) && is_wine_process(pid)
}

/// Compare one argv token by basename, accepting the `C:\...` and `Z:\...`
/// shapes Wine uses. A name target carries no directory at all.
fn arg_name_matches(needle: &str, arg: &str) -> bool {
    let token = arg.rsplit(['/', '\\']).next().unwrap_or(arg);
    norm_name(token) == needle
}

/// A name compares case-folded with a trailing `.exe` dropped. `Overwatch`,
/// `Overwatch.exe`, and `overwatch.exe` are the same target.
fn norm_name(name: &str) -> String {
    let lower = name.trim().to_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// True when `pid` runs one of the Wine loader/server executables.
pub fn is_wine_process(pid: u32) -> bool {
    let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let Some(name) = exe.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name,
        "wine" | "wine64" | "wine-preloader" | "wine64-preloader"
    ) || name.contains("wine-preloader")
}

/// True when `pid` is the shared Wine server. It serves every app in a
/// prefix, so it must never be moved into a game's cgroup.
pub fn is_wineserver(pid: u32) -> bool {
    fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|exe| {
            exe.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .is_some_and(|name| name.starts_with("wineserver"))
}

pub fn start_time(pid: u32) -> Option<u64> {
    crate::cgroup::read_start_time(pid)
}

/// Wine loader binaries that can start a game. The daemon holds their exec
/// before the loader opens the PE, which is the only race-free moment for a
/// name target: the PE path is not known until the launcher's command line is
/// visible.
pub fn wine_loader_files() -> Vec<(PathBuf, u64, u64)> {
    let mut candidates = Vec::new();
    for name in [
        "/usr/bin/wine",
        "/usr/bin/wine64",
        "/usr/bin/wine-preloader",
        "/usr/bin/wine64-preloader",
        "/usr/lib/wine/wine",
        "/usr/lib/wine/wine64",
    ] {
        candidates.push(PathBuf::from(name));
    }

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !name.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(exe) = fs::read_link(entry.path().join("exe")) {
                if is_wine_loader(&exe) {
                    candidates.push(exe);
                }
            }
        }
    }

    for root in [
        "/usr/share/steam/compatibilitytools.d",
        "/usr/local/share/steam/compatibilitytools.d",
        "/opt",
    ] {
        push_tree_wine(std::path::Path::new(root), &mut candidates);
    }

    if let Ok(homes) = fs::read_dir("/home") {
        for home in homes.flatten() {
            let home = home.path();
            for root in [
                home.join(".local/share/lutris/runners/wine"),
                home.join(".local/share/bottles/runners"),
                home.join(".config/heroic/tools/wine"),
                home.join(".local/share/heroic/tools/wine"),
                home.join(".steam/steam/compatibilitytools.d"),
                home.join(".local/share/Steam/compatibilitytools.d"),
                home.join(".steam/steam/steamapps/common"),
                home.join(".local/share/Steam/steamapps/common"),
            ] {
                push_tree_wine(&root, &mut candidates);
            }
            for root in [
                home.join(".steam/steam/steamapps"),
                home.join(".local/share/Steam/steamapps"),
            ] {
                for library in steam_libraries(&root) {
                    push_tree_wine(&library.join("steamapps/common"), &mut candidates);
                }
            }
        }
    }

    let mut files: Vec<(PathBuf, u64, u64)> = candidates
        .into_iter()
        .filter_map(|path| {
            let path = fs::canonicalize(&path).ok()?;
            let metadata = fs::metadata(&path).ok()?;
            if !metadata.is_file() {
                return None;
            }
            Some((path, metadata.dev(), metadata.ino()))
        })
        .collect();
    files.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
    files.dedup_by(|a, b| a.1 == b.1 && a.2 == b.2);
    files
}

/// Additional Steam library roots from `libraryfolders.vdf`. Proton can live
/// on a different mount from the default Steam directory.
fn steam_libraries(root: &std::path::Path) -> Vec<PathBuf> {
    let Ok(text) = fs::read_to_string(root.join("libraryfolders.vdf")) else {
        return Vec::new();
    };
    parse_steam_libraries(&text)
}

fn parse_steam_libraries(text: &str) -> Vec<PathBuf> {
    let mut libraries = Vec::new();
    for line in text.lines() {
        let tokens: Vec<&str> = line.split('"').skip(1).step_by(2).collect();
        for pair in tokens.windows(2) {
            let key = pair[0];
            let value = pair[1];
            // Modern VDF nests `"path" "/mnt/games"`; older files use
            // `"1" "/mnt/games"` directly under `libraryfolders`.
            let looks_like_path = key == "path" || key.chars().all(|ch| ch.is_ascii_digit());
            let path = PathBuf::from(value);
            if looks_like_path && path.is_absolute() {
                libraries.push(path);
            }
        }
    }
    libraries.sort();
    libraries.dedup();
    libraries
}

fn push_tree_wine(root: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        for name in [
            "bin/wine",
            "bin/wine64",
            "bin/wine-preloader",
            "bin/wine64-preloader",
            "dist/bin/wine",
            "dist/bin/wine64",
            "dist/bin/wine-preloader",
            "dist/bin/wine64-preloader",
            "files/bin/wine",
            "files/bin/wine64",
            "files/bin/wine-preloader",
            "files/bin/wine64-preloader",
        ] {
            out.push(dir.join(name));
        }
    }
}

fn is_wine_loader(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "wine" | "wine64" | "wine-preloader" | "wine64-preloader"
            )
        })
}

/// True when the loader's parent command line names the profile's target.
pub fn loader_parent_matches(name: &str, pid: u32) -> bool {
    let needle = norm_name(name);
    if needle.is_empty() {
        return false;
    }
    // The immediate parent can be a short-lived shell or helper; the command
    // that names the game is usually one of the launcher ancestors.
    let mut current = pid;
    for _ in 0..16 {
        let Some(parent) = parent_pid(current) else {
            return false;
        };
        if cmdline(parent)
            .unwrap_or_default()
            .iter()
            .any(|arg| arg_name_matches(&needle, arg))
        {
            return true;
        }
        if parent <= 1 {
            return false;
        }
        current = parent;
    }
    false
}

/// Wine receives the PE on its own command line. The launcher's command line
/// is checked first because it often carries the path the loader resolves;
/// fall back to the loader's own argv.
fn loader_token(needle: &str, parent: u32, pid: u32) -> Option<String> {
    let args: Vec<String> = cmdline(parent)
        .unwrap_or_default()
        .into_iter()
        .chain(cmdline(pid).unwrap_or_default())
        .collect();
    args.iter()
        .find(|arg| arg_name_matches(needle, arg) && path_like(arg))
        .map(|token| token.replace('\\', "/"))
}

fn path_like(token: &str) -> bool {
    let token = token.replace('\\', "/").to_lowercase();
    token.starts_with('/') || token.starts_with("z:/") || token.starts_with("c:/")
}

/// Resolve the PE path from the loader's parent or own command line. Wine
/// receives either a Unix path, `Z:\...` (root), or `C:\...` inside
/// `WINEPREFIX`.
pub fn loader_pe_path(name: &str, pid: u32) -> Option<PathBuf> {
    let needle = norm_name(name);
    let parent = parent_pid(pid)?;
    let token = loader_token(&needle, parent, pid)?;
    let path = if token.starts_with('/') {
        PathBuf::from(&token)
    } else if let Some(rest) = token
        .strip_prefix("Z:/")
        .or_else(|| token.strip_prefix("z:/"))
    {
        PathBuf::from(format!("/{rest}"))
    } else if let Some(rest) = token
        .strip_prefix("C:/")
        .or_else(|| token.strip_prefix("c:/"))
    {
        // The loader's own environment wins: `env WINEPREFIX=… wine …`
        // replaces itself, so only the loader carries the assignment.
        let vars: Vec<String> = [pid, parent].into_iter().flat_map(environ).collect();
        let prefix = vars
            .iter()
            .find_map(|entry| entry.strip_prefix("WINEPREFIX=").map(PathBuf::from))
            .or_else(|| {
                vars.iter()
                    .find_map(|entry| entry.strip_prefix("HOME=").map(PathBuf::from))
                    .map(|home| home.join(".wine"))
            })?;
        prefix.join("drive_c").join(rest)
    } else {
        return None;
    };
    let metadata = fs::metadata(&path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    Some(path)
}

fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn environ(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/environ"))
        .map(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .filter(|entry| !entry.is_empty())
                .map(|entry| String::from_utf8_lossy(entry).into_owned())
                .collect()
        })
        .unwrap_or_default()
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

/// Match one Wine command-line argument against the configured PE path.
///
/// Wine passes the executable path in one of several shapes: the Unix path,
/// a `Z:\` mapping of `/`, a `C:\` path inside the prefix's `drive_c`, or a
/// bare name resolved through `PATH`.
fn wine_arg_matches(target: &str, arg: &str) -> bool {
    let target = target.replace('\\', "/").to_lowercase();
    let arg = arg.replace('\\', "/").to_lowercase();
    if arg.is_empty() {
        return false;
    }
    if arg == target {
        return true;
    }
    if let Some(rest) = arg.strip_prefix("z:/") {
        return target == format!("/{rest}");
    }
    if let Some(rest) = arg.strip_prefix("c:/") {
        return target
            .split_once("/drive_c/")
            .is_some_and(|(_, mapped)| mapped == rest);
    }
    if !arg.contains('/') {
        return target.rsplit('/').next() == Some(arg.as_str());
    }
    false
}

fn cmdline(pid: u32) -> Option<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    Some(
        bytes
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect(),
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
    fn steam_library_paths_parse_modern_and_legacy_vdf() {
        let text = "\"libraryfolders\"\n{\n  \"0\" { \"path\" \"/home/u/.local/share/Steam\" }\n  \"1\" \"/mnt/games/SteamLibrary\"\n}\n";
        let libraries = parse_steam_libraries(text);
        assert_eq!(
            libraries,
            vec![
                PathBuf::from("/home/u/.local/share/Steam"),
                PathBuf::from("/mnt/games/SteamLibrary"),
            ]
        );
        assert!(parse_steam_libraries("\"libraryfolders\" { \"1\" \"relative\" }").is_empty());
    }

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
    fn wine_args_match_linux_and_nt_paths() {
        let target = "/home/u/Games/foo/foo.exe";
        assert!(wine_arg_matches(target, target));
        assert!(wine_arg_matches(target, "Z:\\home\\u\\Games\\foo\\foo.exe"));
        assert!(wine_arg_matches(target, "/HOME/U/games/FOO/FOO.EXE"));
        assert!(wine_arg_matches(target, "foo.exe"));
        assert!(!wine_arg_matches(target, "bar.exe"));
        assert!(!wine_arg_matches(target, "/home/u/Games/bar/foo.exe"));
        assert!(!wine_arg_matches(target, ""));
    }

    #[test]
    fn wine_args_match_drive_c_prefix() {
        let target = "/home/u/.local/share/Steam/steamapps/compatdata/1/pfx/drive_c/Games/foo.exe";
        assert!(wine_arg_matches(target, "C:\\Games\\foo.exe"));
        assert!(!wine_arg_matches(target, "C:\\Games\\bar.exe"));
        assert!(!wine_arg_matches("/opt/foo.exe", "C:\\foo.exe"));
    }

    #[test]
    fn current_process_is_not_wine() {
        assert!(!is_wine_process(std::process::id()));
    }

    #[test]
    fn name_args_match_native_and_wine_basenames() {
        assert!(arg_name_matches("overwatch", "C:\\Games\\Overwatch.exe"));
        assert!(arg_name_matches("overwatch", "Z:\\Games\\Overwatch.exe"));
        assert!(arg_name_matches("overwatch", "/usr/bin/overwatch"));
        assert!(arg_name_matches("overwatch", "Overwatch.exe"));
        assert!(!arg_name_matches("overwatch", "/usr/bin/overwatch-helper"));
        assert!(!arg_name_matches("overwatch", ""));
    }

    #[test]
    fn name_target_ignores_arguments_beyond_argv0() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .arg("decoy-target.exe")
            .spawn()
            .expect("spawn sleep");
        let matched = process_name_matches("decoy-target.exe", child.id());
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            !matched,
            "a command-line argument must not select a process"
        );
    }

    #[test]
    fn name_normalization_drops_exe_and_case() {
        assert_eq!(norm_name(" Overwatch.EXE "), "overwatch");
        assert_eq!(norm_name("Overwatch"), "overwatch");
        assert_eq!(norm_name(".exe"), "");
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
