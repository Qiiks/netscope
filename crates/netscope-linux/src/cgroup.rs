use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::types::profile_id_valid;
pub use crate::types::AttachSource;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Error)]
pub enum CgroupError {
    #[error("invalid profile id")]
    InvalidId,
    #[error("cgroup io: {0}")]
    Io(#[from] std::io::Error),
    #[error("process {0} is gone")]
    ProcessGone(u32),
    #[error("pid {0} was reused during attach")]
    PidReused(u32),
    #[error("cgroup {0} does not exist")]
    Missing(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachOutcome {
    pub tgid: u32,
}

#[derive(Debug)]
pub struct CgroupManager {
    root: PathBuf,
    original: Mutex<HashMap<u32, String>>,
}

impl CgroupManager {
    pub fn new(root: PathBuf) -> Result<Self, CgroupError> {
        let path = root.to_string_lossy();
        if !path.starts_with(CGROUP_ROOT) {
            return Err(CgroupError::Missing(format!(
                "cgroup_root must be under {CGROUP_ROOT}"
            )));
        }
        if root
            .components()
            .any(|component| component.as_os_str() == "..")
        {
            return Err(CgroupError::Missing(
                "cgroup_root must not contain ..".to_string(),
            ));
        }
        Ok(Self {
            root,
            original: Mutex::new(HashMap::new()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn relative_root(&self) -> PathBuf {
        self.root
            .strip_prefix(CGROUP_ROOT)
            .unwrap_or(Path::new(""))
            .to_path_buf()
    }

    pub fn ensure_root(&self) -> Result<(), CgroupError> {
        fs::create_dir_all(&self.root)?;
        Ok(())
    }

    pub fn profile_path(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn ensure_profile(&self, id: &str) -> Result<PathBuf, CgroupError> {
        if !profile_id_valid(id) {
            return Err(CgroupError::InvalidId);
        }
        let path = self.profile_path(id);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    pub fn attach_pid(
        &self,
        id: &str,
        pid: u32,
        _source: AttachSource,
    ) -> Result<AttachOutcome, CgroupError> {
        let tgid = read_tgid(pid)?;
        let start = read_start_time(tgid).ok_or(CgroupError::ProcessGone(pid))?;
        let original = read_cgroup_path(tgid);
        {
            let mut map = self.original.lock().expect("cgroup original lock");
            map.insert(tgid, original);
        }

        let procs = self.profile_path(id).join("cgroup.procs");
        if let Err(err) = write_pid(&procs, tgid) {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Err(CgroupError::ProcessGone(pid));
            }
            return Err(CgroupError::Io(err));
        }

        if read_start_time(tgid) != Some(start) {
            self.restore_tgid(tgid);
            return Err(CgroupError::PidReused(pid));
        }

        Ok(AttachOutcome { tgid })
    }

    pub fn attach_tree(
        &self,
        root_pid: u32,
        id: &str,
        source: AttachSource,
    ) -> Result<Vec<u32>, CgroupError> {
        let mut attached = Vec::new();
        let mut queue = VecDeque::from([root_pid]);
        let mut seen = HashSet::new();
        while let Some(pid) = queue.pop_front() {
            if !seen.insert(pid) {
                continue;
            }
            match self.attach_pid(id, pid, source) {
                Ok(outcome) => attached.push(outcome.tgid),
                Err(CgroupError::ProcessGone(_)) => continue,
                Err(err) => return Err(err),
            }
            if let Ok(children) = read_children(pid) {
                queue.extend(children);
            }
        }
        Ok(attached)
    }

    pub fn procs(&self, id: &str) -> Result<Vec<u32>, CgroupError> {
        let path = self.profile_path(id).join("cgroup.procs");
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(CgroupError::Io(err)),
        };
        Ok(text
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect())
    }

    pub fn drain(&self, id: &str) -> Result<(), CgroupError> {
        let pids = self.procs(id)?;
        for pid in pids {
            let target = {
                let mut map = self.original.lock().expect("cgroup original lock");
                map.remove(&pid)
            };
            let dir = target
                .filter(|path| self.restorable(path))
                .unwrap_or_else(|| CGROUP_ROOT.to_string());
            let path = Path::new(&dir).join("cgroup.procs");
            for attempt in 0..3 {
                match write_pid(&path, pid) {
                    Ok(()) => {
                        tracing::info!(pid, cgroup = %path.display(), "restored");
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                    Err(err) if err.raw_os_error() == Some(libc::ESRCH) => break,
                    Err(err) if attempt == 2 => return Err(CgroupError::Io(err)),
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        }
        Ok(())
    }

    pub fn remove(&self, id: &str) -> Result<(), CgroupError> {
        self.drain(id)?;
        let path = self.profile_path(id);
        for attempt in 0..3 {
            match fs::remove_dir(&path) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) if attempt == 2 => return Err(CgroupError::Io(err)),
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
        Ok(())
    }

    pub fn original_path(&self, pid: u32) -> Option<String> {
        self.original
            .lock()
            .expect("cgroup original lock")
            .get(&pid)
            .cloned()
    }

    fn restorable(&self, path: &str) -> bool {
        let path = Path::new(path);
        if path.starts_with(&self.root) {
            return false;
        }
        path.join("cgroup.procs").is_file()
    }

    fn restore_tgid(&self, tgid: u32) {
        let target = self
            .original
            .lock()
            .expect("cgroup original lock")
            .get(&tgid)
            .cloned();
        let dir = target
            .filter(|path| self.restorable(path))
            .unwrap_or_else(|| CGROUP_ROOT.to_string());
        let _ = write_pid(&Path::new(&dir).join("cgroup.procs"), tgid);
    }
}

pub fn read_cgroup_path(pid: u32) -> String {
    let path = format!("/proc/{pid}/cgroup");
    let Ok(text) = fs::read_to_string(path) else {
        return format!("{CGROUP_ROOT}/cgroup.procs");
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let relative = rest.trim();
            if relative == "/" || relative.is_empty() {
                return CGROUP_ROOT.to_string();
            }
            return format!("{CGROUP_ROOT}{relative}");
        }
    }
    format!("{CGROUP_ROOT}/cgroup.procs")
}

pub fn read_tgid(pid: u32) -> Result<u32, CgroupError> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| CgroupError::ProcessGone(pid))?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            return value
                .trim()
                .parse::<u32>()
                .map_err(|_| CgroupError::ProcessGone(pid));
        }
    }
    Err(CgroupError::ProcessGone(pid))
}

pub fn read_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            return value.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

pub fn read_start_time(pid: u32) -> Option<u64> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    let rest = text.get(close + 2..)?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn read_children(pid: u32) -> std::io::Result<Vec<u32>> {
    let mut children = Vec::new();
    let task_dir = format!("/proc/{pid}/task");
    for entry in fs::read_dir(task_dir)? {
        let entry = entry?;
        let tid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(tid) => tid,
            Err(_) => continue,
        };
        let path = format!("/proc/{pid}/task/{tid}/children");
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        children.extend(
            text.split_whitespace()
                .filter_map(|value| value.parse::<u32>().ok()),
        );
    }
    Ok(children)
}

fn write_pid(path: &Path, pid: u32) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(format!("{pid}\n").as_bytes())?;
    file.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_path_parses_current_process() {
        let path = read_cgroup_path(std::process::id());
        assert!(path.starts_with(CGROUP_ROOT));
    }

    #[test]
    fn rejects_root_outside_cgroup2() {
        assert!(CgroupManager::new(PathBuf::from("/tmp/netscope")).is_err());
    }

    #[test]
    fn relative_root_is_relative_to_cgroup_mount() {
        let manager =
            CgroupManager::new(PathBuf::from("/sys/fs/cgroup/netscope")).expect("valid root");
        assert_eq!(manager.relative_root(), PathBuf::from("netscope"));
    }
}
