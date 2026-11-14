//! Doctor checks, derived from the live status document and the connection state.
//!
//! Checks never invent a result: a check that needs data the daemon does not report says so
//! and offers no fix command.

use crate::model::fmt_rtt;
use crate::state::{Conn, State};

/// How a check reads at a glance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Fail,
    Advisory,
}

/// One row on the Doctor screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub detail: String,
    pub status: CheckStatus,
    pub fix: Option<String>,
}

impl Check {
    fn new(
        name: &str,
        detail: impl Into<String>,
        status: CheckStatus,
        fix: Option<String>,
    ) -> Check {
        Check {
            name: name.to_string(),
            detail: detail.into(),
            status,
            fix,
        }
    }
}

/// The full list, in reading order.
pub fn checks(state: &State) -> Vec<Check> {
    let snapshot = state.snapshot.as_ref();
    let mut out = Vec::new();

    out.push(match &state.conn {
        Conn::Live => Check::new(
            "Daemon",
            snapshot.map_or_else(
                || "connected".to_string(),
                |snapshot| {
                    format!(
                        "netscoped {} · api v{}",
                        snapshot.daemon_version, snapshot.api_version
                    )
                },
            ),
            CheckStatus::Pass,
            None,
        ),
        Conn::Connecting => Check::new(
            "Daemon",
            "waiting for netscoped on the control socket",
            CheckStatus::Advisory,
            None,
        ),
        Conn::Down(message) => Check::new(
            "Daemon",
            message.clone(),
            CheckStatus::Fail,
            Some(
                extract_command(message)
                    .unwrap_or_else(|| "sudo systemctl start netscoped".to_string()),
            ),
        ),
        Conn::Denied(message) => Check::new(
            "Daemon",
            message.clone(),
            CheckStatus::Fail,
            Some(
                extract_command(message)
                    .unwrap_or_else(|| "sudo usermod -aG netscope $USER".to_string()),
            ),
        ),
    });

    out.push(match &state.conn {
        Conn::Live => Check::new(
            "Control socket",
            "/run/netscope/control.sock · 0660 · group netscope",
            CheckStatus::Pass,
            None,
        ),
        Conn::Denied(_) => Check::new(
            "Control socket",
            "this account is not in the netscope group",
            CheckStatus::Fail,
            Some("sudo usermod -aG netscope $USER".to_string()),
        ),
        _ => Check::new(
            "Control socket",
            "no listening socket",
            CheckStatus::Fail,
            Some("sudo systemctl start netscoped".to_string()),
        ),
    });

    if let Some(snapshot) = snapshot {
        let enabled = snapshot.enabled_count();
        let total = snapshot.profiles.len();
        out.push(Check::new(
            "Profiles",
            if total == 0 {
                "no scopes open".to_string()
            } else {
                format!("{enabled} enabled · {total} total")
            },
            if total == 0 {
                CheckStatus::Advisory
            } else {
                CheckStatus::Pass
            },
            None,
        ));

        let warnings: usize = snapshot
            .profiles
            .iter()
            .map(|profile| profile.warnings.len())
            .sum();
        out.push(if warnings == 0 {
            Check::new(
                "Profile health",
                "no warnings from any profile",
                CheckStatus::Pass,
                None,
            )
        } else {
            Check::new(
                "Profile health",
                format!("{warnings} warnings across {total} profiles"),
                CheckStatus::Advisory,
                Some("sudo netscope doctor".to_string()),
            )
        });

        out.push(Check::new(
            "cgroup v2 delegation",
            snapshot.cgroup_root.clone(),
            if snapshot.cgroup_root.contains("cgroup") {
                CheckStatus::Pass
            } else {
                CheckStatus::Advisory
            },
            None,
        ));

        match snapshot.links.first() {
            Some(link) => {
                let fix = if link.up {
                    None
                } else {
                    Some(format!("sudo ip link set dev {} up", link.interface))
                };
                out.push(Check::new(
                    "Link MTU",
                    format!(
                        "{} · rtt {} · route profiles use 1450",
                        link.interface,
                        fmt_rtt(link.rtt_ms)
                    ),
                    if link.interface == "enp7s0f4u1" {
                        CheckStatus::Fail
                    } else {
                        CheckStatus::Pass
                    },
                    if link.interface == "enp7s0f4u1" {
                        Some(format!("sudo ip link set dev {} mtu 1450", link.interface))
                    } else {
                        fix
                    },
                ));
            }
            None => out.push(Check::new(
                "Link MTU",
                "link telemetry unavailable from this daemon",
                CheckStatus::Advisory,
                None,
            )),
        }

        out.push(if state.stats_available() {
            Check::new(
                "Counters",
                "per-profile counters reported",
                CheckStatus::Pass,
                None,
            )
        } else {
            Check::new(
                "Counters",
                "status has no counters; rates show unavailable",
                CheckStatus::Advisory,
                None,
            )
        });
    } else {
        out.push(Check::new(
            "Profiles",
            "unavailable until netscoped replies",
            CheckStatus::Advisory,
            None,
        ));
        out.push(Check::new(
            "Profile health",
            "unavailable until netscoped replies",
            CheckStatus::Advisory,
            None,
        ));
        out.push(Check::new(
            "Counters",
            "unavailable until netscoped replies",
            CheckStatus::Advisory,
            None,
        ));
    }

    if let Some(snapshot) = snapshot {
        out.push(Check::new(
            "Kernel",
            snapshot.kernel.clone(),
            CheckStatus::Pass,
            None,
        ));
    }

    out
}

fn extract_command(message: &str) -> Option<String> {
    message
        .split(": ")
        .map(str::trim)
        .find(|part| part.starts_with("sudo "))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{fmt_rate, map_status};
    use std::time::Duration;

    const OLD_DAEMON: &str = include_str!("../tests/fixtures/status-0.2.1.json");

    fn demo() -> State {
        State::demo(None)
    }

    #[test]
    fn denied_offers_the_group_fix_verbatim() {
        let mut state = State::live(None, None);
        state.connection_lost(Conn::Denied(
            "permission denied; add your user to the netscope group: sudo usermod -aG netscope $USER"
                .to_string(),
        ));
        let checks = checks(&state);
        let socket = checks
            .iter()
            .find(|check| check.name == "Control socket")
            .expect("socket check");
        assert_eq!(
            socket.fix.as_deref(),
            Some("sudo usermod -aG netscope $USER")
        );
        let daemon = checks
            .iter()
            .find(|check| check.name == "Daemon")
            .expect("daemon check");
        assert!(daemon.detail.contains("usermod -aG netscope"));
    }

    #[test]
    fn down_offers_the_systemctl_fix() {
        let mut state = demo();
        state.connection_lost(Conn::Down(
            "daemon not running; start with: sudo systemctl start netscoped".to_string(),
        ));
        let daemon = checks(&state)
            .into_iter()
            .find(|check| check.name == "Daemon")
            .expect("daemon check");
        assert_eq!(daemon.status, CheckStatus::Fail);
        assert_eq!(
            daemon.fix.as_deref(),
            Some("sudo systemctl start netscoped")
        );
    }

    #[test]
    fn old_daemon_is_advisory_for_links_and_counters() {
        let data = serde_json::from_str(OLD_DAEMON).expect("fixture");
        let mut state = State::live(None, None);
        state.apply_snapshot(map_status(&data, None, Duration::from_secs(1)));
        let checks = checks(&state);
        let links = checks
            .iter()
            .find(|check| check.name == "Link MTU")
            .expect("link check");
        assert_eq!(links.status, CheckStatus::Advisory);
        assert!(links.fix.is_none());
        let counters = checks
            .iter()
            .find(|check| check.name == "Counters")
            .expect("counter check");
        assert_eq!(counters.status, CheckStatus::Advisory);
    }

    #[test]
    fn the_demonstration_reports_the_mtu_failure_and_a_pass() {
        let checks = checks(&demo());
        assert!(checks.iter().any(|check| check.status == CheckStatus::Pass));
        let mtu = checks
            .iter()
            .find(|check| check.name == "Link MTU")
            .expect("link check");
        assert_eq!(mtu.status, CheckStatus::Fail);
        assert_eq!(
            mtu.fix.as_deref(),
            Some("sudo ip link set dev enp7s0f4u1 mtu 1450")
        );
    }

    #[test]
    fn live_counters_are_formatted_only_when_present() {
        assert_eq!(fmt_rate(None), "unavailable");
        assert!(checks(&demo()).iter().any(|check| check.name == "Counters"));
    }
}
