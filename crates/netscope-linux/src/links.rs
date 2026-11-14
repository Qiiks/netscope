//! Ordered route-link probing and failover selection.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use socket2::{Domain, Protocol, Socket, Type};

use crate::command;
use crate::types::{LinkPhase, LinkStatus, RouteLink};

/// Consecutive failures before a link is taken down.
const FAIL_THRESHOLD: u8 = 3;
/// Consecutive successes before a down link is used again.
const RECOVER_THRESHOLD: u8 = 2;
/// Integer weights for the smoothed round-trip time (`alpha = 0.3`).
const RTT_OLD_WEIGHT: u32 = 7;
const RTT_NEW_WEIGHT: u32 = 3;
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Probe cadence and destinations shared by every route profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeConfig {
    /// Delay between probe rounds.
    pub interval_ms: u64,
    /// IPv4 target tried over TCP.
    pub target: SocketAddr,
    /// Optional IPv6 target, used only when the profile carries IPv6.
    pub target6: Option<SocketAddr>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval_ms: 2000,
            // Parsed from constants so a bad literal fails at build time.
            target: "1.1.1.1:443".parse().expect("probe target is valid"),
            target6: Some(
                "[2606:4700:4700::1111]:443"
                    .parse()
                    .expect("ipv6 probe target is valid"),
            ),
        }
    }
}

/// Result of one probe. A failed probe is a health signal, not an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeOutcome {
    /// The probe completed.
    Up {
        /// Observed round-trip time.
        rtt_ms: Option<u32>,
    },
    /// The probe ran and did not complete.
    Down,
    /// The probe could not run at all, for example because `ping` is missing.
    /// Skipped outcomes leave the link's state untouched.
    Skipped,
}

impl ProbeOutcome {
    /// A completed probe with its measured latency.
    pub fn success(elapsed: Duration) -> Self {
        let millis = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
        Self::Up {
            rtt_ms: Some(millis),
        }
    }

    /// A probe that ran and failed.
    pub const fn failed() -> Self {
        Self::Down
    }

    /// A probe that could not run; not a health signal either way.
    pub const fn skipped() -> Self {
        Self::Skipped
    }
}

/// Consecutive-probe state for one link.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkEntry {
    /// The configured link.
    pub link: RouteLink,
    /// Current probe state.
    pub phase: LinkPhase,
    fails: u8,
    oks: u8,
    /// Smoothed round-trip time, once a probe succeeded.
    pub rtt_ms: Option<u32>,
    /// Unix time of the last successful probe.
    pub last_ok_unix: Option<u64>,
}

/// Failover state for one route profile.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkMonitor {
    /// One entry per configured link, in preference order.
    pub entries: Vec<LinkEntry>,
    /// Index of the link carrying the default route, if any is healthy.
    pub active: Option<usize>,
}

impl LinkMonitor {
    /// Starts optimistic: every link is assumed up and the first one carries
    /// traffic until probes say otherwise.
    pub fn new(links: Vec<RouteLink>) -> Self {
        let entries = links
            .into_iter()
            .map(|link| LinkEntry {
                link,
                phase: LinkPhase::Up,
                fails: 0,
                oks: 0,
                rtt_ms: None,
                last_ok_unix: None,
            })
            .collect::<Vec<_>>();
        let active = (!entries.is_empty()).then_some(0);
        Self { entries, active }
    }

    /// Configured links in preference order.
    pub fn links(&self) -> impl Iterator<Item = &RouteLink> {
        self.entries.iter().map(|entry| &entry.link)
    }

    /// The link that should carry the default route, if one is healthy.
    pub fn winner(&self) -> Option<&RouteLink> {
        self.active
            .and_then(|index| self.entries.get(index))
            .filter(|entry| entry.phase == LinkPhase::Up)
            .map(|entry| &entry.link)
    }

    /// Wire shape of every link, for `ProfileStatus.links`.
    pub fn statuses(&self) -> Vec<LinkStatus> {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, entry)| LinkStatus {
                interface: entry.link.interface.clone(),
                gateway: entry.link.gateway.clone(),
                gateway6: entry.link.gateway6.clone(),
                phase: entry.phase,
                healthy: entry.phase == LinkPhase::Up,
                active: self.active == Some(index),
                rtt_ms: entry.rtt_ms,
                last_ok_unix: entry.last_ok_unix,
            })
            .collect()
    }

    /// Applies one round of outcomes and returns the link that should carry
    /// the default route. Only a change of winner needs a route switch.
    pub fn step(&mut self, outcomes: &[ProbeOutcome], now_unix: u64) -> Option<usize> {
        for (entry, outcome) in self.entries.iter_mut().zip(outcomes) {
            match outcome {
                ProbeOutcome::Up { rtt_ms } => {
                    entry.fails = 0;
                    entry.oks = entry.oks.saturating_add(1);
                    if let Some(sample) = rtt_ms {
                        entry.rtt_ms = Some(match entry.rtt_ms {
                            None => *sample,
                            Some(previous) => {
                                let weighted = u64::from(previous) * u64::from(RTT_OLD_WEIGHT)
                                    + u64::from(*sample) * u64::from(RTT_NEW_WEIGHT);
                                // +5 rounds to nearest before the divide by ten.
                                u32::try_from((weighted + 5) / 10).unwrap_or(u32::MAX)
                            }
                        });
                    }
                    entry.last_ok_unix = Some(now_unix);
                    if entry.phase == LinkPhase::Down && entry.oks >= RECOVER_THRESHOLD {
                        entry.phase = LinkPhase::Up;
                    }
                }
                ProbeOutcome::Down => {
                    entry.oks = 0;
                    entry.fails = entry.fails.saturating_add(1);
                    if entry.phase == LinkPhase::Up && entry.fails >= FAIL_THRESHOLD {
                        entry.phase = LinkPhase::Down;
                    }
                }
                // No evidence about the link either way.
                ProbeOutcome::Skipped => {}
            }
        }

        // Highest-priority healthy link always wins, so a recovered primary
        // takes back over only once it has met the recovery threshold.
        self.active = self
            .entries
            .iter()
            .position(|entry| entry.phase == LinkPhase::Up);
        self.active
    }
}

/// Probe one link. A link with no usable source address is tested with ICMP.
/// `config.target6` is set only when the profile allows IPv6, so a v6-only
/// link is probed over v6 exactly when that family may carry traffic.
pub fn probe(link: &RouteLink, config: &ProbeConfig) -> ProbeOutcome {
    // A link with a configured gateway needs a probe route through it;
    // SO_BINDTODEVICE alone resolves the off-link target as on-link.
    if let (Some(gateway), true) = (&link.gateway, config.target.is_ipv4()) {
        ensure_probe_route(link, gateway, &config.target);
    }
    if let (Some(gateway6), Some(target6)) = (&link.gateway6, config.target6) {
        if target6.is_ipv6() {
            ensure_probe_route(link, gateway6, &target6);
        }
    }
    if let Some(source) = source_address(&link.interface, 4) {
        return tcp_probe(&link.interface, source, config.target);
    }
    if let (Some(source), Some(target)) = (source_address(&link.interface, 6), config.target6) {
        return tcp_probe(&link.interface, source, target);
    }
    // No source address: probe the gateway directly as a reachability signal.
    if let Some(gateway) = &link.gateway {
        return ping_probe(&link.interface, gateway);
    }
    ping_probe(&link.interface, &config.target.ip().to_string())
}

/// Install a host-scoped route for the probe target through a link's gateway.
/// Without this, an off-link probe target resolves as on-link when
/// SO_BINDTODEVICE forces the egress device, so ARP fails and the link
/// appears permanently down even when it is healthy.
fn ensure_probe_route(link: &RouteLink, gateway: &str, target: &SocketAddr) {
    let (family, prefix) = if target.is_ipv4() {
        ("-4", 32)
    } else {
        ("-6", 128)
    };
    let host = format!("{}/{prefix}", target.ip());
    let _ = command::run(
        "ip",
        &[
            family,
            "route",
            "replace",
            &host,
            "via",
            gateway,
            "dev",
            &link.interface,
        ],
        None,
    );
}

/// First global address of the requested family on the interface.
fn source_address(interface: &str, family: i32) -> Option<IpAddr> {
    let text = command::run_output("ip", &["-j", "addr", "show", "dev", interface]).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    let want = if family == 6 { "inet6" } else { "inet" };
    value
        .as_array()?
        .first()?
        .get("addr_info")?
        .as_array()?
        .iter()
        .find(|entry| {
            entry.get("family").and_then(Value::as_str) == Some(want)
                && entry
                    .get("scope")
                    .and_then(Value::as_str)
                    .is_none_or(|scope| scope == "global")
        })
        .and_then(|entry| entry.get("local")?.as_str()?.parse().ok())
}

fn tcp_probe(interface: &str, source: IpAddr, target: SocketAddr) -> ProbeOutcome {
    let domain = if source.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let Ok(socket) = Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) else {
        return ProbeOutcome::failed();
    };
    let local = SocketAddr::new(source, 0);
    if socket.bind(&local.into()).is_err()
        || socket.bind_device(Some(interface.as_bytes())).is_err()
        || socket.set_mark(0).is_err()
    {
        return ProbeOutcome::failed();
    }
    let started = Instant::now();
    match socket.connect_timeout(&target.into(), PROBE_TIMEOUT) {
        Ok(()) => ProbeOutcome::success(started.elapsed()),
        Err(_) => ProbeOutcome::failed(),
    }
}

fn ping_probe(interface: &str, host: &str) -> ProbeOutcome {
    let flag = if host.contains(':') { "-6" } else { "-4" };
    let started = Instant::now();
    match command::run(
        "ping",
        &[flag, "-I", interface, "-c", "1", "-W", "1", host],
        None,
    ) {
        Ok(_) => ProbeOutcome::success(started.elapsed()),
        // A host without `ping` cannot probe, but that is not a dead link.
        Err(err)
            if err
                .downcast_ref::<io::Error>()
                .is_some_and(|err| err.kind() == io::ErrorKind::NotFound) =>
        {
            ProbeOutcome::skipped()
        }
        Err(_) => ProbeOutcome::failed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(interface: &str) -> RouteLink {
        RouteLink {
            interface: interface.to_string(),
            gateway: None,
            gateway6: None,
        }
    }

    fn monitor(count: usize) -> LinkMonitor {
        LinkMonitor::new(
            (0..count)
                .map(|index| link(&format!("eth{index}")))
                .collect(),
        )
    }

    fn ok() -> ProbeOutcome {
        ProbeOutcome::Up { rtt_ms: Some(40) }
    }

    fn fail() -> ProbeOutcome {
        ProbeOutcome::failed()
    }

    #[test]
    fn three_failures_take_a_link_down() {
        let mut monitor = monitor(1);
        assert_eq!(monitor.step(&[fail()], 10), Some(0));
        assert_eq!(monitor.step(&[fail()], 11), Some(0));
        assert_eq!(monitor.entries[0].phase, LinkPhase::Up);
        assert_eq!(monitor.step(&[fail()], 12), None);
        assert_eq!(monitor.entries[0].phase, LinkPhase::Down);
    }

    #[test]
    fn two_successes_recover_a_link() {
        let mut monitor = monitor(1);
        for now in 0..3 {
            monitor.step(&[fail()], now);
        }
        assert_eq!(monitor.step(&[ok()], 10), None);
        assert_eq!(monitor.entries[0].phase, LinkPhase::Down);
        assert_eq!(monitor.step(&[ok()], 11), Some(0));
        assert_eq!(monitor.entries[0].phase, LinkPhase::Up);
    }

    #[test]
    fn failback_needs_two_successes_while_secondary_is_active() {
        let mut monitor = monitor(2);
        for now in 0..3 {
            monitor.step(&[fail(), ok()], now);
        }
        assert_eq!(monitor.active, Some(1));
        assert_eq!(monitor.step(&[ok(), ok()], 10), Some(1));
        assert_eq!(monitor.active, Some(1));
        assert_eq!(monitor.step(&[ok(), ok()], 11), Some(0));
        assert_eq!(monitor.active, Some(0));
    }

    #[test]
    fn all_links_down_yields_no_winner() {
        let mut monitor = monitor(2);
        for now in 0..3 {
            monitor.step(&[fail(), fail()], now);
        }
        assert_eq!(monitor.active, None);
        assert!(monitor.winner().is_none());
        assert!(monitor.statuses().iter().all(|status| !status.healthy));
    }

    #[test]
    fn a_success_between_failures_stops_the_down_transition() {
        let mut monitor = monitor(1);
        for (now, outcome) in [fail(), fail(), ok(), fail()].into_iter().enumerate() {
            monitor.step(&[outcome], u64::try_from(now).unwrap_or(u64::MAX));
        }
        assert_eq!(monitor.entries[0].phase, LinkPhase::Up);
        assert_eq!(monitor.active, Some(0));
        assert_eq!(monitor.step(&[fail()], 4), Some(0));
        assert_eq!(monitor.step(&[fail()], 5), None);
    }

    #[test]
    fn skipped_probes_leave_health_untouched() {
        let mut monitor = monitor(1);
        monitor.step(&[fail()], 0);
        monitor.step(&[fail()], 1);
        monitor.step(&[ProbeOutcome::skipped()], 2);
        assert_eq!(monitor.entries[0].phase, LinkPhase::Up);
        assert_eq!(monitor.entries[0].fails, 2);
        assert_eq!(monitor.entries[0].last_ok_unix, None);
        assert_eq!(monitor.step(&[fail()], 3), None);
        assert_eq!(monitor.entries[0].phase, LinkPhase::Down);
    }

    #[test]
    fn first_healthy_link_wins() {
        let mut monitor = monitor(3);
        monitor.step(&[fail(), ok(), ok()], 0);
        assert_eq!(monitor.active, Some(0));
        assert_eq!(monitor.step(&[fail(), ok(), ok()], 1), Some(0));
        assert_eq!(monitor.step(&[fail(), ok(), ok()], 2), Some(1));
        assert_eq!(monitor.active, Some(1));
    }

    #[test]
    fn rtt_is_smoothed_and_last_ok_is_recorded() {
        let mut monitor = monitor(1);
        monitor.step(&[ProbeOutcome::Up { rtt_ms: Some(100) }], 7);
        assert_eq!(monitor.entries[0].rtt_ms, Some(100));
        assert_eq!(monitor.entries[0].last_ok_unix, Some(7));
        monitor.step(&[ProbeOutcome::Up { rtt_ms: Some(200) }], 9);
        // 0.7 * 100 + 0.3 * 200 = 130
        assert_eq!(monitor.entries[0].rtt_ms, Some(130));
        assert_eq!(monitor.entries[0].last_ok_unix, Some(9));
    }

    #[test]
    fn statuses_mark_exactly_one_active_link() {
        let monitor = monitor(2);
        let statuses = monitor.statuses();
        assert!(statuses[0].active);
        assert!(!statuses[1].active);
        assert_eq!(statuses[0].interface, "eth0");
        assert!(statuses[0].healthy);
        assert_eq!(statuses[0].phase, LinkPhase::Up);
    }
}
