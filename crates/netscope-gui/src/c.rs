//! Concept C, Quiet Inspector: one rail, one calm reading column per screen.
//!
//! The rail carries connection truth and the single global pause. Screens keep a fixed reading
//! order: what is happening now, then what the daemon manages, then what needs a person.

use rune::{El, ScrollSpec, TextStyle, col, el, icon, row, text, text_input};
use rune_kit::{Button, ButtonVariant, Checkbox, ControlSize, Kit, SegmentedControl, Switch};
use rune_theme_opencode::icons;

use crate::doctor::{self, CheckStatus};
use crate::model::{
    Activity, Link, Mode, Profile, fmt_age, fmt_count, fmt_rate, fmt_rtt, now_unix, snapshot_age,
};
use crate::state::{AddSource, Conn, FILTER_CIDRS, Screen, State};
use crate::ui;

pub fn view(s: &State, k: &Kit) -> El {
    row()
        .w_full()
        .h_full()
        .fill(k.c.page)
        .child(rail(s, k))
        .child(main(s, k))
}

fn rail(s: &State, k: &Kit) -> El {
    let on_scopes = matches!(s.screen, Screen::Apps | Screen::Add);
    col()
        .w(210.0)
        .h_full()
        .padding(14.0)
        .gap(14.0)
        .fill(k.c.bg_base)
        .border_sides([0.0, 1.0, 0.0, 0.0], k.c.border_base)
        .child(ui::brand(k))
        .child(
            col()
                .w_full()
                .gap(2.0)
                .child(ui::nav_tab(
                    k,
                    "Overview",
                    Screen::Overview,
                    s.screen == Screen::Overview,
                ))
                .child(ui::nav_tab(k, "Scopes", Screen::Apps, on_scopes))
                .child(ui::nav_tab(
                    k,
                    "Doctor",
                    Screen::Doctor,
                    s.screen == Screen::Doctor,
                )),
        )
        .child(el().grow(1.0))
        .child(connection_card(s, k))
        .child(pause_button(s, k))
        .child(
            row()
                .w_full()
                .justify_between()
                .child(ui::faint(k, format!("v{}", env!("CARGO_PKG_VERSION"))))
                .child(ui::faint(k, "gui")),
        )
}

fn connection_card(s: &State, k: &Kit) -> El {
    let (ink, title) = match &s.conn {
        Conn::Live if s.stale => (k.c.warning.fg, "stale snapshot"),
        Conn::Live => (k.c.success.fg, "live"),
        Conn::Connecting => (k.c.text_faint, "connecting"),
        Conn::Down(_) => (k.c.danger.fg, "daemon down"),
        Conn::Denied(_) => (k.c.danger.fg, "permission denied"),
    };
    let age = s.snapshot.as_ref().map_or_else(
        || "no snapshot".to_string(),
        |snapshot| format!("updated {}", snapshot_age(snapshot.captured_at)),
    );
    col()
        .w_full()
        .gap(5.0)
        .px(9.0)
        .py(8.0)
        .radius(k.radius.md)
        .fill(k.c.layer_02)
        .child(
            row().gap(6.0).center_y().child(ui::dot(k, ink, 6.0)).child(
                text(title)
                    .font(TextStyle::new(11.5, 550.0).lh(14.0))
                    .color(k.c.text_muted),
            ),
        )
        .child(ui::faint(k, age))
}

fn pause_button(s: &State, k: &Kit) -> El {
    let label = if s.paused {
        "Resume updates"
    } else {
        "Pause updates"
    };
    Button::new(label)
        .variant(ButtonVariant::GhostMuted)
        .control_size(ControlSize::Regular)
        .help(if s.paused {
            "Resume polling the daemon. Enforcement was never paused."
        } else {
            "Freeze the numbers only. Enforcement continues."
        })
        .on_press(|state: &mut State| state.toggle_paused())
        .build(k)
}

fn main(s: &State, k: &Kit) -> El {
    let mut page = col().grow(1.0).min_w(0.0).h_full().min_h(0.0);
    if let Some(banner) = banner(s, k) {
        page = page.child(banner);
    }
    if let Some(notice) = notice(s, k) {
        page = page.child(notice);
    }
    page.child(
        col()
            .w_full()
            .grow(1.0)
            .min_h(0.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .child(
                col()
                    .w_full()
                    .padding(22.0)
                    .gap(14.0)
                    .child(match s.screen {
                        Screen::Overview => overview_head(s, k),
                        Screen::Apps => apps_head(s, k),
                        Screen::Add => add_head(s, k),
                        Screen::Doctor => doctor_head(s, k),
                    })
                    .child(match s.screen {
                        Screen::Overview => overview(s, k),
                        Screen::Apps => apps(s, k),
                        Screen::Add => add(s, k),
                        Screen::Doctor => doctor(s, k),
                    }),
            ),
    )
}

fn banner(s: &State, k: &Kit) -> Option<El> {
    match &s.conn {
        Conn::Live => None,
        Conn::Connecting => Some(
            row()
                .w_full()
                .h(34.0)
                .px(20.0)
                .gap(8.0)
                .center_y()
                .fill(k.c.layer_02)
                .border_sides([0.0, 0.0, 1.0, 0.0], k.c.border_base)
                .child(ui::dot(k, k.c.text_faint, 6.0))
                .child(ui::muted(k, "Connecting to netscoped…")),
        ),
        Conn::Down(message) => Some(
            row()
                .w_full()
                .px(20.0)
                .py(9.0)
                .gap(10.0)
                .center_y()
                .fill(k.alpha(k.c.warning.fg, 0.06))
                .border_sides([0.0, 0.0, 1.0, 0.0], k.alpha(k.c.warning.fg, 0.22))
                .child(ui::dot(k, k.c.warning.fg, 6.0))
                .child(
                    col()
                        .grow(1.0)
                        .min_w(0.0)
                        .gap(1.0)
                        .child(
                            text("Daemon unreachable")
                                .font(TextStyle::new(12.0, 550.0).lh(15.0))
                                .color(k.c.text_base),
                        )
                        .child(
                            text(message.clone())
                                .font(k.ty.small)
                                .color(k.c.text_muted)
                                .truncate(),
                        ),
                )
                .child(
                    Button::new("Doctor")
                        .variant(ButtonVariant::GhostMuted)
                        .control_size(ControlSize::Small)
                        .on_press(|state: &mut State| state.goto(Screen::Doctor))
                        .build(k),
                )
                .child(
                    Button::new("Retry")
                        .variant(ButtonVariant::Outline)
                        .control_size(ControlSize::Small)
                        .on_press(|state: &mut State| state.retry())
                        .build(k),
                ),
        ),
        Conn::Denied(message) => Some(
            row()
                .w_full()
                .px(20.0)
                .py(9.0)
                .gap(10.0)
                .center_y()
                .fill(k.alpha(k.c.danger.fg, 0.06))
                .border_sides([0.0, 0.0, 1.0, 0.0], k.alpha(k.c.danger.fg, 0.24))
                .child(ui::dot(k, k.c.danger.fg, 6.0))
                .child(
                    col()
                        .grow(1.0)
                        .min_w(0.0)
                        .gap(1.0)
                        .child(
                            text("Permission denied")
                                .font(TextStyle::new(12.0, 550.0).lh(15.0))
                                .color(k.c.text_base),
                        )
                        .child(
                            text(message.clone())
                                .font(k.ty.small)
                                .color(k.c.text_muted)
                                .truncate(),
                        ),
                )
                .child(
                    Button::new("Doctor")
                        .variant(ButtonVariant::GhostMuted)
                        .control_size(ControlSize::Small)
                        .on_press(|state: &mut State| state.goto(Screen::Doctor))
                        .build(k),
                )
                .child(
                    Button::new("Retry")
                        .variant(ButtonVariant::Outline)
                        .control_size(ControlSize::Small)
                        .on_press(|state: &mut State| state.retry())
                        .build(k),
                ),
        ),
    }
}

fn notice(s: &State, k: &Kit) -> Option<El> {
    let notice = s.notice.as_ref()?;
    let ink = if notice.ok {
        k.c.success.fg
    } else {
        k.c.danger.fg
    };
    Some(
        row()
            .w_full()
            .h(34.0)
            .px(20.0)
            .gap(8.0)
            .center_y()
            .fill(k.alpha(ink, 0.05))
            .border_sides([0.0, 0.0, 1.0, 0.0], k.alpha(ink, 0.18))
            .child(ui::dot(k, ink, 6.0))
            .child(
                text(notice.message.clone())
                    .font(k.ty.small)
                    .color(k.c.text_muted)
                    .truncate()
                    .grow(1.0),
            )
            .child(
                Button::new("Dismiss")
                    .variant(ButtonVariant::GhostFaint)
                    .control_size(ControlSize::Mini)
                    .on_press(|state: &mut State| state.dismiss_notice())
                    .build(k),
            ),
    )
}

fn page_head(k: &Kit, title: &str, deck: impl Into<String>, trailing: Option<El>) -> El {
    let mut head = row().w_full().gap(16.0).items_center().child(
        col()
            .grow(1.0)
            .min_w(0.0)
            .gap(2.0)
            .child(ui::heading(k, title, 24.0))
            .child(ui::muted(k, deck)),
    );
    if let Some(trailing) = trailing {
        head = head.child(trailing);
    }
    head
}

// ── Overview ──────────────────────────────────────────────────────────────────────────────

fn overview_head(s: &State, k: &Kit) -> El {
    let mut trailing = row().gap(8.0).center_y();
    trailing = trailing.child(connection_pill(s, k));
    if s.can_act() {
        trailing = trailing.child(
            Button::new("Add scope")
                .variant(ButtonVariant::Outline)
                .control_size(ControlSize::Regular)
                .icon(&icons::PLUS)
                .on_press(|state: &mut State| state.goto(Screen::Add))
                .build(k),
        );
    }
    page_head(
        k,
        "Overview",
        "One quiet read of what netscoped carries right now.",
        Some(trailing),
    )
}

fn connection_pill(s: &State, k: &Kit) -> El {
    match &s.conn {
        Conn::Live => ui::pill(k, "LIVE", k.c.success.fg, k.alpha(k.c.success.fg, 0.10)),
        Conn::Connecting => ui::pill(k, "CONNECTING", k.c.text_faint, k.c.layer_02),
        Conn::Down(_) => ui::pill(
            k,
            "DAEMON DOWN",
            k.c.warning.fg,
            k.alpha(k.c.warning.fg, 0.12),
        ),
        Conn::Denied(_) => ui::pill(k, "DENIED", k.c.danger.fg, k.alpha(k.c.danger.fg, 0.12)),
    }
}

fn overview(s: &State, k: &Kit) -> El {
    col()
        .w_full()
        .gap(14.0)
        .child(hero(s, k))
        .child(links_panel(s, k))
        .child(
            row()
                .w_full()
                .gap(14.0)
                .items_start()
                .child(activity_panel(s, k))
                .child(attention_panel(s, k)),
        )
}

fn hero(s: &State, k: &Kit) -> El {
    let dim = s.paused || s.stale;
    let tx = s.total_tx();
    let rx = s.total_rx();
    let pps = s.total_pps();
    let dropped = s.total_dropped();
    let updated = if s.paused {
        "live updates paused".to_string()
    } else if s.stale {
        s.snapshot.as_ref().map_or_else(
            || "stale · no sample".to_string(),
            |snapshot| format!("last snapshot · {}", snapshot_age(snapshot.captured_at)),
        )
    } else if s.stats_available() {
        s.snapshot.as_ref().map_or_else(
            || "no samples yet".to_string(),
            |snapshot| format!("sampled {}", snapshot_age(snapshot.captured_at)),
        )
    } else {
        "counters unavailable from this daemon".to_string()
    };
    col()
        .w_full()
        .gap(10.0)
        .padding(16.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(
            row()
                .w_full()
                .justify_between()
                .items_center()
                .child(ui::label(k, "TOTAL THROUGHPUT"))
                .child(ui::faint(k, updated)),
        )
        .child(
            row()
                .w_full()
                .gap(22.0)
                .items_end()
                .child(hero_metric(k, false, tx, dim))
                .child(hero_metric(k, true, rx, dim))
                .child(el().grow(1.0))
                .child(ui::metric(k, fmt_count(pps), "packets / s", true, dim))
                .child(ui::metric(k, fmt_count(dropped), "dropped", true, dim))
                .child(ui::metric(
                    k,
                    s.snapshot.as_ref().map_or("—".to_string(), |snapshot| {
                        snapshot.generation().to_string()
                    }),
                    "generation",
                    true,
                    dim,
                )),
        )
        .child(if s.rate_history && s.stats_available() {
            ui::spark(
                k,
                &s.history_rx,
                54.0,
                if dim { k.c.text_faint } else { k.c.text_accent },
            )
        } else {
            row()
                .w_full()
                .h(54.0)
                .center()
                .radius(k.radius.md)
                .fill(k.c.bg_deep)
                .child(ui::faint(
                    k,
                    "Rate history unavailable until the daemon reports counters.",
                ))
        })
}

fn hero_metric(k: &Kit, down: bool, value: Option<u64>, dim: bool) -> El {
    col()
        .gap(3.0)
        .min_w(0.0)
        .child(ui::hero_rate(k, down, value, dim))
        .child(ui::faint(k, if down { "received" } else { "sent" }))
}

fn links_panel(s: &State, k: &Kit) -> El {
    let now = now_unix();
    let links = s.links();
    let dim = s.paused || s.stale;
    let meta = if links.is_empty() {
        "not reported by this daemon".to_string()
    } else {
        format!(
            "{} up · {} active",
            links.iter().filter(|link| link.up).count(),
            links.iter().filter(|link| link.active).count()
        )
    };
    col()
        .w_full()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::section_head(k, "LINKS", meta))
        .child(
            row()
                .w_full()
                .padding(12.0)
                .gap(10.0)
                .items_stretch()
                .children(if links.is_empty() {
                    vec![links_unavailable(k)]
                } else {
                    links
                        .iter()
                        .map(|link| link_card(k, link, now, dim))
                        .collect()
                }),
        )
}

fn link_card(k: &Kit, link: &Link, now: u64, dim: bool) -> El {
    let (ink, bg) = if dim {
        (k.c.text_faint, k.c.layer_02)
    } else if !link.up {
        (k.c.danger.fg, k.alpha(k.c.danger.fg, 0.10))
    } else if link.active {
        (k.c.success.fg, k.alpha(k.c.success.fg, 0.10))
    } else {
        (k.c.text_muted, k.c.layer_02)
    };
    let strong = if dim { k.c.text_faint } else { k.c.text_base };
    col()
        .grow(1.0)
        .min_w(0.0)
        .gap(6.0)
        .padding(10.0)
        .radius(k.radius.md)
        .fill(k.c.bg_deep)
        .border(1.0, k.c.border_base)
        .child(
            row()
                .w_full()
                .gap(6.0)
                .center_y()
                .child(ui::dot(k, ink, 6.0))
                .child(
                    text(link.interface.clone())
                        .font(TextStyle::new(12.0, 550.0).lh(15.0).mono())
                        .color(strong)
                        .truncate()
                        .grow(1.0),
                )
                .child(ui::pill(k, link.role(), ink, bg)),
        )
        .child(
            row()
                .w_full()
                .gap(12.0)
                .child(
                    col()
                        .gap(1.0)
                        .child(ui::label(k, "RTT"))
                        .child(ui::mono_text(k, fmt_rtt(link.rtt_ms), strong)),
                )
                .child(
                    col()
                        .gap(1.0)
                        .child(ui::label(k, "LAST OK"))
                        .child(ui::mono_text(
                            k,
                            fmt_age(link.last_ok_unix, now),
                            if dim { k.c.text_faint } else { k.c.text_muted },
                        )),
                ),
        )
        .child(ui::faint(
            k,
            link.gateway
                .clone()
                .or_else(|| link.gateway6.clone())
                .unwrap_or_else(|| "no gateway".to_string()),
        ))
}

fn links_unavailable(k: &Kit) -> El {
    row()
        .w_full()
        .min_h(86.0)
        .padding(12.0)
        .gap(10.0)
        .items_center()
        .radius(k.radius.md)
        .fill(k.c.bg_deep)
        .border(1.0, k.c.border_base)
        .child(icon(&icons::OUTLINE_GLOBE_PLUS, 16.0).color(k.c.text_faint))
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .gap(2.0)
                .child(ui::muted(
                    k,
                    "Gateway, RTT and failover state are unavailable.",
                ))
                .child(ui::faint(
                    k,
                    "The 0.2.1 status document has no link telemetry; values appear after 0.3.",
                )),
        )
}

fn activity_panel(s: &State, k: &Kit) -> El {
    let mut panel = col()
        .grow(1.35)
        .min_w(0.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::section_head(k, "RECENT ACTIVITY", "since launch"))
        .child(
            col().w_full().padding(12.0).gap(7.0).children(
                s.activity
                    .iter()
                    .take(4)
                    .map(|activity| activity_row(k, activity)),
            ),
        );
    if s.activity.is_empty() {
        panel = panel.child(row().padding(12.0).child(ui::faint(k, "No activity yet.")));
    }
    panel
}

fn activity_row(k: &Kit, activity: &Activity) -> El {
    row()
        .w_full()
        .gap(8.0)
        .center_y()
        .child(ui::dot(k, ui::tone_color(k, activity.tone), 5.0))
        .child(
            text(activity.time.clone())
                .font(TextStyle::new(9.5, 500.0).lh(12.0).mono())
                .color(k.c.text_faint)
                .w(64.0),
        )
        .child(ui::muted(k, activity.message.clone()))
}

fn attention_panel(s: &State, k: &Kit) -> El {
    let checks = doctor::checks(s);
    let open: Vec<_> = checks
        .iter()
        .filter(|check| check.status != CheckStatus::Pass)
        .collect();
    let first = checks
        .iter()
        .find(|check| check.status == CheckStatus::Fail && check.fix.is_some())
        .or_else(|| {
            checks
                .iter()
                .find(|check| check.status == CheckStatus::Advisory && check.fix.is_some())
        });
    let (ink, pill_text) = if open.iter().any(|check| check.status == CheckStatus::Fail) {
        (k.c.danger.fg, format!("{}", open.len()))
    } else if open.is_empty() {
        (k.c.success.fg, "0".to_string())
    } else {
        (k.c.warning.fg, format!("{}", open.len()))
    };
    let alert = if open.iter().any(|check| check.status == CheckStatus::Fail) {
        k.c.danger.fg
    } else {
        k.c.warning.fg
    };
    let mut panel = col()
        .grow(1.0)
        .min_w(0.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(
            row()
                .w_full()
                .h(36.0)
                .px(14.0)
                .center_y()
                .justify_between()
                .child(ui::label(k, "NEEDS ATTENTION"))
                .child(ui::pill(k, pill_text.clone(), ink, k.alpha(ink, 0.10))),
        );
    panel = match first {
        Some(check) => panel
            .child(
                row()
                    .w_full()
                    .padding(12.0)
                    .gap(9.0)
                    .items_start()
                    .child(icon(&icons::OUTLINE_HEXAGONAL_WARNING, 14.0).color(alert))
                    .child(
                        col()
                            .grow(1.0)
                            .min_w(0.0)
                            .gap(3.0)
                            .child(ui::muted(k, check.detail.clone()))
                            .child(ui::faint(k, check.name.clone())),
                    ),
            )
            .child(
                row()
                    .w_full()
                    .px(12.0)
                    .pb(12.0)
                    .child(ui::command(k, check.fix.clone().unwrap_or_default())),
            ),
        None => panel.child(
            row()
                .w_full()
                .padding(12.0)
                .gap(9.0)
                .items_start()
                .child(icon(&icons::CHECK, 14.0).color(k.c.success.fg))
                .child(ui::muted(k, "No warnings from netscoped.")),
        ),
    };
    panel
}

// ── Scopes ────────────────────────────────────────────────────────────────────────────────

fn apps_head(s: &State, k: &Kit) -> El {
    let count = s
        .snapshot
        .as_ref()
        .map_or(0, |snapshot| snapshot.profiles.len());
    let trailing = row()
        .gap(8.0)
        .center_y()
        .child(ui::faint(
            k,
            format!(
                "{} enabled / {}",
                s.snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.enabled_count()),
                count
            ),
        ))
        .child(
            Button::new("Add scope")
                .variant(ButtonVariant::Outline)
                .control_size(ControlSize::Regular)
                .icon(&icons::PLUS)
                .disabled(!s.can_act())
                .on_press(|state: &mut State| state.goto(Screen::Add))
                .build(k),
        );
    page_head(
        k,
        "Scopes",
        "What netscoped holds, and who holds it.",
        Some(trailing),
    )
}

fn apps(s: &State, k: &Kit) -> El {
    let Some(profile) = s.selected() else {
        return empty(s, k);
    };
    let mut left = col()
        .grow(1.0)
        .min_w(0.0)
        .gap(14.0)
        .child(policy_panel(k, profile))
        .child(warning_panel(k, profile));
    if let Some(others) = other_scopes_panel(s, k) {
        left = left.child(others);
    }
    col()
        .w_full()
        .gap(14.0)
        .child(profile_panel(s, k, profile))
        .child(
            row().w_full().gap(14.0).items_start().child(left).child(
                col()
                    .w(292.0)
                    .gap(14.0)
                    .child(hold_panel(s, k, profile))
                    .child(actions_panel(s, k, profile)),
            ),
        )
}

/// The profiles this window is not showing. Selecting one moves the inspector to it.
fn other_scopes_panel(s: &State, k: &Kit) -> Option<El> {
    let snapshot = s.snapshot.as_ref()?;
    let others: Vec<(usize, &Profile)> = snapshot
        .profiles
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != s.selected_profile)
        .collect();
    if others.is_empty() {
        return None;
    }
    let mut panel = col()
        .w_full()
        .gap(2.0)
        .padding(10.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(
            row()
                .h(24.0)
                .px(4.0)
                .center_y()
                .child(ui::label(k, "OTHER SCOPES")),
        );
    for (index, profile) in others {
        let consumers = profile.consumers.len();
        let noted = if consumers == 1 {
            "1 consumer".to_string()
        } else {
            format!("{consumers} consumers")
        };
        panel = panel.child(
            row()
                .w_full()
                .h(32.0)
                .px(8.0)
                .gap(8.0)
                .center_y()
                .radius(k.radius.md)
                .hover(k.c.hover)
                .on_press(move |state: &mut State| state.select_profile(index))
                .child(ui::dot(
                    k,
                    if profile.enabled {
                        k.c.success.fg
                    } else {
                        k.c.text_faint
                    },
                    5.0,
                ))
                .child(
                    text(profile.id.clone())
                        .font(k.ty.small)
                        .color(k.c.text_muted)
                        .truncate()
                        .grow(1.0),
                )
                .child(ui::mode_pill(k, profile.mode))
                .child(ui::faint(
                    k,
                    format!("{noted} · gen {}", profile.generation),
                )),
        );
    }
    Some(panel)
}

fn empty(s: &State, k: &Kit) -> El {
    let snapshot = s.snapshot.as_ref();
    col()
        .w_full()
        .gap(14.0)
        .child(
            col()
                .w_full()
                .items_center()
                .gap(10.0)
                .padding(30.0)
                .radius(k.radius.lg)
                .fill(k.c.layer_01)
                .border(1.0, k.c.border_base)
                .child(
                    el()
                        .size(34.0, 34.0)
                        .radius(17.0)
                        .border(2.0, k.c.border_base)
                        .center()
                        .child(ui::dot(k, k.c.text_accent, 10.0)),
                )
                .child(ui::heading(k, "No scopes open", 20.0))
                .child(
                    text("netscoped is running with an empty profile list. Add a running process or an executable to start carrying traffic.")
                        .font(k.ty.ui)
                        .color(k.c.text_muted)
                        .align(rune::Align::Center)
                        .max_w(480.0),
                )
                .child(
                    Button::new("Add scope")
                        .variant(ButtonVariant::Outline)
                        .control_size(ControlSize::Regular)
                        .icon(&icons::PLUS)
                        .on_press(|state: &mut State| state.goto(Screen::Add))
                        .build(k),
                ),
        )
        .child(
            col()
                .w_full()
                .radius(k.radius.lg)
                .fill(k.c.layer_01)
                .border(1.0, k.c.border_base)
                .child(ui::section_head(k, "READY", "what the daemon reports"))
                .child(
                    col()
                        .w_full()
                        .padding(14.0)
                        .child(ui::kv(
                            k,
                            "daemon",
                            snapshot.map_or("unavailable", |snapshot| {
                                snapshot.daemon_version.as_str()
                            }),
                            false,
                        ))
                        .child(ui::kv(k, "control socket", netscope_client::DEFAULT_SOCKET_PATH, false))
                        .child(ui::kv(
                            k,
                            "cgroup root",
                            snapshot.map_or("unavailable", |snapshot| {
                                snapshot.cgroup_root.as_str()
                            }),
                            true,
                        )),
                ),
        )
}

fn profile_panel(s: &State, k: &Kit, profile: &Profile) -> El {
    let stats = profile.stats.as_ref();
    let dim = s.paused || s.stale;
    let state_label = if profile.enabled {
        "enabled"
    } else {
        "disabled"
    };
    col()
        .w_full()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(
            row()
                .w_full()
                .padding(14.0)
                .gap(12.0)
                .items_start()
                .child(
                    col()
                        .grow(1.0)
                        .min_w(0.0)
                        .gap(3.0)
                        .child(
                            row()
                                .gap(8.0)
                                .center_y()
                                .child(ui::heading(k, profile.id.clone(), 19.0))
                                .child(ui::mode_pill(k, profile.mode))
                                .child(ui::health_pill(k, profile.healthy)),
                        )
                        .child(ui::mono_text(k, profile.target.clone(), k.c.text_muted)),
                )
                .child(
                    row()
                        .gap(8.0)
                        .center_y()
                        .child(ui::faint(k, state_label))
                        .child(if s.can_act() {
                            ui::toggle(profile.enabled)
                                .on_toggle(|state: &mut State| state.toggle_selected())
                                .build(k)
                        } else {
                            ui::disabled_toggle(k, profile.enabled)
                        }),
                ),
        )
        .child(ui::divider(k))
        .child(
            row()
                .w_full()
                .padding(14.0)
                .gap(18.0)
                .child(ui::metric(
                    k,
                    fmt_rate(stats.and_then(|stats| stats.rx_bps)),
                    "down",
                    false,
                    dim,
                ))
                .child(ui::metric(
                    k,
                    fmt_rate(stats.and_then(|stats| stats.tx_bps)),
                    "up",
                    false,
                    dim,
                ))
                .child(ui::metric(
                    k,
                    fmt_count(profile.packet_rate()),
                    "packets / s",
                    false,
                    dim,
                ))
                .child(ui::metric(
                    k,
                    fmt_count(profile.dropped()),
                    "dropped",
                    false,
                    dim,
                ))
                .child(ui::metric(
                    k,
                    profile.generation.to_string(),
                    "generation",
                    false,
                    dim,
                ))
                .child(el().grow(1.0))
                .child(ui::metric(
                    k,
                    format!("{}", profile.pids.len()),
                    "pids",
                    true,
                    dim,
                )),
        )
        .child(ui::divider(k))
        .child(row().w_full().px(14.0).py(8.0).child(ui::mono_text(
            k,
            profile.cgroup.clone(),
            k.c.text_faint,
        )))
}

fn policy_panel(k: &Kit, profile: &Profile) -> El {
    let mut panel = col()
        .w_full()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::section_head(
            k,
            "POLICY",
            format!(
                "{} claim{}",
                profile.consumers.len(),
                if profile.consumers.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
        ))
        .child(
            col()
                .w_full()
                .padding(14.0)
                .child(ui::kv(k, "attached", profile.attached.clone(), false))
                .child(ui::kv(k, "mark", profile.mark.clone(), false))
                .child(ui::kv(
                    k,
                    "table / priority",
                    format!("{} / {}", profile.table, profile.rule_priority),
                    false,
                ))
                .child(ui::kv(k, "nft table", profile.nft_table.clone(), true)),
        );
    let policies = if profile.policies.is_empty() {
        vec!["no policies installed".to_string()]
    } else {
        profile.policies.clone()
    };
    panel = panel
        .child(ui::divider(k))
        .child(
            col()
                .w_full()
                .padding(14.0)
                .gap(5.0)
                .children(policies.iter().map(|policy| {
                    row()
                        .w_full()
                        .gap(8.0)
                        .center_y()
                        .child(ui::dot(k, k.c.text_faint, 5.0))
                        .child(ui::mono_text(k, policy.clone(), k.c.text_muted))
                })),
        );
    panel
}

fn warning_panel(k: &Kit, profile: &Profile) -> El {
    if profile.warnings.is_empty() {
        return row()
            .w_full()
            .padding(12.0)
            .gap(8.0)
            .center_y()
            .radius(k.radius.md)
            .fill(k.c.layer_01)
            .border(1.0, k.c.border_base)
            .child(icon(&icons::CHECK, 13.0).color(k.c.success.fg))
            .child(ui::faint(k, "No warnings from this profile."));
    }
    col()
        .w_full()
        .gap(6.0)
        .padding(12.0)
        .radius(k.radius.md)
        .fill(k.alpha(k.c.warning.fg, 0.05))
        .border(1.0, k.alpha(k.c.warning.fg, 0.20))
        .children(profile.warnings.iter().take(2).map(|warning| {
            row()
                .w_full()
                .gap(8.0)
                .items_start()
                .child(icon(&icons::OUTLINE_HEXAGONAL_WARNING, 13.0).color(k.c.warning.fg))
                .child(text(warning.clone()).font(k.ty.small).color(k.c.text_muted))
        }))
}

fn hold_panel(s: &State, k: &Kit, profile: &Profile) -> El {
    let peer = s.is_peer_owned(&profile.id);
    let claimed = if profile.consumers.is_empty() {
        "none".to_string()
    } else {
        profile.consumers.join(", ")
    };
    col()
        .w_full()
        .gap(8.0)
        .padding(14.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::label(k, "HOLD"))
        .child(
            row()
                .gap(8.0)
                .center_y()
                .child(ui::pill(
                    k,
                    if peer { "peer" } else { "persistent" },
                    if peer { k.c.info.fg } else { k.c.text_muted },
                    if peer {
                        k.alpha(k.c.info.fg, 0.12)
                    } else {
                        k.c.layer_02
                    },
                ))
                .child(ui::faint(k, "netscope-gui")),
        )
        .child(ui::kv(k, "consumers", claimed, true))
        .child(ui::faint(
            k,
            if peer {
                "Releases when this window's connection closes."
            } else {
                "Survives this window and a daemon restart."
            },
        ))
}

fn actions_panel(s: &State, k: &Kit, profile: &Profile) -> El {
    let peer = s.is_peer_owned(&profile.id);
    let confirming = s.pending_remove.as_deref() == Some(profile.id.as_str());
    let mut panel = col()
        .w_full()
        .gap(8.0)
        .padding(14.0)
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::label(k, "ACTIONS"));
    if confirming {
        panel = panel
            .child(ui::muted(
                k,
                if peer {
                    "Release this peer hold? The daemon keeps no claim from this window."
                } else {
                    "Remove this scope? Other consumers' claims keep it alive."
                },
            ))
            .child(
                row()
                    .w_full()
                    .gap(8.0)
                    .child(
                        Button::new("Cancel")
                            .variant(ButtonVariant::GhostMuted)
                            .control_size(ControlSize::Regular)
                            .on_press(|state: &mut State| state.cancel_remove())
                            .build(k),
                    )
                    .child(
                        Button::new(if peer { "Release" } else { "Remove" })
                            .variant(ButtonVariant::Danger)
                            .control_size(ControlSize::Regular)
                            .disabled(s.opening)
                            .on_press(|state: &mut State| state.confirm_remove())
                            .build(k),
                    ),
            );
    } else {
        panel = panel
            .child(
                Button::new(if profile.enabled { "Disable" } else { "Enable" })
                    .variant(ButtonVariant::Outline)
                    .control_size(ControlSize::Regular)
                    .disabled(!s.can_act())
                    .on_press(|state: &mut State| state.toggle_selected())
                    .build(k),
            )
            .child(
                Button::new(if peer { "Release hold" } else { "Remove scope" })
                    .variant(ButtonVariant::GhostMuted)
                    .control_size(ControlSize::Regular)
                    .disabled(!s.can_act())
                    .on_press(|state: &mut State| state.request_remove())
                    .build(k),
            );
    }
    panel
}

// ── Add ──────────────────────────────────────────────────────────────────────────────────

fn add_head(s: &State, k: &Kit) -> El {
    let trailing = row()
        .gap(8.0)
        .center_y()
        .child(ui::pill(
            k,
            if s.release_on_close {
                "PEER HOLD"
            } else {
                "PERSISTENT"
            },
            k.c.text_faint,
            k.c.layer_02,
        ))
        .child(
            Button::new("Cancel")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Regular)
                .on_press(|state: &mut State| state.goto(Screen::Apps))
                .build(k),
        );
    page_head(
        k,
        "Add scope",
        "Pick what to carry, then how to carry it.",
        Some(trailing),
    )
}

fn add(s: &State, k: &Kit) -> El {
    col()
        .w_full()
        .gap(12.0)
        .child(source_panel(s, k))
        .child(policy_panel_add(s, k))
        .child(review_panel(s, k))
}

fn source_panel(s: &State, k: &Kit) -> El {
    let mut body = col().w_full().padding(12.0).gap(8.0).child(
        SegmentedControl::new(
            &["Process", "Executable"],
            Some(match s.add_source {
                AddSource::Process => 0,
                AddSource::Executable => 1,
            }),
        )
        .label("Source")
        .fit()
        .on_pick(|state: &mut State, index, _| {
            state.add_source = if index == 0 {
                AddSource::Process
            } else {
                AddSource::Executable
            };
        })
        .build(k),
    );
    body = match s.add_source {
        AddSource::Process => body.child(process_list(s, k)),
        AddSource::Executable => body.child(executable_field(s, k)),
    };
    col()
        .w_full()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::section_head(
            k,
            "SOURCE",
            if s.demo {
                "demo processes"
            } else {
                "live /proc"
            },
        ))
        .child(body)
}

fn process_list(s: &State, k: &Kit) -> El {
    if s.scanning || (!s.demo && s.processes.is_empty()) {
        return row().w_full().h(96.0).center().child(if s.scanning {
            ui::muted(k, "Scanning /proc…")
        } else {
            ui::faint(k, "No processes found.")
        });
    }
    if s.processes.is_empty() {
        return row()
            .w_full()
            .h(80.0)
            .center()
            .child(ui::faint(k, "No processes found."));
    }
    col()
        .w_full()
        .gap(2.0)
        .child(
            row()
                .w_full()
                .h(20.0)
                .px(8.0)
                .gap(8.0)
                .child(row().grow(1.0).child(ui::label(k, "PROCESS")))
                .child(row().w(74.0).justify_end().child(ui::label(k, "PID")))
                .child(
                    row()
                        .w(150.0)
                        .justify_end()
                        .child(ui::label(k, "EXECUTABLE")),
                ),
        )
        .children(
            s.processes
                .iter()
                .take(5)
                .enumerate()
                .map(|(index, process)| {
                    let selected = index == s.selected_proc;
                    let exe = process.exe.rsplit('/').next().unwrap_or(&process.exe);
                    row()
                        .w_full()
                        .h(26.0)
                        .px(8.0)
                        .gap(8.0)
                        .center_y()
                        .radius(k.radius.sm)
                        .fill(if selected {
                            k.alpha(k.c.text_accent, 0.09)
                        } else {
                            rune::Color::TRANSPARENT
                        })
                        .hover(k.c.hover)
                        .on_press(move |state: &mut State| state.selected_proc = index)
                        .child(
                            el().size(7.0, 7.0)
                                .radius(3.5)
                                .fill(if selected {
                                    k.c.text_accent
                                } else {
                                    k.c.border_strong
                                })
                                .a11y_hidden(),
                        )
                        .child(
                            text(process.name.clone())
                                .font(k.ty.ui)
                                .color(if selected {
                                    k.c.text_base
                                } else {
                                    k.c.text_muted
                                })
                                .truncate()
                                .grow(1.0)
                                .min_w(0.0),
                        )
                        .child(
                            text(process.pid.to_string())
                                .font(k.ty.mono)
                                .color(k.c.text_faint)
                                .align(rune::Align::End)
                                .w(74.0),
                        )
                        .child(
                            text(exe.to_string())
                                .font(k.ty.mono)
                                .color(k.c.text_faint)
                                .truncate()
                                .w(150.0),
                        )
                }),
        )
}

fn executable_field(s: &State, k: &Kit) -> El {
    col()
        .w_full()
        .gap(6.0)
        .child(
            row()
                .w_full()
                .h(32.0)
                .px(9.0)
                .center_y()
                .radius(k.radius.md)
                .fill(k.c.bg_deep)
                .border(1.0, k.c.border_base)
                .child(
                    text_input(&s.add_exe, TextStyle::new(12.0, 450.0).lh(15.0).mono())
                        .single_line()
                        .placeholder("/usr/bin/… or a Wine .exe path", k.c.text_faint)
                        .on_edit(|state: &mut State| &mut state.add_exe)
                        .grow(1.0)
                        .min_w(0.0),
                ),
        )
        .child(ui::faint(
            k,
            "Native paths match by inode. A .exe path matches the Wine process basename.",
        ))
}

fn policy_panel_add(s: &State, k: &Kit) -> El {
    let mode_index = match s.add_mode {
        Mode::Route => 0,
        Mode::Filter => 1,
        Mode::Shared => 2,
    };
    let mut body = col().w_full().padding(12.0).gap(8.0).child(
        SegmentedControl::new(&["Route", "Filter", "Shared"], Some(mode_index))
            .label("Policy")
            .fit()
            .on_pick(|state: &mut State, index, _| {
                state.add_mode = match index {
                    0 => Mode::Route,
                    1 => Mode::Filter,
                    _ => Mode::Shared,
                };
            })
            .build(k),
    );
    match s.add_mode {
        Mode::Filter => {
            body = body
                .child(ui::label(k, "DENY DESTINATIONS"))
                .child(
                    row()
                        .w_full()
                        .gap(18.0)
                        .children(FILTER_CIDRS.iter().enumerate().map(|(index, cidr)| {
                            Checkbox::new(s.add_deny[index])
                                .label(*cidr)
                                .on_toggle(move |state: &mut State| {
                                    state.add_deny[index] = !state.add_deny[index];
                                })
                                .build(k)
                        })),
                )
                .child(ui::faint(
                    k,
                    "Everything outside these ranges is allowed. At least one range is required.",
                ));
        }
        Mode::Route => {
            body = body
                .child(ui::label(k, "ORDERED LINKS"))
                .child(if s.add_route.is_empty() {
                    row()
                        .w_full()
                        .h(30.0)
                        .child(ui::faint(k, "No link chosen yet."))
                } else {
                    col()
                        .w_full()
                        .gap(4.0)
                        .children(s.add_route.iter().enumerate().map(|(index, link)| {
                            route_row(s, k, index, link)
                        }))
                })
                .child(
                    row()
                        .w_full()
                        .h(30.0)
                        .px(9.0)
                        .center_y()
                        .gap(6.0)
                        .radius(k.radius.md)
                        .fill(k.c.bg_deep)
                        .border(1.0, k.c.border_base)
                        .child(
                            text_input(&s.add_link, TextStyle::new(12.0, 450.0).lh(15.0).mono())
                                .single_line()
                                .placeholder("interface, e.g. enp7s0f4u1", k.c.text_faint)
                                .on_edit(|state: &mut State| &mut state.add_link)
                                .on_submit(|state: &mut State, _| state.add_route_entry())
                                .grow(1.0)
                                .min_w(0.0),
                        )
                        .child(
                            Button::new("Add")
                                .variant(ButtonVariant::GhostMuted)
                                .control_size(ControlSize::Mini)
                                .on_press(|state: &mut State| state.add_route_entry())
                                .build(k),
                        ),
                )
                .child(if s.demo || s.add_route.len() < 2 {
                    ui::faint(
                        k,
                        "Order is failover order. The daemon uses the first link that is up.",
                    )
                } else {
                    ui::faint(
                        k,
                        "This 0.2.1 daemon enforces the first link; the rest are kept in the window.",
                    )
                });
        }
        Mode::Shared => {
            body = body
                .child(ui::label(k, "SHARED"))
                .child(ui::muted(
                    k,
                    "Join an existing shared profile. No new policy is installed.",
                ))
                .child(ui::faint(
                    k,
                    "The daemon composes filter claims across consumers.",
                ));
        }
    };
    body = body.child(
        row()
            .w_full()
            .items_center()
            .gap(10.0)
            .child(
                Switch::new(s.release_on_close)
                    .on_toggle(|state: &mut State| {
                        state.release_on_close = !state.release_on_close;
                    })
                    .build(k),
            )
            .child(ui::muted(k, "Release when this window closes"))
            .child(el().grow(1.0))
            .child(ui::faint(
                k,
                if s.release_on_close {
                    "peer hold ends with the socket"
                } else {
                    "persistent hold survives a restart"
                },
            )),
    );
    col()
        .w_full()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(ui::section_head(k, "POLICY", "how this scope is carried"))
        .child(body)
}

fn route_row(s: &State, k: &Kit, index: usize, link: &str) -> El {
    let primary = index == 0;
    let last = index + 1 == s.add_route.len();
    row()
        .w_full()
        .h(28.0)
        .px(8.0)
        .gap(7.0)
        .center_y()
        .radius(k.radius.sm)
        .fill(k.c.bg_deep)
        .child(
            text((index + 1).to_string())
                .font(TextStyle::new(9.5, 550.0).lh(12.0).mono())
                .color(k.c.text_faint)
                .w(14.0),
        )
        .child(
            text(link.to_string())
                .font(k.ty.mono)
                .color(k.c.text_base)
                .truncate()
                .grow(1.0)
                .min_w(0.0),
        )
        .child(ui::pill(
            k,
            if primary { "primary" } else { "failover" },
            if primary { k.c.info.fg } else { k.c.text_faint },
            if primary {
                k.alpha(k.c.info.fg, 0.12)
            } else {
                k.c.layer_02
            },
        ))
        .child(
            Button::new("↑")
                .variant(ButtonVariant::GhostFaint)
                .control_size(ControlSize::Mini)
                .disabled(primary)
                .on_press(move |state: &mut State| state.move_route_up(index))
                .build(k),
        )
        .child(
            Button::new("↓")
                .variant(ButtonVariant::GhostFaint)
                .control_size(ControlSize::Mini)
                .disabled(last)
                .on_press(move |state: &mut State| state.move_route_down(index))
                .build(k),
        )
        .child(
            Button::new("×")
                .variant(ButtonVariant::GhostFaint)
                .control_size(ControlSize::Mini)
                .help("Remove link")
                .on_press(move |state: &mut State| state.remove_route_entry(index))
                .build(k),
        )
}

fn review_panel(s: &State, k: &Kit) -> El {
    let mut panel = row()
        .w_full()
        .px(12.0)
        .py(12.0)
        .gap(14.0)
        .items_center()
        .radius(k.radius.lg)
        .fill(k.c.layer_01)
        .border(1.0, k.c.border_base)
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .gap(2.0)
                .child(ui::label(k, "REVIEW"))
                .child(
                    text(format!(
                        "{} · {}",
                        s.add_target_label(),
                        s.add_policy_summary()
                    ))
                    .font(k.ty.small)
                    .color(k.c.text_muted)
                    .truncate(),
                ),
        )
        .child(
            Button::new(if s.opening {
                "Opening…"
            } else {
                "Open scope"
            })
            .variant(ButtonVariant::Contrast)
            .control_size(ControlSize::Regular)
            .disabled(s.opening || !s.can_act())
            .on_press(|state: &mut State| state.begin_open())
            .build(k),
        );
    if let Some(error) = &s.add_error {
        panel = panel.child(
            row()
                .gap(6.0)
                .center_y()
                .child(icon(&icons::CIRCLE_XMARK, 12.0).color(k.c.danger.fg))
                .child(
                    text(error.clone())
                        .font(k.ty.small)
                        .color(k.c.danger.fg)
                        .truncate(),
                ),
        );
    }
    panel
}

// ── Doctor ────────────────────────────────────────────────────────────────────────────────

fn doctor_head(s: &State, k: &Kit) -> El {
    let failing = doctor::checks(s)
        .iter()
        .filter(|check| check.status == CheckStatus::Fail)
        .count();
    let trailing = row()
        .gap(8.0)
        .center_y()
        .child(ui::pill(
            k,
            if failing == 0 {
                "ALL CHECKS PASS"
            } else {
                "NEEDS ATTENTION"
            },
            if failing == 0 {
                k.c.success.fg
            } else {
                k.c.warning.fg
            },
            if failing == 0 {
                k.alpha(k.c.success.fg, 0.10)
            } else {
                k.alpha(k.c.warning.fg, 0.12)
            },
        ))
        .child(
            Button::new("Run again")
                .variant(ButtonVariant::Outline)
                .control_size(ControlSize::Regular)
                .icon(&icons::REFRESH)
                .on_press(|state: &mut State| state.refresh())
                .build(k),
        );
    page_head(
        k,
        "Doctor",
        "What works, what does not, and the command that fixes it.",
        Some(trailing),
    )
}

fn doctor(s: &State, k: &Kit) -> El {
    let checks = doctor::checks(s);
    col()
        .w_full()
        .gap(12.0)
        .child(
            col()
                .w_full()
                .radius(k.radius.lg)
                .fill(k.c.layer_01)
                .border(1.0, k.c.border_base)
                .child(ui::section_head(
                    k,
                    "CHECKS",
                    format!("{} checks", checks.len()),
                ))
                .children(checks.iter().map(|check| check_row(k, check))),
        )
        .child(
            row()
                .w_full()
                .gap(8.0)
                .items_start()
                .child(icon(&icons::OUTLINE_COPY, 13.0).color(k.c.text_faint))
                .child(ui::faint(
                    k,
                    "Fix commands are copied, never run. Root is needed only for the commands shown.",
                ))
                .child(el().grow(1.0))
                .child(ui::faint(
                    k,
                    s.snapshot.as_ref().map_or("no snapshot", |snapshot| {
                        snapshot.kernel.as_str()
                    }),
                )),
        )
}

fn check_row(k: &Kit, check: &doctor::Check) -> El {
    let line = row()
        .w_full()
        .min_h(54.0)
        .px(14.0)
        .py(8.0)
        .gap(12.0)
        .items_center()
        .border_sides([0.0, 0.0, 1.0, 0.0], k.c.border_base)
        .child(ui::check_icon(k, check.status))
        .child(
            row()
                .w(186.0)
                .gap(8.0)
                .center_y()
                .child(
                    text(check.name.clone())
                        .font(k.ty.ui)
                        .color(k.c.text_base)
                        .truncate()
                        .grow(1.0)
                        .min_w(0.0),
                )
                .child(ui::check_pill(k, check.status)),
        )
        .child(
            col()
                .grow(1.0)
                .min_w(0.0)
                .gap(2.0)
                .child(
                    text(check.detail.clone())
                        .font(k.ty.small)
                        .color(k.c.text_muted)
                        .truncate(),
                )
                .child(ui::faint(
                    k,
                    match check.status {
                        CheckStatus::Pass => "ok",
                        CheckStatus::Fail => "fix available",
                        CheckStatus::Advisory => "informational",
                    },
                )),
        );
    match &check.fix {
        Some(fix) => line.child(row().w(292.0).child(ui::command(k, fix.clone()))),
        None => line,
    }
}
