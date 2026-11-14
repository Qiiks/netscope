//! Shared surfaces, type and marks. Everything visual comes from
//! `rune_theme_opencode::kit`, so Quiet Inspector is calm by structure, not by a second palette.

use rune::{Color, El, TextStyle, col, el, icon, row, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit, Switch};
use rune_theme_opencode::icons;

use crate::doctor::CheckStatus;
use crate::model::{Mode, Tone};
use crate::state::Screen;

pub fn theme(dark: bool) -> &'static Kit {
    rune_theme_opencode::kit(dark)
}

pub fn heading(k: &Kit, s: impl Into<String>, size: f32) -> El {
    text(s)
        .font(TextStyle::new(size, 550.0).lh(size * 1.2))
        .color(k.c.text_base)
        .truncate()
}

pub fn label(k: &Kit, s: impl Into<String>) -> El {
    text(s)
        .font(TextStyle::new(10.0, 600.0).tracking(0.6).lh(14.0))
        .color(k.c.text_faint)
}

pub fn muted(k: &Kit, s: impl Into<String>) -> El {
    text(s).font(k.ty.small).color(k.c.text_muted).truncate()
}

pub fn faint(k: &Kit, s: impl Into<String>) -> El {
    text(s).font(k.ty.small).color(k.c.text_faint).truncate()
}

pub fn mono_text(k: &Kit, s: impl Into<String>, c: Color) -> El {
    text(s).font(k.ty.mono).color(c).truncate()
}

pub fn dot(_k: &Kit, c: Color, size: f32) -> El {
    el().size(size, size)
        .radius(size / 2.0)
        .fill(c)
        .a11y_hidden()
}

pub fn tone_color(k: &Kit, t: Tone) -> Color {
    match t {
        Tone::Good => k.c.success.fg,
        Tone::Warn => k.c.warning.fg,
        Tone::Bad => k.c.danger.fg,
        Tone::Muted => k.c.text_faint,
    }
}

/// A small solid capsule, for mode and provenance markers.
pub fn pill(_k: &Kit, label: impl Into<String>, fg: Color, bg: Color) -> El {
    let label = label.into();
    row()
        .h(18.0)
        .px(6.0)
        .center()
        .radius(4.0)
        .fill(bg)
        .role("status")
        .label(label.clone())
        .child(
            text(label)
                .font(TextStyle::new(10.0, 550.0).lh(12.0))
                .color(fg)
                .a11y_hidden(),
        )
}

pub fn mode_pill(k: &Kit, m: Mode) -> El {
    let (fg, bg) = match m {
        Mode::Route => (k.c.info.fg, k.alpha(k.c.info.fg, 0.13)),
        Mode::Filter => (k.c.text_muted, k.c.layer_02),
        Mode::Shared => (k.c.text_accent, k.alpha(k.c.text_accent, 0.13)),
    };
    pill(k, m.label(), fg, bg)
}

pub fn health_pill(k: &Kit, healthy: bool) -> El {
    if healthy {
        pill(k, "healthy", k.c.success.fg, k.alpha(k.c.success.fg, 0.10))
    } else {
        pill(k, "degraded", k.c.danger.fg, k.alpha(k.c.danger.fg, 0.12))
    }
}

pub fn check_pill(k: &Kit, s: CheckStatus) -> El {
    match s {
        CheckStatus::Pass => pill(k, "pass", k.c.success.fg, k.alpha(k.c.success.fg, 0.10)),
        CheckStatus::Fail => pill(k, "fail", k.c.danger.fg, k.alpha(k.c.danger.fg, 0.12)),
        CheckStatus::Advisory => pill(k, "advise", k.c.warning.fg, k.alpha(k.c.warning.fg, 0.12)),
    }
}

pub fn check_icon(k: &Kit, s: CheckStatus) -> El {
    match s {
        CheckStatus::Pass => icon(&icons::CHECK, 12.0).color(k.c.success.fg),
        CheckStatus::Fail => icon(&icons::CIRCLE_XMARK, 12.0).color(k.c.danger.fg),
        CheckStatus::Advisory => {
            icon(&icons::OUTLINE_HEXAGONAL_WARNING, 12.0).color(k.c.warning.fg)
        }
    }
}

pub fn brand(k: &Kit) -> El {
    let mark = el()
        .size(18.0, 18.0)
        .radius(9.0)
        .border(1.5, k.c.text_accent)
        .center()
        .child(dot(k, k.c.text_accent, 6.0));
    row().center_y().gap(7.0).child(mark).child(
        text("netscope")
            .font(TextStyle::new(13.0, 600.0).tracking(-0.2).lh(16.0))
            .color(k.c.text_base),
    )
}

/// A large throughput value, or a quiet `unavailable` when the daemon has no counters.
pub fn hero_rate(k: &Kit, down: bool, bps: Option<u64>, dim: bool) -> El {
    let arrow = if down { "↓" } else { "↑" };
    let ink = if dim { k.c.text_faint } else { k.c.text_base };
    let value = bps.map_or_else(
        || {
            text("unavailable")
                .font(TextStyle::new(18.0, 500.0).lh(26.0))
                .color(k.c.text_faint)
                .truncate()
        },
        |bps| {
            text(crate::model::fmt_rate(Some(bps)))
                .font(TextStyle::new(26.0, 600.0).lh(30.0).mono())
                .color(ink)
                .truncate()
        },
    );
    row()
        .gap(6.0)
        .items_end()
        .child(
            text(arrow)
                .font(TextStyle::new(16.0, 600.0).lh(22.0))
                .color(k.c.text_faint),
        )
        .child(value)
}

/// A bar sparkline. `values` may be raw byte counters or 0..1 samples; the tallest bar sets the
/// scale, so a flat zero line still reads as quiet bars rather than clipping every value to 1.
pub fn spark(k: &Kit, values: &[f32], height: f32, c: Color) -> El {
    let peak = values.iter().copied().fold(0.0_f32, f32::max).max(1.0);
    let bars = values.iter().map(|raw| {
        let v = (raw / peak).clamp(0.03, 1.0);
        el().grow(1.0)
            .max_w(5.0)
            .h((height * v).max(1.0))
            .radius(1.0)
            .fill(if v < 0.05 {
                k.c.border_base
            } else {
                k.alpha(c, 0.28 + 0.62 * v)
            })
    });
    row()
        .w_full()
        .h(height)
        .items_end()
        .gap(1.0)
        .children(bars)
        .a11y_hidden()
}

/// A command with a copy affordance. The GUI never shells out from a click.
pub fn command(k: &Kit, cmd: impl Into<String>) -> El {
    let cmd = cmd.into();
    let copy = cmd.clone();
    row()
        .w_full()
        .h(30.0)
        .pl(8.0)
        .pr(4.0)
        .center_y()
        .gap(8.0)
        .radius(k.radius.md)
        .fill(k.c.bg_deep)
        .border(1.0, k.c.border_base)
        .child(
            text(cmd)
                .font(TextStyle::new(11.5, 450.0).lh(15.0).mono())
                .color(k.c.text_muted)
                .truncate(),
        )
        .child(el().grow(1.0))
        .child(
            Button::new("Copy")
                .variant(ButtonVariant::GhostMuted)
                .control_size(ControlSize::Small)
                .icon(&icons::OUTLINE_COPY)
                .help("Copy to clipboard")
                .on_press_tx(move |state: &mut crate::state::State, tx| {
                    tx.copy(copy.clone());
                    state.notice = Some(crate::state::Notice {
                        message: "copied to clipboard".to_string(),
                        ok: true,
                    });
                })
                .build(k),
        )
}

pub fn toggle(on: bool) -> Switch {
    Switch::new(on)
        .hide_label()
        .control_size(ControlSize::Regular)
}

pub fn disabled_toggle(k: &Kit, on: bool) -> El {
    Switch::new(on)
        .hide_label()
        .control_size(ControlSize::Regular)
        .disabled(true)
        .build(k)
}

pub fn kv(k: &Kit, key: impl Into<String>, value: impl Into<String>, last: bool) -> El {
    let mut r = row()
        .w_full()
        .py(6.0)
        .center_y()
        .justify_between()
        .gap(12.0)
        .child(text(key).font(k.ty.small).color(k.c.text_faint).truncate())
        .child(text(value).font(k.ty.mono).color(k.c.text_muted).truncate());
    if !last {
        r = r.border_sides([0.0, 0.0, 1.0, 0.0], k.c.border_base);
    }
    r
}

pub fn section_head(k: &Kit, title: &str, meta: impl Into<String>) -> El {
    row()
        .w_full()
        .h(36.0)
        .px(14.0)
        .center_y()
        .justify_between()
        .child(label(k, title))
        .child(
            text(meta)
                .font(TextStyle::new(10.0, 500.0).lh(13.0).mono())
                .color(k.c.text_faint)
                .truncate(),
        )
}

pub fn divider(k: &Kit) -> El {
    el().w_full().h(1.0).fill(k.c.border_base).a11y_hidden()
}

pub fn nav_tab(k: &Kit, title: &'static str, screen: Screen, active: bool) -> El {
    let ink = if active {
        k.c.text_base
    } else {
        k.c.text_muted
    };
    row()
        .h(36.0)
        .px(2.0)
        .center_y()
        .border_sides(
            [0.0, 0.0, if active { 2.0 } else { 0.0 }, 0.0],
            k.c.text_accent,
        )
        .child(
            text(title)
                .font(TextStyle::new(12.5, if active { 550.0 } else { 450.0 }).lh(16.0))
                .color(ink),
        )
        .hover(k.c.hover)
        .on_press(move |s: &mut crate::state::State| s.goto(screen))
}

/// A value and its label, right-aligned where numbers read better.
pub fn metric(
    k: &Kit,
    value: impl Into<String>,
    sub: impl Into<String>,
    align_end: bool,
    dim: bool,
) -> El {
    let mut c = col().gap(1.0).min_w(64.0).child(
        text(value)
            .font(TextStyle::new(15.0, 550.0).lh(19.0).mono())
            .color(if dim { k.c.text_faint } else { k.c.text_base })
            .truncate(),
    );
    c = c.child(
        text(sub)
            .font(TextStyle::new(10.0, 450.0).lh(13.0))
            .color(k.c.text_faint)
            .truncate(),
    );
    if align_end {
        c = c.items_end();
    }
    c
}
