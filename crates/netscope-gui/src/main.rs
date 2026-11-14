//! netscope-gui: a calm inspector for netscoped.
//!
//! Normal launch opens the live window and connects to the daemon. `--demo` substitutes a
//! fixed snapshot for screenshots and development; `--snap` is Rune's headless renderer,
//! which also uses the demo snapshot so screenshots never imply a live daemon.

mod c;
mod doctor;
mod model;
mod state;
mod ui;
mod worker;

use std::sync::{OnceLock, mpsc};

use rune::tray::{Tray, TrayEvent, TrayIcon, TrayItem, TraySpec};
use rune::{AppHandle, AppSpec, Cx, El, Waker};

use crate::state::{Conn, Scene, State};

static HANDLE: OnceLock<AppHandle<State>> = OnceLock::new();

type SceneSetup = fn(&mut State);

const SCENES: &[(&str, SceneSetup)] = &[
    ("overview", scene_overview),
    ("scopes", scene_scopes),
    ("add", scene_add),
    ("doctor", scene_doctor),
    ("empty", scene_empty),
    ("down", scene_down),
    ("denied", scene_denied),
    ("narrow", scene_narrow),
];

fn scene_overview(state: &mut State) {
    state.reset_demo(Scene::Overview);
}

fn scene_scopes(state: &mut State) {
    state.reset_demo(Scene::Scopes);
}

fn scene_add(state: &mut State) {
    state.reset_demo(Scene::Add);
}

fn scene_doctor(state: &mut State) {
    state.reset_demo(Scene::Doctor);
}

fn scene_empty(state: &mut State) {
    state.reset_demo(Scene::Empty);
}

fn scene_down(state: &mut State) {
    state.reset_demo(Scene::Down);
}

fn scene_denied(state: &mut State) {
    state.reset_demo(Scene::Denied);
}

fn scene_narrow(state: &mut State) {
    state.reset_demo(Scene::Narrow);
}

fn view(state: &State, cx: &mut Cx<State>) -> El {
    c::view(state, ui::theme(cx.system_dark()))
}

fn setup(state: &mut State, _waker: Waker) {
    let headless = std::env::args().any(|arg| arg == "--snap");
    let Some(handle) = HANDLE.get().cloned() else {
        state.connection_lost(Conn::Down("the app handle is unavailable".to_string()));
        return;
    };

    if !state.demo {
        let (tx, rx) = mpsc::channel();
        state.tx = Some(tx);
        if worker::spawn(rx, handle.clone()).is_err() {
            state.tx = None;
            state.connection_lost(Conn::Down("the daemon worker could not start".to_string()));
        }
    }

    if !headless && state.tray.is_none() {
        state.tray = make_tray(handle);
        state.refresh_tray();
    }
}

fn make_tray(handle: AppHandle<State>) -> Option<Tray> {
    let spec = TraySpec::new("dev.qiiks.netscope", "netscope", tray_icon())
        .tooltip("netscope · connecting")
        .menu(tray_menu(false));
    let events = handle.clone();
    Tray::new(spec, move |event| match event {
        TrayEvent::Activate { token } => {
            if let Some(token) = token {
                events.activate(token);
            } else {
                events.open();
            }
        }
        TrayEvent::Menu(id) if id == "show" => events.open(),
        TrayEvent::Menu(id) if id == "pause" => {
            events.update(|state, _| state.toggle_paused());
        }
        TrayEvent::Menu(id) if id == "quit" => events.quit(),
        TrayEvent::Menu(_) => {}
        _ => {}
    })
    .ok()
}

fn tray_menu(paused: bool) -> Vec<TrayItem> {
    vec![
        TrayItem::action("show", "Show netscope"),
        TrayItem::action(
            "pause",
            if paused {
                "Resume updates"
            } else {
                "Pause updates"
            },
        ),
        TrayItem::Separator,
        TrayItem::action("quit", "Quit"),
    ]
}

/// A scope ring on a transparent field: the rail glyph, not a bolt.
fn tray_icon() -> TrayIcon {
    const SIZE: i32 = 22;
    let mut pixels = Vec::with_capacity(
        usize::try_from(SIZE * SIZE * 4).expect("tray icon dimensions fit in memory"),
    );
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x - SIZE / 2;
            let dy = y - SIZE / 2;
            let distance = dx * dx + dy * dy;
            let ring = (5 * 5..=9 * 9).contains(&distance);
            let core = distance <= 3 * 3;
            if ring || core {
                pixels.extend_from_slice(&[108, 158, 248, 255]);
            } else {
                pixels.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    TrayIcon::rgba(22, 22, pixels)
}

fn main() {
    let demo = std::env::args().any(|arg| arg == "--demo" || arg == "--snap");
    rune::tooling::set_app_id("netscope-gui");
    let spec = AppSpec {
        scenes: SCENES,
        fonts: rune_theme_opencode::FONTS,
        families: rune_theme_opencode::FAMILIES,
        setup: Some(setup),
        ..AppSpec::new(
            "netscope",
            (1100.0, 720.0),
            || State::live(None, None),
            view,
        )
    };
    let mut app = rune::App::new(spec);
    let handle = app.handle();
    app = app.init(move || {
        let _ = HANDLE.set(handle);
        if demo {
            State::demo(None)
        } else {
            State::live(None, None)
        }
    });
    app.run();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scene_builds_in_both_themes() {
        for (_, scene) in SCENES {
            for dark in [true, false] {
                let mut state = State::demo(None);
                scene(&mut state);
                let _ = c::view(&state, ui::theme(dark));
            }
        }
    }
}
