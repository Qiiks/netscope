//! Blocking fanotify thread: forward each held exec to the daemon and write
//! its allow/deny answer back to the kernel.

use std::sync::Arc;
use std::thread::JoinHandle;

use tokio::sync::{mpsc, oneshot};

pub use crate::fanotify::ExecEvent;
use crate::fanotify::Fanotify;

pub fn spawn(fanotify: Arc<Fanotify>, sender: mpsc::Sender<ExecEvent>) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("netscope-fanotify".into())
        .spawn(move || run(&fanotify, &sender))
        .expect("spawn fanotify watcher")
}

fn run(fanotify: &Fanotify, sender: &mpsc::Sender<ExecEvent>) {
    loop {
        let events = match fanotify.read_events() {
            Ok(Some(events)) => events,
            Ok(None) => return,
            Err(error) => {
                tracing::error!(error = %error, "fanotify read failed");
                return;
            }
        };

        for mut event in events {
            if event.overflow {
                // Queue overflow has no permission fd to answer; the daemon
                // rescan is the recovery path.
                if sender.blocking_send(event).is_err() {
                    return;
                }
                continue;
            }

            let event_fd = event.event_fd;
            match event_fd.try_clone() {
                Ok(notify_fd) => event.event_fd = notify_fd,
                Err(error) => {
                    tracing::warn!(error = %error, "fanotify event fd dup failed; allowing exec");
                    let _ = fanotify.respond(event_fd, true);
                    continue;
                }
            }

            let (reply, response) = oneshot::channel();
            event.reply = reply;
            if sender.blocking_send(event).is_err() {
                let _ = fanotify.respond(event_fd, true);
                return;
            }

            let allow = response.blocking_recv().unwrap_or_else(|_| {
                // Daemon death is documented as fail-open; a blocked exec
                // would otherwise never resume.
                tracing::warn!("daemon dropped exec event; allowing");
                true
            });
            if let Err(error) = fanotify.respond(event_fd, allow) {
                tracing::warn!(error = %error, "fanotify response failed");
            }
        }
    }
}
