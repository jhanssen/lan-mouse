//! macOS clipboard backend.
//!
//! Phase 5 of CLIPBOARD_PLAN.md. Polls `NSPasteboard.changeCount` on a tokio
//! interval (250 ms). Self-fire suppression uses a per-instance marker
//! pasteboard type (UTI), mirroring the wayland origin-marker approach: when
//! we write, we attach both `NSPasteboardTypeString` and our marker UTI;
//! when we poll, we skip any selection whose advertised type list contains
//! our marker.
//!
//! NOTE: This file is compiled only on macOS via `cfg(macos_clipboard)`.
//! Verification of this build path requires a macOS toolchain.

use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use objc2::rc::autoreleasepool;
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
use objc2_foundation::{NSData, NSString};
use tokio::sync::mpsc;

use crate::error::ClipboardCreationError;
use crate::{Clipboard, ClipboardChange, ClipboardContent, ClipboardError, OriginHint};

/// Poll cadence for `changeCount`.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Per-instance pasteboard-type prefix.
const MARKER_PREFIX: &str = "de.feschber.LanMouse.origin.";

/// Canonical text MIME we report on the wire.
const MIME_TEXT_UTF8: &str = "text/plain;charset=utf-8";

enum Cmd {
    Set(ClipboardContent),
    Terminate,
}

pub(crate) struct MacOsClipboard {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    event_rx: mpsc::UnboundedReceiver<ClipboardChange>,
    thread: Option<JoinHandle<()>>,
}

impl MacOsClipboard {
    pub(crate) fn new(peer_id: &str) -> Result<Self, ClipboardCreationError> {
        let marker = format!("{MARKER_PREFIX}{peer_id}");

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let thread = thread::Builder::new()
            .name("lan-mouse-clipboard-macos".into())
            .spawn(move || run(marker, cmd_rx, event_tx))
            .map_err(|e| ClipboardCreationError::Backend(format!("spawn thread: {e}")))?;

        Ok(Self {
            cmd_tx,
            event_rx,
            thread: Some(thread),
        })
    }
}

#[async_trait]
impl Clipboard for MacOsClipboard {
    async fn next_event(&mut self) -> Option<ClipboardChange> {
        self.event_rx.recv().await
    }

    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError> {
        self.cmd_tx
            .send(Cmd::Set(content))
            .map_err(|_| ClipboardError::Backend("macos task is gone".into()))?;
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), ClipboardError> {
        let _ = self.cmd_tx.send(Cmd::Terminate);
        if let Some(handle) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = handle.join();
            })
            .await;
        }
        Ok(())
    }
}

fn run(
    marker: String,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    event_tx: mpsc::UnboundedSender<ClipboardChange>,
) {
    // Initial poll: read the current changeCount but do *not* broadcast.
    // Mirrors the plan's "mark initial as seen" rule.
    let mut last_seen: i64 = autoreleasepool(|_| {
        let pb = NSPasteboard::generalPasteboard();
        pb.changeCount() as i64
    });

    let mut next_tick = Instant::now() + POLL_INTERVAL;
    loop {
        // Drain any pending commands without blocking.
        loop {
            match cmd_rx.try_recv() {
                Ok(Cmd::Set(content)) => {
                    last_seen = autoreleasepool(|_| set_clipboard(&content, &marker));
                }
                Ok(Cmd::Terminate) => {
                    log::debug!("macos clipboard thread terminating");
                    return;
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    log::debug!("macos clipboard command channel dropped, exiting");
                    return;
                }
            }
        }

        // Poll the clipboard.
        autoreleasepool(|_| {
            let pb = NSPasteboard::generalPasteboard();
            let current = pb.changeCount() as i64;
            if current == last_seen {
                return;
            }
            last_seen = current;

            if is_marked_by_us(&pb, &marker) {
                log::debug!("macos clipboard: skipping self-fire (marker present)");
                return;
            }

            // SAFETY: extern static defined by AppKit; safe to read.
            let s = match pb.stringForType(unsafe { NSPasteboardTypeString }) {
                Some(s) => s,
                None => {
                    log::debug!("macos clipboard: no text representation");
                    return;
                }
            };
            let text = s.to_string();
            let change = ClipboardChange::Content {
                content: ClipboardContent {
                    mime: MIME_TEXT_UTF8.into(),
                    data: text.into_bytes(),
                },
                origin_hint: OriginHint::Local,
            };
            if event_tx.send(change).is_err() {
                log::debug!("macos clipboard: event consumer gone");
            }
        });

        // Sleep until the next tick. Use a tight cap so set() commands aren't
        // delayed by a full POLL_INTERVAL.
        let now = Instant::now();
        if now < next_tick {
            thread::sleep((next_tick - now).min(Duration::from_millis(50)));
        }
        if Instant::now() >= next_tick {
            next_tick += POLL_INTERVAL;
        }
    }
}

/// Set the clipboard string + marker, return the new `changeCount`. Caller
/// updates `last_seen` to this value so the very next poll tick won't see it
/// as a fresh change (defensive — the marker check above already suppresses
/// the self-fire, but skipping the poll body entirely is faster).
fn set_clipboard(content: &ClipboardContent, marker: &str) -> i64 {
    let pb = NSPasteboard::generalPasteboard();
    pb.clearContents();

    // Best-effort UTF-8 decode. We only ever set text/plain;charset=utf-8 in
    // v1, but be defensive about non-UTF8 payloads.
    let text = match std::str::from_utf8(&content.data) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            log::warn!("macos clipboard: dropping non-UTF8 payload");
            return pb.changeCount() as i64;
        }
    };

    let nsstring = NSString::from_str(&text);
    // SAFETY: extern static defined by AppKit; safe to read.
    pb.setString_forType(&nsstring, unsafe { NSPasteboardTypeString });

    // Marker UTI: payload is the fingerprint as UTF-8 (informational; we only
    // ever check the type name).
    let marker_type = NSString::from_str(marker);
    let payload = NSData::with_bytes(
        marker
            .strip_prefix(MARKER_PREFIX)
            .unwrap_or("")
            .as_bytes(),
    );
    pb.setData_forType(Some(&payload), &marker_type);

    pb.changeCount() as i64
}

fn is_marked_by_us(pb: &NSPasteboard, marker: &str) -> bool {
    let Some(types) = pb.types() else {
        return false;
    };
    types.iter().any(|t| t.to_string() == marker)
}
