//! Clipboard task: bridges the local platform clipboard with the network
//! side-channel (`clipboard_net`).
//!
//! Phase 7 of CLIPBOARD_PLAN.md.
//!
//! State is split into two parts:
//!  * [`ClipboardState`] is pure (no IO) so it can be unit-tested without a
//!    real clipboard backend.
//!  * [`Clipboard`] wraps a [`LanMouseClipboard`] backend plus a
//!    [`ClipboardState`]; this is what the service owns.

use std::collections::HashMap;

use lan_mouse_clipboard::{
    CAP_CLIPBOARD, CapMsg, Clipboard as ClipboardTrait, ClipboardChange, ClipboardContent,
    ClipboardError, LanMouseClipboard, PROTOCOL_VERSION,
};

use crate::clipboard_net::ClipboardNetEvent;

const MIME_TEXT_UTF8: &str = "text/plain;charset=utf-8";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectionOrigin {
    Local,
    Remote,
}

/// Pure loop-suppression and lifecycle state. No IO; suitable for unit tests.
pub(crate) struct ClipboardState {
    local_fingerprint: String,
    local_serial: u64,
    last_seen: HashMap<String, u64>,
    selection_origin: SelectionOrigin,
    last_remote_content: Option<ClipboardContent>,
    /// Content this peer currently holds (last local broadcast or remote
    /// apply). Remote messages carrying identical content are suppressed,
    /// which terminates relay cycles.
    current_content: Option<ClipboardContent>,
    startup_baseline_consumed: bool,
}

/// Decision returned by [`ClipboardState::on_local_change`].
#[derive(Debug, PartialEq)]
pub(crate) enum LocalChangeDecision {
    /// Broadcast this `CapMsg::Clipboard` to all peers.
    Broadcast(CapMsg),
    /// Re-claim the wayland selection by re-applying this content.
    Reclaim(ClipboardContent),
    /// Do nothing (baseline absorbed; null selection with no remote cached).
    Nothing,
}

impl ClipboardState {
    pub(crate) fn new(local_fingerprint: String) -> Self {
        Self {
            local_fingerprint,
            local_serial: 0,
            last_seen: HashMap::new(),
            // Whatever is on the local clipboard at startup is "Local"; we
            // didn't place it there.
            selection_origin: SelectionOrigin::Local,
            last_remote_content: None,
            current_content: None,
            startup_baseline_consumed: false,
        }
    }

    pub(crate) fn local_fingerprint(&self) -> &str {
        &self.local_fingerprint
    }

    fn bump_serial(&mut self) {
        self.local_serial = self.local_serial.wrapping_add(1);
        if self.local_serial == 0 {
            // 0 is a sentinel for "never seen"; skip past it on wrap.
            self.local_serial = 1;
        }
    }

    /// Re-originate remotely-received content for relaying to other peers:
    /// the message goes out under our own fingerprint and a fresh serial so
    /// receivers' origin-vs-TLS-fingerprint check holds.
    pub(crate) fn make_relay(&mut self, content: &ClipboardContent) -> CapMsg {
        self.bump_serial();
        CapMsg::Clipboard {
            origin: self.local_fingerprint.clone(),
            serial: self.local_serial,
            mime: content.mime.clone(),
            data: content.data.clone(),
        }
    }

    /// Process a `ClipboardChange` observed by the local backend.
    pub(crate) fn on_local_change(&mut self, change: ClipboardChange) -> LocalChangeDecision {
        match change {
            ClipboardChange::Content {
                content,
                origin_hint: _,
            } => {
                if !self.startup_baseline_consumed {
                    log::debug!(
                        "clipboard: startup baseline consumed (mime={}, {} bytes)",
                        content.mime,
                        content.data.len()
                    );
                    self.startup_baseline_consumed = true;
                    self.selection_origin = SelectionOrigin::Local;
                    self.current_content = Some(content);
                    return LocalChangeDecision::Nothing;
                }

                self.bump_serial();
                self.selection_origin = SelectionOrigin::Local;
                self.current_content = Some(content.clone());
                log::debug!(
                    "clipboard: broadcasting local change (serial={}, mime={}, {} bytes)",
                    self.local_serial,
                    content.mime,
                    content.data.len()
                );
                LocalChangeDecision::Broadcast(CapMsg::Clipboard {
                    origin: self.local_fingerprint.clone(),
                    serial: self.local_serial,
                    mime: content.mime,
                    data: content.data,
                })
            }
            ClipboardChange::NullSelection => {
                if self.selection_origin != SelectionOrigin::Remote {
                    log::debug!("clipboard: null selection with local origin; not re-claiming");
                    return LocalChangeDecision::Nothing;
                }
                match self.last_remote_content.clone() {
                    Some(content) => {
                        log::info!(
                            "clipboard: re-claiming null selection with last remote content"
                        );
                        LocalChangeDecision::Reclaim(content)
                    }
                    None => {
                        log::debug!(
                            "clipboard: null selection but no remote content cached; not re-claiming"
                        );
                        LocalChangeDecision::Nothing
                    }
                }
            }
        }
    }

    /// Process an inbound `CapMsg::Clipboard`. Returns the content to apply
    /// if the message passes the loop-suppression check; otherwise `None`.
    ///
    /// `origin` must already have been validated against the TLS peer
    /// fingerprint by the caller.
    pub(crate) fn on_remote_message(
        &mut self,
        origin: String,
        serial: u64,
        mime: String,
        data: Vec<u8>,
    ) -> Option<ClipboardContent> {
        if origin == self.local_fingerprint {
            log::warn!(
                "clipboard: received message claiming our own peer_id as origin; dropping"
            );
            return None;
        }
        let last = self.last_seen.get(&origin).copied().unwrap_or(0);
        if serial <= last {
            log::debug!(
                "clipboard: dropping stale remote msg (origin={origin}, serial={serial}, last_seen={last})"
            );
            return None;
        }
        self.last_seen.insert(origin.clone(), serial);
        if mime != MIME_TEXT_UTF8 && mime != "text/plain" {
            log::debug!(
                "clipboard: remote message uses unexpected MIME `{mime}`; applying as text anyway"
            );
        }
        let content = ClipboardContent { mime, data };
        if self.current_content.as_ref() == Some(&content) {
            log::debug!(
                "clipboard: remote content from {origin} matches current content; suppressing"
            );
            return None;
        }
        self.last_remote_content = Some(content.clone());
        self.current_content = Some(content.clone());
        self.selection_origin = SelectionOrigin::Remote;
        Some(content)
    }

    /// Reset `last_seen[peer]` so a freshly (re)connected peer's first message
    /// is always accepted (peer-restart handling).
    pub(crate) fn reset_peer(&mut self, fingerprint: &str) {
        if self.last_seen.remove(fingerprint).is_some() {
            log::debug!("clipboard: reset last_seen[{fingerprint}]");
        }
    }

    /// Test-only accessor.
    #[cfg(test)]
    pub(crate) fn selection_origin(&self) -> SelectionOrigin {
        self.selection_origin
    }

    /// Test-only accessor.
    #[cfg(test)]
    pub(crate) fn last_seen(&self, fingerprint: &str) -> u64 {
        self.last_seen.get(fingerprint).copied().unwrap_or(0)
    }
}

pub(crate) struct Clipboard {
    backend: LanMouseClipboard,
    state: ClipboardState,
}

impl Clipboard {
    pub(crate) fn new(backend: LanMouseClipboard, local_fingerprint: String) -> Self {
        Self {
            backend,
            state: ClipboardState::new(local_fingerprint),
        }
    }

    pub(crate) async fn next_backend_event(&mut self) -> Option<ClipboardChange> {
        self.backend.next_event().await
    }

    /// Drive the backend in response to a local clipboard change. Returns a
    /// `CapMsg` to broadcast (if any). Re-claim (null-selection) side effects
    /// are applied via `backend.set(...)` here, before returning.
    pub(crate) async fn handle_local_change(
        &mut self,
        change: ClipboardChange,
    ) -> Option<CapMsg> {
        match self.state.on_local_change(change) {
            LocalChangeDecision::Broadcast(msg) => Some(msg),
            LocalChangeDecision::Reclaim(content) => {
                if let Err(e) = self.backend.set(content).await {
                    log::warn!("clipboard: re-claim failed: {e}");
                }
                None
            }
            LocalChangeDecision::Nothing => None,
        }
    }

    /// Apply a remote content to the local backend.
    pub(crate) async fn apply_remote(
        &mut self,
        content: ClipboardContent,
    ) -> Result<(), ClipboardError> {
        log::info!(
            "clipboard: applying remote content locally (mime={}, {} bytes)",
            content.mime,
            content.data.len()
        );
        self.backend.set(content).await
    }

    /// Make a `Hello` for this peer.
    #[allow(dead_code)]
    pub(crate) fn make_hello(&self) -> CapMsg {
        CapMsg::Hello {
            protocol_version: PROTOCOL_VERSION,
            peer_id: self.state.local_fingerprint().to_owned(),
            capabilities: CAP_CLIPBOARD,
        }
    }

    pub(crate) async fn terminate(&mut self) {
        if let Err(e) = self.backend.terminate().await {
            log::warn!("clipboard backend terminate: {e}");
        }
    }

    /// Route a clipboard_net event through the loop-suppression state.
    pub(crate) fn handle_net_event(&mut self, event: ClipboardNetEvent) -> NetOutcome {
        match event {
            ClipboardNetEvent::PeerConnected {
                addr: _,
                fingerprint,
                capabilities,
            } => {
                self.state.reset_peer(&fingerprint);
                if capabilities & CAP_CLIPBOARD == 0 {
                    log::info!(
                        "clipboard: peer {fingerprint} does not advertise CAP_CLIPBOARD; clipboard ops will be ignored from this peer"
                    );
                }
                NetOutcome::Nothing
            }
            ClipboardNetEvent::PeerDisconnected {
                addr: _,
                fingerprint: _,
            } => NetOutcome::Nothing,
            ClipboardNetEvent::Message {
                addr: _,
                fingerprint: claimed,
                msg,
            } => match msg {
                CapMsg::Hello { .. } => {
                    log::warn!("clipboard: received unexpected Hello via Message channel");
                    NetOutcome::Nothing
                }
                CapMsg::Clipboard {
                    origin,
                    serial,
                    mime,
                    data,
                } => {
                    if origin != claimed {
                        log::warn!(
                            "clipboard: origin {origin} != tls fingerprint {claimed}; dropping"
                        );
                        return NetOutcome::Nothing;
                    }
                    match self.state.on_remote_message(origin, serial, mime, data) {
                        Some(content) => {
                            let relay = self.state.make_relay(&content);
                            NetOutcome::ApplyLocal {
                                content,
                                relay,
                                src_fingerprint: claimed,
                            }
                        }
                        None => NetOutcome::Nothing,
                    }
                }
            },
        }
    }
}

/// Outcome of routing a `ClipboardNetEvent`.
pub(crate) enum NetOutcome {
    /// Apply `content` locally and relay the re-originated message to every
    /// peer except those whose fingerprint matches `src_fingerprint`. Relaying
    /// makes leaf-to-leaf propagation work in a star topology, where leaves
    /// are only connected to the hub.
    ApplyLocal {
        content: ClipboardContent,
        relay: CapMsg,
        src_fingerprint: String,
    },
    Nothing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lan_mouse_clipboard::OriginHint;

    const FP_LOCAL: &str = "aa:aa";
    const FP_REMOTE_A: &str = "bb:bb";
    const FP_REMOTE_B: &str = "cc:cc";

    fn local_state() -> ClipboardState {
        ClipboardState::new(FP_LOCAL.into())
    }

    fn text(s: &str) -> ClipboardContent {
        ClipboardContent {
            mime: MIME_TEXT_UTF8.into(),
            data: s.as_bytes().to_vec(),
        }
    }

    fn local_change(s: &str) -> ClipboardChange {
        ClipboardChange::Content {
            content: text(s),
            origin_hint: OriginHint::Local,
        }
    }

    fn extract_clipboard(msg: CapMsg) -> (String, u64, String, Vec<u8>) {
        match msg {
            CapMsg::Clipboard {
                origin,
                serial,
                mime,
                data,
            } => (origin, serial, mime, data),
            _ => panic!("expected Clipboard"),
        }
    }

    #[test]
    fn startup_baseline_is_not_broadcast() {
        let mut s = local_state();
        let d = s.on_local_change(local_change("first"));
        assert_eq!(d, LocalChangeDecision::Nothing);
        assert_eq!(s.selection_origin(), SelectionOrigin::Local);
    }

    #[test]
    fn second_local_change_is_broadcast_with_serial_1() {
        let mut s = local_state();
        // Baseline.
        let _ = s.on_local_change(local_change("first"));
        // Real change.
        let d = s.on_local_change(local_change("hello"));
        let LocalChangeDecision::Broadcast(msg) = d else {
            panic!("expected Broadcast, got {d:?}");
        };
        let (origin, serial, mime, data) = extract_clipboard(msg);
        assert_eq!(origin, FP_LOCAL);
        assert_eq!(serial, 1);
        assert_eq!(mime, MIME_TEXT_UTF8);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn local_serial_is_monotonic() {
        let mut s = local_state();
        let _ = s.on_local_change(local_change("baseline"));
        let mut serials = vec![];
        for i in 0..5 {
            let d = s.on_local_change(local_change(&format!("v{i}")));
            let LocalChangeDecision::Broadcast(msg) = d else {
                panic!("expected Broadcast");
            };
            let (_, serial, _, _) = extract_clipboard(msg);
            serials.push(serial);
        }
        assert_eq!(serials, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn remote_message_with_fresh_serial_is_accepted() {
        let mut s = local_state();
        let out = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"r1".to_vec());
        assert_eq!(out.as_ref().map(|c| c.data.as_slice()), Some(b"r1".as_slice()));
        assert_eq!(s.selection_origin(), SelectionOrigin::Remote);
        assert_eq!(s.last_seen(FP_REMOTE_A), 1);
    }

    #[test]
    fn remote_message_with_stale_serial_is_dropped() {
        let mut s = local_state();
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 5, MIME_TEXT_UTF8.into(), b"x".to_vec());
        // Equal serial: drop.
        let out = s.on_remote_message(FP_REMOTE_A.into(), 5, MIME_TEXT_UTF8.into(), b"y".to_vec());
        assert!(out.is_none());
        // Lower serial: drop.
        let out = s.on_remote_message(FP_REMOTE_A.into(), 3, MIME_TEXT_UTF8.into(), b"z".to_vec());
        assert!(out.is_none());
        // last_seen unchanged.
        assert_eq!(s.last_seen(FP_REMOTE_A), 5);
    }

    #[test]
    fn remote_serials_are_tracked_per_peer() {
        let mut s = local_state();
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 10, MIME_TEXT_UTF8.into(), b"a".to_vec());
        // Same serial from a different peer should still be accepted.
        let out =
            s.on_remote_message(FP_REMOTE_B.into(), 10, MIME_TEXT_UTF8.into(), b"b".to_vec());
        assert!(out.is_some());
        assert_eq!(s.last_seen(FP_REMOTE_A), 10);
        assert_eq!(s.last_seen(FP_REMOTE_B), 10);
    }

    #[test]
    fn peer_reset_unblocks_serial_after_restart() {
        let mut s = local_state();
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 9, MIME_TEXT_UTF8.into(), b"x".to_vec());
        // Peer restarts and resets to serial 1; without reset, would be dropped.
        s.reset_peer(FP_REMOTE_A);
        assert_eq!(s.last_seen(FP_REMOTE_A), 0);
        let out =
            s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"y".to_vec());
        assert!(out.is_some());
    }

    #[test]
    fn duplicate_remote_content_is_suppressed() {
        let mut s = local_state();
        let out = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"x".to_vec());
        assert!(out.is_some());
        // Same content from a different peer with a fresh serial: suppressed,
        // but the serial is still consumed.
        let out = s.on_remote_message(FP_REMOTE_B.into(), 1, MIME_TEXT_UTF8.into(), b"x".to_vec());
        assert!(out.is_none());
        assert_eq!(s.last_seen(FP_REMOTE_B), 1);
    }

    #[test]
    fn duplicate_content_accepted_after_local_change() {
        let mut s = local_state();
        let _ = s.on_local_change(local_change("baseline"));
        let out = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"x".to_vec());
        assert!(out.is_some());
        // Local copy of different content invalidates the suppression.
        let _ = s.on_local_change(local_change("y"));
        let out = s.on_remote_message(FP_REMOTE_A.into(), 2, MIME_TEXT_UTF8.into(), b"x".to_vec());
        assert!(out.is_some());
    }

    #[test]
    fn make_relay_re_originates_with_fresh_serial() {
        let mut s = local_state();
        let _ = s.on_local_change(local_change("baseline"));
        let _ = s.on_local_change(local_change("local")); // serial 1
        let msg = s.make_relay(&text("relayed"));
        let (origin, serial, mime, data) = extract_clipboard(msg);
        assert_eq!(origin, FP_LOCAL);
        assert_eq!(serial, 2);
        assert_eq!(mime, MIME_TEXT_UTF8);
        assert_eq!(data, b"relayed");
        // Relaying must not flip the selection origin.
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"r".to_vec());
        let _ = s.make_relay(&text("r"));
        assert_eq!(s.selection_origin(), SelectionOrigin::Remote);
    }

    #[test]
    fn remote_message_with_local_origin_is_dropped() {
        let mut s = local_state();
        let out = s.on_remote_message(FP_LOCAL.into(), 1, MIME_TEXT_UTF8.into(), b"x".to_vec());
        assert!(out.is_none());
    }

    #[test]
    fn null_selection_after_local_does_nothing() {
        let mut s = local_state();
        // Make selection_origin Local.
        let _ = s.on_local_change(local_change("baseline"));
        let _ = s.on_local_change(local_change("hello"));
        assert_eq!(s.selection_origin(), SelectionOrigin::Local);
        let d = s.on_local_change(ClipboardChange::NullSelection);
        assert_eq!(d, LocalChangeDecision::Nothing);
    }

    #[test]
    fn null_selection_after_remote_reclaims() {
        let mut s = local_state();
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"r".to_vec());
        assert_eq!(s.selection_origin(), SelectionOrigin::Remote);
        let d = s.on_local_change(ClipboardChange::NullSelection);
        let LocalChangeDecision::Reclaim(content) = d else {
            panic!("expected Reclaim, got {d:?}");
        };
        assert_eq!(content.data, b"r");
    }

    #[test]
    fn null_selection_after_remote_without_cache_does_nothing() {
        // selection_origin would have to be Remote without last_remote_content
        // being set, which shouldn't happen via the public API, but test the
        // defensive code path.
        let mut s = local_state();
        // Force selection_origin to Remote without populating last_remote_content.
        // Done via direct field access; not exposed on the public API.
        s.selection_origin = SelectionOrigin::Remote;
        let d = s.on_local_change(ClipboardChange::NullSelection);
        assert_eq!(d, LocalChangeDecision::Nothing);
    }

    #[test]
    fn remote_apply_sets_origin_to_remote() {
        let mut s = local_state();
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"x".to_vec());
        assert_eq!(s.selection_origin(), SelectionOrigin::Remote);
        // Local change after a remote should bump serial and flip back to Local.
        let _ = s.on_local_change(local_change("baseline"));
        // baseline absorbed but selection_origin set to Local
        assert_eq!(s.selection_origin(), SelectionOrigin::Local);
    }

    #[test]
    fn remote_does_not_consume_baseline() {
        // A remote message before any local change should NOT consume the
        // startup baseline; the next local change must still be absorbed.
        let mut s = local_state();
        let _ = s.on_remote_message(FP_REMOTE_A.into(), 1, MIME_TEXT_UTF8.into(), b"r".to_vec());
        // First local change should still be the baseline (not broadcast).
        let d = s.on_local_change(local_change("first"));
        assert_eq!(d, LocalChangeDecision::Nothing);
    }

    /// Two-peer integration tests: drive a pair of `ClipboardState` machines
    /// through realistic copy/paste flows, with explicit routing of
    /// `CapMsg::Clipboard` between them. Verifies that loop-suppression
    /// prevents echo, peer-restart works, and out-of-order serials are
    /// rejected.
    mod integration {
        use super::*;

        const FP_A: &str = "aa:aa";
        const FP_B: &str = "bb:bb";

        /// Apply the broadcast from `from` to `to`. The caller is expected
        /// to keep the `CapMsg::Clipboard` they wish to forward.
        fn deliver(state: &mut ClipboardState, msg: CapMsg) -> Option<ClipboardContent> {
            match msg {
                CapMsg::Clipboard {
                    origin,
                    serial,
                    mime,
                    data,
                } => state.on_remote_message(origin, serial, mime, data),
                _ => panic!("expected Clipboard"),
            }
        }

        fn baseline(s: &mut ClipboardState) {
            assert_eq!(
                s.on_local_change(local_change("")),
                LocalChangeDecision::Nothing
            );
        }

        #[test]
        fn a_copies_b_pastes() {
            let mut a = ClipboardState::new(FP_A.into());
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut a);
            baseline(&mut b);

            // A copies "hello".
            let d = a.on_local_change(local_change("hello"));
            let LocalChangeDecision::Broadcast(msg) = d else {
                panic!("expected Broadcast");
            };
            // Delivered to B → applied.
            let applied = deliver(&mut b, msg);
            assert_eq!(applied.as_ref().map(|c| c.data.as_slice()), Some(b"hello".as_slice()));
            // B's state should have FP_A's serial recorded.
            assert_eq!(b.last_seen(FP_A), 1);
            assert_eq!(b.selection_origin(), SelectionOrigin::Remote);
        }

        #[test]
        fn no_loop_when_b_does_not_rebroadcast_remote_apply() {
            // The plan: "A receiver applying a remote `Clipboard` does not
            // re-broadcast." In our model, the on_remote_message path
            // returns the content for the *backend* to apply; the backend's
            // self-fire suppression (origin marker / changeCount sniffing)
            // ensures the resulting local-change event is squelched. We
            // simulate that here by not calling on_local_change after apply.
            let mut a = ClipboardState::new(FP_A.into());
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut a);
            baseline(&mut b);

            let LocalChangeDecision::Broadcast(msg) = a.on_local_change(local_change("hello"))
            else {
                panic!();
            };
            let _ = deliver(&mut b, msg);
            // B's local serial should be unchanged (0 baseline-only).
            assert_eq!(b.last_seen(FP_B), 0);
            // If B had re-broadcast, we'd see local_serial == 1 in a
            // broadcast message; verify by triggering an actual local change
            // and seeing serial 1, not 2.
            let LocalChangeDecision::Broadcast(msg) = b.on_local_change(local_change("from_b"))
            else {
                panic!();
            };
            if let CapMsg::Clipboard { serial, origin, .. } = msg {
                assert_eq!(serial, 1);
                assert_eq!(origin, FP_B);
            } else {
                panic!();
            }
        }

        #[test]
        fn alternating_copies_each_side_wins() {
            let mut a = ClipboardState::new(FP_A.into());
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut a);
            baseline(&mut b);

            // A:1 -> B
            let LocalChangeDecision::Broadcast(msg) = a.on_local_change(local_change("a1")) else {
                panic!();
            };
            assert!(deliver(&mut b, msg).is_some());
            // B:1 -> A
            let LocalChangeDecision::Broadcast(msg) = b.on_local_change(local_change("b1")) else {
                panic!();
            };
            assert!(deliver(&mut a, msg).is_some());
            // A:2 -> B
            let LocalChangeDecision::Broadcast(msg) = a.on_local_change(local_change("a2")) else {
                panic!();
            };
            assert!(deliver(&mut b, msg).is_some());
            // B saw A:1 then A:2 -> last_seen[A] == 2
            assert_eq!(b.last_seen(FP_A), 2);
            // A saw B:1 -> last_seen[B] == 1
            assert_eq!(a.last_seen(FP_B), 1);
        }

        #[test]
        fn out_of_order_delivery_drops_older() {
            let mut a = ClipboardState::new(FP_A.into());
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut a);
            baseline(&mut b);

            let LocalChangeDecision::Broadcast(m1) = a.on_local_change(local_change("a1")) else {
                panic!();
            };
            let LocalChangeDecision::Broadcast(m2) = a.on_local_change(local_change("a2")) else {
                panic!();
            };
            // Deliver newer first, then older. Older must be dropped.
            assert!(deliver(&mut b, m2).is_some());
            assert!(deliver(&mut b, m1).is_none());
            assert_eq!(b.last_seen(FP_A), 2);
        }

        #[test]
        fn peer_restart_unblocks_new_session() {
            let mut a = ClipboardState::new(FP_A.into());
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut a);
            baseline(&mut b);

            // A copies and sends a few times.
            for _ in 0..3 {
                let LocalChangeDecision::Broadcast(msg) = a.on_local_change(local_change("x"))
                else {
                    panic!();
                };
                let _ = deliver(&mut b, msg);
            }
            assert_eq!(b.last_seen(FP_A), 3);

            // A restarts: its local_serial resets. Plan says: on fresh
            // TCP+Hello, the *receiver* resets last_seen[origin] to 0.
            // Without that, A's next message (serial 1) would be dropped.
            b.reset_peer(FP_A);
            assert_eq!(b.last_seen(FP_A), 0);

            // Simulate A restarted (new ClipboardState).
            let mut a2 = ClipboardState::new(FP_A.into());
            baseline(&mut a2);
            let LocalChangeDecision::Broadcast(msg) = a2.on_local_change(local_change("y")) else {
                panic!();
            };
            assert!(deliver(&mut b, msg).is_some());
            assert_eq!(b.last_seen(FP_A), 1);
        }

        #[test]
        fn relay_cycle_terminates() {
            // Star topology with an extra leaf-to-leaf link (worst case:
            // full mesh A-M-B). Every accepted message is relayed; content
            // suppression must terminate the cycle.
            const FP_M: &str = "mm:mm";
            let mut a = ClipboardState::new(FP_A.into());
            let mut m = ClipboardState::new(FP_M.into());
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut a);
            baseline(&mut m);
            baseline(&mut b);

            // A copies "x" and broadcasts to M (star: A is only connected
            // to the hub M).
            let LocalChangeDecision::Broadcast(msg) = a.on_local_change(local_change("x")) else {
                panic!();
            };
            // M accepts and relays to B.
            let content = deliver(&mut m, msg).expect("hub applies");
            let relay = m.make_relay(&content);
            // B accepts and relays to its peers except M (in a mesh, that
            // includes A).
            let content = deliver(&mut b, relay).expect("leaf applies");
            let relay = b.make_relay(&content);
            // A already holds "x": suppressed, cycle dead.
            assert!(deliver(&mut a, relay).is_none());
        }

        #[test]
        fn b_ignores_message_claiming_to_be_b() {
            let mut b = ClipboardState::new(FP_B.into());
            baseline(&mut b);
            // Hostile (impossible-in-v1, but defensive) message claiming
            // B's own fingerprint as origin.
            let out =
                b.on_remote_message(FP_B.into(), 1, MIME_TEXT_UTF8.into(), b"spoof".to_vec());
            assert!(out.is_none());
        }
    }
}
