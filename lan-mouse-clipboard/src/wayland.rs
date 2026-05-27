//! Wayland clipboard backend.
//!
//! Phase 4 of CLIPBOARD_PLAN.md. Supports both `ext_data_control_manager_v1`
//! (preferred) and `zwlr_data_control_manager_v1` v2 (fallback). The wayland
//! dispatch loop runs on a dedicated OS thread; commands and events cross
//! into the tokio runtime via `tokio::sync::mpsc`.

use std::{
    collections::HashMap,
    io::Read,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    sync::Arc,
    thread::{self, JoinHandle},
};

use async_trait::async_trait;
use tokio::sync::mpsc;
use wayland_client::{
    Connection, Dispatch, EventQueue, Proxy, QueueHandle, delegate_noop, event_created_child,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{wl_registry, wl_seat::WlSeat},
};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1::{self as ext_device, ExtDataControlDeviceV1},
    ext_data_control_manager_v1::ExtDataControlManagerV1,
    ext_data_control_offer_v1::{self as ext_offer, ExtDataControlOfferV1},
    ext_data_control_source_v1::{self as ext_source, ExtDataControlSourceV1},
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1::{self as wlr_device, ZwlrDataControlDeviceV1},
    zwlr_data_control_manager_v1::ZwlrDataControlManagerV1,
    zwlr_data_control_offer_v1::{self as wlr_offer, ZwlrDataControlOfferV1},
    zwlr_data_control_source_v1::{self as wlr_source, ZwlrDataControlSourceV1},
};

use crate::{Clipboard, ClipboardChange, ClipboardContent, ClipboardError, OriginHint};
use crate::error::ClipboardCreationError;

/// Canonical UTF-8 plain text MIME type.
const MIME_TEXT_UTF8: &str = "text/plain;charset=utf-8";
/// Legacy fallback MIME type.
const MIME_TEXT_LEGACY: &str = "text/plain";
/// Origin marker MIME prefix. Each lan-mouse instance offers a MIME of the
/// form `application/x-lan-mouse-origin;peer=<fingerprint>` alongside the
/// text MIMEs. Receivers (including this instance) drop any selection whose
/// advertised MIME list contains *their own* marker. The marker carries the
/// peer fingerprint so two lan-mouse instances on the same machine still
/// see each other's clipboard.
const MIME_ORIGIN_PREFIX: &str = "application/x-lan-mouse-origin;peer=";

/// Commands accepted by the wayland dispatch thread.
enum Cmd {
    /// Replace the local selection with the given content.
    Set(ClipboardContent),
    /// Tear down the connection and exit the dispatch thread.
    Terminate,
}

/// Events emitted to the tokio side. Currently this is only the trait's
/// `ClipboardChange`, but a future Phase 7 hook may add a NullSelection
/// variant (see plan).
enum Event {
    Change(ClipboardChange),
}

/// Wakeup pipe used to break the wayland dispatch thread out of `poll()` when
/// a new command is queued via `cmd_tx`. The dispatch thread polls
/// `wakeup_read` alongside the wayland fd; the sender writes a single byte
/// after every `cmd_tx.send`.
#[derive(Clone)]
struct Wakeup {
    write_fd: Arc<OwnedFd>,
}

impl Wakeup {
    fn notify(&self) {
        // SAFETY: write_fd is open for the lifetime of this Arc.
        let buf: [u8; 1] = [0];
        let n = unsafe {
            write(
                self.write_fd.as_raw_fd(),
                buf.as_ptr() as *const _,
                1,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            // EAGAIN is acceptable: a byte is already pending and the reader
            // will see it. Anything else is unexpected.
            if err.raw_os_error() != Some(11) /* EAGAIN */ {
                log::warn!("wayland clipboard wakeup write failed: {err}");
            }
        }
    }
}

pub(crate) struct WaylandClipboard {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    wakeup: Wakeup,
    event_rx: mpsc::UnboundedReceiver<Event>,
    /// JoinHandle for the dispatch thread; held so we can await termination.
    /// Wrapped in an Option so `terminate()` can take it.
    thread: Option<JoinHandle<()>>,
}

impl WaylandClipboard {
    pub(crate) fn new(peer_id: &str) -> Result<Self, ClipboardCreationError> {
        let origin_marker = format!("{MIME_ORIGIN_PREFIX}{peer_id}");
        let conn = Connection::connect_to_env()
            .map_err(|e| ClipboardCreationError::Backend(format!("wayland connect: {e}")))?;
        let (globals, queue) = registry_queue_init::<State>(&conn)
            .map_err(|e| ClipboardCreationError::Backend(format!("wayland registry: {e}")))?;
        let qh = queue.handle();

        // Bind any wl_seat. We just need one for get_data_device.
        let seat: WlSeat = globals.bind(&qh, 1..=8, ()).map_err(|e| {
            ClipboardCreationError::Backend(format!("wl_seat unavailable: {e}"))
        })?;

        // Try ext first, then wlr v2.
        let manager: Manager = if let Ok(m) = globals.bind::<ExtDataControlManagerV1, _, _>(&qh, 1..=1, ()) {
            log::info!("wayland clipboard: using ext_data_control_manager_v1");
            let device = m.get_data_device(&seat, &qh, ());
            Manager::Ext { manager: m, device }
        } else if let Ok(m) = globals.bind::<ZwlrDataControlManagerV1, _, _>(&qh, 2..=2, ()) {
            log::info!("wayland clipboard: using zwlr_data_control_manager_v1 v2");
            let device = m.get_data_device(&seat, &qh, ());
            Manager::Wlr { manager: m, device }
        } else {
            log::warn!("clipboard sync unavailable on this compositor: neither ext_data_control_v1 nor zwlr_data_control_v1 v2 advertised");
            return Err(ClipboardCreationError::Backend(
                "no data-control manager advertised".into(),
            ));
        };

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let (wakeup_read, wakeup_write) = make_pipe_flags(O_CLOEXEC | O_NONBLOCK)
            .ok_or_else(|| ClipboardCreationError::Backend("wakeup pipe2 failed".into()))?;
        let wakeup = Wakeup {
            write_fd: Arc::new(wakeup_write),
        };

        let thread = thread::Builder::new()
            .name("lan-mouse-clipboard-wayland".into())
            .spawn(move || {
                let mut state = State {
                    qh: qh.clone(),
                    manager,
                    offers: HashMap::new(),
                    pending_local_send: None,
                    local_source: None,
                    suppress_next_selection: false,
                    origin_marker,
                    event_tx,
                };
                run_dispatch(conn, queue, &mut state, cmd_rx, wakeup_read);
            })
            .map_err(|e| ClipboardCreationError::Backend(format!("spawn thread: {e}")))?;

        Ok(Self {
            cmd_tx,
            wakeup,
            event_rx,
            thread: Some(thread),
        })
    }
}

#[async_trait]
impl Clipboard for WaylandClipboard {
    async fn next_event(&mut self) -> Option<ClipboardChange> {
        match self.event_rx.recv().await? {
            Event::Change(c) => Some(c),
        }
    }

    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError> {
        self.cmd_tx
            .send(Cmd::Set(content))
            .map_err(|_| ClipboardError::Backend("wayland dispatch thread is gone".into()))?;
        self.wakeup.notify();
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), ClipboardError> {
        let _ = self.cmd_tx.send(Cmd::Terminate);
        self.wakeup.notify();
        if let Some(handle) = self.thread.take() {
            // Don't block tokio on the join — defer to a blocking task.
            let _ = tokio::task::spawn_blocking(move || {
                let _ = handle.join();
            })
            .await;
        }
        Ok(())
    }
}

// ---- dispatch-thread state -----------------------------------------------

enum Manager {
    Ext {
        #[allow(dead_code)] // retained for protocol lifetime; never destroyed manually
        manager: ExtDataControlManagerV1,
        device: ExtDataControlDeviceV1,
    },
    Wlr {
        #[allow(dead_code)]
        manager: ZwlrDataControlManagerV1,
        device: ZwlrDataControlDeviceV1,
    },
}

/// Identity of the active local source. Used to filter the self-fire that
/// the compositor sends back via `selection(offer)` after `set_selection`.
enum LocalSource {
    Ext(ExtDataControlSourceV1),
    Wlr(ZwlrDataControlSourceV1),
}

impl LocalSource {
    fn matches_ext(&self, other: &ExtDataControlSourceV1) -> bool {
        match self {
            LocalSource::Ext(s) => s.id() == other.id(),
            _ => false,
        }
    }
    fn matches_wlr(&self, other: &ZwlrDataControlSourceV1) -> bool {
        match self {
            LocalSource::Wlr(s) => s.id() == other.id(),
            _ => false,
        }
    }
    fn destroy(self) {
        match self {
            LocalSource::Ext(s) => s.destroy(),
            LocalSource::Wlr(s) => s.destroy(),
        }
    }
}

/// Per-offer state: the list of advertised MIME types, and whether the offer
/// is "ours" (i.e. produced by our own data_source).
#[derive(Default)]
struct OfferState {
    mime_types: Vec<String>,
}

struct State {
    qh: QueueHandle<State>,
    manager: Manager,
    /// Pending MIME advertisements for each in-flight offer.
    /// Keyed by proxy id of the offer, since both protocol types have distinct
    /// id namespaces but we never mix them in a single session.
    offers: HashMap<u32, OfferState>,
    /// Bytes queued for our local source's next `send` event(s).
    pending_local_send: Option<Vec<u8>>,
    /// Object identity of our last `set_selection` source, if any.
    local_source: Option<LocalSource>,
    /// True when the next non-null Selection event is the compositor echoing
    /// back our own `set_selection`. Cleared on consume. Race: if another
    /// client sets the selection in the same window, we'll drop their first
    /// selection event. Accepted limitation; see wl-clipboard for prior art.
    ///
    /// This is a belt-and-braces second line of defence; the primary
    /// self-fire suppression is the origin marker MIME (`origin_marker`).
    suppress_next_selection: bool,
    /// Full origin-marker MIME for this instance
    /// (`application/x-lan-mouse-origin;peer=<fp>`). Offered alongside the
    /// text MIMEs on every set; receive-side handlers drop any offer that
    /// carries this exact MIME.
    origin_marker: String,
    event_tx: mpsc::UnboundedSender<Event>,
}

fn run_dispatch(
    conn: Connection,
    mut queue: EventQueue<State>,
    state: &mut State,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    wakeup_read: OwnedFd,
) {
    log::debug!("wayland clipboard dispatch thread started");
    loop {
        // 1. Service any pending wayland events.
        if let Err(e) = queue.dispatch_pending(state) {
            log::error!("wayland dispatch: {e}");
            break;
        }

        // 2. Drain any commands that have arrived since the last loop.
        if !drain_commands(state, &mut cmd_rx, &wakeup_read) {
            return;
        }

        // 3. Flush any requests we just queued.
        if let Err(e) = conn.flush() {
            log::warn!("wayland flush: {e}");
        }

        // 4. Wait for the wayland fd OR the wakeup pipe to become readable.
        let guard = match conn.prepare_read() {
            Some(g) => g,
            None => {
                // Events are already buffered; loop and dispatch them.
                continue;
            }
        };
        let wl_fd = guard.connection_fd().as_raw_fd();
        let mut fds = [
            PollFd {
                fd: wl_fd,
                events: POLLIN,
                revents: 0,
            },
            PollFd {
                fd: wakeup_read.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            },
        ];
        // No timeout: rely on the wakeup pipe for command latency.
        let rc = unsafe { poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(4) /* EINTR */ {
                drop(guard);
                continue;
            }
            log::error!("wayland clipboard poll: {err}");
            break;
        }

        if (fds[0].revents & POLLIN) != 0 {
            if let Err(e) = guard.read() {
                log::error!("wayland clipboard read: {e}");
                break;
            }
        } else {
            drop(guard);
        }

        if (fds[1].revents & POLLIN) != 0 {
            drain_wakeup(&wakeup_read);
        }
    }
    log::debug!("wayland clipboard dispatch thread exiting");
}

/// Returns false if the thread should exit (Terminate received or sender dropped).
fn drain_commands(
    state: &mut State,
    cmd_rx: &mut mpsc::UnboundedReceiver<Cmd>,
    wakeup_read: &OwnedFd,
) -> bool {
    loop {
        match cmd_rx.try_recv() {
            Ok(Cmd::Set(content)) => handle_set(state, content),
            Ok(Cmd::Terminate) => {
                log::debug!("wayland clipboard dispatch thread terminating");
                return false;
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // Consume any pending wakeup bytes so the next poll only
                // triggers on truly new commands.
                drain_wakeup(wakeup_read);
                return true;
            }
            Err(mpsc::error::TryRecvError::Disconnected) => {
                log::debug!("wayland clipboard command channel dropped, exiting");
                return false;
            }
        }
    }
}

fn drain_wakeup(fd: &OwnedFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: fd is a borrowed OwnedFd valid for the lifetime of this call.
        let n = unsafe {
            read(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
            )
        };
        if n <= 0 {
            break;
        }
    }
}

fn handle_set(state: &mut State, content: ClipboardContent) {
    // Destroy previous local source so the new offer "wins" cleanly.
    if let Some(prev) = state.local_source.take() {
        prev.destroy();
    }
    state.pending_local_send = Some(content.data);
    // Suppress the echo selection event that the compositor will emit in
    // response to set_selection below.
    state.suppress_next_selection = true;

    match &state.manager {
        Manager::Ext { manager, device } => {
            let source = manager.create_data_source(&state.qh, ());
            source.offer(MIME_TEXT_UTF8.into());
            source.offer(MIME_TEXT_LEGACY.into());
            source.offer(state.origin_marker.clone());
            device.set_selection(Some(&source));
            state.local_source = Some(LocalSource::Ext(source));
        }
        Manager::Wlr { manager, device } => {
            let source = manager.create_data_source(&state.qh, ());
            source.offer(MIME_TEXT_UTF8.into());
            source.offer(MIME_TEXT_LEGACY.into());
            source.offer(state.origin_marker.clone());
            device.set_selection(Some(&source));
            state.local_source = Some(LocalSource::Wlr(source));
        }
    }
}

/// Spawn a one-shot OS thread that drains a pipe FD to EOF and forwards the
/// result to the tokio side as a `ClipboardChange`.
fn spawn_pipe_reader(fd: OwnedFd, mime: String, event_tx: mpsc::UnboundedSender<Event>) {
    thread::Builder::new()
        .name("lan-mouse-clipboard-pipe".into())
        .spawn(move || {
            let mut file = std::fs::File::from(fd);
            let mut buf = Vec::with_capacity(4096);
            if let Err(e) = file.read_to_end(&mut buf) {
                log::warn!("wayland clipboard pipe read failed: {e}");
                return;
            }
            let change = ClipboardChange::Content {
                content: ClipboardContent { mime, data: buf },
                origin_hint: OriginHint::Local,
            };
            if event_tx.send(Event::Change(change)).is_err() {
                log::debug!("wayland clipboard pipe: tokio receiver dropped");
            }
        })
        .expect("spawn pipe reader");
}

fn make_pipe() -> Option<(OwnedFd, OwnedFd)> {
    make_pipe_flags(O_CLOEXEC)
}

fn make_pipe_flags(flags: std::ffi::c_int) -> Option<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    // SAFETY: pipe2 with the given flags; both fds owned via OwnedFd below.
    let rc = unsafe { pipe2(fds.as_mut_ptr(), flags) };
    if rc != 0 {
        log::warn!("pipe2 failed: errno={}", std::io::Error::last_os_error());
        return None;
    }
    // SAFETY: fds are valid file descriptors just returned by pipe2.
    let read = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
    Some((read, write))
}

// We don't want to add `libc` as a direct dep here; use the existing `nix`-free
// std-only mechanism via `std::os::unix::io` and a direct extern.
extern "C" {
    fn pipe2(fds: *mut std::ffi::c_int, flags: std::ffi::c_int) -> std::ffi::c_int;
    fn poll(
        fds: *mut PollFd,
        nfds: std::ffi::c_ulong,
        timeout: std::ffi::c_int,
    ) -> std::ffi::c_int;
    fn read(
        fd: std::ffi::c_int,
        buf: *mut std::ffi::c_void,
        count: usize,
    ) -> isize;
    fn write(
        fd: std::ffi::c_int,
        buf: *const std::ffi::c_void,
        count: usize,
    ) -> isize;
}
const O_CLOEXEC: std::ffi::c_int = 0o2000000;
const O_NONBLOCK: std::ffi::c_int = 0o4000;
const POLLIN: std::ffi::c_short = 0x0001;

#[repr(C)]
struct PollFd {
    fd: std::ffi::c_int,
    events: std::ffi::c_short,
    revents: std::ffi::c_short,
}

use std::os::fd::FromRawFd;

fn pick_mime(state: &OfferState) -> Option<String> {
    if state.mime_types.iter().any(|m| m == MIME_TEXT_UTF8) {
        Some(MIME_TEXT_UTF8.into())
    } else if state.mime_types.iter().any(|m| m == MIME_TEXT_LEGACY) {
        Some(MIME_TEXT_LEGACY.into())
    } else {
        None
    }
}

// ---- registry --------------------------------------------------------------

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
    }
}

delegate_noop!(State: ignore WlSeat);

// ---- ext-data-control dispatch --------------------------------------------

impl Dispatch<ExtDataControlManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ExtDataControlManagerV1,
        _: <ExtDataControlManagerV1 as Proxy>::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
    }
}

impl Dispatch<ExtDataControlDeviceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtDataControlDeviceV1,
        event: ext_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
        match event {
            ext_device::Event::DataOffer { id } => {
                state.offers.insert(id.id().protocol_id(), OfferState::default());
                // The offer proxy itself is short-lived; it'll be passed
                // back to us in the matching Selection event.
                let _ = id;
            }
            ext_device::Event::Selection { id } => handle_ext_selection(state, id),
            ext_device::Event::PrimarySelection { .. } => {
                // v1 only — and the plan says no primary selection sync.
            }
            ext_device::Event::Finished => {
                log::warn!("ext_data_control_device finished; clipboard sync no longer possible");
            }
            _ => {}
        }
    }

    // data_offer is the only event that creates a new object (opcode 0).
    event_created_child!(State, ExtDataControlDeviceV1, [
        0 => (ExtDataControlOfferV1, ()),
    ]);
}

fn handle_ext_selection(state: &mut State, id: Option<ExtDataControlOfferV1>) {
    let Some(offer) = id else {
        log::debug!("ext clipboard: null selection");
        let _ = state.event_tx.send(Event::Change(ClipboardChange::NullSelection));
        return;
    };
    let offer_id = offer.id().protocol_id();
    let advertised = state.offers.get(&offer_id);
    let is_ours = advertised
        .map(|s| s.mime_types.iter().any(|m| m == &state.origin_marker))
        .unwrap_or(false);
    if is_ours {
        log::debug!("ext clipboard: dropping offer tagged with our origin marker");
        state.suppress_next_selection = false;
        state.offers.remove(&offer_id);
        offer.destroy();
        return;
    }
    if state.suppress_next_selection {
        log::debug!("ext clipboard: suppressing selection (state-machine fallback)");
        state.suppress_next_selection = false;
        state.offers.remove(&offer_id);
        offer.destroy();
        return;
    }
    receive_offer_ext(state, offer);
}

fn receive_offer_ext(state: &mut State, offer: ExtDataControlOfferV1) {
    let offer_state = state
        .offers
        .remove(&offer.id().protocol_id())
        .unwrap_or_default();
    let mime = match pick_mime(&offer_state) {
        Some(m) => m,
        None => {
            log::debug!(
                "ext clipboard: no compatible MIME (had: {:?})",
                offer_state.mime_types
            );
            offer.destroy();
            return;
        }
    };

    let Some((read, write)) = make_pipe() else {
        offer.destroy();
        return;
    };

    offer.receive(mime.clone(), write.as_fd());
    drop(write);

    spawn_pipe_reader(read, mime, state.event_tx.clone());
    offer.destroy();
}

impl Dispatch<ExtDataControlOfferV1, ()> for State {
    fn event(
        state: &mut Self,
        offer: &ExtDataControlOfferV1,
        event: ext_offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
        if let ext_offer::Event::Offer { mime_type } = event {
            state
                .offers
                .entry(offer.id().protocol_id())
                .or_default()
                .mime_types
                .push(mime_type);
        }
    }
}

impl Dispatch<ExtDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        source: &ExtDataControlSourceV1,
        event: ext_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
        match event {
            ext_source::Event::Send { mime_type, fd } => {
                handle_source_send(state, &mime_type, fd);
            }
            ext_source::Event::Cancelled => {
                if let Some(local) = &state.local_source {
                    if local.matches_ext(source) {
                        log::debug!("ext clipboard: our source was cancelled");
                        if let Some(prev) = state.local_source.take() {
                            prev.destroy();
                        }
                        state.pending_local_send = None;
                    }
                }
            }
            _ => {}
        }
    }
}

// ---- wlr-data-control dispatch --------------------------------------------

impl Dispatch<ZwlrDataControlManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZwlrDataControlManagerV1,
        _: <ZwlrDataControlManagerV1 as Proxy>::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
    }
}

impl Dispatch<ZwlrDataControlDeviceV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ZwlrDataControlDeviceV1,
        event: wlr_device::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
        match event {
            wlr_device::Event::DataOffer { id } => {
                state.offers.insert(id.id().protocol_id(), OfferState::default());
                let _ = id;
            }
            wlr_device::Event::Selection { id } => handle_wlr_selection(state, id),
            wlr_device::Event::PrimarySelection { .. } => {
                // No primary selection sync in v1.
            }
            wlr_device::Event::Finished => {
                log::warn!("zwlr_data_control_device finished; clipboard sync no longer possible");
            }
            _ => {}
        }
    }

    event_created_child!(State, ZwlrDataControlDeviceV1, [
        0 => (ZwlrDataControlOfferV1, ()),
    ]);
}

fn handle_wlr_selection(state: &mut State, id: Option<ZwlrDataControlOfferV1>) {
    let Some(offer) = id else {
        log::debug!("wlr clipboard: null selection");
        let _ = state.event_tx.send(Event::Change(ClipboardChange::NullSelection));
        return;
    };
    let offer_id = offer.id().protocol_id();
    let advertised = state.offers.get(&offer_id);
    let is_ours = advertised
        .map(|s| s.mime_types.iter().any(|m| m == &state.origin_marker))
        .unwrap_or(false);
    if is_ours {
        log::debug!("wlr clipboard: dropping offer tagged with our origin marker");
        state.suppress_next_selection = false;
        state.offers.remove(&offer_id);
        offer.destroy();
        return;
    }
    if state.suppress_next_selection {
        log::debug!("wlr clipboard: suppressing selection (state-machine fallback)");
        state.suppress_next_selection = false;
        state.offers.remove(&offer_id);
        offer.destroy();
        return;
    }
    receive_offer_wlr(state, offer);
}

fn receive_offer_wlr(state: &mut State, offer: ZwlrDataControlOfferV1) {
    let offer_state = state
        .offers
        .remove(&offer.id().protocol_id())
        .unwrap_or_default();
    let mime = match pick_mime(&offer_state) {
        Some(m) => m,
        None => {
            log::debug!(
                "wlr clipboard: no compatible MIME (had: {:?})",
                offer_state.mime_types
            );
            offer.destroy();
            return;
        }
    };

    let Some((read, write)) = make_pipe() else {
        offer.destroy();
        return;
    };

    offer.receive(mime.clone(), write.as_fd());
    drop(write);

    spawn_pipe_reader(read, mime, state.event_tx.clone());
    offer.destroy();
}

impl Dispatch<ZwlrDataControlOfferV1, ()> for State {
    fn event(
        state: &mut Self,
        offer: &ZwlrDataControlOfferV1,
        event: wlr_offer::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
        if let wlr_offer::Event::Offer { mime_type } = event {
            state
                .offers
                .entry(offer.id().protocol_id())
                .or_default()
                .mime_types
                .push(mime_type);
        }
    }
}

impl Dispatch<ZwlrDataControlSourceV1, ()> for State {
    fn event(
        state: &mut Self,
        source: &ZwlrDataControlSourceV1,
        event: wlr_source::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
        match event {
            wlr_source::Event::Send { mime_type, fd } => {
                handle_source_send(state, &mime_type, fd);
            }
            wlr_source::Event::Cancelled => {
                if let Some(local) = &state.local_source {
                    if local.matches_wlr(source) {
                        log::debug!("wlr clipboard: our source was cancelled");
                        if let Some(prev) = state.local_source.take() {
                            prev.destroy();
                        }
                        state.pending_local_send = None;
                    }
                }
            }
            _ => {}
        }
    }
}

fn handle_source_send(state: &State, mime_type: &str, fd: OwnedFd) {
    if mime_type == state.origin_marker {
        // Marker MIME: write the fingerprint as payload (just so an inspecting
        // tool sees something). The fingerprint is already encoded in the MIME
        // name; the body is informational.
        let body = mime_type
            .strip_prefix(MIME_ORIGIN_PREFIX)
            .unwrap_or("")
            .as_bytes()
            .to_vec();
        write_then_close(fd, body);
        return;
    }
    if let Some(bytes) = state.pending_local_send.clone() {
        write_then_close(fd, bytes);
    } else {
        drop(fd);
    }
}

fn write_then_close(fd: OwnedFd, bytes: Vec<u8>) {
    use std::io::Write;
    let mut file = std::fs::File::from(fd);
    if let Err(e) = file.write_all(&bytes) {
        log::warn!("wayland clipboard send: write failed: {e}");
    }
    // dropping `file` closes the fd, signalling EOF to the receiver.
}


