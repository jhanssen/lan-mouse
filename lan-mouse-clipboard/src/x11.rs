//! X11 clipboard backend: the CLIPBOARD selection via Xlib, owner changes via
//! XFixes. Transfers larger than one request use ICCCM INCR in both
//! directions. Runs on a dedicated thread with its own `Display`.

use std::{
    ffi::{CString, c_char, c_int, c_long, c_uchar, c_ulong, c_void},
    io::{ErrorKind, Read, Write},
    mem,
    os::{fd::AsRawFd, unix::net::UnixStream},
    ptr,
    rc::Rc,
    sync::{
        Mutex, Once, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::sync::mpsc;
use x11::{xfixes, xlib};

use crate::{
    Clipboard, ClipboardChange, ClipboardContent, ClipboardError, OriginHint,
    error::ClipboardCreationError,
};

const MIME_TEXT_UTF8: &str = "text/plain;charset=utf-8";
const MAX_CONTENT: usize = 64 * 1024 * 1024;
/// A transfer whose peer makes no progress for this long is abandoned.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);

// Xfixes.h; not exported by the `x11` crate.
const XFIXES_SELECTION_NOTIFY: c_int = 0;
const XFIXES_SELECTION_EVENT_MASK: c_ulong = 0b111; // owner set | window destroy | client close

const XA_INTEGER: xlib::Atom = 19;

enum Cmd {
    Set(ClipboardContent),
    Terminate,
}

pub(crate) struct X11Clipboard {
    cmd_tx: mpsc::UnboundedSender<Cmd>,
    wakeup: UnixStream,
    event_rx: mpsc::UnboundedReceiver<ClipboardChange>,
    thread: Option<JoinHandle<()>>,
}

impl X11Clipboard {
    pub(crate) fn new() -> Result<Self, ClipboardCreationError> {
        let backend_err = |e: std::io::Error| ClipboardCreationError::Backend(e.to_string());
        let (wakeup, wakeup_rx) = UnixStream::pair().map_err(backend_err)?;
        wakeup.set_nonblocking(true).map_err(backend_err)?;
        wakeup_rx.set_nonblocking(true).map_err(backend_err)?;
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (init_tx, init_rx) = std_mpsc::channel();

        // Xlib objects are not Send, so the display is opened on the thread.
        let thread = thread::Builder::new()
            .name("lan-mouse-clipboard-x11".into())
            .spawn(move || match X11State::open(event_tx) {
                Ok(mut state) => {
                    let _ = init_tx.send(Ok(()));
                    state.run(cmd_rx, wakeup_rx);
                }
                Err(e) => {
                    let _ = init_tx.send(Err(e));
                }
            })
            .map_err(backend_err)?;

        match init_rx.recv() {
            Ok(Ok(())) => {
                log::info!("x11 clipboard: watching CLIPBOARD selection");
                Ok(Self {
                    cmd_tx,
                    wakeup,
                    event_rx,
                    thread: Some(thread),
                })
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err(ClipboardCreationError::Backend(
                "x11 clipboard thread exited during init".into(),
            )),
        }
    }

    fn notify(&self) {
        if let Err(e) = (&self.wakeup).write(&[0]) {
            // WouldBlock: a wakeup is already pending. BrokenPipe: the thread exited.
            if !matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::BrokenPipe) {
                log::warn!("x11 clipboard wakeup failed: {e}");
            }
        }
    }
}

#[async_trait]
impl Clipboard for X11Clipboard {
    async fn next_event(&mut self) -> Option<ClipboardChange> {
        self.event_rx.recv().await
    }

    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError> {
        self.cmd_tx
            .send(Cmd::Set(content))
            .map_err(|_| ClipboardError::Backend("x11 clipboard thread is gone".into()))?;
        self.notify();
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), ClipboardError> {
        let _ = self.cmd_tx.send(Cmd::Terminate);
        self.notify();
        if let Some(handle) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = handle.join();
            })
            .await;
        }
        Ok(())
    }
}

struct Atoms {
    clipboard: xlib::Atom,
    targets: xlib::Atom,
    timestamp: xlib::Atom,
    incr: xlib::Atom,
    utf8_string: xlib::Atom,
    text_plain_utf8: xlib::Atom,
    text_plain: xlib::Atom,
    /// Property on our window that receives converted selections.
    transfer: xlib::Atom,
    /// Property touched to obtain a server timestamp.
    time_probe: xlib::Atom,
}

impl Atoms {
    unsafe fn intern(dpy: *mut xlib::Display) -> Self {
        let intern = |name: &str| {
            let name = CString::new(name).expect("atom name");
            unsafe { xlib::XInternAtom(dpy, name.as_ptr(), xlib::False) }
        };
        Self {
            clipboard: intern("CLIPBOARD"),
            targets: intern("TARGETS"),
            timestamp: intern("TIMESTAMP"),
            incr: intern("INCR"),
            utf8_string: intern("UTF8_STRING"),
            text_plain_utf8: intern(MIME_TEXT_UTF8),
            text_plain: intern("text/plain"),
            transfer: intern("LAN_MOUSE_CLIPBOARD"),
            time_probe: intern("LAN_MOUSE_TIMESTAMP"),
        }
    }
}

/// Content we serve while owning CLIPBOARD (always UTF-8).
struct Owned {
    data: Rc<[u8]>,
    time: xlib::Time,
}

enum ReadPhase {
    Targets,
    Data { target: xlib::Atom },
    Incr { target: xlib::Atom, buf: Vec<u8> },
}

struct PendingRead {
    phase: ReadPhase,
    time: xlib::Time,
    last_activity: Instant,
}

/// An outgoing INCR transfer to one requestor.
struct IncrSend {
    requestor: xlib::Window,
    property: xlib::Atom,
    type_: xlib::Atom,
    data: Rc<[u8]>,
    offset: usize,
    last_activity: Instant,
}

struct X11State {
    dpy: *mut xlib::Display,
    win: xlib::Window,
    atoms: Atoms,
    xfixes_event_base: c_int,
    /// Largest property payload written in one request.
    max_chunk: usize,
    /// Set by the IO error exit handler; heap-allocated so its address is stable.
    io_dead: Box<AtomicBool>,
    event_tx: mpsc::UnboundedSender<ClipboardChange>,
    owned: Option<Owned>,
    read: Option<PendingRead>,
    sends: Vec<IncrSend>,
}

impl X11State {
    fn open(
        event_tx: mpsc::UnboundedSender<ClipboardChange>,
    ) -> Result<Self, ClipboardCreationError> {
        unsafe {
            let dpy = xlib::XOpenDisplay(ptr::null());
            if dpy.is_null() {
                return Err(ClipboardCreationError::Backend(
                    "cannot open X display".into(),
                ));
            }
            let (mut event_base, mut error_base) = (0, 0);
            if xfixes::XFixesQueryExtension(dpy, &mut event_base, &mut error_base) == 0 {
                xlib::XCloseDisplay(dpy);
                return Err(ClipboardCreationError::Backend(
                    "XFixes extension unavailable".into(),
                ));
            }
            let (mut major, minor) = (1, 0);
            xfixes::XFixesQueryVersion(dpy, &mut major, &minor);

            let io_dead = Box::new(AtomicBool::new(false));
            install_error_handlers(dpy, &io_dead);

            let root = xlib::XDefaultRootWindow(dpy);
            let win = xlib::XCreateSimpleWindow(dpy, root, 0, 0, 1, 1, 0, 0, 0);
            xlib::XSelectInput(dpy, win, xlib::PropertyChangeMask);
            let atoms = Atoms::intern(dpy);
            xfixes::XFixesSelectSelectionInput(
                dpy,
                win,
                atoms.clipboard,
                XFIXES_SELECTION_EVENT_MASK,
            );
            // Non-extended limit, in 4-byte units; leave room for the request header.
            let max_chunk = (xlib::XMaxRequestSize(dpy) as usize * 4).saturating_sub(1024);

            Ok(Self {
                dpy,
                win,
                atoms,
                xfixes_event_base: event_base,
                max_chunk,
                io_dead,
                event_tx,
                owned: None,
                read: None,
                sends: Vec::new(),
            })
        }
    }

    fn run(&mut self, mut cmd_rx: mpsc::UnboundedReceiver<Cmd>, mut wakeup: UnixStream) {
        // Report the current selection like the wayland backend does on bind.
        let owner = unsafe { xlib::XGetSelectionOwner(self.dpy, self.atoms.clipboard) };
        if owner == 0 {
            self.emit(ClipboardChange::NullSelection);
        } else {
            self.start_read(xlib::CurrentTime);
        }

        let x_fd = unsafe { xlib::XConnectionNumber(self.dpy) };
        loop {
            // Round trips made while handling events can queue further events,
            // so drain until Xlib reports none before polling the socket.
            while !self.dead() && unsafe { xlib::XPending(self.dpy) } > 0 {
                let mut ev: xlib::XEvent = unsafe { mem::zeroed() };
                unsafe { xlib::XNextEvent(self.dpy, &mut ev) };
                self.handle_event(&ev);
            }
            if self.dead() {
                log::warn!("x11 clipboard: X connection lost, clipboard sync stopped");
                self.close();
                return;
            }

            // Drain the wakeup before the queue so a concurrent notify is not lost.
            drain(&mut wakeup);
            loop {
                match cmd_rx.try_recv() {
                    Ok(Cmd::Set(content)) => self.set(content),
                    Ok(Cmd::Terminate) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.close();
                        return;
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            self.expire_stale();

            if unsafe { xlib::XPending(self.dpy) } > 0 || self.dead() {
                continue;
            }
            let mut fds = [
                libc::pollfd {
                    fd: x_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: wakeup.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, self.poll_timeout_ms()) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() != ErrorKind::Interrupted {
                    log::error!("x11 clipboard poll: {err}");
                    self.close();
                    return;
                }
            }
        }
    }

    fn dead(&self) -> bool {
        self.io_dead.load(Ordering::Relaxed)
    }

    fn close(&mut self) {
        unregister_display(self.dpy);
        if !self.dead() {
            unsafe {
                xlib::XDestroyWindow(self.dpy, self.win);
                xlib::XCloseDisplay(self.dpy);
            }
        }
        // On a dead connection the Display is leaked: closing it would
        // re-enter the IO error path.
    }

    fn emit(&self, change: ClipboardChange) {
        if self.event_tx.send(change).is_err() {
            log::debug!("x11 clipboard: event receiver dropped");
        }
    }

    fn handle_event(&mut self, ev: &xlib::XEvent) {
        let ty = ev.get_type();
        if ty == self.xfixes_event_base + XFIXES_SELECTION_NOTIFY {
            // SAFETY: XFixes events of this type have this layout.
            let fe = unsafe {
                &*(ev as *const xlib::XEvent as *const xfixes::XFixesSelectionNotifyEvent)
            };
            self.on_owner_change(fe);
            return;
        }
        match ty {
            xlib::SelectionNotify => self.on_selection_notify(unsafe { &ev.selection }),
            xlib::SelectionRequest => self.on_selection_request(unsafe { &ev.selection_request }),
            xlib::SelectionClear => {
                if unsafe { ev.selection_clear.selection } == self.atoms.clipboard {
                    self.owned = None;
                }
            }
            xlib::PropertyNotify => self.on_property(unsafe { &ev.property }),
            _ => {}
        }
    }

    fn on_owner_change(&mut self, fe: &xfixes::XFixesSelectionNotifyEvent) {
        if fe.selection != self.atoms.clipboard || fe.owner == self.win {
            return;
        }
        // A newer owner change is queued behind this one; act on that instead.
        let current = unsafe { xlib::XGetSelectionOwner(self.dpy, self.atoms.clipboard) };
        if current != fe.owner {
            return;
        }
        self.cancel_read();
        if fe.owner == 0 {
            log::debug!("x11 clipboard: selection has no owner");
            self.emit(ClipboardChange::NullSelection);
        } else {
            self.start_read(fe.selection_timestamp);
        }
    }

    fn start_read(&mut self, time: xlib::Time) {
        self.convert(self.atoms.targets, time);
        self.read = Some(PendingRead {
            phase: ReadPhase::Targets,
            time,
            last_activity: Instant::now(),
        });
    }

    fn convert(&self, target: xlib::Atom, time: xlib::Time) {
        unsafe {
            xlib::XConvertSelection(
                self.dpy,
                self.atoms.clipboard,
                target,
                self.atoms.transfer,
                self.win,
                time,
            );
        }
    }

    fn cancel_read(&mut self) {
        if let Some(PendingRead {
            phase: ReadPhase::Incr { .. },
            ..
        }) = self.read
        {
            unsafe { xlib::XDeleteProperty(self.dpy, self.win, self.atoms.transfer) };
        }
        self.read = None;
    }

    fn on_selection_notify(&mut self, se: &xlib::XSelectionEvent) {
        if se.requestor != self.win || se.selection != self.atoms.clipboard {
            return;
        }
        let Some(read) = &self.read else {
            return;
        };
        let time = read.time;
        match read.phase {
            ReadPhase::Targets if se.target == self.atoms.targets => {
                let target = if se.property == 0 {
                    // Owner does not answer TARGETS; ask for UTF-8 directly.
                    self.atoms.utf8_string
                } else {
                    match self.take_property().and_then(|p| self.choose_target(&p)) {
                        Some(t) => t,
                        None => {
                            log::debug!("x11 clipboard: owner offers no text target");
                            self.read = None;
                            return;
                        }
                    }
                };
                self.convert(target, time);
                self.read = Some(PendingRead {
                    phase: ReadPhase::Data { target },
                    time,
                    last_activity: Instant::now(),
                });
            }
            ReadPhase::Data { target } if se.target == target => {
                if se.property == 0 {
                    log::debug!("x11 clipboard: owner refused conversion");
                    self.read = None;
                    return;
                }
                let Some(prop) = self.take_property() else {
                    self.read = None;
                    return;
                };
                if prop.type_ == self.atoms.incr {
                    // Deleting the INCR property (done in take_property) starts the transfer.
                    self.read = Some(PendingRead {
                        phase: ReadPhase::Incr {
                            target,
                            buf: Vec::new(),
                        },
                        time,
                        last_activity: Instant::now(),
                    });
                } else {
                    self.read = None;
                    self.finish_read(target, prop.data);
                }
            }
            _ => {}
        }
    }

    fn on_property(&mut self, pe: &xlib::XPropertyEvent) {
        if pe.window == self.win
            && pe.atom == self.atoms.transfer
            && pe.state == xlib::PropertyNewValue
        {
            self.on_incr_chunk();
        } else if pe.state == xlib::PropertyDelete {
            if let Some(i) = self
                .sends
                .iter()
                .position(|s| s.requestor == pe.window && s.property == pe.atom)
            {
                self.advance_send(i);
            }
        }
    }

    fn on_incr_chunk(&mut self) {
        if !matches!(
            self.read,
            Some(PendingRead {
                phase: ReadPhase::Incr { .. },
                ..
            })
        ) {
            return;
        }
        let chunk = self.take_property();
        let Some(PendingRead {
            phase: ReadPhase::Incr { target, buf },
            last_activity,
            ..
        }) = &mut self.read
        else {
            return;
        };
        let Some(chunk) = chunk else {
            self.read = None;
            return;
        };
        if chunk.data.is_empty() {
            let (target, buf) = (*target, mem::take(buf));
            self.read = None;
            self.finish_read(target, buf);
        } else if buf.len() + chunk.data.len() > MAX_CONTENT {
            log::warn!("x11 clipboard: selection exceeds {MAX_CONTENT} bytes, ignoring");
            self.cancel_read();
        } else {
            buf.extend_from_slice(&chunk.data);
            *last_activity = Instant::now();
        }
    }

    fn finish_read(&mut self, target: xlib::Atom, data: Vec<u8>) {
        let text = if target == xlib::XA_STRING {
            data.iter().map(|&b| b as char).collect::<String>()
        } else {
            match String::from_utf8(data) {
                Ok(s) => s,
                Err(_) => {
                    log::warn!("x11 clipboard: selection is not valid UTF-8, ignoring");
                    return;
                }
            }
        };
        log::debug!("x11 clipboard: read {} bytes", text.len());
        self.emit(ClipboardChange::Content {
            content: ClipboardContent {
                mime: MIME_TEXT_UTF8.into(),
                data: text.into_bytes(),
            },
            origin_hint: OriginHint::Local,
        });
    }

    fn choose_target(&self, prop: &Property) -> Option<xlib::Atom> {
        let offered = prop.atoms();
        [
            self.atoms.utf8_string,
            self.atoms.text_plain_utf8,
            xlib::XA_STRING,
            self.atoms.text_plain,
        ]
        .into_iter()
        .find(|t| offered.contains(t))
    }

    /// Read and delete the transfer property on our window.
    fn take_property(&self) -> Option<Property> {
        let (mut type_, mut format, mut nitems, mut after) = (0, 0, 0, 0);
        let mut data: *mut c_uchar = ptr::null_mut();
        let rc = unsafe {
            xlib::XGetWindowProperty(
                self.dpy,
                self.win,
                self.atoms.transfer,
                0,
                (MAX_CONTENT / 4 + 1) as c_long,
                xlib::True,
                xlib::AnyPropertyType as c_ulong,
                &mut type_,
                &mut format,
                &mut nitems,
                &mut after,
                &mut data,
            )
        };
        if rc != xlib::Success as c_int {
            log::debug!("x11 clipboard: XGetWindowProperty failed ({rc})");
            return None;
        }
        // Xlib returns format-32 items as C longs.
        let item_size = match format {
            8 => 1,
            16 => mem::size_of::<std::ffi::c_short>(),
            32 => mem::size_of::<c_long>(),
            _ => 0,
        };
        let bytes = if data.is_null() {
            Vec::new()
        } else {
            // SAFETY: Xlib allocated nitems items of item_size bytes.
            let v =
                unsafe { std::slice::from_raw_parts(data, nitems as usize * item_size) }.to_vec();
            unsafe { xlib::XFree(data as *mut c_void) };
            v
        };
        if after > 0 {
            // Not deleted by Xlib when data remains.
            unsafe { xlib::XDeleteProperty(self.dpy, self.win, self.atoms.transfer) };
            log::warn!("x11 clipboard: selection exceeds {MAX_CONTENT} bytes, ignoring");
            return None;
        }
        Some(Property {
            type_,
            format,
            data: bytes,
        })
    }

    fn set(&mut self, content: ClipboardContent) {
        if std::str::from_utf8(&content.data).is_err() {
            log::warn!("x11 clipboard: dropping non-UTF-8 payload");
            return;
        }
        self.cancel_read();
        let time = self.server_time();
        unsafe { xlib::XSetSelectionOwner(self.dpy, self.atoms.clipboard, self.win, time) };
        if unsafe { xlib::XGetSelectionOwner(self.dpy, self.atoms.clipboard) } != self.win {
            log::warn!("x11 clipboard: failed to acquire CLIPBOARD");
            self.owned = None;
            return;
        }
        self.owned = Some(Owned {
            data: Rc::from(content.data),
            time,
        });
    }

    /// Obtain a server timestamp via a zero-length property append (ICCCM §2.1).
    fn server_time(&self) -> xlib::Time {
        #[repr(C)]
        struct Probe {
            win: xlib::Window,
            atom: xlib::Atom,
        }
        unsafe extern "C" fn matches(
            _: *mut xlib::Display,
            ev: *mut xlib::XEvent,
            arg: *mut c_char,
        ) -> xlib::Bool {
            unsafe {
                let probe = &*(arg as *const Probe);
                let ev = &*ev;
                (ev.get_type() == xlib::PropertyNotify
                    && ev.property.window == probe.win
                    && ev.property.atom == probe.atom) as xlib::Bool
            }
        }
        let mut probe = Probe {
            win: self.win,
            atom: self.atoms.time_probe,
        };
        let mut ev: xlib::XEvent = unsafe { mem::zeroed() };
        unsafe {
            xlib::XChangeProperty(
                self.dpy,
                self.win,
                self.atoms.time_probe,
                xlib::XA_STRING,
                8,
                xlib::PropModeAppend,
                [0u8].as_ptr(),
                0,
            );
            xlib::XIfEvent(
                self.dpy,
                &mut ev,
                Some(matches),
                &mut probe as *mut Probe as *mut c_char,
            );
            if self.dead() {
                return xlib::CurrentTime;
            }
            ev.property.time
        }
    }

    fn on_selection_request(&mut self, req: &xlib::XSelectionRequestEvent) {
        // Obsolete clients pass None as property (ICCCM §2.2).
        let property = if req.property == 0 {
            req.target
        } else {
            req.property
        };
        let ok = req.selection == self.atoms.clipboard
            && self.reply(req.requestor, property, req.target);
        let mut notify = xlib::XEvent {
            selection: xlib::XSelectionEvent {
                type_: xlib::SelectionNotify,
                serial: 0,
                send_event: xlib::True,
                display: self.dpy,
                requestor: req.requestor,
                selection: req.selection,
                target: req.target,
                property: if ok { property } else { 0 },
                time: req.time,
            },
        };
        unsafe { xlib::XSendEvent(self.dpy, req.requestor, xlib::False, 0, &mut notify) };
    }

    fn reply(&mut self, requestor: xlib::Window, property: xlib::Atom, target: xlib::Atom) -> bool {
        let Some(owned) = &self.owned else {
            return false;
        };
        let a = &self.atoms;
        if target == a.targets {
            let list: [c_ulong; 6] = [
                a.targets,
                a.timestamp,
                a.utf8_string,
                a.text_plain_utf8,
                a.text_plain,
                xlib::XA_STRING,
            ];
            self.change_property(
                requestor,
                property,
                xlib::XA_ATOM,
                32,
                list.as_ptr() as _,
                list.len(),
            );
            true
        } else if target == a.timestamp {
            let time: [c_ulong; 1] = [owned.time];
            self.change_property(requestor, property, XA_INTEGER, 32, time.as_ptr() as _, 1);
            true
        } else if target == a.utf8_string || target == a.text_plain_utf8 || target == a.text_plain {
            let data = owned.data.clone();
            self.send_data(requestor, property, target, data);
            true
        } else if target == xlib::XA_STRING {
            // Latin-1; characters outside it become '?'.
            let text = String::from_utf8_lossy(&owned.data);
            let latin1: Rc<[u8]> = text
                .chars()
                .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
                .collect();
            self.send_data(requestor, property, target, latin1);
            true
        } else {
            false
        }
    }

    fn change_property(
        &self,
        window: xlib::Window,
        property: xlib::Atom,
        type_: xlib::Atom,
        format: c_int,
        data: *const c_uchar,
        nelements: usize,
    ) {
        unsafe {
            xlib::XChangeProperty(
                self.dpy,
                window,
                property,
                type_,
                format,
                xlib::PropModeReplace,
                data,
                nelements as c_int,
            );
        }
    }

    fn send_data(
        &mut self,
        requestor: xlib::Window,
        property: xlib::Atom,
        type_: xlib::Atom,
        data: Rc<[u8]>,
    ) {
        if data.len() <= self.max_chunk {
            self.change_property(requestor, property, type_, 8, data.as_ptr(), data.len());
            return;
        }
        unsafe { xlib::XSelectInput(self.dpy, requestor, xlib::PropertyChangeMask) };
        let len: [c_ulong; 1] = [data.len() as c_ulong];
        self.change_property(
            requestor,
            property,
            self.atoms.incr,
            32,
            len.as_ptr() as _,
            1,
        );
        self.sends
            .retain(|s| !(s.requestor == requestor && s.property == property));
        self.sends.push(IncrSend {
            requestor,
            property,
            type_,
            data,
            offset: 0,
            last_activity: Instant::now(),
        });
    }

    /// The requestor deleted the property: write the next chunk, ending with
    /// a zero-length one.
    fn advance_send(&mut self, i: usize) {
        let s = &self.sends[i];
        let end = (s.offset + self.max_chunk).min(s.data.len());
        let chunk = &s.data[s.offset..end];
        self.change_property(
            s.requestor,
            s.property,
            s.type_,
            8,
            chunk.as_ptr(),
            chunk.len(),
        );
        if chunk.is_empty() {
            let s = self.sends.swap_remove(i);
            self.stop_watching(s.requestor);
        } else {
            let s = &mut self.sends[i];
            s.offset = end;
            s.last_activity = Instant::now();
        }
    }

    fn stop_watching(&self, requestor: xlib::Window) {
        if !self.sends.iter().any(|s| s.requestor == requestor) {
            unsafe { xlib::XSelectInput(self.dpy, requestor, xlib::NoEventMask) };
        }
    }

    fn expire_stale(&mut self) {
        let now = Instant::now();
        if self
            .read
            .as_ref()
            .is_some_and(|r| now - r.last_activity > TRANSFER_TIMEOUT)
        {
            log::warn!("x11 clipboard: selection owner stopped responding");
            self.cancel_read();
        }
        let (stale, live): (Vec<_>, Vec<_>) = mem::take(&mut self.sends)
            .into_iter()
            .partition(|s| now - s.last_activity > TRANSFER_TIMEOUT);
        self.sends = live;
        for s in stale {
            log::warn!("x11 clipboard: requestor {} stopped reading", s.requestor);
            self.stop_watching(s.requestor);
        }
    }

    fn poll_timeout_ms(&self) -> c_int {
        let oldest = self
            .read
            .iter()
            .map(|r| r.last_activity)
            .chain(self.sends.iter().map(|s| s.last_activity))
            .min();
        match oldest {
            None => -1,
            Some(t) => {
                let left = (t + TRANSFER_TIMEOUT).saturating_duration_since(Instant::now());
                left.as_millis().min(c_int::MAX as u128) as c_int + 1
            }
        }
    }
}

struct Property {
    type_: xlib::Atom,
    format: c_int,
    data: Vec<u8>,
}

impl Property {
    fn atoms(&self) -> Vec<xlib::Atom> {
        if self.format != 32 {
            return Vec::new();
        }
        let (chunks, _) = self.data.as_chunks::<{ mem::size_of::<c_ulong>() }>();
        chunks.iter().map(|c| c_ulong::from_ne_bytes(*c)).collect()
    }
}

fn drain(wakeup: &mut UnixStream) {
    let mut buf = [0u8; 64];
    while matches!(wakeup.read(&mut buf), Ok(n) if n > 0) {}
}

// Xlib error handlers are process-global. Errors on our displays (e.g. a
// requestor window vanishing mid-transfer) are logged and a lost connection
// only stops this backend; other displays go to the previous handlers.

type ErrorHandler = unsafe extern "C" fn(*mut xlib::Display, *mut xlib::XErrorEvent) -> c_int;
type IoErrorHandler = unsafe extern "C" fn(*mut xlib::Display) -> c_int;
type SetIoErrorExitHandler = unsafe extern "C" fn(
    *mut xlib::Display,
    Option<unsafe extern "C" fn(*mut xlib::Display, *mut c_void)>,
    *mut c_void,
);

/// Our displays and their `io_dead` flags, as addresses.
static OUR_DISPLAYS: Mutex<Vec<(usize, usize)>> = Mutex::new(Vec::new());
static PREV_HANDLERS: OnceLock<(Option<ErrorHandler>, Option<IoErrorHandler>)> = OnceLock::new();
static INSTALL_HANDLERS: Once = Once::new();

fn io_dead_flag(dpy: *mut xlib::Display) -> Option<*const AtomicBool> {
    let displays = OUR_DISPLAYS.lock().ok()?;
    displays
        .iter()
        .find(|(d, _)| *d == dpy as usize)
        .map(|(_, flag)| *flag as *const AtomicBool)
}

unsafe extern "C" fn on_x_error(dpy: *mut xlib::Display, ev: *mut xlib::XErrorEvent) -> c_int {
    if io_dead_flag(dpy).is_some() {
        let ev = unsafe { &*ev };
        log::debug!(
            "x11 clipboard: X error {} (request {}.{})",
            ev.error_code,
            ev.request_code,
            ev.minor_code
        );
        return 0;
    }
    match PREV_HANDLERS.get().and_then(|h| h.0) {
        Some(prev) => unsafe { prev(dpy, ev) },
        None => 0,
    }
}

unsafe extern "C" fn on_io_error(dpy: *mut xlib::Display) -> c_int {
    if let Some(flag) = io_dead_flag(dpy) {
        // SAFETY: the flag outlives the display's registration.
        unsafe { (*flag).store(true, Ordering::Relaxed) };
        return 0;
    }
    match PREV_HANDLERS.get().and_then(|h| h.1) {
        Some(prev) => unsafe { prev(dpy) },
        None => 0,
    }
}

unsafe extern "C" fn on_io_error_exit(_: *mut xlib::Display, _: *mut c_void) {
    // Returning leaves the display unusable but the process alive.
}

unsafe fn install_error_handlers(dpy: *mut xlib::Display, io_dead: &AtomicBool) {
    INSTALL_HANDLERS.call_once(|| {
        let prev = unsafe {
            (
                xlib::XSetErrorHandler(Some(on_x_error)),
                xlib::XSetIOErrorHandler(Some(on_io_error)),
            )
        };
        let _ = PREV_HANDLERS.set(prev);
    });
    if let Ok(mut d) = OUR_DISPLAYS.lock() {
        d.push((dpy as usize, io_dead as *const AtomicBool as usize));
    }
    // Xlib exits after the IO error handler returns unless an exit handler is
    // set (libX11 >= 1.7). Resolved at runtime so older libraries still link.
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"XSetIOErrorExitHandler".as_ptr()) };
    if sym.is_null() {
        log::warn!("x11 clipboard: libX11 < 1.7, losing the X server will terminate lan-mouse");
        return;
    }
    let set: SetIoErrorExitHandler = unsafe { mem::transmute(sym) };
    unsafe { set(dpy, Some(on_io_error_exit), ptr::null_mut()) };
}

fn unregister_display(dpy: *mut xlib::Display) {
    if let Ok(mut d) = OUR_DISPLAYS.lock() {
        d.retain(|(p, _)| *p != dpy as usize);
    }
}
