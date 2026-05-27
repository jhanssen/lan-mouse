use async_trait::async_trait;

pub use error::{ClipboardCreationError, ClipboardError};
pub use proto::{CAP_CLIPBOARD, CapMsg, PROTOCOL_VERSION};

mod dummy;
pub mod error;
pub mod proto;
#[cfg(macos_clipboard)]
mod macos;
#[cfg(wayland_clipboard)]
mod wayland;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardContent {
    pub mime: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginHint {
    /// Change was caused by a local application.
    Local,
    /// Change was caused by lan-mouse itself (e.g. applying a remote paste).
    LanMouse,
}

/// An observed change to the local clipboard.
#[derive(Debug, Clone)]
pub enum ClipboardChange {
    /// The clipboard now holds the given content.
    Content {
        content: ClipboardContent,
        origin_hint: OriginHint,
    },
    /// The clipboard has been emptied / no current selection. Only the
    /// Wayland backend emits this; the clipboard task uses it to decide
    /// whether to re-claim the selection with the last remote content.
    NullSelection,
}

/// Platform clipboard abstraction.
///
/// Implementations MUST suppress self-fires that result from calling `set()`.
/// `next_event` is cancel-safe: dropping the future before completion does not
/// lose the event (backends buffer internally via an mpsc channel).
#[async_trait]
pub trait Clipboard: Send {
    async fn next_event(&mut self) -> Option<ClipboardChange>;
    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError>;
    async fn terminate(&mut self) -> Result<(), ClipboardError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    #[cfg(wayland_clipboard)]
    Wayland,
    #[cfg(macos_clipboard)]
    MacOs,
    #[cfg(windows_clipboard)]
    Windows,
    Dummy,
}

pub struct LanMouseClipboard {
    inner: Box<dyn Clipboard>,
}

impl LanMouseClipboard {
    fn with_backend(backend: Backend, peer_id: &str) -> Result<Self, ClipboardCreationError> {
        let inner: Box<dyn Clipboard> = match backend {
            #[cfg(wayland_clipboard)]
            Backend::Wayland => Box::new(wayland::WaylandClipboard::new(peer_id)?),
            #[cfg(macos_clipboard)]
            Backend::MacOs => Box::new(macos::MacOsClipboard::new(peer_id)?),
            #[cfg(windows_clipboard)]
            Backend::Windows => todo!("windows backend not yet implemented"),
            Backend::Dummy => {
                let _ = peer_id;
                Box::new(dummy::DummyClipboard::new()?)
            }
        };
        Ok(Self { inner })
    }

    /// `peer_id` should be the local lan-mouse peer's full SHA-256 cert
    /// fingerprint (colon-hex). The Wayland and macOS backends use it to tag
    /// their own clipboard writes (as an extra MIME / pasteboard type) so
    /// they can suppress the resulting self-fire event. Other backends ignore
    /// it.
    pub fn new(
        backend: Option<Backend>,
        peer_id: &str,
    ) -> Result<Self, ClipboardCreationError> {
        if let Some(b) = backend {
            return Self::with_backend(b, peer_id);
        }

        for backend in [
            #[cfg(wayland_clipboard)]
            Backend::Wayland,
            #[cfg(macos_clipboard)]
            Backend::MacOs,
            #[cfg(windows_clipboard)]
            Backend::Windows,
            Backend::Dummy,
        ] {
            match Self::with_backend(backend, peer_id) {
                Ok(c) => {
                    log::info!("using clipboard backend: {backend:?}");
                    return Ok(c);
                }
                Err(e) => log::warn!("clipboard backend {backend:?} unavailable: {e}"),
            }
        }

        Err(ClipboardCreationError::NoAvailableBackend)
    }
}

#[async_trait]
impl Clipboard for LanMouseClipboard {
    async fn next_event(&mut self) -> Option<ClipboardChange> {
        self.inner.next_event().await
    }

    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError> {
        self.inner.set(content).await
    }

    async fn terminate(&mut self) -> Result<(), ClipboardError> {
        self.inner.terminate().await
    }
}
