use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::{
    Clipboard, ClipboardChange, ClipboardContent,
    error::{ClipboardCreationError, ClipboardError},
};

pub(crate) struct DummyClipboard {
    rx: mpsc::Receiver<ClipboardChange>,
    // Keep tx alive so the channel is never closed until we drop both.
    _tx: mpsc::Sender<ClipboardChange>,
}

impl DummyClipboard {
    pub(crate) fn new() -> Result<Self, ClipboardCreationError> {
        let (_tx, rx) = mpsc::channel(8);
        Ok(Self { rx, _tx })
    }
}

#[async_trait]
impl Clipboard for DummyClipboard {
    async fn next_event(&mut self) -> Option<ClipboardChange> {
        self.rx.recv().await
    }

    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError> {
        log::debug!("dummy clipboard set: {} bytes", content.data.len());
        Ok(())
    }

    async fn terminate(&mut self) -> Result<(), ClipboardError> {
        Ok(())
    }
}
