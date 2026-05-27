use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClipboardError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("clipboard backend error: {0}")]
    Backend(String),
}

#[derive(Debug, Error)]
pub enum ClipboardCreationError {
    #[error("no available clipboard backend")]
    NoAvailableBackend,
    #[error("backend error: {0}")]
    Backend(String),
}
