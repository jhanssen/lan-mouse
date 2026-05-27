use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Maximum allowed frame payload size (64 MiB).
const MAX_FRAME_SIZE: u32 = 64 * 1024 * 1024;

/// Wire protocol messages for the clipboard TCP side-channel.
///
/// Framing: [u32 BE length][postcard payload].
/// postcard configuration is the default; changing it is a wire break.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CapMsg {
    Hello {
        /// Bump only on structural changes to CapMsg.
        protocol_version: u16,
        /// Full SHA-256 cert fingerprint as colon-separated lowercase hex.
        peer_id: String,
        /// Bitflags: CAP_CLIPBOARD = 1 << 0.
        capabilities: u32,
    },
    Clipboard {
        /// peer_id of the originating machine.
        origin: String,
        /// Monotonic per-origin serial for loop suppression.
        serial: u64,
        /// MIME type (e.g. "text/plain;charset=utf-8").
        mime: String,
        /// Content bytes.
        data: Vec<u8>,
    },
}

pub const CAP_CLIPBOARD: u32 = 1 << 0;
pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    TooLarge(u32),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("encode error: {0}")]
    Encode(postcard::Error),
    #[error("decode error: {0}")]
    Decode(postcard::Error),
}

/// Encode a `CapMsg` into `[u32 BE length][postcard payload]`.
pub fn encode_frame(msg: &CapMsg) -> Result<Vec<u8>, FrameError> {
    let payload = postcard::to_stdvec(msg).map_err(FrameError::Encode)?;
    let len = payload.len() as u64;
    if len > MAX_FRAME_SIZE as u64 {
        return Err(FrameError::TooLarge(len as u32));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.write_all(&(payload.len() as u32).to_be_bytes())?;
    out.write_all(&payload)?;
    Ok(out)
}

/// Decode a `CapMsg` from a synchronous reader.
///
/// Reads the 4-byte length prefix first; rejects frames larger than 64 MiB
/// before allocating any payload buffer.
pub fn decode_frame<R: Read>(reader: &mut R) -> Result<CapMsg, FrameError> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    postcard::from_bytes(&payload).map_err(FrameError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: CapMsg) {
        let encoded = encode_frame(&msg).expect("encode");
        let decoded = decode_frame(&mut encoded.as_slice()).expect("decode");
        assert_eq!(msg, decoded);
    }

    #[test]
    fn round_trip_hello() {
        round_trip(CapMsg::Hello {
            protocol_version: PROTOCOL_VERSION,
            peer_id: "aa:bb:cc".into(),
            capabilities: CAP_CLIPBOARD,
        });
    }

    #[test]
    fn round_trip_clipboard() {
        round_trip(CapMsg::Clipboard {
            origin: "aa:bb:cc".into(),
            serial: 42,
            mime: "text/plain;charset=utf-8".into(),
            data: b"hello world".to_vec(),
        });
    }

    #[test]
    fn oversize_length_rejected_without_allocation() {
        // Feed a frame claiming 100_000_000 bytes — must error after reading 4 bytes.
        let mut cursor = std::io::Cursor::new(100_000_000u32.to_be_bytes());
        let err = decode_frame(&mut cursor).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(100_000_000)));
        // Cursor should be exactly at position 4 — no payload bytes read.
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn u32_max_rejected() {
        let mut cursor = std::io::Cursor::new(u32::MAX.to_be_bytes());
        let err = decode_frame(&mut cursor).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(u32::MAX)));
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn malformed_payload_returns_error() {
        // Valid length prefix, garbage payload.
        let payload = b"\xff\xff\xff";
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        let err = decode_frame(&mut frame.as_slice()).unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)));
    }

    #[test]
    fn eof_mid_frame_returns_error() {
        // 4-byte length says 100 bytes, but only 10 bytes of payload follow.
        let mut frame = Vec::new();
        frame.extend_from_slice(&100u32.to_be_bytes());
        frame.extend_from_slice(&[0u8; 10]);
        let err = decode_frame(&mut frame.as_slice()).unwrap_err();
        assert!(matches!(err, FrameError::Io(_)));
    }

    #[test]
    fn encode_oversize_data_returns_error() {
        let data = vec![0u8; (MAX_FRAME_SIZE + 1) as usize];
        let msg = CapMsg::Clipboard {
            origin: "x".into(),
            serial: 0,
            mime: "text/plain;charset=utf-8".into(),
            data,
        };
        // postcard will serialise the Vec fine; the size check in encode_frame catches it.
        // (The serialised form includes varint overhead, so it will be > MAX_FRAME_SIZE.)
        let err = encode_frame(&msg).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }
}
