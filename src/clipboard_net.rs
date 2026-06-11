//! Clipboard TCP side-channel (rustls 0.23 over TCP, same port as DTLS-UDP).
//!
//! Phase 2 of CLIPBOARD_PLAN.md. This module exposes [`ClipboardNet`], which:
//!   * runs a TCP listener that accepts mutually-authenticated rustls connections,
//!   * provides an outbound connector triggered when DTLS for a peer comes up,
//!   * performs a postcard-framed `Hello` handshake on each connection,
//!   * forwards inbound `CapMsg` to a consumer via an mpsc channel,
//!   * supports a synchronous port-change in lock-step with the UDP listener.
//!
//! The clipboard task itself (Phase 7) is not wired up yet; the consumer used
//! here is a placeholder that logs each received message.

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use local_channel::mpsc::{Receiver, Sender, channel};
use lan_mouse_clipboard::{CAP_CLIPBOARD, CapMsg, PROTOCOL_VERSION};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError, ServerConfig,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, ring, verify_tls12_signature,
        verify_tls13_signature,
    },
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use socket2::{SockRef, TcpKeepalive};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::{JoinHandle, spawn_local},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use webrtc_dtls::crypto::Certificate as DtlsCertificate;

use crate::crypto;

/// Maximum frame payload size (must match `lan-mouse-clipboard::proto`).
const MAX_FRAME_SIZE: u32 = 64 * 1024 * 1024;

/// TCP keepalive: 30s idle, 10s interval, 3 probes. Matches CLIPBOARD_PLAN.md.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_RETRIES: u32 = 3;

/// `Hello` must be exchanged before any other message; bound the wait so a
/// silent peer cannot pin a slot indefinitely.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// Used as TLS SNI on outgoing connections. The server-cert verifier is custom
/// and ignores this — it is only here to satisfy rustls' API requirements.
const TLS_SNI: &str = "lan-mouse";

#[derive(Debug, Error)]
pub enum ClipboardNetError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    #[error("invalid private key (PKCS#8 DER): {0}")]
    InvalidPrivateKey(String),
    #[error("hello mismatch: tls fingerprint {tls} != hello peer_id {hello}")]
    HelloFingerprintMismatch { tls: String, hello: String },
    #[error("protocol version mismatch: local {local}, remote {remote}")]
    ProtocolVersionMismatch { local: u16, remote: u16 },
    #[error("expected Hello as first frame, got {0:?}")]
    ExpectedHello(&'static str),
    #[error("frame too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    FrameTooLarge(u32),
    #[error("postcard decode error: {0}")]
    Decode(#[from] postcard::Error),
    #[error("postcard encode error: {0}")]
    Encode(postcard::Error),
    #[error("hello handshake timed out")]
    HelloTimeout,
}

/// Events emitted by the clipboard side-channel for the clipboard task.
#[derive(Debug)]
#[allow(dead_code)] // `addr` fields are kept for diagnostics/logging
pub(crate) enum ClipboardNetEvent {
    /// A peer completed the TLS+Hello handshake. Clipboard task resets
    /// `last_seen[peer]` on this event.
    PeerConnected {
        addr: SocketAddr,
        fingerprint: String,
        capabilities: u32,
    },
    /// A peer's connection went away (TLS read error, EOF, etc.).
    PeerDisconnected {
        addr: SocketAddr,
        fingerprint: String,
    },
    /// A `Clipboard` message was received from a peer.
    Message {
        addr: SocketAddr,
        fingerprint: String,
        msg: CapMsg,
    },
}

/// Commands accepted by the [`ClipboardNet`] background task.
enum Command {
    /// Open an outbound clipboard TCP to this peer (idempotent).
    Connect(SocketAddr),
    /// Drop any clipboard TCP for this peer (idempotent).
    Disconnect(SocketAddr),
    /// Rebind the listener to a new port; reports the result back on `reply`.
    ChangePort {
        port: u16,
        reply: tokio::sync::oneshot::Sender<Result<u16, ClipboardNetError>>,
    },
    /// Send a `Clipboard` message to every connected peer, skipping all
    /// connections whose peer fingerprint matches `except_fingerprint` (used
    /// when relaying, to avoid echoing back to the source — a peer pair may
    /// hold two connections, one initiated by each side, so exclusion is by
    /// fingerprint rather than address).
    Broadcast {
        msg: CapMsg,
        except_fingerprint: Option<String>,
    },
}

/// Public handle to the clipboard side-channel.
pub(crate) struct ClipboardNet {
    cmd_tx: Sender<Command>,
    event_rx: Receiver<ClipboardNetEvent>,
    task: JoinHandle<()>,
}

impl ClipboardNet {
    /// Start the listener + dispatcher tasks. Must be called from a tokio
    /// `LocalSet` context (uses `spawn_local`).
    pub(crate) async fn new(
        port: u16,
        cert: DtlsCertificate,
        authorized_keys: Arc<RwLock<HashMap<String, String>>>,
        local_fingerprint: String,
    ) -> Result<Self, ClipboardNetError> {
        let provider = Arc::new(ring::default_provider());
        let server_config =
            Arc::new(build_server_config(&cert, authorized_keys.clone(), provider.clone())?);
        let client_config =
            Arc::new(build_client_config(&cert, authorized_keys.clone(), provider.clone())?);

        let listener = bind_listener(port).await?;
        log::info!("clipboard_net: listening on {}", listener.local_addr()?);

        // `authorized_keys` is consumed by the rustls verifiers built above;
        // not retained on `SharedState`.
        drop(authorized_keys);

        let (cmd_tx, cmd_rx) = channel();
        let (event_tx, event_rx) = channel();
        let state = Arc::new(SharedState {
            local_fingerprint,
            event_tx,
            server_config,
            client_config,
            peers: Mutex::new(HashMap::new()),
        });

        let task = spawn_local(run_dispatcher(state, listener, cmd_rx));

        Ok(Self {
            cmd_tx,
            event_rx,
            task,
        })
    }

    /// Open an outbound clipboard TCP to this peer (idempotent).
    pub(crate) fn connect_to(&self, addr: SocketAddr) {
        let _ = self.cmd_tx.send(Command::Connect(addr));
    }

    /// Drop any clipboard TCP for this peer (idempotent).
    pub(crate) fn disconnect_from(&self, addr: SocketAddr) {
        let _ = self.cmd_tx.send(Command::Disconnect(addr));
    }

    /// Request a port rebind. The result is reported via the returned receiver.
    pub(crate) fn request_port_change(
        &self,
        port: u16,
    ) -> tokio::sync::oneshot::Receiver<Result<u16, ClipboardNetError>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let _ = self.cmd_tx.send(Command::ChangePort { port, reply: tx });
        rx
    }

    /// Broadcast a `Clipboard` message to every connected peer.
    pub(crate) fn broadcast(&self, msg: CapMsg) {
        let _ = self.cmd_tx.send(Command::Broadcast {
            msg,
            except_fingerprint: None,
        });
    }

    /// Broadcast a `Clipboard` message to every connected peer except those
    /// with this fingerprint.
    pub(crate) fn broadcast_except(&self, msg: CapMsg, except_fingerprint: String) {
        let _ = self.cmd_tx.send(Command::Broadcast {
            msg,
            except_fingerprint: Some(except_fingerprint),
        });
    }

    /// Await the next side-channel event.
    pub(crate) async fn event(&mut self) -> Option<ClipboardNetEvent> {
        self.event_rx.recv().await
    }

    /// Abort the dispatcher; per-peer tasks will exit on next read error.
    pub(crate) fn terminate(&self) {
        self.task.abort();
    }
}

struct SharedState {
    local_fingerprint: String,
    event_tx: Sender<ClipboardNetEvent>,
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    peers: Mutex<HashMap<SocketAddr, PeerHandle>>,
}

struct PeerHandle {
    /// Per-peer outbound channel; the writer task drains it.
    out_tx: tokio::sync::mpsc::UnboundedSender<CapMsg>,
    /// Cert fingerprint after Hello completes (for disconnect events).
    fingerprint: String,
}

async fn run_dispatcher(
    state: Arc<SharedState>,
    mut listener: TcpListener,
    mut cmd_rx: Receiver<Command>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, addr)) => {
                    if let Err(e) = configure_keepalive(&stream) {
                        log::warn!("clipboard_net: keepalive setup failed for {addr}: {e}");
                    }
                    let state = state.clone();
                    spawn_local(async move {
                        if let Err(e) = handle_inbound(state, stream, addr).await {
                            log::warn!("clipboard_net: inbound from {addr} closed: {e}");
                        }
                    });
                }
                Err(e) => log::warn!("clipboard_net: accept error: {e}"),
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(Command::Connect(addr)) => {
                    // Skip if already (or currently being) connected.
                    if state.peers.lock().await.contains_key(&addr) {
                        continue;
                    }
                    let state = state.clone();
                    spawn_local(async move {
                        if let Err(e) = handle_outbound(state, addr).await {
                            log::warn!("clipboard_net: outbound to {addr} failed: {e}");
                        }
                    });
                }
                Some(Command::Disconnect(addr)) => {
                    if let Some(peer) = state.peers.lock().await.remove(&addr) {
                        log::info!("clipboard_net: dropping connection to {addr}");
                        // Closing the out channel causes the writer to exit
                        // and drop its half of the TlsStream, which terminates
                        // the reader on the next operation.
                        drop(peer);
                    }
                }
                Some(Command::ChangePort { port, reply }) => {
                    match bind_listener(port).await {
                        Ok(new_listener) => {
                            listener = new_listener;
                            log::info!("clipboard_net: rebound to port {port}");
                            let _ = reply.send(Ok(port));
                        }
                        Err(e) => {
                            log::warn!("clipboard_net: port rebind to {port} failed: {e}");
                            let _ = reply.send(Err(e));
                        }
                    }
                }
                Some(Command::Broadcast { msg, except_fingerprint }) => {
                    let peers = state.peers.lock().await;
                    for (addr, peer) in peers.iter() {
                        if except_fingerprint.as_deref() == Some(peer.fingerprint.as_str()) {
                            continue;
                        }
                        if peer.out_tx.send(msg.clone()).is_err() {
                            log::trace!("clipboard_net: peer {addr} send queue dropped");
                        }
                    }
                }
                None => break,
            },
        }
    }
}

async fn bind_listener(port: u16) -> Result<TcpListener, ClipboardNetError> {
    let addr: SocketAddr = SocketAddr::new("0.0.0.0".parse().expect("valid ip"), port);
    Ok(TcpListener::bind(addr).await?)
}

fn configure_keepalive(stream: &TcpStream) -> io::Result<()> {
    let ka = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    SockRef::from(stream).set_tcp_keepalive(&ka)
}

async fn handle_inbound(
    state: Arc<SharedState>,
    tcp: TcpStream,
    addr: SocketAddr,
) -> Result<(), ClipboardNetError> {
    let acceptor = TlsAcceptor::from(state.server_config.clone());
    let tls = acceptor.accept(tcp).await?;
    let (_, server_state) = tls.get_ref();
    let fingerprint = extract_peer_fingerprint(server_state.peer_certificates())?;
    log::debug!("clipboard_net: inbound TLS up from {addr} ({fingerprint})");
    drive_peer(state, ConnSide::Server(tls), addr, fingerprint).await
}

async fn handle_outbound(
    state: Arc<SharedState>,
    addr: SocketAddr,
) -> Result<(), ClipboardNetError> {
    let tcp = TcpStream::connect(addr).await?;
    if let Err(e) = configure_keepalive(&tcp) {
        log::warn!("clipboard_net: keepalive setup failed for {addr}: {e}");
    }
    let connector = TlsConnector::from(state.client_config.clone());
    let sni = ServerName::try_from(TLS_SNI).expect("static SNI is valid");
    let tls = connector.connect(sni, tcp).await?;
    let (_, client_state) = tls.get_ref();
    let fingerprint = extract_peer_fingerprint(client_state.peer_certificates())?;
    log::debug!("clipboard_net: outbound TLS up to {addr} ({fingerprint})");
    drive_peer(state, ConnSide::Client(tls), addr, fingerprint).await
}

enum ConnSide {
    Server(server::TlsStream<TcpStream>),
    Client(client::TlsStream<TcpStream>),
}

async fn drive_peer(
    state: Arc<SharedState>,
    tls: ConnSide,
    addr: SocketAddr,
    tls_fingerprint: String,
) -> Result<(), ClipboardNetError> {
    // Both sides send Hello first, in parallel.
    let (reader, writer) = match tls {
        ConnSide::Server(s) => {
            let (r, w) = tokio::io::split(s);
            (Reader::Server(r), Writer::Server(w))
        }
        ConnSide::Client(s) => {
            let (r, w) = tokio::io::split(s);
            (Reader::Client(r), Writer::Client(w))
        }
    };

    let hello = CapMsg::Hello {
        protocol_version: PROTOCOL_VERSION,
        peer_id: state.local_fingerprint.clone(),
        capabilities: CAP_CLIPBOARD,
    };

    let (mut reader, mut writer) = (reader, writer);
    writer.write_frame(&hello).await?;

    // Bounded wait for the peer's Hello.
    let peer_hello =
        tokio::time::timeout(HELLO_TIMEOUT, reader.read_frame())
            .await
            .map_err(|_| ClipboardNetError::HelloTimeout)??;
    let (peer_id, peer_caps) = match peer_hello {
        CapMsg::Hello {
            protocol_version,
            peer_id,
            capabilities,
        } => {
            if protocol_version != PROTOCOL_VERSION {
                return Err(ClipboardNetError::ProtocolVersionMismatch {
                    local: PROTOCOL_VERSION,
                    remote: protocol_version,
                });
            }
            if peer_id != tls_fingerprint {
                return Err(ClipboardNetError::HelloFingerprintMismatch {
                    tls: tls_fingerprint,
                    hello: peer_id,
                });
            }
            (peer_id, capabilities)
        }
        CapMsg::Clipboard { .. } => return Err(ClipboardNetError::ExpectedHello("Clipboard")),
    };

    log::info!(
        "clipboard_net: peer {addr} ({peer_id}) up (caps=0x{peer_caps:08x})"
    );

    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<CapMsg>();
    {
        let mut peers = state.peers.lock().await;
        if let Some(existing) = peers.insert(
            addr,
            PeerHandle {
                out_tx,
                fingerprint: peer_id.clone(),
            },
        ) {
            // Replaced a stale entry; nothing to do, the old writer task will
            // notice when its channel is dropped.
            drop(existing);
        }
    }

    let _ = state.event_tx.send(ClipboardNetEvent::PeerConnected {
        addr,
        fingerprint: peer_id.clone(),
        capabilities: peer_caps,
    });

    // Reader loop: forward inbound CapMsg as Message events until EOF/error.
    let reader_state = state.clone();
    let reader_fingerprint = peer_id.clone();
    let reader_task = spawn_local(async move {
        loop {
            match reader.read_frame().await {
                Ok(CapMsg::Hello { .. }) => {
                    log::warn!(
                        "clipboard_net: peer {addr} sent a second Hello; dropping connection"
                    );
                    break;
                }
                Ok(msg) => {
                    let _ = reader_state.event_tx.send(ClipboardNetEvent::Message {
                        addr,
                        fingerprint: reader_fingerprint.clone(),
                        msg,
                    });
                }
                Err(e) => {
                    log::debug!("clipboard_net: reader for {addr} stopped: {e}");
                    break;
                }
            }
        }
    });

    // Writer loop: drain outbound queue.
    while let Some(msg) = out_rx.recv().await {
        if let Err(e) = writer.write_frame(&msg).await {
            log::warn!("clipboard_net: write to {addr} failed: {e}");
            break;
        }
    }

    reader_task.abort();

    {
        let mut peers = state.peers.lock().await;
        if let Some(entry) = peers.get(&addr) {
            if entry.fingerprint == peer_id {
                peers.remove(&addr);
            }
        }
    }
    let _ = state.event_tx.send(ClipboardNetEvent::PeerDisconnected {
        addr,
        fingerprint: peer_id,
    });
    Ok(())
}

/// Wrapper over the two TlsStream variants so the framing code is monomorphic
/// rather than generic. Phase 7 may want generics; not worth the complexity yet.
enum Reader {
    Server(tokio::io::ReadHalf<server::TlsStream<TcpStream>>),
    Client(tokio::io::ReadHalf<client::TlsStream<TcpStream>>),
}

impl Reader {
    async fn read_frame(&mut self) -> Result<CapMsg, ClipboardNetError> {
        match self {
            Reader::Server(r) => read_frame(r).await,
            Reader::Client(r) => read_frame(r).await,
        }
    }
}

enum Writer {
    Server(tokio::io::WriteHalf<server::TlsStream<TcpStream>>),
    Client(tokio::io::WriteHalf<client::TlsStream<TcpStream>>),
}

impl Writer {
    async fn write_frame(&mut self, msg: &CapMsg) -> Result<(), ClipboardNetError> {
        match self {
            Writer::Server(w) => write_frame(w, msg).await,
            Writer::Client(w) => write_frame(w, msg).await,
        }
    }
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<CapMsg, ClipboardNetError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(ClipboardNetError::FrameTooLarge(len));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    Ok(postcard::from_bytes(&payload)?)
}

async fn write_frame<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg: &CapMsg,
) -> Result<(), ClipboardNetError> {
    let payload = postcard::to_stdvec(msg).map_err(ClipboardNetError::Encode)?;
    if payload.len() as u64 > MAX_FRAME_SIZE as u64 {
        return Err(ClipboardNetError::FrameTooLarge(payload.len() as u32));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes()).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

fn extract_peer_fingerprint(
    peer_certs: Option<&[CertificateDer<'_>]>,
) -> Result<String, ClipboardNetError> {
    let leaf = peer_certs
        .and_then(|c| c.first())
        .ok_or_else(|| RustlsError::NoCertificatesPresented)?;
    Ok(crypto::generate_fingerprint(leaf.as_ref()))
}

fn build_server_config(
    cert: &DtlsCertificate,
    authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    provider: Arc<CryptoProvider>,
) -> Result<ServerConfig, ClipboardNetError> {
    let (cert_chain, key) = split_cert(cert)?;
    let verifier = Arc::new(FingerprintVerifier {
        authorized_keys,
        sig_algs: provider.signature_verification_algorithms,
    });
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)?;
    Ok(cfg)
}

fn build_client_config(
    cert: &DtlsCertificate,
    _authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    provider: Arc<CryptoProvider>,
) -> Result<ClientConfig, ClipboardNetError> {
    let (cert_chain, key) = split_cert(cert)?;
    // Outbound clipboard TCP mirrors DTLS' asymmetric trust model: the
    // *server* verifies the *client's* cert against `authorized_keys`; the
    // client accepts any server cert and identifies the peer via the
    // post-handshake `Hello.peer_id`-vs-TLS-fingerprint check (see
    // `drive_peer`).
    let verifier = Arc::new(AcceptAnyServerCert {
        sig_algs: provider.signature_verification_algorithms,
    });
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, key)?;
    Ok(cfg)
}

fn split_cert(
    cert: &DtlsCertificate,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ClipboardNetError> {
    if cert.certificate.is_empty() {
        return Err(ClipboardNetError::InvalidPrivateKey(
            "no certificate present".into(),
        ));
    }
    let cert_chain = cert.certificate.clone();
    let key_der = cert.private_key.serialized_der.clone();
    if key_der.is_empty() {
        return Err(ClipboardNetError::InvalidPrivateKey(
            "empty serialized_der".into(),
        ));
    }
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
    Ok((cert_chain, key))
}

/// Custom verifier shared by client and server. Accepts the peer iff its leaf
/// cert's SHA-256 fingerprint is present in `authorized_keys`. Signature
/// validation is delegated to the rustls webpki helpers using the ring
/// provider's algorithm table.
#[derive(Debug)]
struct FingerprintVerifier {
    authorized_keys: Arc<RwLock<HashMap<String, String>>>,
    sig_algs: WebPkiSupportedAlgorithms,
}

impl FingerprintVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>) -> Result<(), RustlsError> {
        let fp = crypto::generate_fingerprint(end_entity.as_ref());
        if self
            .authorized_keys
            .read()
            .expect("authorized_keys lock")
            .contains_key(&fp)
        {
            Ok(())
        } else {
            log::warn!("clipboard_net: rejecting unauthorized peer with fingerprint {fp}");
            Err(RustlsError::General(format!(
                "peer fingerprint {fp} not authorized"
            )))
        }
    }
}

/// `ServerCertVerifier` that accepts any server cert. Identity is established
/// later via the `Hello` handshake's `peer_id`-vs-TLS-fingerprint check.
#[derive(Debug)]
struct AcceptAnyServerCert {
    sig_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.sig_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.sig_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.sig_algs.supported_schemes()
    }
}

impl ClientCertVerifier for FingerprintVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.check(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.sig_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.sig_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.sig_algs.supported_schemes()
    }
}

