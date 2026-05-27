# Clipboard Sync v1 — Implementation Plan

Plain-text-only cross-machine clipboard sync for lan-mouse. macOS + Linux (Hyprland/wlroots) primary targets. Windows = compile stub. X11 not supported in v1.

## Design decisions (settled)

| Area | Decision |
|---|---|
| Scope | UTF-8 plain text only. Regular clipboard. No primary selection. No images, no files, no HTML. |
| Platforms | macOS + Linux Wayland (Hyprland/wlroots). Windows: empty stub backend. X11: not in v1. |
| Transport | rustls over TCP on the same port number as DTLS-UDP (4242 default), reusing the existing pinned cert. One persistent TCP connection per peer. TCP listener rebinds in sync with UDP listener when `FrontendRequest::ChangePort` fires. |
| Peer lifecycle | Clipboard TCP follows DTLS lifecycle, 1:1. When DTLS for a client transitions to connected (`client_manager.set_active_addr` is set), open clipboard TCP to the same IP+port. When DTLS drops, drop the TCP. No independent reconnect logic. |
| Inbound auth | Accept incoming clipboard TCP from any peer whose cert fingerprint is in `authorized_keys` (same rule DTLS uses). Implemented with a custom rustls `ClientCertVerifier` (rustls 0.23 has no `insecure_skip_verify`). |
| Handshake | Version/capabilities `Hello` as the first framed message on the TCP channel only. UDP/DTLS event path untouched. Clipboard ops gated on `CAP_CLIPBOARD` bit; events keep flowing on UDP regardless. |
| Direction | Bidirectional between all connected/authorized peers. Always on. No toggle, no per-client config. |
| Peer ID / origin | Full SHA-256 cert fingerprint as colon-separated lowercase hex string (same form as `authorized_keys` keys). No truncation. |
| Loop suppression | Per-origin global monotonic serial. Messages carry `(origin, serial)`. Receivers track `last_seen[origin]`; drop messages with `serial <= last_seen[origin]`. Receivers do not re-broadcast received content. |
| Peer restart | `last_seen[origin]` is reset to 0 whenever a fresh TCP connection from that origin completes its `Hello` handshake. No `session_id` field needed. |
| Size cap | 64 MiB hard cap, enforced at the codec layer on both encode and decode. |
| Wire format | `postcard` (serde-based, stable wire format, varint-encoded). Framing: `[u32 BE length][postcard payload]`. |
| Versioning policy | `protocol_version` bumps only on structural changes to `CapMsg`. Adding new supported MIME types is negotiated via `Hello.capabilities` bits and does **not** bump `protocol_version`. |
| Liveness | No application-layer `Ping`/`Pong`. Use TCP keepalive via `socket2::TcpKeepalive` (30s idle, 10s interval, 3 probes) plus read errors. |
| Wayland protocol selection | Prefer `ext_data_control_manager_v1`, fall back to `zwlr_data_control_manager_v1` v2. Hand-rolled with `wayland-client`. If neither manager is advertised at startup, log a clear "clipboard sync unavailable on this compositor" warning and the backend becomes a no-op for that session. |
| Wayland MIME | Offer both `text/plain;charset=utf-8` (canonical) and `text/plain` (legacy fallback). |
| Wayland self-fire | When we call `set_selection` with our own `wl_data_source`, the compositor will send back a `selection(offer)` event for that source. Track our own `wl_data_source` object identity; when `selection(offer)` arrives for our source, do not emit a `ClipboardChange`. |
| Wayland dispatch | Dedicated OS thread running `EventQueue::blocking_dispatch`, with `mpsc` channels to a tokio task. Do **not** use `spawn_blocking` (it pins a worker forever). |
| macOS | Poll `NSPasteboard.changeCount` every 250ms via `objc2`. Each poll iteration wrapped in `objc2::rc::autoreleasepool` to avoid leaking autoreleased objects. |
| macOS self-fire | After `setString:forType:`, record `(new_change_count, sha256(content))`. On next poll, suppress only if **both** match. |
| Startup-clipboard race | On startup (both platforms), read the current clipboard but mark it as "seen" without broadcasting. Only broadcast on the *next* observed change. |
| Wayland persistence | Accept that the clipboard belongs to lan-mouse while it runs and clears on exit. No `wl-copy` hand-off. |
| Wayland null-selection rule | On `selection(NULL)`: re-claim with last content **iff** the last selection originated from a remote peer. If origin was local, do nothing. |
| Origin tracking | `enum SelectionOrigin { Local, Remote }`. Updated only when lan-mouse-wayland successfully calls `set_selection` (`Remote`) or observes a non-lan-mouse owner (`Local`). Initial selection at startup treated as `Local`. |
| Race policy | Last-write-wins by local event-loop arrival order. Origin set by path the winning event came in on. |
| Trait syntax | `Clipboard` trait exposes async methods only (no `Stream` impl). `async fn next_event(&mut self) -> Option<ClipboardChange>` is the read path. Uses `#[async_trait]` to stay dyn-compatible (same pattern as `input-emulation`). |
| Crate placement | `CapMsg` + framing helpers live in `lan-mouse-clipboard`, **not** in `lan-mouse-proto` (which stays the fixed-size UDP codec). |
| GTK frontend | No changes in v1. No toggle. Status indicator deferred. UI "client connected" semantic = DTLS up. Clipboard TCP up/down is a separate, currently invisible state. |

## Wire protocol (new TCP channel only)

### Framing

```
[u32 BE length][postcard payload]
```

`payload` is a postcard-encoded `CapMsg` enum. Max frame size 64 MiB; codec rejects larger frames on encode and decode.

### Messages

```rust
enum CapMsg {
    Hello {
        protocol_version: u16,    // bump only on structural changes to CapMsg
        peer_id: String,          // full SHA-256 cert fingerprint, colon-hex
        capabilities: u32,        // bitflags: CAP_CLIPBOARD = 1 << 0,
                                  //           future MIME-type caps add new bits here
    },
    Clipboard {
        origin: String,           // peer_id of the machine where the copy happened
        serial: u64,              // monotonic per-origin
        mime: String,             // "text/plain;charset=utf-8" for v1
        data: Vec<u8>,            // UTF-8 bytes for v1
    },
}
```

No `Ping`/`Pong` — liveness is handled by TCP keepalive (`socket2::TcpKeepalive`, 30s idle / 10s interval / 3 probes) and read errors.

### Handshake rules

- Both ends send `Hello` as the very first framed message.
- Both ends wait for the peer's `Hello` before sending anything else.
- `Hello.peer_id` **must** equal the SHA-256 fingerprint of the leaf cert presented in the TLS handshake on this connection. If it doesn't, log a warning and close the connection. This prevents an authorized peer from spoofing another authorized peer's `origin` (and silencing them by sending `serial = u64::MAX`).
- `protocol_version` mismatch → log error, close TCP connection. UDP/DTLS event channel keeps working independently.
- Missing `CAP_CLIPBOARD` bit → log info, do not send/receive `Clipboard` messages on this connection.
- On successful `Hello` from a peer, reset `last_seen[peer.peer_id] = 0` to handle peer restart.

### Loop-suppression invariants

- Each lan-mouse instance maintains `local_serial: u64` (its own counter).
- On local clipboard change: `local_serial += 1`; broadcast `Clipboard { origin: self.peer_id, serial: local_serial, ... }`.
- On receive: `msg.origin` **must** match the `peer_id` established by `Hello` on this connection. If not, log a warning and close the connection. Then: if `msg.serial <= last_seen[msg.origin]`, drop silently. Otherwise update `last_seen[msg.origin] = msg.serial` and apply locally.
- A receiver applying a remote `Clipboard` does **not** re-broadcast.
- On fresh TCP connection completing `Hello`: reset `last_seen[origin]` to 0 (so post-restart messages from that origin are accepted).
- `origin` is always the original copier, never an intermediate forwarder. In v1 there is no forwarding (mesh = full N×N TCP connections); the field is reserved for future relay scenarios.

### Versioning policy

- `protocol_version` only changes when `CapMsg` itself changes shape (new variant, removed field, changed field type).
- Adding support for a new MIME type (e.g. `image/png`) is **not** a `protocol_version` bump. Instead:
  - Reserve a new bit in `Hello.capabilities` (e.g. `CAP_MIME_PNG = 1 << 1`).
  - Only send `Clipboard { mime: "image/png", ... }` when the peer advertises that bit.
- Postcard's wire format is stable across crate versions; structural evolution still requires a `protocol_version` bump because postcard does not silently tolerate trailing/missing fields.

## Crate / file layout

### New crate: `lan-mouse-clipboard`

Mirrors the shape of `input-capture` / `input-emulation`.

```
lan-mouse-clipboard/
├── Cargo.toml
├── build.rs                 # sets cfgs for available backends
└── src/
    ├── lib.rs               # Clipboard trait, LanMouseClipboard wrapper, Backend enum, fallback selection
    ├── error.rs
    ├── proto.rs             # CapMsg enum + postcard framing helpers + 64 MiB cap
    ├── wayland.rs           # ext-data-control-v1 + zwlr-data-control-v1 backend
    ├── macos.rs             # NSPasteboard polling backend
    ├── windows.rs           # stub (no-op, logs once)
    └── dummy.rs             # for testing
```

**Public API sketch:**

```rust
#[async_trait]
pub trait Clipboard: Send {
    /// Await the next clipboard change observed locally. Returns `None` only on
    /// terminal shutdown of the backend.
    async fn next_event(&mut self) -> Option<ClipboardChange>;

    /// Set the local clipboard. Backend MUST suppress the self-fire that this
    /// will trigger (Wayland: source-identity check; macOS: changeCount + sha256 check).
    async fn set(&mut self, content: ClipboardContent) -> Result<(), ClipboardError>;

    async fn terminate(&mut self) -> Result<(), ClipboardError>;
}

pub struct ClipboardChange {
    pub content: ClipboardContent,
    pub origin_hint: OriginHint,    // backend-supplied; Wayland: Local | LanMouse, macOS: always Local
}

pub struct ClipboardContent {
    pub mime: String,
    pub data: Vec<u8>,
}
```

Trait is async-method-only (no `Stream`). Uses `#[async_trait]` for boxed futures so it's dyn-compatible. The `next_event` cancel-safety contract: backends must hold partial state internally so that dropping the returned future before completion does not lose an event. The simplest implementation: each backend has an internal `tokio::sync::mpsc::Receiver` populated by a worker thread/task, and `next_event` is just `recv().await`.

**Backend selection (`lib.rs`):**
- macOS target: `macos` backend only.
- Linux target: try `wayland` (ext-data-control → wlr-data-control), else `dummy`.
- Windows target: `windows` stub.

### New files in root `src/`

```
src/
├── clipboard.rs       # Clipboard task (mirrors src/capture.rs shape)
└── clipboard_net.rs   # rustls TCP listener + connector, Hello handshake, frame codec
```

**`src/clipboard.rs` responsibilities:**
- Owns `LanMouseClipboard` backend.
- Tracks `SelectionOrigin` per-platform (Wayland only needs it).
- Maintains `local_serial: u64` and `last_seen: HashMap<String, u64>` (key = peer fingerprint).
- Receives local changes from backend → broadcasts via `clipboard_net`.
- Receives remote `Clipboard` messages from `clipboard_net` → calls `backend.set()` after serial check.
- Implements Wayland null-selection re-claim policy (re-claim if origin == Remote).
- On startup, reads current clipboard from backend and marks it "seen" without broadcasting.

**`src/clipboard_net.rs` responsibilities:**
- TCP listener bound to `0.0.0.0:<port>` (same port number as UDP).
- Rebinds in sync with the UDP listener on `FrontendRequest::ChangePort`.
- Outbound connector triggered when DTLS becomes connected for a client (see `connect.rs` — hook in after `set_active_addr` is set); dials the same IP+port. Drops the TCP when DTLS drops.
- rustls 0.23 server + client configs using the existing `crypto::Certificate`. Custom `ClientCertVerifier` / `ServerCertVerifier` that check the peer's cert fingerprint against `authorized_keys` (rustls has no `insecure_skip_verify`; the verifier replaces standard PKI validation).
- TCP keepalive enabled via `socket2` (30s idle / 10s interval / 3 probes).
- `Hello` handshake state machine; on success, signals clipboard task to reset `last_seen[peer]`.
- Frame encode/decode (`[u32 BE len][postcard payload]`, 64 MiB cap).
- `tokio::mpsc` channels to `clipboard.rs`.

### Modified files

| File | Change |
|---|---|
| `lan-mouse-proto/*` | **No changes.** `CapMsg` lives in `lan-mouse-clipboard::proto`, not here. |
| `src/service.rs` | Add field `clipboard: Clipboard`; constructor wiring; new `tokio::select!` arms for clipboard events and clipboard-net events. Lines ~41-73 (struct), ~82-131 (new), ~146-156 (select). |
| `src/connect.rs` | Add a hook so that when `set_active_addr` succeeds, `clipboard_net` is told to open TCP to that addr. When the receive loop disconnects, signal `clipboard_net` to drop the TCP. |
| `src/listen.rs` | **No changes.** Clipboard TCP listener is separate, in `clipboard_net.rs`. |
| `src/config.rs` | No changes for v1 (always on). |
| `lan-mouse-ipc/src/lib.rs` | No changes for v1 (no UI status). |
| `lan-mouse-gtk/*` | No changes for v1. |
| Root `Cargo.toml` | Add workspace member `lan-mouse-clipboard`. Add new feature `clipboard` (default on). Add dep on `lan-mouse-clipboard` for root crate. Add `postcard` and `socket2` deps. rustls 0.23.12 is already present. |

## Implementation phases

Each phase should compile and `cargo clippy --workspace --all-targets --all-features` clean before moving on.

### Phase 1 — Clipboard crate skeleton + protocol ✅
(Merged with what was previously phase 3.)
1. Create `lan-mouse-clipboard/` workspace member with `Cargo.toml`, `build.rs`, `src/{lib.rs, error.rs, proto.rs, dummy.rs}`.
2. Implement `proto.rs`:
   - `CapMsg` enum (see Wire protocol section).
   - `postcard` serialization with an explicitly pinned `postcard` configuration (the default; pinning is documented in a comment so a future change is recognized as a wire break).
   - `encode_frame(msg) -> Result<Vec<u8>>` and `decode_frame(reader) -> Result<CapMsg>` using `[u32 BE length][postcard payload]`.
   - 64 MiB cap on both encode and decode. **The decoder must check the length prefix and reject before allocating the payload buffer or calling `postcard::from_bytes`.** A hostile peer sending `[u32 BE: 0xFFFFFFFF]` must not cause a 4 GiB allocation.
3. Define `Clipboard` trait (`#[async_trait]`), `LanMouseClipboard` wrapper, `Backend` enum.
4. Implement `dummy` backend.
5. Unit tests:
   - Round-trip every `CapMsg` variant.
   - Partial-read handling (decoder asks for more bytes; doesn't panic on EOF mid-frame).
   - **Oversize-length rejection without allocation**: feed `[u32 BE: 100_000_000][nothing]` and assert the decoder returns an error after reading 4 bytes, before any payload allocation. Same for `u32::MAX`.
   - Malformed postcard payload inside a valid length prefix returns a decode error.
   - Encoding a `CapMsg::Clipboard` with `data.len() > 64 MiB` returns an error and does not produce output.

**Verify:** `cargo test -p lan-mouse-clipboard` and `cargo build --workspace` clean.

### Phase 2 — rustls TCP side-channel
1. Create `src/clipboard_net.rs`.
2. Server: bind TCP on same port number as UDP. rustls 0.23 server config using existing `Certificate`. Custom `ClientCertVerifier` checking peer fingerprint against `authorized_keys` via `crypto::generate_fingerprint`. Accept connections, complete TLS, **record the peer's leaf cert fingerprint** so the `Hello` handler can compare it against `Hello.peer_id` and reject mismatches. Enable TCP keepalive via `socket2`.
3. Client: rustls 0.23 client config with a custom `ServerCertVerifier` that pins on fingerprint. (rustls 0.23 has no `insecure_skip_verify`; the verifier replaces standard PKI validation.) Same fingerprint-vs-`Hello.peer_id` check on the client side after the server's `Hello` arrives.
4. Port-change handling: subscribe to the same port-change signal used by the UDP listener and rebind the TCP listener in sync.
5. Connection lifecycle: outbound TCP is opened when DTLS becomes connected for a peer (hook into `connect.rs` after `set_active_addr`). Closed when DTLS drops. No independent reconnect logic.
6. Channels: `tokio::mpsc<CapMsg>` in both directions per peer.
7. On `Hello` completion, emit a "peer (re)connected" signal that the clipboard task uses to reset `last_seen[peer]`.
8. **Do not yet wire to clipboard task.** Just prove the side-channel works with a placeholder consumer that logs incoming messages.

**Verify:** manual test — start two lan-mouse daemons locally, observe Hello exchange in logs.

### Phase 3 — (removed; merged into phase 1)

### Phase 4 — Wayland backend
1. Add `wayland-client`, `wayland-protocols-wlr`, `wayland-protocols` (for ext-data-control) to `lan-mouse-clipboard/Cargo.toml` under Linux cfg. Confirm the chosen `wayland-protocols` version actually exposes `ext_data_control_v1` bindings; if not, only use `zwlr_data_control_v1`.
2. Implement registry binding: prefer `ext_data_control_manager_v1`, fall back to `zwlr_data_control_manager_v1` v2. Log which one was selected. If neither is advertised, log a "clipboard sync unavailable on this compositor" warning and the backend becomes a no-op (`next_event` parks indefinitely on an empty channel, `set()` is a no-op).
3. Bind any `wl_seat`; call `get_data_device`.
4. Run the wayland dispatch loop on a **dedicated OS thread** via `EventQueue::blocking_dispatch`. Cross-thread communication uses `mpsc` channels into the tokio side. Do not use `spawn_blocking` (it pins a worker forever).
5. Read path:
   - Handle `data_offer` + `offer` events to collect available MIME types per offer.
   - Handle `selection(offer)`: if the offer corresponds to **our own** `wl_data_source` (tracked by object identity), drop it without emitting. Otherwise pick `text/plain;charset=utf-8` if present, else `text/plain`; create a pipe, call `receive(mime, fd)`, read until EOF on a worker thread.
   - Emit `ClipboardChange { origin_hint: Local }` for non-self offers.
   - Handle `selection(NULL)`: emit a `NullSelection` signal on the stream — clipboard task uses this for the re-claim decision.
6. Write path (`set()`):
   - `create_data_source`, `offer("text/plain;charset=utf-8")`, `offer("text/plain")`, `set_selection(source)`.
   - Store last-set content and the source object handle; on `send(mime, fd)` callback, write the stored bytes and close fd.
   - On `cancelled`, drop source and notify clipboard task we lost ownership.

**Verify:** manual test — copy in Firefox, observe `ClipboardChange` event. `cargo run` + `wl-paste` to see lan-mouse-set content.

### Phase 5 — macOS backend
1. Add `objc2`, `objc2-app-kit`, `objc2-foundation` to `lan-mouse-clipboard/Cargo.toml` under macOS cfg.
2. Run polling on a dedicated tokio task that calls `objc2::rc::autoreleasepool` per iteration. Poll `NSPasteboard.generalPasteboard.changeCount` every 250ms.
3. On change: read `stringForType:NSPasteboardTypeString`; if non-null and changed since last read, emit `ClipboardChange { origin_hint: Local }`.
4. `set()`: inside an autorelease pool, `clearContents`, `setString:forType:NSPasteboardTypeString`. Record `(last_set_change_count, last_set_sha256)`; on next poll, suppress self-fire only if **both** match the observed values.
5. On startup, read the current clipboard once, populate `last_set_*` to suppress that initial value as a broadcast trigger (the clipboard task also gates this via its "mark initial as seen" rule).

**Verify:** manual cross-platform test with phase 7 wiring.

### Phase 6 — Windows stub
1. Empty `Clipboard` impl: `next_event` awaits a never-closed channel (parks forever); `set()` is a no-op; `terminate()` returns Ok.
2. Log `warn!("clipboard sync not implemented on Windows in v1")` once at construction.

### Phase 7 — Service integration
1. Add `Clipboard` task struct in `src/clipboard.rs`. Constructor takes the `LanMouseClipboard` backend handle, the clipboard_net send/recv channels, and the local peer fingerprint.
2. State:
   - `local_serial: u64`
   - `last_seen: HashMap<String, u64>` (key = peer fingerprint)
   - `selection_origin: SelectionOrigin` (only meaningful on Wayland; macOS ignores)
   - `last_remote_content: Option<ClipboardContent>` (for Wayland re-claim)
   - `startup_baseline_consumed: bool` (gates the "ignore initial clipboard" rule)
3. Startup: on first backend `ClipboardChange` after construction, mark it as seen (update internal "last broadcast content" tracking) but do **not** broadcast. Set `startup_baseline_consumed = true`. Subsequent local changes broadcast normally.
4. Event loop (inside `tokio::select!`):
   - Local backend `ClipboardChange` (Local origin, after baseline): increment `local_serial`, broadcast `CapMsg::Clipboard`, set `selection_origin = Local`.
   - Local backend null-selection signal: if `selection_origin == Remote` and `last_remote_content.is_some()`, call `backend.set(last_remote_content)`. Else do nothing.
   - Local backend `ClipboardChange` from our own re-claim: ignored at the backend level (Wayland: own-source check; macOS: changeCount+sha256 check).
   - Remote `CapMsg::Clipboard` from clipboard_net: if `serial > last_seen[origin]`, update `last_seen`, store as `last_remote_content`, call `backend.set()`, set `selection_origin = Remote`.
   - "Peer (re)connected" signal from clipboard_net: reset `last_seen[peer] = 0`.
5. Wire into `Service::run` `tokio::select!` (`src/service.rs:146-156`).

**Verify:** end-to-end manual test with two machines (Hyprland ↔ macOS).
- Copy on Hyprland → paste on macOS.
- Copy on macOS → paste on Hyprland.
- Wayland app exits while holding remote content → clipboard stays populated (re-claim).
- Wayland app exits while holding local content → clipboard goes empty (no re-claim).
- Rapid alternating copies on both machines → no infinite loop, last writer wins.

### Phase 8 — Tests, docs, polish
1. Unit tests for `CapMsg` codec (already in phase 1).
2. Unit tests for serial-based loop suppression logic (extract pure function from clipboard task).
3. Integration test: dummy backend on both ends, verify message flow.
4. Update `README.md`: check the clipboard checkbox; note Hyprland/wlroots + macOS only in v1.
5. Update `DOC.md`: fix the stale TCP description; add a clipboard section describing the side-channel and the Hello handshake.
6. Update `AGENTS.md`: fix the UDP/TCP transport claim; add clipboard subsystem to architecture section.
7. `cargo fmt && cargo clippy --workspace --all-targets --all-features` clean.

## Estimated effort

| Phase | Effort |
|---|---|
| 1. Crate skeleton + protocol & framing (postcard) | 1-1.5 days |
| 2. rustls TCP side-channel (with custom verifiers, keepalive, port-rebind) | 2-3 days |
| 3. (merged into phase 1) | — |
| 4. Wayland backend (dedicated thread, own-source tracking) | 3-4 days |
| 5. macOS backend (autoreleasepool, changeCount+sha256 suppression) | 1-2 days |
| 6. Windows stub | 30 min |
| 7. Service integration (clipboard task, startup baseline) | 2 days |
| 8. Tests, docs, polish | 1-2 days |

**Total: ~10-14 days focused work.**

## Resolved decisions (previously open)

- **rustls version:** 0.23.12 is already in `Cargo.toml`. Use it. No `insecure_skip_verify` available; implement custom `ClientCertVerifier` and `ServerCertVerifier` that pin on the SHA-256 fingerprint of the leaf cert against `authorized_keys`.
- **Peer ID:** full SHA-256 fingerprint as colon-separated lowercase hex string (the existing `crypto::certificate_fingerprint` format). Single helper in `crypto.rs` if not already exposed.
- **When to open TCP:** when DTLS becomes connected for that peer; close when DTLS drops. 1:1 lifecycle. Same IP+port as DTLS.
- **Wayland self-fire detection:** track our own `wl_data_source` object identity; skip `selection(offer)` events whose offer corresponds to our own source.
- **Wire format:** `postcard`. Explicitly pin the configuration in a single helper module.
- **Liveness:** TCP keepalive (`socket2::TcpKeepalive`, 30s idle / 10s interval / 3 probes) + read errors. No application-layer `Ping`/`Pong`.
- **Peer restart:** reset `last_seen[origin]` on each fresh TCP+`Hello` completion. No session-id field needed.
- **macOS self-fire:** `(changeCount, sha256(content))` pair must match to suppress.
- **Size cap:** 64 MiB enforced in codec.
- **Startup-clipboard race:** read initial clipboard, mark as seen, do not broadcast until the next change.
- **MIME expansion:** done via `Hello.capabilities` bits; does not bump `protocol_version`.

## Remaining open questions

1. **macOS polling vs notification.** 250ms polling is the conservative default. `NSPasteboard` change notifications via KVO exist on newer macOS. Stick with polling for v1; revisit if latency complaints arise.
2. **`ext_data_control_v1` availability in the chosen `wayland-protocols` crate version.** Verify during phase 4. If the bindings aren't shipped in the version we pin, ship with `zwlr_data_control_v1` only and re-evaluate later.
3. **Hooking outbound TCP into `connect.rs`.** Exact place to fire the "DTLS connected → open clipboard TCP" signal: probably right after `set_active_addr` at `src/connect.rs:196`, or via a channel that the clipboard_net subscribes to. Confirm during phase 2.

## Out of scope for v1 (explicit non-goals)

- Images, file URIs, HTML, RTF, custom MIME types.
- Primary selection (middle-click paste) sync.
- X11 backend.
- GNOME-on-Wayland (mutter does not implement wlr/ext-data-control).
- Windows clipboard read/write (compile-stub only).
- GTK frontend toggle, per-client config, size caps.
- Content history / clipboard manager features (cliphist-style ring buffer).
- Encryption beyond what rustls provides (DTLS for events, TLS for clipboard — both authenticated by pinned cert).
- Compression for large payloads.
- Forwarding / mesh relay (assumed full N×N TCP mesh — `origin` field reserved for future use).
