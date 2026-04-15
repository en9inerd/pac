# Plan: E2E Encrypted Multi-Peer Chat + File Transfer

> **Project name TBD** — monorepo

## Goals

- Learn POSIX sockets, epoll (Linux) + kqueue (macOS), pthreads
- Learn custom TCP framing, transport abstraction, pluggable obfuscation
- Learn protocol design (binary framing, multi-peer key exchange, routing)
- Understand E2E encryption with N peers (pairwise model via libsodium)
- Understand noise-style obfuscation resistant to DPI (TSPU/GFW)
- Zig as build system for C projects
- Go web app serving browser client (JS + libsodium.js), bridges WebSocket ↔ raw TCP

---

## Structure

| Directory | Language | Purpose |
|---|---|---|
| `server/` | C + Zig | TCP relay server, channel management |
| `cli/` | C + Zig | Line-based CLI client |
| `web/` | Go + JS | Serves HTML/JS frontend to browser |
| `shared/` | C | Shared code: frame, transport, protocol |

All three components (server/cli/web) speak the same application protocol (MessagePack messages). Transport differs: CLI uses raw TCP, browser uses WebSocket (bridged to raw TCP by Go). Server is the only backend. `shared/` eliminates duplication of `frame.c/h`, `transport.c/h`, `protocol.c/h` between server and CLI.

---

## Architecture

```
              ┌─────────────────────────────┐
              │  C Server (epoll/kqueue)    │
              │  raw TCP relay + hub        │
              │  Sees: encrypted blobs only │
              └──────┬───────────┬──────────┘
                     │           │
          raw TCP    │           │  raw TCP
        (noise tunnel│           │  (plain, internal only)
         --obfs)     │           │
       ┌─────────────┘           └──────────────┐
       │                                        │
┌──────┴───────┐                    ┌───────────┴──────────┐
│ C CLI Client │                    │  Go Web Server       │
│ libsodium    │                    │  serves static/      │
│ transport.c  │                    │  WebSocket ↔ TCP     │
│ (plain|noise)│                    │  bridge              │
└──────────────┘                    └───────────┬──────────┘
                                                │ wss:// (real TLS — CDN or nginx+cert)
                                    ┌───────────┴──────────┐
                                    │ Browser (JS)         │
                                    │ libsodium.js (wasm)  │
                                    └──────────────────────┘
```

- **Transport:** raw TCP with custom length-prefix framing `[4B len][payload]`
- **Serialization:** MessagePack — binary, compact, deterministic, multi-language safe
- **I/O model:** epoll (Linux) / kqueue (macOS) behind `event_loop.h` abstraction, non-blocking
- **Encryption:** Pairwise E2E — X25519 ECDH → XSalsa20-Poly1305
- **CLI DPI bypass:** noise tunnel inside TLS — nginx/Xray in front, TSPU sees HTTPS
- **Browser DPI bypass:** `wss://` via CDN (preferred) or nginx+Let's Encrypt (no CDN) — Go bridge translates WebSocket ↔ raw TCP
- **Server storage:** in-memory only, auto-expire on TTL or all-disconnect

**Deployment (no CDN):**
```
Browser → wss://yourdomain.com:443 (nginx TLS) → Go bridge → C server
CLI     → TLS:443 (nginx)          → noise tunnel           → C server
```
Free TLS cert via certbot. Requires only a domain name — no CDN account.

---

## Transport Layer

C server speaks raw TCP only. WebSocket lives exclusively in the Go web server (browser bridge). CLI speaks raw TCP directly.

### Custom Framing

```
[4B payload_len (BE uint32)][payload]
```

No masking, no opcodes, no HTTP upgrade. Receiver accumulates bytes until `recv_len >= 4 + payload_len`.

```c
// frame.h/c
typedef struct { uint8_t *data; size_t len; } RecvBuf;  // data = Peer.recv_buf, len = Peer.recv_len

int  frame_write(Transport *t, const uint8_t *payload, uint32_t len);  // goes through transport; SIGPIPE handled by signal(SIGPIPE, SIG_IGN)
int  frame_read(RecvBuf *buf, uint8_t **payload, uint32_t *len); // 0=incomplete, -1=error
```

`payload_len > MAX_FRAME_SIZE` → disconnect. Partial reads handled via `RecvBuf` accumulation in event loop.

### Pluggable Transport

```c
// transport.h
typedef struct Transport {
    void *ctx;                                           // per-connection state (e.g. fd, NoiseState*)
    int  (*send)(void *ctx, const uint8_t *buf, size_t len);
    int  (*recv)(void *ctx, uint8_t *buf, size_t len);
    void (*close)(void *ctx);  // frees transport-level resources only (e.g. noise ctx); fd closed by disconnect()
} Transport;

Transport transport_plain(int fd);        // raw TCP, no obfuscation (default)
Transport transport_noise(int fd, const char *password, bool is_server); // noise tunnel
// future: transport_shadowtls() — real TLS handshake + HMAC proof + noise inside
```

Server selects transport per connection based on `--obfs` flag. Frame layer sits above transport — identical regardless of transport used.

### Protocol Version Negotiation

First frame after transport handshake — client sends, server responds:

```
// MessagePack-encoded (shown as JSON for readability)
{"type":"hello_version","payload":{"v":1,"caps":["file","voice"]}}
{"type":"hello_version_ack","payload":{"v":1}}
```
`caps` = peer application capabilities (e.g. `"file"`, `"voice"`). Sent by client, stored on `Peer`, relayed in `welcome`/`peer_joined`. Server has no app-level caps — ack only confirms negotiated version. Transport (noise/plain) is server-side config, not a peer cap.

No match → server sends error frame + closes. Version stored on `Peer` for session lifetime.

---

## Noise Tunnel (`--obfs password`, CLI + server only)

Makes traffic look like random noise to DPI. No TLS structure. Active-probing resistant. Optional, disabled by default.

### Handshake

```
Client → Server:
  [32B random nonce]   ← first bytes on wire, indistinguishable from noise

Both sides derive (BLAKE2b-32):
  session_key = BLAKE2b-32(password || nonce)
  enc_key_c2s = BLAKE2b-32("c2s" || session_key)
  enc_key_s2c = BLAKE2b-32("s2c" || session_key)
```

Server receives 32B, derives key from configured password, attempts MAC verification on next frame. Wrong password → MAC fails → drop silently. Server reveals nothing to probers.

### Tunnel Frame Format

```
[1B  pad_len  (random 0–255)]
[pad_len random bytes        ]   ← random padding, defeats traffic analysis
[8B  counter  (BE uint64)    ]   ← per-direction monotone, starts at 1
[N+16B ChaCha20-Poly1305 ciphertext+tag]
```

Nonce = `BE64(counter) || 0x00000000` (12B). Increment `send_counter` after each send. Reject if `incoming_counter <= recv_counter` (replay protection).

All crypto already in libsodium:
```c
crypto_generichash()                          // BLAKE2b
crypto_aead_chacha20poly1305_ietf_encrypt()   // ChaCha20-Poly1305
randombytes_buf()                             // nonce + padding
```

```
transport.h/c  — transport_plain(), transport_noise()
                 noise_handshake_client(), noise_handshake_server()
                 noise_wrap(), noise_unwrap()
```

---

## E2E Encryption — Pairwise Model

Each peer generates an ephemeral X25519 keypair on connect. Keys live in RAM only.

### Key Exchange

```
A joins  → JOIN{pub:A, id_pub:A, ...}  →  server WELCOME{channel_id, peers:[], expires_at}
B joins  → JOIN{pub:B, id_pub:B, ...}  →  server WELCOME{channel_id, peers:[A], expires_at}, broadcasts PEER_JOINED{pub:B} to A

A: sharedKey[A,B] = crypto_box_beforenm(B_pub, A_priv)
B: sharedKey[B,A] = crypto_box_beforenm(A_pub, B_priv)  // identical 32B key, never sent
```

### Sending a message (A → B)

```
nonce = randombytes_buf(24)
ct    = crypto_secretbox_easy(msg, nonce, sharedKey[A,B])
send CHAT{to:B_pub, from:A_pub, nonce:hex(nonce), ct:hex(ct)}
// "from" lets B pick sharedKey[A,B] for decryption
// wrong "from" → wrong key → poly1305 fails → rejected
```

Server only routes by `to` field, never decrypts.

---

## Protocol Wire Format

All protocol messages are **MessagePack** wrapped in custom TCP frames `[4B len][payload]`. Binary frames for file chunks use the same framing with a leading type byte. MessagePack chosen over JSON for: binary compactness, deterministic encoding, multi-language safety (C/Go/JS/mobile all produce identical bytes for same data).

**Signing rule:** never sign a MessagePack map (key ordering varies by impl). Sign specific raw field bytes directly:
```
sig = Ed25519_sign(session_pub(32B) || len_u16(name) || utf8(name), identity_priv)
```

**Message envelope:** every MessagePack message has the top-level structure `{type: <str>, payload: <map>}`. RPC request/response pairs additionally carry `{id: <str>}` for matching — all other messages omit `id`.

| Type | Direction | `payload` fields |
|---|---|---|
| `hello_version` | client→server | `{v: <int>, caps: ["file", ...]}` — first frame, version + caps |
| `hello_version_ack` | server→client | `{v: <int>}` — confirmed version |
| `create` | client→server | `{ttl: <int>, max_peers: <int>}` — RPC, requires `id` field |
| `created` | server→client | `{channel_id, join_code, expires_at, max_peers}` — RPC response |
| `join` | client→server | `{channel_id, join_code, pub:"<64hex>", id_pub:"<64hex>", name:"<str>", sig:"<128hex>"}` — join + key exchange in one message |
| `welcome` | server→client | `{channel_id, peers:[{pub, id_pub, name, caps}, ...], expires_at:<unix>}` |
| `peer_joined` | server→all | `{pub:"<64hex>", id_pub:"<64hex>", name:"<str>", caps:[...]}` |
| `peer_left` | server→all | `{pub: "<64hex>"}` |
| `chat` | client→server→peer | `{to, from, nonce:"<48hex>", ct:"<hex>"}` |
| `file_info` | client→server→peer | `{to, from, transfer_id:"<16hex>", name, size, chunks, nonce_prefix:"<32hex>"}` |
| `file_chunk` | binary | `[frame_type(1B)][to_pub(32B)][transfer_id(8B)][chunk_idx(8B BE)][ciphertext]` |
| `file_ack` | peer→server→sender | `{to:"<sender 64hex>", transfer_id:"<16hex>", ok:<bool>, error:"<str>"}` |
| `error` | server→client | `{code:<int>, message:"<str>"}` |
| `leave` | client→server | `{}` |

### Binary Frame Type Registry

```
frame_type = 0x01  →  file_chunk: [frame_type(1B)][to_pub(32B)][transfer_id(8B)][chunk_idx(8B BE)][ct]
frame_type = 0x02–0xFE  →  reserved
frame_type = 0xFF  →  reserved (extension marker)
```

Unknown frame_type → drop silently. Outer `[4B len]` gives total frame size — always safe to advance past unknown binary frames.

### File transfer

```
chunk_size = 65536  // 64KB plaintext
nonce      = nonce_prefix(16B) || chunk_idx(8B BE)  // 24B total
ct         = crypto_secretbox_easy(chunk, nonce, sharedKey[sender, recipient])
```

- `nonce_prefix`: 16B random, generated per file per recipient, sent in `file_info`
- `transfer_id`: 8B random per transfer — receiver matches chunks by `transfer_id` (unique enough at 8B); `from_pub` comes from the preceding `file_info` message and is stored in transfer state
- `file_ack`: sent after all chunks verified. On decrypt failure → `{ok:false, error:"decrypt_failed"}`, sender restarts whole transfer
- Server routes `file_chunk` by `to_pub` (bytes 1–32, after frame_type byte), routes `file_ack` by `payload.to`

### Error codes

| Code | When |
|---|---|
| 400 | Malformed frame / invalid MessagePack / unknown type / version mismatch |
| 403 | Bad join code |
| 404 | Channel not found |
| 409 | Duplicate pub key in channel |
| 429 | Channel full |
| 500 | Internal error |

---

## Server

### I/O Design

Platform-agnostic via `event_loop.h` interface — epoll backend (Linux), kqueue backend (macOS/BSD). `SO_REUSEPORT` available on both.

```c
// event_loop.h
typedef struct EventLoop EventLoop;

EventLoop *el_create(void);
void       el_add(EventLoop*, int fd, uint32_t events, void *data);
void       el_mod(EventLoop*, int fd, uint32_t events, void *data);
void       el_del(EventLoop*, int fd);
int        el_wait(EventLoop*, int timeout_ms);  // returns n events
void      *el_event_data(EventLoop*, int i);     // data ptr for event i
uint32_t   el_event_flags(EventLoop*, int i);    // EL_READ | EL_WRITE | EL_HUP
void       el_destroy(EventLoop*);
int        el_cpu_count(void);                   // sysconf(_SC_NPROCESSORS_ONLN) wrapper

// event_loop.c — #ifdef __linux__ → epoll; #ifdef __APPLE__ → kqueue
```

One event loop per CPU core. Each worker owns its listen socket (`SO_REUSEPORT`) and event loop — kernel load-balances connections. Hub is the only shared state.

- listen fd and peer ptrs registered via `el_add`; dispatch on `el_event_data(el, i)`
- `el_wait` timeout = `EXPIRY_CHECK_MS` — one thread per cycle runs `hub_expire` via `pthread_rwlock_trywrlock`
- Relay: `sender->channel` (O(1)) → find `Peer*`, hold `ch->mu` → lock `write_mu` → `frame_write()` → unlock `write_mu` → unlock `ch->mu`
- `pthread_rwlock_t` on hub: wrlock for join/leave/expire/create only; relay never locks hub

### Data Structures

```c
#define ABS_MAX_PEERS_PER_CHANNEL  1024      // hard ceiling — array allocation bound
#define ABS_MAX_CHANNELS           4096      // hard ceiling
#define MAX_CONNECTIONS            100000
#define PEER_BUF_SIZE              (128 * 1024)
#define MAX_FRAME_SIZE             PEER_BUF_SIZE
#define MAX_EVENTS                 64
#define EXPIRY_CHECK_MS            5000

// runtime config (set from CLI args at startup, stored in ServerConfig)
// defaults shown; operator may override
//   --max-peers N        clamped to [2, ABS_MAX_PEERS_PER_CHANNEL]  default 256
//   --max-channels N     clamped to [1, ABS_MAX_CHANNELS]           default 1024
typedef struct ServerConfig {
    int max_peers_per_channel;  // server-wide ceiling; per-channel max_peers clamped to this
    int max_channels;
    int port;
    bool silent;
    char obfs_password[128];    // empty = obfs disabled by default
} ServerConfig;

typedef enum {
    PEER_TCP_CONNECTED,      // transport handshake in progress
    PEER_VERSION_HANDSHAKE,  // version/caps negotiation
    PEER_AWAITING_JOIN,      // version handshake done, not yet in channel
    PEER_IN_CHANNEL,
    PEER_DISCONNECTED,
} PeerState;

typedef struct NoiseState {
    uint8_t  enc_key_c2s[32], enc_key_s2c[32];
    uint64_t send_counter;  // starts at 1; increment after each send
    uint64_t recv_counter;  // starts at 0; update to incoming; reject if incoming ≤ this
    bool     active;
} NoiseState;

typedef struct Peer {
    int              fd;
    _Atomic int      state;       // PeerState
    uint8_t          pub_key[32];    // session X25519 pub (E2E)
    uint8_t          id_pub[32];     // identity Ed25519 pub (persistent identity)
    char             name[256];      // display name from JOIN, UTF-8
    uint8_t         *recv_buf;    // malloc(PEER_BUF_SIZE) on accept
    size_t           recv_len;
    struct Channel  *channel;
    pthread_mutex_t  write_mu;    // held during frame_write() — prevents fd-reuse race + interleave
    NoiseState       noise;
    Transport        transport;   // plain or noise — set at accept
    time_t           state_since; // for handshake timeout
    uint8_t          proto_version; // negotiated in version handshake
    char             caps[128];     // relayed in WELCOME/PEER_JOINED; stored as comma-separated string e.g. "file,voice"
} Peer;

typedef struct Channel {
    char     id[33];         // 32hex + NUL
    char     join_code[65];  // 64hex + NUL
    Peer    *peers[ABS_MAX_PEERS_PER_CHANNEL];
    int      peer_count, max_peers;
    time_t   expires_at;
    pthread_mutex_t mu;
} Channel;

typedef struct Hub {
    Channel         *channels[ABS_MAX_CHANNELS];
    int              channel_count;
    pthread_rwlock_t rwlock;
} Hub;
```

### Peer Lifecycle

```
accept():
  calloc(1, sizeof(Peer)) → channel = NULL implicit; malloc(PEER_BUF_SIZE) → pthread_mutex_init(write_mu)
  state = PEER_TCP_CONNECTED; state_since = time(NULL)
  el_add(el, fd, EL_READ, peer)

disconnect() — owning worker thread only:
  el_del(el, fd)
  lock(write_mu) → state = DISCONNECTED → close(fd) → unlock(write_mu)
  if peer->channel != NULL:
    lock(ch->mu) → was_empty = hub_remove_peer() → unlock(ch->mu)
    broadcast peer_left
    if was_empty: wrlock(hub) → remove+free channel → unlock(hub)
  free(recv_buf) → mutex_destroy(write_mu) → free(peer)
```

### Lock Ordering

```
hub->rwlock > ch->mu > peer->write_mu
(rule applies to simultaneous holds; sequential critical sections are fine)

join:       wrlock(hub) → lock(ch->mu) → lock(write_mu)  [broadcast welcome + peer_joined]
relay:      lock(ch->mu) → lock(write_mu)
expire:     wrlock(hub) → lock(ch->mu) → collect fds → unlock(ch->mu) → shutdown(fds) → unlock(hub)
disconnect: lock(write_mu) → unlock(write_mu)  then  lock(ch->mu) → unlock(ch->mu)  [never simultaneous]
```

Peer freed only by owning thread — prevents use-after-free in relay. `hub_expire` acquires `ch->mu` to snapshot peer fds before releasing it, then calls `shutdown(fd, SHUT_RD)` — avoids double-close fd-reuse race and races with `disconnect()`'s `hub_remove_peer()`.

### Hub API

```c
Channel *hub_create_channel(Hub*, int ttl, int max_peers);  // caller holds wrlock
Channel *hub_find_channel(Hub*, const char *id);             // caller holds rdlock
Channel *hub_get_channel(Hub*, const char *id, const char *join_code, int *err);
// *err: 0=ok  403=bad code  404=not found;  caller holds WRLOCK (join path)
int  hub_add_peer(Channel*, Peer*);     // -1 if full (→429), -2 if dup pub key (→409); caller holds ch->mu
int  hub_remove_peer(Channel*, Peer*);  // returns 1 if channel now empty; caller holds ch->mu
void hub_expire(Hub*);                  // caller holds wrlock
```

Channel ID: `randombytes_buf(16B)` → 32hex. Join code: `randombytes_buf(32B)` → 64hex.

### Channel Creation

No REST API. Channel created via first protocol message after transport + version handshake:

```
// MessagePack-encoded (shown as JSON for readability)
{"id":"a1b2","type":"create","payload":{"ttl":3600,"max_peers":10}}
{"id":"a1b2","type":"created","payload":{"channel_id":"<32hex>","join_code":"<64hex>","expires_at":<unix>,"max_peers":10}}
```

- `ttl` clamped to [60, 86400]; `max_peers` clamped to [2, server.max_peers_per_channel]; rate-limited to 10 creates/s per IP
- three-layer limit: `ABS_MAX_PEERS_PER_CHANNEL` (compile-time) → `server.max_peers_per_channel` (server args) → `channel.max_peers` (per-channel, protocol)
- creator stays in `PEER_AWAITING_JOIN` after `created` — must send `join` with the returned `channel_id`+`join_code` to enter the channel

### Startup

```c
signal(SIGPIPE, SIG_IGN);
sodium_init();
// parse CLI: --port N --max-peers N --max-channels N --silent --obfs password
// populate ServerConfig, pass to worker threads
```

```bash
./server --port 8080 --max-peers 256 --max-channels 1024
./server --port 8080 --max-peers 2   # dialog-only server
./server --port 8080 --silent --obfs s3cr3t
```

> **DPI/TSPU note:** bare noise tunnel on raw TCP is detectable via entropy analysis (TSPU 2024+). For Russia/censored networks, always run server behind nginx or Xray with TLS on port 443. Noise tunnel inside TLS = TSPU sees HTTPS, inner bytes invisible.
>
> Recommended deployment:
> ```
> CLI → TLS:443 (nginx) → unix socket → C server (--obfs s3cr3t)
> ```
> Infrastructure only — zero protocol changes needed. Alternative: Xray Reality in front of server for strongest fingerprint resistance.

### Logging

Never log: pub keys, join codes, IP addresses, channel IDs, message sizes, ciphertext.
Safe: server.started, channel.created, peer.joined/left, frame.invalid, peer.write_failed, noise.mac_failed.
Format: `<iso8601> LEVEL event k=v`. Output to stderr. `--silent` disables.

### File Structure

```
pac/                              ← monorepo root
├── shared/
│   ├── frame.c/h                 ← shared between server + cli
│   ├── transport.c/h
│   ├── protocol.c/h
│   └── vendor/
│       └── mpack.h               ← libmpack, header-only, vendored
├── server/
│   ├── build.zig
│   ├── src/
│   │   ├── main.c, event_loop.c/h, hub.c/h
│   │   ├── relay.c/h, crypto_util.c/h, log.c/h
│   └── test/
│       ├── test_frame.c, test_hub.c, test_transport.c, test_protocol.c
├── cli/
│   ├── build.zig
│   ├── src/
│   │   ├── main.c, e2e.c/h
│   │   ├── chat_loop.c/h, file_tx.c/h, identity.c/h, log.c/h
│   └── test/test_e2e.c
└── web/
    ├── go.mod, main.go
    └── static/
        ├── index.html, app.js, style.css
        ├── libsodium.js
        └── msgpack.min.js
```

---

## Encrypted Logs (CLI + Browser, client-side only)

**Problem:** session keypairs are ephemeral. Use long-term identity keypair + per-session log key.

```
~/.config/[name]/
  identity.key
  logs/<channel_id>/<unix_ts>.log
```

**Identity key file:**

Two keypairs stored per identity:
- **Ed25519** — signing (JOIN authentication, proves session ownership across implementations)
- **X25519** — encryption (sealing log keys)

```
[8B  magic "SHHID002"][16B argon2id salt][24B nonce]
[secretbox(
    ed25519_pub(32B) + ed25519_priv(64B) +   // signing keypair
    x25519_pub(32B)  + x25519_priv(32B),      // encryption keypair
    nonce, argon2id(passphrase, salt)
 ) → 160B plaintext + 16B tag = 176B]
```

Total file: 8 + 16 + 24 + 176 = **224 bytes**.

Argon2id: `OPSLIMIT_INTERACTIVE`, `MEMLIMIT_INTERACTIVE`. Unlock once at startup.

```c
crypto_sign_keypair(ed25519_pub, ed25519_priv);   // libsodium
crypto_box_keypair(x25519_pub, x25519_priv);      // libsodium
```

**JOIN signing** (raw field bytes, deterministic across all languages):
```c
// signed bytes: session_pub || name_len(2B BE) || name_utf8
uint8_t msg[32 + 2 + name_len];
memcpy(msg, session_pub, 32);
msg[32] = name_len >> 8; msg[33] = name_len & 0xFF;
memcpy(msg + 34, name_utf8, name_len);
crypto_sign_ed25519_detached(sig, NULL, msg, sizeof(msg), ed25519_priv);
```

Peer verifies: `crypto_sign_ed25519_verify_detached(sig, msg, sizeof(msg), sender_ed25519_pub)`.
`id_pub` = Ed25519 pub = persistent identity. Display: `BLAKE2b(id_pub, 8B)` → 16 hex chars.

**Log file:**
```
[8B magic "SHLOG001"]
[80B crypto_box_seal(log_key(32B), x25519_pub)]   ← sealed to self: 32B ephemeral pub + 16B MAC + 32B ciphertext
[per message: 8B ts | 2B dir | 32B sender_pub | 2B len | 24B nonce | N+16B secretbox(msg, log_key)]
```
`crypto_box_seal` = X25519 + XSalsa20-Poly1305, no nonce field needed (ephemeral key inside).

**Session:** generate `log_key`, seal to identity key, write header. Append each message encrypted with `log_key`.

**Read:** `cli logs <channel_id> [--from date] [--to date]`

**Browser:** IndexedDB, same format. Use libsodium.js — NOT WebCrypto (no X25519 in Safari pre-2024).

---

## CLI Client

Two threads: main (stdin + send) + recv (print incoming).

```
Commands:
  create [--server host:port] [--ttl 1h] [--max-peers N]
  join <id> <code> [--server host:port] [--obfs password]
  send-file <id> <code> <path> [--server host:port]

Chat:
  [HH:MM] You: hello
  [HH:MM] Peer(a1b2...): hi
  *** a1b2... joined ***
  /sendfile ./file.pdf
  /quit
```

Filename sanitization before saving: `basename()`, reject `.`/`..`/empty/NUL bytes, truncate to 255 chars. Save to `./received/<name>`.

---

## Web Client

`main.go`: browser connects via `wss://` (real TLS via CDN). Go upgrades to WebSocket, opens raw TCP connection to C server, forwards frames bidirectionally. C server sees a plain TCP peer — no WebSocket code in C.

`app.js`: `sodium.crypto_box_keypair()` → WebSocket → same MessagePack protocol → `hello_version` → `hello_version_ack` → `join` → `welcome`/`peer_joined` → `crypto_box_beforenm()` → `crypto_secretbox_easy()` per message. Plain HTML/CSS, no framework.

---

## Zig Build

```zig
const exe = b.addExecutable(.{ .name = "server", .target = target, .optimize = optimize });
exe.addCSourceFiles(.{
    .files = &.{ "src/main.c", "src/event_loop.c", "src/hub.c",
                 "src/relay.c", "src/crypto_util.c", "src/log.c",
                 "../shared/frame.c", "../shared/transport.c", "../shared/protocol.c" },
    .flags = &.{ "-Wall", "-Wextra", "-std=c23", "-D_GNU_SOURCE" },
});
exe.addIncludePath(b.path("../shared"));          // frame.h, transport.h, protocol.h
exe.addIncludePath(b.path("../shared/vendor"));   // mpack.h
exe.linkSystemLibrary("sodium");
exe.linkLibC();
b.installArtifact(exe);
// zig build -Dtarget=x86_64-linux-musl   → static binary, zero system deps
```

---

## Implementation Order

| Step | What you learn | Build |
|---|---|---|
| 1 | POSIX sockets | TCP echo: socket/bind/listen/accept/recv/send |
| 2 | Custom framing | `[4B len][payload]` — partial reads, RecvBuf accumulation |
| 3 | Pluggable transport | `Transport` interface, `transport_plain()` |
| 4 | Version handshake | `hello_version` / `hello_version_ack` exchange |
| 5 | Event loop single-threaded | Non-blocking, el_wait, partial reads, EAGAIN — epoll on Linux, kqueue on macOS |
| 6 | Multi-threaded event loop | SO_REUSEPORT, N threads, pthread_rwlock_t on hub |
| 7 | Hub + channel creation | Channel CRUD, `create` message, join code, TTL expiry |
| 8 | Key exchange | `join`/`welcome`/`peer_joined`, crypto_box_keypair, crypto_box_beforenm |
| 9 | Relay | Route CHAT by pub key, write_mu, PEER_DISCONNECTED check |
| 10 | CLI client | Connect, plain transport, recv thread, stdin loop, E2E chat |
| 11 | File transfer | Chunk + encrypt, binary frames, reassemble, file_ack |
| 12 | Identity + logs | Argon2id passphrase, identity keypair, per-session log key |
| 13 | Web client | Go WebSocket↔TCP bridge, libsodium.js, wss://, IndexedDB logs |
| 14 | Noise tunnel | BLAKE2b KDF, ChaCha20 tunnel, random padding, `transport_noise()` |

### Step-by-step notes

**Step 1 — TCP echo:** `socket/bind/listen/accept` loop, `recv/send` in blocking mode. Test: `echo "hi" | nc localhost 8000`.

**Step 2 — Custom framing:** implement `frame_write()` / `frame_read()` with `RecvBuf`. Handle partial reads: accumulate bytes, parse 4B length header first, then wait for full payload. Test: `nc localhost 8000` — send length-prefixed bytes, server echoes back.

**Step 3 — Transport interface:** define `Transport` struct. Implement `transport_plain()` — wraps `send()`/`recv()` directly. `frame_write()` / `frame_read()` call through transport. Test: same as step 2 but via transport interface.

**Step 4 — Version handshake:** on accept, server expects `hello_version` as first frame. Parse `{v, caps}` (MessagePack), respond with `hello_version_ack` or error+close. Test: `nc` + `xxd` sending raw MessagePack frame → server responds with ack.

**Step 5 — Single event loop:** `fcntl(O_NONBLOCK)`, `el_create/el_add/el_wait`, handle EAGAIN/EWOULDBLOCK, buffer partial frames in per-peer `recv_buf`. epoll on Linux, kqueue on macOS — same interface. Test: 10 parallel `nc` connections sending frames simultaneously.

**Step 6 — Multi-threaded:** `SO_REUSEPORT`, `WorkerArgs{Hub*, port}`, one thread per CPU core (`el_cpu_count()`). `signal(SIGPIPE, SIG_IGN)` + `sodium_init()` at startup. Test: `htop` shows all cores active.

**Step 7 — Hub + channel creation:** implement hub API, handle `create` message (MessagePack-RPC with `id`), join code check via `sodium_memcmp`, channel TTL expiry. Test: CLI sends `create` → server responds with `created` → creator sends `join` with returned id+code → second CLI sends `join` → both see each other.

**Step 8 — Key exchange:** handle `join` → validate join code → verify Ed25519 sig → store `peer->pub_key`, `peer->id_pub`, `peer->name`. Send WELCOME with peers as `[{pub, id_pub, name, caps}, ...]`. Broadcast PEER_JOINED to existing peers. Test: two CLI instances — each sees the other's pub key + identity.

**Step 9 — Relay:** `relay_to_peer()`: lock `ch->mu` → find `Peer*` → lock `write_mu` → check `!= PEER_DISCONNECTED` → `frame_write(transport, ...)` → unlock `write_mu` → unlock `ch->mu`. Test: chat frame arrives only on correct peer.

**Step 10 — CLI client:** TCP connect, `transport_plain()`, version handshake, two threads (recv prints, main reads stdin), E2E encrypt/decrypt. Test: two CLI instances chat decrypted.

**Step 11 — File transfer:** sender: `file_info` + binary chunks with `nonce_prefix||chunk_idx` nonce. Receiver: match chunks by `transfer_id` (from_pub stored from `file_info`), decrypt each chunk, reassemble, `file_ack`. Test: `sha256sum` of received file matches original.

**Step 12 — Identity + logs:** `identity.c` (Argon2id unlock, generate Ed25519+X25519 keypairs, save/load). `log.c` (seal log key to x25519_pub via `crypto_box_seal`, append encrypted records). Subcommand `cli logs <channel_id>`. Test: reconnect, `cli logs` shows prior session; `join` sig verifies on peer.

**Step 13 — Web client:** Go serves `static/`, opens raw TCP to C server, bridges WebSocket frames ↔ TCP frames bidirectionally. `app.js` uses `sodium.crypto_box_keypair`, same MessagePack protocol. Test: CLI peer and browser peer in same channel, messages decrypt on both.

**Step 14 — Noise tunnel:** implement `transport_noise()`: `noise_handshake_client/server()` (32B nonce exchange + BLAKE2b KDF), `noise_wrap/unwrap()` (ChaCha20-Poly1305 + random padding). `--obfs password` selects noise transport. Test: `tcpdump` shows no recognizable structure; wrong password → server drops silently; active probe → no response.

---

## Milestones

| # | Done when |
|---|---|
| 1 | `nc` echo works |
| 2 | length-prefixed frames echo correctly, partial reads handled |
| 3 | transport interface compiles, plain transport passes frames |
| 4 | version handshake completes, wrong version rejected |
| 5 | 10 parallel connections independent; works on Linux + macOS |
| 6 | all cores active under load |
| 7 | `create` message returns channel_id + join_code |
| 8 | two clients see each other's pub keys |
| 9 | chat frame reaches correct peer only |
| 10 | two CLI clients chat E2E, decrypted |
| 11 | file arrives intact (sha256 match) |
| 12 | `cli logs` shows previous session |
| 13 | CLI + browser chat in same channel |
| 14 | `tcpdump` shows random noise; wrong password → silent drop |

---

## Dependencies

| Dep | Used by | Install |
|---|---|---|
| libsodium | server, cli | `apt install libsodium-dev` / `brew install libsodium` |
| libmpack | server, cli | header-only — `mpack.h` vendored in repo |
| Zig 0.14+ | server, cli | ziglang.org/download |
| Go 1.21+ | web | go.dev/dl |
| gorilla/websocket | Go web server | `go get github.com/gorilla/websocket` |
| @msgpack/msgpack | browser JS | CDN or vendor in `web/static/` |
| libsodium.js | browser | github.com/jedisct1/libsodium.js/releases |
| `nc` / `xxd` | testing | builtin on Linux/macOS |

---

## Verification

**Unit tests** (built by Zig, run under ASan + UBSan):
- Frame: encode/decode round-trip, partial buffer returns 0, oversized frame rejected
- Transport: plain transport passes frames; noise transport — KDF identical both sides, bad password fails, replay rejected
- Hub: channel create/get, join code reject, peer limit, expiry, auto-delete on 0 peers
- Relay: concurrent writes to same peer — no interleaved frames; disconnect during relay — no write to closed fd
- E2E: `crypto_box_beforenm(A_priv,B_pub) == crypto_box_beforenm(B_priv,A_pub)`; tampered ct rejected
- File: nonce = `nonce_prefix||chunk_idx`, sha256 match, filename path traversal rejected
- Noise: random padding varies per frame; `tcpdump` shows no fixed byte patterns

**Security smoke tests:**
```bash
# Linux:
strace ./server               # no plaintext in write() syscalls
# macOS:
dtruss ./server               # same

# Memory (add to .flags in build.zig, then rebuild):
# "-fsanitize=address,undefined"                     # ASan + UBSan (Linux + macOS)

nc localhost 8080             # send garbage → server drops silently (noise mode)
# connect beyond max_peers → error frame + close
# bad join_code → error frame + close
```
