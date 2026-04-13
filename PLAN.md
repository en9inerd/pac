# Plan: E2E Encrypted Multi-Peer Chat + File Transfer

> **Project name TBD** — three separate repos

## Goals

- Learn WebSocket protocol (RFC 6455) by implementing from scratch in C
- Learn POSIX sockets, epoll/kqueue, pthreads
- Learn protocol design (binary framing, multi-peer key exchange, routing)
- Understand E2E encryption with N peers (pairwise model via libsodium)
- Zig as build system for C projects
- Go web app serving browser client (JS + libsodium.js)

---

## Three Repos

| Repo | Language | Purpose |
|---|---|---|
| `[name]-server` | C + Zig | WebSocket relay server, channel management |
| `[name]-cli` | C + Zig | Line-based CLI client |
| `[name]-web` | Go + JS | Serves HTML/JS frontend to browser |

All three speak the same wire protocol. Server is the only backend.

---

## Architecture

```
              ┌─────────────────────────────┐
              │  C Server (epoll-based)     │
              │  WebSocket relay + hub      │
              │  Sees: encrypted blobs only │
              └──────┬───────────┬──────────┘
                     │           │
   obfs tunnel+WS ◄──┘           └──► plain WS
   (--obfs flag)                      (no obfs)
       ┌──────────────┐    ┌─────────────────────┐
       │ C CLI Client │    │ Browser (JS)        │
       │ libsodium    │    │ libsodium.js (wasm) │
       │ obfs.c (opt) │    │ wss:// real TLS     │
       └──────────────┘    └────────┬────────────┘
                                    │ HTTP
                           ┌────────┴─────────┐
                           │  Go Web Server   │
                           │  serves static/  │
                           │  proxies /api/*  │
                           └──────────────────┘
```

- **Transport:** Raw TCP + manual WebSocket (RFC 6455)
- **I/O model:** epoll (Linux) / kqueue (macOS), non-blocking
- **Encryption:** Pairwise E2E — X25519 ECDH → XSalsa20-Poly1305
- **CLI DPI bypass:** fake TLS 1.3 + ChaCha20-Poly1305 tunnel (`--obfs`)
- **Browser DPI bypass:** `wss://` + CDN (real TLS, no custom code needed)
- **Server storage:** in-memory only, auto-expire on TTL or all-disconnect

---

## WebSocket (from scratch — the learning core)

### Handshake

```
Client → Server:
  GET /ws/channel/{id}?code={join_code} HTTP/1.1
  Host: <host>
  Connection: Upgrade
  Upgrade: websocket
  Sec-WebSocket-Key: <base64(random 16B)>
  Sec-WebSocket-Version: 13

Server → Client:
  HTTP/1.1 101 Switching Protocols
  Upgrade: websocket
  Connection: Upgrade
  Sec-WebSocket-Accept: base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

### Frame Format (RFC 6455 §5)

```
Opcodes: 0x1=text  0x2=binary  0x8=close  0x9=ping  0xA=pong
Payload length: 7-bit (0–125) | 126→next 2B uint16 | 127→next 8B uint64
Masking: client→server MUST mask (XOR 4B key). Server→client MUST NOT mask.
```

Server enforcement:
- `FIN=0` (fragmented) → `close(fd)` — protocol uses single-frame messages only
- `payload_len > MAX_FRAME_SIZE` → `close(fd)` — `#define MAX_FRAME_SIZE PEER_BUF_SIZE`
- Unknown opcode → `close(fd)`
- Unmasked client frame → `close(fd)` (RFC 6455 §5.1)

### Shared WS files (server + CLI)

```
ws.h/c      — ws_parse_frame(), ws_write_frame(), ws_handshake()
              ws_send(fd, opcode, payload, len, flags)  [use MSG_NOSIGNAL]
sha1.h/c    — sha1()
b64.h/c     — b64_encode(), b64_decode()
http.h/c    — http_parse_request(), http_get_header()
```

---

## Obfuscation Layer (`--obfs`, CLI + server only)

Makes traffic look like TLS 1.3 to DPI. Optional, disabled by default.

```
Phase 1: Fake TLS ClientHello  →  fake ServerHello + ChangeCipherSpec
Phase 2: Derive symmetric keys  →  ChaCha20-Poly1305 encrypted tunnel
Phase 3: WS upgrade + all frames run inside tunnel
```

**Phase 1 — ClientHello:** standard TLS 1.3 structure; embed `client_nonce` in `client_random[0:16]`, rest random. Cipher suites: `0x1301,0x1302,0x1303,0x00FF`. Extensions: supported_versions, x25519, SNI. Server embeds `server_nonce` in `server_random[0:16]` of ServerHello, rest random.

**Phase 2 — Key derivation** (BLAKE2b-32 = `crypto_generichash(..., 32, ...)`):
```
shared_secret = BLAKE2b-32(password || client_nonce || server_nonce)
enc_key_c2s   = BLAKE2b-32("c2s" || shared_secret)
enc_key_s2c   = BLAKE2b-32("s2c" || shared_secret)
```
After ServerHello both sides exchange fake `ChangeCipherSpec` (6-byte TLS record: `0x14 0x03 0x03 0x00 0x01 0x01`).

**Phase 3 — Tunnel frame format:**
```
[4B payload_len (BE uint32, plaintext)]
[8B counter     (BE uint64, per-direction monotone)]
[N+16B chacha20poly1305_ietf ciphertext+tag]
```
Nonce = `BE64(counter) || 0x00000000` (12B). `send_counter` starts at 1, incremented after each frame sent. `recv_counter` starts at 0, updated to `incoming_counter` after each accepted frame. Reject if `incoming_counter <= recv_counter`.

```
obfs.h/c  — obfs_client_handshake(), obfs_server_handshake(), obfs_derive_keys()
             obfs_wrap_frame(), obfs_unwrap_frame()
```

---

## E2E Encryption — Pairwise Model

Each peer generates an ephemeral X25519 keypair on connect. Keys live in RAM only.

### Key Exchange

```
A joins  → HELLO{pub:A}  →  server WELCOME{channel_id, peers:[], expires_at}
B joins  → HELLO{pub:B}  →  server WELCOME{channel_id, peers:[A], expires_at}, broadcasts PEER_JOINED{pub:B} to A

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

Text frames: `{"type":"<type>","payload":{...}}`. Binary frames: raw file chunks.

| Type | Direction | `payload` fields |
|---|---|---|
| `hello` | client→server | `{pub: "<64hex>"}` |
| `welcome` | server→client | `{channel_id, peers:["<64hex>",...], expires_at:<unix>}` |
| `peer_joined` | server→all | `{pub: "<64hex>"}` |
| `peer_left` | server→all | `{pub: "<64hex>"}` |
| `chat` | client→server→peer | `{to, from, nonce:"<48hex>", ct:"<hex>"}` |
| `file_info` | client→server→peer | `{to, from, transfer_id:"<16hex>", name, size, chunks, nonce_prefix:"<32hex>"}` |
| `file_chunk` | binary | `[to_pub(32B)][transfer_id(8B)][chunk_idx(8B BE)][ciphertext]` |
| `file_ack` | peer→server→sender | `{to:"<sender 64hex>", transfer_id:"<16hex>", ok:<bool>, error:"<str>"}` |
| `error` | server→client | `{code:<int>, message:"<str>"}` |
| `leave` | client→server | `{}` |

### File transfer

```
chunk_size = 65536  // 64KB plaintext
nonce      = nonce_prefix(16B) || chunk_idx(8B BE)  // 24B total
ct         = crypto_secretbox_easy(chunk, nonce, sharedKey[sender, recipient])
```

- `nonce_prefix`: 16B random, generated per file per recipient, sent in `file_info`
- `transfer_id`: 8B random per transfer — receiver matches chunks by `(from_pub, transfer_id)`
- `file_ack`: sent after all chunks verified. On decrypt failure → `{ok:false, error:"decrypt_failed"}`, sender restarts whole transfer
- Server routes `file_chunk` by `to_pub` (first 32B), routes `file_ack` by `payload.to`

### Error codes

| Code | When |
|---|---|
| 400 | Malformed frame / invalid JSON / unknown type |
| 403 | Bad join code (HTTP upgrade rejected) |
| 404 | Channel not found |
| 409 | Duplicate pub key in channel |
| 429 | Channel full |
| 500 | Internal error |

---

## Server

### I/O Design

One epoll thread per CPU core. Each worker owns its listen socket (`SO_REUSEPORT`) and epoll fd — kernel load-balances connections. Hub is the only shared state.

- `listen_fd` in epoll with `.data.fd`; peers with `.data.ptr` — dispatch: `events[i].data.fd == listen_fd`
- `epoll_wait` timeout = `EXPIRY_CHECK_MS` — one thread per cycle runs `hub_expire` via `pthread_rwlock_trywrlock`
- Relay: `sender->channel` (O(1)) → find `Peer*`, hold `ch->mu` → lock `write_mu` → `ws_send()` → unlock `write_mu` → unlock `ch->mu`
- `pthread_rwlock_t` on hub: wrlock for join/leave/expire/create only; relay never locks hub

### Data Structures

```c
#define MAX_PEERS_PER_CHANNEL  64
#define MAX_CHANNELS           1024
#define MAX_CONNECTIONS        100000
#define PEER_BUF_SIZE          (128 * 1024)
#define MAX_FRAME_SIZE         PEER_BUF_SIZE
#define MAX_EVENTS             64
#define EXPIRY_CHECK_MS        5000

typedef enum {
    PEER_TCP_CONNECTED, PEER_WS_HANDSHAKING, PEER_WS_CONNECTED,
    PEER_HELLO_RECEIVED, PEER_IN_CHANNEL, PEER_DISCONNECTED,
} PeerState;

typedef struct Peer {
    int              fd;
    _Atomic int      state;       // PeerState
    uint8_t          pub_key[32];
    uint8_t         *recv_buf;    // malloc(PEER_BUF_SIZE) on accept
    size_t           recv_len;
    struct Channel  *channel;
    pthread_mutex_t  write_mu;    // held during ws_send() — prevents fd-reuse race + interleave
    ObfsState        obfs;
    time_t           state_since; // for handshake timeout
} Peer;

typedef struct ObfsState {
    uint8_t  enc_key_c2s[32], enc_key_s2c[32];
    uint64_t send_counter;  // starts at 1; increment after each send
    uint64_t recv_counter;  // starts at 0; update to incoming after accept; reject if incoming ≤ this
    bool     active;
} ObfsState;

typedef struct Channel {
    char     id[33];         // 32hex + NUL
    char     join_code[65];  // 64hex + NUL
    Peer    *peers[MAX_PEERS_PER_CHANNEL];
    int      peer_count, max_peers;
    time_t   expires_at;
    pthread_mutex_t mu;
} Channel;

typedef struct Hub {
    Channel         *channels[MAX_CHANNELS];
    int              channel_count;
    pthread_rwlock_t rwlock;
} Hub;
```

### Peer Lifecycle

```
accept():
  malloc(Peer) + malloc(PEER_BUF_SIZE) → pthread_mutex_init(write_mu)
  state = PEER_TCP_CONNECTED; state_since = time(NULL)
  epoll_ctl ADD (data.ptr = peer)

disconnect() — owning worker thread only:
  epoll_ctl DEL
  lock(write_mu) → state = DISCONNECTED → close(fd) → unlock(write_mu)
  lock(ch->mu) → was_empty = hub_remove_peer() → unlock(ch->mu)
  broadcast peer_left
  free(recv_buf) → mutex_destroy(write_mu) → free(peer)
  if was_empty: wrlock(hub) → remove+free channel → unlock(hub)
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

### REST API

- `POST /api/channel` — body: `{ttl, max_peers}`; returns `{channel_id, join_code, expires_at, max_peers}`
  - `ttl` in seconds, clamped to [60, 86400]; `max_peers` clamped to [2, 64]; rate-limited to 10/s
- `GET /health` — `200 OK`
- WS upgrade: `GET /ws/channel/{id}?code={join_code}` — 403/404/429 before handshake

### Startup

```c
signal(SIGPIPE, SIG_IGN);
sodium_init();
```

### Logging

Never log: pub keys, join codes, IP addresses, channel IDs, message sizes, ciphertext.
Safe: server.started, channel.created, peer.joined/left, frame.invalid (opcode), peer.write_failed.
Format: `<iso8601> LEVEL event k=v`. Output to stderr. `--silent` disables.

### File Structure

```
server/
├── build.zig
└── src/
    ├── main.c, event_loop.c/h, hub.c/h, ws.c/h, http.c/h
    ├── sha1.c/h, b64.c/h, protocol.c/h, relay.c/h
    ├── crypto_util.c/h, obfs.c/h, log.c/h
└── test/
    ├── test_ws.c, test_hub.c, test_b64.c, test_obfs.c
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
```
[8B  magic "SHHLOG01"][16B argon2id salt][24B nonce]
[80B crypto_secretbox_easy(pub(32B)+priv(32B), nonce, argon2id(passphrase, salt))]
```
Argon2id: `OPSLIMIT_INTERACTIVE`, `MEMLIMIT_INTERACTIVE`. Unlock once at startup.

**Log file:**
```
[8B magic "SHLOG001"][24B log_key_nonce]
[48B crypto_box_easy(log_key(32B), log_key_nonce, identity_pub, identity_priv)]
[per message: 8B ts | 2B dir | 32B sender_pub | 2B len | 24B nonce | N+16B secretbox(msg, log_key)]
```

**Session:** generate `log_key`, seal to identity key, write header. Append each message encrypted with `log_key`.

**Read:** `[name]-cli logs <channel_id> [--from date] [--to date]`

**Browser:** IndexedDB, same format. Use libsodium.js — NOT WebCrypto (no X25519 in Safari pre-2024).

```
cli/src/  identity.c/h, log.c/h
```

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

```
cli/
├── build.zig
└── src/
    ├── main.c, ws_client.c/h, http_client.c/h, e2e.c/h
    ├── chat_loop.c/h, file_tx.c/h, identity.c/h, log.c/h
    ├── sha1.c/h, b64.c/h, obfs.c/h, protocol.c/h
└── test/test_e2e.c
```

---

## Web Client

```
web/
├── go.mod, main.go       — serve static/, proxy POST /api/* to C server
└── static/
    ├── index.html, app.js, style.css
    └── libsodium.js      — from libsodium.js releases
```

`app.js`: `sodium.crypto_box_keypair()` → WebSocket → HELLO → WELCOME/PEER_JOINED → `crypto_box_beforenm()` → `crypto_secretbox_easy()` per message. Plain HTML/CSS, no framework.

---

## Zig Build

```zig
const exe = b.addExecutable(.{ .name = "server", .target = target, .optimize = optimize });
exe.addCSourceFiles(.{
    .files = &.{ "src/main.c", "src/event_loop.c", "src/hub.c", "src/ws.c",
                 "src/http.c", "src/sha1.c", "src/b64.c", "src/protocol.c",
                 "src/relay.c", "src/crypto_util.c", "src/obfs.c", "src/log.c" },
    .flags = &.{ "-Wall", "-Wextra", "-std=c11", "-D_GNU_SOURCE" },
});
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
| 2 | HTTP parsing | Parse upgrade request, extract Sec-WebSocket-Key |
| 3 | WS handshake | SHA1 + base64, send 101, test with `websocat` |
| 4 | WS frames | Parser + writer: opcodes, 3 length variants, masking |
| 5 | epoll single-threaded | Non-blocking, epoll_wait, partial reads, EAGAIN |
| 6 | Multi-threaded epoll | SO_REUSEPORT, N threads, pthread_rwlock_t on hub |
| 7 | Hub | Channel CRUD, join code, peer registration, TTL expiry |
| 8 | Key exchange | HELLO/WELCOME/PEER_JOINED, crypto_box_keypair, crypto_box_beforenm |
| 9 | Relay | Route CHAT by pub key, write_mu, PEER_DISCONNECTED check |
| 10 | CLI client | Connect, mask frames, recv thread, stdin loop, E2E chat |
| 11 | File transfer | Chunk + encrypt, binary frames, reassemble, file_ack |
| 12 | Identity + logs | Argon2id passphrase, identity keypair, per-session log key |
| 13 | Web client | Go static server, libsodium.js, wss://, IndexedDB logs |
| 14 | Obfuscation | Fake TLS ClientHello, BLAKE2b KDF, ChaCha20 tunnel |

### Step-by-step notes

**Step 1 — TCP echo:** `socket/bind/listen/accept` loop, `recv/send` in blocking mode. Test: `echo "hi" | nc localhost 8000`.

**Step 2 — HTTP parser:** parse method, path, `Sec-WebSocket-Key`, `Sec-WebSocket-Version` (must be 13). Struct: `HttpRequest{method, path, ws_key[64], ws_version, is_upgrade}`. Returns bytes consumed / 0=incomplete / -1=error.

**Step 3 — WS handshake:** implement `sha1()` (test vector: `SHA1("abc")=a9993e36...`), `b64_encode()` (test: `b64_encode("Man")=="TWFu"`), send 101. Test: `websocat ws://localhost:8000/ws/test`.

**Step 4 — Frame parser:** unmask `payload[i] ^= mask[i%4]`, handle all 3 length variants, ping→pong, close→reply+close. Write `test/test_ws.c`: all length variants, partial buffer returns 0.

**Step 5 — Single epoll:** `fcntl(O_NONBLOCK)`, `epoll_create1`, handle EAGAIN/EWOULDBLOCK, buffer partial frames in per-peer `recv_buf`. Test: 10 parallel websocat connections.

**Step 6 — Multi-threaded:** `SO_REUSEPORT`, `WorkerArgs{Hub*, port}`, one thread per CPU core (`event_loop_cpu_count()`). `signal(SIGPIPE, SIG_IGN)` + `sodium_init()` at startup. Test: `htop` shows all cores active.

**Step 7 — Hub:** implement hub API above, `POST /api/channel` handler, join code check via `sodium_memcmp`, channel TTL expiry. Test: `curl -X POST .../api/channel`.

**Step 8 — Key exchange:** parse HELLO, store `peer->pub_key`, send WELCOME + broadcast PEER_JOINED. Test with two websocat clients — each sees the other's pub key.

**Step 9 — Relay:** `relay_to_peer()`: lock `ch->mu` → find `Peer*` → lock `write_mu` → check `!= PEER_DISCONNECTED` → `ws_send(..., MSG_NOSIGNAL)` → unlock `write_mu` → unlock `ch->mu`. Test: chat frame arrives only on correct peer.

**Step 10 — CLI client:** TCP connect, HTTP upgrade with client-side masking, two threads (recv prints, main reads stdin), E2E encrypt/decrypt. Test: two CLI instances chat decrypted.

**Step 11 — File transfer:** sender: `file_info` + binary chunks with `nonce_prefix||chunk_idx` nonce. Receiver: match by `(from_pub, transfer_id)`, decrypt each chunk, reassemble, `file_ack`. Test: `sha256sum` of received file matches original.

**Step 12 — Identity + logs:** `identity.c` (Argon2id unlock, save/load keypair). `log.c` (open with sealed log key, append encrypted records). Subcommand `client logs <channel_id>`. Test: reconnect, `client logs` shows prior session.

**Step 13 — Web client:** Go serves `static/`. `app.js` uses `sodium.crypto_box_keypair`, WebSocket, same protocol as CLI. Test: CLI peer and browser peer in same channel, messages decrypt on both.

**Step 14 — Obfuscation:** `obfs_client_handshake()` / `obfs_server_handshake()` wrap TCP before WS. `--obfs` flag on both. Test: `tcpdump` shows TLS record header `0x16 0x03 0x03`, no `GET /ws/`.

---

## Milestones

| # | Done when |
|---|---|
| 1 | `nc` echo works |
| 2 | HTTP fields parsed correctly |
| 3 | `websocat` connects (101) |
| 4 | `websocat` echo + ping/pong |
| 5 | 10 parallel connections independent |
| 6 | All cores active under load |
| 7 | `curl POST /api/channel` creates channel |
| 8 | Two clients see each other's pub keys |
| 9 | Chat frame reaches correct peer only |
| 10 | Two CLI clients chat E2E, decrypted |
| 11 | File arrives intact (sha256 match) |
| 12 | `client logs` shows previous session |
| 13 | CLI + browser chat in same channel |
| 14 | `tcpdump` shows no WS fingerprint |

---

## Dependencies

| Dep | Used by | Install |
|---|---|---|
| libsodium | server, cli | `apt install libsodium-dev` / `brew install libsodium` |
| Zig 0.14+ | server, cli | ziglang.org/download |
| Go 1.21+ | web | go.dev/dl |
| libsodium.js | browser | github.com/jedisct1/libsodium.js/releases |
| websocat | testing | `cargo install websocat` |

---

## Verification

**Unit tests** (built by Zig, run under valgrind):
- WS: frame encode/decode all 3 length variants, mask/unmask, partial buffer
- SHA1: NIST test vectors. base64: round-trip
- Hub: channel create/get, join code reject, peer limit, expiry, auto-delete on 0 peers
- Relay: concurrent writes to same peer — no interleaved frames; disconnect during relay — no write to closed fd
- E2E: `crypto_box_beforenm(A_priv,B_pub) == crypto_box_beforenm(B_priv,A_pub)`; tampered ct rejected
- File: nonce = `nonce_prefix||chunk_idx`, sha256 match, filename path traversal rejected
- Obfs: KDF produces identical keys both sides; bad password fails; replay (duplicate counter) rejected

**Security smoke tests:**
```bash
strace ./server    # no plaintext in write() syscalls
valgrind ./server  # no leaks in frame parser
# send FIN=0 frame, unmasked frame, unknown opcode → server closes cleanly
# connect beyond max_peers → error frame + close
# bad join_code → HTTP 403 before WS upgrade
```
