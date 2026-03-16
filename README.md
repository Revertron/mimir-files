# mimir-files

File hosting server for the [Mimir](https://github.com/Mimir-IM) messaging system.
Runs on the [Yggdrasil](https://yggdrasil-network.github.io/) overlay network and provides chunked file upload/download for Mimir clients.

## Features

- **Yggdrasil networking** — Connects via `ygg_stream`, listens on port 80 over the Yggdrasil mesh.
- **Ed25519 authentication** — Challenge-response auth using the same key scheme as Mimir.
- **Content-addressable storage** — Files stored by SHA-256 hash with automatic deduplication.
- **Chunked transfers** — Upload and download files in chunks (up to 1 MB each) with running hash verification.
- **Per-user quotas** — 3 GB storage quota per user.
- **Automatic expiry** — Files are retained for 15 days, then cleaned up by a background worker.

## Building

```bash
cargo build --release
```

## Usage

```bash
mimir-files --peer <ygg_peer_uri> [--peer <ygg_peer_uri> ...]
```

At least one `--peer` is required to join the Yggdrasil network. The server generates and persists an Ed25519 keypair in `files-server.key` on first run.

### Logging

Logging is controlled via the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug mimir-files --peer tls://...
```

## Wire Protocol

The binary protocol uses a simple framed format:

**Handshake:** `[version:1][proto:1]`

**Request/Response frames:** `[cmd:1][reqId:2][len:4][TLV payload]`

### Commands

| Code | Command | Description |
|------|---------|-------------|
| `0x01` | `GET_NONCE` | Request an auth nonce for a public key |
| `0x02` | `AUTH` | Authenticate with signed nonce |
| `0x03` | `PING` | Keep-alive |
| `0x10` | `UPLOAD` | Upload a file chunk |
| `0x11` | `DOWNLOAD` | Download a file chunk at offset |
| `0x12` | `FILE_INFO` | Query file metadata (size, guid) |

### TLV Tags

| Tag | Name | Description |
|-----|------|-------------|
| `0x01` | `PUBKEY` | Ed25519 public key (32 bytes) |
| `0x02` | `SIGNATURE` | Ed25519 signature (64 bytes) |
| `0x03` | `NONCE` | Auth nonce (32 bytes) |
| `0x12` | `MESSAGE_GUID` | Message GUID (i64) |
| `0x30` | `LIMIT` | Download chunk size limit |
| `0x40` | `FILE_HASH` | SHA-256 file hash (32 bytes) |
| `0x41` | `OFFSET` | Byte offset for chunked transfer |
| `0x42` | `TOTAL_SIZE` | Total file size |
| `0x43` | `CHUNK_DATA` | File chunk payload |

## Storage Layout

Files are stored in a content-addressable structure:

```
data/
  <6-hex-prefix>/
    <64-hex-hash>        # file content
    <64-hex-hash>.meta   # 56-byte sidecar (uploader pubkey + guid + timestamp + size)
  tmp/
    <hash>.tmp           # in-progress uploads
```

The file index is rebuilt from `.meta` files on startup.

## License

MPL-2.0