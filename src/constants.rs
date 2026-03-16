// Wire protocol version
pub const VERSION: u8 = 1;
pub const PROTO_CLIENT: u8 = 0x00;
pub const SERVER_PORT: u16 = 80;

// Command codes
pub const CMD_GET_NONCE: u8 = 0x01;
pub const CMD_AUTH: u8 = 0x02;
pub const CMD_PING: u8 = 0x03;
pub const CMD_UPLOAD: u8 = 0x10;
pub const CMD_DOWNLOAD: u8 = 0x11;
pub const CMD_FILE_INFO: u8 = 0x12;

// Response status
pub const STATUS_OK: u8 = 0x00;
pub const STATUS_ERR: u8 = 0x01;

// TLV Tags — auth (same as mediator)
pub const TAG_PUBKEY: u8 = 0x01;
pub const TAG_SIGNATURE: u8 = 0x02;
pub const TAG_NONCE: u8 = 0x03;

// TLV Tags — identifiers (reused from mediator)
pub const TAG_MESSAGE_GUID: u8 = 0x12;
pub const TAG_LIMIT: u8 = 0x30;

// TLV Tags — file-specific
pub const TAG_FILE_HASH: u8 = 0x40;
pub const TAG_OFFSET: u8 = 0x41;
pub const TAG_TOTAL_SIZE: u8 = 0x42;
pub const TAG_CHUNK_DATA: u8 = 0x43;

// Limits
pub const MAX_PAYLOAD: u32 = 2 * 1024 * 1024; // 2 MB max frame
pub const MAX_CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 MB max chunk data

// Quotas & retention
pub const DEFAULT_USER_QUOTA: u64 = 3 * 1024 * 1024 * 1024; // 3 GB
pub const DEFAULT_RETENTION_SECS: i64 = 15 * 24 * 3600; // 15 days

// Nonce expiry
pub const NONCE_EXPIRY_SECS: i64 = 300; // 5 minutes

// File names
pub const KEY_FILE: &str = "files-server.key";
pub const DATA_DIR: &str = "data";
pub const TMP_DIR: &str = "data/tmp";
