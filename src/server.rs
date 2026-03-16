use crate::client::ClientConn;
use crate::constants::*;
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Unique ID for each client connection.
pub type ClientId = u64;

/// Metadata for a stored file (read from .meta sidecar on startup).
pub struct FileMeta {
    pub uploader: [u8; 32],
    pub guid: i64,
    pub uploaded_at: i64,
    pub size: u64,
}

/// In-memory file index, rebuilt from .meta files on startup.
pub struct FileIndex {
    /// hash_hex -> metadata
    pub files: HashMap<String, FileMeta>,
    /// pubkey -> total bytes of active (non-expired) files
    pub user_usage: HashMap<[u8; 32], u64>,
}

impl FileIndex {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            user_usage: HashMap::new(),
        }
    }

    /// Add a file to the index, updating user usage.
    pub fn insert(&mut self, hash_hex: String, meta: FileMeta) {
        let size = meta.size;
        let uploader = meta.uploader;
        self.files.insert(hash_hex, meta);
        *self.user_usage.entry(uploader).or_insert(0) += size;
    }

    /// Remove a file from the index, updating user usage.
    pub fn remove(&mut self, hash_hex: &str) -> Option<FileMeta> {
        if let Some(meta) = self.files.remove(hash_hex) {
            if let Some(usage) = self.user_usage.get_mut(&meta.uploader) {
                *usage = usage.saturating_sub(meta.size);
                if *usage == 0 {
                    self.user_usage.remove(&meta.uploader);
                }
            }
            Some(meta)
        } else {
            None
        }
    }

    /// Get total bytes used by a given user.
    pub fn usage_for(&self, pubkey: &[u8; 32]) -> u64 {
        self.user_usage.get(pubkey).copied().unwrap_or(0)
    }
}

/// Tracks an in-progress chunked upload.
pub struct UploadProgress {
    pub total_size: u64,
    pub received: u64,
    pub guid: i64,
    pub temp_path: PathBuf,
    pub hasher: Sha256,
    pub last_activity: i64,
}

pub struct ServerState {
    #[allow(dead_code)]
    pub server_pub: [u8; 32],
    #[allow(dead_code)]
    pub server_priv: ed25519_dalek::SigningKey,

    /// Auth nonces in RAM: pubkey -> (nonce, timestamp)
    pub nonces: RwLock<HashMap<[u8; 32], ([u8; 32], i64)>>,

    /// Active uploads: "<hash_hex>:<client_id>" -> progress
    pub uploads: RwLock<HashMap<String, UploadProgress>>,

    /// Active client connections
    pub clients: RwLock<HashMap<ClientId, Arc<ClientConn>>>,

    /// In-memory file index
    pub file_index: RwLock<FileIndex>,

    next_client_id: std::sync::atomic::AtomicU64,
}

impl ServerState {
    pub fn new(
        server_pub: [u8; 32],
        server_priv: ed25519_dalek::SigningKey,
        file_index: FileIndex,
    ) -> Arc<Self> {
        Arc::new(Self {
            server_pub,
            server_priv,
            nonces: RwLock::new(HashMap::new()),
            uploads: RwLock::new(HashMap::new()),
            clients: RwLock::new(HashMap::new()),
            file_index: RwLock::new(file_index),
            next_client_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    pub fn next_id(&self) -> ClientId {
        self.next_client_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Compute the storage path for a file given its hex hash.
pub fn file_path_for_hash(hash_hex: &str) -> PathBuf {
    let prefix = &hash_hex[..6];
    PathBuf::from(DATA_DIR).join(prefix).join(hash_hex)
}

/// Compute the .meta sidecar path for a file given its hex hash.
pub fn meta_path_for_hash(hash_hex: &str) -> PathBuf {
    let prefix = &hash_hex[..6];
    PathBuf::from(DATA_DIR).join(prefix).join(format!("{}.meta", hash_hex))
}

/// Write a 56-byte .meta sidecar file.
pub fn write_meta_file(path: &PathBuf, uploader: &[u8; 32], guid: i64, uploaded_at: i64, size: u64) -> std::io::Result<()> {
    let mut buf = [0u8; 56];
    buf[..32].copy_from_slice(uploader);
    buf[32..40].copy_from_slice(&guid.to_be_bytes());
    buf[40..48].copy_from_slice(&uploaded_at.to_be_bytes());
    buf[48..56].copy_from_slice(&size.to_be_bytes());
    std::fs::write(path, &buf)
}

/// Read a 56-byte .meta sidecar file.
pub fn read_meta_file(path: &PathBuf) -> std::io::Result<FileMeta> {
    let buf = std::fs::read(path)?;
    if buf.len() != 56 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "meta file must be 56 bytes"));
    }
    let mut uploader = [0u8; 32];
    uploader.copy_from_slice(&buf[..32]);
    let guid = i64::from_be_bytes(buf[32..40].try_into().unwrap());
    let uploaded_at = i64::from_be_bytes(buf[40..48].try_into().unwrap());
    let size = u64::from_be_bytes(buf[48..56].try_into().unwrap());
    Ok(FileMeta { uploader, guid, uploaded_at, size })
}

/// Scan the data directory and rebuild the in-memory FileIndex.
pub fn scan_data_dir() -> FileIndex {
    let mut index = FileIndex::new();
    let now = now_unix();

    let data_path = PathBuf::from(DATA_DIR);
    let entries = match std::fs::read_dir(&data_path) {
        Ok(e) => e,
        Err(_) => return index,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        // Each subdirectory is a 6-char hex prefix
        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) if n.len() == 6 => n.to_string(),
            _ => continue,
        };
        let _ = dir_name; // just validating

        let sub_entries = match std::fs::read_dir(&path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for sub_entry in sub_entries.flatten() {
            let file_path = sub_entry.path();
            let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            // Look for .meta files
            if !file_name.ends_with(".meta") {
                continue;
            }

            let hash_hex = file_name.trim_end_matches(".meta").to_string();
            if hash_hex.len() != 64 {
                continue;
            }

            match read_meta_file(&file_path) {
                Ok(meta) => {
                    // Skip expired files (will be cleaned up by background task)
                    if now - meta.uploaded_at > DEFAULT_RETENTION_SECS {
                        continue;
                    }
                    info!("indexed file: {} ({} bytes, user {})", &hash_hex[..8], meta.size, hex::encode(&meta.uploader[..4]));
                    index.insert(hash_hex, meta);
                }
                Err(e) => {
                    warn!("failed to read meta file {}: {}", file_path.display(), e);
                }
            }
        }
    }

    info!("file index rebuilt: {} files, {} users", index.files.len(), index.user_usage.len());
    index
}

/// Run the accept loop using ygg_stream AsyncNode.
pub async fn run_accept_loop(state: Arc<ServerState>, node: Arc<ygg_stream::AsyncNode>, port: u16) {
    info!("listening for client connections on port {}", port);

    loop {
        let conn = match node.accept(port).await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("accept error: {}", e);
                continue;
            }
        };

        let client_id = state.next_id();
        let remote_pub = conn.public_key();
        info!("new client connection {} from {}", client_id, hex::encode(&remote_pub));

        let state2 = state.clone();
        tokio::spawn(async move {
            crate::client::serve_client(state2, conn, client_id).await;
        });
    }
}
