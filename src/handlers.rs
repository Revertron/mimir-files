use crate::client::ClientConn;
use crate::constants::*;
use crate::server::*;
use crate::tlv::*;
use ed25519_dalek::Verifier;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Dispatch a command to the appropriate handler.
pub async fn dispatch(state: &Arc<ServerState>, cc: &Arc<ClientConn>, cmd: u8, req_id: u16, payload: &[u8]) {
    match cmd {
        CMD_GET_NONCE => handle_get_nonce(state, cc, req_id, payload).await,
        CMD_AUTH => handle_auth(state, cc, req_id, payload).await,
        CMD_PING => handle_ping(cc, req_id).await,
        CMD_UPLOAD => handle_upload(state, cc, req_id, payload).await,
        CMD_DOWNLOAD => handle_download(state, cc, req_id, payload).await,
        CMD_FILE_INFO => handle_file_info(state, cc, req_id, payload).await,
        _ => {
            let _ = cc.write_err(req_id, "unknown cmd").await;
        }
    }
}

// ---- Auth handlers ----

fn rand32() -> [u8; 32] {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

async fn handle_get_nonce(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let pk_bytes = match tlv_get_bytes(&tlvs, TAG_PUBKEY, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid pubkey").await; return; }
    };

    let mut pk = [0u8; 32];
    pk.copy_from_slice(pk_bytes);

    let nonce = rand32();
    let now = now_unix();

    {
        let mut nonces = state.nonces.write().await;
        nonces.insert(pk, (nonce, now));
    }

    let resp = match build_tlv_payload(|w| tlv_encode_bytes(w, TAG_NONCE, &nonce)) {
        Ok(r) => r,
        Err(_) => { let _ = cc.write_err(req_id, "tlv encode error").await; return; }
    };
    let _ = cc.write_ok(req_id, &resp).await;
}

async fn handle_auth(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let rawpk = match tlv_get_bytes(&tlvs, TAG_PUBKEY, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid pubkey").await; return; }
    };
    let nonce_bytes = match tlv_get_bytes(&tlvs, TAG_NONCE, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid nonce").await; return; }
    };
    let sig = match tlv_get_bytes(&tlvs, TAG_SIGNATURE, 64) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid signature").await; return; }
    };

    let mut pk = [0u8; 32];
    pk.copy_from_slice(rawpk);

    // Check nonce
    let stored_nonce = {
        let nonces = state.nonces.read().await;
        nonces.get(&pk).map(|(n, _)| *n)
    };

    let stored_nonce = match stored_nonce {
        Some(n) => n,
        None => { let _ = cc.write_err(req_id, "unknown nonce").await; return; }
    };

    if stored_nonce != nonce_bytes {
        let _ = cc.write_err(req_id, "nonce mismatch").await;
        return;
    }

    // Verify Ed25519 signature
    let verify_key = match ed25519_dalek::VerifyingKey::from_bytes(&pk) {
        Ok(k) => k,
        Err(_) => { let _ = cc.write_err(req_id, "invalid pubkey").await; return; }
    };
    let signature = match ed25519_dalek::Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => { let _ = cc.write_err(req_id, "invalid signature").await; return; }
    };
    if verify_key.verify(nonce_bytes, &signature).is_err() {
        let _ = cc.write_err(req_id, "invalid signature").await;
        return;
    }

    // Delete used nonce
    {
        let mut nonces = state.nonces.write().await;
        nonces.remove(&pk);
    }

    info!("User {} authenticated", hex::encode(&pk[..8]));

    {
        *cc.authed.write().await = true;
        *cc.pub_key.write().await = pk;
    }

    let _ = cc.write_ok(req_id, &[]).await;
}

async fn handle_ping(cc: &Arc<ClientConn>, req_id: u16) {
    let _ = cc.write_ok(req_id, &[]).await;
}

// ---- File handlers ----

async fn handle_upload(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "not authenticated").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let hash_bytes = match tlv_get_bytes(&tlvs, TAG_FILE_HASH, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid file hash").await; return; }
    };
    let guid = match tlv_get_i64(&tlvs, TAG_MESSAGE_GUID) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid message guid").await; return; }
    };
    let offset = match tlv_get_u64(&tlvs, TAG_OFFSET) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid offset").await; return; }
    };
    let total_size = match tlv_get_u64(&tlvs, TAG_TOTAL_SIZE) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid total size").await; return; }
    };
    let chunk_data = match tlv_get_bytes(&tlvs, TAG_CHUNK_DATA, 0) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing chunk data").await; return; }
    };

    if chunk_data.len() > MAX_CHUNK_SIZE {
        let _ = cc.write_err(req_id, "chunk too large").await;
        return;
    }

    let hash_hex = hex::encode(hash_bytes);
    let upload_key = format!("{}:{}", hash_hex, cc.id);

    // Check if file already exists
    {
        let index = state.file_index.read().await;
        if index.files.contains_key(&hash_hex) {
            // File already stored, just acknowledge
            let _ = cc.write_ok(req_id, &[]).await;
            return;
        }
    }

    let pub_key = *cc.pub_key.read().await;

    if offset == 0 {
        info!("Starting upload of file with hash {}, {} bytes", &hash_hex[..8], total_size);
        // Starting a new upload -- check quota
        {
            let index = state.file_index.read().await;
            let current_usage = index.usage_for(&pub_key);
            if current_usage + total_size >= DEFAULT_USER_QUOTA {
                let _ = cc.write_err(req_id, "quota exceeded").await;
                return;
            }
        }

        let temp_path = std::path::PathBuf::from(TMP_DIR).join(format!("{}.tmp", hash_hex));

        // Create temp file
        if let Err(e) = tokio::fs::write(&temp_path, &[]).await {
            let _ = cc.write_err(req_id, &format!("failed to create temp file: {}", e)).await;
            return;
        }

        let mut hasher = Sha256::new();
        hasher.update(chunk_data);

        // Write first chunk
        if let Err(e) = tokio::fs::write(&temp_path, chunk_data).await {
            let _ = cc.write_err(req_id, &format!("write error: {}", e)).await;
            return;
        }

        let received = chunk_data.len() as u64;

        if received == total_size {
            // Single-chunk upload: finalize immediately
            if let Err(msg) = finalize_upload(state, &hash_hex, &pub_key, guid, hasher, hash_bytes, &temp_path, total_size).await {
                let _ = cc.write_err(req_id, &msg).await;
                return;
            }
        } else {
            let mut uploads = state.uploads.write().await;
            uploads.insert(upload_key, UploadProgress {
                total_size,
                received,
                guid,
                temp_path,
                hasher,
                last_activity: now_unix(),
            });
        }

        let _ = cc.write_ok(req_id, &[]).await;
    } else {
        // Continuing an existing upload
        let mut uploads = state.uploads.write().await;
        let progress = match uploads.get_mut(&upload_key) {
            Some(p) => p,
            None => { let _ = cc.write_err(req_id, "no active upload for this file").await; return; }
        };

        if offset != progress.received {
            let _ = cc.write_err(req_id, &format!("expected offset {}, got {}", progress.received, offset)).await;
            return;
        }

        // Append chunk to temp file
        use tokio::io::AsyncWriteExt;
        let mut file = match tokio::fs::OpenOptions::new().append(true).open(&progress.temp_path).await {
            Ok(f) => f,
            Err(e) => { let _ = cc.write_err(req_id, &format!("failed to open temp file: {}", e)).await; return; }
        };
        if let Err(e) = file.write_all(chunk_data).await {
            let _ = cc.write_err(req_id, &format!("write error: {}", e)).await;
            return;
        }

        progress.hasher.update(chunk_data);
        progress.received += chunk_data.len() as u64;
        progress.last_activity = now_unix();

        if progress.received == progress.total_size {
            // Upload complete: finalize
            // Take ownership of progress data before dropping the lock
            let temp_path = progress.temp_path.clone();
            let hasher = std::mem::replace(&mut progress.hasher, Sha256::new());
            let guid = progress.guid;
            let total_size = progress.total_size;
            uploads.remove(&upload_key);
            drop(uploads);

            if let Err(msg) = finalize_upload(state, &hash_hex, &pub_key, guid, hasher, hash_bytes, &temp_path, total_size).await {
                let _ = cc.write_err(req_id, &msg).await;
                return;
            }
        }

        let _ = cc.write_ok(req_id, &[]).await;
    }
}

/// Finalize a completed upload: verify hash, move to final location, update index.
async fn finalize_upload(
    state: &Arc<ServerState>,
    hash_hex: &str,
    uploader: &[u8; 32],
    guid: i64,
    hasher: Sha256,
    expected_hash: &[u8],
    temp_path: &std::path::Path,
    size: u64,
) -> Result<(), String> {
    // Verify SHA-256
    let computed = hasher.finalize();
    if computed.as_slice() != expected_hash {
        let _ = tokio::fs::remove_file(temp_path).await;
        return Err(format!("hash mismatch: expected {}, got {}", hash_hex, hex::encode(computed)));
    }

    // Create prefix directory
    let final_path = file_path_for_hash(hash_hex);
    if let Some(parent) = final_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| format!("mkdir error: {}", e))?;
    }

    // Move temp file to final location
    tokio::fs::rename(temp_path, &final_path).await.map_err(|e| format!("rename error: {}", e))?;

    // Write .meta sidecar
    let now = now_unix();
    let meta_path = meta_path_for_hash(hash_hex);
    write_meta_file(&meta_path, uploader, guid, now, size)
        .map_err(|e| format!("meta write error: {}", e))?;

    // Update in-memory index
    {
        let mut index = state.file_index.write().await;
        index.insert(hash_hex.to_string(), FileMeta {
            uploader: *uploader,
            guid,
            uploaded_at: now,
            size,
        });
    }

    info!("File {} uploaded successfully ({} bytes)", &hash_hex[..8], size);
    Ok(())
}

/// Streaming chunk size for download responses (16 KB — matches ygg_stream's
/// SEND_CHUNK_SIZE so each chunk maps to one stream segment without splitting).
const DOWNLOAD_CHUNK_SIZE: usize = 256 * 1024;

async fn handle_download(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "not authenticated").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let hash_bytes = match tlv_get_bytes(&tlvs, TAG_FILE_HASH, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid file hash").await; return; }
    };
    let start_offset = match tlv_get_u64(&tlvs, TAG_OFFSET) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid offset").await; return; }
    };
    let limit = match tlv_get_u32(&tlvs, TAG_LIMIT) {
        Ok(v) => v as u64,
        Err(_) => u64::MAX,
    };

    let hash_hex = hex::encode(hash_bytes);
    let file_path = file_path_for_hash(&hash_hex);

    // Get total size from index
    let total_size = {
        let index = state.file_index.read().await;
        match index.files.get(&hash_hex) {
            Some(meta) => meta.size,
            None => { let _ = cc.write_err(req_id, "file not found").await; return; }
        }
    };

    if start_offset >= total_size {
        let _ = cc.write_err(req_id, "offset beyond file end").await;
        return;
    }

    info!("Starting to push file {:?} of {} bytes", &file_path, total_size);

    // Cap end to limit
    let end = total_size.min(start_offset.saturating_add(limit));

    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut file = match tokio::fs::File::open(&file_path).await {
        Ok(f) => f,
        Err(_) => { let _ = cc.write_err(req_id, "file not found on disk").await; return; }
    };

    if let Err(e) = file.seek(std::io::SeekFrom::Start(start_offset)).await {
        let _ = cc.write_err(req_id, &format!("seek error: {}", e)).await;
        return;
    }

    // Stream chunks: one OK response frame per chunk, all with the same req_id.
    // Client reads frames in a loop until offset + chunk_len >= total_size.
    let mut offset = start_offset;
    while offset < end {
        let read_size = DOWNLOAD_CHUNK_SIZE.min((end - offset) as usize);
        let mut chunk = vec![0u8; read_size];
        match file.read_exact(&mut chunk).await {
            Ok(_) => {}
            Err(e) => { let _ = cc.write_err(req_id, &format!("read error: {}", e)).await; return; }
        }

        let resp = match build_tlv_payload(|w| {
            tlv_encode_bytes(w, TAG_CHUNK_DATA, &chunk)?;
            tlv_encode_u64(w, TAG_TOTAL_SIZE, total_size)?;
            tlv_encode_u64(w, TAG_OFFSET, offset)
        }) {
            Ok(r) => r,
            Err(_) => { let _ = cc.write_err(req_id, "tlv encode error").await; return; }
        };
        if cc.write_ok(req_id, &resp).await.is_err() {
            return; // client disconnected
        }
        info!("Pushed chunk from {offset} of file {:?} total {} bytes", &file_path, total_size);

        offset += read_size as u64;
    }

    info!("Finished pushing file {:?} of {} bytes", &file_path, total_size);
}

async fn handle_file_info(state: &Arc<ServerState>, cc: &Arc<ClientConn>, req_id: u16, p: &[u8]) {
    if !cc.is_authed().await {
        let _ = cc.write_err(req_id, "not authenticated").await;
        return;
    }

    let tlvs = match parse_tlvs(p) {
        Ok(t) => t,
        Err(_) => { let _ = cc.write_err(req_id, "bad tlv payload").await; return; }
    };

    let hash_bytes = match tlv_get_bytes(&tlvs, TAG_FILE_HASH, 32) {
        Ok(v) => v,
        Err(_) => { let _ = cc.write_err(req_id, "missing or invalid file hash").await; return; }
    };

    let hash_hex = hex::encode(hash_bytes);

    let index = state.file_index.read().await;
    match index.files.get(&hash_hex) {
        Some(meta) => {
            let resp = match build_tlv_payload(|w| {
                tlv_encode_u64(w, TAG_TOTAL_SIZE, meta.size)?;
                tlv_encode_i64(w, TAG_MESSAGE_GUID, meta.guid)
            }) {
                Ok(r) => r,
                Err(_) => { let _ = cc.write_err(req_id, "tlv encode error").await; return; }
            };
            let _ = cc.write_ok(req_id, &resp).await;
        }
        None => {
            let _ = cc.write_err(req_id, "file not found").await;
        }
    }
}

/// Background task: clean up expired nonces every 5 minutes.
pub async fn nonce_cleanup_worker(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
    loop {
        interval.tick().await;
        let now = now_unix();
        let mut nonces = state.nonces.write().await;
        let before = nonces.len();
        nonces.retain(|_, (_, ts)| now - *ts < NONCE_EXPIRY_SECS);
        let removed = before - nonces.len();
        if removed > 0 {
            debug!("nonce cleanup: removed {} expired nonces", removed);
        }
    }
}

/// Background task: clean up stale uploads every 30 minutes.
pub async fn stale_upload_cleanup_worker(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
    loop {
        interval.tick().await;
        let now = now_unix();
        let mut uploads = state.uploads.write().await;
        let keys_to_remove: Vec<String> = uploads.iter()
            .filter(|(_, p)| now - p.last_activity > 3600) // 1 hour stale threshold
            .map(|(k, _)| k.clone())
            .collect();
        for key in &keys_to_remove {
            if let Some(progress) = uploads.remove(key) {
                let _ = tokio::fs::remove_file(&progress.temp_path).await;
                debug!("removed stale upload: {}", key);
            }
        }
    }
}

/// Background task: clean up expired files every hour.
pub async fn file_expiry_worker(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        interval.tick().await;
        let now = now_unix();

        let expired_hashes: Vec<String> = {
            let index = state.file_index.read().await;
            index.files.iter()
                .filter(|(_, meta)| now - meta.uploaded_at > DEFAULT_RETENTION_SECS)
                .map(|(hash, _)| hash.clone())
                .collect()
        };

        if expired_hashes.is_empty() {
            continue;
        }

        let mut index = state.file_index.write().await;
        for hash_hex in &expired_hashes {
            index.remove(hash_hex);

            let file_path = file_path_for_hash(hash_hex);
            let meta_path = meta_path_for_hash(hash_hex);
            let _ = tokio::fs::remove_file(&file_path).await;
            let _ = tokio::fs::remove_file(&meta_path).await;

            debug!("expired file removed: {}", &hash_hex[..8]);
        }

        // Try to remove empty prefix directories
        for hash_hex in &expired_hashes {
            let prefix = &hash_hex[..6];
            let dir = std::path::PathBuf::from(DATA_DIR).join(prefix);
            let _ = tokio::fs::remove_dir(&dir).await; // only succeeds if empty
        }

        warn!("file expiry: removed {} expired files", expired_hashes.len());
    }
}
