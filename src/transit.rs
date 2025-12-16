use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::crypto::{
    KEY_SIZE, NONCE_SIZE, derive_record_key_receiver, derive_record_key_sender,
    derive_relay_handshake, derive_transit_receiver_handshake, derive_transit_sender_handshake,
};
use crate::messages::{TransferAck, Transit, TransitHint};

const RECORD_SIZE: usize = 65536 - 16; // 64KB
const TCP_BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer
const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Compression {
    #[default]
    /// Classic zip/deflate (compatible with all clients)
    Zip,
    /// Fast tar+zstd (wormhole-rs only)
    Zstd,
}

impl Compression {
    pub fn mode_string(&self) -> &'static str {
        match self {
            Compression::Zip => "zipfile/deflated",
            Compression::Zstd => "tarball/zstd",
        }
    }

    pub fn from_mode(mode: &str) -> Self {
        match mode {
            "tarball/zstd" => Compression::Zstd,
            _ => Compression::Zip,
        }
    }
}

fn create_progress_bar(total_size: u64, hide_progress: bool) -> ProgressBar {
    if hide_progress {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
                .expect("valid template")
                .progress_chars("#>-"),
        );
        pb
    }
}

pub struct TransitConnection {
    reader: Mutex<BufReader<tokio::io::ReadHalf<TcpStream>>>,
    writer: Mutex<BufWriter<tokio::io::WriteHalf<TcpStream>>>,
    send_cipher: XSalsa20Poly1305,
    recv_cipher: XSalsa20Poly1305,
    send_nonce: AtomicU64,
    recv_nonce: AtomicU64,
}

impl TransitConnection {
    fn new(stream: TcpStream, transit_key: &[u8; KEY_SIZE], is_sender: bool) -> Self {
        let (send_key, recv_key) = if is_sender {
            (
                derive_record_key_sender(transit_key),
                derive_record_key_receiver(transit_key),
            )
        } else {
            (
                derive_record_key_receiver(transit_key),
                derive_record_key_sender(transit_key),
            )
        };

        let send_cipher = XSalsa20Poly1305::new(Key::from_slice(&send_key));
        let recv_cipher = XSalsa20Poly1305::new(Key::from_slice(&recv_key));

        let (read_half, write_half) = tokio::io::split(stream);

        Self {
            reader: Mutex::new(BufReader::with_capacity(TCP_BUFFER_SIZE, read_half)),
            writer: Mutex::new(BufWriter::with_capacity(TCP_BUFFER_SIZE, write_half)),
            send_cipher,
            recv_cipher,
            send_nonce: AtomicU64::new(0),
            recv_nonce: AtomicU64::new(0),
        }
    }

    pub async fn write_record(&self, plaintext: &[u8]) -> Result<()> {
        let nonce_val = self.send_nonce.fetch_add(1, Ordering::Relaxed);
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[NONCE_SIZE - 8..].copy_from_slice(&nonce_val.to_be_bytes());

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .send_cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let total_len = (NONCE_SIZE + ciphertext.len()) as u32;

        let mut writer = self.writer.lock().await;
        writer.write_all(&total_len.to_be_bytes()).await?;
        writer.write_all(&nonce_bytes).await?;
        writer.write_all(&ciphertext).await?;

        Ok(())
    }

    pub async fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.flush().await?;
        Ok(())
    }

    pub async fn read_record(&self) -> Result<Vec<u8>> {
        let mut reader = self.reader.lock().await;

        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;

        if total_len < NONCE_SIZE {
            anyhow::bail!("Invalid record length");
        }

        let mut data = vec![0u8; total_len];
        reader.read_exact(&mut data).await?;
        drop(reader);

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .recv_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        self.recv_nonce.fetch_add(1, Ordering::Relaxed);

        Ok(plaintext)
    }
}

pub async fn get_direct_hints() -> Vec<TransitHint> {
    Vec::new()
}

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    Ok(())
}

pub async fn connect_as_sender(
    transit_key: &[u8; KEY_SIZE],
    peer_hints: &Transit,
    relay_addr: &str,
) -> Result<Arc<TransitConnection>> {
    for hint in &peer_hints.hints_v1 {
        if hint.hint_type == "direct-tcp-v1"
            && let (Some(host), Some(port)) = (&hint.hostname, hint.port)
        {
            let addr = format!("{}:{}", host, port);
            if let Ok(conn) = try_connect_direct_sender(transit_key, &addr).await {
                return Ok(Arc::new(conn));
            }
        }
    }

    let conn = connect_via_relay_sender(transit_key, relay_addr).await?;
    Ok(Arc::new(conn))
}

pub async fn connect_as_receiver(
    transit_key: &[u8; KEY_SIZE],
    peer_hints: &Transit,
    relay_addr: &str,
) -> Result<Arc<TransitConnection>> {
    for hint in &peer_hints.hints_v1 {
        if hint.hint_type == "direct-tcp-v1"
            && let (Some(host), Some(port)) = (&hint.hostname, hint.port)
        {
            let addr = format!("{}:{}", host, port);
            if let Ok(conn) = try_connect_direct_receiver(transit_key, &addr).await {
                return Ok(Arc::new(conn));
            }
        }
    }

    let conn = connect_via_relay_receiver(transit_key, relay_addr).await?;
    Ok(Arc::new(conn))
}

async fn try_connect_direct_sender(
    transit_key: &[u8; KEY_SIZE],
    addr: &str,
) -> Result<TransitConnection> {
    let mut stream = TcpStream::connect(addr).await?;
    configure_stream(&stream)?;

    let handshake = derive_transit_sender_handshake(transit_key);
    stream.write_all(&handshake).await?;

    let expected = derive_transit_receiver_handshake(transit_key);
    let mut response = vec![0u8; expected.len()];
    stream.read_exact(&mut response).await?;

    if response != expected {
        anyhow::bail!("Invalid receiver handshake");
    }

    stream.write_all(b"go\n").await?;

    Ok(TransitConnection::new(stream, transit_key, true))
}

async fn try_connect_direct_receiver(
    transit_key: &[u8; KEY_SIZE],
    addr: &str,
) -> Result<TransitConnection> {
    let mut stream = TcpStream::connect(addr).await?;
    configure_stream(&stream)?;

    let expected = derive_transit_sender_handshake(transit_key);
    let mut response = vec![0u8; expected.len()];
    stream.read_exact(&mut response).await?;

    if response != expected {
        anyhow::bail!("Invalid sender handshake");
    }

    let handshake = derive_transit_receiver_handshake(transit_key);
    stream.write_all(&handshake).await?;

    let mut go_buf = [0u8; 3];
    stream.read_exact(&mut go_buf).await?;

    if &go_buf != b"go\n" {
        anyhow::bail!("Did not receive 'go' from sender");
    }

    Ok(TransitConnection::new(stream, transit_key, false))
}

async fn connect_via_relay_sender(
    transit_key: &[u8; KEY_SIZE],
    relay_addr: &str,
) -> Result<TransitConnection> {
    let mut stream = TcpStream::connect(relay_addr).await?;
    configure_stream(&stream)?;

    let handshake = derive_relay_handshake(transit_key);
    stream.write_all(&handshake).await?;

    let mut ok_buf = [0u8; 3];
    stream.read_exact(&mut ok_buf).await?;

    if &ok_buf != b"ok\n" {
        anyhow::bail!("Relay did not accept connection");
    }

    let sender_handshake = derive_transit_sender_handshake(transit_key);
    stream.write_all(&sender_handshake).await?;

    let expected = derive_transit_receiver_handshake(transit_key);
    let mut response = vec![0u8; expected.len()];
    stream.read_exact(&mut response).await?;

    if response != expected {
        anyhow::bail!("Invalid receiver handshake via relay");
    }

    stream.write_all(b"go\n").await?;

    Ok(TransitConnection::new(stream, transit_key, true))
}

async fn connect_via_relay_receiver(
    transit_key: &[u8; KEY_SIZE],
    relay_addr: &str,
) -> Result<TransitConnection> {
    let mut stream = TcpStream::connect(relay_addr).await?;
    configure_stream(&stream)?;

    let handshake = derive_relay_handshake(transit_key);
    stream.write_all(&handshake).await?;

    let mut ok_buf = [0u8; 3];
    stream.read_exact(&mut ok_buf).await?;

    if &ok_buf != b"ok\n" {
        anyhow::bail!("Relay did not accept connection");
    }

    let expected = derive_transit_sender_handshake(transit_key);
    let mut response = vec![0u8; expected.len()];
    stream.read_exact(&mut response).await?;

    if response != expected {
        anyhow::bail!("Invalid sender handshake via relay");
    }

    let receiver_handshake = derive_transit_receiver_handshake(transit_key);
    stream.write_all(&receiver_handshake).await?;

    let mut go_buf = [0u8; 3];
    stream.read_exact(&mut go_buf).await?;

    if &go_buf != b"go\n" {
        anyhow::bail!("Did not receive 'go' from sender via relay");
    }

    Ok(TransitConnection::new(stream, transit_key, false))
}

pub async fn send_file<R: AsyncRead + Unpin>(
    conn: &Arc<TransitConnection>,
    reader: &mut R,
    total_size: u64,
    hide_progress: bool,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; RECORD_SIZE];
    let mut sent = 0u64;

    let progress = create_progress_bar(total_size, hide_progress);

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        hasher.update(&buf[..n]);
        conn.write_record(&buf[..n]).await?;
        sent += n as u64;
        progress.set_position(sent);
    }

    // Single flush at the end
    conn.flush().await?;
    progress.finish_and_clear();

    let ack_data = conn.read_record().await?;
    let ack: TransferAck = serde_json::from_slice(&ack_data)?;

    if ack.ack != "ok" {
        anyhow::bail!("Transfer not acknowledged");
    }

    let hash = hex::encode(hasher.finalize());
    if ack.sha256.to_lowercase() != hash {
        anyhow::bail!("SHA256 mismatch: expected {}, got {}", hash, ack.sha256);
    }

    Ok(())
}

pub async fn receive_file<W: AsyncWrite + Unpin>(
    conn: &Arc<TransitConnection>,
    writer: &mut W,
    total_size: u64,
    hide_progress: bool,
) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut received = 0u64;

    let progress = create_progress_bar(total_size, hide_progress);

    while received < total_size {
        let data = conn.read_record().await?;
        hasher.update(&data);
        writer.write_all(&data).await?;
        received += data.len() as u64;
        progress.set_position(received);
    }

    progress.finish_and_clear();
    writer.flush().await?;

    let hash = hex::encode(hasher.finalize());
    let ack = TransferAck {
        ack: "ok".to_string(),
        sha256: hash,
    };
    let ack_data = serde_json::to_vec(&ack)?;
    conn.write_record(&ack_data).await?;
    conn.flush().await?;

    Ok(())
}

pub async fn receive_to_vec(
    conn: &Arc<TransitConnection>,
    total_size: u64,
    hide_progress: bool,
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(total_size as usize);
    let mut hasher = Sha256::new();
    let mut received = 0u64;

    let progress = create_progress_bar(total_size, hide_progress);

    while received < total_size {
        let chunk = conn.read_record().await?;
        hasher.update(&chunk);
        data.extend_from_slice(&chunk);
        received += chunk.len() as u64;
        progress.set_position(received);
    }

    progress.finish_and_clear();

    let hash = hex::encode(hasher.finalize());
    let ack = TransferAck {
        ack: "ok".to_string(),
        sha256: hash,
    };
    let ack_data = serde_json::to_vec(&ack)?;
    conn.write_record(&ack_data).await?;
    conn.flush().await?;

    Ok(data)
}

fn compress_file_sync(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    let compressed = zstd::encode_all(std::io::Cursor::new(&data), ZSTD_LEVEL)?;
    Ok(compressed)
}

fn decompress_zstd_sync(data: Vec<u8>) -> Result<Vec<u8>> {
    let decompressed = zstd::decode_all(std::io::Cursor::new(&data))?;
    Ok(decompressed)
}

pub async fn compress_file(path: &Path) -> Result<Vec<u8>> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || compress_file_sync(&path))
        .await
        .context("compress task panicked")?
}

pub async fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || decompress_zstd_sync(data))
        .await
        .context("decompress task panicked")?
}

fn create_zip_sync(path: &Path) -> Result<(Vec<u8>, u64, u64)> {
    use std::io::Cursor;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    let mut buffer = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(&mut buffer);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut num_files = 0u64;
    let mut num_bytes = 0u64;

    fn add_dir_to_zip<W: Write + std::io::Seek>(
        zip: &mut ZipWriter<W>,
        path: &Path,
        prefix: &Path,
        options: SimpleFileOptions,
        num_files: &mut u64,
        num_bytes: &mut u64,
    ) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let name = entry_path.strip_prefix(prefix)?.to_string_lossy();

            let metadata = std::fs::symlink_metadata(&entry_path)?;

            if metadata.is_symlink() {
                // Handle symlinks
                let target = std::fs::read_link(&entry_path)?;
                zip.add_symlink(name.to_string(), target.to_string_lossy(), options)?;
            } else if metadata.is_dir() {
                zip.add_directory(format!("{}/", name), options)?;
                add_dir_to_zip(zip, &entry_path, prefix, options, num_files, num_bytes)?;
            } else if metadata.is_file() {
                zip.start_file(name.to_string(), options)?;
                let data = std::fs::read(&entry_path)?;
                *num_bytes += data.len() as u64;
                *num_files += 1;
                zip.write_all(&data)?;
            }
        }
        Ok(())
    }

    // Use path itself as prefix so archive contains files directly, not dirname/files
    let prefix = path;
    add_dir_to_zip(
        &mut zip,
        path,
        prefix,
        options,
        &mut num_files,
        &mut num_bytes,
    )?;

    zip.finish()?;
    let data = buffer.into_inner();

    Ok((data, num_files, num_bytes))
}

fn create_tar_zstd_sync(path: &Path) -> Result<(Vec<u8>, u64, u64)> {
    use std::io::Cursor;

    let mut num_files = 0u64;
    let mut num_bytes = 0u64;

    // Create tar archive in memory
    let tar_buffer = Cursor::new(Vec::new());
    let mut tar_builder = tar::Builder::new(tar_buffer);

    // Don't follow symlinks - preserve them
    tar_builder.follow_symlinks(false);

    // Recursively add directory contents (not the directory itself)
    fn add_dir_contents(
        builder: &mut tar::Builder<Cursor<Vec<u8>>>,
        dir_path: &Path,
        prefix: &Path,
        num_files: &mut u64,
        num_bytes: &mut u64,
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let rel_path = entry_path.strip_prefix(prefix)?;

            let metadata = std::fs::symlink_metadata(&entry_path)?;

            if metadata.is_symlink() {
                // Add symlink
                let target = std::fs::read_link(&entry_path)?;
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_mode(0o777);
                header.set_mtime(
                    metadata
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                );
                header.set_cksum();
                builder.append_link(&mut header, rel_path, &target)?;
            } else if metadata.is_dir() {
                builder.append_dir(rel_path, &entry_path)?;
                add_dir_contents(builder, &entry_path, prefix, num_files, num_bytes)?;
            } else if metadata.is_file() {
                *num_files += 1;
                *num_bytes += metadata.len();
                builder.append_path_with_name(&entry_path, rel_path)?;
            }
        }
        Ok(())
    }

    add_dir_contents(&mut tar_builder, path, path, &mut num_files, &mut num_bytes)?;

    let tar_data = tar_builder.into_inner()?.into_inner();

    // Compress with zstd
    let compressed = zstd::encode_all(std::io::Cursor::new(&tar_data), ZSTD_LEVEL)?;

    Ok((compressed, num_files, num_bytes))
}

fn extract_zip_sync(data: Vec<u8>, output_path: &Path) -> Result<()> {
    use std::io::Cursor;
    use std::io::Read;

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_path)?;

    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = output_path.join(file.name());

        if file.is_symlink() {
            // Read symlink target from file content
            let mut target = String::new();
            file.read_to_string(&mut target)?;

            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent)?;
            }

            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &outpath)?;

            #[cfg(windows)]
            {
                // On Windows, try to create a symlink (requires privileges)
                // Fall back to copying if that fails
                let target_path = outpath.parent().unwrap_or(output_path).join(&target);
                if target_path.is_dir() {
                    std::os::windows::fs::symlink_dir(&target, &outpath).ok();
                } else {
                    std::os::windows::fs::symlink_file(&target, &outpath).ok();
                }
            }
        } else if file.name().ends_with('/') {
            std::fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut outfile = std::fs::File::create(&outpath)?;
            std::io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(())
}

fn extract_tar_zstd_sync(data: Vec<u8>, output_path: &Path) -> Result<()> {
    use std::io::Cursor;

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_path)?;

    // Decompress zstd
    let decompressed = zstd::decode_all(Cursor::new(&data))?;

    // Extract tar
    let cursor = Cursor::new(decompressed);
    let mut archive = tar::Archive::new(cursor);
    archive.unpack(output_path)?;

    Ok(())
}

pub async fn create_archive(path: &Path, compression: Compression) -> Result<(Vec<u8>, u64, u64)> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || match compression {
        Compression::Zip => create_zip_sync(&path),
        Compression::Zstd => create_tar_zstd_sync(&path),
    })
    .await
    .context("archive task panicked")?
}

pub async fn extract_archive(
    data: &[u8],
    output_path: &Path,
    compression: Compression,
) -> Result<()> {
    let data = data.to_vec();
    let output_path = output_path.to_path_buf();
    tokio::task::spawn_blocking(move || match compression {
        Compression::Zip => extract_zip_sync(data, &output_path),
        Compression::Zstd => extract_tar_zstd_sync(data, &output_path),
    })
    .await
    .context("extract task panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_size() {
        assert!(RECORD_SIZE > 0);
        assert!(RECORD_SIZE <= 65536);
    }

    #[test]
    fn test_compression_mode_string() {
        assert_eq!(Compression::Zip.mode_string(), "zipfile/deflated");
        assert_eq!(Compression::Zstd.mode_string(), "tarball/zstd");
    }

    #[test]
    fn test_compression_from_mode() {
        assert_eq!(Compression::from_mode("zipfile/deflated"), Compression::Zip);
        assert_eq!(Compression::from_mode("tarball/zstd"), Compression::Zstd);
        assert_eq!(Compression::from_mode("unknown"), Compression::Zip);
    }
}
