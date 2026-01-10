use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::exclude::{ExcludePattern, compile_patterns, is_excluded};
use anyhow::{Context, Result};
use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use indicatif::{ProgressBar, ProgressStyle};
use ring::aead::{self, CHACHA20_POLY1305, LessSafeKey, UnboundKey};
use sha2::{Digest, Sha256};
use sysinfo::System;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::crypto::{
    KEY_SIZE, derive_record_key_receiver, derive_record_key_sender, derive_relay_handshake,
    derive_transit_receiver_handshake, derive_transit_sender_handshake,
};
use crate::messages::{TransferAck, Transit, TransitHint};

const RECORD_SIZE: usize = 262144 - 16; // 256KB
const TCP_BUFFER_SIZE: usize = 1024 * 1024; // 1MB buffer
const ZSTD_LEVEL: i32 = 3; // Fast compression

const MEMORY_SAFETY_FACTOR: f64 = 0.5;
const MIN_AVAILABLE_RAM: u64 = 256 * 1024 * 1024;
const XSALSA20_NONCE_SIZE: usize = 24;
const CHACHA20_NONCE_SIZE: usize = 12;

/// Cipher mode for transit encryption
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CipherMode {
    #[default]
    /// XSalsa20-Poly1305 + SHA256 (compatible with Python client)
    Compat,
    /// Ring ChaCha20-Poly1305 + BLAKE3 (faster, wormhole-rs only)
    Fast,
}

impl CipherMode {
    fn nonce_size(self) -> usize {
        match self {
            CipherMode::Compat => XSALSA20_NONCE_SIZE,
            CipherMode::Fast => CHACHA20_NONCE_SIZE,
        }
    }
}

enum Hasher {
    Sha256(Sha256),
    Blake3(Box<blake3::Hasher>),
}

impl Hasher {
    fn new(mode: CipherMode) -> Self {
        match mode {
            CipherMode::Compat => Hasher::Sha256(Sha256::new()),
            CipherMode::Fast => Hasher::Blake3(Box::new(blake3::Hasher::new())),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => {
                h.update(data);
            }
            Hasher::Blake3(h) => {
                h.update(data);
            }
        }
    }

    fn finalize_hex(self) -> String {
        match self {
            Hasher::Sha256(h) => hex::encode(h.finalize()),
            Hasher::Blake3(h) => h.finalize().to_hex().to_string(),
        }
    }
}

static CURRENT_TEMP_FILE: std::sync::Mutex<Option<std::path::PathBuf>> =
    std::sync::Mutex::new(None);

fn register_temp_file(path: &Path) {
    if let Ok(mut guard) = CURRENT_TEMP_FILE.lock() {
        *guard = Some(path.to_path_buf());
    }
}

fn unregister_temp_file() {
    if let Ok(mut guard) = CURRENT_TEMP_FILE.lock() {
        *guard = None;
    }
}

pub fn cleanup_temp_file() {
    if let Ok(mut guard) = CURRENT_TEMP_FILE.lock()
        && let Some(path) = guard.take()
    {
        let _ = std::fs::remove_file(&path);
    }
}

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

/// Source of archive data - either in memory or in a temporary file
pub enum ArchiveSource {
    /// Archive data stored in memory
    Memory(Vec<u8>),
    /// Archive data stored in a temporary file (auto-deleted on drop)
    TempFile(tempfile::NamedTempFile),
}

impl ArchiveSource {
    /// Get the size of the archive data
    pub fn size(&self) -> Result<u64> {
        match self {
            ArchiveSource::Memory(data) => Ok(data.len() as u64),
            ArchiveSource::TempFile(file) => Ok(file.as_file().metadata()?.len()),
        }
    }
}

/// Result of creating an archive
pub struct ArchiveResult {
    /// The archive data source
    pub source: ArchiveSource,
    /// Number of files in the archive
    pub num_files: u64,
    /// Total uncompressed size of files
    pub num_bytes: u64,
}

/// Calculate total size of a directory recursively
fn calculate_dir_size(path: &Path) -> u64 {
    let mut total = 0u64;

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if let Ok(metadata) = std::fs::symlink_metadata(&entry_path) {
                if metadata.is_file() {
                    total += metadata.len();
                } else if metadata.is_dir() {
                    total += calculate_dir_size(&entry_path);
                }
            }
        }
    }

    total
}

/// Get available system memory in bytes
fn get_available_memory() -> u64 {
    let sys = System::new_with_specifics(
        sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
    );
    sys.available_memory()
}

/// Determine if we should use a temporary file for archiving
fn should_use_tempfile(dir_size: u64) -> bool {
    let available = get_available_memory();

    // Use tempfile if:
    // 1. Not enough available RAM (below minimum threshold)
    // 2. Directory size exceeds safety factor of available RAM
    available < MIN_AVAILABLE_RAM || dir_size > (available as f64 * MEMORY_SAFETY_FACTOR) as u64
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

/// Cipher enum for either compat (XSalsa20) or fast (Ring ChaCha20) mode
enum Cipher {
    Compat(XSalsa20Poly1305),
    Fast(Box<LessSafeKey>),
}

impl Cipher {
    fn encrypt(&self, nonce_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Compat(c) => {
                let nonce = Nonce::from_slice(nonce_bytes);
                c.encrypt(nonce, plaintext)
                    .map_err(|_| anyhow::anyhow!("Encryption failed"))
            }
            Cipher::Fast(c) => {
                let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
                    .map_err(|_| anyhow::anyhow!("Invalid nonce size for ChaCha20-Poly1305"))?;
                let mut buffer = plaintext.to_vec();
                buffer.reserve(16); // Tag size
                c.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut buffer)
                    .map_err(|_| anyhow::anyhow!("Encryption failed"))?;
                Ok(buffer)
            }
        }
    }

    fn decrypt(&self, nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Cipher::Compat(c) => {
                let nonce = Nonce::from_slice(nonce_bytes);
                c.decrypt(nonce, ciphertext)
                    .map_err(|_| anyhow::anyhow!("Decryption failed"))
            }
            Cipher::Fast(c) => {
                let nonce = aead::Nonce::try_assume_unique_for_key(nonce_bytes)
                    .map_err(|_| anyhow::anyhow!("Invalid nonce size for ChaCha20-Poly1305"))?;
                let mut buffer = ciphertext.to_vec();
                let plaintext = c
                    .open_in_place(nonce, aead::Aad::empty(), &mut buffer)
                    .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
                let len = plaintext.len();
                buffer.truncate(len);
                Ok(buffer)
            }
        }
    }
}

pub struct TransitConnection {
    reader: Mutex<BufReader<tokio::io::ReadHalf<TcpStream>>>,
    writer: Mutex<BufWriter<tokio::io::WriteHalf<TcpStream>>>,
    send_cipher: Cipher,
    recv_cipher: Cipher,
    send_nonce: AtomicU64,
    recv_nonce: AtomicU64,
    cipher_mode: CipherMode,
}

impl TransitConnection {
    fn new(
        stream: TcpStream,
        transit_key: &[u8; KEY_SIZE],
        is_sender: bool,
        cipher_mode: CipherMode,
    ) -> Self {
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

        let (send_cipher, recv_cipher) = match cipher_mode {
            CipherMode::Compat => (
                Cipher::Compat(XSalsa20Poly1305::new(Key::from_slice(&send_key))),
                Cipher::Compat(XSalsa20Poly1305::new(Key::from_slice(&recv_key))),
            ),
            CipherMode::Fast => (
                Cipher::Fast(Box::new(LessSafeKey::new(
                    UnboundKey::new(&CHACHA20_POLY1305, &send_key).expect("valid key"),
                ))),
                Cipher::Fast(Box::new(LessSafeKey::new(
                    UnboundKey::new(&CHACHA20_POLY1305, &recv_key).expect("valid key"),
                ))),
            ),
        };

        let (read_half, write_half) = tokio::io::split(stream);

        Self {
            reader: Mutex::new(BufReader::with_capacity(TCP_BUFFER_SIZE, read_half)),
            writer: Mutex::new(BufWriter::with_capacity(TCP_BUFFER_SIZE, write_half)),
            send_cipher,
            recv_cipher,
            send_nonce: AtomicU64::new(0),
            recv_nonce: AtomicU64::new(0),
            cipher_mode,
        }
    }

    pub fn cipher_mode(&self) -> CipherMode {
        self.cipher_mode
    }

    pub async fn write_record(&self, plaintext: &[u8]) -> Result<()> {
        let nonce_size = self.cipher_mode.nonce_size();
        let nonce_val = self.send_nonce.fetch_add(1, Ordering::Relaxed);

        // Create nonce with appropriate size
        let mut nonce_bytes = vec![0u8; nonce_size];
        let offset = nonce_size.saturating_sub(8);
        nonce_bytes[offset..].copy_from_slice(&nonce_val.to_be_bytes()[..nonce_size.min(8)]);

        let ciphertext = self.send_cipher.encrypt(&nonce_bytes, plaintext)?;

        let total_len = (nonce_size + ciphertext.len()) as u32;

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
        let nonce_size = self.cipher_mode.nonce_size();
        let mut reader = self.reader.lock().await;

        // Read length
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;

        if total_len < nonce_size + 16 {
            anyhow::bail!("Invalid record length");
        }

        // Read nonce
        let mut nonce_bytes = vec![0u8; nonce_size];
        reader.read_exact(&mut nonce_bytes).await?;

        // Read ciphertext + tag
        let ciphertext_len = total_len - nonce_size;
        let mut ciphertext = vec![0u8; ciphertext_len];
        reader.read_exact(&mut ciphertext).await?;
        drop(reader);

        // Decrypt
        let plaintext = self.recv_cipher.decrypt(&nonce_bytes, &ciphertext)?;

        self.recv_nonce.fetch_add(1, Ordering::Relaxed);

        Ok(plaintext)
    }
}

/// Get local IP addresses (non-loopback)
fn get_local_ips() -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();

    // Try to get IPs by connecting to a public address (doesn't actually connect)
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0")
        && socket.connect("8.8.8.8:80").is_ok()
        && let Ok(addr) = socket.local_addr()
    {
        ips.push(addr.ip());
    }

    // Also try IPv6
    if let Ok(socket) = std::net::UdpSocket::bind("[::]:0")
        && socket.connect("[2001:4860:4860::8888]:80").is_ok()
        && let Ok(addr) = socket.local_addr()
    {
        let ip = addr.ip();
        // Skip link-local IPv6
        if let std::net::IpAddr::V6(v6) = ip
            && !v6.is_loopback()
            && (v6.segments()[0] & 0xffc0) != 0xfe80
        {
            ips.push(ip);
        }
    }

    ips
}

/// Listener for direct connections
pub struct DirectListener {
    listener: tokio::net::TcpListener,
    pub hints: Vec<TransitHint>,
}

impl DirectListener {
    /// Create a new listener on a random port and generate hints
    pub async fn new() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();

        let ips = get_local_ips();
        let hints: Vec<TransitHint> = ips
            .into_iter()
            .map(|ip| TransitHint {
                hint_type: "direct-tcp-v1".to_string(),
                priority: Some(0.0),
                hostname: Some(ip.to_string()),
                port: Some(port),
                hints: None,
            })
            .collect();

        Ok(Self { listener, hints })
    }

    /// Accept a connection and perform sender handshake
    pub async fn accept_as_sender(
        self,
        transit_key: &[u8; KEY_SIZE],
        cipher_mode: CipherMode,
    ) -> Result<TransitConnection> {
        let (mut stream, _addr) = self.listener.accept().await?;
        configure_stream(&stream)?;

        let handshake = derive_transit_sender_handshake(transit_key);
        stream.write_all(&handshake).await?;

        let expected = derive_transit_receiver_handshake(transit_key);
        let mut response = vec![0u8; expected.len()];
        stream.read_exact(&mut response).await?;

        if response != expected {
            anyhow::bail!("Invalid receiver handshake on direct connection");
        }

        stream.write_all(b"go\n").await?;

        Ok(TransitConnection::new(
            stream,
            transit_key,
            true,
            cipher_mode,
        ))
    }

    /// Accept a connection and perform receiver handshake
    pub async fn accept_as_receiver(
        self,
        transit_key: &[u8; KEY_SIZE],
        cipher_mode: CipherMode,
    ) -> Result<TransitConnection> {
        let (mut stream, _addr) = self.listener.accept().await?;
        configure_stream(&stream)?;

        let expected = derive_transit_sender_handshake(transit_key);
        let mut response = vec![0u8; expected.len()];
        stream.read_exact(&mut response).await?;

        if response != expected {
            anyhow::bail!("Invalid sender handshake on direct connection");
        }

        let handshake = derive_transit_receiver_handshake(transit_key);
        stream.write_all(&handshake).await?;

        let mut go_buf = [0u8; 3];
        stream.read_exact(&mut go_buf).await?;
        if &go_buf != b"go\n" {
            anyhow::bail!("Did not receive 'go' on direct connection");
        }

        Ok(TransitConnection::new(
            stream,
            transit_key,
            false,
            cipher_mode,
        ))
    }
}

/// Create a direct listener and return hints with actual port
pub async fn create_direct_listener() -> Result<DirectListener> {
    DirectListener::new().await
}

fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true)?;
    Ok(())
}

pub async fn connect_as_sender(
    transit_key: &[u8; KEY_SIZE],
    peer_hints: &Transit,
    relay_addr: &str,
    timeout: Duration,
    listener: Option<DirectListener>,
    cipher_mode: CipherMode,
) -> Result<Arc<TransitConnection>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TransitConnection>(1);

    // Collect direct addresses from peer hints
    let direct_addrs: Vec<String> = peer_hints
        .hints_v1
        .iter()
        .filter(|h| h.hint_type == "direct-tcp-v1")
        .filter_map(|h| {
            if let (Some(host), Some(port)) = (&h.hostname, h.port) {
                Some(format!("{}:{}", host, port))
            } else {
                None
            }
        })
        .collect();

    // Task 1: Accept on our listener (peer connects to us)
    if let Some(listener) = listener {
        let tx = tx.clone();
        let transit_key = *transit_key;
        tokio::spawn(async move {
            if let Ok(conn) = listener.accept_as_sender(&transit_key, cipher_mode).await {
                let _ = tx.send(conn).await;
            }
        });
    }

    // Task 2: Connect to peer's direct hints
    for addr in direct_addrs {
        let tx = tx.clone();
        let transit_key = *transit_key;
        tokio::spawn(async move {
            if let Ok(conn) =
                try_connect_direct_sender(&transit_key, &addr, timeout, cipher_mode).await
            {
                let _ = tx.send(conn).await;
            }
        });
    }

    // Task 3: Connect via relay (with delay to prefer direct)
    {
        let tx = tx.clone();
        let transit_key = *transit_key;
        let relay_addr = relay_addr.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(conn) =
                connect_via_relay_sender(&transit_key, &relay_addr, timeout, cipher_mode).await
            {
                let _ = tx.send(conn).await;
            }
        });
    }

    drop(tx); // Drop our copy so rx.recv() returns None when all tasks finish

    tokio::time::timeout(timeout, rx.recv())
        .await
        .context("Transit connection timed out")?
        .context("All connection attempts failed")
        .map(Arc::new)
}

pub async fn connect_as_receiver(
    transit_key: &[u8; KEY_SIZE],
    peer_hints: &Transit,
    relay_addr: &str,
    timeout: Duration,
    listener: Option<DirectListener>,
    cipher_mode: CipherMode,
) -> Result<Arc<TransitConnection>> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TransitConnection>(1);

    // Collect direct addresses from peer hints
    let direct_addrs: Vec<String> = peer_hints
        .hints_v1
        .iter()
        .filter(|h| h.hint_type == "direct-tcp-v1")
        .filter_map(|h| {
            if let (Some(host), Some(port)) = (&h.hostname, h.port) {
                Some(format!("{}:{}", host, port))
            } else {
                None
            }
        })
        .collect();

    // Task 1: Accept on our listener (peer connects to us)
    if let Some(listener) = listener {
        let tx = tx.clone();
        let transit_key = *transit_key;
        tokio::spawn(async move {
            if let Ok(conn) = listener.accept_as_receiver(&transit_key, cipher_mode).await {
                let _ = tx.send(conn).await;
            }
        });
    }

    // Task 2: Connect to peer's direct hints
    for addr in direct_addrs {
        let tx = tx.clone();
        let transit_key = *transit_key;
        tokio::spawn(async move {
            if let Ok(conn) =
                try_connect_direct_receiver(&transit_key, &addr, timeout, cipher_mode).await
            {
                let _ = tx.send(conn).await;
            }
        });
    }

    // Task 3: Connect via relay (with delay to prefer direct)
    {
        let tx = tx.clone();
        let transit_key = *transit_key;
        let relay_addr = relay_addr.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(conn) =
                connect_via_relay_receiver(&transit_key, &relay_addr, timeout, cipher_mode).await
            {
                let _ = tx.send(conn).await;
            }
        });
    }

    drop(tx);

    tokio::time::timeout(timeout, rx.recv())
        .await
        .context("Transit connection timed out")?
        .context("All connection attempts failed")
        .map(Arc::new)
}

async fn try_connect_direct_sender(
    transit_key: &[u8; KEY_SIZE],
    addr: &str,
    timeout: Duration,
    cipher_mode: CipherMode,
) -> Result<TransitConnection> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .context("Connection timed out")?
        .context("Failed to connect")?;
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

    Ok(TransitConnection::new(
        stream,
        transit_key,
        true,
        cipher_mode,
    ))
}

async fn try_connect_direct_receiver(
    transit_key: &[u8; KEY_SIZE],
    addr: &str,
    timeout: Duration,
    cipher_mode: CipherMode,
) -> Result<TransitConnection> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .context("Connection timed out")?
        .context("Failed to connect")?;
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

    Ok(TransitConnection::new(
        stream,
        transit_key,
        false,
        cipher_mode,
    ))
}

async fn connect_via_relay_sender(
    transit_key: &[u8; KEY_SIZE],
    relay_addr: &str,
    timeout: Duration,
    cipher_mode: CipherMode,
) -> Result<TransitConnection> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(relay_addr))
        .await
        .context("Relay connection timed out")?
        .context("Failed to connect to relay")?;
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

    Ok(TransitConnection::new(
        stream,
        transit_key,
        true,
        cipher_mode,
    ))
}

async fn connect_via_relay_receiver(
    transit_key: &[u8; KEY_SIZE],
    relay_addr: &str,
    timeout: Duration,
    cipher_mode: CipherMode,
) -> Result<TransitConnection> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(relay_addr))
        .await
        .context("Relay connection timed out")?
        .context("Failed to connect to relay")?;
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

    Ok(TransitConnection::new(
        stream,
        transit_key,
        false,
        cipher_mode,
    ))
}

pub async fn send_file<R: AsyncRead + Unpin>(
    conn: &Arc<TransitConnection>,
    reader: &mut R,
    total_size: u64,
    hide_progress: bool,
) -> Result<()> {
    let mut hasher = Hasher::new(conn.cipher_mode());
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

    let hash = hasher.finalize_hex();
    if ack.sha256.to_lowercase() != hash.to_lowercase() {
        anyhow::bail!("Hash mismatch: expected {}, got {}", hash, ack.sha256);
    }

    Ok(())
}

pub async fn receive_file<W: AsyncWrite + Unpin>(
    conn: &Arc<TransitConnection>,
    writer: &mut W,
    total_size: u64,
    hide_progress: bool,
) -> Result<()> {
    let mut hasher = Hasher::new(conn.cipher_mode());
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

    let hash = hasher.finalize_hex();
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
    let mut hasher = Hasher::new(conn.cipher_mode());
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

    let hash = hasher.finalize_hex();
    let ack = TransferAck {
        ack: "ok".to_string(),
        sha256: hash,
    };
    let ack_data = serde_json::to_vec(&ack)?;
    conn.write_record(&ack_data).await?;
    conn.flush().await?;

    Ok(data)
}

/// Receive data to a temporary file (for large transfers)
pub async fn receive_to_tempfile(
    conn: &Arc<TransitConnection>,
    total_size: u64,
    hide_progress: bool,
) -> Result<tempfile::NamedTempFile> {
    use tokio::io::AsyncWriteExt;

    let temp_file = tempfile::NamedTempFile::new()?;
    register_temp_file(temp_file.path());
    let mut file = tokio::fs::File::create(temp_file.path()).await?;
    let mut hasher = Hasher::new(conn.cipher_mode());
    let mut received = 0u64;

    let progress = create_progress_bar(total_size, hide_progress);

    while received < total_size {
        let chunk = conn.read_record().await?;
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
        received += chunk.len() as u64;
        progress.set_position(received);
    }

    file.flush().await?;
    progress.finish_and_clear();

    let hash = hasher.finalize_hex();
    let ack = TransferAck {
        ack: "ok".to_string(),
        sha256: hash,
    };
    let ack_data = serde_json::to_vec(&ack)?;
    conn.write_record(&ack_data).await?;
    conn.flush().await?;

    unregister_temp_file();
    Ok(temp_file)
}

/// Result of receiving data - either in memory or in a temporary file
pub enum ReceivedData {
    /// Data stored in memory
    Memory(Vec<u8>),
    /// Data stored in a temporary file
    TempFile(tempfile::NamedTempFile),
}

/// Receive data (memory-aware)
///
/// Automatically chooses between in-memory and tempfile based on available RAM.
pub async fn receive_data(
    conn: &Arc<TransitConnection>,
    total_size: u64,
    hide_progress: bool,
) -> Result<ReceivedData> {
    if should_use_tempfile(total_size) {
        let temp_file = receive_to_tempfile(conn, total_size, hide_progress).await?;
        Ok(ReceivedData::TempFile(temp_file))
    } else {
        let data = receive_to_vec(conn, total_size, hide_progress).await?;
        Ok(ReceivedData::Memory(data))
    }
}

/// Compress a file with zstd (in memory)
fn compress_file_sync(path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    let compressed = zstd::encode_all(std::io::Cursor::new(&data), ZSTD_LEVEL)?;
    Ok(compressed)
}

/// Compress a file with zstd to a temporary file (for large files)
fn compress_file_to_tempfile_sync(path: &Path) -> Result<tempfile::NamedTempFile> {
    use std::io::BufReader;

    let input = std::fs::File::open(path)?;
    let mut reader = BufReader::new(input);

    let temp_file = tempfile::NamedTempFile::new()?;
    register_temp_file(temp_file.path());
    let mut encoder = zstd::Encoder::new(temp_file.reopen()?, ZSTD_LEVEL)?;

    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;

    unregister_temp_file();
    Ok(temp_file)
}

/// Decompress zstd data
fn decompress_zstd_sync(data: Vec<u8>) -> Result<Vec<u8>> {
    let decompressed = zstd::decode_all(std::io::Cursor::new(&data))?;
    Ok(decompressed)
}

/// Result of compressing a file
pub enum CompressedFile {
    /// Compressed data in memory
    Memory(Vec<u8>),
    /// Compressed data in a temporary file
    TempFile(tempfile::NamedTempFile),
}

impl CompressedFile {
    /// Get the size of the compressed data
    pub fn size(&self) -> Result<u64> {
        match self {
            CompressedFile::Memory(data) => Ok(data.len() as u64),
            CompressedFile::TempFile(file) => Ok(file.as_file().metadata()?.len()),
        }
    }
}

/// Compress a file (memory-aware)
///
/// Automatically chooses between in-memory and tempfile based on available RAM.
pub async fn compress_file(path: &Path) -> Result<CompressedFile> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file_size = std::fs::metadata(&path)?.len();

        if should_use_tempfile(file_size) {
            // Large file - compress to tempfile
            let temp_file = compress_file_to_tempfile_sync(&path)?;
            Ok(CompressedFile::TempFile(temp_file))
        } else {
            // Small enough - compress in memory
            let data = compress_file_sync(&path)?;
            Ok(CompressedFile::Memory(data))
        }
    })
    .await
    .context("compress task panicked")?
}

/// Decompress zstd data (async wrapper)
pub async fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    let data = data.to_vec();
    tokio::task::spawn_blocking(move || decompress_zstd_sync(data))
        .await
        .context("decompress task panicked")?
}

/// Decompress zstd from file to file (streaming, memory-efficient)
fn decompress_zstd_file_to_file_sync(input: &Path, output: &Path) -> Result<()> {
    use std::io::BufReader;

    let input_file = std::fs::File::open(input)?;
    let mut decoder = zstd::Decoder::new(BufReader::new(input_file))?;

    let mut output_file = std::fs::File::create(output)?;
    std::io::copy(&mut decoder, &mut output_file)?;

    Ok(())
}

/// Decompress zstd from file to file (async wrapper)
pub async fn decompress_zstd_file_to_file(input: &Path, output: &Path) -> Result<()> {
    let input = input.to_path_buf();
    let output = output.to_path_buf();
    tokio::task::spawn_blocking(move || decompress_zstd_file_to_file_sync(&input, &output))
        .await
        .context("decompress task panicked")?
}

fn create_zip_sync(path: &Path, patterns: &[ExcludePattern]) -> Result<(Vec<u8>, u64, u64)> {
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
        patterns: &[ExcludePattern],
        num_files: &mut u64,
        num_bytes: &mut u64,
    ) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let rel_path = entry_path.strip_prefix(prefix)?;
            let metadata = std::fs::symlink_metadata(&entry_path)?;

            // Skip excluded files/directories
            if is_excluded(rel_path, metadata.is_dir(), patterns) {
                continue;
            }

            let name = rel_path.to_string_lossy();

            if metadata.is_symlink() {
                // Handle symlinks
                let target = std::fs::read_link(&entry_path)?;
                zip.add_symlink(name.to_string(), target.to_string_lossy(), options)?;
            } else if metadata.is_dir() {
                zip.add_directory(format!("{}/", name), options)?;
                add_dir_to_zip(
                    zip,
                    &entry_path,
                    prefix,
                    options,
                    patterns,
                    num_files,
                    num_bytes,
                )?;
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
        patterns,
        &mut num_files,
        &mut num_bytes,
    )?;

    zip.finish()?;
    let data = buffer.into_inner();

    Ok((data, num_files, num_bytes))
}

/// Create zip archive to a temporary file (for large directories)
fn create_zip_to_tempfile_sync(
    path: &Path,
    patterns: &[ExcludePattern],
) -> Result<(tempfile::NamedTempFile, u64, u64)> {
    use std::io::BufWriter;
    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    let temp_file = tempfile::NamedTempFile::new()?;
    register_temp_file(temp_file.path());
    let mut zip = ZipWriter::new(BufWriter::new(temp_file.reopen()?));
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut num_files = 0u64;
    let mut num_bytes = 0u64;

    fn add_dir_to_zip_file<W: Write + std::io::Seek>(
        zip: &mut ZipWriter<W>,
        path: &Path,
        prefix: &Path,
        options: SimpleFileOptions,
        patterns: &[ExcludePattern],
        num_files: &mut u64,
        num_bytes: &mut u64,
    ) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let rel_path = entry_path.strip_prefix(prefix)?;
            let metadata = std::fs::symlink_metadata(&entry_path)?;

            // Skip excluded files/directories
            if is_excluded(rel_path, metadata.is_dir(), patterns) {
                continue;
            }

            let name = rel_path.to_string_lossy();

            if metadata.is_symlink() {
                let target = std::fs::read_link(&entry_path)?;
                zip.add_symlink(name.to_string(), target.to_string_lossy(), options)?;
            } else if metadata.is_dir() {
                zip.add_directory(format!("{}/", name), options)?;
                add_dir_to_zip_file(
                    zip,
                    &entry_path,
                    prefix,
                    options,
                    patterns,
                    num_files,
                    num_bytes,
                )?;
            } else if metadata.is_file() {
                zip.start_file(name.to_string(), options)?;
                // Stream file content instead of loading all at once
                let mut file = std::fs::File::open(&entry_path)?;
                let file_size = std::io::copy(&mut file, zip)?;
                *num_bytes += file_size;
                *num_files += 1;
            }
        }
        Ok(())
    }

    let prefix = path;
    add_dir_to_zip_file(
        &mut zip,
        path,
        prefix,
        options,
        patterns,
        &mut num_files,
        &mut num_bytes,
    )?;

    zip.finish()?;

    unregister_temp_file();
    Ok((temp_file, num_files, num_bytes))
}

fn create_tar_zstd_sync(path: &Path, patterns: &[ExcludePattern]) -> Result<(Vec<u8>, u64, u64)> {
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
        patterns: &[ExcludePattern],
        num_files: &mut u64,
        num_bytes: &mut u64,
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let rel_path = entry_path.strip_prefix(prefix)?;
            let metadata = std::fs::symlink_metadata(&entry_path)?;

            // Skip excluded files/directories
            if is_excluded(rel_path, metadata.is_dir(), patterns) {
                continue;
            }

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
                add_dir_contents(builder, &entry_path, prefix, patterns, num_files, num_bytes)?;
            } else if metadata.is_file() {
                *num_files += 1;
                *num_bytes += metadata.len();
                builder.append_path_with_name(&entry_path, rel_path)?;
            }
        }
        Ok(())
    }

    add_dir_contents(
        &mut tar_builder,
        path,
        path,
        patterns,
        &mut num_files,
        &mut num_bytes,
    )?;

    let tar_data = tar_builder.into_inner()?.into_inner();
    let compressed = zstd::encode_all(std::io::Cursor::new(&tar_data), ZSTD_LEVEL)?;

    Ok((compressed, num_files, num_bytes))
}

/// Create tar+zstd archive to a temporary file (for large directories)
fn create_tar_zstd_to_tempfile_sync(
    path: &Path,
    patterns: &[ExcludePattern],
) -> Result<(tempfile::NamedTempFile, u64, u64)> {
    use std::io::BufWriter;

    let mut num_files = 0u64;
    let mut num_bytes = 0u64;

    // Create temporary file for the compressed output
    let temp_file = tempfile::NamedTempFile::new()?;
    register_temp_file(temp_file.path());
    let zstd_writer = zstd::Encoder::new(BufWriter::new(temp_file.reopen()?), ZSTD_LEVEL)?;
    let mut tar_builder = tar::Builder::new(zstd_writer);

    // Don't follow symlinks - preserve them
    tar_builder.follow_symlinks(false);

    // Recursively add directory contents
    fn add_dir_contents_to_tar<W: Write>(
        builder: &mut tar::Builder<W>,
        dir_path: &Path,
        prefix: &Path,
        patterns: &[ExcludePattern],
        num_files: &mut u64,
        num_bytes: &mut u64,
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir_path)? {
            let entry = entry?;
            let entry_path = entry.path();
            let rel_path = entry_path.strip_prefix(prefix)?;
            let metadata = std::fs::symlink_metadata(&entry_path)?;

            // Skip excluded files/directories
            if is_excluded(rel_path, metadata.is_dir(), patterns) {
                continue;
            }

            if metadata.is_symlink() {
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
                add_dir_contents_to_tar(
                    builder,
                    &entry_path,
                    prefix,
                    patterns,
                    num_files,
                    num_bytes,
                )?;
            } else if metadata.is_file() {
                *num_files += 1;
                *num_bytes += metadata.len();
                builder.append_path_with_name(&entry_path, rel_path)?;
            }
        }
        Ok(())
    }

    add_dir_contents_to_tar(
        &mut tar_builder,
        path,
        path,
        patterns,
        &mut num_files,
        &mut num_bytes,
    )?;

    // Finish tar and zstd compression
    let zstd_writer = tar_builder.into_inner()?;
    zstd_writer.finish()?;

    unregister_temp_file();
    Ok((temp_file, num_files, num_bytes))
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

/// Extract zip archive from a file (streaming, memory-efficient)
fn extract_zip_from_file_sync(archive_path: &Path, output_path: &Path) -> Result<()> {
    use std::io::Read;

    std::fs::create_dir_all(output_path)?;

    let file = std::fs::File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = output_path.join(file.name());

        if file.is_symlink() {
            let mut target = String::new();
            file.read_to_string(&mut target)?;

            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent)?;
            }

            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &outpath)?;

            #[cfg(windows)]
            {
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

/// Extract tar+zstd archive from a file (streaming, memory-efficient)
fn extract_tar_zstd_from_file_sync(archive_path: &Path, output_path: &Path) -> Result<()> {
    use std::io::BufReader;

    std::fs::create_dir_all(output_path)?;

    let file = std::fs::File::open(archive_path)?;
    let decoder = zstd::Decoder::new(BufReader::new(file))?;
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(output_path)?;

    Ok(())
}

/// Create archive from directory (memory-aware)
///
/// Automatically chooses between in-memory and tempfile based on available RAM.
/// This prevents OOM crashes when archiving large directories.
pub async fn create_archive(
    path: &Path,
    compression: Compression,
    exclude_patterns: &[String],
) -> Result<ArchiveResult> {
    let path = path.to_path_buf();
    let patterns: Vec<String> = exclude_patterns.to_vec();
    tokio::task::spawn_blocking(move || {
        let compiled_patterns = compile_patterns(&patterns);
        let dir_size = calculate_dir_size(&path);
        let use_tempfile = should_use_tempfile(dir_size);

        match compression {
            Compression::Zip => {
                if use_tempfile {
                    // Large directory - use tempfile to avoid OOM
                    let (temp_file, num_files, num_bytes) =
                        create_zip_to_tempfile_sync(&path, &compiled_patterns)?;
                    Ok(ArchiveResult {
                        source: ArchiveSource::TempFile(temp_file),
                        num_files,
                        num_bytes,
                    })
                } else {
                    // Small enough - use memory (faster)
                    let (data, num_files, num_bytes) = create_zip_sync(&path, &compiled_patterns)?;
                    Ok(ArchiveResult {
                        source: ArchiveSource::Memory(data),
                        num_files,
                        num_bytes,
                    })
                }
            }
            Compression::Zstd => {
                if use_tempfile {
                    // Large directory - use tempfile to avoid OOM
                    let (temp_file, num_files, num_bytes) =
                        create_tar_zstd_to_tempfile_sync(&path, &compiled_patterns)?;
                    Ok(ArchiveResult {
                        source: ArchiveSource::TempFile(temp_file),
                        num_files,
                        num_bytes,
                    })
                } else {
                    // Small enough - use memory (faster)
                    let (data, num_files, num_bytes) =
                        create_tar_zstd_sync(&path, &compiled_patterns)?;
                    Ok(ArchiveResult {
                        source: ArchiveSource::Memory(data),
                        num_files,
                        num_bytes,
                    })
                }
            }
        }
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

/// Extract archive from file to directory (streaming, memory-efficient)
pub async fn extract_archive_from_file(
    archive_path: &Path,
    output_path: &Path,
    compression: Compression,
) -> Result<()> {
    let archive_path = archive_path.to_path_buf();
    let output_path = output_path.to_path_buf();
    tokio::task::spawn_blocking(move || match compression {
        Compression::Zip => extract_zip_from_file_sync(&archive_path, &output_path),
        Compression::Zstd => extract_tar_zstd_from_file_sync(&archive_path, &output_path),
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
        assert!(RECORD_SIZE <= 262144);
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

    #[test]
    fn test_cipher_mode_nonce_size() {
        assert_eq!(CipherMode::Compat.nonce_size(), 24);
        assert_eq!(CipherMode::Fast.nonce_size(), 12);
    }

    #[test]
    fn test_cipher_roundtrip_compat() {
        use crypto_secretbox::aead::KeyInit;
        use crypto_secretbox::{Key, XSalsa20Poly1305};

        let key = [42u8; KEY_SIZE];
        let cipher = Cipher::Compat(XSalsa20Poly1305::new(Key::from_slice(&key)));

        let plaintext = b"Hello, World!";
        let nonce = [0u8; XSALSA20_NONCE_SIZE]; // 24 bytes

        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_roundtrip_fast() {
        use ring::aead::{CHACHA20_POLY1305, LessSafeKey, UnboundKey};

        let key = [42u8; KEY_SIZE];
        let cipher = Cipher::Fast(Box::new(LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap(),
        )));

        let plaintext = b"Hello, World!";
        let nonce = [0u8; CHACHA20_NONCE_SIZE]; // 12 bytes

        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_cipher_different_nonces_produce_different_ciphertext() {
        use crypto_secretbox::aead::KeyInit;
        use crypto_secretbox::{Key, XSalsa20Poly1305};

        let key = [42u8; KEY_SIZE];
        let cipher = Cipher::Compat(XSalsa20Poly1305::new(Key::from_slice(&key)));

        let plaintext = b"Hello, World!";
        let nonce1 = [0u8; XSALSA20_NONCE_SIZE];
        let nonce2 = [1u8; XSALSA20_NONCE_SIZE];

        let ciphertext1 = cipher.encrypt(&nonce1, plaintext).unwrap();
        let ciphertext2 = cipher.encrypt(&nonce2, plaintext).unwrap();

        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_cipher_wrong_key_fails_decryption() {
        use crypto_secretbox::aead::KeyInit;
        use crypto_secretbox::{Key, XSalsa20Poly1305};

        let key1 = [42u8; KEY_SIZE];
        let key2 = [43u8; KEY_SIZE];
        let cipher1 = Cipher::Compat(XSalsa20Poly1305::new(Key::from_slice(&key1)));
        let cipher2 = Cipher::Compat(XSalsa20Poly1305::new(Key::from_slice(&key2)));

        let plaintext = b"Hello, World!";
        let nonce = [0u8; XSALSA20_NONCE_SIZE];

        let ciphertext = cipher1.encrypt(&nonce, plaintext).unwrap();
        let result = cipher2.decrypt(&nonce, &ciphertext);

        assert!(result.is_err());
    }

    #[test]
    fn test_get_local_ips() {
        let ips = get_local_ips();
        // Should get at least one IP on most systems
        // (might be empty in some CI environments)
        for ip in &ips {
            assert!(!ip.is_loopback());
        }
    }

    #[tokio::test]
    async fn test_direct_listener_creation() {
        let listener = DirectListener::new().await;
        assert!(listener.is_ok());

        let listener = listener.unwrap();
        // Should have hints if we have local IPs
        // Each hint should have a valid port
        for hint in &listener.hints {
            assert_eq!(hint.hint_type, "direct-tcp-v1");
            assert!(hint.port.unwrap() > 0);
        }
    }

    #[test]
    fn test_get_available_memory() {
        let mem = get_available_memory();
        // Should have at least some memory available
        assert!(mem > 0);
    }

    #[test]
    fn test_should_use_tempfile() {
        // Very small size should use memory
        assert!(!should_use_tempfile(1024));

        // Very large size should use tempfile
        assert!(should_use_tempfile(100 * 1024 * 1024 * 1024)); // 100 GB
    }

    #[test]
    fn test_calculate_dir_size() {
        // Create temp dir with some files
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let size = calculate_dir_size(temp_dir.path());
        assert!(size >= 11); // "hello world" = 11 bytes
    }

    #[tokio::test]
    async fn test_compress_file_small() {
        // Small file should use memory
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("small.txt");
        std::fs::write(&file_path, "hello world").unwrap();

        let result = compress_file(&file_path).await.unwrap();
        assert!(matches!(result, CompressedFile::Memory(_)));
    }

    #[test]
    fn test_hasher_sha256() {
        let mut hasher = Hasher::new(CipherMode::Compat);
        hasher.update(b"hello");
        let hash = hasher.finalize_hex();
        assert_eq!(hash.len(), 64); // SHA256 = 32 bytes = 64 hex chars
    }

    #[test]
    fn test_hasher_blake3() {
        let mut hasher = Hasher::new(CipherMode::Fast);
        hasher.update(b"hello");
        let hash = hasher.finalize_hex();
        assert_eq!(hash.len(), 64); // BLAKE3 = 32 bytes = 64 hex chars
    }
}
