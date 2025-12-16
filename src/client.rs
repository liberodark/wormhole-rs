use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::fs::File;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::crypto::{
    self, SpakeState, decrypt_message, derive_transit_key, derive_verifier, encrypt_message,
};
use crate::messages::{
    Add, Allocate, Answer, AppVersions, Bind, Claim, ClientMessage, Close, GenericMessage, Mood,
    Offer, OfferDirectory, OfferFile, Open, PakeMsg, Release, ServerMessage, Transit,
    TransitAbility,
};
use crate::transit;
use crate::wordlist;
use crate::{AGENT_STRING, AGENT_VERSION, APP_ID, DEFAULT_RELAY_URL, DEFAULT_TRANSIT_RELAY};

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_PEER_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes

pub struct SendConfig<'a> {
    pub relay_url: &'a str,
    pub transit_relay: &'a str,
    pub code: Option<&'a str>,
    pub code_length: usize,
    pub verify: bool,
    pub hide_progress: bool,
    pub compression: transit::Compression,
    pub connect_timeout: Duration,
    pub peer_timeout: Duration,
}

impl Default for SendConfig<'_> {
    fn default() -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL,
            transit_relay: DEFAULT_TRANSIT_RELAY,
            code: None,
            code_length: 2,
            verify: false,
            hide_progress: false,
            compression: transit::Compression::Zip,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            peer_timeout: DEFAULT_PEER_TIMEOUT,
        }
    }
}

pub struct ReceiveConfig<'a> {
    pub relay_url: &'a str,
    pub transit_relay: &'a str,
    pub output_dir: Option<&'a Path>,
    pub verify: bool,
    pub hide_progress: bool,
    pub auto_accept: bool,
    pub connect_timeout: Duration,
    pub peer_timeout: Duration,
}

impl Default for ReceiveConfig<'_> {
    fn default() -> Self {
        Self {
            relay_url: DEFAULT_RELAY_URL,
            transit_relay: DEFAULT_TRANSIT_RELAY,
            output_dir: None,
            verify: false,
            hide_progress: false,
            auto_accept: false,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            peer_timeout: DEFAULT_PEER_TIMEOUT,
        }
    }
}

fn nameplate_from_code(code: &str) -> Result<&str> {
    let nameplate = code.split('-').next().context("Invalid code format")?;
    nameplate
        .parse::<u32>()
        .context("Nameplate must be a number")?;
    Ok(nameplate)
}

fn build_transit_message(hints: Vec<crate::messages::TransitHint>) -> GenericMessage {
    GenericMessage {
        offer: None,
        answer: None,
        transit: Some(Transit {
            abilities_v1: vec![
                TransitAbility {
                    ability_type: "direct-tcp-v1".to_string(),
                },
                TransitAbility {
                    ability_type: "relay-v1".to_string(),
                },
            ],
            hints_v1: hints,
        }),
        app_versions: None,
        error: None,
    }
}

fn build_file_ack() -> GenericMessage {
    GenericMessage {
        offer: None,
        answer: Some(Answer {
            message_ack: None,
            file_ack: Some("ok".to_string()),
        }),
        transit: None,
        app_versions: None,
        error: None,
    }
}

fn build_message_ack() -> GenericMessage {
    GenericMessage {
        offer: None,
        answer: Some(Answer {
            message_ack: Some("ok".to_string()),
            file_ack: None,
        }),
        transit: None,
        app_versions: None,
        error: None,
    }
}

fn build_reject() -> GenericMessage {
    GenericMessage {
        offer: None,
        answer: None,
        transit: None,
        app_versions: None,
        error: Some("transfer rejected".to_string()),
    }
}

fn build_text_offer(text: &str) -> GenericMessage {
    GenericMessage {
        offer: Some(Offer {
            message: Some(text.to_string()),
            file: None,
            directory: None,
        }),
        answer: None,
        transit: None,
        app_versions: None,
        error: None,
    }
}

fn build_file_offer(
    filename: String,
    filesize: u64,
    mode: Option<String>,
    original_size: Option<u64>,
) -> GenericMessage {
    GenericMessage {
        offer: Some(Offer {
            message: None,
            file: Some(OfferFile {
                filename,
                filesize,
                mode,
                original_size,
            }),
            directory: None,
        }),
        answer: None,
        transit: None,
        app_versions: None,
        error: None,
    }
}

fn build_directory_offer(
    dirname: String,
    num_files: u64,
    num_bytes: u64,
    zipsize: u64,
    compression: transit::Compression,
) -> GenericMessage {
    GenericMessage {
        offer: Some(Offer {
            message: None,
            file: None,
            directory: Some(OfferDirectory {
                dirname,
                mode: compression.mode_string().to_string(),
                numbytes: num_bytes,
                numfiles: num_files,
                zipsize,
            }),
        }),
        answer: None,
        transit: None,
        app_versions: None,
        error: None,
    }
}

struct RendezvousClient {
    ws_sender: futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >,
    ws_receiver: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    side_id: String,
    mailbox_id: Option<String>,
    pending_messages: Vec<crate::messages::Message>,
}

impl RendezvousClient {
    async fn connect(relay_url: &str, timeout: Duration) -> Result<Self> {
        let connect_future = connect_async(relay_url);
        let (ws_stream, _) = tokio::time::timeout(timeout, connect_future)
            .await
            .context("Connection timed out")?
            .context("Failed to connect to relay server")?;

        let (ws_sender, ws_receiver) = ws_stream.split();
        let side_id = crypto::generate_side_id();

        Ok(Self {
            ws_sender,
            ws_receiver,
            side_id,
            mailbox_id: None,
            pending_messages: Vec::new(),
        })
    }

    async fn send(&mut self, msg: ClientMessage) -> Result<()> {
        let json = serde_json::to_string(&msg)?;
        self.ws_sender
            .send(Message::Text(json.into()))
            .await
            .context("Failed to send message")?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<ServerMessage> {
        loop {
            match self.ws_receiver.next().await {
                Some(Ok(Message::Text(text))) => {
                    let msg: ServerMessage = serde_json::from_str(&text)
                        .with_context(|| format!("Failed to parse server message: {}", text))?;
                    return Ok(msg);
                }
                Some(Ok(Message::Close(_))) => {
                    anyhow::bail!("Connection closed by server");
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => {
                    anyhow::bail!("WebSocket error: {}", e);
                }
                None => {
                    anyhow::bail!("Connection closed");
                }
            }
        }
    }

    async fn recv_until<F, T>(&mut self, pred: F) -> Result<T>
    where
        F: Fn(&ServerMessage) -> Option<T>,
    {
        loop {
            let msg = self.recv().await?;
            if let Some(result) = pred(&msg) {
                return Ok(result);
            }
            if let ServerMessage::Message(m) = msg {
                self.pending_messages.push(m);
            }
        }
    }

    async fn bind(&mut self) -> Result<()> {
        let welcome = self.recv().await?;
        if let ServerMessage::Welcome(w) = welcome
            && let Some(error) = w.welcome.error
        {
            anyhow::bail!("Server error: {}", error);
        }

        let bind = ClientMessage::Bind(Bind {
            side: self.side_id.clone(),
            appid: APP_ID.to_string(),
            client_version: vec![AGENT_STRING.to_string(), AGENT_VERSION.to_string()],
        });
        self.send(bind).await?;

        self.recv_until(|msg| matches!(msg, ServerMessage::Ack(_)).then_some(()))
            .await?;

        Ok(())
    }

    async fn allocate(&mut self) -> Result<String> {
        let alloc = ClientMessage::Allocate(Allocate {
            id: crypto::random_hex(2),
        });
        self.send(alloc).await?;

        self.recv_until(|msg| {
            if let ServerMessage::Allocated(a) = msg {
                Some(a.nameplate.clone())
            } else {
                None
            }
        })
        .await
    }

    async fn claim(&mut self, nameplate: &str) -> Result<String> {
        let claim = ClientMessage::Claim(Claim {
            id: crypto::random_hex(2),
            nameplate: nameplate.to_string(),
        });
        self.send(claim).await?;

        self.recv_until(|msg| {
            if let ServerMessage::Claimed(c) = msg {
                Some(c.mailbox.clone())
            } else {
                None
            }
        })
        .await
    }

    async fn open(&mut self, mailbox: &str) -> Result<()> {
        self.mailbox_id = Some(mailbox.to_string());

        let open = ClientMessage::Open(Open {
            id: crypto::random_hex(2),
            mailbox: mailbox.to_string(),
        });
        self.send(open).await?;

        self.recv_until(|msg| matches!(msg, ServerMessage::Ack(_)).then_some(()))
            .await?;

        Ok(())
    }

    async fn add(&mut self, phase: &str, body: &str) -> Result<()> {
        let add = ClientMessage::Add(Add {
            id: crypto::random_hex(2),
            phase: phase.to_string(),
            body: body.to_string(),
        });
        self.send(add).await?;

        self.recv_until(|msg| matches!(msg, ServerMessage::Ack(_)).then_some(()))
            .await?;

        Ok(())
    }

    async fn release(&mut self, nameplate: &str) -> Result<()> {
        let release = ClientMessage::Release(Release {
            id: crypto::random_hex(2),
            nameplate: nameplate.to_string(),
        });
        self.send(release).await?;

        self.recv_until(|msg| matches!(msg, ServerMessage::Released(_)).then_some(()))
            .await?;

        Ok(())
    }

    async fn close(&mut self, mood: Mood) -> Result<()> {
        if let Some(mailbox) = &self.mailbox_id {
            let close = ClientMessage::Close(Close {
                id: crypto::random_hex(2),
                mailbox: mailbox.clone(),
                mood: mood.to_string(),
            });
            self.send(close).await?;

            let _ = self
                .recv_until(|msg| matches!(msg, ServerMessage::Closed(_)).then_some(()))
                .await;
        }
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.ws_sender.close().await?;
        Ok(())
    }

    /// Graceful shutdown - errors are ignored since transfer is already complete
    async fn graceful_close(&mut self, nameplate: &str, mood: Mood) {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let _ = self.release(nameplate).await;
            let _ = self.close(mood).await;
            let _ = self.shutdown().await;
        })
        .await;
    }

    async fn recv_message(&mut self) -> Result<crate::messages::Message> {
        if !self.pending_messages.is_empty() {
            return Ok(self.pending_messages.remove(0));
        }

        self.recv_until(|msg| {
            if let ServerMessage::Message(m) = msg {
                Some(m.clone())
            } else {
                None
            }
        })
        .await
    }
}

async fn do_pake(client: &mut RendezvousClient, code: &str, timeout: Duration) -> Result<Vec<u8>> {
    let (spake, outbound) = SpakeState::new(code, APP_ID);

    let pake_msg = PakeMsg {
        pake_v1: hex::encode(&outbound),
    };
    let pake_json = serde_json::to_string(&pake_msg)?;
    let pake_hex = hex::encode(pake_json.as_bytes());
    client.add("pake", &pake_hex).await?;

    let wait_for_peer = async {
        loop {
            let msg = client.recv_message().await?;
            if msg.phase == "pake" && msg.side != client.side_id {
                let pake_bytes = hex::decode(&msg.body)?;
                let pake_json = String::from_utf8(pake_bytes)?;
                let peer_pake: PakeMsg = serde_json::from_str(&pake_json)?;
                let peer_msg = hex::decode(&peer_pake.pake_v1)?;

                let shared_key = spake.finish(&peer_msg)?;
                return Ok(shared_key);
            }
        }
    };

    tokio::time::timeout(timeout, wait_for_peer)
        .await
        .context("Timed out waiting for peer to enter code")?
}

async fn exchange_versions(
    client: &mut RendezvousClient,
    shared_key: &[u8],
    timeout: Duration,
) -> Result<()> {
    let versions = GenericMessage {
        offer: None,
        answer: None,
        transit: None,
        app_versions: Some(AppVersions {
            app_versions: serde_json::json!({}),
        }),
        error: None,
    };
    let versions_json = serde_json::to_string(&versions)?;
    let encrypted = encrypt_message(
        shared_key,
        &client.side_id,
        "version",
        versions_json.as_bytes(),
    )?;
    client.add("version", &encrypted).await?;

    let wait_for_peer = async {
        loop {
            let msg = client.recv_message().await?;
            if msg.phase == "version" && msg.side != client.side_id {
                let _ = decrypt_message(shared_key, &msg.side, "version", &msg.body)?;
                return Ok(());
            }
        }
    };

    tokio::time::timeout(timeout, wait_for_peer)
        .await
        .context("Timed out waiting for peer version exchange")?
}

async fn send_app_data(
    client: &mut RendezvousClient,
    shared_key: &[u8],
    phase: u32,
    data: &GenericMessage,
) -> Result<()> {
    let json = serde_json::to_string(data)?;
    let encrypted = encrypt_message(
        shared_key,
        &client.side_id,
        &phase.to_string(),
        json.as_bytes(),
    )?;
    client.add(&phase.to_string(), &encrypted).await?;
    Ok(())
}

async fn recv_app_data(
    client: &mut RendezvousClient,
    shared_key: &[u8],
) -> Result<(String, GenericMessage)> {
    loop {
        let msg = client.recv_message().await?;
        if msg.side != client.side_id && msg.phase.parse::<u32>().is_ok() {
            let decrypted = decrypt_message(shared_key, &msg.side, &msg.phase, &msg.body)?;
            let data: GenericMessage = serde_json::from_slice(&decrypted)?;
            return Ok((msg.phase, data));
        }
    }
}

async fn recv_app_data_timeout(
    client: &mut RendezvousClient,
    shared_key: &[u8],
    timeout: Duration,
) -> Result<(String, GenericMessage)> {
    tokio::time::timeout(timeout, recv_app_data(client, shared_key))
        .await
        .context("Timed out waiting for peer response")?
}

/// Allocate or use provided code, claim mailbox, print instructions
async fn setup_sender(
    client: &mut RendezvousClient,
    code: Option<&str>,
    code_length: usize,
) -> Result<(String, String)> {
    let (code, nameplate) = if let Some(c) = code {
        let np = nameplate_from_code(c)?;
        (c.to_string(), np.to_string())
    } else {
        let nameplate = client.allocate().await?;
        let passphrase = wordlist::generate_passphrase(code_length);
        let code = format!("{}-{}", nameplate, passphrase);
        (code, nameplate)
    };

    let mailbox = client.claim(&nameplate).await?;
    client.open(&mailbox).await?;

    println!("Wormhole code is: {}", code);
    println!("On the other computer, please run:");
    println!("  wormhole-rs recv {}", code);

    Ok((code, nameplate))
}

/// Verify shared key with user confirmation
async fn verify_key(
    client: &mut RendezvousClient,
    shared_key: &[u8],
    verify: bool,
    is_sender: bool,
) -> Result<()> {
    if verify {
        let verifier = derive_verifier(shared_key);
        println!("Verifier: {}", hex::encode(&verifier[..8]));
        let peer = if is_sender { "receiver" } else { "sender" };
        eprint!("Verify this matches the {}? (yes/no): ", peer);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            client.close(Mood::Errory).await?;
            client.shutdown().await?;
            anyhow::bail!("Verification rejected");
        }
    }
    Ok(())
}

/// Wait for peer transit hints and file acknowledgment
async fn wait_for_transit_ack(
    client: &mut RendezvousClient,
    shared_key: &[u8],
    timeout: Duration,
) -> Result<Transit> {
    let wait_for_peer = async {
        let mut peer_transit = None;
        let mut answer_received = false;

        while !answer_received || peer_transit.is_none() {
            let (_, msg) = recv_app_data(client, shared_key).await?;

            if let Some(err) = msg.error {
                anyhow::bail!("Transfer error: {}", err);
            }

            if let Some(t) = msg.transit {
                peer_transit = Some(t);
            }

            if let Some(ans) = msg.answer
                && ans.file_ack == Some("ok".to_string())
            {
                answer_received = true;
            }
        }

        peer_transit.context("No transit hints from peer")
    };

    tokio::time::timeout(timeout, wait_for_peer)
        .await
        .context("Timed out waiting for peer to accept transfer")?
}

/// Prompt user to accept transfer, return false if rejected
fn prompt_accept(prompt: &str) -> Result<bool> {
    println!("{}", prompt);
    eprint!("Accept? (y/n): ");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_lowercase() == "y")
}

/// Handle transfer rejection
async fn handle_rejection(client: &mut RendezvousClient, shared_key: &[u8]) -> Result<()> {
    send_app_data(client, shared_key, 0, &build_reject()).await?;
    client.close(Mood::Happy).await?;
    client.shutdown().await?;
    anyhow::bail!("Transfer rejected");
}

/// Send a text message through the wormhole
pub async fn send_text(text: &str, config: &SendConfig<'_>) -> Result<()> {
    let mut client = RendezvousClient::connect(config.relay_url, config.connect_timeout).await?;
    client.bind().await?;

    let (code, nameplate) = setup_sender(&mut client, config.code, config.code_length).await?;
    let shared_key = do_pake(&mut client, &code, config.peer_timeout).await?;

    verify_key(&mut client, &shared_key, config.verify, true).await?;
    exchange_versions(&mut client, &shared_key, config.peer_timeout).await?;

    send_app_data(&mut client, &shared_key, 0, &build_text_offer(text)).await?;

    let (_, answer) = recv_app_data_timeout(&mut client, &shared_key, config.peer_timeout).await?;

    if let Some(err) = answer.error {
        anyhow::bail!("Transfer error: {}", err);
    }

    if let Some(ans) = answer.answer
        && ans.message_ack == Some("ok".to_string())
    {
        println!("text message sent");
    }

    client.graceful_close(&nameplate, Mood::Happy).await;

    Ok(())
}

/// Send a file through the wormhole
pub async fn send_file(path: &Path, config: &SendConfig<'_>) -> Result<()> {
    let metadata = tokio::fs::metadata(path).await?;
    let original_filename = path
        .file_name()
        .context("Invalid filename")?
        .to_string_lossy()
        .to_string();
    let original_size = metadata.len();

    // Prepare file data based on compression
    let (data, filename, filesize, mode, orig_size) = match config.compression {
        transit::Compression::Zstd => {
            let compressed = transit::compress_file(path).await?;
            let compressed_size = compressed.len() as u64;
            (
                Some(compressed),
                format!("{}.zst", original_filename),
                compressed_size,
                Some("zstd".to_string()),
                Some(original_size),
            )
        }
        transit::Compression::Zip => {
            // No compression for single files in zip mode
            (None, original_filename, original_size, None, None)
        }
    };

    let mut client = RendezvousClient::connect(config.relay_url, config.connect_timeout).await?;
    client.bind().await?;

    let (code, nameplate) = setup_sender(&mut client, config.code, config.code_length).await?;
    let shared_key = do_pake(&mut client, &code, config.peer_timeout).await?;

    verify_key(&mut client, &shared_key, config.verify, true).await?;
    exchange_versions(&mut client, &shared_key, config.peer_timeout).await?;

    let transit_key = derive_transit_key(&shared_key, APP_ID);

    // Create direct listener for peer to connect to us
    let listener = transit::create_direct_listener().await.ok();
    let hints = listener
        .as_ref()
        .map(|l| l.hints.clone())
        .unwrap_or_default();

    send_app_data(&mut client, &shared_key, 0, &build_transit_message(hints)).await?;
    send_app_data(
        &mut client,
        &shared_key,
        1,
        &build_file_offer(filename, filesize, mode, orig_size),
    )
    .await?;

    let peer_transit = wait_for_transit_ack(&mut client, &shared_key, config.peer_timeout).await?;
    let conn = transit::connect_as_sender(
        &transit_key,
        &peer_transit,
        config.transit_relay,
        config.connect_timeout,
        listener,
    )
    .await?;

    if let Some(compressed_data) = data {
        // Send compressed data from memory
        let mut cursor = std::io::Cursor::new(compressed_data);
        transit::send_file(&conn, &mut cursor, filesize, config.hide_progress).await?;
    } else {
        // Send file directly
        let mut file = File::open(path).await?;
        transit::send_file(&conn, &mut file, filesize, config.hide_progress).await?;
    }

    println!("file sent");

    client.graceful_close(&nameplate, Mood::Happy).await;

    Ok(())
}

/// Send a directory through the wormhole
pub async fn send_directory(path: &Path, config: &SendConfig<'_>) -> Result<()> {
    let (zip_data, num_files, num_bytes) =
        transit::create_archive(path, config.compression).await?;
    let dirname = path
        .file_name()
        .context("Invalid directory name")?
        .to_string_lossy()
        .to_string();
    let zipsize = zip_data.len() as u64;

    let mut client = RendezvousClient::connect(config.relay_url, config.connect_timeout).await?;
    client.bind().await?;

    let (code, nameplate) = setup_sender(&mut client, config.code, config.code_length).await?;
    let shared_key = do_pake(&mut client, &code, config.peer_timeout).await?;

    verify_key(&mut client, &shared_key, config.verify, true).await?;
    exchange_versions(&mut client, &shared_key, config.peer_timeout).await?;

    let transit_key = derive_transit_key(&shared_key, APP_ID);

    // Create direct listener for peer to connect to us
    let listener = transit::create_direct_listener().await.ok();
    let hints = listener
        .as_ref()
        .map(|l| l.hints.clone())
        .unwrap_or_default();

    send_app_data(&mut client, &shared_key, 0, &build_transit_message(hints)).await?;
    send_app_data(
        &mut client,
        &shared_key,
        1,
        &build_directory_offer(dirname, num_files, num_bytes, zipsize, config.compression),
    )
    .await?;

    let peer_transit = wait_for_transit_ack(&mut client, &shared_key, config.peer_timeout).await?;
    let conn = transit::connect_as_sender(
        &transit_key,
        &peer_transit,
        config.transit_relay,
        config.connect_timeout,
        listener,
    )
    .await?;

    let mut cursor = std::io::Cursor::new(zip_data);
    transit::send_file(&conn, &mut cursor, zipsize, config.hide_progress).await?;

    println!("directory sent");

    client.graceful_close(&nameplate, Mood::Happy).await;

    Ok(())
}

/// Receive a file, directory, or text message through the wormhole
pub async fn receive(code: &str, config: &ReceiveConfig<'_>) -> Result<()> {
    let nameplate = nameplate_from_code(code)?;

    let mut client = RendezvousClient::connect(config.relay_url, config.connect_timeout).await?;
    client.bind().await?;

    let mailbox = client.claim(nameplate).await?;
    client.open(&mailbox).await?;

    let shared_key = do_pake(&mut client, code, config.peer_timeout).await?;

    verify_key(&mut client, &shared_key, config.verify, false).await?;
    exchange_versions(&mut client, &shared_key, config.peer_timeout).await?;

    // Wait for offer with timeout
    let (offer, peer_transit) = {
        let wait_for_offer = async {
            let mut offer = None;
            let mut peer_transit = None;

            while offer.is_none() {
                let (_, msg) = recv_app_data(&mut client, &shared_key).await?;

                if let Some(err) = msg.error {
                    anyhow::bail!("Transfer error: {}", err);
                }

                if let Some(t) = msg.transit {
                    peer_transit = Some(t);
                }

                if let Some(o) = msg.offer {
                    offer = Some(o);
                }
            }

            Ok::<_, anyhow::Error>((offer.unwrap(), peer_transit))
        };

        tokio::time::timeout(config.peer_timeout, wait_for_offer)
            .await
            .context("Timed out waiting for sender's offer")??
    };

    if let Some(text) = offer.message {
        send_app_data(&mut client, &shared_key, 0, &build_message_ack()).await?;
        println!("{}", text);
        client.graceful_close(nameplate, Mood::Happy).await;
    } else if let Some(file_offer) = offer.file {
        // Determine if file is compressed
        let is_compressed = file_offer.mode.as_deref() == Some("zstd");

        // Use original filename (strip .zst if compressed)
        let final_filename = if is_compressed {
            file_offer
                .filename
                .strip_suffix(".zst")
                .unwrap_or(&file_offer.filename)
                .to_string()
        } else {
            file_offer.filename.clone()
        };

        let output_path = config
            .output_dir
            .map(|d| d.join(&final_filename))
            .unwrap_or_else(|| std::path::PathBuf::from(&final_filename));

        if !config.auto_accept {
            let prompt = if is_compressed {
                let orig_size = file_offer.original_size.unwrap_or(file_offer.filesize);
                format!(
                    "Receiving file ({} bytes, compressed): {}",
                    orig_size, final_filename
                )
            } else {
                format!(
                    "Receiving file ({} bytes): {}",
                    file_offer.filesize, file_offer.filename
                )
            };
            if !prompt_accept(&prompt)? {
                handle_rejection(&mut client, &shared_key).await?;
            }
        }

        let transit_key = derive_transit_key(&shared_key, APP_ID);

        // Create direct listener for peer to connect to us
        let listener = transit::create_direct_listener().await.ok();
        let hints = listener
            .as_ref()
            .map(|l| l.hints.clone())
            .unwrap_or_default();

        send_app_data(&mut client, &shared_key, 0, &build_transit_message(hints)).await?;
        send_app_data(&mut client, &shared_key, 1, &build_file_ack()).await?;

        let peer_transit = peer_transit.context("No transit hints from sender")?;
        let conn = transit::connect_as_receiver(
            &transit_key,
            &peer_transit,
            config.transit_relay,
            config.connect_timeout,
            listener,
        )
        .await?;

        if is_compressed {
            // Receive compressed data, decompress, write to file
            let compressed_data =
                transit::receive_to_vec(&conn, file_offer.filesize, config.hide_progress).await?;
            let decompressed = transit::decompress_zstd(&compressed_data).await?;
            tokio::fs::write(&output_path, &decompressed).await?;
        } else {
            // Receive directly to file
            let mut file = File::create(&output_path).await?;
            transit::receive_file(&conn, &mut file, file_offer.filesize, config.hide_progress)
                .await?;
        }

        println!("Received file: {}", output_path.display());

        client.graceful_close(nameplate, Mood::Happy).await;
    } else if let Some(dir_offer) = offer.directory {
        let output_path = config
            .output_dir
            .map(|d| d.join(&dir_offer.dirname))
            .unwrap_or_else(|| std::path::PathBuf::from(&dir_offer.dirname));

        if !config.auto_accept {
            let prompt = format!(
                "Receiving directory ({} files, {} bytes): {}",
                dir_offer.numfiles, dir_offer.numbytes, dir_offer.dirname
            );
            if !prompt_accept(&prompt)? {
                handle_rejection(&mut client, &shared_key).await?;
            }
        }

        let transit_key = derive_transit_key(&shared_key, APP_ID);

        // Create direct listener for peer to connect to us
        let listener = transit::create_direct_listener().await.ok();
        let hints = listener
            .as_ref()
            .map(|l| l.hints.clone())
            .unwrap_or_default();

        send_app_data(&mut client, &shared_key, 0, &build_transit_message(hints)).await?;
        send_app_data(&mut client, &shared_key, 1, &build_file_ack()).await?;

        let peer_transit = peer_transit.context("No transit hints from sender")?;
        let conn = transit::connect_as_receiver(
            &transit_key,
            &peer_transit,
            config.transit_relay,
            config.connect_timeout,
            listener,
        )
        .await?;

        let zip_data =
            transit::receive_to_vec(&conn, dir_offer.zipsize, config.hide_progress).await?;
        let compression = transit::Compression::from_mode(&dir_offer.mode);
        transit::extract_archive(&zip_data, &output_path, compression).await?;

        println!("Received directory: {}", output_path.display());

        client.graceful_close(nameplate, Mood::Happy).await;
    } else {
        anyhow::bail!("Unknown offer type");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nameplate_from_code() {
        assert_eq!(nameplate_from_code("7-guitarist-revenge").unwrap(), "7");
        assert_eq!(nameplate_from_code("123-foo-bar").unwrap(), "123");
        assert!(nameplate_from_code("abc-foo-bar").is_err());
        assert!(nameplate_from_code("").is_err());
    }
}
