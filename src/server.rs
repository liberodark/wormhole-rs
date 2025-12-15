use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, broadcast};
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use crate::messages::{
    Ack, AllocatedResp, ClaimedResp, ClientMessage, ClosedResp, ErrorMsg, NameplateEntry,
    NameplatesResp, ReleasedResp, ServerMessage, Welcome, WelcomeInfo,
};

/// Server configuration
pub struct ServerConfig {
    pub motd: String,
    pub cli_version: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            motd: "Welcome to wormhole-rs relay server".to_string(),
            cli_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Mailbox for message exchange between two sides
struct Mailbox {
    #[allow(dead_code)]
    id: String,
    messages: Vec<MailboxMessage>,
    sides: Vec<String>,
    sender: broadcast::Sender<MailboxMessage>,
}

#[derive(Clone, Debug)]
struct MailboxMessage {
    id: String,
    side: String,
    phase: String,
    body: String,
    server_rx: f64,
}

impl Mailbox {
    fn new(id: String) -> Self {
        let (sender, _) = broadcast::channel(100);
        Self {
            id,
            messages: Vec::new(),
            sides: Vec::new(),
            sender,
        }
    }

    fn add_side(&mut self, side: &str) -> bool {
        if self.sides.len() >= 2 {
            return false; // Crowded
        }
        if !self.sides.contains(&side.to_string()) {
            self.sides.push(side.to_string());
        }
        true
    }

    fn add_message(&mut self, id: &str, side: &str, phase: &str, body: &str) {
        let msg = MailboxMessage {
            id: id.to_string(),
            side: side.to_string(),
            phase: phase.to_string(),
            body: body.to_string(),
            server_rx: server_timestamp(),
        };
        self.messages.push(msg.clone());
        let _ = self.sender.send(msg);
    }

    fn subscribe(&self) -> broadcast::Receiver<MailboxMessage> {
        self.sender.subscribe()
    }
}

/// Server state shared across connections
struct ServerState {
    config: ServerConfig,
    nameplates: RwLock<HashMap<String, String>>, // nameplate -> mailbox_id
    mailboxes: RwLock<HashMap<String, Arc<Mutex<Mailbox>>>>,
    next_nameplate: Mutex<u32>,
}

impl ServerState {
    fn new(config: ServerConfig) -> Self {
        Self {
            config,
            nameplates: RwLock::new(HashMap::new()),
            mailboxes: RwLock::new(HashMap::new()),
            next_nameplate: Mutex::new(1),
        }
    }

    async fn allocate_nameplate(&self) -> (String, String) {
        let mut next = self.next_nameplate.lock().await;
        let nameplate = next.to_string();
        *next += 1;

        let mailbox_id = crate::crypto::random_hex(20);
        let mailbox = Mailbox::new(mailbox_id.clone());

        self.nameplates
            .write()
            .await
            .insert(nameplate.clone(), mailbox_id.clone());
        self.mailboxes
            .write()
            .await
            .insert(mailbox_id.clone(), Arc::new(Mutex::new(mailbox)));

        (nameplate, mailbox_id)
    }

    async fn claim_nameplate(&self, nameplate: &str, side: &str) -> Option<String> {
        let mailboxes = self.mailboxes.read().await;
        let nameplates = self.nameplates.read().await;

        if let Some(mailbox_id) = nameplates.get(nameplate) {
            if let Some(mailbox) = mailboxes.get(mailbox_id) {
                let mut mb = mailbox.lock().await;
                if mb.add_side(side) {
                    return Some(mailbox_id.clone());
                }
            }
        } else {
            drop(nameplates);
            drop(mailboxes);

            let mailbox_id = crate::crypto::random_hex(20);
            let mut mailbox = Mailbox::new(mailbox_id.clone());
            mailbox.add_side(side);

            self.nameplates
                .write()
                .await
                .insert(nameplate.to_string(), mailbox_id.clone());
            self.mailboxes
                .write()
                .await
                .insert(mailbox_id.clone(), Arc::new(Mutex::new(mailbox)));

            return Some(mailbox_id);
        }

        None
    }

    async fn release_nameplate(&self, nameplate: &str) {
        self.nameplates.write().await.remove(nameplate);
    }

    async fn get_mailbox(&self, mailbox_id: &str) -> Option<Arc<Mutex<Mailbox>>> {
        self.mailboxes.read().await.get(mailbox_id).cloned()
    }

    async fn list_nameplates(&self) -> Vec<String> {
        self.nameplates.read().await.keys().cloned().collect()
    }
}

fn server_timestamp() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

/// Handle a single WebSocket connection
async fn handle_websocket(stream: TcpStream, addr: SocketAddr, state: Arc<ServerState>) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            eprintln!("[{}] WebSocket handshake failed: {}", addr, e);
            return;
        }
    };

    println!("[{}] New WebSocket connection", addr);
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let welcome = ServerMessage::Welcome(Welcome {
        welcome: WelcomeInfo {
            motd: state.config.motd.clone(),
            current_cli_version: state.config.cli_version.clone(),
            error: None,
        },
        server_tx: Some(server_timestamp()),
    });

    if let Ok(json) = serde_json::to_string(&welcome) {
        let _ = ws_sender.send(Message::Text(json.into())).await;
    }

    let mut side_id: Option<String> = None;
    let mut open_mailbox: Option<Arc<Mutex<Mailbox>>> = None;
    let mut mailbox_receiver: Option<broadcast::Receiver<MailboxMessage>> = None;

    loop {
        tokio::select! {
            msg = ws_receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let client_msg: Result<ClientMessage, _> = serde_json::from_str(&text);

                        match client_msg {
                            Ok(ClientMessage::Bind(bind)) => {
                                side_id = Some(bind.side.clone());
                                let ack = ServerMessage::Ack(Ack {
                                    id: None,
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }
                            }

                            Ok(ClientMessage::Allocate(alloc)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(alloc.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                let (nameplate, _) = state.allocate_nameplate().await;
                                let resp = ServerMessage::Allocated(AllocatedResp {
                                    nameplate,
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }
                            }

                            Ok(ClientMessage::Claim(claim)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(claim.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                let side = side_id.as_deref().unwrap_or("unknown");
                                if let Some(mailbox_id) = state.claim_nameplate(&claim.nameplate, side).await {
                                    let resp = ServerMessage::Claimed(ClaimedResp {
                                        mailbox: mailbox_id,
                                        server_tx: Some(server_timestamp()),
                                    });
                                    if let Ok(json) = serde_json::to_string(&resp) {
                                        let _ = ws_sender.send(Message::Text(json.into())).await;
                                    }
                                } else {
                                    let err = ServerMessage::Error(ErrorMsg {
                                        error: "crowded".to_string(),
                                        orig: None,
                                        server_tx: Some(server_timestamp()),
                                    });
                                    if let Ok(json) = serde_json::to_string(&err) {
                                        let _ = ws_sender.send(Message::Text(json.into())).await;
                                    }
                                }
                            }

                            Ok(ClientMessage::Open(open)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(open.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                if let Some(mailbox) = state.get_mailbox(&open.mailbox).await {
                                    {
                                        let mb = mailbox.lock().await;
                                        for msg in &mb.messages {
                                            let server_msg = ServerMessage::Message(crate::messages::Message {
                                                id: msg.id.clone(),
                                                side: msg.side.clone(),
                                                phase: msg.phase.clone(),
                                                body: msg.body.clone(),
                                                server_rx: Some(msg.server_rx),
                                                server_tx: Some(server_timestamp()),
                                            });
                                            if let Ok(json) = serde_json::to_string(&server_msg) {
                                                let _ = ws_sender.send(Message::Text(json.into())).await;
                                            }
                                        }
                                        mailbox_receiver = Some(mb.subscribe());
                                    }
                                    open_mailbox = Some(mailbox);
                                }
                            }

                            Ok(ClientMessage::Add(add)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(add.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                if let Some(ref mailbox) = open_mailbox {
                                    let side = side_id.as_deref().unwrap_or("unknown");
                                    let mut mb = mailbox.lock().await;
                                    mb.add_message(&add.id, side, &add.phase, &add.body);
                                }
                            }

                            Ok(ClientMessage::List(list)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(list.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                let nameplates = state.list_nameplates().await;
                                let resp = ServerMessage::Nameplates(NameplatesResp {
                                    nameplates: nameplates
                                        .into_iter()
                                        .map(|id| NameplateEntry { id })
                                        .collect(),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }
                            }

                            Ok(ClientMessage::Release(release)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(release.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                state.release_nameplate(&release.nameplate).await;

                                let resp = ServerMessage::Released(ReleasedResp {
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }
                            }

                            Ok(ClientMessage::Close(close)) => {
                                let ack = ServerMessage::Ack(Ack {
                                    id: Some(close.id.clone()),
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&ack) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }

                                let resp = ServerMessage::Closed(ClosedResp {
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }
                            }

                            Ok(ClientMessage::Ping(ping)) => {
                                let resp = ServerMessage::Pong(crate::messages::Pong {
                                    pong: ping.ping,
                                    server_tx: Some(server_timestamp()),
                                });
                                if let Ok(json) = serde_json::to_string(&resp) {
                                    let _ = ws_sender.send(Message::Text(json.into())).await;
                                }
                            }

                            Err(e) => {
                                eprintln!("[{}] Failed to parse message: {} - {}", addr, e, text);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        println!("[{}] Connection closed", addr);
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        eprintln!("[{}] WebSocket error: {}", addr, e);
                        break;
                    }
                }
            }

            msg = async {
                if let Some(ref mut receiver) = mailbox_receiver {
                    receiver.recv().await.ok()
                } else {
                    std::future::pending::<Option<MailboxMessage>>().await
                }
            } => {
                if let Some(msg) = msg
                    && side_id.as_deref() != Some(&msg.side)
                {
                    let server_msg = ServerMessage::Message(crate::messages::Message {
                        id: msg.id,
                        side: msg.side,
                        phase: msg.phase,
                        body: msg.body,
                        server_rx: Some(msg.server_rx),
                        server_tx: Some(server_timestamp()),
                    });
                    if let Ok(json) = serde_json::to_string(&server_msg) {
                        let _ = ws_sender.send(Message::Text(json.into())).await;
                    }
                }
            }
        }
    }
}

/// Handle transit relay connection
async fn handle_relay(mut stream: TcpStream, addr: SocketAddr, relay_state: Arc<RelayState>) {
    let mut header = [0u8; 128];
    let mut pos = 0;

    loop {
        if pos >= header.len() {
            eprintln!("[{}] Relay header too long", addr);
            return;
        }

        match stream.read(&mut header[pos..pos + 1]).await {
            Ok(0) => return,
            Ok(_) => {
                if header[pos] == b'\n' {
                    break;
                }
                pos += 1;
            }
            Err(_) => return,
        }
    }

    let header_str = String::from_utf8_lossy(&header[..pos]);

    if !header_str.starts_with("please relay ") {
        eprintln!("[{}] Invalid relay header: {}", addr, header_str);
        return;
    }

    let parts: Vec<&str> = header_str.split_whitespace().collect();
    if parts.len() < 5 || parts[3] != "for" || parts[4] != "side" {
        eprintln!("[{}] Invalid relay header format", addr);
        return;
    }

    let token = parts[2];
    let side = parts.get(5).unwrap_or(&"unknown");

    println!("[{}] Relay request: token={}, side={}", addr, token, side);

    let peer = {
        let mut waiters = relay_state.waiters.lock().await;
        waiters.remove(token)
    };

    match peer {
        Some(mut peer_stream) => {
            println!("[{}] Connecting to peer", addr);

            let _ = stream.write_all(b"ok\n").await;
            let _ = peer_stream.write_all(b"ok\n").await;

            let (mut r1, mut w1) = stream.into_split();
            let (mut r2, mut w2) = peer_stream.into_split();

            let t1 = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut r1, &mut w2).await;
            });

            let t2 = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut r2, &mut w1).await;
            });

            let _ = tokio::join!(t1, t2);
            println!("[{}] Relay session ended", addr);
        }
        None => {
            println!("[{}] Waiting for peer...", addr);
            relay_state
                .waiters
                .lock()
                .await
                .insert(token.to_string(), stream);
        }
    }
}

/// State for transit relay - maps tokens to waiting connections
struct RelayState {
    waiters: Mutex<HashMap<String, TcpStream>>,
}

/// Run the wormhole server (rendezvous + transit relay)
pub async fn run(bind: &str, ws_port: u16, relay_port: u16, motd: Option<&str>) -> Result<()> {
    let config = ServerConfig {
        motd: motd.unwrap_or(&ServerConfig::default().motd).to_string(),
        ..Default::default()
    };

    let state = Arc::new(ServerState::new(config));
    let relay_state = Arc::new(RelayState {
        waiters: Mutex::new(HashMap::new()),
    });

    let ws_addr = format!("{}:{}", bind, ws_port);
    let ws_listener = TcpListener::bind(&ws_addr).await?;
    println!("Rendezvous server listening on ws://{}", ws_addr);

    let relay_addr = format!("{}:{}", bind, relay_port);
    let relay_listener = TcpListener::bind(&relay_addr).await?;
    println!("Transit relay listening on {}", relay_addr);

    loop {
        tokio::select! {
            Ok((stream, addr)) = ws_listener.accept() => {
                let state = Arc::clone(&state);
                tokio::spawn(handle_websocket(stream, addr, state));
            }
            Ok((stream, addr)) = relay_listener.accept() => {
                let relay_state = Arc::clone(&relay_state);
                tokio::spawn(handle_relay(stream, addr, relay_state));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert!(!config.motd.is_empty());
        assert!(!config.cli_version.is_empty());
    }

    #[tokio::test]
    async fn test_allocate_nameplate() {
        let state = ServerState::new(ServerConfig::default());

        let (np1, _) = state.allocate_nameplate().await;
        let (np2, _) = state.allocate_nameplate().await;

        assert_eq!(np1, "1");
        assert_eq!(np2, "2");
    }

    #[tokio::test]
    async fn test_claim_nameplate() {
        let state = ServerState::new(ServerConfig::default());

        let mailbox1 = state.claim_nameplate("42", "side1").await;
        assert!(mailbox1.is_some());

        let mailbox2 = state.claim_nameplate("42", "side2").await;
        assert!(mailbox2.is_some());

        let mailbox3 = state.claim_nameplate("42", "side3").await;
        assert!(mailbox3.is_none()); // Crowded
    }

    #[tokio::test]
    async fn test_list_nameplates() {
        let state = ServerState::new(ServerConfig::default());

        let _ = state.allocate_nameplate().await;
        let _ = state.allocate_nameplate().await;

        let nameplates = state.list_nameplates().await;
        assert_eq!(nameplates.len(), 2);
    }
}
