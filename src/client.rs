use std::path::Path;

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
use crate::{AGENT_STRING, AGENT_VERSION, APP_ID};

fn nameplate_from_code(code: &str) -> Result<&str> {
    let nameplate = code.split('-').next().context("Invalid code format")?;
    nameplate
        .parse::<u32>()
        .context("Nameplate must be a number")?;
    Ok(nameplate)
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
    async fn connect(relay_url: &str) -> Result<Self> {
        let (ws_stream, _) = connect_async(relay_url)
            .await
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

async fn do_pake(client: &mut RendezvousClient, code: &str) -> Result<Vec<u8>> {
    let (spake, outbound) = SpakeState::new(code, APP_ID);

    let pake_msg = PakeMsg {
        pake_v1: hex::encode(&outbound),
    };
    let pake_json = serde_json::to_string(&pake_msg)?;
    let pake_hex = hex::encode(pake_json.as_bytes());
    client.add("pake", &pake_hex).await?;

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
}

async fn exchange_versions(client: &mut RendezvousClient, shared_key: &[u8]) -> Result<()> {
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

    loop {
        let msg = client.recv_message().await?;
        if msg.phase == "version" && msg.side != client.side_id {
            let _ = decrypt_message(shared_key, &msg.side, "version", &msg.body)?;
            return Ok(());
        }
    }
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

/// Send a text message through the wormhole
pub async fn send_text(
    relay_url: &str,
    _transit_relay: &str,
    text: &str,
    code: Option<&str>,
    code_length: usize,
    verify: bool,
) -> Result<()> {
    let mut client = RendezvousClient::connect(relay_url).await?;
    client.bind().await?;

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

    let shared_key = do_pake(&mut client, &code).await?;

    if verify {
        let verifier = derive_verifier(&shared_key);
        println!("Verifier: {}", hex::encode(&verifier[..8]));
        eprint!("Verify this matches the receiver? (yes/no): ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            client.close(Mood::Errory).await?;
            anyhow::bail!("Verification rejected");
        }
    }

    exchange_versions(&mut client, &shared_key).await?;

    let offer = GenericMessage {
        offer: Some(Offer {
            message: Some(text.to_string()),
            file: None,
            directory: None,
        }),
        answer: None,
        transit: None,
        app_versions: None,
        error: None,
    };
    send_app_data(&mut client, &shared_key, 0, &offer).await?;

    let (_, answer) = recv_app_data(&mut client, &shared_key).await?;

    if let Some(err) = answer.error {
        anyhow::bail!("Transfer error: {}", err);
    }

    if let Some(ans) = answer.answer
        && ans.message_ack == Some("ok".to_string())
    {
        println!("text message sent");
    }

    client.release(&nameplate).await?;
    client.close(Mood::Happy).await?;

    Ok(())
}

/// Send a file through the wormhole
pub async fn send_file(
    relay_url: &str,
    transit_relay: &str,
    path: &Path,
    code: Option<&str>,
    code_length: usize,
    verify: bool,
    hide_progress: bool,
) -> Result<()> {
    let metadata = tokio::fs::metadata(path).await?;
    let filename = path
        .file_name()
        .context("Invalid filename")?
        .to_string_lossy()
        .to_string();
    let filesize = metadata.len();

    let mut client = RendezvousClient::connect(relay_url).await?;
    client.bind().await?;

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

    let shared_key = do_pake(&mut client, &code).await?;

    if verify {
        let verifier = derive_verifier(&shared_key);
        println!("Verifier: {}", hex::encode(&verifier[..8]));
        eprint!("Verify this matches the receiver? (yes/no): ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            client.close(Mood::Errory).await?;
            anyhow::bail!("Verification rejected");
        }
    }

    exchange_versions(&mut client, &shared_key).await?;

    let transit_key = derive_transit_key(&shared_key, APP_ID);
    let transit_msg = GenericMessage {
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
            hints_v1: transit::get_direct_hints().await,
        }),
        app_versions: None,
        error: None,
    };
    send_app_data(&mut client, &shared_key, 0, &transit_msg).await?;

    let offer = GenericMessage {
        offer: Some(Offer {
            message: None,
            file: Some(OfferFile { filename, filesize }),
            directory: None,
        }),
        answer: None,
        transit: None,
        app_versions: None,
        error: None,
    };
    send_app_data(&mut client, &shared_key, 1, &offer).await?;

    let mut peer_transit = None;
    let mut answer_received = false;

    while !answer_received || peer_transit.is_none() {
        let (_, msg) = recv_app_data(&mut client, &shared_key).await?;

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

    let peer_transit = peer_transit.context("No transit hints from peer")?;
    let conn = transit::connect_as_sender(&transit_key, &peer_transit, transit_relay).await?;

    let mut file = File::open(path).await?;
    transit::send_file(&conn, &mut file, filesize, hide_progress).await?;

    println!("file sent");

    client.release(&nameplate).await?;
    client.close(Mood::Happy).await?;

    Ok(())
}

/// Send a directory through the wormhole
pub async fn send_directory(
    relay_url: &str,
    transit_relay: &str,
    path: &Path,
    code: Option<&str>,
    code_length: usize,
    verify: bool,
    hide_progress: bool,
) -> Result<()> {
    let (zip_data, num_files, num_bytes) = transit::create_zip(path).await?;
    let dirname = path
        .file_name()
        .context("Invalid directory name")?
        .to_string_lossy()
        .to_string();
    let zipsize = zip_data.len() as u64;

    let mut client = RendezvousClient::connect(relay_url).await?;
    client.bind().await?;

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

    let shared_key = do_pake(&mut client, &code).await?;

    if verify {
        let verifier = derive_verifier(&shared_key);
        println!("Verifier: {}", hex::encode(&verifier[..8]));
        eprint!("Verify this matches the receiver? (yes/no): ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            client.close(Mood::Errory).await?;
            anyhow::bail!("Verification rejected");
        }
    }

    exchange_versions(&mut client, &shared_key).await?;

    let transit_key = derive_transit_key(&shared_key, APP_ID);
    let transit_msg = GenericMessage {
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
            hints_v1: transit::get_direct_hints().await,
        }),
        app_versions: None,
        error: None,
    };
    send_app_data(&mut client, &shared_key, 0, &transit_msg).await?;

    let offer = GenericMessage {
        offer: Some(Offer {
            message: None,
            file: None,
            directory: Some(OfferDirectory {
                dirname,
                mode: "zipfile/deflated".to_string(),
                numbytes: num_bytes,
                numfiles: num_files,
                zipsize,
            }),
        }),
        answer: None,
        transit: None,
        app_versions: None,
        error: None,
    };
    send_app_data(&mut client, &shared_key, 1, &offer).await?;

    let mut peer_transit = None;
    let mut answer_received = false;

    while !answer_received || peer_transit.is_none() {
        let (_, msg) = recv_app_data(&mut client, &shared_key).await?;

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

    let peer_transit = peer_transit.context("No transit hints from peer")?;
    let conn = transit::connect_as_sender(&transit_key, &peer_transit, transit_relay).await?;

    let mut cursor = std::io::Cursor::new(zip_data);
    transit::send_file(&conn, &mut cursor, zipsize, hide_progress).await?;

    println!("directory sent");

    client.release(&nameplate).await?;
    client.close(Mood::Happy).await?;

    Ok(())
}

/// Receive a file, directory, or text message through the wormhole
pub async fn receive(
    relay_url: &str,
    transit_relay: &str,
    code: &str,
    output_dir: Option<&Path>,
    verify: bool,
    hide_progress: bool,
    auto_accept: bool,
) -> Result<()> {
    let nameplate = nameplate_from_code(code)?;

    let mut client = RendezvousClient::connect(relay_url).await?;
    client.bind().await?;

    let mailbox = client.claim(nameplate).await?;
    client.open(&mailbox).await?;

    let shared_key = do_pake(&mut client, code).await?;

    if verify {
        let verifier = derive_verifier(&shared_key);
        println!("Verifier: {}", hex::encode(&verifier[..8]));
        eprint!("Verify this matches the sender? (yes/no): ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            client.close(Mood::Errory).await?;
            anyhow::bail!("Verification rejected");
        }
    }

    exchange_versions(&mut client, &shared_key).await?;

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

    let offer = offer.unwrap();

    if let Some(text) = offer.message {
        let answer = GenericMessage {
            offer: None,
            answer: Some(Answer {
                message_ack: Some("ok".to_string()),
                file_ack: None,
            }),
            transit: None,
            app_versions: None,
            error: None,
        };
        send_app_data(&mut client, &shared_key, 0, &answer).await?;

        println!("{}", text);

        client.release(nameplate).await?;
        client.close(Mood::Happy).await?;
    } else if let Some(file_offer) = offer.file {
        let output_path = output_dir
            .map(|d| d.join(&file_offer.filename))
            .unwrap_or_else(|| std::path::PathBuf::from(&file_offer.filename));

        if !auto_accept {
            println!(
                "Receiving file ({} bytes): {}",
                file_offer.filesize, file_offer.filename
            );
            eprint!("Accept? (y/n): ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                let reject = GenericMessage {
                    offer: None,
                    answer: None,
                    transit: None,
                    app_versions: None,
                    error: Some("transfer rejected".to_string()),
                };
                send_app_data(&mut client, &shared_key, 0, &reject).await?;
                client.close(Mood::Happy).await?;
                anyhow::bail!("Transfer rejected");
            }
        }

        let transit_key = derive_transit_key(&shared_key, APP_ID);
        let transit_msg = GenericMessage {
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
                hints_v1: transit::get_direct_hints().await,
            }),
            app_versions: None,
            error: None,
        };
        send_app_data(&mut client, &shared_key, 0, &transit_msg).await?;

        let answer = GenericMessage {
            offer: None,
            answer: Some(Answer {
                message_ack: None,
                file_ack: Some("ok".to_string()),
            }),
            transit: None,
            app_versions: None,
            error: None,
        };
        send_app_data(&mut client, &shared_key, 1, &answer).await?;

        let peer_transit = peer_transit.context("No transit hints from sender")?;
        let conn = transit::connect_as_receiver(&transit_key, &peer_transit, transit_relay).await?;

        let mut file = File::create(&output_path).await?;
        transit::receive_file(&conn, &mut file, file_offer.filesize, hide_progress).await?;

        println!("Received file: {}", output_path.display());

        client.release(nameplate).await?;
        client.close(Mood::Happy).await?;
    } else if let Some(dir_offer) = offer.directory {
        let output_path = output_dir
            .map(|d| d.join(&dir_offer.dirname))
            .unwrap_or_else(|| std::path::PathBuf::from(&dir_offer.dirname));

        if !auto_accept {
            println!(
                "Receiving directory ({} files, {} bytes): {}",
                dir_offer.numfiles, dir_offer.numbytes, dir_offer.dirname
            );
            eprint!("Accept? (y/n): ");
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            if input.trim().to_lowercase() != "y" {
                let reject = GenericMessage {
                    offer: None,
                    answer: None,
                    transit: None,
                    app_versions: None,
                    error: Some("transfer rejected".to_string()),
                };
                send_app_data(&mut client, &shared_key, 0, &reject).await?;
                client.close(Mood::Happy).await?;
                anyhow::bail!("Transfer rejected");
            }
        }

        let transit_key = derive_transit_key(&shared_key, APP_ID);
        let transit_msg = GenericMessage {
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
                hints_v1: transit::get_direct_hints().await,
            }),
            app_versions: None,
            error: None,
        };
        send_app_data(&mut client, &shared_key, 0, &transit_msg).await?;

        let answer = GenericMessage {
            offer: None,
            answer: Some(Answer {
                message_ack: None,
                file_ack: Some("ok".to_string()),
            }),
            transit: None,
            app_versions: None,
            error: None,
        };
        send_app_data(&mut client, &shared_key, 1, &answer).await?;

        let peer_transit = peer_transit.context("No transit hints from sender")?;
        let conn = transit::connect_as_receiver(&transit_key, &peer_transit, transit_relay).await?;

        let zip_data = transit::receive_to_vec(&conn, dir_offer.zipsize, hide_progress).await?;
        transit::extract_zip(&zip_data, &output_path).await?;

        println!("Received directory: {}", output_path.display());

        client.release(nameplate).await?;
        client.close(Mood::Happy).await?;
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
