use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    pub welcome: WelcomeInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeInfo {
    #[serde(default)]
    pub motd: String,
    #[serde(default)]
    pub current_cli_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ack {
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocatedResp {
    pub nameplate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimedResp {
    pub mailbox: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub side: String,
    pub phase: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_rx: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameplatesResp {
    pub nameplates: Vec<NameplateEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameplateEntry {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleasedResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosedResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMsg {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orig: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bind {
    pub side: String,
    pub appid: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_version: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allocate {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: String,
    pub nameplate: String,
}

/// Open a mailbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Open {
    pub id: String,
    pub mailbox: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Add {
    pub id: String,
    pub phase: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct List {
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub id: String,
    pub nameplate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Close {
    pub id: String,
    pub mailbox: String,
    pub mood: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {
    pub id: String,
    pub ping: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {
    pub pong: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_tx: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    Bind(Bind),
    Allocate(Allocate),
    Claim(Claim),
    Open(Open),
    Add(Add),
    List(List),
    Release(Release),
    Close(Close),
    Ping(Ping),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    Welcome(Welcome),
    Ack(Ack),
    Allocated(AllocatedResp),
    Claimed(ClaimedResp),
    Message(Message),
    Nameplates(NameplatesResp),
    Released(ReleasedResp),
    Closed(ClosedResp),
    Pong(Pong),
    Error(ErrorMsg),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PakeMsg {
    pub pake_v1: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppVersions {
    #[serde(default)]
    pub app_versions: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<Offer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<Answer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transit: Option<Transit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_versions: Option<AppVersions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<OfferFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory: Option<OfferDirectory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferFile {
    pub filename: String,
    pub filesize: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferDirectory {
    pub dirname: String,
    pub mode: String,
    pub numbytes: u64,
    pub numfiles: u64,
    pub zipsize: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Answer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_ack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_ack: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transit {
    #[serde(rename = "abilities-v1")]
    pub abilities_v1: Vec<TransitAbility>,
    #[serde(rename = "hints-v1")]
    pub hints_v1: Vec<TransitHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitAbility {
    #[serde(rename = "type")]
    pub ability_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitHint {
    #[serde(rename = "type")]
    pub hint_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<Vec<TransitHintDetail>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitHintDetail {
    #[serde(rename = "type")]
    pub hint_type: String,
    pub hostname: String,
    pub port: u16,
    #[serde(default)]
    pub priority: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferAck {
    pub ack: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Mood {
    Happy,
    Lonely,
    Scary,
    Errory,
}

impl Mood {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mood::Happy => "happy",
            Mood::Lonely => "lonely",
            Mood::Scary => "scary",
            Mood::Errory => "errory",
        }
    }
}

impl std::fmt::Display for Mood {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TransferType {
    Text,
    File,
    Directory,
}

impl std::fmt::Display for TransferType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferType::Text => write!(f, "text"),
            TransferType::File => write!(f, "file"),
            TransferType::Directory => write!(f, "directory"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_serialization() {
        let bind = ClientMessage::Bind(Bind {
            side: "abc123".to_string(),
            appid: "lothar.com/wormhole/text-or-file-xfer".to_string(),
            client_version: vec!["wormhole-rs".to_string(), "0.1.0".to_string()],
        });

        let json = serde_json::to_string(&bind).unwrap();
        assert!(json.contains("\"type\":\"bind\""));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_server_message_deserialization() {
        let json =
            r#"{"type":"welcome","welcome":{"motd":"Hello","current_cli_version":"0.12.0"}}"#;
        let msg: ServerMessage = serde_json::from_str(json).unwrap();

        match msg {
            ServerMessage::Welcome(w) => {
                assert_eq!(w.welcome.motd, "Hello");
                assert_eq!(w.welcome.current_cli_version, "0.12.0");
            }
            _ => panic!("Expected Welcome message"),
        }
    }

    #[test]
    fn test_offer_file_serialization() {
        let offer = Offer {
            message: None,
            file: Some(OfferFile {
                filename: "test.txt".to_string(),
                filesize: 1024,
            }),
            directory: None,
        };

        let json = serde_json::to_string(&offer).unwrap();
        assert!(json.contains("test.txt"));
        assert!(json.contains("1024"));
        assert!(!json.contains("message"));
    }

    #[test]
    fn test_transit_serialization() {
        let transit = Transit {
            abilities_v1: vec![
                TransitAbility {
                    ability_type: "direct-tcp-v1".to_string(),
                },
                TransitAbility {
                    ability_type: "relay-v1".to_string(),
                },
            ],
            hints_v1: vec![TransitHint {
                hint_type: "direct-tcp-v1".to_string(),
                priority: Some(0.0),
                hostname: Some("192.168.1.1".to_string()),
                port: Some(8080),
                hints: None,
            }],
        };

        let json = serde_json::to_string(&transit).unwrap();
        assert!(json.contains("abilities-v1"));
        assert!(json.contains("hints-v1"));
        assert!(json.contains("direct-tcp-v1"));
    }

    #[test]
    fn test_mood_display() {
        assert_eq!(Mood::Happy.as_str(), "happy");
        assert_eq!(Mood::Lonely.as_str(), "lonely");
        assert_eq!(Mood::Scary.as_str(), "scary");
        assert_eq!(Mood::Errory.as_str(), "errory");
    }

    #[test]
    fn test_generic_message_with_error() {
        let msg = GenericMessage {
            offer: None,
            answer: None,
            transit: None,
            app_versions: None,
            error: Some("transfer rejected".to_string()),
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("transfer rejected"));
        assert!(!json.contains("offer"));
    }
}
