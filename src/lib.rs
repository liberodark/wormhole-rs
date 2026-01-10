pub mod client;
pub mod crypto;
pub mod exclude;
pub mod messages;
pub mod server;
pub mod transit;
pub mod wordlist;

pub const DEFAULT_RELAY_URL: &str = "ws://relay.magic-wormhole.io:4000/v1";
pub const DEFAULT_TRANSIT_RELAY: &str = "transit.magic-wormhole.io:4001";
pub const APP_ID: &str = "lothar.com/wormhole/text-or-file-xfer";
pub const AGENT_STRING: &str = "wormhole-rs";
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
