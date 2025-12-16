use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use wormhole_rs::{DEFAULT_RELAY_URL, DEFAULT_TRANSIT_RELAY, client, server, transit};

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
enum CompressArg {
    /// Classic zip with deflate (compatible with all clients)
    #[default]
    Zip,
    /// Fast zstd compression (wormhole-rs only)
    Zstd,
}

impl From<CompressArg> for transit::Compression {
    fn from(arg: CompressArg) -> Self {
        match arg {
            CompressArg::Zip => transit::Compression::Zip,
            CompressArg::Zstd => transit::Compression::Zstd,
        }
    }
}

#[derive(Parser)]
#[command(name = "wormhole-rs")]
#[command(about = "Magic Wormhole - secure file transfer")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        #[arg(long, short = 't', conflicts_with = "path")]
        text: Option<String>,

        #[arg(long)]
        code: Option<String>,

        #[arg(long, short = 'c', default_value = "2")]
        code_length: usize,

        #[arg(long, env = "WORMHOLE_RELAY_URL")]
        relay_url: Option<String>,

        #[arg(long, env = "WORMHOLE_TRANSIT_RELAY")]
        transit_relay: Option<String>,

        #[arg(long, short = 'v')]
        verify: bool,

        #[arg(long)]
        hide_progress: bool,

        #[arg(long, value_enum, default_value = "zip")]
        compress: CompressArg,

        #[arg(long, default_value = "30")]
        connect_timeout: u64,

        #[arg(long, default_value = "300")]
        peer_timeout: u64,
    },

    #[command(visible_alias = "recv")]
    Receive {
        #[arg(value_name = "CODE")]
        code: Option<String>,

        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        #[arg(long, env = "WORMHOLE_RELAY_URL")]
        relay_url: Option<String>,

        #[arg(long, env = "WORMHOLE_TRANSIT_RELAY")]
        transit_relay: Option<String>,

        #[arg(long, short = 'v')]
        verify: bool,

        #[arg(long)]
        hide_progress: bool,

        #[arg(long, short = 'y')]
        accept: bool,

        #[arg(long, default_value = "30")]
        connect_timeout: u64,

        #[arg(long, default_value = "300")]
        peer_timeout: u64,
    },

    /// Run as a relay server
    Server {
        #[arg(long, default_value = "4000")]
        port: u16,

        #[arg(long, default_value = "4001")]
        relay_port: u16,

        #[arg(long, default_value = "0.0.0.0")]
        bind: String,

        #[arg(long)]
        motd: Option<String>,
    },

    #[command(name = "shell-completion")]
    ShellCompletion {
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

fn print_completions<G: clap_complete::Generator>(generator: G, cmd: &mut clap::Command) {
    clap_complete::generate(
        generator,
        cmd,
        cmd.get_name().to_string(),
        &mut std::io::stdout(),
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            path,
            text,
            code,
            code_length,
            relay_url,
            transit_relay,
            verify,
            hide_progress,
            compress,
            connect_timeout,
            peer_timeout,
        } => {
            let relay_url = relay_url.unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());
            let transit_relay = transit_relay.unwrap_or_else(|| DEFAULT_TRANSIT_RELAY.to_string());

            let config = client::SendConfig {
                relay_url: &relay_url,
                transit_relay: &transit_relay,
                code: code.as_deref(),
                code_length,
                verify,
                hide_progress,
                compression: compress.into(),
                connect_timeout: Duration::from_secs(connect_timeout),
                peer_timeout: if peer_timeout == 0 {
                    Duration::MAX
                } else {
                    Duration::from_secs(peer_timeout)
                },
            };

            if let Some(text_msg) = text {
                client::send_text(&text_msg, &config).await?;
            } else if let Some(file_path) = path {
                if file_path.is_dir() {
                    client::send_directory(&file_path, &config).await?;
                } else {
                    client::send_file(&file_path, &config).await?;
                }
            } else {
                eprint!("Text to send: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let text_msg = input.trim();

                client::send_text(text_msg, &config).await?;
            }
        }

        Commands::Receive {
            code,
            output,
            relay_url,
            transit_relay,
            verify,
            hide_progress,
            accept,
            connect_timeout,
            peer_timeout,
        } => {
            let relay_url = relay_url.unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());
            let transit_relay = transit_relay.unwrap_or_else(|| DEFAULT_TRANSIT_RELAY.to_string());

            let code = if let Some(c) = code {
                c
            } else {
                // Interactive code input
                eprint!("Enter receive wormhole code: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                input.trim().to_string()
            };

            let config = client::ReceiveConfig {
                relay_url: &relay_url,
                transit_relay: &transit_relay,
                output_dir: output.as_deref(),
                verify,
                hide_progress,
                auto_accept: accept,
                connect_timeout: Duration::from_secs(connect_timeout),
                peer_timeout: if peer_timeout == 0 {
                    Duration::MAX
                } else {
                    Duration::from_secs(peer_timeout)
                },
            };

            client::receive(&code, &config).await?;
        }

        Commands::Server {
            port,
            relay_port,
            bind,
            motd,
        } => {
            println!("Starting wormhole-rs server...");
            println!("Rendezvous: ws://{}:{}", bind, port);
            println!("Transit relay: {}:{}", bind, relay_port);

            server::run(&bind, port, relay_port, motd.as_deref()).await?;
        }

        Commands::ShellCompletion { shell } => {
            let mut cmd = Cli::command();
            print_completions(shell, &mut cmd);
        }
    }

    Ok(())
}
