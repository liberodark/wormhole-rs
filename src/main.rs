use std::path::PathBuf;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use wormhole_rs::{DEFAULT_RELAY_URL, DEFAULT_TRANSIT_RELAY, client, server};

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
        } => {
            let relay_url = relay_url.unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());
            let transit_relay = transit_relay.unwrap_or_else(|| DEFAULT_TRANSIT_RELAY.to_string());

            if let Some(text_msg) = text {
                // Send text
                client::send_text(
                    &relay_url,
                    &transit_relay,
                    &text_msg,
                    code.as_deref(),
                    code_length,
                    verify,
                )
                .await?;
            } else if let Some(file_path) = path {
                // Send file or directory
                if file_path.is_dir() {
                    client::send_directory(
                        &relay_url,
                        &transit_relay,
                        &file_path,
                        code.as_deref(),
                        code_length,
                        verify,
                        hide_progress,
                    )
                    .await?;
                } else {
                    client::send_file(
                        &relay_url,
                        &transit_relay,
                        &file_path,
                        code.as_deref(),
                        code_length,
                        verify,
                        hide_progress,
                    )
                    .await?;
                }
            } else {
                // Interactive text input
                eprint!("Text to send: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let text_msg = input.trim();

                client::send_text(
                    &relay_url,
                    &transit_relay,
                    text_msg,
                    code.as_deref(),
                    code_length,
                    verify,
                )
                .await?;
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

            client::receive(
                &relay_url,
                &transit_relay,
                &code,
                output.as_deref(),
                verify,
                hide_progress,
                accept,
            )
            .await?;
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
