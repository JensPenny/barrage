use std::{fs, io::{ErrorKind, Write, stdout}, process};

use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use hl7_mllp_codec::MllpCodec;
use log::{error, info, warn};
use serde_derive::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::{bytes::BytesMut, codec::Framed};
use crossterm::{cursor, queue, style::{self, Stylize}, terminal, ExecutableCommand, QueueableCommand};

// Alias for boxed dynamic errors
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, clap::ValueEnum, Default, Serialize, Deserialize)]
enum ConnectionType {
    #[default]
    TcpMllpClient,
    HttpClient,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage the barrage configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Test the current connection configurations
    TestConnection {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Send the messages
    Send, // Todo add possible overrides for the send command
}

// Todo choose between set or explicit-set
#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Pretty print the current configuration
    Show,
    /// Set one or more configuration parameters
    // Set {
    //     /// kv-pairs of the settings. For example: host=127.0.0.1
    //     #[arg(value_parser = parse_key_val::<String, String>)]
    //     pairs: Vec<(String, String)>,
    // },
    /// Set a config parameter explicitly
    Set {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long, value_enum)]
        connection_type: Option<ConnectionType>,
        #[arg(long)]
        payload_path: Option<std::path::PathBuf>,
    },
}

// Configuration class
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    host: String,
    port: u16,
    connection_type: ConnectionType,
    payload_path: std::path::PathBuf,
}

// Default configuration
impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 20_000,
            connection_type: ConnectionType::TcpMllpClient,
            payload_path: "payload/".into(),
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::init();

    set_ctrlc_handler();

    let cli = Cli::parse();
    let mut cfg: Config = confy::load_path("barrage.conf").unwrap_or_else(|e| {
        error!("Error loading config: {}", e);
        Config::default()
    });

    info!("Loaded config: {:#?}", cfg);

    match cli.command {
        Commands::Config { action } => match action {
            ConfigCommands::Show => show_config(cfg),
            ConfigCommands::Set {
                host,
                port,
                connection_type,
                payload_path,
            } => {
                if let Some(host) = host {
                    cfg.host = host;
                }
                if let Some(port) = port {
                    cfg.port = port
                };
                if let Some(connection_type) = connection_type {
                    cfg.connection_type = connection_type
                };
                if let Some(payload_path) = payload_path {
                    cfg.payload_path = payload_path
                };

                confy::store_path("barrage.conf", &cfg)?;
                info!("Config updates saved: {:#?}", cfg);
            }
        },
        Commands::TestConnection { host, port } => {
            match test_connection(host.unwrap_or(cfg.host), port.unwrap_or(cfg.port)).await {
                Ok(_) => println!("{}", "Connection succeeded!".green()), 
                Err(e) => println!("{}", format!("Could not connect: {:?}", e).red()),
            }
        },
        Commands::Send => send_messages(cfg)?,
    }
    return Ok(());
}

async fn test_connection(host: String, port: u16) -> Result<()> {
    let stream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let mut transport = Framed::new(stream, MllpCodec::new());
    transport
        .send(BytesMut::from(
            "MSH|^~\\&|WIR|||36|20200514123930||VXU^V04^VXU_V04|43|P|2.5.1|||ER",
        ))
        .await?;

        match transport.next().await {
            Some(Ok(_msg)) => Ok(()),
            Some(Err(e)) => Err(e.into()),
            None => Err(std::io::Error::new(ErrorKind::TimedOut, "No response from remote host").into()),
        }
}

// Sends an mllp framed message. This looks to be the actual thing to use here
fn send_as_mllp(cfg: Config, msg: String) {
    // https://docs.rs/hl7-mllp-codec/latest/hl7_mllp_codec/
}

/**
 * Shows a stats panel in the CLI and updates it when the stats can change
 */
fn show_stats(_amount_passed: u16) -> Result<()>{
    let mut stdout = stdout();
    
    stdout.execute(terminal::Clear(terminal::ClearType::All))?;

    for y in 0..40 {
        for x in 0..150 {
            if (y == 0 || y == 40-1) || (x == 0 || x == 150 - 1) {
                stdout
                    .queue(cursor::MoveTo(x,y))?
                    .queue(style::PrintStyledContent( "█".dark_magenta()))?;
            }
        }
    }
    stdout.flush()?;
    Ok(())
}

fn send_messages(cfg: Config) -> Result<()> {
    // 1. List the paths in the payload directory
    let payloads = cfg.payload_path.read_dir();
    let paths = match payloads {
        Ok(paths) => paths,
        Err(err) => {
            error!(
                "Could not find directory path for messages. Aborting. {}",
                err
            );
            return Err(err.into());
        }
    };

    let mut file_contents: Vec<String> = Vec::new();

    // Iterate over the paths and load them in memory
    for path_result in paths {
        let path = match path_result {
            Ok(p) => p,
            Err(e) => {
                // ignore filepath errors
                warn!("Could not process path. Error {}", e);
                continue;
            }
        };

        // Todo collect or map the paths, then sort by filename
        //     let mut entries: Vec<_> = fs::read_dir("payloads")?
        //     .filter_map(Result::ok) // discard errors
        //     .collect();

        // // Sort alphabetically by filename
        // entries.sort_by_key(|dir| dir.path());

        let payload_content = match fs::read_to_string(path.path()) {
            Ok(c) => c,
            Err(e) => {
                // ignore if we can't load a single file
                warn!(
                    "Could not read file at path {}. Error {}",
                    path.path().display(),
                    e
                );
                continue;
            }
        };
        let formatted = format!("Loaded file at {}", path.path().display());
        println!("{}", formatted.green());
        file_contents.push(payload_content);
    }

    for content in file_contents {
        info!("Found content {}", content);
    }

    return show_stats(10);

}

fn show_config(cfg: Config) {
    println!("{}", "╭─────────────────────────────────────╮".cyan());
    println!("{}", "│          Barrage Configuration      │".cyan());
    println!("{}", "╰─────────────────────────────────────╯".cyan());
    println!();

    println!("{}", "📡 Connection Settings:".blue().bold());
    println!("   {:<15} {}", "Host:".green(), cfg.host.yellow());
    println!(
        "   {:<15} {}",
        "Port:".green(),
        cfg.port.to_string().yellow()
    );
    println!(
        "   {:<15} {}",
        "Connection Type:".green(),
        format!("{:?}", cfg.connection_type).yellow()
    );
    println!();

    println!("{}", "📁 File Settings:".blue().bold());
    println!(
        "   {:<15} {}",
        "Payload Path:".green(),
        cfg.payload_path.display().to_string().yellow()
    );
    println!();

    // Show config file location and status
    let config_path = std::path::Path::new("barrage.conf");
    println!("{}", "⚙️  Configuration:".blue().bold());

    if config_path.exists() {
        println!(
            "   {:<15} {} {}",
            "File:".green(),
            config_path.display().to_string().yellow(),
            "✓".green()
        );

        if let Ok(metadata) = config_path.metadata() {
            if let Ok(modified) = metadata.modified() {
                let datetime = modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                println!(
                    "   {:<15} {}",
                    "Last Modified:".green(),
                    format!(
                        "{} seconds ago",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            - datetime
                    )
                    .black()
                );
            }

            let size = metadata.len();
            println!(
                "   {:<15} {} bytes",
                "Size:".green(),
                size.to_string().black()
            );
        }
    } else {
        println!(
            "   {:<15} {} {}",
            "File:".green(),
            config_path.display().to_string().yellow(),
            "(using defaults)".black()
        );
        println!(
            "   {:<15} {}",
            "Status:".green(),
            "No config file found".red()
        );
    }
    println!();

    // Add a helpful tip
    println!(
        "{}",
        "💡 Tip: Use 'barrage config set --help' to see available configuration options"
            .black()
    );
}

fn set_ctrlc_handler() {
    ctrlc::set_handler(move || {
        println!("received Ctrl+C!");
        process::exit(1); // Exit on ctrl+c. Todo - see later if we should gracefully exit on first ctrl c
    })
    .expect("Error setting Ctrl-C handler");
}
