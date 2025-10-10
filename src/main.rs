use std::{
    fs,
    io::{ErrorKind, Write, stdout},
    process,
    sync::Arc,
    thread::{self},
    time::{Duration, Instant},
};

use clap::{Parser, Subcommand};
use crossterm::{
    ExecutableCommand, QueueableCommand, cursor,
    style::{self, Stylize},
    terminal,
};
use futures::{SinkExt, StreamExt, lock::Mutex};
use hl7_mllp_codec::MllpCodec;
use log::{error, info, warn};
use serde_derive::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_util::{bytes::BytesMut, codec::Framed};
use tokio::time::{timeout};


pub use self::stats::Stats;
mod stats;

// Alias for boxed dynamic errors
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, clap::ValueEnum, Default, Serialize, Deserialize)]
pub enum ConnectionType {
    #[default]
    TcpMllpClient,
    HttpClient,
}

#[derive(Debug, Clone, clap::ValueEnum, Default, Serialize, Deserialize)]
pub enum SendMode {     
    #[default]
    Timed,      // Keep sending messages for a set amount of time
    Single,     // Send all messages in the folder once
    SetAmount,  // Send a set amount of messages
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
        #[arg(long, value_enum)]
        send_mode: Option<SendMode>,
        #[arg(long, default_value="10")]
        send_time: Option<u8>,
    },
}

// Configuration class
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config {
    host: String,
    port: u16,
    connection_type: ConnectionType,
    payload_path: std::path::PathBuf,
    send_mode: SendMode, 
    send_time: u8
}

// Default configuration
impl ::std::default::Default for Config {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 20_000,
            connection_type: ConnectionType::TcpMllpClient,
            payload_path: "payload/".into(),
            send_mode: SendMode::Timed,
            send_time: 10,
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
        // Todo translate the error "Bad TOML data" to something like "Configuration error - did you remove or forget a field?"
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
                send_mode, 
                send_time
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
                if let Some(send_mode) = send_mode {
                    cfg.send_mode = send_mode
                };
                if let Some(send_time) = send_time { 
                    cfg.send_time = send_time
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
        }
        Commands::Send => send_messages(cfg).await?,
    }
    return Ok(());
}

async fn test_connection(host: String, port: u16) -> Result<()> {
    let stream: TcpStream = TcpStream::connect(format!("{}:{}", host, port)).await?;
    let mut transport = Framed::new(stream, MllpCodec::new());
    transport
        .send(BytesMut::from(
            "MSH|^~\\&|WIR|||36|20200514123930||VXU^V04^VXU_V04|43|P|2.5.1|||ER",
        ))
        .await?;

    match transport.next().await {
        Some(Ok(_msg)) => Ok(()),
        Some(Err(e)) => Err(e.into()),
        None => {
            Err(std::io::Error::new(ErrorKind::TimedOut, "No response from remote host").into())
        }
    }
}

// // Sends an mllp framed message. This looks to be the actual thing to use here
// fn send_as_mllp(cfg: Config, msg: String) {
//     // https://docs.rs/hl7-mllp-codec/latest/hl7_mllp_codec/
// }

/**
 * Shows a stats panel in the CLI
 * This function only shows the initial scaffolded stats page. The update function will attempt to update this in-place (I guess?)
 */
#[rustfmt::skip] // Skip formatting for this function, the current look is nice
fn show_stats() -> Result<()> {
    let mut stdout = stdout();

    stdout.execute(terminal::Clear(terminal::ClearType::All))?;
    stdout.execute(cursor::MoveTo(0, 0))?;

    // Informative - the longest line is 18 characters long. Recommend >20: offset when actually printing the stats
    stdout
        .queue(style::PrintStyledContent("╭────────────────────────────╮".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│         Live stats         │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("├────────────────────────────┤".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│ Messages sent:             │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│ Messages failed:           │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│ Bytes sent:                │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│ Elapsed time:              │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│ Time remaining:            │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("│ Message rate:              │".cyan()))?.queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent("╰────────────────────────────╯".cyan()))?.queue(cursor::MoveToNextLine(1))?;
    
    stdout.flush()?;
    let progressbar = indicatif::ProgressBar::new(100);
    progressbar.inc(10);
    progressbar.elapsed(); // Todo make this progress bar something useful later on (?)

    thread::sleep(Duration::from_secs(2));
    // let stats = Stats {
    //     messages_sent: 10,
    //     messages_failed: 2,
    //     bytes_sent: 0,
    //     start_time: Instant::now(),
    //     last_update: Instant::now(),
    //     connection_errors: 0 };
    // update_stats(&stats);
    Ok(())
}

fn update_stats(stats: &Stats) -> Result<()> {
    let mut stdout = stdout();

    //stdout.execute(cursor::MoveTo(0,0))?;
    stdout.execute(cursor::MoveTo(0, 3))?;

    let elapsed_time = (Instant::now() - stats.start_time).as_secs();
    let mut message_rate: u64 = 0;
    if elapsed_time != 0 {
        message_rate = stats.messages_sent as u64 / elapsed_time;
    }
    stdout
        .queue(style::PrintStyledContent(
            format!("│ {:<20} {:>5} │", "Messages sent:", stats.messages_sent).cyan(),
        ))?
        .queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent(
            format!(
                "│ {:<20} {:>5} │",
                "Messages failed:", stats.messages_failed
            )
            .cyan(),
        ))?
        .queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent(
            format!("│ {:<20} {:>5} │", "Bytes sent:", stats.bytes_sent).cyan(),
        ))?
        .queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent(
            format!("│ {:<20} {:>5} │", "Elapsed time:", elapsed_time).cyan(),
        ))?
        .queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent(
            format!("│ {:<20} {:>5} │", "Time remaining:", "0 s").cyan(),
        ))?
        .queue(cursor::MoveToNextLine(1))?
        .queue(style::PrintStyledContent(
            format!("│ {:<20} {:>5} │", "Message rate:", message_rate).cyan(),
        ))?
        .queue(cursor::MoveToNextLine(1))?
        .queue(cursor::MoveToNextLine(3))?; //Move over all lines that we should not redraw. The old buffer will be used here
    stdout.flush()?;

    // Todo update should also fix the progress bar (later)
    Ok(())
}

async fn send_messages(cfg: Config) -> Result<()> {
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

    //2. Iterate over the paths and load them in memory
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

    // 3. Show a message about the messages and that they are loaded, and stand by to start the live sending
    //start_stats_thread(stats);
    // for content in file_contents {
    //     info!("Found content {}", content);
    // }

    // 4. Start the worker threads to start sending messages
    let stats = Arc::new(Mutex::new(Stats::new()));
    let amount_workers = 4;
    let mut handles = Vec::new(); // Can be an array, we know the length

    for _i in 0..amount_workers {
        let msg_clone = file_contents.clone();
        let cfg_clone = cfg.clone();
        let stats_clone = Arc::clone(&stats);

        let join_handle = tokio::spawn(async move {
            let stream: TcpStream =
                TcpStream::connect(format!("{}:{}", cfg_clone.host, cfg_clone.port))
                    .await
                    .unwrap();
            let mut transport = Framed::new(stream, MllpCodec::new());

            // For now we all send the same message
            for (_idx, to_send_msg) in msg_clone.iter().enumerate() {
                let is_sent = send_message(
                    Arc::clone(&stats_clone),
                    cfg_clone.clone(),
                    to_send_msg.to_string(),
                    &mut transport,
                ).await;

                // Todo check if this is ok. We kind of want to ignore ok / err here, or just dump them in some kind of log for the messages if needed
                match is_sent {
                    Ok(res) => res, 
                    Err(e) => error!("Error while sending message: {}", e)  
                }
            }
        });

        handles.push(join_handle);

        // let handle = tokio::spawn(async move {
        //     let stream: TcpStream = TcpStream::connect(format!("{}:{}", cfg.host, cfg.port)).await.unwrap();
        //     let mut transport = Framed::new(stream, MllpCodec::new());

        //     // For now they just all send the same mesag
        //     for (idx, msg) in msg_clone.iter().enumerate() {
        //         if idx % amount_workers == i {
        //             if let Err(e) =
        //                 send_message(stat_clone, cfg, msg.to_string(), transport).await
        //             {
        //                 error!("Worker {} failed to send message: {}", i, e);
        //             }
        //         }
        //     }
        // });
        // handles.push(handle);
    }

    //Cancellation token to nuke other threads if required
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let _ = show_stats(); // Initially show the stats
    // Create a separate worker to handle ui updates
    let display_stats = Arc::clone(&stats);
    let display_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(50));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let stats_guard = display_stats.lock().await;
                    let snapshot = stats_guard.clone();

                    match update_stats(&snapshot) {
                        Ok(_) => println!("{}", "Stats updated!".green()),
                        Err(e) => println!("{}", format!("Stat update failed: {:?}", e).red()),
                    }
                }
                _ = &mut shutdown_rx => {
                    info!("Stats display task shutting down");
                    
                    //Update the stats a last time
                    let stats_guard = display_stats.lock().await;
                    let snapshot = stats_guard.clone();
                    let _ = update_stats(&snapshot);
                    break;
                }
            }
        }
    });

    for handle in handles {
        if let Err(e) = handle.await {
            error!("Worker task failed: {}", e);
        }
    }

    // Kill the display task
    let _ = shutdown_tx.send(());

    if let Err(e) = display_handle.await {
        error!("Display task failed: {}", e);
    }

    // Wait for all workers to complete
    // for handle in handles {
    //     if let Err(e) = handle.await {
    //         error!("Worker task failed: {}", e);
    //     }
    // }

    // 5. While we are running, show the stats page

    return Ok(());
}

//Drawing stats to the terminal is blocking

//Sending messages can be async
async fn send_message(
    stats: Arc<Mutex<Stats>>,
    cfg: Config,
    msg: String,
    transport: &mut Framed<TcpStream, MllpCodec>,
) -> Result<()> {
    // Todo make this so that we can stop gracefully
    loop {
        match cfg.connection_type {
            ConnectionType::TcpMllpClient => {
                info!("Starting to send message");
                transport.send(BytesMut::from(msg.as_str())).await?;
                info!("Message sent, waiting for response");

                let response = timeout(Duration::from_secs(10), transport.next()).await;
                let resp_ok;
                match response {
                    Err(_) => {
                        info!("Timeout waiting for response from server");
                        let mut stats = stats.lock().await;
                        stats.messages_failed += 1;
                        stats.last_update = Instant::now();
                        return Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            "No response from remote host (timeout)",
                        )
                        .into());
                    }
                    Ok(res) => {
                        // Continue processing below
                        resp_ok = res;
                    }
                }

                let res = match resp_ok {
                    Some(Ok(_msg)) => {
                        info!("Received response from server");
                        let mut stats = stats.lock().await;
                        stats.messages_sent += 1;
                        stats.bytes_sent += _msg.len() as u64;
                        stats.last_update = Instant::now();
                        Ok(())
                    }
                    Some(Err(e)) => {
                        info!("Error receiving response from server: {}", e);
                        let mut stats = stats.lock().await;
                        stats.messages_failed += 1;
                        stats.last_update = Instant::now();
                        Err(e.into())
                    }
                    None => {
                        info!("No response from server (timeout?)");
                        let mut stats = stats.lock().await;
                        stats.messages_failed += 1;
                        stats.last_update = Instant::now();
                        Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            "No response from remote host",
                        )
                        .into())
                    }
                };

                if res.is_err() {
                    return res;
                } else {
                    info!("Message exchange completed successfully");
                    return Ok(());
                }
            }
            ConnectionType::HttpClient => {
                // Todo implement http client sending
                return Err("HTTP client not implemented yet".into());
            }
        }
    }
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
    println!(
        "   {:<15} {}", 
        "Send mode".green(), 
        format!("{:?}", cfg.send_mode).yellow()
    );
    println!(
        "   {:<15} {}",
        "Send time (sec):".green(),
        cfg.send_time.to_string().yellow()
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
        "💡 Tip: Use 'barrage config set --help' to see available configuration options".black()
    );
}

fn set_ctrlc_handler() {
    ctrlc::set_handler(move || {
        println!("received Ctrl+C!");
        process::exit(1); // Exit on ctrl+c. Todo - see later if we should gracefully exit on first ctrl c
    })
    .expect("Error setting Ctrl-C handler");
}
