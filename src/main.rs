use std::{error::Error, process, thread::sleep, time::Duration};

use barrage::match_lines;

use clap::{Parser, Subcommand};
use log::{info, warn};
use serde_derive::{Serialize, Deserialize};
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
    command: Commands
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage the barrage configuration
    Config{ 
        #[command(subcommand)]
        action: ConfigCommands,
    },
    /// Test the current connection configurations
    TestConnection{
        #[arg(short, long)]
        host: Option<String>, 
        #[arg(short, long)]
        port: Option<u16>,
    },
    /// Send the messages
    Send
    // Todo add possible overrides for the send command
}

// Todo choose between set or explicit-set
#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Pretty print the current configuration
    Show, 
    /// Set one or more configuration parameters
    Set {
        /// kv-pairs of the settings. For example: host=127.0.0.1
        #[arg(value_parser = parse_key_val::<String, String>)]
        pairs: Vec<(String, String)>,
    },
    /// Set a config parameter explicitly
    SetE {
        #[arg(long)] host: Option<String>, 
        #[arg(long)] port: Option<u16>, 
        #[arg(long, value_enum)] connection_type: Option<ConnectionType>, 
        #[arg(long)] payload_path: Option<std::path::PathBuf>,
    }
}

// Clap docs: https://docs.rs/crate/clap/latest/source/examples/typed-derive.rs
/// Parse a single key-value pair
fn parse_key_val<T, U>(s: &str) -> std::result::Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
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
            payload_path: "/payload".into(),
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    set_ctrlc_handler();

    let cli = Cli::parse();

    match cli.command {
        Commands::Config { action } => match action {
            ConfigCommands::Show => todo!(),
            ConfigCommands::Set { pairs } => {
                for (key, value) in pairs {
                    match key.as_str() {
                        "host" => info!("config set host: {}", value),
                        "port" => info!("Config set port: {}", value),
                        "connection_type" => info!("Config set connection_type: {}", value),
                        "payload_path" => info!("Config set payload_path: {}", value),
                        _ => return Err(format!("Unknown config key: {}", key).into()),
                    }
                }
            },
        },
        Commands::TestConnection { host, port } => todo!(),
        Commands::Send => todo!(),
    }
    // let mut is_running = false;
    // let cfg: Config = confy::load("barrage", None)?;
    // info!("used config: {:#?}", cfg);


    // let args = Cli::parse();
    // println!("pattern: {:?}, path: {:?}", &args.pattern, &args.path);
    // let result = std::fs::read_to_string(&args.path);
    // let content = match result {
    //     Ok(content) => content,
    //     Err(error) => {
    //         return Err(error.into());
    //     }
    // };

    // // if is_running {
    //     match_lines(&content, &args.pattern, &mut std::io::stdout());
    //     info!("showing progress bar");
    //     warn!("really showing progress bar");
    //     show_progress_bar();
    // }
    return Ok(());
    // todo use bufreader to see if we should load the messages that we want to send into memory

    // todo create a sender, then create
}

fn set_ctrlc_handler() {
    ctrlc::set_handler(move || {
        println!("received Ctrl+C!");
        // is_running = false;
        process::exit(1); // Exit on ctrl+c. Todo - see later if we should gracefully exit on first ctrl c
    })
    .expect("Error setting Ctrl-C handler");
}

fn show_progress_bar() {
    let pb = indicatif::ProgressBar::new(100);
    for _i in 0..100 {
        sleep(Duration::new(0, 200_000_000));
        pb.inc(1);
    }
    pb.finish_with_message("done");
}
