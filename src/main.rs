use std::{thread::sleep, time::Duration};

use barrage::match_lines;
use clap::Parser;
use log::{info, warn};
use serde_derive::{Serialize, Deserialize};
// Alias for boxed dynamic errors
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, clap::ValueEnum, Default)]
enum ConnectionType {
    #[default]
    TcpMllpClient,
    HttpClient,
}
#[derive(Parser, Debug)]
struct Cli {
    /// The string or pattern to look for
    pattern: String,
    /// The path of the file where to search the regex
    path: std::path::PathBuf,
    /// The host where barrage should send its messages
    host: Option<String>,
    /// The port where barrage should send its messages
    port: Option<u16>,
    /// The connection type of the outbound connection
    connection_type: Option<ConnectionType>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    host: String, 
    port: u16
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        Self { 
            host: "localhost".to_string(), 
            port: 20_000,
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let mut is_running = false;
    let cfg: Config = confy::load("barrage", None)?;
    info!("used config: {:#?}", cfg);

    ctrlc::set_handler(move || {
        println!("received Ctrl+C!");
        is_running = false;
    })
    .expect("Error setting Ctrl-C handler");

    let args = Cli::parse();
    println!("pattern: {:?}, path: {:?}", &args.pattern, &args.path);
    let result = std::fs::read_to_string(&args.path);
    let content = match result {
        Ok(content) => content,
        Err(error) => {
            return Err(error.into());
        }
    };

    if is_running {
        match_lines(&content, &args.pattern, &mut std::io::stdout());
        info!("showing progress bar");
        warn!("really showing progress bar");
        show_progress_bar();
    }
    return Ok(());
    // todo use bufreader to see if we should load the messages that we want to send into memory

    // todo create a sender, then create
}

fn show_progress_bar() {
    let pb = indicatif::ProgressBar::new(100);
    for _i in 0..100 {
        sleep(Duration::new(0, 200_000_000));
        pb.inc(1);
    }
    pb.finish_with_message("done");
}
