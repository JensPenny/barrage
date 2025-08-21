use clap::Parser;

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
    port: Option<i8>,
    /// The connection type of the outbound connection
    connection_type: Option<ConnectionType>,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    println!("pattern: {:?}, path: {:?}", &args.pattern, &args.path);
    let result = std::fs::read_to_string(&args.path);
    let content = match result {
        Ok(content) => content,
        Err(error) => {
            return Err(error.into());
        }
    };

    for line in content.lines() {
        if line.contains(&args.pattern) {
            println!("{}", line);
        }
    }
    return Ok(());
    // todo use bufreader to see if we should load the messages that we want to send into memory

    // todo create a sender, then create
}
