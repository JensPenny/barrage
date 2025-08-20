use clap::Parser;


#[derive(Parser, Debug)]
struct Cli {
    
    pattern: String, 

    path: std::path::PathBuf,

    host: Option<String>, 

    port: Option<i8>,

    connection_type: Option<String>, // Todo this should be an enum or something with the types of data that this client can send
}

fn main() {
    let args = Cli::parse();
    println!("pattern: {:?}, path: {:?}", &args.pattern, &args.path);
    let content = std::fs::read_to_string(&args.path).expect("could not read file");

    for line in content.lines() {
        if line.contains(&args.pattern) {
            println!("{}", line);
        }
    }
    // todo use bufreader to see if we should load the messages that we want to send into memory

    // todo create a sender, then create 
}
