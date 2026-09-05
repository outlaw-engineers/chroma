use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "chroma", version = env!("CARGO_PKG_VERSION"), about = "Chroma blockchain node and wallet")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Node {
        #[arg(short, long, default_value = "127.0.0.1:8333")]
        listen: SocketAddr,
        #[arg(short, long)]
        connect: Vec<SocketAddr>,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    Block {
        #[command(subcommand)]
        command: BlockCommands,
    },
    Mnemonic {
        #[arg(short, long, default_value = "default")]
        name: String,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    Create {
        #[arg(short, long)]
        name: String,
    },
    Address {
        #[arg(short, long)]
        name: String,
    },
    Balance {
        #[arg(short, long)]
        name: String,
        #[arg(long, default_value = "127.0.0.1:8333")]
        rpc: SocketAddr,
    },
}

#[derive(Subcommand)]
enum BlockCommands {
    Height {
        #[arg(long, default_value = "127.0.0.1:8333")]
        rpc: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Node { listen, connect, data_dir } => {
            println!("Starting Chroma node on {}", listen);
            println!("Data directory: {}", data_dir.display());
            if !connect.is_empty() {
                println!("Connecting to: {:?}", connect);
            }
            let genesis_hash = chroma_core::hash::Hash::blake3(b"Chroma Genesis");
            let config = chroma_p2p::NodeConfig::new(listen, genesis_hash);
            let mut node = chroma_p2p::Node::new(config);
            for addr in &connect {
                node.connect(*addr);
            }
            node.run().await?;
            tokio::signal::ctrl_c().await?;
            println!("Shutting down...");
        }
        Commands::Wallet { command } => match command {
            WalletCommands::Create { name } => {
                let wallet = chroma_wallet::Wallet::generate(&name);
                println!("Wallet created: {}", wallet.name());
                println!("Address: {:?}", wallet.address());
                println!("Save your secret key:");
                println!("  {}", hex::encode(wallet.secret_bytes()));
            }
            WalletCommands::Address { name } => {
                eprintln!("Wallet '{}' address lookup requires a key store (not yet implemented)", name);
                std::process::exit(1);
            }
            WalletCommands::Balance { name: _, rpc: _ } => {
                eprintln!("Balance query requires RPC (not yet implemented)");
                std::process::exit(1);
            }
        },
        Commands::Block { command } => match command {
            BlockCommands::Height { rpc: _ } => {
                eprintln!("Block height query requires RPC (not yet implemented)");
                std::process::exit(1);
            }
        },
        Commands::Mnemonic { name } => {
            let phrase = chroma_wallet::generate_seed_phrase();
            let wallet = chroma_wallet::wallet_from_seed_phrase(&name, &phrase)?;
            println!("Generated mnemonic for '{}':", name);
            println!("  {}", phrase.join(" "));
            println!("Address: {:?}", wallet.address());
        }
    }

    Ok(())
}
