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
        /// Network to run on: devnet, testnet, mainnet, or regtest.
        /// regtest uses a trivial proof of work with no retargeting, so a
        /// single node can produce blocks immediately.
        #[arg(long, default_value = "devnet")]
        network: String,
        /// Follow the chain without mining.
        #[arg(long)]
        no_mining: bool,
        /// Address to pay block rewards to. A fresh one is generated if
        /// omitted, so two nodes never mine identical blocks by accident.
        #[arg(long)]
        miner_address: Option<String>,
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
        #[arg(long)]
        seed: String,
    },
    Balance {
        #[arg(short, long)]
        address: String,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum BlockCommands {
    Height {
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
}

fn address_to_bech32(addr: &chroma_core::types::Address) -> String {
    chroma_crypto::address::AddressString::from_hash160(&addr.as_hash160(), None)
        .map(|a| a.0)
        .unwrap_or_else(|| format!("{}", addr))
}

fn bech32_to_address(s: &str) -> Option<chroma_core::types::Address> {
    if s.starts_with("chr1") {
        let addr_str = chroma_crypto::address::AddressString(s.to_string());
        let h = addr_str.to_hash160()?;
        Some(chroma_core::types::Address::from_hash160(h))
    } else {
        let hex_str = s.trim_start_matches("0x");
        let bytes = hex::decode(hex_str).ok()?;
        if bytes.len() != 20 {
            return None;
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&bytes);
        Some(chroma_core::types::Address::from_hash160(
            chroma_core::hash::Hash160(h),
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Node { listen, connect, data_dir, network, no_mining, miner_address } => {
            println!("Starting Chroma node on {}", listen);
            println!("Data directory: {}", data_dir.display());
            if !connect.is_empty() {
                println!("Connecting to: {:?}", connect);
            }
            let params = match chroma_consensus::ChainParams::parse(&network) {
                Some(p) => p,
                None => {
                    eprintln!(
                        "Unknown network '{}'. Expected devnet, testnet, mainnet or regtest.",
                        network
                    );
                    std::process::exit(1);
                }
            };
            let genesis = chroma_consensus::build_genesis_block_with(&params);
            let genesis_hash = genesis.hash();
            println!("Network: {}", params.network.as_str());
            let config = chroma_p2p::NodeConfig::new(listen, genesis_hash)
                .with_params(params)
                .with_data_dir(data_dir)
                .with_connect_addrs(connect)
                .with_mining(!no_mining);
            let config = match miner_address {
                Some(text) => match bech32_to_address(&text) {
                    Some(addr) => config.with_miner_address(addr),
                    None => {
                        eprintln!("Invalid --miner-address: expected bech32m (chr1...) or 0x hex");
                        std::process::exit(1);
                    }
                },
                None => config,
            };
            if !no_mining {
                println!("Mining rewards to: {}", address_to_bech32(&config.miner_address));
            }
            let mut node = chroma_p2p::Node::new(config);
            let mut event_rx = node.event_rx().expect("event_rx already taken");
            tokio::spawn(async move {
                while let Some(event) = event_rx.recv().await {
                    match event {
                        chroma_p2p::NodeEvent::PeerConnected(addr) => {
                            println!("[PEER] Connected: {}", addr);
                        }
                        chroma_p2p::NodeEvent::PeerDisconnected(addr) => {
                            println!("[PEER] Disconnected: {}", addr);
                        }
                        chroma_p2p::NodeEvent::BlockReceived(hash, height) => {
                            println!("[BLOCK] Received: height={} hash={}", height, &hash.to_hex()[..16]);
                        }
                        chroma_p2p::NodeEvent::BlockMined(hash, height) => {
                            println!("[BLOCK] Mined: height={} hash={}", height, &hash.to_hex()[..16]);
                        }
                        chroma_p2p::NodeEvent::TxReceived(hash) => {
                            println!("[TX] Received: {}", &hash.to_hex()[..16]);
                        }
                        chroma_p2p::NodeEvent::Reorganized { depth, new_tip } => {
                            println!(
                                "[REORG] rolled back {} block(s), new tip {}",
                                depth,
                                &new_tip.to_hex()[..16]
                            );
                        }
                        chroma_p2p::NodeEvent::HeadersAccepted(count) => {
                            println!("[SYNC] Accepted {} header(s)", count);
                        }
                        chroma_p2p::NodeEvent::SyncComplete => {
                            println!("[SYNC] Complete");
                        }
                        chroma_p2p::NodeEvent::Error(e) => {
                            eprintln!("[ERROR] {}", e);
                        }
                    }
                }
            });
            node.run().await?;
            tokio::signal::ctrl_c().await?;
            println!("Shutting down...");
            node.shutdown().await;
            println!("Stopped cleanly.");
        }
        Commands::Wallet { command } => match command {
            WalletCommands::Create { name } => {
                let wallet = chroma_wallet::Wallet::generate(&name);
                println!("Wallet created: {}", wallet.name());
                println!("Address: {}", address_to_bech32(&wallet.address()));
                println!("Save your secret key:");
                println!("  {}", hex::encode(wallet.secret_bytes()));
            }
            WalletCommands::Address { name, seed } => {
                let words: Vec<String> = seed.split_whitespace().map(|s| s.to_string()).collect();
                match chroma_wallet::wallet_from_seed_phrase(&name, &words) {
                    Ok(wallet) => {
                        println!("Wallet '{}':", name);
                        println!("  Address: {}", address_to_bech32(&wallet.address()));
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            WalletCommands::Balance { address, data_dir } => {
                let addr = match bech32_to_address(&address) {
                    Some(a) => a,
                    None => {
                        eprintln!("Invalid address: expected bech32m (chr1...) or 0x-prefixed hex");
                        std::process::exit(1);
                    }
                };
                match chroma_storage::Storage::open(&data_dir) {
                    Ok(storage) => {
                        match storage.get_account(&addr) {
                            Ok(Some(account)) => {
                                let chr = account.balance as f64 / 1_000_000.0;
                                println!("Balance: {} CHR ({} units)", chr, account.balance);
                                println!("Nonce: {}", account.nonce);
                            }
                            Ok(None) => {
                                println!("Balance: 0 CHR (account not found)");
                            }
                            Err(e) => {
                                eprintln!("Error reading account: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to open database at {}: {}", data_dir.display(), e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Block { command } => match command {
            BlockCommands::Height { data_dir } => {
                match chroma_storage::Storage::open(&data_dir) {
                    Ok(storage) => {
                        match storage.get_tip() {
                            Ok(Some(tip)) => {
                                println!("Block height: {}", tip.height);
                                println!("Chain tip: {}", tip.hash.to_hex());
                                let supply_chr = tip.supply as f64 / 1_000_000.0;
                                println!("Supply: {} CHR ({} units)", supply_chr, tip.supply);
                            }
                            Ok(None) => {
                                println!("No chain found. Start the node to initialize.");
                            }
                            Err(e) => {
                                eprintln!("Error reading chain tip: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to open database at {}: {}", data_dir.display(), e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Mnemonic { name } => {
            let phrase = chroma_wallet::generate_seed_phrase();
            let wallet = chroma_wallet::wallet_from_seed_phrase(&name, &phrase)?;
            println!("Generated mnemonic for '{}':", name);
            println!("  {}", phrase.join(" "));
            println!("Address: {}", address_to_bech32(&wallet.address()));
        }
    }

    Ok(())
}
