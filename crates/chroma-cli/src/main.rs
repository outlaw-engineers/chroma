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
        /// Peer to dial, as `<node-id-hex>@host:port`. The identity is
        /// required: Noise XK authenticates the far end against a key known
        /// in advance, so there is nothing to verify without it.
        #[arg(short, long)]
        connect: Vec<chroma_p2p::peer::PeerAddress>,
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
    /// Build, sign and submit a transaction.
    Tx {
        #[command(subcommand)]
        command: TxCommands,
    },
}

#[derive(Subcommand)]
enum TxCommands {
    Send {
        /// Sender's secret key, hex encoded.
        #[arg(long)]
        secret: String,
        /// Recipient address (bech32m chr1... or 0x hex).
        #[arg(long)]
        to: String,
        /// Amount in units (1 CHR = 1,000,000 units).
        #[arg(long)]
        amount: u64,
        /// Node to submit to.
        #[arg(long, default_value = "127.0.0.1:8333")]
        node: SocketAddr,
        /// Sender's next nonce. Read from --data-dir when omitted.
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
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

/// Open a node's database for reading.
///
/// sled takes an exclusive lock, so this fails while a node is running on the
/// same directory. Querying a live node needs the RPC layer the spec leaves
/// open (§13); until then, stop the node or pass the value explicitly.
fn open_storage(data_dir: &std::path::Path) -> anyhow::Result<chroma_storage::Storage> {
    chroma_storage::Storage::open(data_dir).map_err(|e| {
        let hint = if e.to_string().contains("lock") {
            " (a node is running on this data directory; stop it first)"
        } else {
            ""
        };
        anyhow::anyhow!("cannot open {}: {}{}", data_dir.display(), e, hint)
    })
}

/// Submit a signed transaction to a node over the P2P protocol.
///
/// There is no RPC yet (spec §13 leaves it open), so the CLI speaks the same
/// wire protocol a peer would: handshake, send the transaction, and wait long
/// enough for the node to have processed it.
async fn submit_transaction(
    node: SocketAddr,
    tx: &chroma_tx::Transaction,
) -> anyhow::Result<()> {
    use chroma_core::serialize::CanonicalEncode;
    use chroma_p2p::wire::{decode_frame, FrameDecode, Message, MessageType, VersionMessage};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(node).await?;

    let version = VersionMessage {
        version: chroma_p2p::PROTOCOL_VERSION,
        services: 0,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        height: 0,
        // Our own listen port is meaningless here: we are a client, not a
        // peer to dial back.
        nonce: rand_nonce(),
        listen_port: 0,
    };
    stream
        .write_all(&Message::new(MessageType::Version, version.encode()).encode())
        .await?;

    // Wait for the node's verack before sending, so the transaction is not
    // dropped by a peer that has not finished the handshake.
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut ready = false;
    while !ready {
        loop {
            match decode_frame(&buf) {
                Ok(FrameDecode::Complete { message, consumed }) => {
                    buf.drain(..consumed);
                    if message.msg_type == MessageType::VerAck {
                        ready = true;
                    }
                    if message.msg_type == MessageType::Version {
                        stream
                            .write_all(&Message::new(MessageType::VerAck, vec![]).encode())
                            .await?;
                    }
                }
                Ok(FrameDecode::Incomplete { .. }) => break,
                Err(e) => anyhow::bail!("node sent a malformed frame: {}", e),
            }
        }
        if ready {
            break;
        }
        let n = tokio::time::timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for the node's handshake"))??;
        if n == 0 {
            anyhow::bail!("node closed the connection during the handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    stream
        .write_all(&Message::new(MessageType::Tx, tx.encode()).encode())
        .await?;
    stream.flush().await?;

    // Give the node a moment to read and validate before we hang up; a reject
    // arrives on this connection if it did not like it.
    let listen = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        stream.read(&mut chunk),
    )
    .await;
    if let Ok(Ok(n)) = listen {
        buf.extend_from_slice(&chunk[..n]);
        while let Ok(FrameDecode::Complete { message, consumed }) = decode_frame(&buf) {
            buf.drain(..consumed);
            if message.msg_type == MessageType::Reject {
                if let Ok(reject) = chroma_p2p::wire::RejectMessage::decode(&message.payload) {
                    anyhow::bail!("node rejected the transaction: {}", reject.reason);
                }
                anyhow::bail!("node rejected the transaction");
            }
        }
    }

    Ok(())
}

fn rand_nonce() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    h.finish()
}

/// Read this node's Noise secret from the data directory, creating one on
/// first run.
///
/// Stored as hex in `node_key`, owner-readable only where the platform
/// supports it: anyone holding it can impersonate the node to its peers.
fn load_or_create_node_key(data_dir: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    let path = data_dir.join("node_key");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let raw = hex::decode(text.trim())
            .map_err(|_| anyhow::anyhow!("{} is not 32 bytes of hex", path.display()))?;
        if raw.len() == 32 {
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&raw);
            return Ok(secret);
        }
        anyhow::bail!("{} is not 32 bytes of hex", path.display());
    }

    let keypair = chroma_crypto::noise::NodeKeypair::generate()
        .map_err(|e| anyhow::anyhow!("failed to generate node identity: {}", e))?;
    let secret = keypair.secret_bytes();
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(&path, hex::encode(secret))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(secret)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Node { listen, connect, data_dir, network, no_mining, miner_address } => {
            println!("Starting Chroma node on {}", listen);
            println!("Data directory: {}", data_dir.display());
            for peer in &connect {
                println!("Connecting to: {}", peer);
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
            // The identity lives in the data directory so a restarted node
            // keeps the id its peers know it by. A fresh key every run would
            // make `--connect` entries go stale on every restart.
            let node_secret = load_or_create_node_key(&data_dir)?;

            let genesis = chroma_consensus::build_genesis_block_with(&params);
            let genesis_hash = genesis.hash();
            println!("Network: {}", params.network.as_str());
            let config = chroma_p2p::NodeConfig::new(listen, genesis_hash)
                .with_params(params)
                .with_data_dir(data_dir)
                .with_connect_addrs(connect)
                .with_node_secret(node_secret)
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
            println!("Node identity: {}@{}", node.node_id().to_hex(), listen);
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
                match open_storage(&data_dir) {
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
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Block { command } => match command {
            BlockCommands::Height { data_dir } => {
                match open_storage(&data_dir) {
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
                        eprintln!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Tx { command } => match command {
            TxCommands::Send {
                secret,
                to,
                amount,
                node,
                nonce,
                data_dir,
            } => {
                let secret_bytes = match hex::decode(secret.trim_start_matches("0x")) {
                    Ok(b) if b.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        eprintln!("Invalid --secret: expected 32 bytes of hex");
                        std::process::exit(1);
                    }
                };
                let secret_key = match chroma_crypto::schnorr::SecretKey32::from_bytes(secret_bytes)
                {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("Invalid secret key: {}", e);
                        std::process::exit(1);
                    }
                };
                let wallet = chroma_wallet::Wallet::from_secret_key("cli", secret_key)?;
                let sender = wallet.address();

                let recipient = match bech32_to_address(&to) {
                    Some(a) => a,
                    None => {
                        eprintln!("Invalid --to: expected bech32m (chr1...) or 0x hex");
                        std::process::exit(1);
                    }
                };

                // The nonce must match the account's, so read it from the
                // chain unless the caller supplied one.
                let next_nonce = match nonce {
                    Some(n) => n,
                    None => match open_storage(&data_dir) {
                        Ok(storage) => storage
                            .get_account(&sender)
                            .ok()
                            .flatten()
                            .map(|a| a.nonce)
                            .unwrap_or(0),
                        Err(e) => {
                            eprintln!("{}", e);
                            eprintln!("Pass --nonce to submit without reading the chain.");
                            std::process::exit(1);
                        }
                    },
                };

                let tx = wallet.create_transaction(
                    recipient,
                    chroma_core::types::Amount(amount),
                    chroma_core::types::Nonce(next_nonce),
                )?;
                let tx_hash = chroma_core::hash::Hash::blake3(
                    &chroma_core::serialize::CanonicalEncode::encode(&tx),
                );

                println!("From:   {}", address_to_bech32(&sender));
                println!("To:     {}", address_to_bech32(&recipient));
                println!("Amount: {} units", amount);
                println!("Nonce:  {}", next_nonce);

                match submit_transaction(node, &tx).await {
                    Ok(()) => println!("Submitted to {}: {}", node, tx_hash.to_hex()),
                    Err(e) => {
                        eprintln!("Submission failed: {}", e);
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
