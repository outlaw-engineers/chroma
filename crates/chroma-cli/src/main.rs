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
        /// Peer to dial, as `<node-id>.<noise-key>@host:port`. Both keys are
        /// required: the handshake needs the static key to connect at all,
        /// and the identity to know it reached the node it meant to.
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
        /// Name of the stored wallet to send from. Its passphrase is prompted
        /// for: a secret key passed on the command line would be left in the
        /// shell history and visible to every process on the machine.
        #[arg(long)]
        wallet: String,
        /// Recipient address (bech32m chr1... or 0x hex).
        #[arg(long)]
        to: String,
        /// Amount in units (1 CHR = 1,000,000 units).
        #[arg(long)]
        amount: u64,
        /// Node to submit to, as `<node-id>.<noise-key>@host:port`. The
        /// connection is encrypted, so the node's keys are needed to open it
        /// — take them from the node's startup log.
        #[arg(long)]
        node: chroma_p2p::peer::PeerAddress,
        /// Sender's next nonce. Read from --data-dir when omitted.
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Create a wallet, store it encrypted, and print its seed phrase once.
    Create {
        #[arg(short, long)]
        name: String,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
    /// Restore a wallet from its seed phrase and store it encrypted.
    Import {
        #[arg(short, long)]
        name: String,
        /// The 12- or 24-word BIP-39 phrase, quoted.
        #[arg(long)]
        seed: String,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
    /// List the wallets stored in the data directory.
    List {
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
    /// Show a wallet's address. Reads the stored wallet unless --seed is given.
    Address {
        #[arg(short, long)]
        name: String,
        /// Derive from this seed phrase instead of reading the stored wallet.
        #[arg(long)]
        seed: Option<String>,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
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
    chroma_wallet::address_to_bech32(addr)
}

/// Environment variable holding a wallet passphrase, for scripts and tests.
///
/// Prompting is the normal path. This exists because there is no other way to
/// drive the CLI unattended, and it is deliberately named so that anyone
/// reading a script can see the passphrase is sitting in the environment.
const PASSPHRASE_ENV: &str = "CHROMA_WALLET_PASSPHRASE";

/// Ask for a wallet passphrase.
///
/// `confirm` is for a passphrase being set rather than entered: a typo when
/// creating a wallet locks the key away permanently, so it is asked twice.
fn ask_passphrase(prompt: &str, confirm: bool) -> anyhow::Result<String> {
    if let Ok(from_env) = std::env::var(PASSPHRASE_ENV) {
        return Ok(from_env);
    }

    let passphrase = rpassword::prompt_password(prompt)?;
    if passphrase.is_empty() {
        anyhow::bail!("an empty passphrase would leave the wallet unprotected");
    }
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")?;
        if again != passphrase {
            anyhow::bail!("the passphrases do not match");
        }
    }
    Ok(passphrase)
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

/// A short-lived, encrypted connection to a node, speaking the peer protocol.
///
/// There is no RPC yet (spec §13 leaves it open), so the CLI connects the way
/// a peer would. That means the Noise handshake first: since §10 the link is
/// encrypted from the first byte, and a plaintext frame would be read as a
/// handshake message and get the connection dropped.
struct NodeClient {
    stream: tokio::net::TcpStream,
    session: chroma_crypto::noise::Session,
    /// Ciphertext read but not yet a whole Noise chunk.
    sealed: Vec<u8>,
    /// Decrypted bytes not yet a whole protocol frame.
    plain: Vec<u8>,
}

impl NodeClient {
    async fn connect(node: &chroma_p2p::peer::PeerAddress) -> anyhow::Result<Self> {
        use chroma_crypto::noise::{Handshake, NodeKeypair};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(node.socket).await?;

        // A throwaway identity: this connection exists to hand over one
        // transaction, and a stable key would only let nodes correlate the
        // submissions of whoever is running the CLI.
        let identity = NodeKeypair::generate()?;
        let mut handshake = Handshake::initiator(&identity, &node.node_id, &node.noise_key)?;

        for step in 0..3 {
            if step % 2 == 0 {
                let msg = handshake.write_message()?;
                stream.write_all(&(msg.len() as u16).to_be_bytes()).await?;
                stream.write_all(&msg).await?;
            } else {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).await.map_err(|e| {
                    anyhow::anyhow!("node closed the connection during the handshake: {}", e)
                })?;
                let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
                stream.read_exact(&mut msg).await?;
                handshake.read_message(&msg)?;
            }
        }

        Ok(NodeClient {
            stream,
            session: handshake.into_session()?,
            sealed: Vec::new(),
            plain: Vec::new(),
        })
    }

    async fn send(&mut self, msg: chroma_p2p::wire::Message) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let sealed = self.session.encrypt(&msg.encode())?;
        self.stream.write_all(&sealed).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Next protocol frame, or `None` if the deadline passes or the node hangs
    /// up.
    async fn recv(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> anyhow::Result<Option<chroma_p2p::wire::Message>> {
        use chroma_p2p::wire::{decode_frame, FrameDecode};
        use tokio::io::AsyncReadExt;

        let mut chunk = vec![0u8; 4096];
        loop {
            match decode_frame(&self.plain) {
                Ok(FrameDecode::Complete { message, consumed }) => {
                    self.plain.drain(..consumed);
                    return Ok(Some(message));
                }
                Ok(FrameDecode::Incomplete { .. }) => {}
                Err(e) => anyhow::bail!("node sent a malformed frame: {}", e),
            }

            let n = match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => return Ok(None),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
            };
            self.sealed.extend_from_slice(&chunk[..n]);

            // Each Noise chunk is a 4-byte big-endian length and that many
            // ciphertext bytes; a partial one waits for the rest.
            while self.sealed.len() >= 4 {
                let len = u32::from_be_bytes([
                    self.sealed[0],
                    self.sealed[1],
                    self.sealed[2],
                    self.sealed[3],
                ]) as usize;
                if self.sealed.len() < 4 + len {
                    break;
                }
                let ciphertext = self.sealed[..4 + len].to_vec();
                self.sealed.drain(..4 + len);
                self.plain
                    .extend_from_slice(&self.session.decrypt(&ciphertext)?);
            }
        }
    }
}

/// Submit a signed transaction to a node over the P2P protocol.
async fn submit_transaction(
    node: &chroma_p2p::peer::PeerAddress,
    tx: &chroma_tx::Transaction,
) -> anyhow::Result<()> {
    use chroma_core::serialize::CanonicalEncode;
    use chroma_p2p::wire::{Message, MessageType, VersionMessage};

    let mut client = NodeClient::connect(node).await?;

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
    client
        .send(Message::new(MessageType::Version, version.encode()))
        .await?;

    // Wait for the node's verack before sending, so the transaction is not
    // dropped by a peer that has not finished the handshake.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match client.recv(deadline).await? {
            Some(message) => match message.msg_type {
                MessageType::VerAck => break,
                MessageType::Version => {
                    client
                        .send(Message::new(MessageType::VerAck, vec![]))
                        .await?
                }
                _ => {}
            },
            None => anyhow::bail!("node closed the connection during the handshake"),
        }
    }

    client
        .send(Message::new(MessageType::Tx, tx.encode()))
        .await?;

    // Give the node a moment to read and validate before we hang up; a reject
    // arrives on this connection if it did not like it.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(500);
    while let Some(message) = client.recv(deadline).await? {
        if message.msg_type == MessageType::Reject {
            if let Ok(reject) = chroma_p2p::wire::RejectMessage::decode(&message.payload) {
                anyhow::bail!("node rejected the transaction: {}", reject.reason);
            }
            anyhow::bail!("node rejected the transaction");
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

/// Read this node's identity seed from the data directory, creating one on
/// first run.
///
/// Stored as hex in `node_key`, owner-readable only where the platform
/// supports it: anyone holding it can impersonate the node to its peers. Both
/// the ed25519 identity and the X25519 static key come from this one seed, so
/// this file is the whole backup.
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

    // Owner-only from the moment it exists, and an error if that cannot be
    // arranged: anyone who can read this file can impersonate the node.
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(hex::encode(secret).as_bytes())?;
        file.sync_all()?;
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
            // A build without the `randomx` feature cannot hash a header for
            // any network that uses RandomX, so it can neither mine nor
            // validate there. Refuse at startup: the alternative is a node
            // that runs, connects, and silently rejects every block it is
            // sent, which looks like a network problem rather than a build
            // that is missing a feature.
            if params.pow == chroma_crypto::randomx::PowAlgorithm::RandomX
                && !chroma_crypto::randomx::randomx_available()
            {
                eprintln!(
                    "This build has no RandomX support, so it cannot validate or mine on {}.",
                    params.network.as_str()
                );
                eprintln!(
                    "Rebuild with the 'randomx' feature (the default; it needs cmake and a"
                );
                eprintln!("C++ toolchain), or run with --network regtest.");
                std::process::exit(1);
            }

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
            // Printed in the form a peer would pass to --connect, since that
            // is what an operator needs to hand out.
            println!(
                "Node identity: {}.{}@{}",
                node.node_id().to_hex(),
                node.noise_key().to_hex(),
                listen
            );
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
            WalletCommands::Create { name, data_dir } => {
                // The wallet is generated from a phrase rather than a bare
                // key, so the printed phrase really is a full backup: the
                // keystore can be lost and the wallet still restored.
                let phrase = chroma_wallet::generate_seed_phrase();
                let wallet = chroma_wallet::wallet_from_seed_phrase(&name, &phrase)?;
                let passphrase = ask_passphrase("New wallet passphrase: ", true)?;
                let path = chroma_wallet::keystore::save(&data_dir, &wallet, &passphrase)?;

                println!("Wallet created: {}", wallet.name());
                println!("Address: {}", address_to_bech32(&wallet.address()));
                println!("Stored:  {}", path.display());
                println!();
                println!("Write down the seed phrase. It is shown once and is the only way");
                println!("to recover this wallet if the file or the passphrase is lost:");
                println!();
                println!("  {}", phrase.join(" "));
            }
            WalletCommands::Import { name, seed, data_dir } => {
                let words: Vec<String> = seed.split_whitespace().map(|s| s.to_string()).collect();
                let wallet = match chroma_wallet::wallet_from_seed_phrase(&name, &words) {
                    Ok(wallet) => wallet,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                let passphrase = ask_passphrase("New wallet passphrase: ", true)?;
                let path = chroma_wallet::keystore::save(&data_dir, &wallet, &passphrase)?;
                println!("Wallet imported: {}", wallet.name());
                println!("Address: {}", address_to_bech32(&wallet.address()));
                println!("Stored:  {}", path.display());
            }
            WalletCommands::List { data_dir } => {
                let names = chroma_wallet::keystore::list(&data_dir);
                if names.is_empty() {
                    println!("No wallets in {}", data_dir.display());
                }
                for name in names {
                    // The address is in the keystore header, so listing does
                    // not need anyone's passphrase.
                    match chroma_wallet::keystore::load_address(&data_dir, &name) {
                        Ok(address) => println!("{}\t{}", name, address),
                        Err(e) => println!("{}\t<unreadable: {}>", name, e),
                    }
                }
            }
            WalletCommands::Address { name, seed, data_dir } => {
                let address = match seed {
                    Some(seed) => {
                        let words: Vec<String> =
                            seed.split_whitespace().map(|s| s.to_string()).collect();
                        match chroma_wallet::wallet_from_seed_phrase(&name, &words) {
                            Ok(wallet) => address_to_bech32(&wallet.address()),
                            Err(e) => {
                                eprintln!("Error: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                    None => match chroma_wallet::keystore::load_address(&data_dir, &name) {
                        Ok(address) => address,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    },
                };
                println!("Wallet '{}':", name);
                println!("  Address: {}", address);
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
                wallet: wallet_name,
                to,
                amount,
                node,
                nonce,
                data_dir,
            } => {
                let passphrase = ask_passphrase("Wallet passphrase: ", false)?;
                let wallet =
                    match chroma_wallet::keystore::load(&data_dir, &wallet_name, &passphrase) {
                        Ok(wallet) => wallet,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            std::process::exit(1);
                        }
                    };
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

                match submit_transaction(&node, &tx).await {
                    Ok(()) => println!("Submitted to {}: {}", node.socket, tx_hash.to_hex()),
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
