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
        /// Keep a transaction index, so `tx get` and `tx history` can be
        /// answered.
        ///
        /// Off by default: nothing in consensus or relay looks a transaction
        /// up by hash, so this is a cost for serving other people's queries.
        /// Turning it on indexes what the chain already holds on the next
        /// start; there is no separate reindex step.
        #[arg(long)]
        index_transactions: bool,
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
    /// Print this node's identity without starting it.
    ///
    /// Creates the key if the data directory does not have one yet, so a
    /// seed record can be written before the node is first run.
    NodeId {
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
        /// Address to show the identity with, as it would be dialed.
        #[arg(long, default_value = "127.0.0.1:8333")]
        listen: SocketAddr,
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
        /// Amount in CHR, written as a decimal: `1.5`, `0.00001`.
        ///
        /// Exactly one of this and --amount-units is required.
        #[arg(long, conflicts_with = "amount_units", required_unless_present = "amount_units")]
        amount: Option<String>,
        /// Amount in units, for scripts that already count that way.
        /// 1 CHR = 1,000,000 units.
        #[arg(long)]
        amount_units: Option<u64>,
        /// Node to submit to, as `<node-id>.<noise-key>@host:port`. Omit it
        /// to use whatever the network's DNS seed publishes.
        #[arg(long)]
        node: Option<chroma_p2p::peer::PeerAddress>,
        /// Network whose seed to ask when --node is omitted.
        #[arg(long, default_value = "mainnet")]
        network: String,
        /// Sender's next nonce. Read from --data-dir when omitted.
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value = "chroma_data")]
        data_dir: PathBuf,
    },
    /// Look a transaction up by its hash.
    ///
    /// Answerable only by a node started with --index-transactions.
    Get {
        /// The transaction hash, 64 hex characters.
        #[arg(long)]
        hash: String,
        #[arg(long)]
        node: Option<chroma_p2p::peer::PeerAddress>,
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
    /// List the transactions touching an address.
    History {
        /// Address as bech32m (chr1...) or 0x hex.
        #[arg(long)]
        address: String,
        /// How many of the most recent to show.
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        node: Option<chroma_p2p::peer::PeerAddress>,
        #[arg(long, default_value = "mainnet")]
        network: String,
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
    /// Show an address's balance, as a node reports it.
    Balance {
        #[arg(short, long)]
        address: String,
        /// Node to ask, as `<node-id>.<noise-key>@host:port`. Omit it to use
        /// whatever the network's DNS seed publishes.
        #[arg(long)]
        node: Option<chroma_p2p::peer::PeerAddress>,
        /// Network whose seed to ask when --node is omitted.
        #[arg(long, default_value = "mainnet")]
        network: String,
    },
}

#[derive(Subcommand)]
enum BlockCommands {
    /// Show where a node's chain stands.
    Height {
        /// Node to ask, as `<node-id>.<noise-key>@host:port`. Omit it to use
        /// whatever the network's DNS seed publishes.
        #[arg(long)]
        node: Option<chroma_p2p::peer::PeerAddress>,
        /// Network whose seed to ask when --node is omitted.
        #[arg(long, default_value = "mainnet")]
        network: String,
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

/// Parse a 64-character hex hash.
fn parse_hash(s: &str) -> Option<chroma_core::hash::Hash> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&bytes);
    Some(chroma_core::hash::Hash(raw))
}

/// Parse an amount written in CHR into units.
///
/// The protocol counts in units and only in units: `RPC.md` §7.3 puts the
/// conversion in the display layer, and this program is the display layer.
/// Asking someone to type 10 when they mean a hundred-thousandth of a coin is
/// the wire format leaking out through the front door.
///
/// Parsed by splitting on the point and doing integer arithmetic, never
/// through `f64`. A binary float cannot hold 0.1, and money that is off by an
/// unpredictable unit is worse than money that is awkward to type.
fn parse_chr(s: &str) -> anyhow::Result<u64> {
    use chroma_core::constants::UNITS_PER_CHR;

    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty amount");
    }
    if s.starts_with('+') || s.starts_with('-') {
        anyhow::bail!("amounts carry no sign: {}", s);
    }
    if s.contains(['e', 'E']) {
        anyhow::bail!("exponent notation is not accepted: {}", s);
    }

    let (whole_str, frac_str) = match s.split_once('.') {
        Some((_, _)) if s.matches('.').count() > 1 => {
            anyhow::bail!("more than one decimal point: {}", s)
        }
        Some((whole, frac)) => {
            if frac.is_empty() {
                anyhow::bail!("nothing after the decimal point: {}", s);
            }
            (whole, frac)
        }
        None => (s, ""),
    };

    if whole_str.is_empty() {
        anyhow::bail!("no digits before the decimal point: {} (write 0{})", s, s);
    }
    for part in [whole_str, frac_str] {
        if !part.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("not a decimal number: {}", s);
        }
    }

    // Six, because a unit is 10^-6 CHR. A seventh digit is a value the chain
    // cannot represent, and rounding it away silently would send an amount
    // nobody asked for.
    let places = UNITS_PER_CHR.to_string().len() - 1;
    if frac_str.len() > places {
        anyhow::bail!(
            "{} has more than {} decimal places; the smallest unit is {} CHR",
            s,
            places,
            1.0 / UNITS_PER_CHR as f64
        );
    }

    let whole: u64 = whole_str
        .parse()
        .map_err(|_| anyhow::anyhow!("amount out of range: {}", s))?;
    let mut padded = frac_str.to_string();
    while padded.len() < places {
        padded.push('0');
    }
    let frac: u64 = if padded.is_empty() { 0 } else { padded.parse()? };

    whole
        .checked_mul(UNITS_PER_CHR)
        .and_then(|units| units.checked_add(frac))
        .ok_or_else(|| anyhow::anyhow!("amount out of range: {}", s))
}

/// Render units as CHR, exactly.
///
/// Integer arithmetic for the same reason as [`parse_chr`]: this used to
/// divide by a million in `f64`, which prints whatever the nearest binary
/// double happens to be.
fn format_chr(units: u64) -> String {
    use chroma_core::constants::UNITS_PER_CHR;

    let whole = units / UNITS_PER_CHR;
    let frac = units % UNITS_PER_CHR;
    if frac == 0 {
        return whole.to_string();
    }
    let places = UNITS_PER_CHR.to_string().len() - 1;
    let frac = format!("{:0width$}", frac, width = places);
    format!("{}.{}", whole, frac.trim_end_matches('0'))
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

        // Bounded: a seed can name a node that is firewalled or gone, and
        // the caller should move on to the next rather than wait forever.
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(node.socket),
        )
        .await
        .map_err(|_| anyhow::anyhow!("connection to {} timed out", node.socket))??;

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

impl NodeClient {
    /// Complete the version handshake, so the node will answer us.
    async fn handshake(&mut self) -> anyhow::Result<()> {
        use chroma_p2p::wire::{Message, MessageType, VersionMessage};

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
        self.send(Message::new(MessageType::Version, version.encode()))
            .await?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match self.recv(deadline).await? {
                Some(message) => match message.msg_type {
                    MessageType::VerAck => return Ok(()),
                    MessageType::Version => {
                        self.send(Message::new(MessageType::VerAck, vec![])).await?
                    }
                    _ => {}
                },
                None => anyhow::bail!("node closed the connection during the handshake"),
            }
        }
    }

    /// Ask a question and wait for the matching answer, ignoring the block and
    /// transaction traffic a node volunteers in the meantime.
    async fn ask(
        &mut self,
        request: chroma_p2p::wire::Message,
        expect: chroma_p2p::wire::MessageType,
    ) -> anyhow::Result<chroma_p2p::wire::Message> {
        self.send(request).await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while let Some(message) = self.recv(deadline).await? {
            if message.msg_type == expect {
                return Ok(message);
            }
        }
        anyhow::bail!("no answer from the node")
    }
}

/// Connect to a node, ready to ask it something.
///
/// The database cannot be read while a node holds it, so anything about the
/// chain has to come from the node itself. `--node` names one; without it the
/// network's DNS seed is asked, which is what the seed record is for.
async fn connect_to_node(
    node: Option<chroma_p2p::peer::PeerAddress>,
    network: &str,
) -> anyhow::Result<NodeClient> {
    let candidates = match node {
        Some(node) => vec![node],
        None => {
            let params = chroma_consensus::ChainParams::parse(network).ok_or_else(|| {
                anyhow::anyhow!(
                    "Unknown network '{}'. Expected devnet, testnet, mainnet or regtest.",
                    network
                )
            })?;
            let found = chroma_p2p::discovery::Discovery::seed_peers(params.network).await;
            if found.is_empty() {
                anyhow::bail!(
                    "no node given and the {} seed published none; pass --node <node-id>.<noise-key>@host:port",
                    params.network.as_str()
                );
            }
            found
        }
    };

    let mut last = None;
    for peer in &candidates {
        match NodeClient::connect(peer).await {
            Ok(mut client) => match client.handshake().await {
                Ok(()) => return Ok(client),
                Err(e) => {
                    eprintln!("{}: {}", peer.socket, e);
                    last = Some(e);
                }
            },
            Err(e) => {
                eprintln!("{}: {}", peer.socket, e);
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("no node to connect to")))
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
        Commands::Node {
            listen,
            connect,
            data_dir,
            network,
            no_mining,
            miner_address,
            index_transactions,
        } => {
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
            // The data directory carries one network's chain, and opening it
            // as another silently adopts those blocks as this network's
            // history.
            if let Err(e) = chroma_p2p::check_data_dir_network(&data_dir, params) {
                eprintln!("{}", e);
                std::process::exit(1);
            }

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
                .with_data_dir(data_dir.clone())
                .with_connect_addrs(connect)
                .with_node_secret(node_secret)
                .with_mining(!no_mining)
                .with_transaction_index(index_transactions);
            let config = match miner_address {
                Some(text) => match bech32_to_address(&text) {
                    Some(addr) => config.with_miner_address(addr),
                    None => {
                        eprintln!("Invalid --miner-address: expected bech32m (chr1...) or 0x hex");
                        std::process::exit(1);
                    }
                },
                None => {
                    // The default is a fresh address whose key is generated
                    // and thrown away, so every block mined to it pays into
                    // an address nobody can ever spend from. Fine as a way of
                    // keeping two test nodes from mining identical blocks;
                    // not something to do to someone's actual rewards.
                    if !no_mining {
                        eprintln!("Mining needs --miner-address: without one the rewards are paid");
                        eprintln!("to a fresh address whose key is discarded, and are unspendable.");
                        eprintln!();
                        eprintln!("  chroma wallet create --name miner --data-dir {}", data_dir.display());
                        eprintln!("  chroma node --miner-address <the chr1... it prints> ...");
                        eprintln!();
                        eprintln!("Or pass --no-mining to follow the chain without mining.");
                        std::process::exit(1);
                    }
                    config
                }
            };
            if !no_mining {
                println!("Mining rewards to: {}", address_to_bech32(&config.miner_address));
            }
            let mut node = chroma_p2p::Node::new(config);
            // Printed in the form a peer would pass to --connect, since that
            // is what an operator needs to hand out — and with the file it
            // came from, because the identity follows the data directory and
            // "why did it change?" is otherwise unanswerable from the log.
            println!(
                "Node identity (from {}): {}.{}@{}",
                data_dir.join("node_key").display(),
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
            WalletCommands::Balance {
                address,
                node,
                network,
            } => {
                use chroma_p2p::wire::{AccountMessage, GetAccountMessage, Message, MessageType};

                let addr = match bech32_to_address(&address) {
                    Some(a) => a,
                    None => {
                        eprintln!("Invalid address: expected bech32m (chr1...) or 0x-prefixed hex");
                        std::process::exit(1);
                    }
                };

                let mut client = connect_to_node(node, &network).await?;
                let reply = client
                    .ask(
                        Message::new(
                            MessageType::GetAccount,
                            GetAccountMessage { address: addr }.encode(),
                        ),
                        MessageType::Account,
                    )
                    .await?;
                let account = AccountMessage::decode(&reply.payload)?;

                println!(
                    "Balance: {} CHR ({} units)",
                    format_chr(account.balance),
                    account.balance
                );
                println!("Nonce: {}", account.nonce);
                if !account.exists {
                    println!("(this chain has no record of that address)");
                }
            }
        },
        Commands::Block { command } => match command {
            BlockCommands::Height { node, network } => {
                use chroma_core::types::CompactTarget;
                use chroma_p2p::wire::{ChainInfoMessage, Message, MessageType};

                let mut client = connect_to_node(node, &network).await?;
                let reply = client
                    .ask(
                        Message::new(MessageType::GetChainInfo, vec![]),
                        MessageType::ChainInfo,
                    )
                    .await?;
                let info = ChainInfoMessage::decode(&reply.payload)?;

                println!("Block height: {}", info.height);
                println!("Chain tip: {}", info.tip.to_hex());
                println!(
                    "Supply: {} CHR ({} units)",
                    format_chr(info.supply),
                    info.supply
                );
                println!(
                    "Difficulty: about 2^{} hashes per block (bits {:#010x})",
                    CompactTarget(info.bits).expected_hashes_log2(),
                    info.bits
                );
            }
        },
        Commands::Tx { command } => match command {
            TxCommands::Send {
                wallet: wallet_name,
                to,
                amount,
                amount_units,
                node,
                network,
                nonce,
                data_dir,
            } => {
                // clap guarantees exactly one of the two is present.
                let amount = match (amount, amount_units) {
                    (Some(chr), None) => match parse_chr(&chr) {
                        Ok(units) => units,
                        Err(e) => {
                            eprintln!("Invalid --amount: {}", e);
                            std::process::exit(1);
                        }
                    },
                    (None, Some(units)) => units,
                    _ => unreachable!("clap enforces exactly one amount"),
                };
                if amount == 0 {
                    eprintln!("Nothing to send: an amount must be greater than zero.");
                    std::process::exit(1);
                }

                // Without an explicit node, ask the seed. A wallet that can
                // only be used by someone already running a node is not much
                // of a wallet, and the seed record exists precisely so that
                // one address is enough to find the network.
                let candidates = match node {
                    Some(node) => vec![node],
                    None => {
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
                        let found = chroma_p2p::discovery::Discovery::seed_peers(
                            params.network,
                        )
                        .await;
                        if found.is_empty() {
                            eprintln!(
                                "No node given and the {} seed published none.",
                                params.network.as_str()
                            );
                            eprintln!("Pass --node <node-id>.<noise-key>@host:port.");
                            std::process::exit(1);
                        }
                        for peer in &found {
                            println!("From the seed: {}", peer);
                        }
                        found
                    }
                };
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
                println!("Amount: {} CHR ({} units)", format_chr(amount), amount);
                println!("Nonce:  {}", next_nonce);

                // Try each candidate: a seed can name a node that is not
                // answering just now, and that should cost a retry rather
                // than the whole submission.
                let mut last_error = None;
                let mut submitted = false;
                for peer in &candidates {
                    match submit_transaction(peer, &tx).await {
                        Ok(()) => {
                            println!("Submitted to {}: {}", peer.socket, tx_hash.to_hex());
                            submitted = true;
                            break;
                        }
                        Err(e) => {
                            eprintln!("{}: {}", peer.socket, e);
                            last_error = Some(e);
                        }
                    }
                }
                if !submitted {
                    eprintln!(
                        "Submission failed: {}",
                        last_error.map(|e| e.to_string()).unwrap_or_default()
                    );
                    std::process::exit(1);
                }
            }
            TxCommands::Get { hash, node, network } => {
                use chroma_p2p::wire::{
                    GetTransactionMessage, LookupStatus, Message, MessageType, TransactionAtMessage,
                };

                let tx_hash = match parse_hash(&hash) {
                    Some(h) => h,
                    None => {
                        eprintln!("Invalid --hash: expected 64 hex characters");
                        std::process::exit(1);
                    }
                };

                let mut client = connect_to_node(node, &network).await?;
                let reply = client
                    .ask(
                        Message::new(
                            MessageType::GetTransaction,
                            GetTransactionMessage { tx_hash }.encode(),
                        ),
                        MessageType::TransactionAt,
                    )
                    .await?;
                let found = TransactionAtMessage::decode(&reply.payload)?;

                match found.status {
                    LookupStatus::NotIndexed => {
                        eprintln!("That node keeps no transaction index, so it cannot answer.");
                        eprintln!("Start a node with --index-transactions, or ask another one.");
                        std::process::exit(1);
                    }
                    LookupStatus::NotFound => {
                        println!("No transaction with that hash on this node.");
                    }
                    LookupStatus::Found => {
                        println!("Transaction: {}", found.tx_hash.to_hex());
                        println!("Block:       {}", found.block_hash.to_hex());
                        println!("Height:      {}", found.height);
                        println!("Position:    {}", found.position);
                        if let Some(tx) = &found.transaction {
                            println!("From:        {}", address_to_bech32(&tx.sender_address()));
                            println!("To:          {}", address_to_bech32(&tx.recipient));
                            println!(
                                "Amount:      {} CHR ({} units)",
                                format_chr(tx.amount.0),
                                tx.amount.0
                            );
                            println!("Nonce:       {}", tx.nonce.0);
                        }
                        if !found.on_active_chain {
                            println!();
                            println!("This block lost a fork. The transaction was mined, but not");
                            println!("on the chain the network is following, so it did not move");
                            println!("anything. It may be mined again on the winning chain.");
                        }
                    }
                }
            }
            TxCommands::History {
                address,
                limit,
                node,
                network,
            } => {
                use chroma_p2p::wire::{
                    GetHistoryMessage, HistoryMessage, LookupStatus, Message, MessageType,
                };

                let addr = match bech32_to_address(&address) {
                    Some(a) => a,
                    None => {
                        eprintln!("Invalid address: expected bech32m (chr1...) or 0x hex");
                        std::process::exit(1);
                    }
                };

                let mut client = connect_to_node(node, &network).await?;
                let reply = client
                    .ask(
                        Message::new(
                            MessageType::GetHistory,
                            GetHistoryMessage {
                                address: addr,
                                limit,
                            }
                            .encode(),
                        ),
                        MessageType::History,
                    )
                    .await?;
                let history = HistoryMessage::decode(&reply.payload)?;

                if history.status == LookupStatus::NotIndexed {
                    eprintln!("That node keeps no transaction index, so it cannot answer.");
                    eprintln!("Start a node with --index-transactions, or ask another one.");
                    std::process::exit(1);
                }

                if history.entries.is_empty() {
                    println!("No transactions for {}", address_to_bech32(&addr));
                } else {
                    println!(
                        "Showing {} of {} transaction(s) for {}",
                        history.entries.len(),
                        history.total,
                        address_to_bech32(&addr)
                    );
                    println!();
                    println!("{:>8}  {:>3}  TRANSACTION", "HEIGHT", "POS");
                    for entry in &history.entries {
                        println!(
                            "{:>8}  {:>3}  {}",
                            entry.height,
                            entry.position,
                            entry.tx_hash.to_hex()
                        );
                    }
                }
            }
        },
        Commands::NodeId { data_dir, listen } => {
            let secret = load_or_create_node_key(&data_dir)?;
            let identity = chroma_crypto::noise::NodeKeypair::from_secret(secret)
                .map_err(|e| anyhow::anyhow!("invalid node secret: {}", e))?;
            println!("Key file: {}", data_dir.join("node_key").display());
            println!("Node ID:  {}", identity.node_id().to_hex());
            println!("Noise key:{}", identity.noise_key().to_hex());
            println!();
            println!("As a peer would dial it:");
            println!(
                "  {}.{}@{}",
                identity.node_id().to_hex(),
                identity.noise_key().to_hex(),
                listen
            );
            println!();
            println!("As a DNS seed TXT record (substitute the public address):");
            println!(
                "  chroma-seed={}.{}@{}",
                identity.node_id().to_hex(),
                identity.noise_key().to_hex(),
                listen
            );
        }
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

#[cfg(test)]
mod tests {
    use super::{format_chr, parse_chr};

    #[test]
    fn whole_coins_parse() {
        assert_eq!(parse_chr("1").unwrap(), 1_000_000);
        assert_eq!(parse_chr("0").unwrap(), 0);
        assert_eq!(parse_chr("1354").unwrap(), 1_354_000_000);
    }

    #[test]
    fn fractions_parse_to_the_unit() {
        assert_eq!(parse_chr("1.5").unwrap(), 1_500_000);
        assert_eq!(parse_chr("0.00001").unwrap(), 10);
        assert_eq!(parse_chr("0.000001").unwrap(), 1, "one unit");
        assert_eq!(parse_chr("1353.99999").unwrap(), 1_353_999_990);
    }

    #[test]
    fn a_seventh_decimal_place_is_refused_not_rounded() {
        // The chain cannot represent it. Rounding it away would send an
        // amount the caller did not ask for, which is the one outcome a
        // money command must never have.
        let err = parse_chr("0.0000001").unwrap_err().to_string();
        assert!(err.contains("decimal places"), "{}", err);
    }

    #[test]
    fn malformed_amounts_are_refused() {
        for bad in [
            "", " ", "-1", "+1", "1.", ".5", "1.2.3", "abc", "1e6", "1 000", "1,5",
        ] {
            assert!(parse_chr(bad).is_err(), "{:?} should not parse", bad);
        }
    }

    #[test]
    fn an_amount_past_the_supply_is_out_of_range() {
        // 18_446_744_073_710 CHR overflows u64 units.
        assert!(parse_chr("18446744073710").is_err());
    }

    #[test]
    fn formatting_is_exact() {
        assert_eq!(format_chr(0), "0");
        assert_eq!(format_chr(1), "0.000001");
        assert_eq!(format_chr(10), "0.00001");
        assert_eq!(format_chr(1_000_000), "1");
        assert_eq!(format_chr(1_500_000), "1.5");
        assert_eq!(format_chr(1_353_999_990), "1353.99999");
    }

    #[test]
    fn formatting_and_parsing_agree() {
        for units in [0u64, 1, 10, 999_999, 1_000_000, 1_353_999_990, u64::MAX] {
            let rendered = format_chr(units);
            assert_eq!(
                parse_chr(&rendered).unwrap(),
                units,
                "{} rendered as {}",
                units,
                rendered
            );
        }
    }
}
