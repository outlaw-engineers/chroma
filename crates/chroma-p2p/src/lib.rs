pub mod wire;
pub mod peer;
pub mod mempool;
pub mod discovery;
pub mod sync;
pub mod orphan;

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use chroma_core::hash::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::discovery::Discovery;
use crate::mempool::Mempool;
use crate::sync::ChainSyncer;
use crate::orphan::OrphanPool;
use crate::peer::{
    ConnectionSlot, PeerManager, PeerState, PEER_TIMEOUT_SECS, PING_INTERVAL_SECS,
    VERSION_TIMEOUT_SECS,
};
use crate::wire::{
    decode_frame, FrameDecode, GetDataMessage, GetHeadersMessage, HeadersMessage, InvEntry,
    InvMessage, InvType, Message, MessageType, PingMessage, RejectMessage, VersionMessage,
    MAX_MESSAGE_SIZE,
};

/// Capacity of the per-connection outbound queue. Bounded so that a peer that
/// stops reading applies backpressure instead of growing our memory without
/// limit.
const PEER_SEND_QUEUE: usize = 256;

/// Size of a single read from a socket. Frames larger than this are
/// reassembled across reads by the framing loop.
const READ_CHUNK: usize = 16 * 1024;

/// How long shutdown waits for a task to notice the signal before abandoning
/// it.
const SHUTDOWN_GRACE_SECS: u64 = 5;

/// Largest inventory we will act on in one message, in either direction.
/// Bounds the work a single peer can ask of us.
const MAX_INVENTORY: usize = 500;

pub const PROTOCOL_VERSION: u32 = 1;
pub const SERVICES: u64 = 0;

#[derive(Debug)]
pub enum P2pError {
    Io(std::io::Error),
    Protocol(String),
}

impl fmt::Display for P2pError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            P2pError::Io(e) => write!(f, "io: {}", e),
            P2pError::Protocol(s) => write!(f, "protocol: {}", s),
        }
    }
}

impl From<std::io::Error> for P2pError {
    fn from(e: std::io::Error) -> Self {
        P2pError::Io(e)
    }
}

impl From<chroma_core::error::CoreError> for P2pError {
    fn from(e: chroma_core::error::CoreError) -> Self {
        P2pError::Protocol(e.to_string())
    }
}

/// A fresh random payout address, so two nodes started the same way do not
/// mine to the same account.
pub fn random_address() -> chroma_core::types::Address {
    let secret = chroma_crypto::schnorr::SecretKey32::generate();
    let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret)
        .expect("a generated secret key always has a public key");
    chroma_core::types::Address::from_hash160(chroma_core::hash::Hash160(
        chroma_crypto::hash::hash160(&pubkey.0),
    ))
}

pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub connect_addrs: Vec<SocketAddr>,
    pub genesis_hash: Hash,
    pub chain_height: Arc<AtomicU32>,
    pub data_dir: PathBuf,
    /// Run the mining loop. Off in tests that only exercise networking.
    pub mining_enabled: bool,
    /// Consensus parameters for the network this node is on.
    pub params: chroma_consensus::ChainParams,
    /// Address the block reward is paid to.
    ///
    /// Two nodes mining to the same address with the same empty block and the
    /// same timestamp produce byte-identical blocks, so they never actually
    /// compete — which silently hides whether fork choice works at all.
    pub miner_address: chroma_core::types::Address,
}

impl NodeConfig {
    pub fn new(listen_addr: SocketAddr, genesis_hash: Hash) -> Self {
        NodeConfig {
            listen_addr,
            connect_addrs: Vec::new(),
            genesis_hash,
            chain_height: Arc::new(AtomicU32::new(0)),
            data_dir: PathBuf::from("chroma_data"),
            mining_enabled: true,
            params: chroma_consensus::ChainParams::devnet(),
            miner_address: random_address(),
        }
    }

    pub fn with_miner_address(mut self, address: chroma_core::types::Address) -> Self {
        self.miner_address = address;
        self
    }

    /// Select the network. Also fixes up the expected genesis hash, since
    /// each network has its own genesis.
    pub fn with_params(mut self, params: chroma_consensus::ChainParams) -> Self {
        self.genesis_hash = chroma_consensus::build_genesis_block_with(&params).hash();
        self.params = params;
        self
    }

    pub fn with_data_dir(mut self, data_dir: PathBuf) -> Self {
        self.data_dir = data_dir;
        self
    }

    pub fn with_connect_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.connect_addrs = addrs;
        self
    }

    pub fn with_mining(mut self, enabled: bool) -> Self {
        self.mining_enabled = enabled;
        self
    }
}

pub struct Node {
    config: NodeConfig,
    peer_manager: Arc<RwLock<PeerManager>>,
    mempool: Arc<RwLock<Mempool>>,
    discovery: Discovery,
    storage: Arc<chroma_storage::Storage>,
    chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    syncer: Arc<RwLock<ChainSyncer>>,
    orphans: Arc<RwLock<OrphanPool>>,
    event_tx: mpsc::UnboundedSender<NodeEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<NodeEvent>>,
    outbound_tx: Option<mpsc::UnboundedSender<OutboundCommand>>,
    outbound_rx: Option<mpsc::UnboundedReceiver<OutboundCommand>>,
    /// Identity nonce echoed in our version message, used to spot the case
    /// where we dial ourselves.
    identity_nonce: u64,
    shutdown_tx: broadcast::Sender<()>,
    tasks: Vec<JoinHandle<()>>,
    /// Address actually bound by `run()`. Differs from `config.listen_addr`
    /// when the caller asked for port 0.
    local_addr: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub enum NodeEvent {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    BlockReceived(Hash, u32),
    BlockMined(Hash, u32),
    TxReceived(Hash),
    /// Number of headers accepted from a peer in one batch.
    HeadersAccepted(usize),
    /// The active chain was replaced by one with more work.
    Reorganized { depth: u32, new_tip: Hash },
    SyncComplete,
    Error(String),
}

enum OutboundCommand {
    Send(SocketAddr, Message),
    Connect(SocketAddr),
    Disconnect(SocketAddr),
}

/// Lets consensus read blocks back during a reorg without depending on the
/// storage crate.
struct StorageBlocks<'a>(&'a chroma_storage::Storage);

impl chroma_consensus::BlockSource for StorageBlocks<'_> {
    fn get_block(&self, hash: &Hash) -> Option<chroma_block::Block> {
        self.0.get_block_by_hash(hash).ok().flatten()
    }
}

/// Everything a live connection needs from the node.
///
/// Passed as one struct because the connection handler needs seven pieces of
/// shared state, and threading them as positional arguments through three call
/// sites made it easy to swap two of them by mistake.
#[derive(Clone)]
struct ConnectionContext {
    peer_manager: Arc<RwLock<PeerManager>>,
    mempool: Arc<RwLock<Mempool>>,
    storage: Arc<chroma_storage::Storage>,
    chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    syncer: Arc<RwLock<ChainSyncer>>,
    orphans: Arc<RwLock<OrphanPool>>,
    event_tx: mpsc::UnboundedSender<NodeEvent>,
    /// Used to relay an accepted block on to our other peers.
    outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
    chain_height: Arc<AtomicU32>,
    listen_port: u16,
    identity_nonce: u64,
    /// Connection handlers are spawned detached, so they need their own way to
    /// learn about shutdown. Dropping the peer's send channel is not enough:
    /// the handler holds a clone of it, so the writer task would never see the
    /// channel close and the socket would linger until the idle timeout.
    shutdown_tx: broadcast::Sender<()>,
}

impl ConnectionContext {
    /// Our version handshake payload, carrying the port we listen on so the
    /// peer can key us by a stable address rather than an ephemeral one.
    fn version_message(&self) -> VersionMessage {
        VersionMessage {
            version: PROTOCOL_VERSION,
            services: SERVICES,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            height: self.chain_height.load(Ordering::Relaxed),
            nonce: self.identity_nonce,
            listen_port: self.listen_port,
        }
    }
}

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, _) = broadcast::channel(1);

        let db_path = config.data_dir.clone();
        let storage = chroma_storage::Storage::open(&db_path)
            .expect("failed to open storage database");

        let chain_state = Self::init_chain_state(&storage, config.genesis_hash, config.params);

        let height = chain_state.tip.height.0;
        config.chain_height.store(height, Ordering::Relaxed);

        // Seed the header chain from what is already on disk, so a restarted
        // node resumes sync from its own tip instead of from genesis.
        let mut syncer = ChainSyncer::with_params(config.params);
        for (_, header) in chain_state.headers.iter() {
            syncer.insert_header(header.clone());
        }

        Node {
            config,
            peer_manager: Arc::new(RwLock::new(PeerManager::new())),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            discovery: Discovery::new(),
            storage: Arc::new(storage),
            chain_state: Arc::new(RwLock::new(chain_state)),
            syncer: Arc::new(RwLock::new(syncer)),
            orphans: Arc::new(RwLock::new(OrphanPool::new())),
            event_tx,
            event_rx: Some(event_rx),
            outbound_tx: Some(outbound_tx),
            outbound_rx: Some(outbound_rx),
            identity_nonce: rand_u64(),
            shutdown_tx,
            tasks: Vec::new(),
            local_addr: None,
        }
    }

    fn init_chain_state(
        storage: &chroma_storage::Storage,
        expected_genesis_hash: Hash,
        params: chroma_consensus::ChainParams,
    ) -> chroma_consensus::ChainState {
        use chroma_consensus::ChainState;
        use chroma_core::u256::U256;

        match storage.get_tip() {
            Ok(Some(persisted_tip)) => {
                // Prefer the persisted state: revalidating every block on
                // startup costs the whole chain's validation time, which grows
                // without bound. The stored accounts are trusted only after
                // their root matches the tip header, so a truncated or
                // corrupted state falls back to a full replay.
                match Self::restore_from_state(storage, params, &persisted_tip) {
                    Some(chain) => {
                        println!(
                            "Loaded chain from storage: height={}, supply={} units",
                            chain.tip.height.0,
                            chain.state.total_supply()
                        );
                        chain
                    }
                    None => {
                        println!("Stored state did not verify; replaying the chain");
                        Self::replay_from_storage(storage, params, persisted_tip.height)
                    }
                }
            }
            _ => {
                let chain = ChainState::with_params(params);
                let genesis = chroma_consensus::build_genesis_block_with(&params);
                let genesis_hash = genesis.hash();

                if expected_genesis_hash != genesis_hash {
                    eprintln!(
                        "Warning: expected genesis hash {} but computed {}",
                        expected_genesis_hash.to_hex(),
                        genesis_hash.to_hex()
                    );
                }

                storage.apply_block(&genesis).ok();

                let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
                    &genesis.header.bits.to_full_target(),
                ));
                let tip = chroma_storage::PersistedTip {
                    height: 0,
                    hash: genesis_hash,
                    cumulative_work: genesis_work.to_be_bytes(),
                    supply: 0,
                };
                storage.put_tip(&tip).ok();
                storage.put_genesis_hash(&genesis_hash).ok();
                storage.flush().ok();

                println!("Created genesis block: {}", genesis_hash.to_hex());

                chain
            }
        }
    }

    /// Rebuild chain state from the persisted accounts, verifying it against
    /// the tip header's state root.
    ///
    /// Returns `None` when anything does not line up, leaving the caller to
    /// replay instead.
    fn restore_from_state(
        storage: &chroma_storage::Storage,
        params: chroma_consensus::ChainParams,
        persisted_tip: &chroma_storage::PersistedTip,
    ) -> Option<chroma_consensus::ChainState> {
        use chroma_consensus::{BlockIndexEntry, ChainState, ChainTip};
        use chroma_core::types::BlockHeight;
        use chroma_core::u256::U256;

        let tip_header = storage.get_header(persisted_tip.height).ok()??;
        if tip_header.hash() != persisted_tip.hash {
            return None;
        }

        let state = storage.load_state().ok()?;
        if state.compute_state_root() != tip_header.state_root {
            return None;
        }

        // Headers are cheap to re-read, and the work per block follows from
        // the target each header declares — no state needed.
        let mut chain = ChainState::with_params(params);
        let mut cumulative = chain.tip.cumulative_work;
        for height in 1..=persisted_tip.height {
            let header = storage.get_header(height).ok()??;
            let work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
                &header.bits.to_full_target(),
            ));
            cumulative = cumulative.checked_add(&work)?;
            chain.index.insert(
                header.hash(),
                BlockIndexEntry {
                    header: header.clone(),
                    cumulative_work: cumulative,
                },
            );
            chain.headers.insert(height, header);
        }

        chain.state = state;
        chain.tip = ChainTip {
            height: BlockHeight(persisted_tip.height),
            hash: persisted_tip.hash,
            header: tip_header,
            cumulative_work: cumulative,
            supply: chain.state.total_supply(),
        };
        chain.tips.insert(chain.tip.hash, chain.tip.clone());
        Some(chain)
    }

    /// Rebuild chain state by revalidating every stored block.
    fn replay_from_storage(
        storage: &chroma_storage::Storage,
        params: chroma_consensus::ChainParams,
        height: u32,
    ) -> chroma_consensus::ChainState {
        use chroma_consensus::ChainState;

        let mut chain = ChainState::with_params(params);
        let source = StorageBlocks(storage);
        for h in 1..=height {
            match storage.get_block_by_height(h) {
                Ok(Some(block)) => {
                    if let Err(e) = chain.apply_block_with(&block, &source) {
                        eprintln!("Stopping replay at height {}: {}", h, e);
                        break;
                    }
                }
                _ => break,
            }
        }
        chain
    }

    pub fn storage(&self) -> &chroma_storage::Storage {
        &self.storage
    }

    /// The address the listener is bound to, once `run()` has been called.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        self.mempool.clone()
    }

    pub fn peer_manager(&self) -> Arc<RwLock<PeerManager>> {
        self.peer_manager.clone()
    }

    pub fn chain_state(&self) -> Arc<RwLock<chroma_consensus::ChainState>> {
        self.chain_state.clone()
    }

    pub fn chain_height(&self) -> u32 {
        self.config.chain_height.load(Ordering::Relaxed)
    }

    pub fn event_rx(&mut self) -> Option<mpsc::UnboundedReceiver<NodeEvent>> {
        self.event_rx.take()
    }

    /// Start the node: listener, dialer, peer maintenance and (optionally) the
    /// miner. Returns once the tasks are spawned; call [`Node::shutdown`] to
    /// stop them.
    pub async fn run(&mut self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        // Resolve the bound address: the caller may have asked for port 0.
        let bound = listener.local_addr()?;
        let listen_port = bound.port();
        self.local_addr = Some(bound);

        let discovered = self
            .discovery
            .discover_peers(self.peer_manager.clone(), &self.config.connect_addrs)
            .await;

        let outbound_rx = self.outbound_rx.take().expect("run() called twice");
        let outbound_tx = self.outbound_tx.as_ref().unwrap().clone();

        let ctx = ConnectionContext {
            peer_manager: self.peer_manager.clone(),
            mempool: self.mempool.clone(),
            storage: self.storage.clone(),
            chain_state: self.chain_state.clone(),
            syncer: self.syncer.clone(),
            orphans: self.orphans.clone(),
            event_tx: self.event_tx.clone(),
            outbound_tx: outbound_tx.clone(),
            chain_height: self.config.chain_height.clone(),
            listen_port,
            identity_nonce: self.identity_nonce,
            shutdown_tx: self.shutdown_tx.clone(),
        };

        {
            let ctx = ctx.clone();
            let shutdown = self.shutdown_tx.subscribe();
            self.tasks.push(tokio::spawn(async move {
                Self::run_outbound(ctx, outbound_rx, shutdown).await;
            }));
        }

        // Dial the explicitly configured peers *and* whatever discovery turned
        // up from the seed lists. Discovery only registers addresses in the
        // peer manager; without dialing what it returns, a peer learned from a
        // seed would sit in the table forever and never be connected to.
        // Repeats are harmless — begin_connection rejects a second dial.
        for addr in self
            .config
            .connect_addrs
            .iter()
            .copied()
            .chain(discovered.into_iter())
        {
            let _ = outbound_tx.send(OutboundCommand::Connect(addr));
        }

        {
            let ctx = ctx.clone();
            let shutdown = self.shutdown_tx.subscribe();
            self.tasks.push(tokio::spawn(async move {
                Self::run_inbound(listener, ctx, shutdown).await;
            }));
        }

        {
            let peer_mgr = self.peer_manager.clone();
            let tick_tx = outbound_tx.clone();
            let shutdown = self.shutdown_tx.subscribe();
            self.tasks.push(tokio::spawn(async move {
                Self::run_peer_tick(peer_mgr, tick_tx, shutdown).await;
            }));
        }

        if self.config.mining_enabled {
            let storage = self.storage.clone();
            let chain_state = self.chain_state.clone();
            let event_tx = self.event_tx.clone();
            let height = self.config.chain_height.clone();
            let miner_address = self.config.miner_address;
            let miner_pool = self.mempool.clone();
            let shutdown = self.shutdown_tx.subscribe();
            let peer_mgr = self.peer_manager.clone();
            let miner_tx = outbound_tx.clone();
            let miner_syncer = self.syncer.clone();
            self.tasks.push(tokio::spawn(async move {
                Self::run_miner(
                    storage, chain_state, event_tx, height, miner_address, miner_pool, peer_mgr,
                    miner_tx, miner_syncer, shutdown,
                )
                .await;
            }));
        }

        Ok(())
    }

    /// Signal every task to stop, wait for them, close peer connections and
    /// flush storage to disk.
    ///
    /// Safe to call more than once, and safe to call on a node that was never
    /// started.
    ///
    /// The database lock is held until the `Node` itself is dropped: sled
    /// takes it exclusively, so another `Node` cannot open the same data
    /// directory until this one is gone.
    pub async fn shutdown(&mut self) {
        // A send error just means no task is listening; shutdown proceeds.
        let _ = self.shutdown_tx.send(());

        // Dropping the command sender unblocks run_outbound's recv().
        self.outbound_tx = None;

        // Dropping the per-peer channels makes each writer task finish, which
        // closes the socket and lets the remote see a clean EOF.
        {
            let mut pm = self.peer_manager.write().await;
            let addrs: Vec<SocketAddr> = pm.connected_peers().into_iter().map(|p| p.addr).collect();
            for addr in addrs {
                pm.mark_disconnected(&addr);
            }
        }

        let tasks = std::mem::take(&mut self.tasks);
        for task in tasks {
            let abort = task.abort_handle();
            if tokio::time::timeout(Duration::from_secs(SHUTDOWN_GRACE_SECS), task)
                .await
                .is_err()
            {
                // Overran its grace period (a mining round, most likely).
                // Cancel it so it cannot still be writing while we flush.
                abort.abort();
            }
        }

        if let Err(e) = self.storage.flush() {
            let _ = self.event_tx.send(NodeEvent::Error(format!("flush on shutdown: {}", e)));
        }
    }

    /// A handle that triggers [`Node::shutdown`] from another task.
    pub fn shutdown_signal(&self) -> broadcast::Sender<()> {
        self.shutdown_tx.clone()
    }

    async fn run_outbound(
        ctx: ConnectionContext,
        mut outbound_rx: mpsc::UnboundedReceiver<OutboundCommand>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        loop {
            let cmd = tokio::select! {
                _ = shutdown.recv() => break,
                cmd = outbound_rx.recv() => match cmd {
                    Some(cmd) => cmd,
                    None => break,
                },
            };

            match cmd {
                OutboundCommand::Connect(addr) => {
                    // Claim the slot before dialing so two concurrent Connect
                    // commands for the same peer cannot both open a socket.
                    let slot = {
                        let mut pm = ctx.peer_manager.write().await;
                        pm.begin_connection(addr, false)
                    };
                    if slot != ConnectionSlot::Accepted {
                        continue;
                    }

                    let stream = match tokio::time::timeout(
                        Duration::from_secs(PEER_TIMEOUT_SECS),
                        TcpStream::connect(addr),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        _ => {
                            let mut pm = ctx.peer_manager.write().await;
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.score_bad(5);
                            }
                            pm.mark_disconnected(&addr);
                            continue;
                        }
                    };

                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        let event_tx = ctx.event_tx.clone();
                        if let Err(e) = Self::handle_connection(stream, addr, ctx, false).await {
                            let _ = event_tx.send(NodeEvent::Error(format!("{}: {}", addr, e)));
                        }
                    });
                }

                // Send over the peer's established connection. There is
                // deliberately no fallback that opens a fresh socket: a
                // message to a peer we are not connected to is a bug in the
                // caller, not something to paper over with a new TCP dial.
                OutboundCommand::Send(addr, msg) => {
                    let channel = {
                        let pm = ctx.peer_manager.read().await;
                        pm.get_channel(&addr).cloned()
                    };
                    match channel {
                        Some(tx) => {
                            if tx.send(msg.encode()).await.is_err() {
                                let mut pm = ctx.peer_manager.write().await;
                                pm.mark_disconnected(&addr);
                            }
                        }
                        None => {
                            let _ = ctx.event_tx.send(NodeEvent::Error(format!(
                                "send to {}: no established connection",
                                addr
                            )));
                        }
                    }
                }

                OutboundCommand::Disconnect(addr) => {
                    // Dropping the channel ends the writer task, which closes
                    // the socket and unblocks the reader.
                    let mut pm = ctx.peer_manager.write().await;
                    pm.mark_disconnected(&addr);
                }
            }
        }
    }

    async fn run_inbound(
        listener: TcpListener,
        ctx: ConnectionContext,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        loop {
            let (stream, src) = tokio::select! {
                _ = shutdown.recv() => break,
                accepted = listener.accept() => match accepted {
                    Ok(v) => v,
                    Err(_) => continue,
                },
            };

            // The peer's real identity is not known until its version message
            // arrives, so the slot is claimed inside handle_connection once
            // the announced listen port is known. Only the crude inbound cap
            // is applied here.
            let over_capacity = {
                let pm = ctx.peer_manager.read().await;
                pm.inbound_count() >= crate::peer::MAX_INBOUND_PEERS
            };
            if over_capacity {
                drop(stream);
                continue;
            }

            let ctx = ctx.clone();
            tokio::spawn(async move {
                let event_tx = ctx.event_tx.clone();
                if let Err(e) = Self::handle_connection(stream, src, ctx, true).await {
                    let _ = event_tx.send(NodeEvent::Error(format!("{}: {}", src, e)));
                }
            });
        }
    }

    /// Drive one peer connection for its whole lifetime.
    ///
    /// The socket is split: a writer task owns the write half and is fed from
    /// an mpsc channel registered in the `PeerManager`, so any part of the node
    /// can send to this peer over the connection that is already open. This
    /// loop owns the read half and does framing.
    async fn handle_connection(
        stream: TcpStream,
        src: SocketAddr,
        ctx: ConnectionContext,
        inbound: bool,
    ) -> Result<(), P2pError> {
        stream.set_nodelay(true).ok();
        let (mut reader, mut writer) = stream.into_split();

        // `src` is the socket's remote address. For an inbound connection that
        // is an ephemeral port, so the peer is re-keyed to its advertised
        // listen address once the version message arrives.
        let mut peer_key = src;
        let mut keyed = !inbound;

        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(PEER_SEND_QUEUE);
        let writer_task = tokio::spawn(async move {
            while let Some(bytes) = out_rx.recv().await {
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });

        if !inbound {
            let mut pm = ctx.peer_manager.write().await;
            pm.set_channel(peer_key, out_tx.clone());
        }

        // Outbound side speaks first.
        if !inbound {
            let version = Message::new(MessageType::Version, ctx.version_message().encode());
            if out_tx.send(version.encode()).await.is_err() {
                Self::finish_connection(&ctx, &peer_key, keyed, out_tx, writer_task).await;
                return Err(P2pError::Protocol("peer write channel closed".into()));
            }
        }

        let mut acc: Vec<u8> = Vec::with_capacity(READ_CHUNK);
        let mut chunk = vec![0u8; READ_CHUNK];
        let handshake_deadline =
            tokio::time::Instant::now() + Duration::from_secs(VERSION_TIMEOUT_SECS);
        let mut shutdown = ctx.shutdown_tx.subscribe();
        let mut result: Result<(), P2pError> = Ok(());

        'read: loop {
            let ready = {
                let pm = ctx.peer_manager.read().await;
                pm.get_peer(&peer_key)
                    .map(|p| p.state == PeerState::Ready)
                    .unwrap_or(false)
            };

            // Until the handshake completes the connection lives on a short
            // leash; afterwards the idle timeout governs, refreshed by pings.
            let deadline = if ready {
                tokio::time::Instant::now() + Duration::from_secs(PEER_TIMEOUT_SECS)
            } else {
                handshake_deadline
            };

            let read = tokio::select! {
                _ = shutdown.recv() => break 'read,
                read = tokio::time::timeout_at(deadline, reader.read(&mut chunk)) => read,
            };

            let n = match read {
                Ok(Ok(0)) => break 'read, // clean EOF
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    result = Err(P2pError::Io(e));
                    break 'read;
                }
                Err(_) => {
                    result = Err(P2pError::Protocol(if ready {
                        "peer timed out".into()
                    } else {
                        "handshake timed out".into()
                    }));
                    break 'read;
                }
            };
            acc.extend_from_slice(&chunk[..n]);

            // The accumulator legitimately holds one incomplete maximum-size
            // frame plus whatever else arrived in the same read, so the cap
            // has to allow for a full chunk of slack on top of a full frame.
            // Without it, a peer sending back-to-back maximum frames would be
            // banned for behaving correctly.
            if acc.len() > MAX_MESSAGE_SIZE + crate::wire::HEADER_SIZE + READ_CHUNK {
                Self::penalize(&ctx, &peer_key, 20).await;
                result = Err(P2pError::Protocol("peer exceeded frame size limit".into()));
                break 'read;
            }

            loop {
                match decode_frame(&acc) {
                    Ok(FrameDecode::Complete { message, consumed }) => {
                        acc.drain(..consumed);
                        match Self::handle_message(
                            message,
                            &ctx,
                            &out_tx,
                            &mut peer_key,
                            &mut keyed,
                            src,
                            inbound,
                        )
                        .await
                        {
                            Ok(true) => {}
                            Ok(false) => break 'read, // peer asked to be dropped
                            Err(e) => {
                                result = Err(e);
                                break 'read;
                            }
                        }
                    }
                    // Not a whole frame yet — wait for more bytes rather than
                    // tearing down a perfectly good connection.
                    Ok(FrameDecode::Incomplete { .. }) => break,
                    Err(e) => {
                        Self::penalize(&ctx, &peer_key, 20).await;
                        result = Err(P2pError::Protocol(format!("malformed frame: {}", e)));
                        break 'read;
                    }
                }
            }
        }

        Self::finish_connection(&ctx, &peer_key, keyed, out_tx, writer_task).await;
        result
    }

    /// Tear down bookkeeping for a connection that has ended.
    ///
    /// `owns_peer` distinguishes a connection that claimed the peer slot from
    /// one that was turned away (a duplicate, or a self-connection). Only the
    /// owner may mark the peer disconnected — otherwise a rejected duplicate
    /// would tear down the live connection it collided with.
    async fn finish_connection(
        ctx: &ConnectionContext,
        peer_key: &SocketAddr,
        owns_peer: bool,
        out_tx: mpsc::Sender<Vec<u8>>,
        writer_task: JoinHandle<()>,
    ) {
        if owns_peer {
            let mut pm = ctx.peer_manager.write().await;
            pm.mark_disconnected(peer_key);
        }

        // Closing the queue lets the writer drain anything already queued (a
        // reject, a final pong) and shut the socket down cleanly, rather than
        // having those bytes cut off mid-flight.
        drop(out_tx);
        let abort = writer_task.abort_handle();
        if tokio::time::timeout(Duration::from_secs(1), writer_task)
            .await
            .is_err()
        {
            abort.abort();
        }

        if owns_peer {
            let _ = ctx.event_tx.send(NodeEvent::PeerDisconnected(*peer_key));
        }
    }

    async fn penalize(ctx: &ConnectionContext, addr: &SocketAddr, points: i32) {
        let mut pm = ctx.peer_manager.write().await;
        if let Some(peer) = pm.get_peer_mut(addr) {
            peer.score_bad(points);
        }
    }

    /// Handle one decoded message.
    ///
    /// Returns `Ok(false)` when the connection should be closed without it
    /// being an error (self-connection, duplicate connection).
    async fn handle_message(
        msg: Message,
        ctx: &ConnectionContext,
        out_tx: &mpsc::Sender<Vec<u8>>,
        peer_key: &mut SocketAddr,
        keyed: &mut bool,
        src: SocketAddr,
        inbound: bool,
    ) -> Result<bool, P2pError> {
        match msg.msg_type {
            MessageType::Version => {
                let ver = VersionMessage::decode(&msg.payload)?;

                // We dialed ourselves, or an attacker is reflecting our own
                // handshake back at us. Either way, drop it.
                if ver.nonce == ctx.identity_nonce {
                    return Ok(false);
                }

                if inbound {
                    // Re-key from the ephemeral source port to the port the
                    // peer actually listens on, then claim the slot. Doing it
                    // here is what makes duplicate-connection detection work
                    // for inbound peers at all.
                    let announced = SocketAddr::new(src.ip(), ver.listen_port);
                    let slot = {
                        let mut pm = ctx.peer_manager.write().await;
                        pm.begin_connection(announced, true)
                    };
                    if slot != ConnectionSlot::Accepted {
                        return Ok(false);
                    }
                    *peer_key = announced;
                    *keyed = true;
                    let mut pm = ctx.peer_manager.write().await;
                    pm.set_channel(announced, out_tx.clone());
                }

                {
                    let mut pm = ctx.peer_manager.write().await;
                    if let Some(peer) = pm.get_peer_mut(peer_key) {
                        peer.version = ver.version;
                        peer.height = ver.height;
                        peer.services = ver.services;
                        peer.state = PeerState::Handshaking;
                        peer.last_seen = Some(std::time::Instant::now());
                    }
                }

                // An inbound peer has not seen our version yet.
                if inbound {
                    let version = Message::new(MessageType::Version, ctx.version_message().encode());
                    Self::send(out_tx, version).await?;
                }
                Self::send(out_tx, Message::new(MessageType::VerAck, vec![])).await?;
                Ok(true)
            }

            MessageType::VerAck => {
                let announce = {
                    let mut pm = ctx.peer_manager.write().await;
                    match pm.get_peer_mut(peer_key) {
                        Some(peer) => {
                            let first = peer.state != PeerState::Ready;
                            peer.state = PeerState::Ready;
                            peer.last_seen = Some(std::time::Instant::now());
                            first
                        }
                        None => false,
                    }
                };
                if announce {
                    let _ = ctx.event_tx.send(NodeEvent::PeerConnected(*peer_key));

                    // Ask a peer that claims a longer chain for the headers we
                    // are missing. Without this the handshake completes and
                    // both sides simply sit there.
                    let peer_height = {
                        let pm = ctx.peer_manager.read().await;
                        pm.get_peer(peer_key).map(|p| p.height).unwrap_or(0)
                    };
                    let request = {
                        let mut syncer = ctx.syncer.write().await;
                        let from = syncer.best_hash;
                        if peer_height > syncer.best_height && !syncer.is_syncing() {
                            Some(syncer.start_header_sync(*peer_key, from))
                        } else {
                            None
                        }
                    };
                    if let Some(req) = request {
                        Self::send(
                            out_tx,
                            Message::new(MessageType::GetHeaders, req.encode()),
                        )
                        .await?;
                    }
                }
                Ok(true)
            }

            MessageType::Ping => {
                let ping = PingMessage::decode(&msg.payload)?;
                Self::send(
                    out_tx,
                    Message::new(MessageType::Pong, PingMessage { nonce: ping.nonce }.encode()),
                )
                .await?;
                let mut pm = ctx.peer_manager.write().await;
                if let Some(peer) = pm.get_peer_mut(peer_key) {
                    peer.last_seen = Some(std::time::Instant::now());
                    peer.score_tick();
                }
                Ok(true)
            }

            MessageType::Pong => {
                let pong = PingMessage::decode(&msg.payload)?;
                let mut pm = ctx.peer_manager.write().await;
                if let Some(peer) = pm.get_peer_mut(peer_key) {
                    match peer.last_ping_nonce {
                        // An unsolicited or stale pong is not proof of life.
                        Some(expected) if expected == pong.nonce => {
                            peer.last_seen = Some(std::time::Instant::now());
                            peer.last_ping_nonce = None;
                            peer.last_ping_at = None;
                            peer.score_tick();
                        }
                        Some(_) => peer.score_bad(1),
                        None => {}
                    }
                }
                Ok(true)
            }

            MessageType::Tx => {
                let tx = <chroma_tx::Transaction as chroma_core::serialize::CanonicalDecode>::decode(
                    &msg.payload,
                )?;

                if !tx.verify_signature() {
                    Self::penalize(ctx, peer_key, 10).await;
                    let reject = RejectMessage {
                        message: "tx".to_string(),
                        code: 0x01,
                        reason: "invalid signature".to_string(),
                    };
                    Self::send(out_tx, Message::new(MessageType::Reject, reject.encode())).await?;
                    return Ok(true);
                }

                let hash = Hash::blake3(&chroma_core::serialize::CanonicalEncode::encode(&tx));
                let added = {
                    let mut pool = ctx.mempool.write().await;
                    pool.add_transaction(tx)
                };
                match added {
                    Ok(true) => {
                        let mut pm = ctx.peer_manager.write().await;
                        if let Some(peer) = pm.get_peer_mut(peer_key) {
                            peer.last_seen = Some(std::time::Instant::now());
                            peer.score_tick();
                        }
                        drop(pm);
                        let _ = ctx.event_tx.send(NodeEvent::TxReceived(hash));
                        // Pass it on, or a transaction only ever reaches the
                        // one node it was submitted to.
                        Self::announce(ctx, InvType::Tx, hash, Some(*peer_key)).await;
                    }
                    // Already held: not an error, and not worth re-announcing.
                    Ok(false) => {}
                    Err(e) => {
                        let _ = ctx
                            .event_tx
                            .send(NodeEvent::Error(format!("mempool rejected tx: {}", e)));
                    }
                }
                Ok(true)
            }

            MessageType::GetHeaders => {
                let req = GetHeadersMessage::decode(&msg.payload)?;
                let headers = {
                    let syncer = ctx.syncer.read().await;
                    syncer.headers_after(&req.start_hash, &req.stop_hash)
                };
                Self::send(
                    out_tx,
                    Message::new(MessageType::Headers, HeadersMessage { headers }.encode()),
                )
                .await?;
                Ok(true)
            }

            MessageType::Headers => {
                let resp = HeadersMessage::decode(&msg.payload)?;

                // An empty response means the peer has nothing beyond what we
                // already hold, so this branch of the sync is done.
                if resp.headers.is_empty() {
                    let mut syncer = ctx.syncer.write().await;
                    if syncer.sync_peer() == Some(*peer_key) {
                        syncer.sync_complete();
                        drop(syncer);
                        let _ = ctx.event_tx.send(NodeEvent::SyncComplete);
                    }
                    return Ok(true);
                }

                let offered = resp.headers.len();
                let (batch, best_hash) = {
                    let mut syncer = ctx.syncer.write().await;
                    let batch = syncer.absorb_headers(&resp.headers);
                    (batch, syncer.best_hash)
                };

                // Persist what was accepted so the chain survives a restart.
                for header in resp.headers.iter().take(batch.accepted) {
                    if let Err(e) = ctx.storage.put_header(header.height.0, header) {
                        let _ = ctx
                            .event_tx
                            .send(NodeEvent::Error(format!("storing header: {}", e)));
                    }
                }
                let _ = ctx.storage.flush();

                if let Some(reason) = batch.rejected {
                    // Headers that do not link up, carry the wrong target, or
                    // fail their own proof of work are a protocol violation.
                    Self::penalize(ctx, peer_key, 20).await;
                    let _ = ctx.event_tx.send(NodeEvent::Error(format!(
                        "bad headers from {}: {}",
                        peer_key, reason
                    )));
                    return Ok(true);
                }

                let _ = ctx.event_tx.send(NodeEvent::HeadersAccepted(batch.accepted));

                // Now fetch the blocks behind those headers, oldest first.
                // Without this, blocks only arrive as live announcements and
                // the historical ones are pulled in one at a time by the
                // orphan handler walking backwards — one round trip per
                // block, in the wrong direction.
                Self::request_missing_blocks(ctx, out_tx, &resp.headers[..batch.accepted]).await?;

                // A full batch means the peer probably has more.
                if batch.accepted == offered {
                    let more = GetHeadersMessage {
                        start_hash: best_hash,
                        stop_hash: Hash::ZERO,
                    };
                    Self::send(out_tx, Message::new(MessageType::GetHeaders, more.encode()))
                        .await?;
                }
                Ok(true)
            }

            MessageType::Inv => {
                let inv = InvMessage::decode(&msg.payload)?;

                // Ask only for what we are missing. Requesting everything
                // announced means re-downloading blocks we already have, and
                // on a busy network that is most of them.
                let mut wanted = Vec::new();
                for entry in inv.inventory.into_iter().take(MAX_INVENTORY) {
                    let missing = match entry.inv_type {
                        InvType::Block => !Self::have_block(ctx, &entry.hash).await,
                        InvType::Tx => {
                            let pool = ctx.mempool.read().await;
                            !pool.has_transaction(&entry.hash)
                        }
                    };
                    if missing {
                        wanted.push(entry);
                    }
                }

                if !wanted.is_empty() {
                    let getdata = GetDataMessage { inventory: wanted };
                    Self::send(out_tx, Message::new(MessageType::GetData, getdata.encode())).await?;
                }
                Ok(true)
            }

            MessageType::GetData => {
                let req = GetDataMessage::decode(&msg.payload)?;
                let mut not_found = Vec::new();

                for entry in req.inventory.into_iter().take(MAX_INVENTORY) {
                    match entry.inv_type {
                        InvType::Block => {
                            match ctx.storage.get_block_by_hash(&entry.hash) {
                                Ok(Some(block)) => {
                                    Self::send(
                                        out_tx,
                                        Message::new(MessageType::Block, block.encode_block()),
                                    )
                                    .await?;
                                }
                                _ => not_found.push(entry),
                            }
                        }
                        InvType::Tx => {
                            let payload = {
                                let pool = ctx.mempool.read().await;
                                pool.get_transaction(&entry.hash)
                                    .map(chroma_core::serialize::CanonicalEncode::encode)
                            };
                            match payload {
                                Some(bytes) => {
                                    Self::send(out_tx, Message::new(MessageType::Tx, bytes)).await?;
                                }
                                None => not_found.push(entry),
                            }
                        }
                    }
                }

                if !not_found.is_empty() {
                    let msg = InvMessage {
                        inventory: not_found,
                    };
                    Self::send(out_tx, Message::new(MessageType::NotFound, msg.encode())).await?;
                }
                Ok(true)
            }

            MessageType::Block => {
                let block = match chroma_block::Block::decode_block(&msg.payload) {
                    Ok(block) => block,
                    Err(e) => {
                        Self::penalize(ctx, peer_key, 10).await;
                        let _ = ctx.event_tx.send(NodeEvent::Error(format!(
                            "block decode failed from {}: {}",
                            peer_key, e
                        )));
                        return Ok(true);
                    }
                };

                Self::accept_block(ctx, out_tx, block, Some(*peer_key)).await?;
                Ok(true)
            }

            MessageType::Addr
            | MessageType::GetAddr
            | MessageType::Reject
            | MessageType::NotFound => Ok(true),
        }
    }


    /// Ask for the blocks behind `headers` that we do not already hold.
    ///
    /// Requested in ascending height so that parents arrive before children:
    /// responses come back in order on one connection, so each block can be
    /// connected as it lands instead of being parked as an orphan.
    async fn request_missing_blocks(
        ctx: &ConnectionContext,
        out_tx: &mpsc::Sender<Vec<u8>>,
        headers: &[chroma_block::BlockHeader],
    ) -> Result<(), P2pError> {
        let mut wanted = Vec::new();
        for header in headers {
            let hash = header.hash();
            if Self::have_block(ctx, &hash).await {
                continue;
            }
            wanted.push(InvEntry {
                inv_type: InvType::Block,
                hash,
            });
            if wanted.len() >= MAX_INVENTORY {
                break;
            }
        }

        if wanted.is_empty() {
            return Ok(());
        }

        let req = GetDataMessage { inventory: wanted };
        Self::send(out_tx, Message::new(MessageType::GetData, req.encode())).await
    }

    /// True if this block is already on disk.
    ///
    /// Uses the hash→height index rather than loading the block, so an
    /// inventory of hundreds costs hundreds of key lookups, not hundreds of
    /// block deserializations.
    async fn have_block(ctx: &ConnectionContext, hash: &Hash) -> bool {
        matches!(ctx.storage.get_height_for_hash(hash), Ok(Some(_)))
    }

    /// Validate and connect a block, then whatever was waiting on it.
    ///
    /// `from` is the peer that sent it, which is excluded from the relay so we
    /// do not immediately announce the block back to its source.
    async fn accept_block(
        ctx: &ConnectionContext,
        out_tx: &mpsc::Sender<Vec<u8>>,
        block: chroma_block::Block,
        from: Option<SocketAddr>,
    ) -> Result<(), P2pError> {
        let hash = block.hash();

        // Already have it: a duplicate announcement, or two peers relaying the
        // same block. Not an error, and not worth re-validating.
        if Self::have_block(ctx, &hash).await {
            return Ok(());
        }
        {
            let orphans = ctx.orphans.read().await;
            if orphans.contains(&hash) {
                return Ok(());
            }
        }

        // Do we have the parent? Genesis is the one block with no parent.
        let parent_known = block.header.height.0 == 0
            || Self::have_block(ctx, &block.header.previous_hash).await
            || {
                let cs = ctx.chain_state.read().await;
                cs.tip.hash == block.header.previous_hash
            };

        if !parent_known {
            // Park it and go get the parent, rather than dropping a block we
            // may well be able to use in a moment.
            let parent = {
                let mut orphans = ctx.orphans.write().await;
                orphans.insert(block)
            };
            if let Some(parent) = parent {
                let req = GetDataMessage {
                    inventory: vec![InvEntry {
                        inv_type: InvType::Block,
                        hash: parent,
                    }],
                };
                Self::send(out_tx, Message::new(MessageType::GetData, req.encode())).await?;
            }
            return Ok(());
        }

        // Connect this block, then anything that was waiting on it, and so on
        // down the parked chain.
        let mut queue = vec![block];
        while let Some(candidate) = queue.pop() {
            let candidate_hash = candidate.hash();

            let applied = {
                let mut cs = ctx.chain_state.write().await;
                let source = StorageBlocks(ctx.storage.as_ref());
                // Store first: a reorg replays the branch out of storage, so
                // the block has to be readable before it can be chosen.
                let _ = ctx.storage.apply_block(&candidate);
                match cs.apply_block_with(&candidate, &source) {
                    Ok(outcome) => {
                        if let chroma_consensus::BlockOutcome::Reorganized { depth } = outcome {
                            let _ = ctx
                                .event_tx
                                .send(NodeEvent::Reorganized { depth, new_tip: cs.tip.hash });
                            for (height, header) in cs.headers.clone() {
                                let _ = ctx.storage.set_hash_for_height(height, &header.hash());
                                let _ = ctx.storage.put_header(height, &header);
                            }
                        }
                        let tip = &cs.tip;
                        let persisted = chroma_storage::PersistedTip {
                            height: tip.height.0,
                            hash: tip.hash,
                            cumulative_work: tip.cumulative_work.to_be_bytes(),
                            supply: tip.supply,
                        };
                        let _ = ctx.storage.put_tip(&persisted);
                        let _ = ctx.storage.put_state(&cs.state);
                        let _ = ctx.storage.flush();
                        true
                    }
                    Err(e) => {
                        let _ = ctx
                            .event_tx
                            .send(NodeEvent::Error(format!("block validation failed: {}", e)));
                        false
                    }
                }
            };

            if !applied {
                // Its children can never connect either.
                let mut orphans = ctx.orphans.write().await;
                orphans.remove(&candidate_hash);
                for child in orphans.take_children_of(&candidate_hash) {
                    orphans.remove(&child.hash());
                }
                continue;
            }

            {
                let mut syncer = ctx.syncer.write().await;
                syncer.insert_header(candidate.header.clone());
            }
            {
                let mined: Vec<Hash> = candidate
                    .transactions
                    .iter()
                    .skip(1)
                    .map(|tx| Hash::blake3(&chroma_core::serialize::CanonicalEncode::encode(tx)))
                    .collect();
                if !mined.is_empty() {
                    let mut pool = ctx.mempool.write().await;
                    pool.remove_transactions(&mined);
                }
            }

            let height = {
                let cs = ctx.chain_state.read().await;
                cs.tip.height.0
            };
            ctx.chain_height.store(height, Ordering::Relaxed);
            let _ = ctx
                .event_tx
                .send(NodeEvent::BlockReceived(candidate_hash, height));

            Self::announce(ctx, InvType::Block, candidate_hash, from).await;

            let unblocked = {
                let mut orphans = ctx.orphans.write().await;
                orphans.take_children_of(&candidate_hash)
            };
            queue.extend(unblocked);
        }

        Ok(())
    }

    /// Announce an item to every ready peer except `except`.
    ///
    /// Only the hash goes out: peers that already have it say nothing, and
    /// only those missing it spend bandwidth asking. Pushing whole blocks to
    /// everyone would send the same megabyte to peers that already had it.
    async fn announce(
        ctx: &ConnectionContext,
        inv_type: InvType,
        hash: Hash,
        except: Option<SocketAddr>,
    ) {
        let inv = InvMessage {
            inventory: vec![InvEntry { inv_type, hash }],
        };
        let msg = Message::new(MessageType::Inv, inv.encode());

        let peers: Vec<SocketAddr> = {
            let pm = ctx.peer_manager.read().await;
            pm.peers_for_announcement()
        };
        for addr in peers {
            if Some(addr) == except {
                continue;
            }
            let _ = ctx
                .outbound_tx
                .send(OutboundCommand::Send(addr, msg.clone()));
        }
    }

    async fn send(out_tx: &mpsc::Sender<Vec<u8>>, msg: Message) -> Result<(), P2pError> {
        out_tx
            .send(msg.encode())
            .await
            .map_err(|_| P2pError::Protocol("peer write channel closed".into()))
    }

    async fn run_peer_tick(
        peer_manager: Arc<RwLock<PeerManager>>,
        outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                _ = interval.tick() => {}
            }

            // Cut peers that stopped answering before pinging the rest.
            let stale = {
                let pm = peer_manager.read().await;
                pm.stale_peers(Duration::from_secs(PEER_TIMEOUT_SECS))
            };
            for addr in stale {
                let _ = outbound_tx.send(OutboundCommand::Disconnect(addr));
            }

            let addrs: Vec<SocketAddr> = {
                let pm = peer_manager.read().await;
                pm.peers_for_announcement()
            };

            for addr in addrs {
                let nonce = rand_u64();
                {
                    let mut pm = peer_manager.write().await;
                    match pm.get_peer_mut(&addr) {
                        // A ping is already outstanding; the staleness check
                        // above is what eventually drops a silent peer.
                        Some(peer) if peer.last_ping_nonce.is_some() => continue,
                        Some(peer) => {
                            peer.last_ping_nonce = Some(nonce);
                            peer.last_ping_at = Some(std::time::Instant::now());
                        }
                        None => continue,
                    }
                }
                let msg = Message::new(MessageType::Ping, PingMessage { nonce }.encode());
                let _ = outbound_tx.send(OutboundCommand::Send(addr, msg));
            }

            let mut pm = peer_manager.write().await;
            pm.prune_disconnected();
        }
    }

    async fn run_miner(
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
        miner_address: chroma_core::types::Address,
        mempool: Arc<RwLock<Mempool>>,
        peer_manager: Arc<RwLock<PeerManager>>,
        outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
        syncer: Arc<RwLock<ChainSyncer>>,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        use chroma_consensus::miner::{
            assemble_block, mine_block_with_limit, next_block_timestamp, timestamp_is_valid,
            BlockAssemblyContext,
        };
        use chroma_core::types::BlockHeight;


        loop {
            // Checked between rounds; a round in progress finishes first.
            if shutdown.try_recv().is_ok() {
                break;
            }
            let (height, previous_hash, mtp, bits, parent_state) = {
                let cs = chain_state.read().await;
                let tip = &cs.tip;
                let next_height = tip.height.0 + 1;
                (
                    next_height,
                    tip.hash,
                    cs.compute_median_time_past(next_height),
                    tip.header.bits,
                    cs.state.clone(),
                )
            };

            let timestamp = next_block_timestamp(chroma_consensus::now_secs(), mtp);

            let ctx = BlockAssemblyContext {
                height: BlockHeight(height),
                previous_hash,
                timestamp,
                bits,
                coinbase_recipient: miner_address,
            };

            // Take whatever the mempool holds. assemble_block drops anything
            // that will not apply, so a stale entry costs a skip, not a block.
            let candidates: Vec<chroma_tx::Transaction> = {
                let pool = mempool.read().await;
                pool.transactions().into_iter().cloned().collect()
            };

            match assemble_block(&ctx, &candidates, &parent_state) {
                Ok(mut block) => {
                    match mine_block_with_limit(&mut block, 10_000_000) {
                        Ok(()) => {
                            // Mining can take a while; if the stamp has gone
                            // stale meanwhile, rebuild rather than submit a
                            // block our own validation would reject.
                            if !timestamp_is_valid(
                                block.header.timestamp,
                                chroma_consensus::now_secs(),
                                mtp,
                            ) {
                                continue;
                            }
                            let mut cs = chain_state.write().await;
                            match cs.apply_block(&block) {
                                Ok(()) => {
                                    let block_hash = block.hash();
                                    let tip = &cs.tip;
                                    let persisted = chroma_storage::PersistedTip {
                                        height: tip.height.0,
                                        hash: tip.hash,
                                        cumulative_work: tip.cumulative_work.to_be_bytes(),
                                        supply: tip.supply,
                                    };
                                    let _ = storage.apply_block(&block);
                                    let _ = storage.put_tip(&persisted);
                                    let _ = storage.put_state(&cs.state);
                                    let _ = storage.flush();

                                    chain_height.store(height, Ordering::Relaxed);
                                    {
                                        let mut sync = syncer.write().await;
                                        sync.insert_header(block.header.clone());
                                    }
                                    // Anything that made it into the block is
                                    // no longer pending.
                                    {
                                        let mined: Vec<Hash> = block
                                            .transactions
                                            .iter()
                                            .skip(1)
                                            .map(|tx| {
                                                Hash::blake3(
                                                    &chroma_core::serialize::CanonicalEncode::encode(tx),
                                                )
                                            })
                                            .collect();
                                        if !mined.is_empty() {
                                            let mut pool = mempool.write().await;
                                            pool.remove_transactions(&mined);
                                        }
                                    }
                                    let _ = event_tx.send(NodeEvent::BlockMined(block_hash, height));
                                    println!("Mined block #{}: {}", height, block_hash.to_hex());

                                    // Announce it, or the block never leaves
                                    // this node and the network forks.
                                    let inv = InvMessage {
                                        inventory: vec![InvEntry {
                                            inv_type: InvType::Block,
                                            hash: block_hash,
                                        }],
                                    };
                                    let announcement =
                                        Message::new(MessageType::Inv, inv.encode());
                                    let peers: Vec<SocketAddr> = {
                                        let pm = peer_manager.read().await;
                                        pm.peers_for_announcement()
                                    };
                                    for addr in peers {
                                        let _ = outbound_tx.send(OutboundCommand::Send(
                                            addr,
                                            announcement.clone(),
                                        ));
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Mined block rejected: {}", e);
                                }
                            }
                        }
                        Err(_) => {
                            tokio::select! {
                                _ = shutdown.recv() => return,
                                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Block assembly failed: {}", e);
                    tokio::select! {
                        _ = shutdown.recv() => return,
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    }
                }
            }

            tokio::select! {
                _ = shutdown.recv() => return,
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    pub fn connect(&self, addr: SocketAddr) {
        if let Some(tx) = &self.outbound_tx {
            let _ = tx.send(OutboundCommand::Connect(addr));
        }
    }

    pub fn send_message(&self, addr: SocketAddr, msg: Message) {
        if let Some(tx) = &self.outbound_tx {
            let _ = tx.send(OutboundCommand::Send(addr, msg));
        }
    }

    pub fn broadcast_message(&self, msg: Message) {
        if let Some(tx) = &self.outbound_tx {
            let tx = tx.clone();
            let peers = self.peer_manager.clone();
            tokio::spawn(async move {
                let pm = peers.read().await;
            let addrs: Vec<SocketAddr> = pm.connected_peers().into_iter().map(|p| p.addr).collect();
                drop(pm);
                for addr in addrs {
                    let _ = tx.send(OutboundCommand::Send(addr, msg.clone()));
                }
            });
        }
    }

    pub fn broadcast_transaction(&self, tx_hash: Hash) {
        let entry = InvEntry {
            inv_type: InvType::Tx,
            hash: tx_hash,
        };
        let inv = InvMessage {
            inventory: vec![entry],
        };
        self.broadcast_message(Message::new(MessageType::Inv, inv.encode()));
    }

    pub fn broadcast_block(&self, block_hash: Hash, _height: u32) {
        let entry = InvEntry {
            inv_type: InvType::Block,
            hash: block_hash,
        };
        let inv = InvMessage {
            inventory: vec![entry],
        };
        self.broadcast_message(Message::new(MessageType::Inv, inv.encode()));
    }
}

fn rand_u64() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::time::SystemTime;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let s = RandomState::new();
    let mut h = s.build_hasher();
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    h.write_u64(nanos);
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_addr(n: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), n)
    }

    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("chroma_test_{}", id));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_node_config() {
        let addr = test_addr(8333);
        let genesis = Hash::blake3(b"genesis");
        let config = NodeConfig::new(addr, genesis);
        assert_eq!(config.listen_addr, addr);
        assert_eq!(config.genesis_hash, genesis);
        assert!(config.connect_addrs.is_empty());
    }

    #[test]
    fn test_node_creation() {
        let addr = test_addr(8333);
        let genesis = chroma_consensus::build_genesis_block();
        let genesis_hash = genesis.hash();
        let dir = temp_dir();
        let config = NodeConfig::new(addr, genesis_hash).with_data_dir(dir.clone());
        let node = Node::new(config);
        assert!(node.event_rx.is_some());
        assert!(node.outbound_rx.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_rand_u64() {
        let a = rand_u64();
        let b = rand_u64();
        assert_ne!(a, b);
    }

    #[test]
    fn test_p2p_error_display() {
        let err = P2pError::Protocol("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
