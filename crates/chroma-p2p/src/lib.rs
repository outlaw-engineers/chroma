pub mod wire;
pub mod peer;
pub mod mempool;
pub mod discovery;
pub mod sync;

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

pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub connect_addrs: Vec<SocketAddr>,
    pub genesis_hash: Hash,
    pub chain_height: Arc<AtomicU32>,
    pub data_dir: PathBuf,
    /// Run the mining loop. Off in tests that only exercise networking.
    pub mining_enabled: bool,
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
        }
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
    SyncComplete,
    Error(String),
}

enum OutboundCommand {
    Send(SocketAddr, Message),
    Connect(SocketAddr),
    Disconnect(SocketAddr),
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
    event_tx: mpsc::UnboundedSender<NodeEvent>,
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

        let chain_state = Self::init_chain_state(&storage, config.genesis_hash);

        let height = chain_state.tip.height.0;
        config.chain_height.store(height, Ordering::Relaxed);

        // Seed the header chain from what is already on disk, so a restarted
        // node resumes sync from its own tip instead of from genesis.
        let mut syncer = ChainSyncer::with_genesis(chroma_consensus::build_genesis_block().header);
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
    ) -> chroma_consensus::ChainState {
        use chroma_consensus::{build_genesis_block, ChainTip, ChainState};
        use chroma_core::types::BlockHeight;
        use chroma_core::u256::U256;
        use std::collections::BTreeMap;

        match storage.get_tip() {
            Ok(Some(persisted_tip)) => {
                let mut headers = BTreeMap::new();
                let mut current_height = 0u32;
                while let Ok(Some(header)) = storage.get_header(current_height) {
                    headers.insert(current_height, header);
                    if current_height == persisted_tip.height {
                        break;
                    }
                    current_height += 1;
                }

                let mut state = chroma_state::State::new();
                let total_supply = storage.get_supply().unwrap_or(0);
                if total_supply > 0 {
                    state.apply_subsidy(&chroma_core::types::Address::from_hash160(
                        chroma_core::hash::Hash160([0u8; 20]),
                    ), persisted_tip.height).ok();
                }

                let cumulative_work = U256::from_be_bytes(&persisted_tip.cumulative_work);
                let tip_header = headers.get(&persisted_tip.height).cloned().unwrap_or_else(|| {
                    build_genesis_block().header
                });

                let tip = ChainTip {
                    height: BlockHeight(persisted_tip.height),
                    hash: persisted_tip.hash,
                    header: tip_header,
                    cumulative_work,
                    supply: persisted_tip.supply,
                };

                let mut tips = BTreeMap::new();
                tips.insert(persisted_tip.hash, tip.clone());

                println!("Loaded chain from storage: height={}, supply={} units",
                    persisted_tip.height, persisted_tip.supply);

                ChainState {
                    headers,
                    tip,
                    state,
                    tips,
                }
            }
            _ => {
                let chain = ChainState::with_genesis();
                let genesis = build_genesis_block();
                let genesis_hash = genesis.hash();

                if expected_genesis_hash != genesis_hash {
                    eprintln!("Warning: expected genesis hash {} but computed {}",
                        expected_genesis_hash.to_hex(), genesis_hash.to_hex());
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

        let ctx = ConnectionContext {
            peer_manager: self.peer_manager.clone(),
            mempool: self.mempool.clone(),
            storage: self.storage.clone(),
            chain_state: self.chain_state.clone(),
            syncer: self.syncer.clone(),
            event_tx: self.event_tx.clone(),
            chain_height: self.config.chain_height.clone(),
            listen_port,
            identity_nonce: self.identity_nonce,
            shutdown_tx: self.shutdown_tx.clone(),
        };

        let outbound_rx = self.outbound_rx.take().expect("run() called twice");
        let outbound_tx = self.outbound_tx.as_ref().unwrap().clone();

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
            let shutdown = self.shutdown_tx.subscribe();
            self.tasks.push(tokio::spawn(async move {
                Self::run_miner(storage, chain_state, event_tx, height, shutdown).await;
            }));
        }

        Ok(())
    }

    /// Signal every task to stop, wait for them, close peer connections and
    /// flush storage to disk.
    ///
    /// Safe to call more than once, and safe to call on a node that was never
    /// started.
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
                if !inv.inventory.is_empty() {
                    let getdata = GetDataMessage {
                        inventory: inv.inventory,
                    };
                    Self::send(out_tx, Message::new(MessageType::GetData, getdata.encode())).await?;
                }
                Ok(true)
            }

            MessageType::Block => {
                match chroma_block::Block::decode_block(&msg.payload) {
                    Ok(block) => {
                        let block_hash = block.hash();
                        let block_height = block.header.height.0;

                        let mut cs = ctx.chain_state.write().await;
                        match cs.apply_block(&block) {
                            Ok(()) => {
                                let _ = ctx.storage.apply_block(&block);
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

                                ctx.chain_height.store(block_height, Ordering::Relaxed);
                                let _ = ctx
                                    .event_tx
                                    .send(NodeEvent::BlockReceived(block_hash, block_height));
                            }
                            Err(e) => {
                                let _ = ctx.event_tx.send(NodeEvent::Error(format!(
                                    "block validation failed: {}",
                                    e
                                )));
                            }
                        }
                    }
                    Err(e) => {
                        Self::penalize(ctx, peer_key, 10).await;
                        let _ = ctx.event_tx.send(NodeEvent::Error(format!(
                            "block decode failed from {}: {}",
                            peer_key, e
                        )));
                    }
                }
                Ok(true)
            }

            MessageType::GetData
            | MessageType::Addr
            | MessageType::GetAddr
            | MessageType::Reject
            | MessageType::NotFound => Ok(true),
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
        mut shutdown: broadcast::Receiver<()>,
    ) {
        use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
        use chroma_core::constants::TARGET_BLOCK_TIME_SECS;
        use chroma_core::types::BlockHeight;
        use chroma_core::hash::Hash160;

        let miner_address = {
            let mut addr = [0u8; 20];
            addr[0] = 0xDE;
            addr[1] = 0xAD;
            addr[2] = 0xBE;
            addr[3] = 0xEF;
            chroma_core::types::Address::from_hash160(Hash160(addr))
        };

        loop {
            // Checked between rounds; a round in progress finishes first.
            if shutdown.try_recv().is_ok() {
                break;
            }
            let (height, previous_hash, previous_timestamp, bits, parent_state) = {
                let cs = chain_state.read().await;
                let tip = &cs.tip;
                (
                    tip.height.0 + 1,
                    tip.hash,
                    tip.header.timestamp,
                    tip.header.bits,
                    cs.state.clone(),
                )
            };

            let network_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let timestamp = std::cmp::max(
                previous_timestamp + TARGET_BLOCK_TIME_SECS,
                network_time,
            );

            let ctx = BlockAssemblyContext {
                height: BlockHeight(height),
                previous_hash,
                previous_timestamp: timestamp.saturating_sub(TARGET_BLOCK_TIME_SECS),
                bits,
                coinbase_recipient: miner_address.clone(),
            };

            match assemble_block(&ctx, &[], &parent_state) {
                Ok(mut block) => {
                    block.header.timestamp = timestamp;
                    match mine_block_with_limit(&mut block, 10_000_000) {
                        Ok(()) => {
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
                                    let _ = event_tx.send(NodeEvent::BlockMined(block_hash, height));
                                    println!("Mined block #{}: {}", height, block_hash.to_hex());
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
