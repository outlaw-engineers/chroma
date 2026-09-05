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

use chroma_core::hash::Hash;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

use crate::discovery::Discovery;
use crate::mempool::Mempool;
use crate::peer::{
    PeerManager, PeerState, MAX_OUTBOUND_PEERS, PEER_TIMEOUT_SECS, PING_INTERVAL_SECS,
    VERSION_TIMEOUT_SECS,
};
use crate::wire::{
    GetDataMessage, GetHeadersMessage, InvEntry, InvMessage, InvType, Message, MessageType,
    PingMessage, VersionMessage, HEADER_SIZE,
};

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
}

impl NodeConfig {
    pub fn new(listen_addr: SocketAddr, genesis_hash: Hash) -> Self {
        NodeConfig {
            listen_addr,
            connect_addrs: Vec::new(),
            genesis_hash,
            chain_height: Arc::new(AtomicU32::new(0)),
            data_dir: PathBuf::from("chroma_data"),
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
}

pub struct Node {
    config: NodeConfig,
    peer_manager: Arc<RwLock<PeerManager>>,
    mempool: Arc<RwLock<Mempool>>,
    discovery: Discovery,
    storage: Arc<chroma_storage::Storage>,
    chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    event_tx: mpsc::UnboundedSender<NodeEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<NodeEvent>>,
    outbound_tx: Option<mpsc::UnboundedSender<OutboundCommand>>,
    outbound_rx: Option<mpsc::UnboundedReceiver<OutboundCommand>>,
}

#[derive(Clone, Debug)]
pub enum NodeEvent {
    PeerConnected(SocketAddr),
    PeerDisconnected(SocketAddr),
    BlockReceived(Hash, u32),
    BlockMined(Hash, u32),
    TxReceived(Hash),
    SyncComplete,
    Error(String),
}

enum OutboundCommand {
    Send(SocketAddr, Message),
    Connect(SocketAddr),
    #[allow(dead_code)]
    Disconnect(SocketAddr),
}

impl Node {
    pub fn new(config: NodeConfig) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();

        let db_path = config.data_dir.clone();
        let storage = chroma_storage::Storage::open(&db_path)
            .expect("failed to open storage database");

        let chain_state = Self::init_chain_state(&storage, config.genesis_hash);

        let height = chain_state.tip.height.0;
        config.chain_height.store(height, Ordering::Relaxed);

        Node {
            config,
            peer_manager: Arc::new(RwLock::new(PeerManager::new())),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            discovery: Discovery::new(),
            storage: Arc::new(storage),
            chain_state: Arc::new(RwLock::new(chain_state)),
            event_tx,
            event_rx: Some(event_rx),
            outbound_tx: Some(outbound_tx),
            outbound_rx: Some(outbound_rx),
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

    pub fn chain_height(&self) -> u32 {
        self.config.chain_height.load(Ordering::Relaxed)
    }

    pub fn event_rx(&mut self) -> Option<mpsc::UnboundedReceiver<NodeEvent>> {
        self.event_rx.take()
    }

    pub async fn run(&mut self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let peer_mgr = self.peer_manager.clone();
        let mempool = self.mempool.clone();
        let genesis_hash = self.config.genesis_hash;

        let mut discovery = Discovery::new();
        let _ = discovery
            .discover_peers(peer_mgr.clone(), &self.config.connect_addrs)
            .await;

        let event_tx = self.event_tx.clone();
        let outbound_rx = self.outbound_rx.take().unwrap();

        let peer_mgr_out = peer_mgr.clone();
        let event_tx_out = event_tx.clone();
        let chain_height_out = self.config.chain_height.clone();
        let storage_out = self.storage.clone();
        let chain_state_out = self.chain_state.clone();
        tokio::spawn(async move {
            Self::run_outbound(
                peer_mgr_out, outbound_rx, event_tx_out, chain_height_out,
                storage_out, chain_state_out,
            ).await;
        });

        let outbound_tx_ref = self.outbound_tx.as_ref().unwrap();
        for addr in &self.config.connect_addrs {
            let _ = outbound_tx_ref.send(OutboundCommand::Connect(*addr));
        }

        let peer_mgr_in = peer_mgr.clone();
        let mempool_in = mempool.clone();
        let event_tx_in = event_tx.clone();
        let chain_height_in = self.config.chain_height.clone();
        let storage_in = self.storage.clone();
        let chain_state_in = self.chain_state.clone();
        tokio::spawn(async move {
            Self::run_inbound(
                listener,
                peer_mgr_in,
                mempool_in,
                event_tx_in,
                genesis_hash,
                chain_height_in,
                storage_in,
                chain_state_in,
            )
            .await;
        });

        let peer_mgr_tick = peer_mgr.clone();
        let outbound_tx_tick = self.outbound_tx.as_ref().unwrap().clone();
        tokio::spawn(async move {
            Self::run_peer_tick(peer_mgr_tick, outbound_tx_tick).await;
        });

        let mining_storage = self.storage.clone();
        let mining_chain_state = self.chain_state.clone();
        let mining_event_tx = self.event_tx.clone();
        let mining_height = self.config.chain_height.clone();
        tokio::spawn(async move {
            Self::run_miner(mining_storage, mining_chain_state, mining_event_tx, mining_height).await;
        });

        Ok(())
    }

    async fn run_outbound(
        peer_manager: Arc<RwLock<PeerManager>>,
        mut outbound_rx: mpsc::UnboundedReceiver<OutboundCommand>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    ) {
        while let Some(cmd) = outbound_rx.recv().await {
            match cmd {
                OutboundCommand::Connect(addr) => {
                    let pm = peer_manager.read().await;
                    let banned = pm.get_peer(&addr).map(|p| p.is_banned()).unwrap_or(false);
                    drop(pm);
                    if banned {
                        continue;
                    }

                    match tokio::time::timeout(
                        std::time::Duration::from_secs(PEER_TIMEOUT_SECS),
                        TcpStream::connect(addr),
                    )
                    .await
                    {
                        Ok(Ok(mut stream)) => {
                            let pm = peer_manager.write().await;
                            if let Some(peer) = pm.get_peer(&addr) {
                                if peer.state == PeerState::Ready || peer.state == PeerState::Connected {
                                    drop(pm);
                                    continue;
                                }
                            }
                            drop(pm);

                            let mut pm = peer_manager.write().await;
                            pm.add_peer(addr);
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.state = PeerState::Connected;
                                peer.connected_at = Some(std::time::Instant::now());
                            }
                            drop(pm);

                            let height = chain_height.load(Ordering::Relaxed);
                            let version = VersionMessage {
                                version: PROTOCOL_VERSION,
                                services: SERVICES,
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                                height,
                                nonce: rand_u64(),
                            };
                            let msg = Message::new(MessageType::Version, version.encode());
                            if stream.write_all(&msg.encode()).await.is_err() {
                                let mut pm = peer_manager.write().await;
                                if let Some(peer) = pm.get_peer_mut(&addr) {
                                    peer.score_bad(5);
                                }
                                continue;
                            }

                            let pm = peer_manager.clone();
                            let et = event_tx.clone();
                            let et2 = event_tx.clone();
                            let ch = chain_height.clone();
                            let st = storage.clone();
                            let cs = chain_state.clone();
                            tokio::spawn(async move {
                                match Self::handle_connection(
                                    stream, addr, pm, et, ch, st, cs, true,
                                ).await {
                                    Ok(()) => {}
                                    Err(e) => {
                                        let _ = et2.send(NodeEvent::Error(
                                            format!("{}: {}", addr, e),
                                        ));
                                    }
                                }
                            });
                        }
                        _ => {
                            let mut pm = peer_manager.write().await;
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.score_bad(5);
                            }
                        }
                    }
                }
                OutboundCommand::Send(addr, msg) => {
                    if let Ok(mut stream) = TcpStream::connect(addr).await {
                        let _ = stream.write_all(&msg.encode()).await;
                    }
                }
                OutboundCommand::Disconnect(addr) => {
                    let mut pm = peer_manager.write().await;
                    pm.remove_peer(&addr);
                    drop(pm);
                    let _ = event_tx.send(NodeEvent::PeerDisconnected(addr));
                }
            }
        }
    }

    async fn run_inbound(
        listener: TcpListener,
        peer_manager: Arc<RwLock<PeerManager>>,
        _mempool: Arc<RwLock<Mempool>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        _genesis_hash: Hash,
        chain_height: Arc<AtomicU32>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
    ) {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };

            let pm = peer_manager.read().await;
            let banned = pm.get_peer(&addr).map(|p| p.is_banned()).unwrap_or(false);
            let count = pm.connected_count();
            drop(pm);

            if banned || count >= MAX_OUTBOUND_PEERS + 16 {
                drop(stream);
                continue;
            }

            let pm = peer_manager.clone();
            let et = event_tx.clone();
            let et2 = event_tx.clone();
            let ch = chain_height.clone();
            let st = storage.clone();
            let cs = chain_state.clone();

            tokio::spawn(async move {
                match Self::handle_connection(stream, addr, pm, et, ch, st, cs, false).await {
                    Ok(()) => {}
                    Err(e) => {
                        let _ = et2.send(NodeEvent::Error(format!("{}: {}", addr, e)));
                    }
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        peer_manager: Arc<RwLock<PeerManager>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        already_sent_version: bool,
    ) -> Result<(), P2pError> {
        {
            let mut pm = peer_manager.write().await;
            pm.add_peer(addr);
            if let Some(peer) = pm.get_peer_mut(&addr) {
                peer.state = PeerState::Connected;
                peer.connected_at = Some(std::time::Instant::now());
            }
        }

        if !already_sent_version {
            let height = chain_height.load(Ordering::Relaxed);
            let version = VersionMessage {
                version: PROTOCOL_VERSION,
                services: SERVICES,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                height,
                nonce: rand_u64(),
            };
            let msg = Message::new(MessageType::Version, version.encode());
            stream.write_all(&msg.encode()).await?;
        }

        let mut buf = vec![0u8; 8192];
        let mut read_pos = 0;

        loop {
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(VERSION_TIMEOUT_SECS),
                stream.read(&mut buf[read_pos..]),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                _ => break,
            };
            read_pos += n;

            while read_pos >= HEADER_SIZE {
                match Message::decode(&buf[..read_pos]) {
                    Ok((msg, consumed)) => {
                        buf.drain(..consumed);
                        read_pos -= consumed;

                        match msg.msg_type {
                            MessageType::Version => {
                                let ver = VersionMessage::decode(&msg.payload)?;
                                let mut pm = peer_manager.write().await;
                                if let Some(peer) = pm.get_peer_mut(&addr) {
                                    peer.version = ver.version;
                                    peer.height = ver.height;
                                    peer.services = ver.services;
                                    peer.state = PeerState::Handshaking;
                                }
                                drop(pm);

                                let verack = Message::new(MessageType::VerAck, vec![]);
                                stream.write_all(&verack.encode()).await?;
                            }
                            MessageType::VerAck => {
                                let mut pm = peer_manager.write().await;
                                if let Some(peer) = pm.get_peer_mut(&addr) {
                                    peer.state = PeerState::Ready;
                                    peer.last_seen = Some(std::time::Instant::now());
                                }
                                drop(pm);
                                let _ = event_tx.send(NodeEvent::PeerConnected(addr));
                            }
                            MessageType::Ping => {
                                let ping = PingMessage::decode(&msg.payload)?;
                                let pong = Message::new(
                                    MessageType::Pong,
                                    PingMessage { nonce: ping.nonce }.encode(),
                                );
                                stream.write_all(&pong.encode()).await?;
                                let mut pm = peer_manager.write().await;
                                if let Some(peer) = pm.get_peer_mut(&addr) {
                                    peer.last_seen = Some(std::time::Instant::now());
                                    peer.score_tick();
                                }
                            }
                            MessageType::Pong => {
                                let mut pm = peer_manager.write().await;
                                if let Some(peer) = pm.get_peer_mut(&addr) {
                                    peer.last_seen = Some(std::time::Instant::now());
                                }
                            }
                            MessageType::GetHeaders => {
                                let _ = GetHeadersMessage::decode(&msg.payload)?;
                                let empty_headers = Message::new(MessageType::Headers, vec![0u8; 4]);
                                stream.write_all(&empty_headers.encode()).await?;
                            }
                            MessageType::Inv => {
                                let inv = InvMessage::decode(&msg.payload)?;
                                if !inv.inventory.is_empty() {
                                    let getdata = GetDataMessage {
                                        inventory: inv.inventory,
                                    };
                                    let resp =
                                        Message::new(MessageType::GetData, getdata.encode());
                                    stream.write_all(&resp.encode()).await?;
                                }
                            }
                            MessageType::Block => {
                                let block_data = msg.payload;
                                match chroma_block::Block::decode_block(&block_data) {
                                    Ok(block) => {
                                        let block_hash = block.hash();
                                        let block_height = block.header.height.0;

                                        {
                                            let mut cs = chain_state.write().await;
                                            if let Err(e) = cs.apply_block(&block) {
                                                let _ = event_tx.send(NodeEvent::Error(
                                                    format!("block validation failed: {}", e)
                                                ));
                                            } else {
                                                let _ = storage.apply_block(&block);
                                                let tip = &cs.tip;
                                                let persisted = chroma_storage::PersistedTip {
                                                    height: tip.height.0,
                                                    hash: tip.hash,
                                                    cumulative_work: tip.cumulative_work.to_be_bytes(),
                                                    supply: tip.supply,
                                                };
                                                let _ = storage.put_tip(&persisted);
                                                let _ = storage.put_state(&cs.state);
                                                let _ = storage.flush();

                                                chain_height.store(block_height, Ordering::Relaxed);
                                                let _ = event_tx.send(NodeEvent::BlockReceived(block_hash, block_height));
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(NodeEvent::Error(
                                            format!("block decode failed from {}: {}", addr, e)
                                        ));
                                    }
                                }
                            }
                            MessageType::GetData
                            | MessageType::Tx
                            | MessageType::Addr
                            | MessageType::GetAddr
                            | MessageType::Reject
                            | MessageType::NotFound
                            | MessageType::Headers => {}
                        }
                    }
                    Err(_) => break,
                }
            }
        }

        let mut pm = peer_manager.write().await;
        pm.remove_peer(&addr);
        drop(pm);
        let _ = event_tx.send(NodeEvent::PeerDisconnected(addr));
        Ok(())
    }

    async fn run_peer_tick(
        peer_manager: Arc<RwLock<PeerManager>>,
        outbound_tx: mpsc::UnboundedSender<OutboundCommand>,
    ) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PING_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let pm = peer_manager.read().await;
            let addrs: Vec<SocketAddr> = pm.peers_for_announcement();
            drop(pm);

            for addr in addrs {
                let ping = PingMessage { nonce: rand_u64() };
                let msg = Message::new(MessageType::Ping, ping.encode());
                let _ = outbound_tx.send(OutboundCommand::Send(addr, msg));
            }
        }
    }

    async fn run_miner(
        storage: Arc<chroma_storage::Storage>,
        chain_state: Arc<RwLock<chroma_consensus::ChainState>>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<AtomicU32>,
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
            let (height, previous_hash, previous_timestamp, state_root, bits) = {
                let cs = chain_state.read().await;
                let tip = &cs.tip;
                (tip.height.0 + 1, tip.hash, tip.header.timestamp, tip.header.state_root, tip.header.bits)
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
                state_root,
                bits,
                coinbase_recipient: miner_address.clone(),
            };

            match assemble_block(&ctx, &[]) {
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
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Block assembly failed: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
