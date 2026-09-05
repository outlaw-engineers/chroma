pub mod wire;
pub mod peer;
pub mod mempool;
pub mod discovery;
pub mod sync;

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    pub chain_height: Arc<tokio::sync::RwLock<u32>>,
}

impl NodeConfig {
    pub fn new(listen_addr: SocketAddr, genesis_hash: Hash) -> Self {
        NodeConfig {
            listen_addr,
            connect_addrs: Vec::new(),
            genesis_hash,
            chain_height: Arc::new(tokio::sync::RwLock::new(0)),
        }
    }
}

pub struct Node {
    config: NodeConfig,
    peer_manager: Arc<RwLock<PeerManager>>,
    mempool: Arc<RwLock<Mempool>>,
    #[allow(dead_code)]
    discovery: Discovery,
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
        Node {
            config,
            peer_manager: Arc::new(RwLock::new(PeerManager::new())),
            mempool: Arc::new(RwLock::new(Mempool::new())),
            discovery: Discovery::new(),
            event_tx,
            event_rx: Some(event_rx),
            outbound_tx: Some(outbound_tx),
            outbound_rx: Some(outbound_rx),
        }
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
        tokio::spawn(async move {
            Self::run_outbound(peer_mgr_out, outbound_rx, event_tx_out, chain_height_out).await;
        });

        let peer_mgr_in = peer_mgr.clone();
        let mempool_in = mempool.clone();
        let event_tx_in = event_tx.clone();
        let chain_height_in = self.config.chain_height.clone();
        tokio::spawn(async move {
            Self::run_inbound(
                listener,
                peer_mgr_in,
                mempool_in,
                event_tx_in,
                genesis_hash,
                chain_height_in,
            )
            .await;
        });

        let peer_mgr_tick = peer_mgr.clone();
        tokio::spawn(async move {
            Self::run_peer_tick(peer_mgr_tick).await;
        });

        Ok(())
    }

    async fn run_outbound(
        peer_manager: Arc<RwLock<PeerManager>>,
        mut outbound_rx: mpsc::UnboundedReceiver<OutboundCommand>,
        event_tx: mpsc::UnboundedSender<NodeEvent>,
        chain_height: Arc<tokio::sync::RwLock<u32>>,
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
                        Ok(Ok(stream)) => {
                            let mut pm = peer_manager.write().await;
                            pm.add_peer(addr);
                            if let Some(peer) = pm.get_peer_mut(&addr) {
                                peer.state = PeerState::Connected;
                                peer.connected_at = Some(std::time::Instant::now());
                            }
                            drop(pm);
                            let _ = event_tx.send(NodeEvent::PeerConnected(addr));

                            let height = *chain_height.read().await;
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
                            let mut stream = stream;
                            let _ = stream.write_all(&msg.encode()).await;
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
        chain_height: Arc<tokio::sync::RwLock<u32>>,
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

            tokio::spawn(async move {
                match Self::handle_connection(stream, addr, pm, et, ch).await {
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
        chain_height: Arc<tokio::sync::RwLock<u32>>,
    ) -> Result<(), P2pError> {
        {
            let mut pm = peer_manager.write().await;
            pm.add_peer(addr);
            if let Some(peer) = pm.get_peer_mut(&addr) {
                peer.state = PeerState::Connected;
                peer.connected_at = Some(std::time::Instant::now());
            }
        }

        let height = *chain_height.read().await;
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
                            MessageType::GetData
                            | MessageType::Tx
                            | MessageType::Block
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

    async fn run_peer_tick(peer_manager: Arc<RwLock<PeerManager>>) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(PING_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let pm = peer_manager.read().await;
            let peers: Vec<SocketAddr> = pm.ready_peers().into_iter().map(|p| p.addr).collect();
            drop(pm);

            for addr in peers {
                let ping = PingMessage { nonce: rand_u64() };
                let msg = Message::new(MessageType::Ping, ping.encode());
                if let Ok(mut stream) = TcpStream::connect(addr).await {
                    let _ = stream.write_all(&msg.encode()).await;
                }
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
                let addrs: Vec<SocketAddr> = pm.peers_for_announcement();
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
        let genesis = Hash::blake3(b"genesis");
        let config = NodeConfig::new(addr, genesis);
        let node = Node::new(config);
        assert!(node.event_rx.is_some());
        assert!(node.outbound_rx.is_some());
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
