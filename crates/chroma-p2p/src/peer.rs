use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, UNIX_EPOCH};

use tokio::sync::mpsc;

pub const PEER_SCORE_GOOD: i32 = 10;
pub const PEER_SCORE_BAD: i32 = -100;
pub const BAN_SCORE_THRESHOLD: i32 = -200;
pub const MAX_OUTBOUND_PEERS: usize = 8;
pub const MAX_INBOUND_PEERS: usize = 16;
pub const PEER_TIMEOUT_SECS: u64 = 30;
pub const PING_INTERVAL_SECS: u64 = 5;
pub const VERSION_TIMEOUT_SECS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Connected,
    Handshaking,
    Ready,
    Disconnected,
    Banned,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub state: PeerState,
    pub score: i32,
    pub connected_at: Option<Instant>,
    pub last_seen: Option<Instant>,
    pub last_ping_nonce: Option<u64>,
    pub height: u32,
    pub version: u32,
    pub services: u64,
    pub ban_until: Option<Instant>,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr) -> Self {
        PeerInfo {
            addr,
            state: PeerState::Disconnected,
            score: 0,
            connected_at: None,
            last_seen: None,
            last_ping_nonce: None,
            height: 0,
            version: 0,
            services: 0,
            ban_until: None,
        }
    }

    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.ban_until {
            Instant::now() < until
        } else {
            self.score <= BAN_SCORE_THRESHOLD
        }
    }

    pub fn score_tick(&mut self) {
        self.score = self.score.saturating_add(1);
    }

    pub fn score_bad(&mut self, points: i32) {
        self.score = self.score.saturating_sub(points);
        if self.score <= BAN_SCORE_THRESHOLD {
            self.ban_until = Some(Instant::now() + Duration::from_secs(3600));
            self.state = PeerState::Banned;
        }
    }
}

pub struct PeerManager {
    peers: HashMap<SocketAddr, PeerInfo>,
    channels: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>,
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerManager {
    pub fn new() -> Self {
        PeerManager {
            peers: HashMap::new(),
            channels: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        if !self.peers.contains_key(&addr) {
            self.peers.insert(addr, PeerInfo::new(addr));
        }
    }

    pub fn remove_peer(&mut self, addr: &SocketAddr) {
        self.peers.remove(addr);
        self.channels.remove(addr);
    }

    pub fn get_peer(&self, addr: &SocketAddr) -> Option<&PeerInfo> {
        self.peers.get(addr)
    }

    pub fn get_peer_mut(&mut self, addr: &SocketAddr) -> Option<&mut PeerInfo> {
        self.peers.get_mut(addr)
    }

    pub fn connected_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| matches!(p.state, PeerState::Ready))
            .count()
    }

    pub fn ready_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Ready && !p.is_banned())
            .collect()
    }

    pub fn connected_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| !matches!(p.state, PeerState::Disconnected) && !p.is_banned())
            .collect()
    }

    pub fn need_more_peers(&self) -> bool {
        self.connected_count() < MAX_OUTBOUND_PEERS
    }

    pub fn random_peer(&self) -> Option<&PeerInfo> {
        let ready: Vec<&PeerInfo> = self.ready_peers();
        if ready.is_empty() {
            return None;
        }
        let idx = (std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize)
            % ready.len();
        ready.into_iter().nth(idx)
    }

    pub fn set_channel(&mut self, addr: SocketAddr, tx: mpsc::Sender<Vec<u8>>) {
        self.channels.insert(addr, tx);
    }

    pub fn get_channel(&self, addr: &SocketAddr) -> Option<&mpsc::Sender<Vec<u8>>> {
        self.channels.get(addr)
    }

    pub fn ban_peer(&mut self, addr: &SocketAddr) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.score = BAN_SCORE_THRESHOLD - 1;
            peer.ban_until = Some(Instant::now() + Duration::from_secs(3600));
            peer.state = PeerState::Banned;
        }
    }

    pub fn prune_disconnected(&mut self) {
        let addrs: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Disconnected)
            .map(|(a, _)| *a)
            .collect();
        for addr in addrs {
            self.remove_peer(&addr);
        }
    }

    pub fn peers_for_announcement(&self) -> Vec<SocketAddr> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Ready && !p.is_banned())
            .map(|p| p.addr)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn test_addr(n: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), n)
    }

    #[test]
    fn test_add_and_get_peer() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        assert!(pm.get_peer(&addr).is_some());
    }

    #[test]
    fn test_remove_peer() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.remove_peer(&addr);
        assert!(pm.get_peer(&addr).is_none());
    }

    #[test]
    fn test_connected_count() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        pm.add_peer(a1);
        pm.add_peer(a2);
        assert_eq!(pm.connected_count(), 0);

        pm.get_peer_mut(&a1).unwrap().state = PeerState::Ready;
        assert_eq!(pm.connected_count(), 1);
    }

    #[test]
    fn test_need_more_peers() {
        let mut pm = PeerManager::new();
        assert!(pm.need_more_peers());

        for i in 0..MAX_OUTBOUND_PEERS {
            let addr = test_addr((8333 + i) as u16);
            pm.add_peer(addr);
            pm.get_peer_mut(&addr).unwrap().state = PeerState::Ready;
        }
        assert!(!pm.need_more_peers());
    }

    #[test]
    fn test_peer_scoring() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);

        for _ in 0..5 {
            pm.get_peer_mut(&addr).unwrap().score_tick();
        }
        assert_eq!(pm.get_peer(&addr).unwrap().score, 5);

        pm.get_peer_mut(&addr)
            .unwrap()
            .score_bad(210);
        assert!(pm.get_peer(&addr).unwrap().is_banned());
    }

    #[test]
    fn test_ban_peer() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.ban_peer(&addr);
        assert!(pm.get_peer(&addr).unwrap().is_banned());
        assert_eq!(pm.get_peer(&addr).unwrap().state, PeerState::Banned);
    }

    #[test]
    fn test_peer_info_new() {
        let addr = test_addr(9000);
        let info = PeerInfo::new(addr);
        assert_eq!(info.addr, addr);
        assert_eq!(info.state, PeerState::Disconnected);
        assert_eq!(info.score, 0);
        assert!(!info.is_banned());
    }

    #[test]
    fn test_prune_disconnected() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        pm.add_peer(a1);
        pm.add_peer(a2);
        pm.get_peer_mut(&a1).unwrap().state = PeerState::Ready;
        pm.prune_disconnected();
        assert!(pm.get_peer(&a1).is_some());
        assert!(pm.get_peer(&a2).is_none());
    }

    #[test]
    fn test_ready_peers() {
        let mut pm = PeerManager::new();
        let a1 = test_addr(8333);
        let a2 = test_addr(8334);
        let a3 = test_addr(8335);
        pm.add_peer(a1);
        pm.add_peer(a2);
        pm.add_peer(a3);
        pm.get_peer_mut(&a1).unwrap().state = PeerState::Ready;
        pm.get_peer_mut(&a2).unwrap().state = PeerState::Connected;
        pm.ban_peer(&a3);

        let ready = pm.ready_peers();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].addr, a1);
    }
}
