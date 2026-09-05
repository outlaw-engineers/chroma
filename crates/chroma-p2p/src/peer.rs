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

/// Per-peer rate limits (spec §5). Enforced over a rolling one-second window.
pub const MSG_RATE_LIMIT: u32 = 100;
pub const TX_RATE_LIMIT: u32 = 10;

/// Counters for one peer's rolling rate-limit window.
#[derive(Clone, Debug)]
pub struct RateWindow {
    started: Instant,
    messages: u32,
    transactions: u32,
}

impl RateWindow {
    fn new() -> Self {
        RateWindow {
            started: Instant::now(),
            messages: 0,
            transactions: 0,
        }
    }

    fn roll(&mut self, now: Instant) {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.messages = 0;
            self.transactions = 0;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    Connecting,
    Connected,
    Handshaking,
    Ready,
    Disconnected,
    Banned,
}

/// Outcome of claiming a connection slot for a peer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConnectionSlot {
    /// The slot was claimed; the caller owns this connection.
    Accepted,
    /// A connection to this peer is already live.
    Duplicate,
    /// The peer is banned.
    Banned,
    /// The relevant connection limit is already reached.
    Full,
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub state: PeerState,
    pub score: i32,
    pub connected_at: Option<Instant>,
    pub last_seen: Option<Instant>,
    pub last_ping_nonce: Option<u64>,
    /// When the outstanding ping was sent, for timeout detection.
    pub last_ping_at: Option<Instant>,
    pub height: u32,
    pub version: u32,
    pub services: u64,
    pub ban_until: Option<Instant>,
    /// True if the remote opened the connection to us.
    pub inbound: bool,
    /// Rolling counters backing the per-peer rate limits.
    rate: RateWindow,
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
            last_ping_at: None,
            height: 0,
            version: 0,
            services: 0,
            ban_until: None,
            inbound: false,
            rate: RateWindow::new(),
        }
    }

    /// Count a received message against the peer's allowance.
    ///
    /// Returns false once the peer is over its limit for the current second.
    /// Without this a single peer can make us spend unbounded work — signature
    /// verification alone costs ~84 µs per transaction.
    pub fn allow_message(&mut self) -> bool {
        self.allow_message_at(Instant::now())
    }

    pub fn allow_message_at(&mut self, now: Instant) -> bool {
        self.rate.roll(now);
        self.rate.messages = self.rate.messages.saturating_add(1);
        self.rate.messages <= MSG_RATE_LIMIT
    }

    /// Count a received transaction against the peer's separate, tighter
    /// transaction allowance.
    pub fn allow_transaction(&mut self) -> bool {
        self.allow_transaction_at(Instant::now())
    }

    pub fn allow_transaction_at(&mut self, now: Instant) -> bool {
        self.rate.roll(now);
        self.rate.transactions = self.rate.transactions.saturating_add(1);
        self.rate.transactions <= TX_RATE_LIMIT
    }

    /// True while a connection to this peer is live or being established.
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            PeerState::Connecting | PeerState::Connected | PeerState::Handshaking | PeerState::Ready
        )
    }

    /// True if the peer has gone quiet for longer than `timeout`.
    pub fn is_stale(&self, timeout: Duration) -> bool {
        let reference = self.last_seen.or(self.connected_at);
        match reference {
            Some(t) => t.elapsed() > timeout,
            None => false,
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

    /// Atomically claim a connection slot for `addr`.
    ///
    /// Checking "is this peer already connected?" and marking it connected must
    /// happen under one lock acquisition, otherwise two simultaneous dials to
    /// the same peer both observe "not connected" and both proceed.
    pub fn begin_connection(&mut self, addr: SocketAddr, inbound: bool) -> ConnectionSlot {
        if let Some(peer) = self.peers.get(&addr) {
            if peer.is_banned() {
                return ConnectionSlot::Banned;
            }
            if peer.is_active() {
                return ConnectionSlot::Duplicate;
            }
        }

        let limit_reached = if inbound {
            self.inbound_count() >= MAX_INBOUND_PEERS
        } else {
            self.outbound_count() >= MAX_OUTBOUND_PEERS
        };
        if limit_reached {
            return ConnectionSlot::Full;
        }

        let peer = self.peers.entry(addr).or_insert_with(|| PeerInfo::new(addr));
        peer.state = PeerState::Connecting;
        peer.inbound = inbound;
        peer.connected_at = Some(Instant::now());
        peer.last_seen = None;
        peer.last_ping_nonce = None;
        peer.last_ping_at = None;
        ConnectionSlot::Accepted
    }

    /// Mark a peer's connection as closed.
    ///
    /// The `PeerInfo` is kept so the accumulated score and any ban survive the
    /// disconnect — dropping the entry would let a misbehaving peer clear its
    /// own ban simply by reconnecting.
    pub fn mark_disconnected(&mut self, addr: &SocketAddr) {
        self.channels.remove(addr);
        if let Some(peer) = self.peers.get_mut(addr) {
            if peer.state != PeerState::Banned {
                peer.state = PeerState::Disconnected;
            }
            peer.last_ping_nonce = None;
            peer.last_ping_at = None;
        }
    }

    /// Number of live inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers.values().filter(|p| p.inbound && p.is_active()).count()
    }

    /// Number of live outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers.values().filter(|p| !p.inbound && p.is_active()).count()
    }

    /// Peers that have gone quiet for longer than `timeout` and should be cut.
    pub fn stale_peers(&self, timeout: Duration) -> Vec<SocketAddr> {
        self.peers
            .values()
            .filter(|p| p.is_active() && p.is_stale(timeout))
            .map(|p| p.addr)
            .collect()
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

    /// Drop entries for peers that are disconnected and not banned.
    /// Banned peers are retained so that the ban outlives the connection.
    pub fn prune_disconnected(&mut self) {
        let addrs: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Disconnected && !p.is_banned())
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
    fn test_begin_connection_rejects_duplicate() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        assert_eq!(pm.begin_connection(addr, false), ConnectionSlot::Accepted);
        // A second dial while the first is live must not open another socket.
        assert_eq!(pm.begin_connection(addr, false), ConnectionSlot::Duplicate);

        // ...but reconnecting after a clean disconnect is allowed.
        pm.mark_disconnected(&addr);
        assert_eq!(pm.begin_connection(addr, false), ConnectionSlot::Accepted);
    }

    #[test]
    fn test_begin_connection_rejects_banned() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.ban_peer(&addr);
        assert_eq!(pm.begin_connection(addr, false), ConnectionSlot::Banned);
    }

    #[test]
    fn test_begin_connection_enforces_separate_limits() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_OUTBOUND_PEERS {
            let addr = test_addr(9000 + i as u16);
            assert_eq!(pm.begin_connection(addr, false), ConnectionSlot::Accepted);
        }
        assert_eq!(
            pm.begin_connection(test_addr(9999), false),
            ConnectionSlot::Full
        );
        // The inbound budget is separate and still has room.
        assert_eq!(
            pm.begin_connection(test_addr(9998), true),
            ConnectionSlot::Accepted
        );

        for i in 1..MAX_INBOUND_PEERS {
            let addr = test_addr(10_000 + i as u16);
            assert_eq!(pm.begin_connection(addr, true), ConnectionSlot::Accepted);
        }
        assert_eq!(
            pm.begin_connection(test_addr(11_000), true),
            ConnectionSlot::Full
        );
    }

    #[test]
    fn test_ban_survives_disconnect() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        pm.add_peer(addr);
        pm.ban_peer(&addr);

        // Disconnect must not erase the ban (remove_peer would have).
        pm.mark_disconnected(&addr);
        assert!(pm.get_peer(&addr).unwrap().is_banned());
        pm.prune_disconnected();
        assert!(
            pm.get_peer(&addr).is_some_and(|p| p.is_banned()),
            "a banned peer must not be pruned away"
        );
        assert_eq!(pm.begin_connection(addr, true), ConnectionSlot::Banned);
    }

    #[test]
    fn test_mark_disconnected_clears_channel() {
        let mut pm = PeerManager::new();
        let addr = test_addr(8333);
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(4);
        pm.begin_connection(addr, false);
        pm.set_channel(addr, tx);
        assert!(pm.get_channel(&addr).is_some());
        pm.mark_disconnected(&addr);
        assert!(pm.get_channel(&addr).is_none());
        assert_eq!(pm.get_peer(&addr).unwrap().state, PeerState::Disconnected);
    }

    #[test]
    fn test_stale_peers() {
        let mut pm = PeerManager::new();
        let fresh = test_addr(8333);
        let quiet = test_addr(8334);
        pm.begin_connection(fresh, false);
        pm.begin_connection(quiet, false);
        pm.get_peer_mut(&fresh).unwrap().state = PeerState::Ready;
        pm.get_peer_mut(&fresh).unwrap().last_seen = Some(Instant::now());
        pm.get_peer_mut(&quiet).unwrap().state = PeerState::Ready;
        pm.get_peer_mut(&quiet).unwrap().last_seen =
            Some(Instant::now() - Duration::from_secs(PEER_TIMEOUT_SECS + 5));

        let stale = pm.stale_peers(Duration::from_secs(PEER_TIMEOUT_SECS));
        assert_eq!(stale, vec![quiet]);
    }

    #[test]
    fn test_message_rate_limit() {
        let mut peer = PeerInfo::new(test_addr(8333));
        let now = Instant::now();

        for i in 0..MSG_RATE_LIMIT {
            assert!(
                peer.allow_message_at(now),
                "message {} should be within the allowance",
                i
            );
        }
        assert!(!peer.allow_message_at(now), "one past the limit must be refused");

        // The window rolls, and the peer is allowed again.
        let later = now + Duration::from_millis(1_100);
        assert!(peer.allow_message_at(later));
    }

    #[test]
    fn test_transaction_rate_limit_is_separate_and_tighter() {
        let mut peer = PeerInfo::new(test_addr(8333));
        let now = Instant::now();

        for _ in 0..TX_RATE_LIMIT {
            assert!(peer.allow_transaction_at(now));
        }
        assert!(!peer.allow_transaction_at(now));

        // Messages have their own, larger budget, untouched by the above.
        assert!(peer.allow_message_at(now));
    }

    #[test]
    fn test_rate_window_rolls_forward() {
        let mut peer = PeerInfo::new(test_addr(8333));
        let mut now = Instant::now();
        for _ in 0..5 {
            for _ in 0..TX_RATE_LIMIT {
                assert!(peer.allow_transaction_at(now));
            }
            assert!(!peer.allow_transaction_at(now));
            now += Duration::from_secs(1);
        }
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
