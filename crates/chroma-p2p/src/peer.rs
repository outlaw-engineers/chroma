use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant, UNIX_EPOCH};

use tokio::sync::mpsc;

/// Everything needed to dial a peer: where it is, who it is, and the static
/// key its handshake will use.
///
/// Both keys are here because they do different jobs. Noise XK does its
/// Diffie-Hellman against the X25519 static key, so the dialer must hold that
/// key before it connects. The node id is the ed25519 identity that signed
/// that static key, and it is the part that has to be right: a substituted
/// static key fails the handshake, because whoever substituted it cannot sign
/// it as this identity.
///
/// Written as `<node-id>.<noise-key>@host:port`, both keys in hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerAddress {
    pub node_id: chroma_crypto::noise::NodeId,
    pub noise_key: chroma_crypto::noise::NoiseKey,
    pub socket: SocketAddr,
}

impl PeerAddress {
    pub fn new(
        node_id: chroma_crypto::noise::NodeId,
        noise_key: chroma_crypto::noise::NoiseKey,
        socket: SocketAddr,
    ) -> Self {
        PeerAddress {
            node_id,
            noise_key,
            socket,
        }
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}@{}",
            self.node_id.to_hex(),
            self.noise_key.to_hex(),
            self.socket
        )
    }
}

impl FromStr for PeerAddress {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (keys, socket) = s.split_once('@').ok_or_else(|| {
            format!(
                "expected <node-id>.<noise-key>@<host:port>, got {:?}",
                s
            )
        })?;
        let (id, key) = keys.split_once('.').ok_or_else(|| {
            format!(
                "expected <node-id>.<noise-key>@<host:port>, got {:?}",
                s
            )
        })?;
        let node_id = chroma_crypto::noise::NodeId::from_hex(id)
            .map_err(|e| format!("bad node id: {}", e))?;
        let noise_key = chroma_crypto::noise::NoiseKey::from_hex(key)
            .map_err(|e| format!("bad noise key: {}", e))?;
        let socket: SocketAddr = socket
            .parse()
            .map_err(|e| format!("bad socket address: {}", e))?;
        Ok(PeerAddress {
            node_id,
            noise_key,
            socket,
        })
    }
}

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

/// Bytes a peer may send us per second.
///
/// Message count alone does not bound bandwidth: `MAX_MESSAGE_SIZE` is 4 MiB
/// and a hundred messages a second are allowed, so without this a single peer
/// may legitimately push 400 MiB/s at us.
pub const BYTE_RATE_LIMIT: usize = 1024 * 1024;

/// Inventory entries a peer may ask for per second.
///
/// `GetData` gets a limit of its own because it is the only request that
/// reads the database. One message carries up to `MAX_INVENTORY` entries and
/// a hundred messages a second are allowed, so charging it to the ordinary
/// message budget permits 50,000 block reads a second.
pub const GETDATA_RATE_LIMIT: u32 = 50;

/// Connections allowed from one address group (see [`AddressGroup`]).
pub const MAX_CONNECTIONS_PER_GROUP: usize = 2;

/// Connections allowed from one IPv6 site (/48), across all its /64s.
pub const MAX_CONNECTIONS_PER_SITE: usize = 4;

/// Inbound slots held back for address groups we have no connection from.
///
/// Without this an attacker who is inside every other limit can still take
/// every inbound slot and leave the node unable to hear from anyone else.
/// Outbound slots are not at risk: we choose those ourselves.
pub const RESERVED_INBOUND_SLOTS: usize = 4;

/// The unit a peer's resource use is counted under.
///
/// Not an address. A single IPv6 subscriber line is handed a /64, so counting
/// by address would give one household 2^64 accounts, which is the same as no
/// limit at all. /64 is roughly one line and /48 roughly one site, and both
/// are counted so that a site cannot spread across its own /64s.
///
/// IPv4 is counted by /24: smaller than that is not routed separately, so it
/// is the smallest block someone has to actually obtain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AddressGroup {
    /// An IPv4 /24.
    V4([u8; 3]),
    /// An IPv6 /64.
    V6([u8; 8]),
    /// Loopback and private ranges, which are exempt from the connection
    /// limits: several nodes on one machine, or on one LAN, is a normal way
    /// to run this and not something to defend against.
    Local,
}

impl AddressGroup {
    pub fn of(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_private() || v4.is_link_local() {
                    return AddressGroup::Local;
                }
                let o = v4.octets();
                AddressGroup::V4([o[0], o[1], o[2]])
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() {
                    return AddressGroup::Local;
                }
                let o = v6.octets();
                // fc00::/7, the unique-local range.
                if o[0] & 0xFE == 0xFC {
                    return AddressGroup::Local;
                }
                // fe80::/10, link-local.
                if o[0] == 0xFE && o[1] & 0xC0 == 0x80 {
                    return AddressGroup::Local;
                }
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&o[..8]);
                AddressGroup::V6(prefix)
            }
        }
    }

    /// The wider IPv6 grouping (/48) this belongs to, if any.
    pub fn site(&self) -> Option<[u8; 6]> {
        match self {
            AddressGroup::V6(prefix) => {
                let mut site = [0u8; 6];
                site.copy_from_slice(&prefix[..6]);
                Some(site)
            }
            _ => None,
        }
    }

    pub fn is_local(&self) -> bool {
        matches!(self, AddressGroup::Local)
    }
}

/// Counters for one peer's rolling rate-limit window.
#[derive(Clone, Debug)]
pub struct RateWindow {
    started: Instant,
    messages: u32,
    transactions: u32,
    getdata: u32,
    bytes: usize,
}

impl RateWindow {
    fn new() -> Self {
        RateWindow {
            started: Instant::now(),
            messages: 0,
            transactions: 0,
            getdata: 0,
            bytes: 0,
        }
    }

    fn roll(&mut self, now: Instant) {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.messages = 0;
            self.transactions = 0;
            self.getdata = 0;
            self.bytes = 0;
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
    /// The node identity this peer presented, once known.
    pub node_id: Option<chroma_crypto::noise::NodeId>,
    /// The static key that identity authorised. Needed to dial the peer, so
    /// an entry without it can be talked to but not called back.
    pub noise_key: Option<chroma_crypto::noise::NoiseKey>,
    /// True once a handshake completed on this address at least once.
    ///
    /// Only these are worth passing to other nodes: an address we merely heard
    /// about, or one we failed to reach, would just spread noise.
    pub handshaked: bool,
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
            node_id: None,
            noise_key: None,
            handshaked: false,
            rate: RateWindow::new(),
        }
    }

    /// The address another node could dial this peer on.
    ///
    /// Both keys or nothing: XK needs the static key to connect at all, and
    /// the identity to know whether it reached the right node, so half an
    /// identity is not something to hand out or act on.
    pub fn peer_address(&self) -> Option<PeerAddress> {
        match (self.node_id, self.noise_key) {
            (Some(node_id), Some(noise_key)) => {
                Some(PeerAddress::new(node_id, noise_key, self.addr))
            }
            _ => None,
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

    /// Charge `count` inventory entries against this peer's `GetData` budget.
    pub fn allow_getdata(&mut self, count: usize) -> bool {
        self.allow_getdata_at(count, Instant::now())
    }

    pub fn allow_getdata_at(&mut self, count: usize, now: Instant) -> bool {
        self.rate.roll(now);
        self.rate.getdata = self
            .rate
            .getdata
            .saturating_add(count.min(u32::MAX as usize) as u32);
        self.rate.getdata <= GETDATA_RATE_LIMIT
    }

    /// Charge `bytes` received against this peer's bandwidth budget.
    pub fn allow_bytes(&mut self, bytes: usize) -> bool {
        self.allow_bytes_at(bytes, Instant::now())
    }

    pub fn allow_bytes_at(&mut self, bytes: usize, now: Instant) -> bool {
        self.rate.roll(now);
        self.rate.bytes = self.rate.bytes.saturating_add(bytes);
        self.rate.bytes <= BYTE_RATE_LIMIT
    }

    /// The address group this peer is counted under.
    pub fn group(&self) -> AddressGroup {
        AddressGroup::of(self.addr.ip())
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
    /// Inbound sockets accepted but not yet through the handshake, counted by
    /// address group.
    ///
    /// Without this the inbound cap only bounds *completed* handshakes: an
    /// attacker opens sockets, leaves them mid-handshake, and none of them are
    /// counted anywhere. The count is by group rather than by socket so the
    /// same table answers both the total and the per-group limit.
    pending_inbound: HashMap<AddressGroup, usize>,
}

/// The answer to "may this inbound socket proceed?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundAdmission {
    /// Accepted; the caller must call `release_inbound` when the connection
    /// ends, however it ends.
    Accepted,
    /// No inbound slot left at all.
    Full,
    /// This address group already holds as many connections as it may.
    GroupFull,
    /// Slots remain, but the ones left are reserved for groups we have no
    /// connection from, and this is not one of those.
    Reserved,
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
            pending_inbound: HashMap::new(),
        }
    }

    /// Connections currently held by `group`, counting both the sockets still
    /// in their handshake and the peers past it.
    pub fn connections_from(&self, group: AddressGroup) -> usize {
        let pending = self.pending_inbound.get(&group).copied().unwrap_or(0);
        let established = self
            .peers
            .values()
            .filter(|p| p.is_active() && p.group() == group)
            .count();
        pending + established
    }

    /// Connections currently held by an IPv6 site (/48), across its /64s.
    fn connections_from_site(&self, site: [u8; 6]) -> usize {
        let pending: usize = self
            .pending_inbound
            .iter()
            .filter(|(g, _)| g.site() == Some(site))
            .map(|(_, n)| *n)
            .sum();
        let established = self
            .peers
            .values()
            .filter(|p| p.is_active() && p.group().site() == Some(site))
            .count();
        pending + established
    }

    /// Inbound sockets in flight, handshaking or connected.
    pub fn inbound_in_flight(&self) -> usize {
        let pending: usize = self.pending_inbound.values().sum();
        pending + self.inbound_count()
    }

    /// Decide whether a freshly accepted socket may proceed, and if so claim
    /// its place.
    ///
    /// Called with the socket's source address, which for an inbound
    /// connection has an ephemeral port and so cannot identify the peer. The
    /// address group can still be read from it, and that is what the limits
    /// are counted under.
    pub fn admit_inbound(&mut self, src: SocketAddr) -> InboundAdmission {
        let group = AddressGroup::of(src.ip());

        // A node sharing a machine or a LAN with us is a normal setup, not an
        // attack, and is exempt from the group limits. The total still holds.
        if !group.is_local() {
            if self.connections_from(group) >= MAX_CONNECTIONS_PER_GROUP {
                return InboundAdmission::GroupFull;
            }
            if let Some(site) = group.site() {
                if self.connections_from_site(site) >= MAX_CONNECTIONS_PER_SITE {
                    return InboundAdmission::GroupFull;
                }
            }
        }

        let in_flight = self.inbound_in_flight();
        if in_flight >= MAX_INBOUND_PEERS {
            return InboundAdmission::Full;
        }

        // The last few slots are kept for groups we are not already talking
        // to, so that filling the table is not the same as silencing the node.
        let known_group = self.connections_from(group) > 0;
        if known_group && in_flight >= MAX_INBOUND_PEERS - RESERVED_INBOUND_SLOTS {
            return InboundAdmission::Reserved;
        }

        *self.pending_inbound.entry(group).or_insert(0) += 1;
        InboundAdmission::Accepted
    }

    /// Give back the place claimed by `admit_inbound`.
    ///
    /// Must be called once per accepted socket, on every path out of the
    /// connection — a leak here silently shrinks the inbound capacity until
    /// the node stops accepting anything.
    pub fn release_inbound(&mut self, src: SocketAddr) {
        let group = AddressGroup::of(src.ip());
        if let Some(count) = self.pending_inbound.get_mut(&group) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.pending_inbound.remove(&group);
            }
        }
    }

    pub fn add_peer(&mut self, addr: SocketAddr) {
        if !self.peers.contains_key(&addr) {
            self.peers.insert(addr, PeerInfo::new(addr));
        }
    }

    /// Record a peer whose identity we already know, so it can be dialed.
    pub fn add_known_peer(&mut self, peer: PeerAddress) {
        let entry = self
            .peers
            .entry(peer.socket)
            .or_insert_with(|| PeerInfo::new(peer.socket));
        entry.node_id = Some(peer.node_id);
        entry.noise_key = Some(peer.noise_key);
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

    /// Addresses worth telling other nodes about.
    ///
    /// Restricted to peers we have actually completed a handshake with and
    /// that are not banned, so gossip spreads reachable nodes rather than
    /// whatever a peer chose to claim.
    pub fn shareable_addrs(&self, limit: usize, except: Option<SocketAddr>) -> Vec<PeerAddress> {
        self.peers
            .values()
            .filter(|p| p.handshaked && !p.is_banned())
            .filter(|p| Some(p.addr) != except)
            .filter_map(|p| p.peer_address())
            .take(limit)
            .collect()
    }

    /// Peers we know of but are not connected to, for filling out our
    /// outbound slots.
    ///
    /// Only those whose identity we know: Noise XK cannot dial an address
    /// without knowing which node should answer it.
    pub fn dialable_addrs(&self, limit: usize) -> Vec<PeerAddress> {
        self.peers
            .values()
            .filter(|p| !p.is_active() && !p.is_banned())
            .filter_map(|p| p.peer_address())
            .take(limit)
            .collect()
    }

    /// How many more outbound connections we would like.
    pub fn outbound_deficit(&self) -> usize {
        MAX_OUTBOUND_PEERS.saturating_sub(self.outbound_count())
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

    // -----------------------------------------------------------------------
    // Address groups and inbound admission
    // -----------------------------------------------------------------------

    fn v6(s: &str) -> SocketAddr {
        SocketAddr::new(s.parse::<std::net::Ipv6Addr>().unwrap().into(), 8333)
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4([a, b, c, d].into()), 8333)
    }

    #[test]
    fn ipv4_is_grouped_by_prefix_not_by_address() {
        assert_eq!(
            AddressGroup::of(v4(203, 0, 113, 1).ip()),
            AddressGroup::of(v4(203, 0, 113, 254).ip()),
            "one /24 is one group"
        );
        assert_ne!(
            AddressGroup::of(v4(203, 0, 113, 1).ip()),
            AddressGroup::of(v4(203, 0, 114, 1).ip())
        );
    }

    #[test]
    fn ipv6_is_grouped_by_prefix_not_by_address() {
        // The one that matters. A subscriber line is handed a /64, so counting
        // IPv6 by address would give one household 2^64 separate accounts --
        // which is the same as having no limit.
        assert_eq!(
            AddressGroup::of(v6("2001:db8:1:2::1").ip()),
            AddressGroup::of(v6("2001:db8:1:2:ffff:ffff:ffff:ffff").ip()),
            "one /64 is one group"
        );
        assert_ne!(
            AddressGroup::of(v6("2001:db8:1:2::1").ip()),
            AddressGroup::of(v6("2001:db8:1:3::1").ip()),
            "a different /64 is a different group"
        );
        assert_eq!(
            AddressGroup::of(v6("2001:db8:1:2::1").ip()).site(),
            AddressGroup::of(v6("2001:db8:1:3::1").ip()).site(),
            "but both are the same /48 site"
        );
    }

    #[test]
    fn local_addresses_are_exempt() {
        for addr in [
            v4(127, 0, 0, 1),
            v4(192, 168, 1, 5),
            v4(10, 0, 0, 7),
            v6("::1"),
            v6("fd00::1"),
        ] {
            assert!(
                AddressGroup::of(addr.ip()).is_local(),
                "{} should be exempt",
                addr
            );
        }
    }

    #[test]
    fn one_group_gets_only_its_share_of_inbound() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_CONNECTIONS_PER_GROUP {
            assert_eq!(
                pm.admit_inbound(v4(203, 0, 113, i as u8)),
                InboundAdmission::Accepted
            );
        }
        assert_eq!(
            pm.admit_inbound(v4(203, 0, 113, 200)),
            InboundAdmission::GroupFull,
            "a different address in the same /24 is the same group"
        );
        assert_eq!(
            pm.admit_inbound(v4(203, 0, 114, 1)),
            InboundAdmission::Accepted
        );
    }

    #[test]
    fn an_ipv6_site_cannot_spread_across_its_own_subnets() {
        let mut pm = PeerManager::new();
        // Four connections, each from a different /64 of one /48.
        for n in 0..MAX_CONNECTIONS_PER_SITE {
            let addr = v6(&format!("2001:db8:1:{}::1", n));
            assert_eq!(pm.admit_inbound(addr), InboundAdmission::Accepted);
        }
        assert_eq!(
            pm.admit_inbound(v6("2001:db8:1:99::1")),
            InboundAdmission::GroupFull,
            "a fresh /64 inside a site that has used its share"
        );
        assert_eq!(
            pm.admit_inbound(v6("2001:db8:2:1::1")),
            InboundAdmission::Accepted,
            "a different /48 is a different site"
        );
    }

    #[test]
    fn the_last_slots_are_kept_for_groups_we_do_not_know() {
        let mut pm = PeerManager::new();
        let open = MAX_INBOUND_PEERS - RESERVED_INBOUND_SLOTS;
        for n in 0..open {
            let addr = v4(203, 0, n as u8, 1);
            assert_eq!(pm.admit_inbound(addr), InboundAdmission::Accepted);
        }
        // A group already at the table cannot have the reserved slots.
        assert_eq!(
            pm.admit_inbound(v4(203, 0, 0, 2)),
            InboundAdmission::Reserved
        );
        // One we have never heard from can.
        assert_eq!(
            pm.admit_inbound(v4(198, 51, 100, 1)),
            InboundAdmission::Accepted
        );
    }

    #[test]
    fn a_socket_that_never_finishes_its_handshake_still_occupies_a_slot() {
        // The gap this closes: inbound_count() only counts peers past the
        // handshake, so opening sockets and leaving them there used to cost
        // an attacker nothing and count against nothing.
        let mut pm = PeerManager::new();
        assert_eq!(pm.inbound_in_flight(), 0);
        pm.admit_inbound(v4(203, 0, 113, 1));
        assert_eq!(pm.inbound_in_flight(), 1);
        assert_eq!(pm.inbound_count(), 0, "no handshake has completed");

        pm.release_inbound(v4(203, 0, 113, 1));
        assert_eq!(pm.inbound_in_flight(), 0);
    }

    #[test]
    fn inbound_fills_up() {
        let mut pm = PeerManager::new();
        let mut accepted = 0;
        for n in 0..MAX_INBOUND_PEERS * 2 {
            // A fresh group each time, so only the total can be what stops it.
            let addr = v4(198, 51, n as u8, 1);
            if pm.admit_inbound(addr) == InboundAdmission::Accepted {
                accepted += 1;
            }
        }
        assert_eq!(accepted, MAX_INBOUND_PEERS);
        assert_eq!(pm.admit_inbound(v4(198, 51, 200, 1)), InboundAdmission::Full);
    }
}
