use std::sync::Arc;

use tokio::sync::RwLock;

use crate::peer::{PeerAddress, PeerManager};

/// Hard-coded bootstrap nodes (devnet). Empty until devnet addresses are
/// assigned; peers are supplied with `--connect` in the meantime.
pub const SEED_NODES: &[&str] = &[];

/// DNS seeds. Each name carries TXT records naming bootstrap nodes; see
/// `SEED_RECORD.md` in the repository root for the exact format and the
/// current contents of the record.
pub const DNS_SEEDS: &[&str] = &["seed.chroma.org.uk"];

/// Prefix every seed TXT string carries.
///
/// A zone holds records for other things too (SPF, verification tokens), so
/// anything without this prefix is skipped rather than parsed.
pub const SEED_TXT_PREFIX: &str = "chroma-seed=";

pub const MAX_SEED_FAILURES: usize = 3;

/// How long one DNS lookup may take before it counts as a failure.
pub const DNS_TIMEOUT_SECS: u64 = 5;

/// Cap on peers taken from one DNS answer.
///
/// A seed operator, or anyone who can spoof a plaintext DNS reply, would
/// otherwise decide how big our peer table gets.
pub const MAX_PEERS_PER_SEED: usize = 32;

pub struct Discovery {
    seed_failures: usize,
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery {
    pub fn new() -> Self {
        Discovery { seed_failures: 0 }
    }

    /// Number of consecutive seed lookups that have failed.
    pub fn seed_failures(&self) -> usize {
        self.seed_failures
    }

    /// Register bootstrap addresses and report the ones that are new.
    ///
    /// This only populates the peer table — it does not dial. The caller must
    /// connect to what is returned, or a discovered peer is never contacted.
    pub async fn discover_peers(
        &mut self,
        peer_manager: Arc<RwLock<PeerManager>>,
        connect_addrs: &[PeerAddress],
    ) -> Vec<PeerAddress> {
        let mut found = Vec::new();

        for peer in connect_addrs {
            let mut pm = peer_manager.write().await;
            if pm.get_peer(&peer.socket).is_none() {
                pm.add_known_peer(*peer);
                found.push(*peer);
            }
        }

        // Seeds publish `<node-id>@host:port` entries, since Noise XK needs
        // the identity as well as the address.
        for seed in SEED_NODES.iter().chain(DNS_SEEDS.iter()) {
            if self.seed_failures >= MAX_SEED_FAILURES {
                break;
            }
            match Self::resolve_seed(seed).await {
                Some(peers) => {
                    self.seed_failures = 0;
                    for peer in peers {
                        let mut pm = peer_manager.write().await;
                        if pm.get_peer(&peer.socket).is_none() {
                            pm.add_known_peer(peer);
                            found.push(peer);
                        }
                    }
                }
                None => self.seed_failures += 1,
            }
        }

        found
    }

    /// Resolve one seed entry into peers.
    ///
    /// A literal entry is `<node-id>@host:port`. Anything else is a DNS name,
    /// looked up for TXT records whose strings are
    /// `chroma-seed=<node-id>@host:port`.
    ///
    /// Either way the identity is mandatory. DNS is not authenticated and we
    /// do not require DNSSEC, so a seed answer is only a hint about where to
    /// look; what makes it safe to act on is that the Noise handshake refuses
    /// to talk to anything but the named key. A bare `host:port` would have to
    /// be dialed unauthenticated, so it is rejected.
    async fn resolve_seed(seed: &str) -> Option<Vec<PeerAddress>> {
        if seed.contains('@') {
            return Self::resolve_literal(seed).await;
        }
        Self::resolve_txt(seed).await
    }

    /// Resolve a `<node-id>@host:port` entry, whose host may still be a name.
    async fn resolve_literal(entry: &str) -> Option<Vec<PeerAddress>> {
        let (key, hostport) = entry.split_once('@')?;
        let node_id = chroma_crypto::noise::NodeId::from_hex(key).ok()?;

        // tokio's resolver, not `ToSocketAddrs`: the latter blocks the worker
        // thread it runs on, so a slow or unreachable seed would stall
        // unrelated tasks for the whole lookup.
        match tokio::net::lookup_host(hostport).await {
            Ok(addrs) => Some(
                addrs
                    .map(|socket| PeerAddress::new(node_id, socket))
                    .take(MAX_PEERS_PER_SEED)
                    .collect(),
            ),
            Err(_) => None,
        }
    }

    /// Look a seed name up for TXT records and parse the entries out of them.
    ///
    /// A name that resolves but holds nothing we understand counts as a
    /// failure: an empty answer is not a working seed, and treating it as one
    /// would reset the failure budget on every lookup.
    async fn resolve_txt(name: &str) -> Option<Vec<PeerAddress>> {
        // The system resolver configuration: a node should reach seeds the same
        // way the rest of the host does.
        let resolver = hickory_resolver::Resolver::builder_tokio()
            .ok()?
            .build()
            .ok()?;
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(DNS_TIMEOUT_SECS),
            resolver.txt_lookup(format!("{}.", name)),
        )
        .await
        .ok()?
        .ok()?;

        let mut peers = Vec::new();
        for record in answer.answers() {
            let txt = match &record.data {
                hickory_resolver::proto::rr::RData::TXT(txt) => txt,
                _ => continue,
            };
            // A TXT record is a list of strings, each capped at 255 bytes, so
            // one record can hold several entries.
            for raw in txt.txt_data.iter() {
                let text = match std::str::from_utf8(raw) {
                    Ok(text) => text,
                    Err(_) => continue,
                };
                if let Some(entry) = Self::parse_txt_entry(text) {
                    if !peers.contains(&entry) {
                        peers.push(entry);
                    }
                }
                if peers.len() >= MAX_PEERS_PER_SEED {
                    return Some(peers);
                }
            }
        }

        if peers.is_empty() {
            None
        } else {
            Some(peers)
        }
    }

    /// Parse one TXT string. Returns `None` for anything that is not a seed
    /// entry, so unrelated records in the same zone are ignored rather than
    /// treated as malformed.
    fn parse_txt_entry(text: &str) -> Option<PeerAddress> {
        use std::str::FromStr;

        let entry = text.trim().strip_prefix(SEED_TXT_PREFIX)?;
        // Only literal addresses: a name here would mean another lookup, and
        // a seed that can redirect us to arbitrary further lookups is a
        // needlessly large surface for something DNS already answers.
        PeerAddress::from_str(entry.trim()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_crypto::noise::NodeId;
    use std::net::SocketAddr;

    fn peer(port: u16) -> PeerAddress {
        let mut raw = [0u8; 32];
        raw[0] = port as u8;
        raw[1] = (port >> 8) as u8;
        let socket: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
        PeerAddress::new(NodeId::from_bytes(raw), socket)
    }

    #[test]
    fn test_new_discovery() {
        let d = Discovery::new();
        assert_eq!(d.seed_failures(), 0);
    }

    /// `discover_peers` registers addresses but never dials them, so its
    /// return value is the only way the caller learns what to connect to.
    /// `Node::run` depends on that: anything discovery reports must come back
    /// out, or a peer learned from a seed would be registered and then never
    /// connected to.
    #[tokio::test]
    async fn test_discover_peers_reports_what_it_registers() {
        let pm = Arc::new(RwLock::new(PeerManager::new()));
        let a = peer(8333);
        let b = peer(8334);

        let mut d = Discovery::new();
        let found = d.discover_peers(pm.clone(), &[a, b]).await;
        assert!(
            found.starts_with(&[a, b]),
            "configured peers must be reported back, got {:?}",
            found
        );

        let guard = pm.read().await;
        assert_eq!(guard.get_peer(&a.socket).unwrap().node_id, Some(a.node_id));
        assert_eq!(guard.get_peer(&b.socket).unwrap().node_id, Some(b.node_id));
        drop(guard);

        // Already-known peers are not reported a second time.
        let again = d.discover_peers(pm.clone(), &[a, b]).await;
        assert!(!again.contains(&a));
        assert!(!again.contains(&b));
    }

    /// An unresolvable seed must be counted, not panic or hang, and must stop
    /// being retried once the failure budget is spent.
    #[tokio::test]
    async fn test_unresolvable_seed_is_counted() {
        let id = NodeId::from_bytes([7u8; 32]).to_hex();
        let seed = format!("{}@this-host-does-not-exist.invalid:8333", id);
        assert!(Discovery::resolve_seed(&seed).await.is_none());

        let pm = Arc::new(RwLock::new(PeerManager::new()));
        let mut d = Discovery::new();
        for _ in 0..MAX_SEED_FAILURES + 2 {
            let _ = d.discover_peers(pm.clone(), &[]).await;
        }
        assert!(d.seed_failures() <= MAX_SEED_FAILURES);
    }

    /// A seed entry without an identity is useless: Noise XK authenticates the
    /// responder against a key the dialer already holds, so a bare `host:port`
    /// would have to be dialed unauthenticated. Reject it instead.
    #[tokio::test]
    async fn test_seed_without_node_id_is_rejected() {
        assert!(Discovery::resolve_seed("127.0.0.1:8333").await.is_none());
    }

    /// Only entries with the seed prefix are taken. A zone holds unrelated TXT
    /// records, and treating one of those as a peer would mean dialing
    /// whatever an SPF string happened to parse as.
    #[test]
    fn test_txt_entry_requires_the_prefix() {
        let id = NodeId::from_bytes([3u8; 32]).to_hex();
        let good = format!("{}{}@127.0.0.1:8333", SEED_TXT_PREFIX, id);
        let parsed = Discovery::parse_txt_entry(&good).expect("prefixed entry must parse");
        assert_eq!(parsed.socket, "127.0.0.1:8333".parse::<SocketAddr>().unwrap());
        assert_eq!(parsed.node_id.to_hex(), id);

        assert!(Discovery::parse_txt_entry(&format!("{}@127.0.0.1:8333", id)).is_none());
        assert!(Discovery::parse_txt_entry("v=spf1 -all").is_none());
        assert!(Discovery::parse_txt_entry("").is_none());
    }

    /// Surrounding whitespace is what a zone file editor adds by accident; it
    /// should not cost an entry.
    #[test]
    fn test_txt_entry_tolerates_whitespace() {
        let id = NodeId::from_bytes([9u8; 32]).to_hex();
        for entry in [
            format!("  {}{}@127.0.0.1:8333  ", SEED_TXT_PREFIX, id),
            format!("{} {}@127.0.0.1:8333", SEED_TXT_PREFIX, id),
            format!("\t{}{}@127.0.0.1:8333\n", SEED_TXT_PREFIX, id),
        ] {
            assert!(
                Discovery::parse_txt_entry(&entry).is_some(),
                "whitespace should not cost an entry: {:?}",
                entry
            );
        }
    }

    /// An entry without an identity must be refused wherever it appears. Noise
    /// XK has nothing to authenticate the far end against without one, so the
    /// address alone is worse than useless.
    #[test]
    fn test_txt_entry_without_identity_is_refused() {
        assert!(
            Discovery::parse_txt_entry(&format!("{}127.0.0.1:8333", SEED_TXT_PREFIX)).is_none()
        );
        assert!(
            Discovery::parse_txt_entry(&format!("{}not-a-node@127.0.0.1:8333", SEED_TXT_PREFIX))
                .is_none()
        );
    }

    /// Live check against the published record, for whoever is editing the
    /// zone. Ignored by default: it needs working DNS and the record to exist,
    /// neither of which a test run should depend on.
    ///
    /// `cargo test -p chroma-p2p -- --ignored live_seed_record`
    #[tokio::test]
    #[ignore = "requires DNS and a published seed record"]
    async fn live_seed_record_resolves() {
        for seed in DNS_SEEDS {
            let peers = Discovery::resolve_seed(seed)
                .await
                .unwrap_or_else(|| panic!("{} published no usable seed entries", seed));
            for peer in &peers {
                println!("{} -> {}", seed, peer);
            }
            assert!(!peers.is_empty());
        }
    }
}
