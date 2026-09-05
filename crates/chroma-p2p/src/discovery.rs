use std::sync::Arc;

use tokio::sync::RwLock;

use crate::peer::{PeerAddress, PeerManager};

/// Hard-coded bootstrap nodes (devnet). Empty until devnet addresses are
/// assigned; peers are supplied with `--connect` in the meantime.
pub const SEED_NODES: &[&str] = &[];

/// DNS seeds. Each name resolves to a set of bootstrap node addresses.
///
/// The record does not exist yet, so resolution fails and the failure budget
/// below stops it being retried. Bootstrapping is via `--connect` until the
/// record is published.
pub const DNS_SEEDS: &[&str] = &["seed.chroma.org.uk:8333"];

pub const MAX_SEED_FAILURES: usize = 3;

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
        // the identity as well as the address. Resolving them is handled by
        // `resolve_seed`, which currently only understands literal entries;
        // the TXT lookup lands with the seed record itself.
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
    /// A seed entry is `<node-id>@host:port`. Plain host:port entries are
    /// rejected rather than dialed: without the node identity there is nothing
    /// for the Noise handshake to authenticate the far end against, so
    /// connecting would defeat the point.
    async fn resolve_seed(seed: &str) -> Option<Vec<PeerAddress>> {
        let (key, hostport) = seed.split_once('@')?;
        let node_id = chroma_crypto::noise::NodeId::from_hex(key).ok()?;

        // tokio's resolver, not `ToSocketAddrs`: the latter blocks the worker
        // thread it runs on, so a slow or unreachable seed would stall
        // unrelated tasks for the whole lookup.
        match tokio::net::lookup_host(hostport).await {
            Ok(addrs) => Some(
                addrs
                    .map(|socket| PeerAddress::new(node_id, socket))
                    .collect(),
            ),
            Err(_) => None,
        }
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
}
