use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::peer::PeerManager;

/// Hard-coded bootstrap nodes (devnet). Empty until devnet addresses are
/// assigned; peers are supplied with `--connect` in the meantime.
pub const SEED_NODES: &[&str] = &[];

/// DNS seeds. Each name resolves to a set of bootstrap node addresses.
pub const DNS_SEEDS: &[&str] = &["seed.chroma.network:8333"];

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
        connect_addrs: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        let mut found = Vec::new();

        for &addr in connect_addrs {
            let mut pm = peer_manager.write().await;
            if pm.get_peer(&addr).is_none() {
                pm.add_peer(addr);
                found.push(addr);
            }
        }

        for seed in SEED_NODES.iter().chain(DNS_SEEDS.iter()) {
            if self.seed_failures >= MAX_SEED_FAILURES {
                break;
            }
            match Self::resolve(seed).await {
                Some(addrs) => {
                    self.seed_failures = 0;
                    for a in addrs {
                        let mut pm = peer_manager.write().await;
                        if pm.get_peer(&a).is_none() {
                            pm.add_peer(a);
                            found.push(a);
                        }
                    }
                }
                None => self.seed_failures += 1,
            }
        }

        found
    }

    /// Resolve one seed entry.
    ///
    /// Uses tokio's resolver rather than `ToSocketAddrs`, which blocks the
    /// worker thread it runs on — a DNS seed that is slow or unreachable would
    /// otherwise stall unrelated tasks on that thread for the whole lookup.
    async fn resolve(seed: &str) -> Option<Vec<SocketAddr>> {
        match tokio::net::lookup_host(seed).await {
            Ok(addrs) => Some(addrs.collect()),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let a: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:8334".parse().unwrap();

        let mut d = Discovery::new();
        let found = d.discover_peers(pm.clone(), &[a, b]).await;
        assert!(
            found.starts_with(&[a, b]),
            "configured peers must be reported back, got {:?}",
            found
        );

        let guard = pm.read().await;
        assert!(guard.get_peer(&a).is_some());
        assert!(guard.get_peer(&b).is_some());
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
        assert_eq!(
            Discovery::resolve("this-host-does-not-exist.invalid:8333").await,
            None
        );

        let pm = Arc::new(RwLock::new(PeerManager::new()));
        let mut d = Discovery::new();
        for _ in 0..MAX_SEED_FAILURES + 2 {
            let _ = d.discover_peers(pm.clone(), &[]).await;
        }
        assert!(d.seed_failures() <= MAX_SEED_FAILURES);
    }
}
