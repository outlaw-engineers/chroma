use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::peer::PeerManager;

pub const SEED_NODES: &[&str] = &[];
pub const DNS_SEEDS: &[&str] = &[];
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

    pub async fn discover_peers(
        &mut self,
        peer_manager: Arc<RwLock<PeerManager>>,
        connect_addrs: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        let mut found = Vec::new();

        for &addr in connect_addrs {
            let mut pm = peer_manager.write().await;
            if !pm.get_peer(&addr).is_some() {
                pm.add_peer(addr);
                found.push(addr);
            }
        }

        for seed in SEED_NODES {
            if let Ok(addr) = seed.to_socket_addrs() {
                for a in addr {
                    let mut pm = peer_manager.write().await;
                    if pm.get_peer(&a).is_none() {
                        pm.add_peer(a);
                        found.push(a);
                    }
                }
                self.seed_failures = 0;
            } else {
                self.seed_failures += 1;
                if self.seed_failures >= MAX_SEED_FAILURES {
                    break;
                }
            }
        }

        for seed in DNS_SEEDS {
            if let Ok(addrs) = seed.to_socket_addrs() {
                for a in addrs {
                    let mut pm = peer_manager.write().await;
                    if pm.get_peer(&a).is_none() {
                        pm.add_peer(a);
                        found.push(a);
                    }
                }
                self.seed_failures = 0;
            } else {
                self.seed_failures += 1;
                if self.seed_failures >= MAX_SEED_FAILURES {
                    break;
                }
            }
        }

        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_discovery() {
        let d = Discovery::new();
        assert_eq!(d.seed_failures, 0);
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
        assert_eq!(found, vec![a, b], "configured peers must be reported back");

        let guard = pm.read().await;
        assert!(guard.get_peer(&a).is_some());
        assert!(guard.get_peer(&b).is_some());
        drop(guard);

        // Already-known peers are not reported a second time.
        let again = d.discover_peers(pm.clone(), &[a, b]).await;
        assert!(again.is_empty());
    }
}
