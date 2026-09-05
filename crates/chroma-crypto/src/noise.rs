//! Noise Protocol Transport
//!
//! Node identity: ed25519 public key -> Node ID
//! Transport: Noise_XK_25519_ChaChaPoly_BLAKE2s
//!
//! This provides:
//! - Mutual authentication (both parties know each other's static keys)
//! - Forward secrecy (ephemeral key exchange)
//! - Encryption
//!
//! NOT an admission-control mechanism -- any node can join by generating
//! an identity and connecting.

use getrandom::getrandom;

/// Node identity (32-byte static key)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Generate a new random NodeId
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes).expect("CSPRNG failure");
        NodeId(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }
}

/// Noise handshake state (placeholder)
pub struct NoiseState {
    pub local_node_id: NodeId,
    pub peer_node_id: Option<NodeId>,
    // In production: full Noise_XK state
}

impl NoiseState {
    pub fn new(local_id: NodeId) -> Self {
        NoiseState {
            local_node_id: local_id,
            peer_node_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generation() {
        let id1 = NodeId::generate();
        let id2 = NodeId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_node_id_from_bytes() {
        let bytes = [0x42u8; 32];
        let id = NodeId::from_bytes(bytes);
        assert_eq!(id.0, bytes);
    }

    #[test]
    fn test_noise_state() {
        let id = NodeId::generate();
        let state = NoiseState::new(id);
        assert_eq!(state.local_node_id, id);
        assert!(state.peer_node_id.is_none());
    }
}