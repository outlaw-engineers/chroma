//! Per-network consensus parameters.
//!
//! Everything that differs between networks lives here rather than being read
//! from global constants, so that a regression-test network can exist
//! alongside the real ones without any consensus code branching on a mode
//! flag.

use chroma_core::constants::{GENESIS_TARGET_BITS, GENESIS_TIMESTAMP};
use chroma_core::types::{CompactTarget, NetworkId};

/// Hardest target the retarget algorithm may produce (smallest value).
pub const DEFAULT_MIN_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[10] = 0xFF;
    t[11] = 0xFF;
    t
};

/// Easiest target the retarget algorithm may produce (largest value).
/// About 4× the genesis target, which is one full downward adjustment.
pub const DEFAULT_MAX_TARGET: [u8; 32] = {
    let mut t = [0u8; 32];
    t[3] = 0x03;
    t[4] = 0xFF;
    t[5] = 0xFF;
    t[6] = 0xC0;
    t
};

/// Regtest proof-of-work target. About half of all hashes satisfy it, so a
/// nonce search finds a solution in a couple of attempts and block production
/// is effectively free.
pub const REGTEST_GENESIS_BITS: u32 = 0x207fffff;

/// Consensus parameters for one network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    pub network: NetworkId,
    /// Target the genesis block declares, and the floor for difficulty.
    pub genesis_bits: CompactTarget,
    pub genesis_timestamp: u64,
    /// Hardest permitted target (smallest value).
    pub min_target: [u8; 32],
    /// Easiest permitted target (largest value).
    pub max_target: [u8; 32],
    /// Hold the target fixed instead of retargeting every window. Used by
    /// regtest so that block production stays instant and deterministic no
    /// matter how fast blocks are produced.
    pub no_retargeting: bool,
}

impl ChainParams {
    pub const fn mainnet() -> Self {
        ChainParams {
            network: NetworkId::Mainnet,
            genesis_bits: CompactTarget(GENESIS_TARGET_BITS),
            genesis_timestamp: GENESIS_TIMESTAMP,
            min_target: DEFAULT_MIN_TARGET,
            max_target: DEFAULT_MAX_TARGET,
            no_retargeting: false,
        }
    }

    pub const fn testnet() -> Self {
        ChainParams {
            network: NetworkId::Testnet,
            ..Self::mainnet()
        }
    }

    pub const fn devnet() -> Self {
        ChainParams {
            network: NetworkId::Devnet,
            ..Self::mainnet()
        }
    }

    /// Local regression-test network.
    ///
    /// Genesis difficulty 1 needs on the order of 2^32 hashes per block, which
    /// no single node can sustain against a 10-second target. Regtest drops
    /// the target to one that almost any nonce satisfies and freezes it, so
    /// tests and local development can mine real, fully validated blocks
    /// immediately.
    pub const fn regtest() -> Self {
        ChainParams {
            network: NetworkId::Regtest,
            genesis_bits: CompactTarget(REGTEST_GENESIS_BITS),
            genesis_timestamp: GENESIS_TIMESTAMP,
            min_target: DEFAULT_MIN_TARGET,
            // The genesis target is already the easiest one allowed.
            max_target: [0xFF; 32],
            no_retargeting: true,
        }
    }

    pub fn for_network(network: NetworkId) -> Self {
        match network {
            NetworkId::Mainnet => Self::mainnet(),
            NetworkId::Testnet => Self::testnet(),
            NetworkId::Regtest => Self::regtest(),
            NetworkId::Devnet | NetworkId::Unknown => Self::devnet(),
        }
    }

    /// Parse a network name as accepted on the command line.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "mainnet" => Some(Self::mainnet()),
            "testnet" => Some(Self::testnet()),
            "devnet" => Some(Self::devnet()),
            "regtest" => Some(Self::regtest()),
            _ => None,
        }
    }
}

impl Default for ChainParams {
    fn default() -> Self {
        Self::devnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::hash::Hash;

    #[test]
    fn test_parse_names() {
        assert_eq!(ChainParams::parse("regtest"), Some(ChainParams::regtest()));
        assert_eq!(ChainParams::parse("REGTEST"), Some(ChainParams::regtest()));
        assert_eq!(ChainParams::parse("devnet"), Some(ChainParams::devnet()));
        assert_eq!(ChainParams::parse("mainnet"), Some(ChainParams::mainnet()));
        assert!(ChainParams::parse("nonsense").is_none());
    }

    #[test]
    fn test_regtest_target_is_trivially_reachable() {
        // The point of regtest is that a solution is always a handful of
        // nonces away, so block production costs nothing. The target admits
        // roughly half of all hashes, so 64 attempts failing would mean
        // something is badly wrong rather than being bad luck.
        let target = ChainParams::regtest().genesis_bits.to_full_target();
        let hits = (0..64u32)
            .filter(|n| {
                let hash = Hash::blake3(&n.to_le_bytes());
                chroma_crypto::randomx::hash_meets_target(&hash, &target)
            })
            .count();
        assert!(
            hits > 16,
            "regtest target admitted only {}/64 hashes; mining would not be trivial",
            hits
        );
    }

    #[test]
    fn test_regtest_target_is_far_easier_than_the_real_one() {
        use chroma_core::u256::U256;
        let regtest = U256::from_be_bytes(&ChainParams::regtest().genesis_bits.to_full_target());
        let devnet = U256::from_be_bytes(&ChainParams::devnet().genesis_bits.to_full_target());
        assert!(regtest > devnet, "a larger target is an easier one");
    }

    #[test]
    fn test_real_networks_keep_difficulty_one() {
        for params in [
            ChainParams::mainnet(),
            ChainParams::testnet(),
            ChainParams::devnet(),
        ] {
            assert_eq!(params.genesis_bits, CompactTarget(GENESIS_TARGET_BITS));
            assert!(!params.no_retargeting, "only regtest freezes difficulty");
        }
    }

    #[test]
    fn test_networks_have_distinct_ids() {
        use chroma_core::serialize::CanonicalEncode;
        let encodings: Vec<Vec<u8>> = [
            NetworkId::Devnet,
            NetworkId::Testnet,
            NetworkId::Mainnet,
            NetworkId::Regtest,
        ]
        .iter()
        .map(|n| n.encode())
        .collect();
        let mut unique = encodings.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), encodings.len(), "network ids must not collide");
    }
}
