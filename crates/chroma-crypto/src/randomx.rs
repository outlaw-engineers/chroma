//! RandomX Proof of Work
//!
//! RandomX is a CPU-oriented proof-of-work algorithm.
//! For Chroma v1 (devnet), we use a placeholder PoW:
//! BLAKE3 hash with difficulty target.
//!
//! The full RandomX integration will be done via FFI binding to the
//! reference RandomX implementation (monero-project/rust-randomx or similar).
//!
//! Security properties (from spec v0.1):
//! - Seed: H(block at height epoch_start - 100)
//! - Epoch: 1000 blocks (~2h 47min)
//! - Seed lag: 100 blocks (mitigates grinding)
//! - VM cache: ~2 GB RAM, init 1-2s, amortized over epoch

use chroma_core::{Hash, blake3};
use crate::error::{CryptoError, CryptoResult as Result};

/// RandomX PoW result
/// In production: 32-byte hash, compared against target
pub struct PowResult {
    pub hash: Hash,
}

/// Placeholder PoW: BLAKE3 hashing for devnet
/// This will be replaced with RandomX FFI in the full implementation
pub fn pow_blake3(prev_hash: &Hash, merkle_root: &Hash, nonce: u64, extra_nonce: &[u8]) -> Hash {
    let mut data = Vec::with_capacity(80);
    data.extend_from_slice(prev_hash.as_bytes());
    data.extend_from_slice(merkle_root.as_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(extra_nonce);
    blake3(&data)
}

/// Check if a hash meets the target
/// target is a 256-bit value (big-endian, lower = harder)
/// Returns true if hash_as_uint256 <= target_as_uint256
pub fn hash_meets_target(hash: &Hash, target: &[u8; 32]) -> bool {
    // Compare as big-endian integers: hash <= target
    // Scan from most significant byte (index 0) to least significant (index 31)
    for i in 0..32 {
        if hash.0[i] < target[i] {
            return true;  // hash is smaller at this byte position
        }
        if hash.0[i] > target[i] {
            return false; // hash is larger at this byte position
        }
    }
    true // all bytes equal: hash == target, which meets the target
}

/// Calculate cumulative work: 2^256 / target
/// Returns the work as a 256-bit value (for comparison)
pub fn calculate_work(target: &[u8; 32]) -> [u8; 32] {
    use chroma_core::u256::U256;

    let target_u256 = U256::from_be_bytes(target);
    if target_u256.is_zero() {
        return U256::MAX.to_be_bytes();
    }

    // work = (2^256 - 1) / target + 1
    let max = U256::MAX;
    let (q, _r) = max.div_rem(&target_u256);
    let work = q.wrapping_add(&U256::ONE);
    work.to_be_bytes()
}

/// RandomX seed derivation
/// seed = H(block_hash_at_height(epoch_start - SEED_LAG))
pub fn derive_seed(block_hash: &Hash) -> Hash {
    *block_hash
}

/// Epoch calculation: height / EPOCH_LENGTH
pub fn epoch_for_height(height: u32, epoch_length: u32) -> u32 {
    height / epoch_length
}

/// Check if we're at a seed update point (epoch boundary)
pub fn is_seed_update_height(height: u32, epoch_length: u32) -> bool {
    height % epoch_length == 0
}

/// Placeholder initialization for RandomX VM
pub fn init_randomx_context(_seed: &Hash) -> Result<()> {
    Err(CryptoError::RandomX("not implemented in devnet".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::Hash;

    #[test]
    fn test_pow_blake3() {
        let prev_hash = Hash::from_bytes([0x42u8; 32]);
        let merkle_root = Hash::from_bytes([0x24u8; 32]);
        let nonce = 12345u64;
        let extra = b"test";

        let result = pow_blake3(&prev_hash, &merkle_root, nonce, extra);
        assert_eq!(result.as_bytes().len(), 32);

        let result2 = pow_blake3(&prev_hash, &merkle_root, nonce, extra);
        assert_eq!(result, result2);

        let result3 = pow_blake3(&prev_hash, &merkle_root, nonce + 1, extra);
        assert_ne!(result, result3);
    }

    #[test]
    fn test_hash_meets_target() {
        // Basic: hash below target
        let hash = Hash::from_bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]);

        let target = [0xFFu8; 32];
        assert!(hash_meets_target(&hash, &target));

        // All zeros target: only zero hash passes
        let target_low = [0x00u8; 32];
        assert!(!hash_meets_target(&hash, &target_low));

        // Zero hash meets any target
        let zero_hash = Hash::from_bytes([0u8; 32]);
        assert!(hash_meets_target(&zero_hash, &target_low));
        assert!(hash_meets_target(&zero_hash, &target));

        // Hash exactly equal to target
        let exact_target = [0x42u8; 32];
        let exact_hash = Hash::from_bytes([0x42u8; 32]);
        assert!(hash_meets_target(&exact_hash, &exact_target));

        // Hash one above target (should fail)
        let mut target_bytes = [0u8; 32];
        target_bytes[31] = 0x41; // target = ...0x41
        let mut hash_bytes = [0u8; 32];
        hash_bytes[31] = 0x42; // hash = ...0x42
        let hash_above = Hash::from_bytes(hash_bytes);
        assert!(!hash_meets_target(&hash_above, &target_bytes));

        // Hash one below target (should pass)
        let mut target_bytes2 = [0u8; 32];
        target_bytes2[31] = 0x42;
        let mut hash_bytes2 = [0u8; 32];
        hash_bytes2[31] = 0x41;
        let hash_below = Hash::from_bytes(hash_bytes2);
        assert!(hash_meets_target(&hash_below, &target_bytes2));

        // Differing high-order bytes
        let mut target_ho = [0u8; 32];
        target_ho[0] = 0x02;
        let mut hash_ho = [0u8; 32];
        hash_ho[0] = 0x01;
        let hash_high_order = Hash::from_bytes(hash_ho);
        assert!(hash_meets_target(&hash_high_order, &target_ho));

        // Hash higher at high-order byte (should fail)
        let mut hash_ho2 = [0u8; 32];
        hash_ho2[0] = 0x03;
        let hash_high_order_fail = Hash::from_bytes(hash_ho2);
        assert!(!hash_meets_target(&hash_high_order_fail, &target_ho));

        // Maximum hash vs maximum target
        let max_hash = Hash::from_bytes([0xFFu8; 32]);
        let max_target = [0xFFu8; 32];
        assert!(hash_meets_target(&max_hash, &max_target));

        // The specific bug case from the handoff:
        // hash = [0x01, 0xFF, ...], target = [0x02, 0x00, ...]
        // Old code: 0x01<=0x02 (true), 0xFF<=0x00 (false) -> false (WRONG)
        // Correct: 0x01<0x02 -> true (hash is smaller)
        let mut bug_hash_bytes = [0u8; 32];
        bug_hash_bytes[0] = 0x01;
        bug_hash_bytes[1] = 0xFF;
        let bug_hash = Hash::from_bytes(bug_hash_bytes);
        let mut bug_target = [0u8; 32];
        bug_target[0] = 0x02;
        bug_target[1] = 0x00;
        assert!(hash_meets_target(&bug_hash, &bug_target));
    }

    #[test]
    fn test_epoch_calculation() {
        assert_eq!(epoch_for_height(0, 1000), 0);
        assert_eq!(epoch_for_height(999, 1000), 0);
        assert_eq!(epoch_for_height(1000, 1000), 1);
        assert_eq!(epoch_for_height(1999, 1000), 1);
        assert_eq!(epoch_for_height(2000, 1000), 2);
    }

    #[test]
    fn test_seed_update_check() {
        assert!(is_seed_update_height(0, 1000));
        assert!(!is_seed_update_height(999, 1000));
        assert!(is_seed_update_height(1000, 1000));
        assert!(is_seed_update_height(2000, 1000));
    }

    #[test]
    fn test_derive_seed() {
        let block_hash = Hash::from_bytes([0xABu8; 32]);
        let seed = derive_seed(&block_hash);
        assert_eq!(seed, block_hash);
    }

    #[test]
    fn test_calculate_work() {
        use chroma_core::u256::U256;

        // Target = 0xFF...FF (max): work should be ~1
        let max_target = [0xFFu8; 32];
        let work = calculate_work(&max_target);
        let work_u256 = U256::from_be_bytes(&work);
        // (2^256 - 1) / (2^256 - 1) + 1 = 1 + 1 = 2
        assert_eq!(work_u256, U256::from_u64(2));

        // Target = 1: work should be 2^256 - 1 + 1 = 2^256... which wraps to 0
        let one_target = {
            let mut t = [0u8; 32];
            t[31] = 1;
            t
        };
        let work2 = calculate_work(&one_target);
        let work2_u256 = U256::from_be_bytes(&work2);
        // (2^256 - 1) / 1 + 1 = 2^256, which wraps to 0
        assert_eq!(work2_u256, U256::ZERO);

        // Target = 2: work = (2^256 - 1) / 2 + 1
        let two_target = {
            let mut t = [0u8; 32];
            t[31] = 2;
            t
        };
        let work3 = calculate_work(&two_target);
        let work3_u256 = U256::from_be_bytes(&work3);
        // (2^256 - 1) / 2 = 2^255 - 1 (all ones except MSB), +1 = 2^255
        let expected = U256::from_u64(0).with_bit_set(255);
        assert_eq!(work3_u256, expected, "target=2 should produce work = 2^255");

        // Same target should give same work (determinism)
        let work_again = calculate_work(&max_target);
        assert_eq!(work, work_again);

        // Larger target should produce smaller work
        let mut large_target = [0xFFu8; 32];
        large_target[0] = 0xFE; // slightly less than MAX
        let work_large = calculate_work(&large_target);
        let work_large_u256 = U256::from_be_bytes(&work_large);
        assert!(work_large_u256 < U256::from_u64(4), "larger target = smaller work");

        // Smaller target should produce larger work
        let mut small_target = [0u8; 32];
        small_target[0] = 0x01;
        let work_small = calculate_work(&small_target);
        let work_small_u256 = U256::from_be_bytes(&work_small);
        assert!(work_small_u256 > U256::from_u64(4), "smaller target = larger work");
    }

    #[test]
    fn test_hash_meets_target_transitivity() {
        // If hash_a <= target and hash_b <= hash_a, then hash_b <= target
        let target = [0x80u8; 32];
        let hash_a_bytes = [0x40u8; 32];
        let hash_b_bytes = [0x20u8; 32];
        let hash_a = Hash::from_bytes(hash_a_bytes);
        let hash_b = Hash::from_bytes(hash_b_bytes);
        assert!(hash_meets_target(&hash_a, &target));
        assert!(hash_meets_target(&hash_b, &target));
        assert!(hash_meets_target(&hash_b, &hash_a.0));
    }

    #[test]
    fn test_hash_meets_target_boundary_values() {
        // All boundary cases for single-byte comparison
        let cases: Vec<([u8; 32], [u8; 32], bool)> = vec![
            ([0x00u8; 32], [0x01u8; 32], true),   // hash < target
            ([0x01u8; 32], [0x00u8; 32], false),   // hash > target
            ([0x42u8; 32], [0x42u8; 32], true),     // hash == target
            ([0xFFu8; 32], [0xFFu8; 32], true),     // hash == target (max)
            ([0x00u8; 32], [0x00u8; 32], true),     // hash == target (zero)
        ];
        for (hash_bytes, target, expected) in cases {
            let hash = Hash::from_bytes(hash_bytes);
            assert_eq!(hash_meets_target(&hash, &target), expected,
                "hash={:?} target={:?}", hash_bytes[0], target[0]);
        }
    }

    #[test]
    fn test_calculate_work_target_1_is_max() {
        use chroma_core::u256::U256;
        let target_1 = {
            let mut t = [0u8; 32];
            t[31] = 1;
            t
        };
        let work = calculate_work(&target_1);
        // When target=1, work wraps to 0 (2^256 wraps)
        let work_u256 = U256::from_be_bytes(&work);
        assert_eq!(work_u256, U256::ZERO, "target=1 should produce work 0 (wrapped from 2^256)");
    }

    #[test]
    fn test_pow_blake3_different_nonces() {
        let prev = Hash::from_bytes([0x01u8; 32]);
        let merkle = Hash::from_bytes([0x02u8; 32]);
        let mut results = std::collections::HashSet::new();
        for nonce in 0..100u64 {
            let h = pow_blake3(&prev, &merkle, nonce, b"");
            assert!(results.insert(h), "duplicate hash at nonce {}", nonce);
        }
    }

    #[test]
    fn test_pow_blake3_empty_extra() {
        let prev = Hash::from_bytes([0xAAu8; 32]);
        let merkle = Hash::from_bytes([0xBBu8; 32]);
        let h1 = pow_blake3(&prev, &merkle, 0, b"");
        let h2 = pow_blake3(&prev, &merkle, 0, &[]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_epoch_boundaries() {
        // Epoch 0: heights 0-999
        for h in 0..1000u32 {
            assert_eq!(epoch_for_height(h, 1000), 0);
        }
        // Epoch 1: heights 1000-1999
        for h in 1000..2000u32 {
            assert_eq!(epoch_for_height(h, 1000), 1);
        }
    }

    #[test]
    fn test_seed_update_at_exact_boundaries() {
        assert!(is_seed_update_height(0, 1000));
        assert!(!is_seed_update_height(1, 1000));
        assert!(is_seed_update_height(1000, 1000));
        assert!(!is_seed_update_height(1001, 1000));
        assert!(is_seed_update_height(2000, 1000));
    }

    #[test]
    fn test_init_randomx_context_returns_error() {
        let seed = Hash::from_bytes([0u8; 32]);
        assert!(init_randomx_context(&seed).is_err());
    }
}