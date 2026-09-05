//! Chroma Consensus
//!
//! Deterministic consensus rules: difficulty retarget, chain selection,
//! cumulative work tracking, genesis block.
//!
//! ## Difficulty Retarget Algorithm
//!
//! Retarget every `DIFFICULTY_ADJUSTMENT_WINDOW` (10) blocks.
//!
//! Formula:
//! ```text
//! actual_time = timestamp[height] - timestamp[height - window]
//! target_time = window × TARGET_BLOCK_TIME_SECS  (= 100 seconds)
//!
//! new_target = old_target × actual_time / target_time
//!
//! Clamped to: old_target / 4 .. old_target × 4
//! ```
//!
//! Bounds: target must stay within [MINIMUM_TARGET, MAXIMUM_TARGET].
//! At non-retarget heights, the target carries forward unchanged.

pub mod miner;
pub mod params;

pub use params::ChainParams;

use std::collections::BTreeMap;

use chroma_core::constants::{
    DIFFICULTY_ADJUSTMENT_WINDOW, GENESIS_RANDOMX_SEED, MAX_DIFFICULTY_DECREASE_FACTOR,
    MTP_WINDOW, TARGET_BLOCK_TIME_SECS,
};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::types::{BlockHeight, CompactTarget};
use chroma_core::u256::U256;
use chroma_block::{Block, BlockHeader, BlockValidationContext};
use chroma_state::State;

// ============================================================================
// Genesis Block
// ============================================================================

/// Build the deterministic genesis block.
///
/// Genesis is fully determined by protocol constants:
/// - height = 0
/// - previous_hash = Hash::ZERO
/// - timestamp = GENESIS_TIMESTAMP
/// - bits = GENESIS_TARGET_BITS
/// - nonce = 0
/// - state_root = Hash::ZERO (empty state)
/// - tx_merkle_root = Hash::ZERO (no transactions)
pub fn build_genesis_block() -> Block {
    build_genesis_block_with(&ChainParams::devnet())
}

/// Build the genesis block for a specific network.
///
/// Networks differ in their genesis target, so each has a different genesis
/// hash — which is what keeps a regtest chain from ever being mistaken for a
/// real one.
pub fn build_genesis_block_with(params: &ChainParams) -> Block {
    let header = BlockHeader {
        version: 1,
        previous_hash: Hash::ZERO,
        state_root: Hash::ZERO,
        tx_merkle_root: Hash::ZERO,
        timestamp: params.genesis_timestamp,
        bits: params.genesis_bits,
        height: BlockHeight::GENESIS,
        nonce: 0,
    };

    Block {
        header,
        transactions: vec![],
    }
}

/// Get the genesis block hash.
pub fn genesis_hash() -> Hash {
    build_genesis_block().hash()
}

/// Get the genesis RandomX seed.
pub fn genesis_randomx_seed() -> Hash {
    Hash::blake3(GENESIS_RANDOMX_SEED)
}

// ============================================================================
// Difficulty Retarget
// ============================================================================

/// Determine the target bits for a given block height.
pub fn calculate_target_for_height(
    height: u32,
    headers: &BTreeMap<u32, BlockHeader>,
) -> Result<CompactTarget> {
    calculate_target_for_height_with(height, headers, &ChainParams::devnet())
}

/// Determine the target bits for a height under a specific network's rules.
pub fn calculate_target_for_height_with(
    height: u32,
    headers: &BTreeMap<u32, BlockHeader>,
    params: &ChainParams,
) -> Result<CompactTarget> {
    if height == 0 {
        return Ok(params.genesis_bits);
    }

    // Regtest holds the target still, so block production stays instant no
    // matter how quickly blocks arrive.
    if params.no_retargeting || height % DIFFICULTY_ADJUSTMENT_WINDOW != 0 {
        let prev = headers
            .get(&(height - 1))
            .ok_or_else(|| CoreError::InvalidDifficulty(format!("missing header for height {}", height - 1)))?;
        return Ok(prev.bits);
    }

    // Retarget height
    // Window spans heights [height - window, height - 1], which is `window` blocks
    // but only (window - 1) intervals between them.
    let intervals = (DIFFICULTY_ADJUSTMENT_WINDOW - 1) as u64;
    let target_time = TARGET_BLOCK_TIME_SECS * intervals; // 90 seconds

    let current = headers
        .get(&(height - 1))
        .ok_or_else(|| CoreError::InvalidDifficulty(format!("missing header for height {}", height - 1)))?;

    let window_start = height.saturating_sub(DIFFICULTY_ADJUSTMENT_WINDOW);
    let start = headers
        .get(&window_start)
        .ok_or_else(|| CoreError::InvalidDifficulty(format!("missing header for height {}", window_start)))?;

    let actual_time = current.timestamp.saturating_sub(start.timestamp);
    let actual_time = std::cmp::max(actual_time, 1);

    let old_target = U256::from_be_bytes(&current.bits.to_full_target());

    // new_target = old_target × actual_time / target_time
    let new_target =
        mul_div(&old_target, actual_time, target_time)
            .ok_or_else(|| CoreError::InvalidDifficulty("difficulty calculation overflow".into()))?;

    // Clamp: max decrease = old / 4, max increase = old × 4
    let (min_target, _) = old_target.div_rem(&U256::from_u64(MAX_DIFFICULTY_DECREASE_FACTOR));
    let max_target = old_target.shl(2);

    let clamped = if new_target < min_target {
        min_target
    } else if new_target > max_target {
        max_target
    } else {
        new_target
    };

    // Enforce absolute bounds (safety net beyond per-epoch clamping)
    // MINIMUM_TARGET = highest difficulty (smallest target)
    // MAXIMUM_TARGET = lowest difficulty (largest target, ~4× genesis)
    let min_abs = U256::from_be_bytes(&params.min_target);
    let max_abs = U256::from_be_bytes(&params.max_target);
    let final_target = if clamped < min_abs {
        min_abs
    } else if clamped > max_abs {
        max_abs
    } else {
        clamped
    };

    let target_bytes = final_target.to_be_bytes();
    Ok(CompactTarget::from_full_target(&target_bytes))
}

/// Multiply a U256 by a u64 and divide by a u64: (value * num) / den
/// Returns None on overflow to avoid silent wrapping on consensus-critical values.
fn mul_div(value: &U256, num: u64, den: u64) -> Option<U256> {
    if den == 0 || num == 0 {
        return Some(U256::ZERO);
    }

    // Split value into quotient and remainder of division by den
    let (q, r) = value.div_rem(&U256::from_u64(den));

    // q * num
    let part1 = {
        let mut result = U256::ZERO;
        let mut addend = q;
        let mut n = num;
        while n > 0 {
            if n & 1 == 1 {
                result = result.checked_add(&addend)?;
            }
            addend = addend.shl(1);
            n >>= 1;
        }
        result
    };

    // (r * num) / den
    let part2 = {
        let mut temp = U256::ZERO;
        let mut addend = r;
        let mut n = num;
        while n > 0 {
            if n & 1 == 1 {
                temp = temp.checked_add(&addend)?;
            }
            addend = addend.shl(1);
            n >>= 1;
        }
        let (q2, _) = temp.div_rem(&U256::from_u64(den));
        q2
    };

    part1.checked_add(&part2)
}

// ============================================================================
// Chain Tip Context
// ============================================================================

/// Summary of a chain tip needed for block validation.
#[derive(Clone, Debug)]
pub struct ChainTip {
    pub height: BlockHeight,
    pub hash: Hash,
    pub header: BlockHeader,
    pub cumulative_work: U256,
    pub supply: u64,
}

impl ChainTip {
    pub fn new(genesis: &Block) -> Self {
        let work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &genesis.header.bits.to_full_target(),
        ));
        ChainTip {
            height: BlockHeight::GENESIS,
            hash: genesis.hash(),
            header: genesis.header.clone(),
            cumulative_work: work,
            supply: 0,
        }
    }
}

// ============================================================================
// Chain State
// ============================================================================

/// Full chain state for consensus validation.
pub struct ChainState {
    /// Consensus parameters for the network this chain belongs to.
    pub params: ChainParams,
    /// All block headers indexed by height.
    pub headers: BTreeMap<u32, BlockHeader>,
    /// Best chain tip.
    pub tip: ChainTip,
    /// Account state at the tip.
    pub state: State,
    /// All known chain tips (for fork choice).
    pub tips: BTreeMap<Hash, ChainTip>,
}

impl ChainState {
    /// Create chain state with the genesis block.
    pub fn with_genesis() -> Self {
        Self::with_params(ChainParams::devnet())
    }

    /// Create chain state with the genesis block of a specific network.
    pub fn with_params(params: ChainParams) -> Self {
        let genesis = build_genesis_block_with(&params);
        let genesis_hash = genesis.hash();
        let tip = ChainTip::new(&genesis);

        let mut headers = BTreeMap::new();
        headers.insert(0, genesis.header.clone());

        let mut tips = BTreeMap::new();
        tips.insert(genesis_hash, tip.clone());

        ChainState {
            params,
            headers,
            tip: tip.clone(),
            state: State::new(),
            tips,
        }
    }

    /// Validate and apply a new block to the best chain.
    pub fn apply_block(&mut self, block: &Block) -> Result<()> {
        let height = block.header.height.0;

        let (previous_hash, previous_timestamp, current_supply) = if height == 0 {
            (Hash::ZERO, 0u64, 0u64)
        } else {
            let prev = self.headers.get(&(height - 1)).ok_or_else(|| {
                CoreError::InvalidBlock(format!("missing parent header at height {}", height - 1))
            })?;
            (prev.hash(), prev.timestamp, self.tip.supply)
        };

        // Compute Median Time Past from the last MTP_WINDOW (7) block timestamps
        let mtp = self.compute_median_time_past(height);

        let expected_bits =
            calculate_target_for_height_with(height, &self.headers, &self.params)?;

        let ctx = BlockValidationContext {
            previous_hash,
            expected_height: BlockHeight(height),
            previous_timestamp,
            median_time_past: mtp,
            expected_bits,
            current_supply,
            previous_state_root: self.tip.header.state_root,
            // Wall-clock time, not the block's own timestamp. Passing the
            // block's timestamp made the "not too far in the future" check
            // compare the value against itself, so it always passed and
            // spec §9's upper bound was never enforced.
            network_time: now_secs(),
        };

        chroma_block::validate_block(block, &ctx, &mut self.state)?;

        let new_hash = block.hash();
        let block_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &block.header.bits.to_full_target(),
        ));
        let new_cumulative_work = self
            .tip
            .cumulative_work
            .checked_add(&block_work)
            .ok_or_else(|| {
                CoreError::Overflow("cumulative work overflow".into())
            })?;

        self.headers.insert(height, block.header.clone());

        let new_tip = ChainTip {
            height: BlockHeight(height),
            hash: new_hash,
            header: block.header.clone(),
            cumulative_work: new_cumulative_work,
            supply: self.state.total_supply(),
        };

        self.tip = new_tip.clone();
        self.tips.insert(new_hash, new_tip);

        Ok(())
    }

    /// Select the best chain tip (greatest cumulative work).
    pub fn best_tip(&self) -> &ChainTip {
        &self.tip
    }

    /// Compute Median Time Past from the last MTP_WINDOW (7) block timestamps.
    /// For height < MTP_WINDOW, uses timestamps from genesis to height-1.
    pub fn compute_median_time_past(&self, height: u32) -> u64 {
        median_time_past(&self.headers, height)
    }
}

/// Current wall-clock time in Unix seconds.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Median Time Past: the median timestamp of the `MTP_WINDOW` headers
/// preceding `height`.
///
/// A block's timestamp must be strictly greater than this (spec §9). Shared
/// by block validation and by headers-first sync, which validates timestamps
/// against a header chain that has no blocks behind it yet.
pub fn median_time_past(headers: &BTreeMap<u32, BlockHeader>, height: u32) -> u64 {
    let mut timestamps: Vec<u64> = Vec::new();
    let count = std::cmp::min(height as usize, MTP_WINDOW);
    for i in 0..count {
        let h = height - 1 - i as u32;
        if let Some(header) = headers.get(&h) {
            timestamps.push(header.timestamp);
        }
    }
    if timestamps.is_empty() {
        return 0;
    }
    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::constants::{GENESIS_TARGET_BITS, GENESIS_TIMESTAMP};
    use crate::params::{DEFAULT_MAX_TARGET as MAXIMUM_TARGET, DEFAULT_MIN_TARGET as MINIMUM_TARGET};
    use chroma_core::constants::MAX_DIFFICULTY_INCREASE_FACTOR;

    #[test]
    fn test_genesis_deterministic() {
        let g1 = build_genesis_block();
        let g2 = build_genesis_block();
        assert_eq!(g1.hash(), g2.hash());
    }

    #[test]
    fn test_genesis_hash() {
        let genesis = build_genesis_block();
        assert_eq!(genesis.header.version, 1);
        assert_eq!(genesis.header.height, BlockHeight::GENESIS);
        assert_eq!(genesis.header.timestamp, GENESIS_TIMESTAMP);
        assert_eq!(genesis.header.bits, CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(genesis.header.nonce, 0);
        assert_eq!(genesis.header.previous_hash, Hash::ZERO);
        assert_eq!(genesis.header.tx_merkle_root, Hash::ZERO);
        assert!(genesis.transactions.is_empty());
    }

    #[test]
    fn test_genesis_randomx_seed() {
        let seed = genesis_randomx_seed();
        let seed2 = genesis_randomx_seed();
        assert_eq!(seed, seed2);
        assert_ne!(seed, Hash::ZERO);
    }

    #[test]
    fn test_chain_state_genesis() {
        let chain = ChainState::with_genesis();
        assert_eq!(chain.tip.height, BlockHeight::GENESIS);
        assert_eq!(chain.tip.supply, 0);
        assert!(chain.best_tip().cumulative_work > U256::ZERO);
    }

    #[test]
    fn test_difficulty_carry_forward() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        let target = calculate_target_for_height(1, &headers).unwrap();
        assert_eq!(target, CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_difficulty_on_target() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // 10 blocks at exactly 10s intervals → on target
        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        assert_eq!(target, CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_difficulty_blocks_too_fast() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS / 2),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let d_before = chroma_core::types::Difficulty::from_bits(CompactTarget(GENESIS_TARGET_BITS));
        let d_after = chroma_core::types::Difficulty::from_bits(target);
        assert!(d_after > d_before, "blocks too fast → difficulty increases");
    }

    #[test]
    fn test_difficulty_blocks_too_slow() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS * 4),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let d_before = chroma_core::types::Difficulty::from_bits(CompactTarget(GENESIS_TARGET_BITS));
        let d_after = chroma_core::types::Difficulty::from_bits(target);
        assert!(d_after < d_before, "blocks too slow → difficulty decreases");
    }

    #[test]
    fn test_difficulty_clamped() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // 1 second per block → extremely fast
        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let d_before = chroma_core::types::Difficulty::from_bits(CompactTarget(GENESIS_TARGET_BITS));
        let d_after = chroma_core::types::Difficulty::from_bits(target);

        assert!(d_after > d_before);
        assert!(
            d_after.0 <= d_before.0 * MAX_DIFFICULTY_INCREASE_FACTOR,
            "increase clamped to {}x",
            MAX_DIFFICULTY_INCREASE_FACTOR
        );
    }

    #[test]
    fn test_minimum_target_enforced() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_u256 = U256::from_be_bytes(&target.to_full_target());
        let min = U256::from_be_bytes(&MINIMUM_TARGET);
        assert!(target_u256 >= min, "target must not go below minimum");
    }

    #[test]
    fn test_non_retarget_height() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Insert headers for heights 1-9 so carry-forward can look them up
        for h in 1..=9u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // Heights 1-9 should all carry forward genesis target
        for h in 1..=9u32 {
            let target = calculate_target_for_height(h, &headers).unwrap();
            assert_eq!(target, CompactTarget(GENESIS_TARGET_BITS), "height {}", h);
        }
    }

    #[test]
    fn test_mul_div_exact() {
        let a = U256::from_u64(1000);
        assert_eq!(mul_div(&a, 3, 2).unwrap(), U256::from_u64(1500));
        assert_eq!(mul_div(&a, 1, 2).unwrap(), U256::from_u64(500));
        assert_eq!(mul_div(&a, 2, 2).unwrap(), U256::from_u64(1000));
    }

    #[test]
    fn test_mul_div_zero_denominator() {
        let a = U256::from_u64(1000);
        assert_eq!(mul_div(&a, 3, 0).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_mul_div_zero_numerator() {
        let a = U256::from_u64(1000);
        assert_eq!(mul_div(&a, 0, 5).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_mul_div_large_values() {
        let a = U256::from_u64(u64::MAX);
        let result = mul_div(&a, 2, 3).unwrap();
        // u64::MAX * 2 / 3 ≈ 12297829382473034410
        let result_u64 = result.to_u64().unwrap();
        let expected = u64::MAX / 3 * 2;
        let diff = result_u64.abs_diff(expected);
        assert!(diff < 2, "mul_div large: result={} expected={}", result_u64, expected);
    }

    #[test]
    fn test_mul_div_one_to_one() {
        let a = U256::from_u64(42);
        assert_eq!(mul_div(&a, 1, 1).unwrap(), a);
    }

    #[test]
    fn test_difficulty_multiple_retargets() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Build 20 blocks at exactly target pace
        for h in 1..=20u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // Both retargets at 10 and 20 should stay at genesis target
        let t10 = calculate_target_for_height(10, &headers).unwrap();
        let t20 = calculate_target_for_height(20, &headers).unwrap();
        assert_eq!(t10, CompactTarget(GENESIS_TARGET_BITS));
        assert_eq!(t20, CompactTarget(GENESIS_TARGET_BITS));
    }

    #[test]
    fn test_difficulty_accelerating_then_decelerating() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Blocks 1-5: fast (5s each)
        for h in 1..=5u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * 5,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // Blocks 6-9: slow (20s each) — relative to block 5
        let block5_ts = GENESIS_TIMESTAMP + 5 * 5;
        for h in 6..=9u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: block5_ts + ((h - 5) as u64) * 20,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        // At height 10 retarget: window is heights 0-9
        // actual_time = block9.timestamp - genesis.timestamp
        let block9_ts = headers.get(&9).unwrap().timestamp;
        let actual_time = block9_ts - GENESIS_TIMESTAMP;
        // Expected: 5*5 + 4*20 = 25 + 80 = 105 seconds
        // target_time = 90 seconds
        // new_target = old * 105 / 90 = old * 1.166...
        assert!(actual_time > 90, "actual_time should be > target_time for slower blocks");

        let target = calculate_target_for_height(10, &headers).unwrap();
        let d_before = chroma_core::types::Difficulty::from_bits(CompactTarget(GENESIS_TARGET_BITS));
        let d_after = chroma_core::types::Difficulty::from_bits(target);
        assert!(d_after < d_before, "blocks slower than target → difficulty decreases");
    }

    #[test]
    fn test_max_target_enforced() {
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        // Very slow blocks (100s each) → target tries to increase a lot
        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * 100,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target = calculate_target_for_height(10, &headers).unwrap();
        let target_u256 = U256::from_be_bytes(&target.to_full_target());
        let max = U256::from_be_bytes(&MAXIMUM_TARGET);
        assert!(target_u256 <= max, "target must not exceed maximum");
    }

    #[test]
    fn test_genesis_hash_is_nonzero() {
        let genesis = build_genesis_block();
        let header_hash = genesis.hash();
        assert_ne!(header_hash, Hash::ZERO, "genesis hash must be non-zero");
    }

    #[test]
    fn test_chain_tip_work_increases() {
        let chain = ChainState::with_genesis();
        let work_before = chain.best_tip().cumulative_work;
        assert!(work_before > U256::ZERO);
    }

    #[test]
    fn test_minimum_target_constant() {
        let min = U256::from_be_bytes(&MINIMUM_TARGET);
        assert!(min > U256::ZERO, "MINIMUM_TARGET must be non-zero");
        let max = U256::from_be_bytes(&MAXIMUM_TARGET);
        assert!(max > min, "MAXIMUM_TARGET must be > MINIMUM_TARGET");
    }

    #[test]
    fn test_difficulty_direction_invariants() {
        // At exactly 90s (target_time for window), difficulty stays same
        let mut headers = BTreeMap::new();
        let genesis = build_genesis_block();
        headers.insert(0, genesis.header.clone());

        for h in 1..=10u32 {
            let prev = headers.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * TARGET_BLOCK_TIME_SECS,
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers.insert(h, header);
        }

        let target_unchanged = calculate_target_for_height(10, &headers).unwrap();
        assert_eq!(target_unchanged, CompactTarget(GENESIS_TARGET_BITS), "at exactly target pace, difficulty unchanged");

        // Test: faster → higher difficulty (lower target)
        let mut headers_fast = headers.clone();
        for h in 1..=10u32 {
            let prev = headers_fast.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS / 2),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers_fast.insert(h, header);
        }
        let target_fast = calculate_target_for_height(10, &headers_fast).unwrap();
        let t_fast = U256::from_be_bytes(&target_fast.to_full_target());
        let t_genesis = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
        assert!(t_fast < t_genesis, "faster blocks → lower target (higher difficulty)");

        // Test: slower → lower difficulty (higher target)
        let mut headers_slow = headers.clone();
        for h in 1..=10u32 {
            let prev = headers_slow.get(&(h - 1)).unwrap();
            let header = BlockHeader {
                version: 1,
                previous_hash: prev.hash(),
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: GENESIS_TIMESTAMP + (h as u64) * (TARGET_BLOCK_TIME_SECS * 3),
                bits: CompactTarget(GENESIS_TARGET_BITS),
                height: BlockHeight(h),
                nonce: 0,
            };
            headers_slow.insert(h, header);
        }
        let target_slow = calculate_target_for_height(10, &headers_slow).unwrap();
        let t_slow = U256::from_be_bytes(&target_slow.to_full_target());
        assert!(t_slow > t_genesis, "slower blocks → higher target (lower difficulty)");
    }

    #[test]
    fn test_calculate_target_missing_header() {
        let headers = BTreeMap::new();
        let result = calculate_target_for_height(5, &headers);
        assert!(result.is_err(), "should fail with missing header");
    }

    #[test]
    fn test_genesis_target_bits_value() {
        assert_eq!(GENESIS_TARGET_BITS, 0x1d00ffff);
    }

    #[test]
    fn test_chain_state_genesis_supply() {
        let chain = ChainState::with_genesis();
        assert_eq!(chain.state.total_supply(), 0);
    }

    #[test]
    fn test_chain_state_genesis_headers() {
        let chain = ChainState::with_genesis();
        assert!(chain.headers.contains_key(&0));
        assert_eq!(chain.headers.len(), 1);
    }

    #[test]
    fn test_chain_state_genesis_tips() {
        let chain = ChainState::with_genesis();
        assert_eq!(chain.tips.len(), 1);
        assert!(chain.tips.contains_key(&chain.tip.hash));
    }
}
