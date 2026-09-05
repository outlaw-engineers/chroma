//! Block Assembly and Mining
//!
//! Assembles blocks from the mempool, creates coinbase transactions,
//! and performs Proof-of-Work (BLAKE3 placeholder for devnet).

use chroma_core::constants::{
    BLOCK_REWARD_UNITS, MAX_FUTURE_TIMESTAMP_OFFSET,
};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::types::{Amount, BlockHeight, CompactTarget};
use chroma_block::{Block, BlockHeader};
use chroma_tx::Transaction;

/// Maximum number of transactions to include in a block.
const MAX_BLOCK_TXS: usize = 10_000;

/// Choose a timestamp for the next block.
///
/// Validation demands `median_time_past < timestamp <= now + 20`. Pacing the
/// chain by stamping `parent + target_block_time` breaks the upper bound as
/// soon as blocks are found faster than the target — on regtest that is
/// immediately, and the miner then spends its time producing blocks its own
/// validation rejects. Wall-clock time is the right value; the median only
/// sets a floor.
pub fn next_block_timestamp(now: u64, median_time_past: u64) -> u64 {
    std::cmp::max(now, median_time_past.saturating_add(1))
}

/// Whether `timestamp` is still acceptable to validation at time `now`.
pub fn timestamp_is_valid(timestamp: u64, now: u64, median_time_past: u64) -> bool {
    timestamp > median_time_past
        && timestamp <= now.saturating_add(MAX_FUTURE_TIMESTAMP_OFFSET as u64)
}

/// Block assembly context needed for mining.
pub struct BlockAssemblyContext {
    pub height: BlockHeight,
    pub previous_hash: Hash,
    /// Timestamp to stamp on the block.
    ///
    /// The caller must pick one that validation will accept: strictly after
    /// the median time past, and no more than
    /// `MAX_FUTURE_TIMESTAMP_OFFSET` ahead of wall-clock time. See
    /// [`next_block_timestamp`].
    pub timestamp: u64,
    pub bits: CompactTarget,
    pub coinbase_recipient: chroma_core::types::Address,
}

/// Assemble a new block from mempool transactions.
///
/// Creates the coinbase, selects transactions that actually apply on top of
/// `parent_state`, and records the resulting state root in the header. Does
/// NOT perform mining (nonce search) — the caller must do that.
///
/// The header must carry the state root *after* the block is applied, because
/// that is what validation recomputes and compares against. Filling it with
/// the parent's root — which is what the assembly context used to supply —
/// makes every block fail validation at its own state-root check, since the
/// coinbase subsidy alone always changes the state.
pub fn assemble_block(
    ctx: &BlockAssemblyContext,
    mempool_txs: &[Transaction],
    parent_state: &chroma_state::State,
) -> Result<Block> {
    let coinbase = Transaction::coinbase(ctx.coinbase_recipient, Amount(BLOCK_REWARD_UNITS));

    // Apply to a scratch copy in the same order validation will, so the root
    // we publish is the one a validator arrives at.
    let mut working = parent_state.clone();
    working.apply_subsidy(&ctx.coinbase_recipient, ctx.height.0)?;

    let mut transactions = Vec::with_capacity(1 + mempool_txs.len());
    transactions.push(coinbase);

    let budget = MAX_BLOCK_TXS.saturating_sub(1);
    for tx in mempool_txs.iter().take(budget) {
        if tx.is_coinbase() || !tx.verify_signature() {
            continue;
        }
        // A transaction that does not apply here (stale nonce, spent balance)
        // would make the whole block invalid, so it is left out rather than
        // included and hoped for.
        if working
            .apply_transaction(&tx.sender_address(), &tx.recipient, tx.amount.0, tx.nonce.0)
            .is_err()
        {
            continue;
        }
        transactions.push(tx.clone());
    }

    let tx_merkle_root = Block::compute_tx_merkle_root(&transactions);

    let header = BlockHeader {
        version: 1,
        previous_hash: ctx.previous_hash,
        state_root: working.compute_state_root(),
        tx_merkle_root,
        timestamp: ctx.timestamp,
        bits: ctx.bits,
        height: ctx.height,
        nonce: 0,
    };

    Ok(Block {
        header,
        transactions,
    })
}

/// Mine a block by searching for a valid nonce.
///
/// Iterates the nonce field of the block header until the hash meets the target.
/// Returns the block with a valid nonce, or an error if no solution found within
/// the search space.
///
/// For devnet (BLAKE3 placeholder): expects to find a solution relatively quickly
/// with the default difficulty target.
pub fn mine_block(block: &mut Block) -> Result<()> {
    let target = block.header.bits.to_full_target();

    for nonce in 0..=u64::MAX {
        block.header.nonce = nonce;
        let header_hash = block.header.hash();
        if chroma_crypto::randomx::hash_meets_target(&header_hash, &target) {
            return Ok(());
        }

        if nonce % 10_000_000 == 0 && nonce > 0 {
            // Progress heartbeat — in production, this would yield to the runtime
        }
    }

    Err(CoreError::InvalidProofOfWork(
        "exhausted nonce search space".into(),
    ))
}

/// Mine a block with timeout.
///
/// Searches for at most `max_nonces` nonce values before returning an error.
pub fn mine_block_with_limit(block: &mut Block, max_nonces: u64) -> Result<()> {
    let target = block.header.bits.to_full_target();

    for nonce in 0..max_nonces {
        block.header.nonce = nonce;
        let header_hash = block.header.hash();
        if chroma_crypto::randomx::hash_meets_target(&header_hash, &target) {
            return Ok(());
        }
    }

    Err(CoreError::InvalidProofOfWork(
        "nonce search limit reached without finding solution".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_genesis_block;
    use chroma_state::State;
    use chroma_core::hash::Hash160;
    use chroma_core::types::{Address, Nonce};

    fn test_address() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xAA;
        Address::from_hash160(Hash160(h))
    }

    fn easy_bits() -> CompactTarget {
        CompactTarget(0x1f00ffff)
    }

    #[test]
    fn test_next_block_timestamp_stays_within_the_future_bound() {
        use chroma_core::constants::MAX_FUTURE_TIMESTAMP_OFFSET;

        // Blocks arriving faster than the target must not push the stamp past
        // what validation accepts. Pacing by parent + target_block_time did
        // exactly that, and the miner rejected its own blocks.
        let now = 1_800_000_000u64;
        for mtp in [0u64, now - 100, now - 1, now, now + 5] {
            let ts = next_block_timestamp(now, mtp);
            assert!(ts > mtp, "timestamp {} must be past MTP {}", ts, mtp);
            assert!(
                ts <= now + MAX_FUTURE_TIMESTAMP_OFFSET as u64,
                "timestamp {} is too far ahead of now {}",
                ts,
                now
            );
            assert!(timestamp_is_valid(ts, now, mtp));
        }
    }

    #[test]
    fn test_timestamp_validity_matches_the_consensus_bounds() {
        let now = 1_800_000_000u64;
        let mtp = now - 50;
        assert!(timestamp_is_valid(now, now, mtp));
        assert!(timestamp_is_valid(mtp + 1, now, mtp));
        assert!(!timestamp_is_valid(mtp, now, mtp), "must be strictly after MTP");
        assert!(timestamp_is_valid(now + 20, now, mtp), "20s ahead is allowed");
        assert!(!timestamp_is_valid(now + 21, now, mtp), "21s ahead is not");
    }

    #[test]
    fn test_assemble_block_empty_mempool() {
        let genesis = build_genesis_block();
        let genesis_hash = genesis.hash();

        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis_hash,
            timestamp: genesis.header.timestamp + 10,
            bits: CompactTarget(0x1d00ffff),
            coinbase_recipient: test_address(),
        };

        let block = assemble_block(&ctx, &[], &State::new()).unwrap();
        assert_eq!(block.header.height, BlockHeight(1));
        assert_eq!(block.header.previous_hash, genesis_hash);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);
        assert_eq!(block.transactions[0].nonce.0, 0);
        assert_ne!(block.header.tx_merkle_root, Hash::ZERO);
    }

    #[test]
    fn test_assemble_block_with_transactions() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: CompactTarget(0x1d00ffff),
            coinbase_recipient: test_address(),
        };

        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0xBB; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let sender_addr = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

        let tx = chroma_tx::create_transaction(
            &secret,
            sender_addr,
            test_address(),
            Amount(100_000),
            Nonce(0),
        )
        .unwrap();

        // The sender needs a balance, or the transaction cannot apply and is
        // correctly left out of the block.
        let mut funded = State::new();
        funded.apply_subsidy(&sender_addr, 0).unwrap();

        let block = assemble_block(&ctx, &[tx.clone()], &funded).unwrap();
        assert_eq!(block.transactions.len(), 2);
        assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);
        assert_eq!(block.transactions[1], tx);
    }

    #[test]
    fn test_assemble_block_skips_inapplicable_transactions() {
        // A transaction from an account with no balance would make the whole
        // block invalid, so assembly must drop it rather than include it.
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: CompactTarget(0x1d00ffff),
            coinbase_recipient: test_address(),
        };

        let secret = chroma_crypto::schnorr::SecretKey32::from_bytes([0xCC; 32]).unwrap();
        let pubkey = chroma_crypto::schnorr::PublicKey32::from_secret(&secret).unwrap();
        let broke = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));
        let tx = chroma_tx::create_transaction(
            &secret,
            broke,
            test_address(),
            Amount(100_000),
            Nonce(0),
        )
        .unwrap();

        let block = assemble_block(&ctx, &[tx], &State::new()).unwrap();
        assert_eq!(block.transactions.len(), 1, "only the coinbase should remain");
    }

    #[test]
    fn test_assembled_block_state_root_matches_validation() {
        // The header must carry the state root *after* the block applies.
        // Previously it carried the parent's root, so every mined block was
        // rejected at its own state-root check.
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let parent = State::new();
        let block = assemble_block(&ctx, &[], &parent).unwrap();

        let mut applied = parent.clone();
        applied.apply_subsidy(&test_address(), 1).unwrap();
        assert_eq!(
            block.header.state_root,
            applied.compute_state_root(),
            "header must commit to the post-block state"
        );
        assert_ne!(
            block.header.state_root,
            parent.compute_state_root(),
            "the subsidy always changes the state, so the roots must differ"
        );
    }

    #[test]
    fn test_mine_block_easy() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();
        mine_block_with_limit(&mut block, 10_000_000).unwrap();

        let target = block.header.bits.to_full_target();
        let hash = block.header.hash();
        assert!(
            chroma_crypto::randomx::hash_meets_target(&hash, &target),
            "mined block should meet target"
        );
    }

    #[test]
    fn test_mine_block_deterministic_per_nonce() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();

        let target = block.header.bits.to_full_target();

        let mut found_nonce = None;
        for nonce in 0..10_000_000u64 {
            block.header.nonce = nonce;
            let hash = block.header.hash();
            if chroma_crypto::randomx::hash_meets_target(&hash, &target) {
                found_nonce = Some(nonce);
                break;
            }
        }

        let nonce = found_nonce.expect("should find a valid nonce");
        block.header.nonce = nonce;
        let hash = block.header.hash();
        assert!(chroma_crypto::randomx::hash_meets_target(&hash, &target));
    }

    #[test]
    fn test_coinbase_has_zero_sender_pubkey() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let block = assemble_block(&ctx, &[], &State::new()).unwrap();
        let coinbase = &block.transactions[0];
        assert_eq!(coinbase.sender_pubkey.0, [0u8; 32]);
        assert_eq!(coinbase.signature.0, [0u8; 64]);
    }

    #[test]
    fn test_mine_block_valid_pow() {
        let genesis = build_genesis_block();
        let ctx = BlockAssemblyContext {
            height: BlockHeight(1),
            previous_hash: genesis.hash(),
            timestamp: genesis.header.timestamp + 10,
            bits: easy_bits(),
            coinbase_recipient: test_address(),
        };

        let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();
        mine_block_with_limit(&mut block, 10_000_000).unwrap();

        let target = block.header.bits.to_full_target();
        assert!(chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target));
    }
}
