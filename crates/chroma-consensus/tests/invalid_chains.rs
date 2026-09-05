//! A node must refuse chains that break consensus rules, whatever they claim.
//!
//! Each test takes a block that would otherwise be accepted and breaks exactly
//! one rule, so a failure names the rule that stopped being enforced.

use chroma_block::{validate_block, Block, BlockValidationContext};
use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
use chroma_consensus::{build_genesis_block_with, now_secs, ChainParams, ChainState};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::types::{Address, Amount, BlockHeight, CompactTarget, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_state::State;

fn payout() -> Address {
    Address::from_hash160(Hash160([0xC0; 20]))
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

/// A block that validates cleanly, plus the context to validate it in.
fn good_block() -> (Block, BlockValidationContext, State) {
    let genesis = build_genesis_block_with(&params());
    let state = State::new();
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        timestamp: genesis.header.timestamp + 10,
        bits: genesis.header.bits,
        coinbase_recipient: payout(),
    };
    let mut block = assemble_block(&ctx, &[], &state).unwrap();
    mine_block_with_limit(&mut block, 100_000, &chroma_consensus::miner::PowContext::blake3()).unwrap();

    let vctx = BlockValidationContext {
        previous_hash: genesis.hash(),
        expected_height: BlockHeight(1),
        previous_timestamp: genesis.header.timestamp,
        median_time_past: genesis.header.timestamp,
        expected_bits: genesis.header.bits,
        current_supply: 0,
        previous_state_root: genesis.header.state_root,
        network_time: now_secs(),
        pow_algorithm: chroma_crypto::randomx::PowAlgorithm::Blake3,
        pow_seed: chroma_core::hash::Hash::ZERO,
    };
    (block, vctx, state)
}

/// Assert that a tampered block is refused, and say which rule should have
/// caught it.
fn assert_refused(block: &Block, ctx: &BlockValidationContext, rule: &str) {
    let mut state = State::new();
    let result = validate_block(block, ctx, &mut state);
    assert!(result.is_err(), "{} was not enforced", rule);
    assert_eq!(
        state.compute_state_root(),
        Hash::ZERO,
        "{}: a refused block must leave no trace in the state",
        rule
    );
}

#[test]
fn baseline_block_is_accepted() {
    // If this fails the other tests prove nothing.
    let (block, ctx, mut state) = good_block();
    validate_block(&block, &ctx, &mut state).expect("the baseline block must validate");
}

#[test]
fn rejects_insufficient_proof_of_work() {
    let (mut block, ctx, _) = good_block();
    // Break the proof of work while leaving everything else intact.
    let target = block.header.bits.to_full_target();
    loop {
        block.header.nonce = block.header.nonce.wrapping_add(1);
        if !chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target) {
            break;
        }
    }
    assert_refused(&block, &ctx, "proof of work");
}

#[test]
fn rejects_wrong_difficulty() {
    let (mut block, ctx, _) = good_block();
    block.header.bits = CompactTarget(0x1d00ffff);
    assert_refused(&block, &ctx, "declared difficulty");
}

#[test]
fn rejects_wrong_height() {
    let (mut block, ctx, _) = good_block();
    block.header.height = BlockHeight(7);
    assert_refused(&block, &ctx, "height continuity");
}

#[test]
fn rejects_wrong_parent() {
    let (mut block, ctx, _) = good_block();
    block.header.previous_hash = Hash::blake3(b"some other block");
    assert_refused(&block, &ctx, "parent linkage");
}

#[test]
fn rejects_timestamp_at_or_before_median() {
    let (mut block, mut ctx, _) = good_block();
    ctx.median_time_past = block.header.timestamp;
    assert_refused(&block, &ctx, "timestamp past the median");

    block.header.timestamp = ctx.median_time_past - 1;
    assert_refused(&block, &ctx, "timestamp past the median");
}

#[test]
fn rejects_timestamp_too_far_ahead() {
    let (mut block, ctx, _) = good_block();
    block.header.timestamp = now_secs() + 3_600;
    assert_refused(&block, &ctx, "future timestamp bound");
}

#[test]
fn rejects_wrong_state_root() {
    let (mut block, ctx, _) = good_block();
    block.header.state_root = Hash::blake3(b"not the state root");
    assert_refused(&block, &ctx, "state root commitment");
}

#[test]
fn rejects_wrong_merkle_root() {
    let (mut block, ctx, _) = good_block();
    block.header.tx_merkle_root = Hash::blake3(b"not the merkle root");
    assert_refused(&block, &ctx, "transaction merkle root");
}

#[test]
fn rejects_unknown_version() {
    let (mut block, ctx, _) = good_block();
    block.header.version = 99;
    assert_refused(&block, &ctx, "block version");
}

#[test]
fn rejects_empty_block() {
    let (mut block, ctx, _) = good_block();
    block.transactions.clear();
    assert_refused(&block, &ctx, "coinbase presence");
}

#[test]
fn rejects_oversized_coinbase_reward() {
    let (mut block, ctx, _) = good_block();
    block.transactions[0].amount = Amount(2_000_000);
    assert_refused(&block, &ctx, "coinbase reward amount");
}

#[test]
fn rejects_transaction_with_a_broken_signature() {
    // A block whose transfer does not verify must be refused whole.
    let genesis = build_genesis_block_with(&params());
    let secret = SecretKey32::generate();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(hash160(&pubkey.0)));

    let mut state = State::new();
    state.apply_subsidy(&sender, 0).unwrap();

    let tx = chroma_tx::create_transaction(
        &secret,
        sender,
        Address::from_hash160(Hash160([0x44; 20])),
        Amount(1_000),
        Nonce(0),
    )
    .unwrap();

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        timestamp: genesis.header.timestamp + 10,
        bits: genesis.header.bits,
        coinbase_recipient: payout(),
    };
    let mut block = assemble_block(&ctx, &[tx], &state).unwrap();
    assert_eq!(block.transactions.len(), 2);

    // Corrupt the signature after assembly.
    block.transactions[1].signature.0[0] ^= 0xFF;
    mine_block_with_limit(&mut block, 100_000, &chroma_consensus::miner::PowContext::blake3()).unwrap();

    let vctx = BlockValidationContext {
        previous_hash: genesis.hash(),
        expected_height: BlockHeight(1),
        previous_timestamp: genesis.header.timestamp,
        median_time_past: genesis.header.timestamp,
        expected_bits: genesis.header.bits,
        current_supply: 0,
        previous_state_root: genesis.header.state_root,
        network_time: now_secs(),
        pow_algorithm: chroma_crypto::randomx::PowAlgorithm::Blake3,
        pow_seed: chroma_core::hash::Hash::ZERO,
    };

    let before = state.clone();
    assert!(
        validate_block(&block, &vctx, &mut state).is_err(),
        "a bad signature must sink the block"
    );
    assert_eq!(
        state.compute_state_root(),
        before.compute_state_root(),
        "a refused block must leave the state untouched"
    );
}

#[test]
fn chain_refuses_to_build_on_an_invalid_block() {
    // A rejected block must not enter the index, so nothing can be built on
    // it afterwards.
    let mut chain = ChainState::with_params(params());
    let genesis = build_genesis_block_with(&params());

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        timestamp: genesis.header.timestamp + 10,
        bits: genesis.header.bits,
        coinbase_recipient: payout(),
    };
    let mut bad = assemble_block(&ctx, &[], &chain.state).unwrap();
    mine_block_with_limit(&mut bad, 100_000, &chroma_consensus::miner::PowContext::blake3()).unwrap();
    bad.header.state_root = Hash::blake3(b"wrong");

    assert!(chain.apply_block(&bad).is_err());
    assert_eq!(chain.tip.height.0, 0, "the tip must not move");
    assert!(
        !chain.index.contains_key(&bad.hash()),
        "a refused block must not be indexed"
    );

    // A child of the refused block therefore has no known parent.
    let child_ctx = BlockAssemblyContext {
        height: BlockHeight(2),
        previous_hash: bad.hash(),
        timestamp: bad.header.timestamp + 10,
        bits: bad.header.bits,
        coinbase_recipient: payout(),
    };
    let mut child = assemble_block(&child_ctx, &[], &chain.state).unwrap();
    mine_block_with_limit(&mut child, 100_000, &chroma_consensus::miner::PowContext::blake3()).unwrap();
    let err = chain.apply_block(&child).unwrap_err();
    assert!(err.to_string().contains("missing parent"), "got: {}", err);
}
