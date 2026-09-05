//! End-to-end mining: assemble, mine, serialize, validate.
//!
//! These cover the path that was completely broken before: a mined block could
//! not be decoded (the coinbase sentinel was rejected as a public key), and
//! even in memory it failed its own state-root check because the header
//! carried the parent's state root rather than the post-block one.

use chroma_block::{validate_block, Block, BlockValidationContext};
use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
use chroma_consensus::{build_genesis_block, now_secs};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::types::{Address, Amount, BlockHeight, CompactTarget, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_state::State;

/// A target reachable in a test. Genesis difficulty needs billions of hashes.
fn easy_bits() -> CompactTarget {
    CompactTarget(0x1f00ffff)
}

fn miner_address() -> Address {
    Address::from_hash160(Hash160([0xDE; 20]))
}

fn assembly_ctx(height: u32, parent: &chroma_block::BlockHeader) -> BlockAssemblyContext {
    BlockAssemblyContext {
        height: BlockHeight(height),
        previous_hash: parent.hash(),
        previous_timestamp: parent.timestamp,
        bits: easy_bits(),
        coinbase_recipient: miner_address(),
    }
}

fn validation_ctx(
    height: u32,
    parent: &chroma_block::BlockHeader,
    supply: u64,
) -> BlockValidationContext {
    BlockValidationContext {
        previous_hash: parent.hash(),
        expected_height: BlockHeight(height),
        previous_timestamp: parent.timestamp,
        median_time_past: parent.timestamp,
        expected_bits: easy_bits(),
        current_supply: supply,
        previous_state_root: parent.state_root,
        network_time: now_secs(),
    }
}

#[test]
fn mined_block_passes_validation() {
    let genesis = build_genesis_block();
    let mut state = State::new();

    let mut block = assemble_block(&assembly_ctx(1, &genesis.header), &[], &state).unwrap();
    mine_block_with_limit(&mut block, 20_000_000).expect("mining should succeed at easy bits");

    let root = validate_block(&block, &validation_ctx(1, &genesis.header, 0), &mut state)
        .expect("a freshly mined block must validate");

    assert_eq!(root, block.header.state_root);
    assert_eq!(state.total_supply(), 1_000_000, "one block reward was minted");
    assert_eq!(state.get_account(&miner_address()).balance, 1_000_000);
}

#[test]
fn mined_block_survives_the_codec() {
    // Storage and relay both go through encode/decode. The coinbase sentinel
    // used to make this fail, so a mined block could never leave the process.
    let genesis = build_genesis_block();
    let state = State::new();

    let mut block = assemble_block(&assembly_ctx(1, &genesis.header), &[], &state).unwrap();
    mine_block_with_limit(&mut block, 20_000_000).unwrap();

    let decoded = Block::decode_block(&block.encode_block()).expect("mined block must decode");
    assert_eq!(decoded.hash(), block.hash());
    assert_eq!(decoded.transactions.len(), 1);
    assert!(decoded.transactions[0].is_coinbase());

    let mut fresh = State::new();
    validate_block(&decoded, &validation_ctx(1, &genesis.header, 0), &mut fresh)
        .expect("the decoded copy must validate identically");
}

#[test]
fn chain_of_blocks_accumulates_supply() {
    let genesis = build_genesis_block();
    let mut state = State::new();
    let mut parent = genesis.header.clone();

    for height in 1..=3u32 {
        let mut block = assemble_block(&assembly_ctx(height, &parent), &[], &state).unwrap();
        mine_block_with_limit(&mut block, 20_000_000).unwrap();
        validate_block(
            &block,
            &validation_ctx(height, &parent, state.total_supply()),
            &mut state,
        )
        .unwrap_or_else(|e| panic!("block {} failed: {}", height, e));
        parent = block.header.clone();
    }

    assert_eq!(state.total_supply(), 3_000_000);
    assert_eq!(state.get_account(&miner_address()).balance, 3_000_000);
}

#[test]
fn rejected_block_leaves_state_untouched() {
    // Validation applies the subsidy and every transaction before it can check
    // the state root, so it has to work on a copy. Applying in place left a
    // rejected block's effects behind and corrupted everything after it.
    let genesis = build_genesis_block();
    let mut state = State::new();

    let mut block = assemble_block(&assembly_ctx(1, &genesis.header), &[], &state).unwrap();
    mine_block_with_limit(&mut block, 20_000_000).unwrap();
    block.header.state_root = Hash::blake3(b"not the real root");

    let before_root = state.compute_state_root();
    let before_supply = state.total_supply();

    let result = validate_block(&block, &validation_ctx(1, &genesis.header, 0), &mut state);
    assert!(result.is_err(), "a wrong state root must be rejected");
    assert_eq!(state.compute_state_root(), before_root);
    assert_eq!(state.total_supply(), before_supply);
    assert_eq!(state.get_account(&miner_address()).balance, 0);
}

#[test]
fn block_carrying_a_transfer_validates() {
    let genesis = build_genesis_block();
    let mut state = State::new();

    // Fund a sender by paying it the first block's subsidy.
    let secret = SecretKey32::from_bytes([0x42; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(hash160(&pubkey.0)));

    let funding_ctx = BlockAssemblyContext {
        coinbase_recipient: sender,
        ..assembly_ctx(1, &genesis.header)
    };
    let mut funding = assemble_block(&funding_ctx, &[], &state).unwrap();
    mine_block_with_limit(&mut funding, 20_000_000).unwrap();
    validate_block(&funding, &validation_ctx(1, &genesis.header, 0), &mut state).unwrap();

    // Now spend some of it in the next block.
    let recipient = Address::from_hash160(Hash160([0x99; 20]));
    let tx = chroma_tx::create_transaction(
        &secret,
        sender,
        recipient,
        Amount(250_000),
        Nonce(0),
    )
    .unwrap();

    let mut block =
        assemble_block(&assembly_ctx(2, &funding.header), &[tx.clone()], &state).unwrap();
    assert_eq!(block.transactions.len(), 2, "the transfer must be included");
    mine_block_with_limit(&mut block, 20_000_000).unwrap();

    validate_block(
        &block,
        &validation_ctx(2, &funding.header, state.total_supply()),
        &mut state,
    )
    .expect("a block with a valid transfer must validate");

    assert_eq!(state.get_account(&recipient).balance, 250_000);
    assert_eq!(state.get_account(&sender).balance, 1_000_000 - 250_000);
    assert_eq!(state.get_account(&sender).nonce, 1);
    assert_eq!(state.total_supply(), 2_000_000, "transfers do not mint");
}

#[test]
fn a_second_coinbase_cannot_mint() {
    // The sentinel key never verifies, so a coinbase-marked transaction
    // outside slot 0 is caught by the ordinary signature check.
    let genesis = build_genesis_block();
    let mut state = State::new();

    let mut block = assemble_block(&assembly_ctx(1, &genesis.header), &[], &state).unwrap();
    let thief = Address::from_hash160(Hash160([0x66; 20]));
    block
        .transactions
        .push(chroma_tx::Transaction::coinbase(thief, Amount(1_000_000)));
    block.header.tx_merkle_root = Block::compute_tx_merkle_root(&block.transactions);
    mine_block_with_limit(&mut block, 20_000_000).unwrap();

    let result = validate_block(&block, &validation_ctx(1, &genesis.header, 0), &mut state);
    assert!(result.is_err(), "a second coinbase must be rejected");
    assert_eq!(state.get_account(&thief).balance, 0);
    assert_eq!(state.total_supply(), 0);
}

// ---------------------------------------------------------------------------
// Regtest
// ---------------------------------------------------------------------------

/// On regtest a single node must be able to extend the chain through the full
/// `ChainState::apply_block` path — the thing devnet's difficulty-1 target
/// makes impossible in practice.
#[test]
fn regtest_chain_advances() {
    use chroma_consensus::{ChainParams, ChainState};

    let params = ChainParams::regtest();
    let mut chain = ChainState::with_params(params);
    assert_eq!(chain.tip.height.0, 0);

    for height in 1..=5u32 {
        let ctx = BlockAssemblyContext {
            height: BlockHeight(height),
            previous_hash: chain.tip.hash,
            previous_timestamp: chain.tip.header.timestamp,
            bits: chain.tip.header.bits,
            coinbase_recipient: miner_address(),
        };
        let mut block = assemble_block(&ctx, &[], &chain.state).unwrap();
        mine_block_with_limit(&mut block, 1_000)
            .unwrap_or_else(|e| panic!("regtest mining should be trivial: {}", e));

        chain
            .apply_block(&block)
            .unwrap_or_else(|e| panic!("regtest block {} rejected: {}", height, e));
        assert_eq!(chain.tip.height.0, height);
    }

    assert_eq!(chain.tip.supply, 5_000_000, "five block rewards");
    assert_eq!(chain.state.get_account(&miner_address()).balance, 5_000_000);
}

/// Regtest holds the target fixed, including across a retarget boundary.
#[test]
fn regtest_never_retargets() {
    use chroma_consensus::{ChainParams, ChainState};

    let params = ChainParams::regtest();
    let mut chain = ChainState::with_params(params);
    let genesis_bits = chain.tip.header.bits;

    // Past height 10, where a real network would adjust.
    for height in 1..=12u32 {
        let ctx = BlockAssemblyContext {
            height: BlockHeight(height),
            previous_hash: chain.tip.hash,
            previous_timestamp: chain.tip.header.timestamp,
            bits: chain.tip.header.bits,
            coinbase_recipient: miner_address(),
        };
        let mut block = assemble_block(&ctx, &[], &chain.state).unwrap();
        mine_block_with_limit(&mut block, 1_000).unwrap();
        chain.apply_block(&block).unwrap();
        assert_eq!(
            chain.tip.header.bits, genesis_bits,
            "regtest difficulty must not move at height {}",
            height
        );
    }
}

/// Regtest and devnet must be separate chains, so a regtest block can never
/// be mistaken for a real one.
#[test]
fn regtest_genesis_differs_from_devnet() {
    use chroma_consensus::{build_genesis_block_with, ChainParams};

    let regtest = build_genesis_block_with(&ChainParams::regtest());
    let devnet = build_genesis_block_with(&ChainParams::devnet());
    assert_ne!(regtest.hash(), devnet.hash());
    assert_eq!(devnet.hash(), build_genesis_block().hash());
}
