//! RandomX proof of work, end to end.
//!
//! Uses the regtest *target* with the RandomX *function*, so the real hash is
//! exercised without needing difficulty-1 work: a solution is a couple of
//! hashes away, and each costs tens of milliseconds.

use chroma_block::{validate_block, BlockValidationContext};
use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext, PowContext};
use chroma_consensus::{build_genesis_block_with, now_secs, ChainParams, ChainState};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::serialize::CanonicalEncode;
use chroma_core::types::{Address, BlockHeight};
use chroma_crypto::randomx::PowAlgorithm;
use chroma_state::State;

fn payout() -> Address {
    Address::from_hash160(Hash160([0x7A; 20]))
}

/// Regtest's easy target, but with RandomX doing the hashing.
fn randomx_params() -> ChainParams {
    ChainParams {
        pow: PowAlgorithm::RandomX,
        ..ChainParams::regtest()
    }
}

#[test]
fn mines_and_validates_a_randomx_block() {
    let params = randomx_params();
    let genesis = build_genesis_block_with(&params);
    let mut state = State::new();

    let seed = chroma_consensus::genesis_randomx_seed();
    let pow = PowContext {
        algorithm: PowAlgorithm::RandomX,
        seed,
    };

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        timestamp: genesis.header.timestamp + 10,
        bits: genesis.header.bits,
        coinbase_recipient: payout(),
    };
    let mut block = assemble_block(&ctx, &[], &state).unwrap();
    mine_block_with_limit(&mut block, 200, &pow).expect("a solution should be a few hashes away");

    let vctx = BlockValidationContext {
        previous_hash: genesis.hash(),
        expected_height: BlockHeight(1),
        previous_timestamp: genesis.header.timestamp,
        median_time_past: genesis.header.timestamp,
        expected_bits: genesis.header.bits,
        current_supply: 0,
        previous_state_root: genesis.header.state_root,
        network_time: now_secs(),
        pow_algorithm: PowAlgorithm::RandomX,
        pow_seed: seed,
    };

    validate_block(&block, &vctx, &mut state).expect("a RandomX block must validate");
    assert_eq!(state.get_account(&payout()).balance, 1_000_000);
}

#[test]
fn proof_of_work_is_not_the_block_identity() {
    // RandomX keys on the epoch seed and is deliberately expensive; the block
    // is still identified by the BLAKE3 hash of its header. Conflating the two
    // would mean the block's id changed with the epoch.
    let params = randomx_params();
    let genesis = build_genesis_block_with(&params);
    let seed = chroma_consensus::genesis_randomx_seed();
    let pow = PowContext {
        algorithm: PowAlgorithm::RandomX,
        seed,
    };

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        timestamp: genesis.header.timestamp + 10,
        bits: genesis.header.bits,
        coinbase_recipient: payout(),
    };
    let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();
    mine_block_with_limit(&mut block, 200, &pow).unwrap();

    let identity = block.hash();
    let work = pow.hash_header(&block.header).unwrap();
    assert_ne!(identity, work);
    assert_eq!(
        identity,
        Hash::blake3(&block.header.encode()),
        "the identity hash must stay BLAKE3 of the header"
    );
}

#[test]
fn work_done_for_one_epoch_does_not_carry_to_another() {
    // This is what makes rotating the seed meaningful: a block's proof of work
    // is only work *for that seed*.
    //
    // Building a cache costs a couple of seconds, so this uses exactly two
    // seeds and compares the two hashes against a target between them, rather
    // than searching for a seed that happens to miss.
    let params = randomx_params();
    let genesis = build_genesis_block_with(&params);
    let seed = chroma_consensus::genesis_randomx_seed();
    let other_seed = Hash::blake3(b"a different epoch");
    assert_ne!(seed, other_seed);

    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        timestamp: genesis.header.timestamp + 10,
        bits: genesis.header.bits,
        coinbase_recipient: payout(),
    };
    let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();

    let pow = PowContext {
        algorithm: PowAlgorithm::RandomX,
        seed,
    };
    mine_block_with_limit(&mut block, 200, &pow).expect("mine under the real seed");

    let under_seed = pow.hash_header(&block.header).unwrap();
    let under_other = PowContext {
        algorithm: PowAlgorithm::RandomX,
        seed: other_seed,
    }
    .hash_header(&block.header)
    .unwrap();

    assert_ne!(
        under_seed, under_other,
        "the same header must hash differently under a different seed"
    );

    // Set the bar exactly at whichever hash is lower. The seed that produced
    // it clears the bar; the other one cannot.
    let (lower, higher) = if under_seed.0 <= under_other.0 {
        (under_seed, under_other)
    } else {
        (under_other, under_seed)
    };
    assert!(chroma_crypto::randomx::hash_meets_target(&lower, &lower.0));
    assert!(
        !chroma_crypto::randomx::hash_meets_target(&higher, &lower.0),
        "work under the wrong seed must not satisfy a target the right one does"
    );
}

#[test]
fn chain_state_derives_the_epoch_seed_from_its_headers() {
    // Early heights have no seed block yet, so they use the genesis seed.
    let chain = ChainState::with_params(randomx_params());
    assert_eq!(
        chain.pow_seed_for(1, &chain.headers),
        chroma_consensus::genesis_randomx_seed()
    );
    assert_eq!(
        chain.pow_seed_for(999, &chain.headers),
        chroma_consensus::genesis_randomx_seed()
    );

    // Past the first epoch the seed would come from height 900, which this
    // chain does not have, so it still falls back rather than guessing.
    assert_eq!(
        chain.pow_seed_for(1000, &chain.headers),
        chroma_consensus::genesis_randomx_seed()
    );
}

#[test]
fn real_networks_are_configured_for_randomx() {
    for params in [
        ChainParams::mainnet(),
        ChainParams::testnet(),
        ChainParams::devnet(),
    ] {
        assert_eq!(params.pow, PowAlgorithm::RandomX);
    }
    assert_eq!(
        ChainParams::regtest().pow,
        PowAlgorithm::Blake3,
        "regtest stays cheap on purpose"
    );
}
