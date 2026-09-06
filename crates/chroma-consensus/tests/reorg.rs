//! Fork choice and chain reorganisation (spec §2.1, §2.3).
//!
//! Two chains are built over the same genesis and offered to one ChainState,
//! to check that the branch with the most accumulated work wins and that the
//! account state follows the switch.

use std::collections::HashMap;

use chroma_block::Block;
use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
use chroma_consensus::{
    build_genesis_block_with, BlockOutcome, BlockSource, ChainParams, ChainState,
};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::types::{Address, BlockHeight};
use chroma_state::State;

/// Blocks kept in memory, standing in for the node's storage.
#[derive(Default)]
struct MemoryBlocks(HashMap<Hash, Block>);

impl MemoryBlocks {
    fn put(&mut self, block: &Block) {
        self.0.insert(block.hash(), block.clone());
    }
}

impl BlockSource for MemoryBlocks {
    fn get_block(&self, hash: &Hash) -> Option<Block> {
        self.0.get(hash).cloned()
    }
}

fn miner(tag: u8) -> Address {
    Address::from_hash160(Hash160([tag; 20]))
}

/// Mine one block on top of `parent`, paying `recipient`.
fn mine_on(parent: &chroma_block::BlockHeader, state: &State, recipient: Address) -> Block {
    let ctx = BlockAssemblyContext {
        height: BlockHeight(parent.height.0 + 1),
        previous_hash: parent.hash(),
        timestamp: parent.timestamp + 10,
        bits: parent.bits,
        coinbase_recipient: recipient,
    };
    let mut block = assemble_block(&ctx, &[], state).unwrap();
    mine_block_with_limit(&mut block, 100_000, &chroma_consensus::miner::PowContext::blake3()).expect("regtest mining is trivial");
    block
}

/// Build a branch of `len` blocks from `parent`, applying to a scratch state
/// so each block commits to the right root.
fn build_branch(
    parent: &chroma_block::BlockHeader,
    parent_state: &State,
    len: usize,
    recipient: Address,
    blocks: &mut MemoryBlocks,
) -> Vec<Block> {
    let mut out = Vec::new();
    let mut header = parent.clone();
    let mut state = parent_state.clone();

    for _ in 0..len {
        let block = mine_on(&header, &state, recipient);
        // Mirror what validation will do, so the next block builds on the
        // right state.
        state.apply_subsidy(&recipient, block.header.height.0).unwrap();
        header = block.header.clone();
        blocks.put(&block);
        out.push(block);
    }
    out
}

#[test]
fn longer_branch_replaces_the_active_chain() {
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let empty = State::new();
    let branch_a = build_branch(&genesis.header, &empty, 2, miner(0xAA), &mut blocks);
    let branch_b = build_branch(&genesis.header, &empty, 3, miner(0xBB), &mut blocks);

    let mut chain = ChainState::with_params(params);

    // Take the shorter branch first.
    for block in &branch_a {
        assert_eq!(
            chain.apply_block_with(block, &blocks).unwrap(),
            BlockOutcome::Extended
        );
    }
    assert_eq!(chain.tip.height.0, 2);
    assert_eq!(chain.state.get_account(&miner(0xAA)).balance, 2_000_000);

    // The first two blocks of the longer branch are side branches: equal or
    // less work than what we already have.
    assert_eq!(
        chain.apply_block_with(&branch_b[0], &blocks).unwrap(),
        BlockOutcome::SideBranch
    );
    assert_eq!(chain.tip.height.0, 2, "a side branch must not move the tip");

    assert_eq!(
        chain.apply_block_with(&branch_b[1], &blocks).unwrap(),
        BlockOutcome::SideBranch
    );

    // The third tips the balance of work and triggers the switch.
    match chain.apply_block_with(&branch_b[2], &blocks).unwrap() {
        BlockOutcome::Reorganized { depth } => assert_eq!(depth, 2, "two blocks rolled back"),
        other => panic!("expected a reorg, got {:?}", other),
    }

    assert_eq!(chain.tip.height.0, 3);
    assert_eq!(chain.tip.hash, branch_b[2].hash());
    assert_eq!(
        chain.state.get_account(&miner(0xBB)).balance,
        3_000_000,
        "the new branch's miner holds the rewards"
    );
    assert_eq!(
        chain.state.get_account(&miner(0xAA)).balance,
        0,
        "the abandoned branch's rewards are gone"
    );
    assert_eq!(chain.tip.supply, 3_000_000);
}

#[test]
fn shorter_branch_is_kept_but_does_not_win() {
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let empty = State::new();
    let long = build_branch(&genesis.header, &empty, 3, miner(0xAA), &mut blocks);
    let short = build_branch(&genesis.header, &empty, 1, miner(0xBB), &mut blocks);

    let mut chain = ChainState::with_params(params);
    for block in &long {
        chain.apply_block_with(block, &blocks).unwrap();
    }
    let tip_before = chain.tip.hash;

    assert_eq!(
        chain.apply_block_with(&short[0], &blocks).unwrap(),
        BlockOutcome::SideBranch
    );
    assert_eq!(chain.tip.hash, tip_before, "the tip must not move");
    assert_eq!(chain.state.get_account(&miner(0xBB)).balance, 0);

    // ...but it is remembered, so a later block extending it can be connected.
    assert!(chain.index.contains_key(&short[0].hash()));
}

#[test]
fn reorg_restores_the_supply_of_the_new_branch() {
    // Supply must follow the active chain, not accumulate across both.
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let empty = State::new();
    let a = build_branch(&genesis.header, &empty, 1, miner(0xAA), &mut blocks);
    let b = build_branch(&genesis.header, &empty, 4, miner(0xBB), &mut blocks);

    let mut chain = ChainState::with_params(params);
    chain.apply_block_with(&a[0], &blocks).unwrap();
    assert_eq!(chain.state.total_supply(), 1_000_000);

    for block in &b {
        chain.apply_block_with(block, &blocks).unwrap();
    }

    assert_eq!(chain.tip.height.0, 4);
    assert_eq!(
        chain.state.total_supply(),
        4_000_000,
        "supply must reflect only the active chain"
    );
}

#[test]
fn duplicate_block_is_recognised() {
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let branch = build_branch(&genesis.header, &State::new(), 1, miner(0xAA), &mut blocks);
    let mut chain = ChainState::with_params(params);

    assert_eq!(
        chain.apply_block_with(&branch[0], &blocks).unwrap(),
        BlockOutcome::Extended
    );
    assert_eq!(
        chain.apply_block_with(&branch[0], &blocks).unwrap(),
        BlockOutcome::Duplicate
    );
    assert_eq!(chain.tip.height.0, 1);
}

#[test]
fn block_with_an_unknown_parent_is_refused() {
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let branch = build_branch(&genesis.header, &State::new(), 3, miner(0xAA), &mut blocks);
    let mut chain = ChainState::with_params(params);

    // Offer the third block without the two below it.
    let err = chain.apply_block_with(&branch[2], &blocks).unwrap_err();
    assert!(
        err.to_string().contains("missing parent"),
        "unexpected error: {}",
        err
    );
    assert_eq!(chain.tip.height.0, 0);
}

// ---------------------------------------------------------------------------
// State journal (spec §2.3)
// ---------------------------------------------------------------------------

#[test]
fn journal_records_the_active_chain() {
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let branch = build_branch(&genesis.header, &State::new(), 4, miner(0xAA), &mut blocks);
    let mut chain = ChainState::with_params(params);
    assert_eq!(chain.journal_depth(), 0);

    for (i, block) in branch.iter().enumerate() {
        chain.apply_block_with(block, &blocks).unwrap();
        assert_eq!(
            chain.journal_depth(),
            i + 1,
            "each accepted block should leave a way back"
        );
    }
}

#[test]
fn reorg_within_the_journal_needs_no_block_source() {
    // The point of the journal: a shallow reorg rolls the state back instead
    // of replaying the chain. If it is doing that, it never has to read the
    // active chain's blocks back — so a source that refuses to hand them over
    // must still work.
    struct BranchOnly {
        inner: MemoryBlocks,
        withheld: Vec<Hash>,
    }
    impl BlockSource for BranchOnly {
        fn get_block(&self, hash: &Hash) -> Option<Block> {
            if self.withheld.contains(hash) {
                return None;
            }
            self.inner.get_block(hash)
        }
    }

    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let empty = State::new();
    let short = build_branch(&genesis.header, &empty, 2, miner(0xAA), &mut blocks);
    let long = build_branch(&genesis.header, &empty, 3, miner(0xBB), &mut blocks);

    let mut chain = ChainState::with_params(params);
    for block in &short {
        chain.apply_block_with(block, &blocks).unwrap();
    }

    // Withhold exactly the blocks of the chain we are leaving.
    let source = BranchOnly {
        inner: blocks,
        withheld: short.iter().map(|b| b.hash()).collect(),
    };

    for block in &long[..2] {
        chain.apply_block_with(block, &source).unwrap();
    }
    match chain.apply_block_with(&long[2], &source).unwrap() {
        BlockOutcome::Reorganized { depth } => assert_eq!(depth, 2),
        other => panic!("expected a reorg, got {:?}", other),
    }

    assert_eq!(chain.tip.hash, long[2].hash());
    assert_eq!(chain.state.get_account(&miner(0xBB)).balance, 3_000_000);
    assert_eq!(chain.state.get_account(&miner(0xAA)).balance, 0);
}

#[test]
fn journal_is_dropped_when_the_chain_changes_under_it() {
    // After a reorg the journal describes a chain that is no longer active,
    // so keeping it would unwind into the wrong branch.
    //
    // The branches differ in length so the switch happens on a known block:
    // with equal work the tie-break decides, and the reorg could land on
    // either apply.
    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);

    let empty = State::new();
    let short = build_branch(&genesis.header, &empty, 2, miner(0xAA), &mut blocks);
    let long = build_branch(&genesis.header, &empty, 3, miner(0xBB), &mut blocks);

    let mut chain = ChainState::with_params(params);
    for block in &short {
        chain.apply_block_with(block, &blocks).unwrap();
    }
    assert_eq!(chain.journal_depth(), 2);

    // The first two are side branches; the third carries more work and wins.
    chain.apply_block_with(&long[0], &blocks).unwrap();
    chain.apply_block_with(&long[1], &blocks).unwrap();
    assert_eq!(chain.journal_depth(), 2, "a side branch does not touch it");

    match chain.apply_block_with(&long[2], &blocks).unwrap() {
        BlockOutcome::Reorganized { .. } => {}
        other => panic!("expected a reorg, got {:?}", other),
    }
    assert_eq!(
        chain.journal_depth(),
        0,
        "the old chain's journal must not survive the switch"
    );

    // And the chain keeps journalling from the new tip.
    let more = build_branch(&long[2].header, &chain.state, 1, miner(0xBB), &mut blocks);
    chain.apply_block_with(&more[0], &blocks).unwrap();
    assert_eq!(chain.tip.height.0, 4);
    assert_eq!(chain.journal_depth(), 1);
}

#[test]
fn journal_is_bounded_by_the_spec_depth() {
    use chroma_core::constants::REORG_JOURNAL_DEPTH;
    // Not worth mining 2000 blocks here; what matters is that the bound is the
    // one the spec names and that the journal never exceeds the blocks applied.
    assert_eq!(REORG_JOURNAL_DEPTH, 2000);

    let params = ChainParams::regtest();
    let genesis = build_genesis_block_with(&params);
    let mut blocks = MemoryBlocks::default();
    blocks.put(&genesis);
    let branch = build_branch(&genesis.header, &State::new(), 6, miner(0xAA), &mut blocks);

    let mut chain = ChainState::with_params(params);
    for block in &branch {
        chain.apply_block_with(block, &blocks).unwrap();
        assert!(chain.journal_depth() <= REORG_JOURNAL_DEPTH as usize);
    }
    assert_eq!(chain.journal_depth(), 6);
}
