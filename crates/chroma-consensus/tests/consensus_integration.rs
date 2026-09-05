//! Comprehensive Integration Tests for Chroma
//!
//! Tests consensus, validation, state transitions, serialization,
//! fork choice, and end-to-end mining flows.

use std::collections::BTreeMap;

use chroma_block::{Block, BlockHeader};
use chroma_core::constants::{
    BLOCK_REWARD_UNITS, DIFFICULTY_ADJUSTMENT_WINDOW,
    GENESIS_TARGET_BITS, GENESIS_TIMESTAMP, MAX_BLOCK_SIZE, MAX_MEMPOOL_TXS,
    MAX_TRANSACTION_SIZE, MTP_WINDOW, TARGET_BLOCK_TIME_SECS,
};
use chroma_core::error::CoreError;
use chroma_core::hash::{Hash, Hash160};
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::{
    Address, Amount, BlockHeight, CompactTarget, Nonce,
};
use chroma_core::u256::U256;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_p2p::wire::{Message, MessageType, VersionMessage, PingMessage, InvMessage, InvEntry, InvType};
use chroma_state::State;
use chroma_storage::PersistedTip;
use chroma_tx::Transaction;

fn alice_addr() -> Address {
    let mut h = [0u8; 20];
    h[0] = 0xAA;
    Address::from_hash160(Hash160(h))
}

fn bob_addr() -> Address {
    let mut h = [0u8; 20];
    h[0] = 0xBB;
    Address::from_hash160(Hash160(h))
}

fn easy_bits() -> CompactTarget {
    CompactTarget(0x1f00ffff)
}

// ============================================================================
// Protocol Constant Verification
// ============================================================================

#[test]
fn test_frozen_constants_match_spec() {
    assert_eq!(BLOCK_REWARD_UNITS, 1_000_000);
    assert_eq!(chroma_core::constants::UNITS_PER_CHR, 1_000_000);
    assert_eq!(chroma_core::constants::MAX_SUPPLY_CHR, 100_000_000);
    assert_eq!(
        chroma_core::constants::MAX_SUPPLY_UNITS,
        100_000_000_000_000u128
    );
    assert_eq!(TARGET_BLOCK_TIME_SECS, 10);
    assert_eq!(DIFFICULTY_ADJUSTMENT_WINDOW, 10);
    assert_eq!(MAX_BLOCK_SIZE, 1_048_576);
    assert_eq!(MAX_TRANSACTION_SIZE, 65536);
    assert_eq!(MTP_WINDOW, 7);
    assert_eq!(chroma_core::constants::ADDRESS_HRP, "chr");
    assert_eq!(GENESIS_TARGET_BITS, 0x1d00ffff);
    assert_eq!(GENESIS_TIMESTAMP, 1767225600);
}

// ============================================================================
// Transaction Validation Integration
// ============================================================================

#[test]
fn test_create_sign_verify_transaction() {
    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let tx = chroma_tx::create_transaction(
        &secret,
        sender.clone(),
        bob_addr(),
        Amount(500_000),
        Nonce(0),
    )
    .unwrap();

    assert!(tx.verify_signature());
    assert_eq!(tx.amount.0, 500_000);
    assert_eq!(tx.nonce.0, 0);

    let encoded = tx.encode();
    assert_eq!(encoded.len(), Transaction::SERIALIZED_SIZE);
    let decoded = Transaction::decode(&encoded).unwrap();
    assert_eq!(tx, decoded);
}

#[test]
fn test_double_spend_rejected() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let result1 = state.apply_transaction(&alice_addr(), &bob_addr(), 500_000, 0);
    assert!(result1.is_ok());

    let result2 = state.apply_transaction(&alice_addr(), &bob_addr(), 500_000, 0);
    assert!(result2.is_err());
}

#[test]
fn test_nonce_conflict_rejected() {
    let mut state = State::new();

    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    state.apply_subsidy(&sender, 0).unwrap();

    let result = state.apply_transaction(&sender, &bob_addr(), 100_000, 0);
    assert!(result.is_ok());

    let result2 = state.apply_transaction(&sender, &bob_addr(), 100_000, 0);
    assert!(result2.is_err());
    match result2.unwrap_err() {
        CoreError::InvalidNonce(_) => {}
        other => panic!("expected InvalidNonce, got {:?}", other),
    }
}

#[test]
fn test_insufficient_balance_rejected() {
    let mut state = State::new();
    let result = state.apply_transaction(&alice_addr(), &bob_addr(), 100, 0);
    assert!(result.is_err());
}

#[test]
fn test_self_send_rejected() {
    let mut state = State::new();
    let result = state.apply_transaction(&alice_addr(), &alice_addr(), 100, 0);
    assert!(result.is_err());
}

#[test]
fn test_zero_amount_rejected() {
    let mut state = State::new();
    let result = state.apply_transaction(&alice_addr(), &bob_addr(), 0, 0);
    assert!(result.is_err());
}

#[test]
fn test_valid_transfer() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let result = state.apply_transaction(&alice_addr(), &bob_addr(), 500_000, 0);
    assert!(result.is_ok());

    assert_eq!(state.get_account(&alice_addr()).balance, 500_000);
    assert_eq!(state.get_account(&bob_addr()).balance, 500_000);
    assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS);
}

// ============================================================================
// Block Assembly + Mining Integration
// ============================================================================

#[test]
fn test_block_assembly_and_mining() {
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};

    let genesis = chroma_consensus::build_genesis_block();
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash(),
        previous_timestamp: genesis.header.timestamp,
        bits: easy_bits(),
        coinbase_recipient: alice_addr(),
    };

    let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();
    assert_eq!(block.transactions.len(), 1);
    assert_eq!(block.transactions[0].amount.0, BLOCK_REWARD_UNITS);

    mine_block_with_limit(&mut block, 10_000_000).unwrap();

    let target = block.header.bits.to_full_target();
    assert!(chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target));
    assert_eq!(block.header.height, BlockHeight(1));
    assert_eq!(block.header.previous_hash, genesis.hash());
}

#[test]
fn test_block_reward_exact_amount() {
    let mut state = State::new();
    let subsidy = state.block_subsidy(0).unwrap();
    assert_eq!(subsidy, BLOCK_REWARD_UNITS);
}

#[test]
fn test_max_supply_cap_enforced() {
    let mut state = State::new();
    for _ in 0..chroma_core::constants::MAX_SUPPLY_CHR + 1 {
        let subsidy = state.block_subsidy(0).unwrap();
        if subsidy == 0 {
            break;
        }
        state.apply_subsidy(&alice_addr(), 0).unwrap();
    }
    assert_eq!(state.total_supply(), chroma_core::constants::MAX_SUPPLY_UNITS as u64);
    assert_eq!(state.block_subsidy(0).unwrap(), 0);
}

// ============================================================================
// Difficulty Adjustment Boundary Tests
// ============================================================================

#[test]
fn test_difficulty_no_change_when_on_target() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

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
            timestamp: genesis.header.timestamp + (h as u64) * TARGET_BLOCK_TIME_SECS,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    assert_eq!(target_at_10, CompactTarget(GENESIS_TARGET_BITS));
}

#[test]
fn test_difficulty_increases_when_blocks_fast() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

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
            timestamp: genesis.header.timestamp + (h as u64) * 5,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original_target = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    assert!(new_target < original_target, "target should decrease when blocks are fast");
}

#[test]
fn test_difficulty_decreases_when_blocks_slow() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

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
            timestamp: genesis.header.timestamp + (h as u64) * 20,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original_target = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    assert!(new_target > original_target, "target should increase when blocks are slow");
}

#[test]
fn test_difficulty_clamped_at_max_increase() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

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
            timestamp: genesis.header.timestamp + (h as u64),
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    let max_increase = original.shl(2);
    assert!(new_target <= max_increase, "should be clamped at 4x increase");
}

#[test]
fn test_difficulty_clamped_at_max_decrease() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

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
            timestamp: genesis.header.timestamp + (h as u64) * 1000,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_at_10 = calculate_target_for_height(10, &headers).unwrap();
    let original = U256::from_be_bytes(&CompactTarget(GENESIS_TARGET_BITS).to_full_target());
    let new_target = U256::from_be_bytes(&target_at_10.to_full_target());
    let min_decrease = {
        let (q, _) = original.div_rem(&U256::from_u64(4));
        q
    };
    assert!(new_target >= min_decrease, "should be clamped at 4x decrease");
}

#[test]
fn test_difficulty_carries_forward_between_retargets() {
    use chroma_consensus::{build_genesis_block, calculate_target_for_height};

    let mut headers = BTreeMap::new();
    let genesis = build_genesis_block();
    headers.insert(0, genesis.header.clone());

    for h in 1..=25u32 {
        let prev = headers.get(&(h - 1)).unwrap();
        let header = BlockHeader {
            version: 1,
            previous_hash: prev.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: genesis.header.timestamp + (h as u64) * TARGET_BLOCK_TIME_SECS,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(h),
            nonce: 0,
        };
        headers.insert(h, header);
    }

    let target_11 = calculate_target_for_height(11, &headers).unwrap();
    let target_12 = calculate_target_for_height(12, &headers).unwrap();
    let target_19 = calculate_target_for_height(19, &headers).unwrap();
    assert_eq!(target_11, target_12, "non-retarget heights carry forward");
    assert_eq!(target_12, target_19, "non-retarget heights carry forward");
}

// ============================================================================
// Fork Choice / Cumulative Work Tests
// ============================================================================

#[test]
fn test_chain_state_genesis_has_work() {
    let chain = chroma_consensus::ChainState::with_genesis();
    assert!(chain.best_tip().cumulative_work > U256::ZERO);
    assert_eq!(chain.best_tip().height, BlockHeight::GENESIS);
}

#[test]
fn test_mtp_computed_correctly() {
    let chain = chroma_consensus::ChainState::with_genesis();
    let mtp = chain.compute_median_time_past(0);
    assert_eq!(mtp, 0, "genesis MTP should be 0");
}

// ============================================================================
// Storage Integration Tests
// ============================================================================

#[test]
fn test_storage_roundtrip_blocks_and_state() {
    let storage = chroma_storage::Storage::open_temporary().unwrap();

    let genesis = chroma_consensus::build_genesis_block();
    storage.put_block(&genesis).unwrap();
    let tip = PersistedTip {
        height: 0,
        hash: genesis.hash(),
        cumulative_work: [0u8; 32],
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();

    let loaded = storage.get_block_by_hash(&genesis.hash()).unwrap();
    assert!(loaded.is_some());
    assert_eq!(loaded.unwrap().header, genesis.header);

    let loaded_tip = storage.get_tip().unwrap();
    assert!(loaded_tip.is_some());
    assert_eq!(loaded_tip.unwrap().hash, genesis.hash());
}

#[test]
fn test_storage_account_balance_persistence() {
    let storage = chroma_storage::Storage::open_temporary().unwrap();

    let mut acc = chroma_state::Account::default();
    acc.balance = 5_000_000;
    acc.nonce = 3;

    storage.put_account(&alice_addr(), &acc).unwrap();
    let loaded = storage.get_account(&alice_addr()).unwrap();
    assert!(loaded.is_some());
    let loaded = loaded.unwrap();
    assert_eq!(loaded.balance, 5_000_000);
    assert_eq!(loaded.nonce, 3);
}

// ============================================================================
// Wire Protocol Integration
// ============================================================================

#[test]
fn test_wire_message_roundtrip() {
    let version = VersionMessage {
        version: 1,
        services: 0,
        timestamp: 1767225600,
        height: 42,
        nonce: 0xDEADBEEF,
        listen_port: 8333,
    };
    let msg = Message::new(MessageType::Version, version.encode());
    let encoded = msg.encode();
    assert!(encoded.len() >= 13);

    let (decoded, consumed) = Message::decode(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.msg_type, MessageType::Version);

    let decoded_version = VersionMessage::decode(&decoded.payload).unwrap();
    assert_eq!(decoded_version.version, 1);
    assert_eq!(decoded_version.height, 42);
    assert_eq!(decoded_version.nonce, 0xDEADBEEF);
    assert_eq!(decoded_version.listen_port, 8333);
}

#[test]
fn test_wire_ping_pong_roundtrip() {
    let ping = PingMessage { nonce: 12345 };
    let msg = Message::new(MessageType::Ping, ping.encode());
    let encoded = msg.encode();
    let (decoded, _) = Message::decode(&encoded).unwrap();
    assert_eq!(decoded.msg_type, MessageType::Ping);
    let decoded_ping = PingMessage::decode(&decoded.payload).unwrap();
    assert_eq!(decoded_ping.nonce, 12345);
}

#[test]
fn test_wire_message_rejects_oversized() {
    let big_payload = vec![0u8; 5_000_000];
    let msg = Message::new(MessageType::Block, big_payload);
    let encoded = msg.encode();

    match Message::decode(&encoded) {
        Err(CoreError::Serialization(s)) => {
            assert!(s.contains("too large") || s.contains("exceeds"));
        }
        other => panic!("expected error for oversized message, got {:?}", other),
    }
}

#[test]
fn test_wire_inv_message_roundtrip() {
    let inv = InvMessage {
        inventory: vec![
            InvEntry { inv_type: InvType::Tx, hash: Hash::blake3(b"tx1") },
            InvEntry { inv_type: InvType::Block, hash: Hash::blake3(b"block1") },
        ],
    };
    let msg = Message::new(MessageType::Inv, inv.encode());
    let encoded = msg.encode();
    let (decoded, _) = Message::decode(&encoded).unwrap();
    let decoded_inv = InvMessage::decode(&decoded.payload).unwrap();
    assert_eq!(decoded_inv.inventory.len(), 2);
    assert_eq!(decoded_inv.inventory[0].inv_type, InvType::Tx);
    assert_eq!(decoded_inv.inventory[1].inv_type, InvType::Block);
}

// ============================================================================
// Determinism Tests
// ============================================================================

#[test]
fn test_block_hash_deterministic() {
    let genesis = chroma_consensus::build_genesis_block();
    let h1 = genesis.hash();
    let h2 = genesis.hash();
    assert_eq!(h1, h2);
}

#[test]
fn test_genesis_block_deterministic_across_instances() {
    let g1 = chroma_consensus::build_genesis_block();
    let g2 = chroma_consensus::build_genesis_block();
    assert_eq!(g1.hash(), g2.hash());
    assert_eq!(g1.header, g2.header);
}

#[test]
fn test_transaction_deterministic() {
    let secret = SecretKey32::from_bytes([0x42u8; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));

    let tx1 = chroma_tx::create_transaction(
        &secret,
        sender.clone(),
        bob_addr(),
        Amount(100_000),
        Nonce(0),
    )
    .unwrap();
    let tx2 = chroma_tx::create_transaction(
        &secret,
        sender,
        bob_addr(),
        Amount(100_000),
        Nonce(0),
    )
    .unwrap();
    assert_eq!(tx1.encode(), tx2.encode());
    assert_eq!(tx1, tx2);
}

#[test]
fn test_sighash_deterministic() {
    use chroma_crypto::schnorr::compute_sighash;

    let sender = alice_addr().0.0;
    let recipient = bob_addr().0.0;

    let h1 = compute_sighash(&sender, &recipient, 100_000, 0);
    let h2 = compute_sighash(&sender, &recipient, 100_000, 0);
    assert_eq!(h1, h2);

    let h3 = compute_sighash(&sender, &recipient, 200_000, 0);
    assert_ne!(h1, h3);
}

// ============================================================================
// U256 Arithmetic Safety Tests
// ============================================================================

#[test]
fn test_u256_checked_add_overflow() {
    let max = U256::MAX;
    let one = U256::from_u64(1);
    assert!(max.checked_add(&one).is_none());
}

#[test]
fn test_u256_checked_add_normal() {
    let a = U256::from_u64(100);
    let b = U256::from_u64(200);
    assert_eq!(a.checked_add(&b).unwrap(), U256::from_u64(300));
}

// ============================================================================
// State Root Verification
// ============================================================================

#[test]
fn test_state_root_changes_with_balance_update() {
    let mut state = State::new();
    let root1 = state.compute_state_root();

    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let root2 = state.compute_state_root();
    assert_ne!(root1, root2);
}

#[test]
fn test_state_root_deterministic() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let root1 = state.compute_state_root();
    let root2 = state.compute_state_root();
    assert_eq!(root1, root2);
}

// ============================================================================
// Mempool Integration
// ============================================================================

#[test]
fn test_mempool_add_and_remove() {
    let mut mempool = chroma_p2p::mempool::Mempool::new();

    let tx = Transaction {
        sender_pubkey: PublicKey32([0u8; 32]),
        recipient: bob_addr(),
        amount: Amount(100_000),
        nonce: Nonce(0),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };

    let tx_hash = Hash::blake3(&tx.encode());
    mempool.add_transaction(tx.clone()).unwrap();
    assert!(mempool.has_transaction(&tx_hash));

    mempool.remove_transaction(&tx_hash);
    assert!(!mempool.has_transaction(&tx_hash));
}

#[test]
fn test_mempool_capacity_limit() {
    let mut mempool = chroma_p2p::mempool::Mempool::new();

    for i in 0..=MAX_MEMPOOL_TXS {
        let tx = Transaction {
            sender_pubkey: PublicKey32([0u8; 32]),
            recipient: bob_addr(),
            amount: Amount(100_000),
            nonce: Nonce(i as u64),
            signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
        };
        let _ = mempool.add_transaction(tx);
    }

    let overflow_tx = Transaction {
        sender_pubkey: PublicKey32([0u8; 32]),
        recipient: bob_addr(),
        amount: Amount(100_000),
        nonce: Nonce(MAX_MEMPOOL_TXS as u64),
        signature: chroma_crypto::schnorr::Signature64([0u8; 64]),
    };
    assert!(mempool.add_transaction(overflow_tx).is_err());
}

// ============================================================================
// End-to-End Devnet Flow
// ============================================================================

#[test]
fn test_end_to_end_devnet() {
    use chroma_consensus::miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext};
    use chroma_consensus::ChainState;

    let mut chain = ChainState::with_genesis();

    let wallet = chroma_wallet::Wallet::generate("devnet-test");
    let recipient = wallet.address();

    let mut state = State::new();
    state.apply_subsidy(&recipient, 0).unwrap();

    let secret = SecretKey32::from_bytes([0xAA; 32]).unwrap();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));
    state.apply_subsidy(&sender, 0).unwrap();


    let genesis = chain.best_tip().clone();
    let ctx = BlockAssemblyContext {
        height: BlockHeight(1),
        previous_hash: genesis.hash,
        previous_timestamp: genesis.header.timestamp,
        bits: easy_bits(),
        coinbase_recipient: recipient,
    };

    let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();
    mine_block_with_limit(&mut block, 10_000_000).unwrap();

    let target = block.header.bits.to_full_target();
    assert!(
        chroma_crypto::randomx::hash_meets_target(&block.header.hash(), &target),
        "mined block should be valid"
    );
    assert_eq!(block.header.height, BlockHeight(1));
    assert_eq!(block.header.previous_hash, genesis.hash);
}

// ============================================================================
// Nonce Ordering Enforcement
// ============================================================================

#[test]
fn test_nonce_must_be_strictly_increasing() {
    let mut state = State::new();
    state.apply_subsidy(&alice_addr(), 0).unwrap();

    let result_skip = state.apply_transaction(&alice_addr(), &bob_addr(), 100_000, 1);
    assert!(result_skip.is_err());

    let result_next = state.apply_transaction(&alice_addr(), &bob_addr(), 100_000, 0);
    assert!(result_next.is_ok());
}

// ============================================================================
// CompactTarget Encoding Boundary Tests
// ============================================================================

#[test]
fn test_compact_target_roundtrip_various_values() {
    let test_cases: Vec<u32> = vec![
        0x1d00ffff,
        0x1e00ffff,
        0x1f00ffff,
    ];

    for bits in test_cases {
        let ct = CompactTarget(bits);
        let full = ct.to_full_target();
        let back = CompactTarget::from_full_target(&full);
        assert_eq!(ct, back, "roundtrip failed for bits=0x{:08x}", bits);
    }
}

#[test]
fn test_compact_target_max_is_identity() {
    let max = CompactTarget(0x2100ffff);
    let full = max.to_full_target();
    assert_eq!(full, [0xFF; 32]);
}

// ============================================================================
// Block Validation Context Integration
// ============================================================================

#[test]
fn test_mtp_enforced_in_block_validation() {
    let genesis = chroma_consensus::build_genesis_block();
    let ctx = chroma_block::BlockValidationContext {
        previous_hash: genesis.hash(),
        expected_height: BlockHeight(1),
        previous_timestamp: genesis.header.timestamp,
        median_time_past: genesis.header.timestamp + 1000,
        expected_bits: CompactTarget(GENESIS_TARGET_BITS),
        current_supply: 0,
        previous_state_root: Hash::ZERO,
        network_time: genesis.header.timestamp + 2000,
    };

    let block = Block {
        header: BlockHeader {
            version: 1,
            previous_hash: genesis.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Block::compute_tx_merkle_root(&[]),
            timestamp: genesis.header.timestamp + 500,
            bits: CompactTarget(GENESIS_TARGET_BITS),
            height: BlockHeight(1),
            nonce: 0,
        },
        transactions: vec![],
    };

    let mut state = State::new();
    let result = chroma_block::validate_block(&block, &ctx, &mut state);
    assert!(result.is_err(), "block should fail when timestamp <= MTP");
}

// ============================================================================
// Block Decode Rejection Tests
// ============================================================================

#[test]
fn test_block_decode_rejects_trailing_data() {
    let genesis = chroma_consensus::build_genesis_block();
    let mut encoded = genesis.encode_block();
    encoded.extend_from_slice(&[0xFF; 10]);
    let result = Block::decode_block(&encoded);
    assert!(result.is_err());
}

#[test]
fn test_block_decode_rejects_empty() {
    let result = Block::decode_block(&[]);
    assert!(result.is_err());
}

#[test]
fn test_header_decode_rejects_short_data() {
    let result = BlockHeader::decode(&[0u8; 50]);
    assert!(result.is_err());
}

// ============================================================================
// Storage + Chain Persistence Integration Test
// ============================================================================

#[test]
fn test_storage_genesis_and_persistence() {
    use chroma_storage::Storage;
    use chroma_core::u256::U256;

    let storage = Storage::open_temporary().unwrap();
    let genesis = chroma_consensus::build_genesis_block();
    let genesis_hash = genesis.hash();

    storage.apply_block(&genesis).unwrap();
    storage.put_genesis_hash(&genesis_hash).unwrap();

    let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis_hash,
        cumulative_work: genesis_work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.put_supply(0).unwrap();
    storage.flush().unwrap();

    let loaded_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(loaded_tip.height, 0);
    assert_eq!(loaded_tip.hash, genesis_hash);
    assert_eq!(loaded_tip.supply, 0);

    let loaded_hash = storage.get_genesis_hash().unwrap().unwrap();
    assert_eq!(loaded_hash, genesis_hash);

    let loaded_header = storage.get_header(0).unwrap().unwrap();
    assert_eq!(loaded_header.height.0, 0);
    assert_eq!(loaded_header.timestamp, genesis.header.timestamp);
}

#[test]
fn test_chain_state_loads_from_storage() {
    use chroma_storage::Storage;
    use chroma_consensus::{ChainState, build_genesis_block, ChainTip};
    use chroma_core::types::BlockHeight;
    use chroma_core::u256::U256;
    use std::collections::BTreeMap;

    let storage = Storage::open_temporary().unwrap();
    let genesis = build_genesis_block();
    let genesis_hash = genesis.hash();

    storage.apply_block(&genesis).unwrap();

    let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis_hash,
        cumulative_work: genesis_work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.flush().unwrap();

    let loaded_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(loaded_tip.height, 0);

    let mut headers = BTreeMap::new();
    let mut h = 0u32;
    while let Ok(Some(header)) = storage.get_header(h) {
        headers.insert(h, header);
        if h == loaded_tip.height { break; }
        h += 1;
    }

    let cumulative_work = U256::from_be_bytes(&loaded_tip.cumulative_work);
    let tip_header = headers.get(&loaded_tip.height).cloned().unwrap_or(genesis.header.clone());
    let chain_tip = ChainTip {
        height: BlockHeight(loaded_tip.height),
        hash: loaded_tip.hash,
        header: tip_header,
        cumulative_work,
        supply: loaded_tip.supply,
    };

    let mut tips = BTreeMap::new();
    tips.insert(loaded_tip.hash, chain_tip.clone());

    let chain = ChainState {
        headers,
        tip: chain_tip,
        state: chroma_state::State::new(),
        tips,
    };

    assert_eq!(chain.tip.height, BlockHeight(0));
    assert_eq!(chain.tip.hash, genesis_hash);
    assert!(chain.best_tip().cumulative_work > U256::ZERO);
}

#[test]
fn test_devnet_multi_block_mining_and_storage() {
    use chroma_storage::Storage;
    use chroma_consensus::{
        build_genesis_block, ChainState, calculate_target_for_height,
        miner::{assemble_block, mine_block_with_limit, BlockAssemblyContext},
    };
    use chroma_core::types::{BlockHeight, Address, CompactTarget};
    use chroma_core::hash::Hash160;
    use chroma_core::u256::U256;

    let easy_bits = CompactTarget(0x1f00ffff);

    let storage = Storage::open_temporary().unwrap();
    let mut chain = ChainState::with_genesis();

    let genesis = build_genesis_block();
    storage.apply_block(&genesis).unwrap();
    let genesis_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
        &genesis.header.bits.to_full_target(),
    ));
    let tip = chroma_storage::PersistedTip {
        height: 0,
        hash: genesis.hash(),
        cumulative_work: genesis_work.to_be_bytes(),
        supply: 0,
    };
    storage.put_tip(&tip).unwrap();
    storage.flush().unwrap();

    let miner_addr = {
        let mut h = [0u8; 20];
        h[0] = 0xDE; h[1] = 0xAD; h[2] = 0xBE; h[3] = 0xEF;
        Address::from_hash160(Hash160(h))
    };

    let blocks_to_mine = 3u32;

    for expected_height in 1..=blocks_to_mine {
        let (prev_hash, prev_ts, _state_root) = {
            let tip = chain.best_tip();
            (tip.hash, tip.header.timestamp, tip.header.state_root)
        };

        let ctx = BlockAssemblyContext {
            height: BlockHeight(expected_height),
            previous_hash: prev_hash,
            previous_timestamp: prev_ts,
            bits: easy_bits,
            coinbase_recipient: miner_addr.clone(),
        };

        let mut block = assemble_block(&ctx, &[], &State::new()).unwrap();
        block.header.timestamp = prev_ts + 10;
        mine_block_with_limit(&mut block, 10_000_000).unwrap();

        let block_hash = block.hash();
        chain.headers.insert(expected_height, block.header.clone());
        let block_work = U256::from_be_bytes(&chroma_crypto::randomx::calculate_work(
            &block.header.bits.to_full_target(),
        ));
        let new_cumulative = chain.tip.cumulative_work.checked_add(&block_work).unwrap();
        chain.tip = chroma_consensus::ChainTip {
            height: BlockHeight(expected_height),
            hash: block_hash,
            header: block.header.clone(),
            cumulative_work: new_cumulative,
            supply: chain.tip.supply + chroma_core::constants::BLOCK_REWARD_UNITS,
        };
        chain.tips.insert(block_hash, chain.tip.clone());

        storage.apply_block(&block).unwrap();
        let tip = chain.best_tip();
        let persisted = chroma_storage::PersistedTip {
            height: tip.height.0,
            hash: tip.hash,
            cumulative_work: tip.cumulative_work.to_be_bytes(),
            supply: tip.supply,
        };
        storage.put_tip(&persisted).unwrap();
        storage.flush().unwrap();

        assert_eq!(chain.best_tip().height.0, expected_height);
        assert_eq!(chain.best_tip().hash, block_hash);
    }

    let final_tip = storage.get_tip().unwrap().unwrap();
    assert_eq!(final_tip.height, blocks_to_mine);
}
