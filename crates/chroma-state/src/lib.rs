//! Chroma State Model
//!
//! Account/balance model. State transitions are pure functions.
//! The state is a mapping from Address → Account.
//! State commitment: a sorted Merkle tree over (address, account) pairs
//! (spec §7.2).

use std::collections::BTreeMap;

use chroma_core::constants::{
    BLOCK_REWARD_UNITS, MAX_SUPPLY_UNITS,
};
use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::types::Address;

// ============================================================================
// Account
// ============================================================================

/// Per-account state: balance and transaction nonce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Balance in atomic units (1 CHR = 1,000,000 units)
    pub balance: u64,
    /// Number of transactions sent from this account.
    /// Each transaction must have nonce == account.nonce.
    /// After processing, nonce is incremented by 1.
    pub nonce: u64,
}

impl Account {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Account { balance, nonce }
    }

    /// Encode account for state commitment (fixed 16 bytes: balance_le64 || nonce_le64)
    fn encode_value(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16);
        buf.extend_from_slice(&self.balance.to_le_bytes());
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Decode account from 16 bytes
    #[allow(dead_code)]
    fn decode_value(data: &[u8]) -> Result<Self> {
        if data.len() != 16 {
            return Err(CoreError::Serialization(format!(
                "account: expected 16 bytes, got {}",
                data.len()
            )));
        }
        let balance = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let nonce = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        Ok(Account { balance, nonce })
    }
}

// ============================================================================
// State
// ============================================================================

/// Global account state. Deterministic, ordered by address for commitment.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// Accounts sorted by address for deterministic iteration.
    accounts: BTreeMap<[u8; 20], Account>,
    /// Total circulating supply in atomic units.
    total_supply: u64,
}

impl State {
    /// Create empty state.
    pub fn new() -> Self {
        State {
            accounts: BTreeMap::new(),
            total_supply: 0,
        }
    }

    /// Get account, returning default (zero) if not found.
    pub fn get_account(&self, address: &Address) -> Account {
        self.accounts
            .get(address.as_hash160().as_bytes())
            .copied()
            .unwrap_or(Account::default())
    }

    /// Get total supply.
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }

    /// Set account (used by state transitions and genesis).
    fn set_account(&mut self, address: &Address, account: Account) {
        *self
            .accounts
            .entry(*address.as_hash160().as_bytes())
            .or_insert_with(Account::default) = account;
    }

    /// Hash of one `(key, value)` pair as a Merkle leaf.
    ///
    /// Spec §7.2: `Leaf = H(encode(key) || encode(value))`.
    fn leaf_hash(address: &[u8; 20], account: &Account) -> Hash {
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(address);
        buf.extend_from_slice(&account.encode_value());
        Hash::blake3(&buf)
    }

    /// Hash of an internal node: `H(left || right)`.
    fn node_hash(left: &Hash, right: &Hash) -> Hash {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(left.as_bytes());
        buf.extend_from_slice(right.as_bytes());
        Hash::blake3(&buf)
    }

    /// The leaves of the state tree, in key order.
    fn leaves(&self) -> Vec<Hash> {
        self.accounts
            .iter()
            .map(|(addr, account)| Self::leaf_hash(addr, account))
            .collect()
    }

    /// Compute the state root as a sorted Merkle tree over `(key, value)`
    /// pairs (spec §7.2).
    ///
    /// An empty state hashes to `Hash::ZERO`, per the spec's empty root — not
    /// to the hash of an empty buffer. Genesis declares a zero state root, so
    /// anything else would leave genesis inconsistent with its own state.
    ///
    /// A level with an odd number of nodes carries the last node up unchanged
    /// rather than duplicating it. The spec does not pin this down; promotion
    /// avoids any chance of two different trees sharing a root, which is the
    /// failure mode duplication is known for.
    pub fn compute_state_root(&self) -> Hash {
        let mut level = self.leaves();
        if level.is_empty() {
            return Hash::ZERO;
        }

        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                match pair {
                    [left, right] => next.push(Self::node_hash(left, right)),
                    [odd] => next.push(*odd),
                    _ => unreachable!("chunks(2) yields one or two elements"),
                }
            }
            level = next;
        }

        level[0]
    }

    /// Merkle path proving `address`'s account is committed to by the state
    /// root, as sibling hashes from the leaf upwards.
    ///
    /// Returns `None` for an address with no account, since there is no leaf
    /// to prove.
    pub fn merkle_proof(&self, address: &Address) -> Option<MerkleProof> {
        let key = *address.as_hash160().as_bytes();
        let mut index = self.accounts.keys().position(|k| *k == key)?;

        let mut level = self.leaves();
        let mut steps = Vec::new();

        while level.len() > 1 {
            let sibling = if index % 2 == 0 { index + 1 } else { index - 1 };
            // A promoted odd node has no sibling at this level, so nothing is
            // recorded and it simply moves up.
            if sibling < level.len() {
                steps.push(ProofStep {
                    hash: level[sibling],
                    sibling_on_right: index % 2 == 0,
                });
            }

            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                match pair {
                    [left, right] => next.push(Self::node_hash(left, right)),
                    [odd] => next.push(*odd),
                    _ => unreachable!(),
                }
            }
            level = next;
            index /= 2;
        }

        Some(MerkleProof {
            account: self.get_account(address),
            steps,
        })
    }


    // ========================================================================
    // State Transitions
    // ========================================================================

    /// Apply a transfer transaction.
    ///
    /// Invariants enforced:
    /// - amount > 0
    /// - sender balance >= amount (checked arithmetic)
    /// - sender nonce matches tx nonce
    /// - sender != recipient (no self-sends)
    /// - total supply is conserved
    /// - no integer overflow/underflow
    pub fn apply_transaction(
        &mut self,
        sender: &Address,
        recipient: &Address,
        amount: u64,
        nonce: u64,
    ) -> Result<()> {
        // amount > 0
        if amount == 0 {
            return Err(CoreError::InvalidTransaction(
                "amount must be greater than zero".to_string(),
            ));
        }

        // sender != recipient
        if sender == recipient {
            return Err(CoreError::InvalidTransaction(
                "sender and recipient must differ".to_string(),
            ));
        }

        let mut sender_account = self.get_account(sender);

        // Nonce check: must equal expected nonce
        if nonce != sender_account.nonce {
            return Err(CoreError::InvalidNonce(format!(
                "expected nonce {}, got {}",
                sender_account.nonce, nonce
            )));
        }

        // Balance check: sender must have enough
        let new_sender_balance = sender_account
            .balance
            .checked_sub(amount)
            .ok_or_else(|| {
                CoreError::InsufficientBalance(format!(
                    "account has {} units, tried to send {}",
                    sender_account.balance, amount
                ))
            })?;

        // Update sender
        sender_account.balance = new_sender_balance;
        sender_account.nonce = sender_account
            .nonce
            .checked_add(1)
            .ok_or_else(|| CoreError::Overflow("nonce overflow".into()))?;
        self.set_account(sender, sender_account);

        // Update recipient (create if needed)
        let mut recipient_account = self.get_account(recipient);
        recipient_account.balance = recipient_account
            .balance
            .checked_add(amount)
            .ok_or_else(|| {
                CoreError::Overflow(format!(
                    "recipient balance overflow: {} + {}",
                    recipient_account.balance, amount
                ))
            })?;
        self.set_account(recipient, recipient_account);

        Ok(())
    }

    /// Apply block subsidy (coinbase). Only called by consensus for valid blocks.
    ///
    /// subsidy = min(BLOCK_REWARD_UNITS, MAX_SUPPLY - total_supply)
    /// If total_supply >= MAX_SUPPLY, subsidy = 0.
    pub fn apply_subsidy(&mut self, recipient: &Address, height: u32) -> Result<u64> {
        let subsidy = self.block_subsidy(height)?;

        if subsidy > 0 {
            let mut account = self.get_account(recipient);
            account.balance = account
                .balance
                .checked_add(subsidy)
                .ok_or_else(|| {
                    CoreError::Overflow(format!(
                        "coinbase overflow: {} + {}",
                        account.balance, subsidy
                    ))
                })?;
            self.set_account(recipient, account);
            self.total_supply = (self.total_supply as u128)
                .checked_add(subsidy as u128)
                .and_then(|v| u64::try_from(v).ok())
                .ok_or_else(|| CoreError::Overflow("total supply overflow".into()))?;
        }

        Ok(subsidy)
    }

    /// Calculate the block subsidy for a given height.
    /// Uses checked arithmetic against MAX_SUPPLY.
    pub fn block_subsidy(&self, _height: u32) -> Result<u64> {
        let remaining = MAX_SUPPLY_UNITS
            .checked_sub(self.total_supply as u128)
            .unwrap_or(0);

        if remaining == 0 {
            return Ok(0);
        }

        let subsidy = std::cmp::min(BLOCK_REWARD_UNITS as u128, remaining);
        u64::try_from(subsidy).map_err(|_| CoreError::Overflow("subsidy exceeds u64".into()))
    }
}

// ============================================================================
// Merkle Proofs
// ============================================================================

/// One sibling on a Merkle path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofStep {
    pub hash: Hash,
    /// True when the sibling sits to the right of the node being proved.
    pub sibling_on_right: bool,
}

/// A Merkle path from an account leaf to the state root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub account: Account,
    pub steps: Vec<ProofStep>,
}

impl MerkleProof {
    /// Recompute the root this proof implies for `address`.
    pub fn compute_root(&self, address: &Address) -> Hash {
        let mut current = State::leaf_hash(address.as_hash160().as_bytes(), &self.account);
        for step in &self.steps {
            current = if step.sibling_on_right {
                State::node_hash(&current, &step.hash)
            } else {
                State::node_hash(&step.hash, &current)
            };
        }
        current
    }

    /// Check the proof against a known state root.
    pub fn verify(&self, address: &Address, root: &Hash) -> bool {
        self.compute_root(address) == *root
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xAA;
        Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    fn bob() -> Address {
        let mut h = [0u8; 20];
        h[0] = 0xBB;
        Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    /// Distinct addresses for Merkle tree tests.
    fn test_address(n: u8) -> Address {
        let mut h = [0u8; 20];
        h[0] = n;
        h[1] = n.wrapping_mul(31);
        Address::from_hash160(chroma_core::hash::Hash160(h))
    }

    fn fund_account(state: &mut State, addr: &Address, amount: u64) {
        let mut acc = state.get_account(addr);
        acc.balance = amount;
        state.set_account(addr, acc);
        state.total_supply = state.total_supply.saturating_add(amount);
    }

    #[test]
    fn test_empty_state() {
        let state = State::new();
        let alice_addr = alice();
        assert_eq!(state.get_account(&alice_addr).balance, 0);
        assert_eq!(state.get_account(&alice_addr).nonce, 0);
        assert_eq!(state.total_supply(), 0);
    }

    #[test]
    fn test_apply_transaction_basic() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();

        assert_eq!(state.get_account(&alice_addr).balance, 9_000_000);
        assert_eq!(state.get_account(&alice_addr).nonce, 1);
        assert_eq!(state.get_account(&bob_addr).balance, 1_000_000);
    }

    #[test]
    fn test_supply_conservation() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);
        let supply_before = state.total_supply();

        state
            .apply_transaction(&alice_addr, &bob_addr, 3_333_333, 0)
            .unwrap();

        assert_eq!(state.total_supply(), supply_before, "supply must be conserved");
    }

    #[test]
    fn test_zero_amount_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 0, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 100);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 101, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InsufficientBalance(_)));
    }

    #[test]
    fn test_nonce_mismatch() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 5)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));
    }

    #[test]
    fn test_nonce_must_increment() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();

        // Replay with nonce=0 must fail
        let err = state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));

        // Must use nonce=1 now
        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 1)
            .unwrap();
        assert_eq!(state.get_account(&alice_addr).nonce, 2);
    }

    #[test]
    fn test_self_send_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let err = state
            .apply_transaction(&alice_addr, &alice_addr, 1_000_000, 0)
            .unwrap_err();
        assert!(matches!(err, CoreError::InvalidTransaction(_)));
    }

    #[test]
    fn test_block_subsidy_normal() {
        let state = State::new();
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, BLOCK_REWARD_UNITS);
    }

    #[test]
    fn test_block_subsidy_at_cap() {
        let mut state = State::new();
        state.total_supply = MAX_SUPPLY_UNITS as u64;
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, 0);
    }

    #[test]
    fn test_block_subsidy_near_cap() {
        let mut state = State::new();
        state.total_supply = (MAX_SUPPLY_UNITS - 500_000) as u64;
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, 500_000);
    }

    #[test]
    fn test_empty_state_root_is_zero() {
        // Spec §7.2: the empty root is 32 zero bytes. Genesis declares a zero
        // state root, so an empty state must agree with it.
        let state = State::new();
        assert_eq!(state.compute_state_root(), Hash::ZERO);
    }

    #[test]
    fn test_single_account_root_is_its_leaf() {
        let mut state = State::new();
        let addr = test_address(1);
        state.set_account(&addr, Account::new(500, 0));

        let expected = State::leaf_hash(addr.as_hash160().as_bytes(), &Account::new(500, 0));
        assert_eq!(state.compute_state_root(), expected);
    }

    #[test]
    fn test_root_changes_with_any_field() {
        let mut state = State::new();
        state.set_account(&test_address(1), Account::new(100, 0));
        let base = state.compute_state_root();

        let mut balance_changed = state.clone();
        balance_changed.set_account(&test_address(1), Account::new(101, 0));
        assert_ne!(balance_changed.compute_state_root(), base);

        let mut nonce_changed = state.clone();
        nonce_changed.set_account(&test_address(1), Account::new(100, 1));
        assert_ne!(nonce_changed.compute_state_root(), base);

        let mut key_added = state.clone();
        key_added.set_account(&test_address(2), Account::new(0, 0));
        assert_ne!(key_added.compute_state_root(), base);
    }

    #[test]
    fn test_root_is_independent_of_insertion_order() {
        let mut forwards = State::new();
        let mut backwards = State::new();
        for i in 0..7u8 {
            forwards.set_account(&test_address(i), Account::new(i as u64 * 10, i as u64));
        }
        for i in (0..7u8).rev() {
            backwards.set_account(&test_address(i), Account::new(i as u64 * 10, i as u64));
        }
        assert_eq!(forwards.compute_state_root(), backwards.compute_state_root());
    }

    #[test]
    fn test_merkle_proof_verifies_for_every_account() {
        // Odd counts exercise the promoted-node path at several levels.
        for count in 1..=9u8 {
            let mut state = State::new();
            for i in 0..count {
                state.set_account(&test_address(i), Account::new(i as u64 * 7 + 1, i as u64));
            }
            let root = state.compute_state_root();

            for i in 0..count {
                let addr = test_address(i);
                let proof = state
                    .merkle_proof(&addr)
                    .unwrap_or_else(|| panic!("no proof for account {} of {}", i, count));
                assert!(
                    proof.verify(&addr, &root),
                    "proof failed for account {} in a tree of {}",
                    i,
                    count
                );
            }
        }
    }

    #[test]
    fn test_merkle_proof_rejects_wrong_account_data() {
        let mut state = State::new();
        for i in 0..5u8 {
            state.set_account(&test_address(i), Account::new(i as u64 * 3, 0));
        }
        let root = state.compute_state_root();
        let addr = test_address(2);

        let mut tampered = state.merkle_proof(&addr).unwrap();
        tampered.account.balance += 1;
        assert!(
            !tampered.verify(&addr, &root),
            "a proof carrying the wrong balance must not verify"
        );

        // A proof for one account must not verify for another.
        let other = state.merkle_proof(&test_address(3)).unwrap();
        assert!(!other.verify(&addr, &root));
    }

    #[test]
    fn test_merkle_proof_absent_account() {
        let mut state = State::new();
        state.set_account(&test_address(1), Account::new(10, 0));
        assert!(state.merkle_proof(&test_address(9)).is_none());
    }

    #[test]
    fn test_proof_length_is_logarithmic() {
        let mut state = State::new();
        for i in 0..16u8 {
            state.set_account(&test_address(i), Account::new(i as u64, 0));
        }
        let proof = state.merkle_proof(&test_address(0)).unwrap();
        assert_eq!(proof.steps.len(), 4, "16 leaves should need log2(16) siblings");
    }

    #[test]
    fn test_state_root_deterministic() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        let root1 = state.compute_state_root();
        state
            .apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0)
            .unwrap();
        let root2 = state.compute_state_root();

        assert_ne!(root1, root2, "state root must change after transaction");
    }

    #[test]
    fn test_state_root_ordering() {
        // State root must be deterministic regardless of insertion order
        let mut state1 = State::new();
        let mut state2 = State::new();
        let alice_addr = alice();
        let bob_addr = bob();

        fund_account(&mut state1, &alice_addr, 10_000_000);
        fund_account(&mut state1, &bob_addr, 5_000_000);

        fund_account(&mut state2, &bob_addr, 5_000_000);
        fund_account(&mut state2, &alice_addr, 10_000_000);

        assert_eq!(
            state1.compute_state_root(),
            state2.compute_state_root(),
            "state root is order-independent (BTreeMap)"
        );
    }

    #[test]
    fn test_apply_multiple_transactions_sequential_nonces() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        for i in 0..5u64 {
            state.apply_transaction(&alice_addr, &bob_addr, 100_000, i).unwrap();
        }

        assert_eq!(state.get_account(&alice_addr).balance, 10_000_000 - 500_000);
        assert_eq!(state.get_account(&bob_addr).balance, 500_000);
        assert_eq!(state.get_account(&alice_addr).nonce, 5);
    }

    #[test]
    fn test_nonce_gap_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        // Skip nonce 0, try nonce 1
        let err = state.apply_transaction(&alice_addr, &bob_addr, 100_000, 1).unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));
    }

    #[test]
    fn test_double_nonce_rejected() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 10_000_000);

        state.apply_transaction(&alice_addr, &bob_addr, 100_000, 0).unwrap();
        let err = state.apply_transaction(&alice_addr, &bob_addr, 100_000, 0).unwrap_err();
        assert!(matches!(err, CoreError::InvalidNonce(_)));
    }

    #[test]
    fn test_exact_balance_transfer() {
        let mut state = State::new();
        let alice_addr = alice();
        let bob_addr = bob();
        fund_account(&mut state, &alice_addr, 1_000_000);

        state.apply_transaction(&alice_addr, &bob_addr, 1_000_000, 0).unwrap();

        assert_eq!(state.get_account(&alice_addr).balance, 0);
        assert_eq!(state.get_account(&bob_addr).balance, 1_000_000);
        assert_eq!(state.get_account(&alice_addr).nonce, 1);
    }

    #[test]
    fn test_subsidy_at_various_heights() {
        let state = State::new();
        // Subsidy should be constant regardless of height (until cap)
        for h in [0, 1, 100, 999999, u32::MAX] {
            assert_eq!(state.block_subsidy(h).unwrap(), BLOCK_REWARD_UNITS, "height {}", h);
        }
    }

    #[test]
    fn test_supply_cannot_exceed_max() {
        let mut state = State::new();
        state.total_supply = MAX_SUPPLY_UNITS as u64;
        let subsidy = state.block_subsidy(0).unwrap();
        assert_eq!(subsidy, 0, "no subsidy when at max supply");
    }

    #[test]
    fn test_zero_account_is_default() {
        let state = State::new();
        let addr = alice();
        let acc = state.get_account(&addr);
        assert_eq!(acc.balance, 0);
        assert_eq!(acc.nonce, 0);
    }

    #[test]
    fn test_fund_does_not_double_count_supply() {
        let mut state = State::new();
        let alice_addr = alice();
        fund_account(&mut state, &alice_addr, 500_000);
        assert_eq!(state.total_supply(), 500_000);
        fund_account(&mut state, &alice_addr, 500_000);
        assert_eq!(state.total_supply(), 1_000_000);
    }

    #[test]
    fn test_many_accounts_state_root() {
        let mut state = State::new();
        for i in 0..100u8 {
            let mut h = [0u8; 20];
            h[0] = i;
            let addr = Address::from_hash160(chroma_core::hash::Hash160(h));
            fund_account(&mut state, &addr, 1_000_000);
        }
        let root = state.compute_state_root();
        assert_ne!(root, Hash::ZERO);
        // Same state → same root
        assert_eq!(root, state.compute_state_root());
    }

    #[test]
    fn test_apply_subsidy_increases_total_supply() {
        let mut state = State::new();
        let alice_addr = alice();
        state.apply_subsidy(&alice_addr, 0).unwrap();
        assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS);
        state.apply_subsidy(&alice_addr, 1).unwrap();
        assert_eq!(state.total_supply(), BLOCK_REWARD_UNITS * 2);
    }

    #[test]
    fn test_apply_subsidy_creates_account() {
        let mut state = State::new();
        let alice_addr = alice();
        state.apply_subsidy(&alice_addr, 0).unwrap();
        assert_eq!(state.get_account(&alice_addr).balance, BLOCK_REWARD_UNITS);
    }
}
