//! The pending-transaction pool, and the resource limits that keep it from
//! being filled by whoever wants to.
//!
//! Chroma has no fees, so there is no price to raise when the pool is in
//! demand and no payment to charge for a slot in it. What replaces that is
//! written up in `protocol/MEMPOOL.md`; the part implemented here is its
//! centre. Every entry is charged to the address group that delivered it
//! (§6.1), and one group may hold only a fraction of the pool.
//!
//! The account a transaction claims to come from is *not* what anything is
//! counted under. Accounts come from `getrandom`, so a limit per account is
//! not a limit at all: whoever it would bind simply holds more accounts.
//! Address groups have to be obtained.

use std::collections::HashMap;

use chroma_core::hash::Hash;
use chroma_core::serialize::CanonicalEncode;
use chroma_core::types::Address;
use chroma_state::State;
use chroma_tx::Transaction;

use crate::peer::{AddressGroup, MAX_INBOUND_PEERS, MAX_OUTBOUND_PEERS};

pub const MAX_MEMPOOL_SIZE: usize = 50_000_000;
pub const MAX_MEMPOOL_TXS: usize = 100_000;

/// Entries one address group may hold at once.
///
/// An even share of the pool per connection the node will ever have. An
/// attacker holding every inbound slot therefore reaches
/// `MAX_INBOUND_PEERS / (MAX_INBOUND_PEERS + MAX_OUTBOUND_PEERS)` of the pool
/// and no more, however many accounts they send from — the outbound slots are
/// ones we dialled ourselves.
pub const QUOTA_PER_SOURCE: usize = MAX_MEMPOOL_TXS / (MAX_INBOUND_PEERS + MAX_OUTBOUND_PEERS);

/// How long an entry may sit before it is dropped.
///
/// With no fees nothing is stuck for being too cheap, but a transaction whose
/// sender advanced their nonce by another route will never be mined, and
/// there is no reason to hold it forever.
pub const EXPIRY_SECS: u64 = 3600;

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub tx_hash: Hash,
    pub size: usize,
    /// Unix seconds, for expiry. Was previously always zero, which made
    /// expiry impossible to implement on top of it.
    pub added_at: u64,
    /// Whose quota this entry counts against.
    pub source: AddressGroup,
    /// Cached so removal can maintain the per-sender totals without
    /// recovering the address from the public key again.
    pub sender: Address,
}

/// What the pool already holds for one sender, so effective state can be
/// computed without walking every entry.
#[derive(Clone, Copy, Debug, Default)]
struct Pending {
    count: u64,
    spent: u64,
}

/// Why a transaction was not taken.
///
/// A dedicated type rather than a string: the caller decides which of these
/// deserve a peer penalty, and that decision should not be made by matching
/// on error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// A coinbase never belongs in the pool.
    Coinbase,
    /// The delivering group is already holding its share.
    SourceQuotaFull,
    /// The sender has no account, or an empty one.
    UnfundedSender,
    /// Already spent: below the sender's next nonce.
    NonceTooLow,
    /// Ahead of the sender's next nonce. Gaps are not queued.
    NonceTooHigh,
    /// More than the sender can still pay, counting what is already pending.
    InsufficientBalance,
    /// The signature does not verify.
    BadSignature,
    /// The pool is full and this transaction is not worth evicting for.
    Full,
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Rejection::Coinbase => "coinbase",
            Rejection::SourceQuotaFull => "source quota full",
            Rejection::UnfundedSender => "unfunded sender",
            Rejection::NonceTooLow => "nonce too low",
            Rejection::NonceTooHigh => "nonce too high",
            Rejection::InsufficientBalance => "insufficient balance",
            Rejection::BadSignature => "bad signature",
            Rejection::Full => "mempool full",
        };
        f.write_str(reason)
    }
}

impl Rejection {
    /// Whether a peer sending this deserves a mark against it.
    ///
    /// A transaction that lost a race — its nonce taken by another, its
    /// balance spent by another — is not misbehaviour: a peer relaying in
    /// good faith produces those constantly. A malformed or unsigned one, or
    /// one from an account with nothing in it, is not something an honest
    /// peer relays.
    pub fn is_misbehaviour(&self) -> bool {
        matches!(
            self,
            Rejection::Coinbase | Rejection::BadSignature | Rejection::UnfundedSender
        )
    }
}

/// What happened to a transaction the pool was offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Newly held. Worth relaying.
    Accepted,
    /// Already held. Not an error, and not worth relaying again.
    Duplicate,
}

pub struct Mempool {
    entries: HashMap<Hash, MempoolEntry>,
    tx_order: Vec<Hash>,
    total_size: usize,
    /// Entries held per delivering group. The quota is enforced against this.
    per_source: HashMap<AddressGroup, usize>,
    /// Pending count and outstanding spend per sender, for effective state.
    per_sender: HashMap<Address, Pending>,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            entries: HashMap::new(),
            tx_order: Vec::new(),
            total_size: 0,
            per_source: HashMap::new(),
            per_sender: HashMap::new(),
        }
    }

    /// The nonce the sender's next transaction must carry, counting what the
    /// pool already holds for them.
    ///
    /// Judging against committed state alone would reject every sender's
    /// second pending transaction, since the first has not been mined yet.
    pub fn effective_nonce(&self, state: &State, sender: &Address) -> u64 {
        let committed = state.get_account(sender).nonce;
        let pending = self.per_sender.get(sender).map(|p| p.count).unwrap_or(0);
        committed.saturating_add(pending)
    }

    /// What the sender can still spend, after what the pool already holds.
    ///
    /// Committed balance alone would let a set of pending transactions add up
    /// to more than the sender has.
    pub fn effective_balance(&self, state: &State, sender: &Address) -> u64 {
        let committed = state.get_account(sender).balance;
        let pending = self.per_sender.get(sender).map(|p| p.spent).unwrap_or(0);
        committed.saturating_sub(pending)
    }

    /// Entries currently charged to `source`.
    pub fn held_by(&self, source: AddressGroup) -> usize {
        self.per_source.get(&source).copied().unwrap_or(0)
    }

    /// Offer a transaction to the pool.
    ///
    /// The checks run cheapest first, and the signature check runs last on
    /// purpose. A state lookup is a hash-map hit; verifying a Schnorr
    /// signature is around fifty microseconds, a thousand times more. Ordered
    /// the other way — which is how this used to be wired — a sender with no
    /// balance still costs a verification. Ordered this way they do not.
    ///
    /// Nothing is weakened by the order: every check before the signature
    /// reads only the sender's own public state, which anyone can look up
    /// anyway, and a transaction that fails the signature is still refused.
    pub fn add_transaction(
        &mut self,
        tx: Transaction,
        source: AddressGroup,
        state: &State,
        now: u64,
    ) -> Result<Admission, Rejection> {
        if tx.is_coinbase() {
            return Err(Rejection::Coinbase);
        }

        let encoded = tx.encode();
        let tx_hash = Hash::blake3(&encoded);
        if self.entries.contains_key(&tx_hash) {
            return Ok(Admission::Duplicate);
        }

        if self.held_by(source) >= QUOTA_PER_SOURCE {
            return Err(Rejection::SourceQuotaFull);
        }

        let sender = tx.sender_address();
        let account = state.get_account(&sender);
        if !state.has_account(&sender) || account.balance == 0 {
            return Err(Rejection::UnfundedSender);
        }

        let expected = self.effective_nonce(state, &sender);
        match tx.nonce.0.cmp(&expected) {
            std::cmp::Ordering::Less => return Err(Rejection::NonceTooLow),
            std::cmp::Ordering::Greater => return Err(Rejection::NonceTooHigh),
            std::cmp::Ordering::Equal => {}
        }

        if tx.amount.0 > self.effective_balance(state, &sender) {
            return Err(Rejection::InsufficientBalance);
        }

        if !tx.verify_signature() {
            return Err(Rejection::BadSignature);
        }

        let size = encoded.len();
        while self.tx_order.len() >= MAX_MEMPOOL_TXS
            || self.total_size + size > MAX_MEMPOOL_SIZE
        {
            if !self.evict_for(source) {
                return Err(Rejection::Full);
            }
        }

        let entry = MempoolEntry {
            tx,
            tx_hash,
            size,
            added_at: now,
            source,
            sender,
        };
        self.charge(&entry);
        self.total_size += size;
        self.tx_order.push(tx_hash);
        self.entries.insert(tx_hash, entry);
        Ok(Admission::Accepted)
    }

    /// Make room for an arrival from `incoming`, if there is anything that
    /// should give way to it.
    ///
    /// The entry dropped is the newest one held by whichever group holds the
    /// most. Newest because a sender's pending transactions are a nonce
    /// sequence and dropping from the middle strands the rest; by largest
    /// holder because that is the group whose share is furthest above even.
    ///
    /// Returns false when the arrival's own group is already the largest
    /// holder, in which case there is nothing to gain by evicting.
    fn evict_for(&mut self, incoming: AddressGroup) -> bool {
        let largest = self
            .per_source
            .iter()
            .max_by_key(|(group, count)| (**count, std::cmp::Reverse(**group == incoming)))
            .map(|(group, count)| (*group, *count));

        let (group, count) = match largest {
            Some(v) => v,
            None => return false,
        };
        if group == incoming || count <= self.held_by(incoming) {
            return false;
        }

        let victim = self
            .tx_order
            .iter()
            .rev()
            .find(|hash| {
                self.entries
                    .get(*hash)
                    .map(|e| e.source == group)
                    .unwrap_or(false)
            })
            .copied();

        match victim {
            Some(hash) => self.remove_transaction(&hash),
            None => false,
        }
    }

    /// Drop everything older than `EXPIRY_SECS`.
    pub fn expire(&mut self, now: u64) -> usize {
        let stale: Vec<Hash> = self
            .entries
            .values()
            .filter(|e| now.saturating_sub(e.added_at) > EXPIRY_SECS)
            .map(|e| e.tx_hash)
            .collect();
        for hash in &stale {
            self.remove_transaction(hash);
        }
        stale.len()
    }

    fn charge(&mut self, entry: &MempoolEntry) {
        *self.per_source.entry(entry.source).or_insert(0) += 1;
        let pending = self.per_sender.entry(entry.sender).or_default();
        pending.count = pending.count.saturating_add(1);
        pending.spent = pending.spent.saturating_add(entry.tx.amount.0);
    }

    fn discharge(&mut self, entry: &MempoolEntry) {
        if let Some(count) = self.per_source.get_mut(&entry.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_source.remove(&entry.source);
            }
        }
        if let Some(pending) = self.per_sender.get_mut(&entry.sender) {
            pending.count = pending.count.saturating_sub(1);
            pending.spent = pending.spent.saturating_sub(entry.tx.amount.0);
            if pending.count == 0 {
                self.per_sender.remove(&entry.sender);
            }
        }
    }

    pub fn remove_transaction(&mut self, hash: &Hash) -> bool {
        if let Some(entry) = self.entries.remove(hash) {
            self.total_size -= entry.size;
            self.tx_order.retain(|h| *h != *hash);
            self.discharge(&entry);
            true
        } else {
            false
        }
    }

    pub fn has_transaction(&self, hash: &Hash) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn get_transaction(&self, hash: &Hash) -> Option<&Transaction> {
        self.entries.get(hash).map(|e| &e.tx)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn size(&self) -> usize {
        self.total_size
    }

    pub fn transaction_hashes(&self) -> Vec<Hash> {
        self.tx_order.clone()
    }

    pub fn transactions(&self) -> Vec<&Transaction> {
        self.tx_order
            .iter()
            .filter_map(|h| self.entries.get(h).map(|e| &e.tx))
            .collect()
    }

    pub fn remove_transactions(&mut self, hashes: &[Hash]) {
        for hash in hashes {
            self.remove_transaction(hash);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.tx_order.clear();
        self.total_size = 0;
        self.per_source.clear();
        self.per_sender.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::hash::Hash160;
    use chroma_core::types::{Amount, Nonce};
    use chroma_crypto::hash::hash160;
    use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
    use chroma_state::Account;

    fn account_of(seed: u8) -> (SecretKey32, Address) {
        let secret = SecretKey32::from_bytes([seed; 32]).unwrap();
        let pubkey = PublicKey32::from_secret(&secret).unwrap();
        (secret, Address::from_hash160(Hash160(hash160(&pubkey.0))))
    }

    fn funded(seed: u8, balance: u64) -> (SecretKey32, Address, State) {
        let (secret, address) = account_of(seed);
        let mut state = State::new();
        state.restore_account(&address, Account::new(balance, 0));
        (secret, address, state)
    }

    fn tx_from(secret: &SecretKey32, from: Address, amount: u64, nonce: u64) -> Transaction {
        let to = Address::from_hash160(Hash160([0x99; 20]));
        chroma_tx::create_transaction(secret, from, to, Amount(amount), Nonce(nonce)).unwrap()
    }

    fn group(n: u8) -> AddressGroup {
        AddressGroup::V4([203, 0, n])
    }

    #[test]
    fn test_empty_mempool() {
        let pool = Mempool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_has_nonexistent() {
        let pool = Mempool::new();
        assert!(!pool.has_transaction(&Hash::blake3(b"nope")));
        assert!(pool.get_transaction(&Hash::blake3(b"nope")).is_none());
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut pool = Mempool::new();
        assert!(!pool.remove_transaction(&Hash::blake3(b"nope")));
    }

    #[test]
    fn test_clear_empty() {
        let mut pool = Mempool::new();
        pool.clear();
        assert!(pool.is_empty());
    }

    #[test]
    fn test_transaction_hashes_empty() {
        let pool = Mempool::new();
        assert!(pool.transaction_hashes().is_empty());
    }

    #[test]
    fn test_transactions_empty() {
        let pool = Mempool::new();
        assert!(pool.transactions().is_empty());
    }

    #[test]
    fn test_remove_transactions_empty() {
        let mut pool = Mempool::new();
        pool.remove_transactions(&[]);
        assert!(pool.is_empty());
    }

    #[test]
    fn a_funded_sender_is_accepted() {
        let (secret, sender, state) = funded(0x11, 1_000);
        let mut pool = Mempool::new();
        let tx = tx_from(&secret, sender, 100, 0);
        assert_eq!(
            pool.add_transaction(tx, group(1), &state, 0),
            Ok(Admission::Accepted)
        );
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.held_by(group(1)), 1);
    }

    #[test]
    fn an_empty_account_is_refused_before_its_signature_is_checked() {
        // The whole point of the check order. This transaction carries a
        // signature that cannot verify; if the signature were checked first
        // the answer would be BadSignature, and every flood of garbage from
        // accounts with nothing in them would cost a verification each.
        let (secret, sender) = account_of(0x12);
        let state = State::new();
        let mut pool = Mempool::new();
        let mut tx = tx_from(&secret, sender, 100, 0);
        tx.signature.0[0] ^= 0xFF;

        assert_eq!(
            pool.add_transaction(tx, group(1), &state, 0),
            Err(Rejection::UnfundedSender)
        );
    }

    #[test]
    fn a_bad_signature_from_a_funded_account_is_still_refused() {
        let (secret, sender, state) = funded(0x13, 1_000);
        let mut pool = Mempool::new();
        let mut tx = tx_from(&secret, sender, 100, 0);
        tx.signature.0[0] ^= 0xFF;

        assert_eq!(
            pool.add_transaction(tx, group(1), &state, 0),
            Err(Rejection::BadSignature)
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn a_second_transaction_from_one_sender_is_judged_against_the_first() {
        // Against committed state the second would look like a repeated nonce
        // and be refused, because the first has not been mined.
        let (secret, sender, state) = funded(0x14, 1_000);
        let mut pool = Mempool::new();

        pool.add_transaction(tx_from(&secret, sender, 100, 0), group(1), &state, 0)
            .unwrap();
        assert_eq!(pool.effective_nonce(&state, &sender), 1);
        assert_eq!(pool.effective_balance(&state, &sender), 900);

        assert_eq!(
            pool.add_transaction(tx_from(&secret, sender, 100, 1), group(1), &state, 0),
            Ok(Admission::Accepted)
        );
    }

    #[test]
    fn pending_spending_cannot_exceed_the_balance() {
        let (secret, sender, state) = funded(0x15, 1_000);
        let mut pool = Mempool::new();

        pool.add_transaction(tx_from(&secret, sender, 900, 0), group(1), &state, 0)
            .unwrap();
        assert_eq!(
            pool.add_transaction(tx_from(&secret, sender, 200, 1), group(1), &state, 0),
            Err(Rejection::InsufficientBalance),
            "committed balance covers it; what is already pending does not"
        );
    }

    #[test]
    fn a_nonce_gap_is_not_queued() {
        let (secret, sender, state) = funded(0x16, 1_000);
        let mut pool = Mempool::new();
        assert_eq!(
            pool.add_transaction(tx_from(&secret, sender, 100, 5), group(1), &state, 0),
            Err(Rejection::NonceTooHigh)
        );
    }

    #[test]
    fn resending_is_not_an_error() {
        let (secret, sender, state) = funded(0x17, 1_000);
        let mut pool = Mempool::new();
        let tx = tx_from(&secret, sender, 100, 0);
        pool.add_transaction(tx.clone(), group(1), &state, 0).unwrap();
        assert_eq!(
            pool.add_transaction(tx, group(1), &state, 0),
            Ok(Admission::Duplicate)
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn a_coinbase_never_enters_the_pool() {
        let state = State::new();
        let mut pool = Mempool::new();
        let coinbase =
            Transaction::coinbase(Address::from_hash160(Hash160([1; 20])), Amount(1_000_000));
        assert_eq!(
            pool.add_transaction(coinbase, group(1), &state, 0),
            Err(Rejection::Coinbase)
        );
    }

    #[test]
    fn removing_an_entry_gives_back_its_sender_and_source_totals() {
        let (secret, sender, state) = funded(0x18, 1_000);
        let mut pool = Mempool::new();
        let tx = tx_from(&secret, sender, 100, 0);
        let hash = Hash::blake3(&tx.encode());
        pool.add_transaction(tx, group(1), &state, 0).unwrap();

        assert!(pool.remove_transaction(&hash));
        assert_eq!(pool.held_by(group(1)), 0);
        assert_eq!(pool.effective_nonce(&state, &sender), 0);
        assert_eq!(pool.effective_balance(&state, &sender), 1_000);
    }

    #[test]
    fn one_source_cannot_take_more_than_its_quota() {
        // However many accounts it sends from. Two here, so the result cannot
        // be mistaken for a per-account limit.
        let (first_secret, first) = account_of(0x21);
        let (second_secret, second) = account_of(0x22);
        let mut state = State::new();
        state.restore_account(&first, Account::new(1_000_000_000, 0));
        state.restore_account(&second, Account::new(1_000_000_000, 0));

        let mut pool = Mempool::new();
        let mut accepted = 0usize;
        for n in 0..QUOTA_PER_SOURCE as u64 {
            let (secret, sender) = if n % 2 == 0 {
                (&first_secret, first)
            } else {
                (&second_secret, second)
            };
            let tx = tx_from(secret, sender, 1, n / 2);
            match pool.add_transaction(tx, group(1), &state, 0) {
                Ok(Admission::Accepted) => accepted += 1,
                other => panic!("rejected at {}: {:?}", n, other),
            }
        }
        assert_eq!(accepted, QUOTA_PER_SOURCE);

        let overflow = tx_from(&first_secret, first, 1, QUOTA_PER_SOURCE as u64 / 2);
        assert_eq!(
            pool.add_transaction(overflow, group(1), &state, 0),
            Err(Rejection::SourceQuotaFull)
        );
    }

    #[test]
    fn a_different_source_still_has_room() {
        let (secret, sender, state) = funded(0x23, 1_000_000);
        let mut pool = Mempool::new();
        for n in 0..3u64 {
            pool.add_transaction(tx_from(&secret, sender, 1, n), group(1), &state, 0)
                .unwrap();
        }
        let (other_secret, other) = account_of(0x24);
        let mut state = state;
        state.restore_account(&other, Account::new(1_000, 0));

        assert_eq!(
            pool.add_transaction(tx_from(&other_secret, other, 1, 0), group(2), &state, 0),
            Ok(Admission::Accepted)
        );
        assert_eq!(pool.held_by(group(1)), 3);
        assert_eq!(pool.held_by(group(2)), 1);
    }

    #[test]
    fn stale_entries_are_dropped() {
        let (secret, sender, state) = funded(0x25, 1_000);
        let mut pool = Mempool::new();
        pool.add_transaction(tx_from(&secret, sender, 100, 0), group(1), &state, 100)
            .unwrap();

        assert_eq!(pool.expire(100 + EXPIRY_SECS), 0, "not yet stale");
        assert_eq!(pool.expire(100 + EXPIRY_SECS + 1), 1);
        assert!(pool.is_empty());
        assert_eq!(pool.held_by(group(1)), 0);
    }

    #[test]
    fn the_quota_is_a_share_of_the_pool() {
        let sources = MAX_INBOUND_PEERS + MAX_OUTBOUND_PEERS;
        assert!(
            QUOTA_PER_SOURCE * sources <= MAX_MEMPOOL_TXS,
            "every source at its quota must still fit in the pool"
        );
        assert!(
            QUOTA_PER_SOURCE * sources > MAX_MEMPOOL_TXS - sources,
            "and should not be wasteful about it"
        );

        // What an attacker holding every inbound slot can reach. The outbound
        // slots are ones we dialled, so they are not theirs to take.
        let reachable = QUOTA_PER_SOURCE * MAX_INBOUND_PEERS;
        assert!(
            reachable < MAX_MEMPOOL_TXS * 3 / 4,
            "taking every inbound slot should not come close to the whole pool"
        );
    }
}
