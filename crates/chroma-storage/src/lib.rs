//! Chroma Storage
//!
//! sled-based persistence for blocks, chain state, and account data.
//!
//! ## Database Schema
//!
//! - `headers:{height:u32}` → serialized BlockHeader
//! - `blocks:{hash:32}` → serialized full Block
//! - `hash_to_height:{hash:32}` → height as u32 LE
//! - `tip` → serialized ChainTip metadata
//! - `accounts:{address:20}` → account data (balance_le64 || nonce_le64)
//! - `supply` → total supply as u64 LE
//! - `meta:{key}` → arbitrary metadata

use std::path::Path;

use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::serialize::{CanonicalDecode, CanonicalEncode};
use chroma_core::types::Address;
use chroma_block::Block;
use chroma_state::{Account, State};

// ============================================================================
// Storage Keys
// ============================================================================

fn header_key(height: u32) -> Vec<u8> {
    let mut key = b"headers:".to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn block_key(hash: &Hash) -> Vec<u8> {
    let mut key = b"blocks:".to_vec();
    key.extend_from_slice(hash.as_bytes());
    key
}

fn hash_to_height_key(hash: &Hash) -> Vec<u8> {
    let mut key = b"hash_to_height:".to_vec();
    key.extend_from_slice(hash.as_bytes());
    key
}

/// Big-endian height so the index iterates in chain order.
fn height_to_hash_key(height: u32) -> Vec<u8> {
    let mut key = b"height_to_hash:".to_vec();
    key.extend_from_slice(&height.to_be_bytes());
    key
}

fn account_key(address: &Address) -> Vec<u8> {
    let mut key = b"accounts:".to_vec();
    key.extend_from_slice(address.as_hash160().as_bytes());
    key
}

/// Where a transaction sits, keyed by its hash.
///
/// The value names the **block hash**, never the height. That one choice is
/// what keeps this index out of the reorg path: a block that loses a fork is
/// still a block we hold, so the entry never becomes wrong — it merely points
/// at something that is no longer on the active chain, which the existing
/// height/hash pair answers on its own. An index keyed by height would have to
/// be rewritten on every reorg, and every rewrite is a chance for the index
/// and the chain to disagree.
fn tx_index_key(tx_hash: &Hash) -> Vec<u8> {
    let mut key = b"txindex:".to_vec();
    key.extend_from_slice(tx_hash.as_bytes());
    key
}

/// One address's involvement in one transaction.
///
/// Keyed by block hash for the same reason as [`tx_index_key`]. Ordering is
/// not in the key, so a history read sorts what it finds; the alternative —
/// putting the height in the key to get chain order for free — brings back
/// the rewrite-on-reorg this design exists to avoid.
fn tx_address_key(address: &Address, block_hash: &Hash, position: u32) -> Vec<u8> {
    let mut key = b"txaddr:".to_vec();
    key.extend_from_slice(address.as_hash160().as_bytes());
    key.extend_from_slice(block_hash.as_bytes());
    key.extend_from_slice(&position.to_be_bytes());
    key
}

fn tx_address_prefix(address: &Address) -> Vec<u8> {
    let mut key = b"txaddr:".to_vec();
    key.extend_from_slice(address.as_hash160().as_bytes());
    key
}

const TIP_KEY: &[u8] = b"tip";
/// Active-chain height the transaction index has been walked to.
///
/// Without it, a database that ran for a while with indexing off has holes,
/// and a lookup cannot tell "no such transaction" from "never indexed". The
/// difference matters enough to keep one number for it.
const INDEXED_THROUGH_KEY: &[u8] = b"indexed_through";
const SUPPLY_KEY: &[u8] = b"supply";
const GENESIS_HASH_KEY: &[u8] = b"genesis_hash";

// ============================================================================
// Chain Tip Metadata
// ============================================================================

/// One transaction as the index holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexedTx {
    pub tx_hash: Hash,
    pub block_hash: Hash,
    pub height: u32,
    /// Where in the block it sits. Position 0 is the coinbase.
    pub position: u32,
}

/// Persisted chain tip metadata.
#[derive(Clone, Debug)]
pub struct PersistedTip {
    pub height: u32,
    pub hash: Hash,
    pub cumulative_work: [u8; 32],
    pub supply: u64,
}

impl CanonicalEncode for PersistedTip {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 32 + 32 + 8);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(self.hash.as_bytes());
        buf.extend_from_slice(&self.cumulative_work);
        buf.extend_from_slice(&self.supply.to_le_bytes());
        buf
    }
}

impl CanonicalDecode for PersistedTip {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 76 {
            return Err(CoreError::Serialization("persisted tip too short".to_string()));
        }
        let height = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[4..36]);
        let mut work = [0u8; 32];
        work.copy_from_slice(&data[36..68]);
        let supply = u64::from_le_bytes([
            data[68], data[69], data[70], data[71],
            data[72], data[73], data[74], data[75],
        ]);
        Ok(PersistedTip {
            height,
            hash: Hash::from_bytes(hash),
            cumulative_work: work,
            supply,
        })
    }

    fn decode_partial(data: &[u8]) -> Result<(Self, usize)> {
        let tip = PersistedTip::decode(data)?;
        Ok((tip, 76))
    }
}

// ============================================================================
// Storage
// ============================================================================

/// Persistent blockchain storage backed by sled.
pub struct Storage {
    db: sled::Db,
    #[allow(dead_code)]
    path: Option<std::path::PathBuf>,
}

impl Storage {
    /// Open or create a storage database at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref().to_path_buf();
        let db = sled::Config::new()
            .path(&p)
            .open()
            .map_err(|e| CoreError::Storage(format!("failed to open database: {}", e)))?;
        Ok(Storage { db, path: Some(p) })
    }

    /// Open a temporary database for testing.
    pub fn open_temporary() -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::current_dir()
            .unwrap_or_default()
            .join("test_dbs");
        let dir = base.join(format!("sled_{}", id));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| {
            CoreError::Storage(format!("failed to create test dir: {}", e))
        })?;
        let db = sled::Config::new()
            .path(&dir)
            .open()
            .map_err(|e| CoreError::Storage(format!("failed to open temp database: {}", e)))?;
        Ok(Storage { db, path: Some(dir) })
    }

    // ========================================================================
    // Block Headers
    // ========================================================================

    /// Store a block header at its height.
    pub fn put_header(&self, height: u32, header: &chroma_block::BlockHeader) -> Result<()> {
        let key = header_key(height);
        let encoded = header.encode();
        self.db
            .insert(&key, encoded)
            .map_err(|e| CoreError::Storage(format!("put_header: {}", e)))?;
        Ok(())
    }

    /// Retrieve a block header by height.
    pub fn get_header(&self, height: u32) -> Result<Option<chroma_block::BlockHeader>> {
        let key = header_key(height);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_header: {}", e)))?
        {
            Some(data) => {
                let header = chroma_block::BlockHeader::decode(&data)?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Check if a header exists at the given height.
    pub fn has_header(&self, height: u32) -> Result<bool> {
        let key = header_key(height);
        self.db
            .contains_key(&key)
            .map_err(|e| CoreError::Storage(format!("has_header: {}", e)))
    }

    // ========================================================================
    // Full Blocks
    // ========================================================================

    /// Store a full block, keyed by its hash.
    pub fn put_block(&self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let key = block_key(&hash);
        let encoded = block.encode_block();
        self.db
            .insert(&key, encoded)
            .map_err(|e| CoreError::Storage(format!("put_block: {}", e)))?;

        // Also store hash→height mapping. This one belongs to the block
        // itself — a block's height is part of it — so it is safe to write for
        // any block we hold.
        let height_key = hash_to_height_key(&hash);
        self.db
            .insert(height_key, block.header.height.0.to_le_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_block height mapping: {}", e)))?;

        // The reverse index is deliberately not written here. It names the
        // active chain's block at a height, and blocks are stored before
        // anyone knows whether they will be on the active chain — a losing
        // branch is stored precisely so a later reorg can replay it. Writing
        // it here let a side branch repoint the height at itself.
        // [`Storage::mark_active`] is where that happens.
        Ok(())
    }

    /// Retrieve the block hash stored at a height on the active chain.
    pub fn get_hash_for_height(&self, height: u32) -> Result<Option<Hash>> {
        match self
            .db
            .get(height_to_hash_key(height))
            .map_err(|e| CoreError::Storage(format!("get_hash_for_height: {}", e)))?
        {
            Some(data) => {
                let hash = Hash::from_slice(&data)
                    .map_err(|e| CoreError::Storage(format!("hash index: {}", e)))?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }

    /// Point the height index at `hash`, replacing whatever was there.
    ///
    /// A reorg reuses heights, so the index must be rewritten for the new
    /// branch rather than only appended to.
    pub fn set_hash_for_height(&self, height: u32, hash: &Hash) -> Result<()> {
        self.db
            .insert(height_to_hash_key(height), hash.as_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("set_hash_for_height: {}", e)))?;
        Ok(())
    }

    /// Retrieve a full block by its hash.
    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>> {
        let key = block_key(hash);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_block: {}", e)))?
        {
            Some(data) => {
                let block = Block::decode_block(&data)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// Retrieve the height for a block hash.
    pub fn get_height_for_hash(&self, hash: &Hash) -> Result<Option<u32>> {
        let key = hash_to_height_key(hash);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_height_for_hash: {}", e)))?
        {
            Some(data) => {
                if data.len() < 4 {
                    return Err(CoreError::Storage("invalid height data".to_string()));
                }
                let height = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(Some(height))
            }
            None => Ok(None),
        }
    }

    /// Get the block stored at a height on the active chain.
    ///
    /// Uses the height→hash index; previously this scanned every
    /// `hash_to_height` entry in the database on each lookup, which made
    /// serving a range of blocks quadratic in chain length.
    pub fn get_block_by_height(&self, height: u32) -> Result<Option<Block>> {
        match self.get_hash_for_height(height)? {
            Some(hash) => self.get_block_by_hash(&hash),
            None => Ok(None),
        }
    }

    // ========================================================================
    // Chain Tip
    // ========================================================================

    /// Store the chain tip metadata.
    pub fn put_tip(&self, tip: &PersistedTip) -> Result<()> {
        let encoded = tip.encode();
        self.db
            .insert(TIP_KEY, encoded)
            .map_err(|e| CoreError::Storage(format!("put_tip: {}", e)))?;
        Ok(())
    }

    /// Retrieve the chain tip metadata.
    pub fn get_tip(&self) -> Result<Option<PersistedTip>> {
        match self
            .db
            .get(TIP_KEY)
            .map_err(|e| CoreError::Storage(format!("get_tip: {}", e)))?
        {
            Some(data) => {
                let tip = PersistedTip::decode(&data)?;
                Ok(Some(tip))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Account State
    // ========================================================================

    /// Store an account.
    pub fn put_account(&self, address: &Address, account: &Account) -> Result<()> {
        let key = account_key(address);
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&account.balance.to_le_bytes());
        data.extend_from_slice(&account.nonce.to_le_bytes());
        self.db
            .insert(&key, data)
            .map_err(|e| CoreError::Storage(format!("put_account: {}", e)))?;
        Ok(())
    }

    /// Retrieve an account.
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = account_key(address);
        match self
            .db
            .get(&key)
            .map_err(|e| CoreError::Storage(format!("get_account: {}", e)))?
        {
            Some(data) => {
                if data.len() != 16 {
                    return Err(CoreError::Storage(format!(
                        "account data: expected 16 bytes, got {}",
                        data.len()
                    )));
                }
                let balance = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                let nonce = u64::from_le_bytes([
                    data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
                ]);
                Ok(Some(Account { balance, nonce }))
            }
            None => Ok(None),
        }
    }

    /// Store the total supply.
    pub fn put_supply(&self, supply: u64) -> Result<()> {
        self.db
            .insert(SUPPLY_KEY, supply.to_le_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_supply: {}", e)))?;
        Ok(())
    }

    /// Retrieve the total supply.
    pub fn get_supply(&self) -> Result<u64> {
        match self
            .db
            .get(SUPPLY_KEY)
            .map_err(|e| CoreError::Storage(format!("get_supply: {}", e)))?
        {
            Some(data) => {
                if data.len() < 8 {
                    return Err(CoreError::Storage("supply data too short".to_string()));
                }
                Ok(u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]))
            }
            None => Ok(0),
        }
    }

    /// Store the genesis block hash.
    pub fn put_genesis_hash(&self, hash: &Hash) -> Result<()> {
        self.db
            .insert(GENESIS_HASH_KEY, hash.as_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_genesis_hash: {}", e)))?;
        Ok(())
    }

    /// Retrieve the genesis block hash.
    pub fn get_genesis_hash(&self) -> Result<Option<Hash>> {
        match self
            .db
            .get(GENESIS_HASH_KEY)
            .map_err(|e| CoreError::Storage(format!("get_genesis_hash: {}", e)))?
        {
            Some(data) => {
                if data.len() < 32 {
                    return Err(CoreError::Storage("genesis hash too short".to_string()));
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&data[..32]);
                Ok(Some(Hash::from_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Batch Operations
    // ========================================================================

    /// Record that a block is the active chain's block at its height.
    ///
    /// The height-keyed records — the header and the height→hash index —
    /// describe the active chain, not everything we have stored. Two blocks
    /// can exist at one height; only one of them is the answer to "what is at
    /// height H", and the caller is the only one that knows which. A reorg
    /// rewrites these for every height it moved.
    pub fn mark_active(&self, block: &Block) -> Result<()> {
        let height = block.header.height.0;
        self.put_header(height, &block.header)?;
        self.set_hash_for_height(height, &block.hash())?;
        Ok(())
    }

    /// Forget the active-chain records above `height`.
    ///
    /// A reorg can move the tip to a chain that is shorter than the one it
    /// replaced, since fork choice is on work and not on length. The heights
    /// past the new tip would otherwise keep answering with blocks from the
    /// chain that lost. The blocks themselves are left alone: they are still
    /// reachable by hash, and a later reorg may need to replay them.
    ///
    /// Walks up from `height + 1` and stops at the first height with nothing
    /// stored, so it costs what it removes rather than a scan of the chain.
    pub fn clear_heights_above(&self, height: u32) -> Result<()> {
        let mut h = height.saturating_add(1);
        loop {
            let removed = self
                .db
                .remove(height_to_hash_key(h))
                .map_err(|e| CoreError::Storage(format!("clear_heights_above: {}", e)))?;
            let removed_header = self
                .db
                .remove(header_key(h))
                .map_err(|e| CoreError::Storage(format!("clear_heights_above: {}", e)))?;
            if removed.is_none() && removed_header.is_none() {
                return Ok(());
            }
            match h.checked_add(1) {
                Some(next) => h = next,
                None => return Ok(()),
            }
        }
    }

    /// Store a block and mark it active, for one that extended the tip.
    ///
    /// A block that might be on a losing branch must be stored with
    /// [`Storage::put_block`] instead, and marked active only if it wins.
    pub fn apply_block(&self, block: &Block) -> Result<()> {
        self.put_block(block)?;
        self.mark_active(block)?;
        Ok(())
    }

    // ========================================================================
    // Transaction index
    // ========================================================================

    /// Record where every transaction in `block` sits, and which addresses it
    /// touched.
    ///
    /// Safe to call for a block on any branch, and that is how it is used:
    /// indexing every block we accept means a reorg needs no work here at all.
    /// A losing branch's entries stay, point at a block that is still on disk,
    /// and are filtered out by the active-chain check at read time.
    ///
    /// One batch, so a half-written index cannot survive a crash.
    pub fn index_block(&self, block: &Block) -> Result<()> {
        let block_hash = block.hash();
        let height = block.header.height.0;
        let mut batch = sled::Batch::default();

        for (position, tx) in block.transactions.iter().enumerate() {
            let position = position as u32;
            let tx_hash = Hash::blake3(&tx.encode());

            let mut location = Vec::with_capacity(36);
            location.extend_from_slice(block_hash.as_bytes());
            location.extend_from_slice(&position.to_le_bytes());
            batch.insert(tx_index_key(&tx_hash), location);

            let mut value = Vec::with_capacity(36);
            value.extend_from_slice(tx_hash.as_bytes());
            value.extend_from_slice(&height.to_le_bytes());

            // The coinbase has no sender: its public key is a sentinel, and
            // the address it hashes to belongs to nobody. Indexing it would
            // put every block ever mined into one meaningless history.
            if !tx.is_coinbase() {
                batch.insert(
                    tx_address_key(&tx.sender_address(), &block_hash, position),
                    value.clone(),
                );
            }
            // A transfer to oneself writes one entry, not two: the key is the
            // same, and it did happen once.
            batch.insert(
                tx_address_key(&tx.recipient, &block_hash, position),
                value,
            );
        }

        self.db
            .apply_batch(batch)
            .map_err(|e| CoreError::Storage(format!("index_block: {}", e)))
    }

    /// Where a transaction is, if the index has it.
    ///
    /// The block named may be on a branch that lost. Ask
    /// [`Storage::is_on_active_chain`] before treating it as confirmed.
    pub fn transaction_location(&self, tx_hash: &Hash) -> Result<Option<(Hash, u32)>> {
        let raw = self
            .db
            .get(tx_index_key(tx_hash))
            .map_err(|e| CoreError::Storage(format!("transaction_location: {}", e)))?;
        let raw = match raw {
            Some(v) => v,
            None => return Ok(None),
        };
        if raw.len() != 36 {
            return Err(CoreError::Storage(
                "transaction_location: malformed entry".to_string(),
            ));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw[..32]);
        let mut position = [0u8; 4];
        position.copy_from_slice(&raw[32..36]);
        Ok(Some((Hash(hash), u32::from_le_bytes(position))))
    }

    /// Whether a block we hold is the one the active chain has at its height.
    pub fn is_on_active_chain(&self, block_hash: &Hash) -> Result<bool> {
        let height = match self.get_height_for_hash(block_hash)? {
            Some(h) => h,
            None => return Ok(false),
        };
        Ok(self.get_hash_for_height(height)? == Some(*block_hash))
    }

    /// Every transaction the index has for an address, in chain order.
    ///
    /// Sorted here rather than by the key, which is what buys the index its
    /// freedom from reorgs (see [`tx_address_key`]). The cost is one pass over
    /// the address's own entries, which is what listing them costs anyway.
    ///
    /// With `active_only`, entries whose block lost a fork are left out. Those
    /// are the transactions someone might otherwise believe had happened.
    pub fn transactions_for_address(
        &self,
        address: &Address,
        active_only: bool,
    ) -> Result<Vec<IndexedTx>> {
        let mut found = Vec::new();
        for entry in self.db.scan_prefix(tx_address_prefix(address)) {
            let (key, value) = entry
                .map_err(|e| CoreError::Storage(format!("transactions_for_address: {}", e)))?;
            let prefix = b"txaddr:".len() + 20;
            if key.len() != prefix + 32 + 4 || value.len() != 36 {
                continue;
            }

            let mut block_hash = [0u8; 32];
            block_hash.copy_from_slice(&key[prefix..prefix + 32]);
            let block_hash = Hash(block_hash);
            let mut position = [0u8; 4];
            position.copy_from_slice(&key[prefix + 32..]);

            if active_only && !self.is_on_active_chain(&block_hash)? {
                continue;
            }

            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&value[..32]);
            let mut height = [0u8; 4];
            height.copy_from_slice(&value[32..36]);

            found.push(IndexedTx {
                tx_hash: Hash(tx_hash),
                block_hash,
                height: u32::from_le_bytes(height),
                position: u32::from_be_bytes(position),
            });
        }
        found.sort_by_key(|tx| (tx.height, tx.position));
        Ok(found)
    }

    /// The active-chain height the index has been walked to, if ever.
    pub fn get_indexed_through(&self) -> Result<Option<u32>> {
        let raw = self
            .db
            .get(INDEXED_THROUGH_KEY)
            .map_err(|e| CoreError::Storage(format!("get_indexed_through: {}", e)))?;
        match raw {
            Some(v) if v.len() == 4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&v);
                Ok(Some(u32::from_le_bytes(buf)))
            }
            _ => Ok(None),
        }
    }

    pub fn put_indexed_through(&self, height: u32) -> Result<()> {
        self.db
            .insert(INDEXED_THROUGH_KEY, height.to_le_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_indexed_through: {}", e)))?;
        Ok(())
    }

    /// Store all accounts from a State.
    /// Persist every account, replacing whatever was stored before.
    ///
    /// This used to write only the supply despite its name, so balances were
    /// never persisted at all and every `wallet balance` reported "account not
    /// found" no matter how much had been mined.
    ///
    /// Stored accounts are cleared first: a reorg can remove an account
    /// entirely, and leaving the old row behind would report a balance that
    /// the active chain does not agree with. That makes this O(accounts) per
    /// call; writing only what changed is the optimisation.
    pub fn put_state(&self, state: &State) -> Result<()> {
        // One batch rather than an insert per account: this runs after every
        // block, and issuing thousands of individual writes made it the most
        // expensive thing in the block path by a wide margin (60 ms at 10k
        // accounts, against 2 ms to recompute the state root).
        let mut batch = sled::Batch::default();

        let live: std::collections::HashSet<Vec<u8>> = state
            .accounts()
            .map(|(address, _)| account_key(&address))
            .collect();

        for entry in self.db.scan_prefix(b"accounts:") {
            let (key, _) =
                entry.map_err(|e| CoreError::Storage(format!("put_state scan: {}", e)))?;
            let key = key.to_vec();
            if !live.contains(&key) {
                batch.remove(key);
            }
        }

        for (address, account) in state.accounts() {
            let mut value = Vec::with_capacity(16);
            value.extend_from_slice(&account.balance.to_le_bytes());
            value.extend_from_slice(&account.nonce.to_le_bytes());
            batch.insert(account_key(&address), value);
        }

        self.db
            .apply_batch(batch)
            .map_err(|e| CoreError::Storage(format!("put_state: {}", e)))?;
        self.put_supply(state.total_supply())?;
        Ok(())
    }

    /// Load every stored account into a `State`.
    ///
    /// Lets a restart resume from the persisted state instead of revalidating
    /// the whole chain. The caller must check the resulting state root against
    /// the stored tip before trusting it.
    pub fn load_state(&self) -> Result<State> {
        let mut state = State::new();
        for entry in self.db.scan_prefix(b"accounts:") {
            let (key, value) =
                entry.map_err(|e| CoreError::Storage(format!("load_state scan: {}", e)))?;
            if key.len() != b"accounts:".len() + 20 {
                continue;
            }
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&key[b"accounts:".len()..]);
            let account = Account::decode_stored(&value)?;
            state.restore_account(&Address::from_hash160(chroma_core::hash::Hash160(addr)), account);
        }
        state.restore_supply(self.get_supply()?);
        Ok(state)
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<()> {
        self.db
            .flush()
            .map_err(|e| CoreError::Storage(format!("flush: {}", e)))?;
        Ok(())
    }

    /// Get the approximate size of the database on disk.
    pub fn size_on_disk(&self) -> Result<u64> {
        self.db
            .size_on_disk()
            .map_err(|e| CoreError::Storage(format!("size_on_disk: {}", e)))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::hash::Hash160;
    use chroma_core::types::{BlockHeight, CompactTarget};
    use chroma_block::BlockHeader;

    fn test_header(height: u32) -> BlockHeader {
        BlockHeader {
            version: 1,
            previous_hash: Hash::blake3(&height.to_le_bytes()),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: 1_700_000_000 + (height as u64) * 10,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(height),
            nonce: 0,
        }
    }

    fn test_block(height: u32) -> Block {
        Block {
            header: test_header(height),
            transactions: vec![],
        }
    }

    /// A block is stored before anyone knows whether it will be on the active
    /// chain — a losing branch is stored precisely so a later reorg can replay
    /// it. Storing one must not repoint its height at itself: `put_block` used
    /// to write the height→hash index, so a side branch arriving at a height
    /// silently became the answer for that height, and a restart replayed the
    /// wrong block.
    #[test]
    fn test_storing_a_side_branch_does_not_take_over_its_height() {
        let storage = Storage::open_temporary().unwrap();

        let active = test_block(7);
        storage.apply_block(&active).unwrap();

        // Same height, different block: a competing branch.
        let mut rival = test_block(7);
        rival.header.nonce = 99;
        assert_ne!(rival.hash(), active.hash());
        storage.put_block(&rival).unwrap();

        assert_eq!(
            storage.get_block_by_height(7).unwrap().map(|b| b.hash()),
            Some(active.hash()),
            "the active chain's block must still be the answer for its height"
        );
        assert_eq!(
            storage.get_header(7).unwrap().map(|h| h.hash()),
            Some(active.hash()),
            "the stored header at a height is the active chain's"
        );

        // The rival is still readable by hash, which is what a reorg needs.
        assert_eq!(
            storage.get_block_by_hash(&rival.hash()).unwrap().map(|b| b.hash()),
            Some(rival.hash())
        );

        // ...and it takes over once it is the one that won.
        storage.mark_active(&rival).unwrap();
        assert_eq!(
            storage.get_block_by_height(7).unwrap().map(|b| b.hash()),
            Some(rival.hash())
        );
    }

    /// Fork choice is on work, not length, so a reorg can leave the tip lower
    /// than it was. The heights above it must stop answering with the chain
    /// that lost.
    #[test]
    fn test_clearing_heights_above_a_lower_tip() {
        let storage = Storage::open_temporary().unwrap();

        for height in 1..=5 {
            storage.apply_block(&test_block(height)).unwrap();
        }
        assert!(storage.get_block_by_height(5).unwrap().is_some());

        storage.clear_heights_above(3).unwrap();

        assert!(storage.get_block_by_height(3).unwrap().is_some());
        for height in 4..=5 {
            assert!(
                storage.get_block_by_height(height).unwrap().is_none(),
                "height {} is above the tip and must not answer",
                height
            );
            assert!(storage.get_header(height).unwrap().is_none());
        }

        // The blocks themselves survive: a later reorg may replay them.
        assert!(storage
            .get_block_by_hash(&test_block(5).hash())
            .unwrap()
            .is_some());
    }

    fn test_address(n: u8) -> Address {
        let mut h = [0u8; 20];
        h[0] = n;
        Address::from_hash160(Hash160(h))
    }

    #[test]
    fn test_open_and_close() {
        let storage = Storage::open_temporary().unwrap();
        let _ = storage;
    }

    #[test]
    fn test_put_state_persists_accounts() {
        // put_state used to write only the supply, so balances never reached
        // disk and every balance query reported "account not found".
        let storage = Storage::open_temporary().unwrap();
        let mut state = State::new();
        state.apply_subsidy(&test_address(1), 1).unwrap();
        state.apply_subsidy(&test_address(2), 2).unwrap();

        storage.put_state(&state).unwrap();

        let a = storage.get_account(&test_address(1)).unwrap().unwrap();
        assert_eq!(a.balance, 1_000_000);
        let b = storage.get_account(&test_address(2)).unwrap().unwrap();
        assert_eq!(b.balance, 1_000_000);
        assert_eq!(storage.get_supply().unwrap(), 2_000_000);
    }

    #[test]
    fn test_put_state_drops_accounts_the_chain_no_longer_has() {
        // A reorg can remove an account entirely; the stored row must go with
        // it, or the balance query answers from an abandoned branch.
        let storage = Storage::open_temporary().unwrap();

        let mut before = State::new();
        before.apply_subsidy(&test_address(1), 1).unwrap();
        storage.put_state(&before).unwrap();
        assert!(storage.get_account(&test_address(1)).unwrap().is_some());

        let mut after = State::new();
        after.apply_subsidy(&test_address(2), 1).unwrap();
        storage.put_state(&after).unwrap();

        assert!(
            storage.get_account(&test_address(1)).unwrap().is_none(),
            "the abandoned branch's account must not survive"
        );
        assert!(storage.get_account(&test_address(2)).unwrap().is_some());
    }

    #[test]
    fn test_load_state_round_trips() {
        let storage = Storage::open_temporary().unwrap();
        let mut state = State::new();
        for i in 1..=5u8 {
            state.apply_subsidy(&test_address(i), i as u32).unwrap();
        }
        storage.put_state(&state).unwrap();

        let loaded = storage.load_state().unwrap();
        assert_eq!(loaded.account_count(), state.account_count());
        assert_eq!(loaded.total_supply(), state.total_supply());
        assert_eq!(
            loaded.compute_state_root(),
            state.compute_state_root(),
            "a restored state must commit to the same root"
        );
        for i in 1..=5u8 {
            assert_eq!(
                loaded.get_account(&test_address(i)).balance,
                state.get_account(&test_address(i)).balance
            );
        }
    }

    #[test]
    fn test_load_state_of_empty_database() {
        let storage = Storage::open_temporary().unwrap();
        let loaded = storage.load_state().unwrap();
        assert_eq!(loaded.account_count(), 0);
        assert_eq!(loaded.total_supply(), 0);
        assert_eq!(loaded.compute_state_root(), Hash::ZERO);
    }

    #[test]
    fn test_height_index_round_trip() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(7);
        storage.apply_block(&block).unwrap();

        assert_eq!(
            storage.get_hash_for_height(7).unwrap(),
            Some(block.hash()),
            "a block marked active must answer for its height"
        );
        assert_eq!(
            storage.get_block_by_height(7).unwrap().map(|b| b.hash()),
            Some(block.hash())
        );
        assert!(storage.get_block_by_height(8).unwrap().is_none());
    }

    #[test]
    fn test_height_index_is_rewritable_for_reorg() {
        // A reorg reuses heights, so the index has to be repointable rather
        // than append-only.
        let storage = Storage::open_temporary().unwrap();

        let mut original = test_block(3);
        original.header.nonce = 1;
        storage.put_block(&original).unwrap();

        let mut replacement = test_block(3);
        replacement.header.nonce = 2;
        storage.put_block(&replacement).unwrap();
        assert_ne!(original.hash(), replacement.hash());

        storage
            .set_hash_for_height(3, &replacement.hash())
            .unwrap();
        assert_eq!(
            storage.get_block_by_height(3).unwrap().map(|b| b.hash()),
            Some(replacement.hash()),
            "the height index must follow the active branch"
        );

        // The displaced block is still retrievable by hash.
        assert!(storage.get_block_by_hash(&original.hash()).unwrap().is_some());
    }

    #[test]
    fn test_height_index_survives_many_blocks() {
        let storage = Storage::open_temporary().unwrap();
        for h in 0..50u32 {
            storage.apply_block(&test_block(h)).unwrap();
        }
        for h in 0..50u32 {
            assert_eq!(
                storage.get_block_by_height(h).unwrap().map(|b| b.header.height.0),
                Some(h)
            );
        }
    }

    #[test]
    fn test_put_and_get_header() {
        let storage = Storage::open_temporary().unwrap();
        let header = test_header(1);
        storage.put_header(1, &header).unwrap();
        let retrieved = storage.get_header(1).unwrap().unwrap();
        assert_eq!(retrieved, header);
    }

    #[test]
    fn test_get_header_missing() {
        let storage = Storage::open_temporary().unwrap();
        assert!(storage.get_header(999).unwrap().is_none());
    }

    #[test]
    fn test_has_header() {
        let storage = Storage::open_temporary().unwrap();
        assert!(!storage.has_header(0).unwrap());
        storage.put_header(0, &test_header(0)).unwrap();
        assert!(storage.has_header(0).unwrap());
    }

    #[test]
    fn test_put_and_get_block() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(5);
        let hash = block.hash();
        storage.put_block(&block).unwrap();
        let retrieved = storage.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header, block.header);
    }

    #[test]
    fn test_get_height_for_hash() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(42);
        let hash = block.hash();
        storage.put_block(&block).unwrap();
        let height = storage.get_height_for_hash(&hash).unwrap().unwrap();
        assert_eq!(height, 42);
    }

    #[test]
    fn test_apply_block() {
        let storage = Storage::open_temporary().unwrap();
        let block = test_block(1);
        let hash = block.hash();
        storage.apply_block(&block).unwrap();

        assert!(storage.has_header(1).unwrap());
        let retrieved = storage.get_block_by_hash(&hash).unwrap().unwrap();
        assert_eq!(retrieved.header.height.0, 1);
    }

    #[test]
    fn test_put_and_get_tip() {
        let storage = Storage::open_temporary().unwrap();
        let tip = PersistedTip {
            height: 100,
            hash: Hash::blake3(b"tip"),
            cumulative_work: [1u8; 32],
            supply: 100_000_000,
        };
        storage.put_tip(&tip).unwrap();
        let retrieved = storage.get_tip().unwrap().unwrap();
        assert_eq!(retrieved.height, 100);
        assert_eq!(retrieved.hash, tip.hash);
        assert_eq!(retrieved.supply, 100_000_000);
    }

    #[test]
    fn test_get_tip_missing() {
        let storage = Storage::open_temporary().unwrap();
        assert!(storage.get_tip().unwrap().is_none());
    }

    #[test]
    fn test_put_and_get_account() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0xAA);
        let account = Account::new(5_000_000, 42);
        storage.put_account(&addr, &account).unwrap();
        let retrieved = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved.balance, 5_000_000);
        assert_eq!(retrieved.nonce, 42);
    }

    #[test]
    fn test_get_account_missing() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0xBB);
        assert!(storage.get_account(&addr).unwrap().is_none());
    }

    #[test]
    fn test_supply_roundtrip() {
        let storage = Storage::open_temporary().unwrap();
        assert_eq!(storage.get_supply().unwrap(), 0);
        storage.put_supply(50_000_000).unwrap();
        assert_eq!(storage.get_supply().unwrap(), 50_000_000);
    }

    #[test]
    fn test_genesis_hash_roundtrip() {
        let storage = Storage::open_temporary().unwrap();
        assert!(storage.get_genesis_hash().unwrap().is_none());
        let hash = Hash::blake3(b"genesis");
        storage.put_genesis_hash(&hash).unwrap();
        assert_eq!(storage.get_genesis_hash().unwrap().unwrap(), hash);
    }

    #[test]
    fn test_multiple_blocks() {
        let storage = Storage::open_temporary().unwrap();
        let mut hashes = Vec::new();
        for h in 0..10u32 {
            let block = test_block(h);
            let hash = block.hash();
            hashes.push(hash);
            storage.apply_block(&block).unwrap();
        }

        // All headers retrievable
        for h in 0..10u32 {
            assert!(storage.has_header(h).unwrap());
        }

        // All blocks retrievable by hash
        for (i, hash) in hashes.iter().enumerate() {
            let block = storage.get_block_by_hash(hash).unwrap().unwrap();
            assert_eq!(block.header.height.0, i as u32);
        }
    }

    #[test]
    fn test_persisted_tip_serialization_roundtrip() {
        let tip = PersistedTip {
            height: 999,
            hash: Hash::blake3(b"test"),
            cumulative_work: [0xFF; 32],
            supply: u64::MAX,
        };
        let encoded = tip.encode();
        let decoded = PersistedTip::decode(&encoded).unwrap();
        assert_eq!(decoded.height, tip.height);
        assert_eq!(decoded.hash, tip.hash);
        assert_eq!(decoded.cumulative_work, tip.cumulative_work);
        assert_eq!(decoded.supply, tip.supply);
    }

    #[test]
    fn test_account_overwrite() {
        let storage = Storage::open_temporary().unwrap();
        let addr = test_address(0xCC);
        let acc1 = Account::new(100, 0);
        let acc2 = Account::new(200, 5);
        storage.put_account(&addr, &acc1).unwrap();
        storage.put_account(&addr, &acc2).unwrap();
        let retrieved = storage.get_account(&addr).unwrap().unwrap();
        assert_eq!(retrieved.balance, 200);
        assert_eq!(retrieved.nonce, 5);
    }

    #[test]
    fn test_flush() {
        let storage = Storage::open_temporary().unwrap();
        storage.put_supply(42).unwrap();
        storage.flush().unwrap();
        assert_eq!(storage.get_supply().unwrap(), 42);
    }

    #[test]
    fn test_many_accounts() {
        let storage = Storage::open_temporary().unwrap();
        for i in 0..100u8 {
            let addr = test_address(i);
            let acc = Account::new((i as u64) * 1_000_000, i as u64);
            storage.put_account(&addr, &acc).unwrap();
        }

        for i in 0..100u8 {
            let addr = test_address(i);
            let acc = storage.get_account(&addr).unwrap().unwrap();
            assert_eq!(acc.balance, (i as u64) * 1_000_000);
            assert_eq!(acc.nonce, i as u64);
        }
    }

    // -----------------------------------------------------------------------
    // Transaction index
    // -----------------------------------------------------------------------

    fn indexed_block(height: u32, nonce_salt: u64) -> (Block, chroma_tx::Transaction) {
        use chroma_core::types::{Amount, Nonce};
        use chroma_crypto::schnorr::{PublicKey32, SecretKey32};

        let secret = SecretKey32::from_bytes([0x41; 32]).unwrap();
        let pubkey = PublicKey32::from_secret(&secret).unwrap();
        let sender = Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)));
        let recipient = Address::from_hash160(Hash160([0x55; 20]));

        let coinbase = chroma_tx::Transaction::coinbase(sender, Amount(1_000_000));
        let transfer = chroma_tx::create_transaction(
            &secret,
            sender,
            recipient,
            Amount(10),
            Nonce(nonce_salt),
        )
        .unwrap();

        let mut header = test_header(height);
        header.nonce = nonce_salt;
        (
            Block {
                header,
                transactions: vec![coinbase, transfer.clone()],
            },
            transfer,
        )
    }

    fn sender_address() -> Address {
        use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
        let secret = SecretKey32::from_bytes([0x41; 32]).unwrap();
        let pubkey = PublicKey32::from_secret(&secret).unwrap();
        Address::from_hash160(Hash160(chroma_crypto::hash::hash160(&pubkey.0)))
    }

    #[test]
    fn a_transaction_can_be_found_by_its_hash() {
        let storage = Storage::open_temporary().unwrap();
        let (block, transfer) = indexed_block(1, 0);
        let tx_hash = Hash::blake3(&transfer.encode());

        storage.apply_block(&block).unwrap();
        storage.index_block(&block).unwrap();

        let (found_block, position) = storage
            .transaction_location(&tx_hash)
            .unwrap()
            .expect("indexed");
        assert_eq!(found_block, block.hash());
        assert_eq!(position, 1, "position 0 is the coinbase");
    }

    #[test]
    fn an_unindexed_transaction_is_simply_absent() {
        let storage = Storage::open_temporary().unwrap();
        let (block, transfer) = indexed_block(1, 0);
        storage.apply_block(&block).unwrap();
        // No index_block call.
        assert_eq!(
            storage
                .transaction_location(&Hash::blake3(&transfer.encode()))
                .unwrap(),
            None
        );
    }

    #[test]
    fn the_index_survives_a_reorg_without_being_rewritten() {
        // The point of keying on the block hash. Two blocks compete for one
        // height; both are indexed when they arrive, and nothing has to be
        // undone when the winner changes — the active-chain check answers it.
        let storage = Storage::open_temporary().unwrap();
        let (first, first_tx) = indexed_block(1, 1);
        let (second, second_tx) = indexed_block(1, 2);
        assert_ne!(first.hash(), second.hash());

        storage.apply_block(&first).unwrap();
        storage.index_block(&first).unwrap();
        storage.put_block(&second).unwrap();
        storage.index_block(&second).unwrap();

        assert!(storage.is_on_active_chain(&first.hash()).unwrap());
        assert!(!storage.is_on_active_chain(&second.hash()).unwrap());

        // The reorg: the second block takes the height.
        storage.mark_active(&second).unwrap();

        assert!(!storage.is_on_active_chain(&first.hash()).unwrap());
        assert!(storage.is_on_active_chain(&second.hash()).unwrap());

        // Both lookups still resolve; only their standing changed.
        for tx in [&first_tx, &second_tx] {
            assert!(storage
                .transaction_location(&Hash::blake3(&tx.encode()))
                .unwrap()
                .is_some());
        }

        // Two entries per block for this address: it is paid by the coinbase
        // and it sends the transfer.
        let history = storage
            .transactions_for_address(&sender_address(), true)
            .unwrap();
        assert_eq!(history.len(), 2, "only the winning block's entries count");
        assert!(history.iter().all(|tx| tx.block_hash == second.hash()));

        let all = storage
            .transactions_for_address(&sender_address(), false)
            .unwrap();
        assert_eq!(all.len(), 4, "the losing branch is still on record");
    }

    #[test]
    fn history_comes_back_in_chain_order() {
        let storage = Storage::open_temporary().unwrap();
        // Indexed out of order on purpose: the key carries no height, so the
        // ordering has to come from the sort.
        for height in [3u32, 1, 2] {
            let (block, _) = indexed_block(height, height as u64);
            storage.apply_block(&block).unwrap();
            storage.index_block(&block).unwrap();
        }
        let history = storage
            .transactions_for_address(&sender_address(), true)
            .unwrap();
        let heights: Vec<u32> = history.iter().map(|tx| tx.height).collect();
        assert_eq!(heights, vec![1, 1, 2, 2, 3, 3], "coinbase then transfer, per block");
        let positions: Vec<u32> = history.iter().map(|tx| tx.position).collect();
        assert_eq!(positions, vec![0, 1, 0, 1, 0, 1], "and in block order within a height");
    }

    #[test]
    fn a_coinbase_is_indexed_for_its_recipient_only() {
        // Its sender is a sentinel key belonging to nobody, and putting every
        // block ever mined into that address's history would be noise.
        let storage = Storage::open_temporary().unwrap();
        let (block, _) = indexed_block(1, 0);
        storage.apply_block(&block).unwrap();
        storage.index_block(&block).unwrap();

        let coinbase_hash = Hash::blake3(&block.transactions[0].encode());
        let (_, position) = storage
            .transaction_location(&coinbase_hash)
            .unwrap()
            .expect("the coinbase is indexed");
        assert_eq!(position, 0);

        let sentinel = block.transactions[0].sender_address();
        assert!(storage
            .transactions_for_address(&sentinel, false)
            .unwrap()
            .is_empty());

        // The miner sees it, because the coinbase pays them.
        let mined = storage
            .transactions_for_address(&sender_address(), true)
            .unwrap();
        assert!(mined.iter().any(|tx| tx.tx_hash == coinbase_hash));
    }

    #[test]
    fn the_indexed_height_is_remembered() {
        let storage = Storage::open_temporary().unwrap();
        assert_eq!(storage.get_indexed_through().unwrap(), None, "never run");
        storage.put_indexed_through(42).unwrap();
        assert_eq!(storage.get_indexed_through().unwrap(), Some(42));
    }
}
