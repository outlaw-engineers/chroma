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

const TIP_KEY: &[u8] = b"tip";
const SUPPLY_KEY: &[u8] = b"supply";
const GENESIS_HASH_KEY: &[u8] = b"genesis_hash";

// ============================================================================
// Chain Tip Metadata
// ============================================================================

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

        // Also store hash→height mapping
        let height_key = hash_to_height_key(&hash);
        self.db
            .insert(height_key, block.header.height.0.to_le_bytes().to_vec())
            .map_err(|e| CoreError::Storage(format!("put_block height mapping: {}", e)))?;

        // ...and the reverse index, so height lookups do not have to scan.
        self.db
            .insert(
                height_to_hash_key(block.header.height.0),
                hash.as_bytes().to_vec(),
            )
            .map_err(|e| CoreError::Storage(format!("put_block hash index: {}", e)))?;

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

    /// Apply a full block to storage: header, full block, hash mapping.
    pub fn apply_block(&self, block: &Block) -> Result<()> {
        let height = block.header.height.0;
        self.put_header(height, &block.header)?;
        self.put_block(block)?;
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
        storage.put_block(&block).unwrap();

        assert_eq!(
            storage.get_hash_for_height(7).unwrap(),
            Some(block.hash()),
            "put_block must populate the height index"
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
            storage.put_block(&test_block(h)).unwrap();
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
}
