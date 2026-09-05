use std::collections::HashMap;

use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash;
use chroma_core::serialize::CanonicalEncode;
use chroma_tx::Transaction;

pub const MAX_MEMPOOL_SIZE: usize = 50_000_000;
pub const MAX_MEMPOOL_TXS: usize = 100_000;

#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub tx_hash: Hash,
    pub size: usize,
    pub added_at: u64,
    pub fee_per_byte: u64,
}

pub struct Mempool {
    entries: HashMap<Hash, MempoolEntry>,
    tx_order: Vec<Hash>,
    total_size: usize,
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
        }
    }

    pub fn add_transaction(&mut self, tx: Transaction) -> Result<bool> {
        let encoded = tx.encode();
        let tx_hash = Hash::blake3(&encoded);
        if self.entries.contains_key(&tx_hash) {
            return Ok(false);
        }
        if self.tx_order.len() >= MAX_MEMPOOL_TXS {
            return Err(CoreError::InvalidTransaction(
                "mempool full: too many transactions".to_string(),
            ));
        }
        let size = encoded.len();
        if self.total_size + size > MAX_MEMPOOL_SIZE {
            return Err(CoreError::InvalidTransaction(
                "mempool full: size limit exceeded".to_string(),
            ));
        }
        let fee_per_byte = 0;
        let entry = MempoolEntry {
            tx,
            tx_hash,
            size,
            added_at: 0,
            fee_per_byte,
        };
        self.total_size += size;
        self.tx_order.push(tx_hash);
        self.entries.insert(tx_hash, entry);
        Ok(true)
    }

    pub fn remove_transaction(&mut self, hash: &Hash) -> bool {
        if let Some(entry) = self.entries.remove(hash) {
            self.total_size -= entry.size;
            self.tx_order.retain(|h| *h != *hash);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
