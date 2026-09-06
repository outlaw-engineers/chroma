//! Blocks whose parent we do not have yet.
//!
//! Blocks can arrive out of order — a relay race between peers, or an
//! announcement that overtakes the block below it. Such a block cannot be
//! validated (its parent's state is unknown), but discarding it means waiting
//! for a re-announcement that may never come. It is parked here instead, and
//! reconsidered as soon as its parent lands.
//!
//! The pool is strictly bounded: anyone can send us a block claiming any
//! parent, so an unbounded pool would be a memory-exhaustion hole.

use std::collections::HashMap;

use chroma_block::Block;
use chroma_core::hash::Hash;

/// Maximum blocks held at once. Beyond this the oldest is dropped.
pub const MAX_ORPHANS: usize = 64;

struct Entry {
    block: Block,
    /// Insertion order, used to pick a victim when the pool is full.
    seq: u64,
}

/// A bounded set of blocks waiting for their parent.
pub struct OrphanPool {
    by_hash: HashMap<Hash, Entry>,
    /// Parent hash → hashes of the blocks waiting on it.
    waiting_on: HashMap<Hash, Vec<Hash>>,
    next_seq: u64,
}

impl Default for OrphanPool {
    fn default() -> Self {
        Self::new()
    }
}

impl OrphanPool {
    pub fn new() -> Self {
        OrphanPool {
            by_hash: HashMap::new(),
            waiting_on: HashMap::new(),
            next_seq: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }

    pub fn contains(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Park a block. Returns the parent hash to request, or `None` if we were
    /// already holding this block.
    pub fn insert(&mut self, block: Block) -> Option<Hash> {
        let hash = block.hash();
        if self.by_hash.contains_key(&hash) {
            return None;
        }

        if self.by_hash.len() >= MAX_ORPHANS {
            self.evict_oldest();
        }

        let parent = block.header.previous_hash;
        let seq = self.next_seq;
        self.next_seq += 1;

        self.by_hash.insert(hash, Entry { block, seq });
        self.waiting_on.entry(parent).or_default().push(hash);
        Some(parent)
    }

    /// Remove and return the blocks whose parent is `parent`.
    ///
    /// Called after a block is accepted, to see what can now be connected.
    pub fn take_children_of(&mut self, parent: &Hash) -> Vec<Block> {
        let hashes = match self.waiting_on.remove(parent) {
            Some(hashes) => hashes,
            None => return Vec::new(),
        };
        hashes
            .into_iter()
            .filter_map(|h| self.by_hash.remove(&h).map(|e| e.block))
            .collect()
    }

    /// Drop a block we no longer want to hold (it turned out to be invalid).
    pub fn remove(&mut self, hash: &Hash) {
        if let Some(entry) = self.by_hash.remove(hash) {
            let parent = entry.block.header.previous_hash;
            if let Some(siblings) = self.waiting_on.get_mut(&parent) {
                siblings.retain(|h| h != hash);
                if siblings.is_empty() {
                    self.waiting_on.remove(&parent);
                }
            }
        }
    }

    fn evict_oldest(&mut self) {
        let victim = self
            .by_hash
            .iter()
            .min_by_key(|(_, e)| e.seq)
            .map(|(h, _)| *h);
        if let Some(hash) = victim {
            self.remove(&hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_block::BlockHeader;
    use chroma_core::types::{BlockHeight, CompactTarget};

    fn block_with_parent(parent: Hash, nonce: u64) -> Block {
        Block {
            header: BlockHeader {
                version: 1,
                previous_hash: parent,
                state_root: Hash::ZERO,
                tx_merkle_root: Hash::ZERO,
                timestamp: 1_767_225_600,
                bits: CompactTarget::DIFFICULTY_1,
                height: BlockHeight(1),
                nonce,
            },
            transactions: vec![],
        }
    }

    #[test]
    fn test_insert_reports_the_parent_to_fetch() {
        let mut pool = OrphanPool::new();
        let parent = Hash::blake3(b"parent");
        let block = block_with_parent(parent, 1);

        assert_eq!(pool.insert(block.clone()), Some(parent));
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&block.hash()));

        // Re-offering the same block is a no-op, not a second request.
        assert_eq!(pool.insert(block), None);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_children_are_released_when_the_parent_arrives() {
        let mut pool = OrphanPool::new();
        let parent = Hash::blake3(b"parent");
        pool.insert(block_with_parent(parent, 1));
        pool.insert(block_with_parent(parent, 2));
        pool.insert(block_with_parent(Hash::blake3(b"other"), 3));

        let released = pool.take_children_of(&parent);
        assert_eq!(released.len(), 2);
        assert_eq!(pool.len(), 1, "the unrelated orphan stays parked");

        // Taking twice yields nothing the second time.
        assert!(pool.take_children_of(&parent).is_empty());
    }

    #[test]
    fn test_pool_is_bounded() {
        // A peer can claim any parent it likes, so the pool must not grow
        // without limit.
        let mut pool = OrphanPool::new();
        for i in 0..(MAX_ORPHANS as u64 * 2) {
            pool.insert(block_with_parent(Hash::blake3(&i.to_le_bytes()), i));
        }
        assert_eq!(pool.len(), MAX_ORPHANS);
    }

    #[test]
    fn test_eviction_drops_the_oldest_first() {
        let mut pool = OrphanPool::new();
        let first = block_with_parent(Hash::blake3(b"p0"), 0);
        pool.insert(first.clone());
        for i in 1..MAX_ORPHANS as u64 {
            pool.insert(block_with_parent(Hash::blake3(&i.to_le_bytes()), i));
        }
        assert!(pool.contains(&first.hash()));

        // One more pushes the first one out.
        pool.insert(block_with_parent(Hash::blake3(b"newest"), 9999));
        assert!(!pool.contains(&first.hash()));
        assert_eq!(pool.len(), MAX_ORPHANS);
    }

    #[test]
    fn test_remove_clears_the_parent_index() {
        let mut pool = OrphanPool::new();
        let parent = Hash::blake3(b"parent");
        let block = block_with_parent(parent, 1);
        pool.insert(block.clone());

        pool.remove(&block.hash());
        assert!(pool.is_empty());
        assert!(
            pool.take_children_of(&parent).is_empty(),
            "a removed orphan must not linger in the parent index"
        );
    }
}
