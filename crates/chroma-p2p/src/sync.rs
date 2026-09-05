use std::collections::BTreeMap;

use chroma_block::BlockHeader;
use chroma_core::hash::Hash;

use crate::wire::{GetDataMessage, GetHeadersMessage, InvEntry, InvType};

pub const MAX_HEADERS_PER_RESPONSE: usize = 2000;
pub const MAX_BLOCKS_PER_RESPONSE: usize = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    SyncingHeaders,
    SyncingBlocks,
    CaughtUp,
}

/// Outcome of validating a batch of headers from a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderBatch {
    /// How many headers were accepted onto the header chain.
    pub accepted: usize,
    /// Why the batch stopped, if it did not run to completion. A rejection is
    /// a protocol violation by the peer, not a transient condition.
    pub rejected: Option<String>,
}

impl HeaderBatch {
    pub fn is_clean(&self) -> bool {
        self.rejected.is_none()
    }
}

pub struct ChainSyncer {
    pub state: SyncState,
    pub best_height: u32,
    pub best_hash: Hash,
    sync_peer: Option<std::net::SocketAddr>,
    /// The header chain, ahead of the validated block chain during
    /// headers-first sync. Keyed by height.
    headers: BTreeMap<u32, BlockHeader>,
}

impl ChainSyncer {
    pub fn new(genesis_hash: Hash) -> Self {
        ChainSyncer {
            state: SyncState::Idle,
            best_height: 0,
            best_hash: genesis_hash,
            sync_peer: None,
            headers: BTreeMap::new(),
        }
    }

    /// Create a syncer seeded with the genesis header.
    ///
    /// Headers can only be validated against a chain that already has a
    /// starting point, so a syncer without genesis can never accept anything.
    pub fn with_genesis(genesis: BlockHeader) -> Self {
        let hash = genesis.hash();
        let mut headers = BTreeMap::new();
        headers.insert(genesis.height.0, genesis);
        ChainSyncer {
            state: SyncState::Idle,
            best_height: 0,
            best_hash: hash,
            sync_peer: None,
            headers,
        }
    }

    /// Read-only view of the header chain.
    pub fn headers(&self) -> &BTreeMap<u32, BlockHeader> {
        &self.headers
    }

    /// Take a header we already consider valid (e.g. loaded from storage).
    pub fn insert_header(&mut self, header: BlockHeader) {
        let hash = header.hash();
        let height = header.height.0;
        self.headers.insert(height, header);
        if height >= self.best_height {
            self.best_height = height;
            self.best_hash = hash;
        }
    }

    /// Headers we can serve to a peer that asked for what follows `after`.
    ///
    /// Returns up to `MAX_HEADERS_PER_RESPONSE` headers in ascending height
    /// order, stopping early at `stop` when it is not the zero hash.
    pub fn headers_after(&self, after: &Hash, stop: &Hash) -> Vec<BlockHeader> {
        let start_height = match self.height_of(after) {
            Some(h) => h,
            // We do not know the peer's starting point, so we have nothing
            // useful to offer. A locator-based walk-back belongs with block
            // download.
            None => return Vec::new(),
        };

        let mut out = Vec::new();
        for (_, header) in self.headers.range((start_height + 1)..) {
            out.push(header.clone());
            if out.len() >= MAX_HEADERS_PER_RESPONSE {
                break;
            }
            if *stop != Hash::ZERO && header.hash() == *stop {
                break;
            }
        }
        out
    }

    /// Height of a header we hold, by hash.
    pub fn height_of(&self, hash: &Hash) -> Option<u32> {
        self.headers
            .iter()
            .find(|(_, h)| h.hash() == *hash)
            .map(|(height, _)| *height)
    }

    /// Validate and append a batch of headers received from a peer.
    ///
    /// Each header must connect to the one before it, carry the target the
    /// retarget rules demand, satisfy its own proof of work, and have a
    /// timestamp past the median of the preceding window. Headers we already
    /// hold are counted as accepted so that a peer resending an overlapping
    /// range is not punished.
    pub fn absorb_headers(&mut self, incoming: &[BlockHeader]) -> HeaderBatch {
        let mut accepted = 0usize;

        for header in incoming {
            let height = header.height.0;

            if let Some(known) = self.headers.get(&height) {
                if known.hash() == header.hash() {
                    accepted += 1;
                    continue;
                }
                return HeaderBatch {
                    accepted,
                    rejected: Some(format!(
                        "header at height {} conflicts with the one we hold",
                        height
                    )),
                };
            }

            if height == 0 {
                return HeaderBatch {
                    accepted,
                    rejected: Some("peer offered a second genesis block".to_string()),
                };
            }

            let parent = match self.headers.get(&(height - 1)) {
                Some(parent) => parent,
                None => {
                    return HeaderBatch {
                        accepted,
                        rejected: Some(format!("header at height {} has no parent", height)),
                    }
                }
            };

            if header.previous_hash != parent.hash() {
                return HeaderBatch {
                    accepted,
                    rejected: Some(format!(
                        "header at height {} does not link to its parent",
                        height
                    )),
                };
            }

            match chroma_consensus::calculate_target_for_height(height, &self.headers) {
                Ok(expected) if expected == header.bits => {}
                Ok(expected) => {
                    return HeaderBatch {
                        accepted,
                        rejected: Some(format!(
                            "header at height {} declares bits {:08x}, expected {:08x}",
                            height, header.bits.0, expected.0
                        )),
                    }
                }
                Err(e) => {
                    return HeaderBatch {
                        accepted,
                        rejected: Some(format!("cannot compute target at height {}: {}", height, e)),
                    }
                }
            }

            // Proof of work is what makes a header chain expensive to forge,
            // so it is checked here rather than deferred to block download.
            let target = header.bits.to_full_target();
            if !chroma_crypto::randomx::hash_meets_target(&header.hash(), &target) {
                return HeaderBatch {
                    accepted,
                    rejected: Some(format!("header at height {} does not meet its target", height)),
                };
            }

            let mtp = chroma_consensus::median_time_past(&self.headers, height);
            if header.timestamp <= mtp {
                return HeaderBatch {
                    accepted,
                    rejected: Some(format!(
                        "header at height {} has timestamp {} at or before MTP {}",
                        height, header.timestamp, mtp
                    )),
                };
            }

            self.insert_header(header.clone());
            accepted += 1;
        }

        HeaderBatch {
            accepted,
            rejected: None,
        }
    }

    pub fn start_header_sync(&mut self, peer: std::net::SocketAddr, from_hash: Hash) -> GetHeadersMessage {
        self.state = SyncState::SyncingHeaders;
        self.sync_peer = Some(peer);
        GetHeadersMessage {
            start_hash: from_hash,
            stop_hash: Hash::ZERO,
        }
    }

    pub fn start_block_sync(&mut self, peer: std::net::SocketAddr) -> GetDataMessage {
        self.state = SyncState::SyncingBlocks;
        self.sync_peer = Some(peer);
        GetDataMessage {
            inventory: vec![InvEntry {
                inv_type: InvType::Block,
                hash: self.best_hash,
            }],
        }
    }

    pub fn received_header(&mut self, hash: Hash, height: u32) {
        if height > self.best_height {
            self.best_height = height;
            self.best_hash = hash;
        }
    }

    pub fn sync_complete(&mut self) {
        self.state = SyncState::CaughtUp;
        self.sync_peer = None;
    }

    pub fn sync_failed(&mut self) {
        self.state = SyncState::Idle;
        self.sync_peer = None;
    }

    pub fn is_syncing(&self) -> bool {
        matches!(self.state, SyncState::SyncingHeaders | SyncState::SyncingBlocks)
    }

    pub fn sync_peer(&self) -> Option<std::net::SocketAddr> {
        self.sync_peer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chroma_core::types::{BlockHeight, CompactTarget};

    /// A target that takes a few thousand hashes to hit, so tests can produce
    /// real proof of work. The genesis target is difficulty 1, which needs
    /// billions of attempts and is not reachable in a test.
    fn easy_bits() -> CompactTarget {
        CompactTarget(0x1f00ffff)
    }

    fn test_genesis() -> BlockHeader {
        BlockHeader {
            version: 1,
            previous_hash: Hash::ZERO,
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: 1_767_225_600,
            bits: easy_bits(),
            height: BlockHeight(0),
            nonce: 0,
        }
    }

    /// Build a header on top of `parent` and search for a nonce that satisfies
    /// its target.
    fn mine_on(parent: &BlockHeader) -> BlockHeader {
        let mut header = BlockHeader {
            version: 1,
            previous_hash: parent.hash(),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: parent.timestamp + 10,
            bits: parent.bits,
            height: BlockHeight(parent.height.0 + 1),
            nonce: 0,
        };
        let target = header.bits.to_full_target();
        for nonce in 0..50_000_000u64 {
            header.nonce = nonce;
            if chroma_crypto::randomx::hash_meets_target(&header.hash(), &target) {
                return header;
            }
        }
        panic!("could not mine a test header");
    }

    fn mined_chain(len: usize) -> (BlockHeader, Vec<BlockHeader>) {
        let genesis = test_genesis();
        let mut chain = Vec::new();
        let mut parent = genesis.clone();
        for _ in 0..len {
            let next = mine_on(&parent);
            chain.push(next.clone());
            parent = next;
        }
        (genesis, chain)
    }

    #[test]
    fn test_absorb_valid_chain() {
        let (genesis, chain) = mined_chain(4);
        let mut syncer = ChainSyncer::with_genesis(genesis);

        let batch = syncer.absorb_headers(&chain);
        assert!(batch.is_clean(), "unexpected rejection: {:?}", batch.rejected);
        assert_eq!(batch.accepted, 4);
        assert_eq!(syncer.best_height, 4);
        assert_eq!(syncer.best_hash, chain[3].hash());
    }

    #[test]
    fn test_absorb_is_idempotent() {
        // A peer resending an overlapping range is normal, not misbehaviour.
        let (genesis, chain) = mined_chain(3);
        let mut syncer = ChainSyncer::with_genesis(genesis);

        assert_eq!(syncer.absorb_headers(&chain).accepted, 3);
        let again = syncer.absorb_headers(&chain);
        assert!(again.is_clean());
        assert_eq!(again.accepted, 3);
        assert_eq!(syncer.best_height, 3);
    }

    #[test]
    fn test_absorb_rejects_broken_link() {
        let (genesis, mut chain) = mined_chain(3);
        chain[2].previous_hash = Hash::blake3(b"not the parent");

        let mut syncer = ChainSyncer::with_genesis(genesis);
        let batch = syncer.absorb_headers(&chain);
        assert_eq!(batch.accepted, 2, "the valid prefix should still be kept");
        assert!(batch.rejected.unwrap().contains("does not link"));
        assert_eq!(syncer.best_height, 2);
    }

    #[test]
    fn test_absorb_rejects_bad_pow() {
        let (genesis, mut chain) = mined_chain(2);
        // Break the proof of work without touching anything else.
        chain[1].nonce = chain[1].nonce.wrapping_add(1);

        let mut syncer = ChainSyncer::with_genesis(genesis);
        let batch = syncer.absorb_headers(&chain);
        assert_eq!(batch.accepted, 1);
        assert!(batch.rejected.unwrap().contains("does not meet its target"));
    }

    #[test]
    fn test_absorb_rejects_wrong_bits() {
        let (genesis, mut chain) = mined_chain(1);
        chain[0].bits = CompactTarget(0x1e00ffff);

        let mut syncer = ChainSyncer::with_genesis(genesis);
        let batch = syncer.absorb_headers(&chain);
        assert_eq!(batch.accepted, 0);
        assert!(batch.rejected.unwrap().contains("declares bits"));
    }

    #[test]
    fn test_absorb_rejects_timestamp_at_mtp() {
        let (genesis, chain) = mined_chain(1);
        let mut stale = chain[0].clone();
        stale.timestamp = genesis.timestamp; // equal to MTP, must be strictly after

        // Re-mine so the failure is the timestamp, not the proof of work.
        let target = stale.bits.to_full_target();
        let mut mined = false;
        for nonce in 0..50_000_000u64 {
            stale.nonce = nonce;
            if chroma_crypto::randomx::hash_meets_target(&stale.hash(), &target) {
                mined = true;
                break;
            }
        }
        assert!(mined);

        let mut syncer = ChainSyncer::with_genesis(genesis);
        let batch = syncer.absorb_headers(&[stale]);
        assert_eq!(batch.accepted, 0);
        assert!(batch.rejected.unwrap().contains("MTP"));
    }

    #[test]
    fn test_absorb_rejects_second_genesis() {
        let (genesis, _) = mined_chain(0);
        let mut syncer = ChainSyncer::with_genesis(genesis.clone());

        let mut impostor = genesis.clone();
        impostor.timestamp += 1;
        let batch = syncer.absorb_headers(&[impostor]);
        assert_eq!(batch.accepted, 0);
        assert!(batch.rejected.unwrap().contains("conflicts"));
    }

    #[test]
    fn test_absorb_rejects_orphan() {
        let (genesis, chain) = mined_chain(3);
        let mut syncer = ChainSyncer::with_genesis(genesis);

        // Offer only the last header: its parent is unknown to us.
        let batch = syncer.absorb_headers(&chain[2..]);
        assert_eq!(batch.accepted, 0);
        assert!(batch.rejected.unwrap().contains("no parent"));
    }

    #[test]
    fn test_headers_after_serves_the_range() {
        let (genesis, chain) = mined_chain(4);
        let genesis_hash = genesis.hash();
        let mut syncer = ChainSyncer::with_genesis(genesis);
        syncer.absorb_headers(&chain);

        let from_genesis = syncer.headers_after(&genesis_hash, &Hash::ZERO);
        assert_eq!(from_genesis.len(), 4);
        assert_eq!(from_genesis[0].height.0, 1);
        assert_eq!(from_genesis[3].height.0, 4);

        // Midway through the chain.
        let from_second = syncer.headers_after(&chain[1].hash(), &Hash::ZERO);
        assert_eq!(from_second.len(), 2);
        assert_eq!(from_second[0].height.0, 3);

        // Caught up: nothing further to offer.
        assert!(syncer.headers_after(&chain[3].hash(), &Hash::ZERO).is_empty());

        // An unknown starting point yields nothing rather than the whole chain.
        assert!(syncer
            .headers_after(&Hash::blake3(b"unknown"), &Hash::ZERO)
            .is_empty());
    }

    #[test]
    fn test_headers_after_honours_stop_hash() {
        let (genesis, chain) = mined_chain(4);
        let genesis_hash = genesis.hash();
        let mut syncer = ChainSyncer::with_genesis(genesis);
        syncer.absorb_headers(&chain);

        let stopped = syncer.headers_after(&genesis_hash, &chain[1].hash());
        assert_eq!(stopped.len(), 2);
        assert_eq!(stopped[1].hash(), chain[1].hash());
    }

    #[test]
    fn test_new_syncer() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        assert_eq!(syncer.state, SyncState::Idle);
        assert_eq!(syncer.best_height, 0);
        assert_eq!(syncer.best_hash, genesis);
    }

    #[test]
    fn test_start_header_sync() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let peer = "127.0.0.1:8333".parse().unwrap();
        let from = Hash::blake3(b"start");
        let msg = syncer.start_header_sync(peer, from);
        assert_eq!(syncer.state, SyncState::SyncingHeaders);
        assert_eq!(msg.start_hash, from);
        assert_eq!(msg.stop_hash, Hash::ZERO);
    }

    #[test]
    fn test_received_header() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let h1 = Hash::blake3(b"block1");
        syncer.received_header(h1, 1);
        assert_eq!(syncer.best_height, 1);
        assert_eq!(syncer.best_hash, h1);
    }

    #[test]
    fn test_received_header_no_regression() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        let h1 = Hash::blake3(b"block1");
        let h0 = Hash::blake3(b"block0");
        syncer.received_header(h1, 1);
        syncer.received_header(h0, 0);
        assert_eq!(syncer.best_height, 1);
        assert_eq!(syncer.best_hash, h1);
    }

    #[test]
    fn test_sync_complete() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingHeaders;
        syncer.sync_complete();
        assert_eq!(syncer.state, SyncState::CaughtUp);
        assert!(syncer.sync_peer().is_none());
    }

    #[test]
    fn test_sync_failed() {
        let genesis = Hash::blake3(b"genesis");
        let mut syncer = ChainSyncer::new(genesis);
        syncer.state = SyncState::SyncingBlocks;
        syncer.sync_failed();
        assert_eq!(syncer.state, SyncState::Idle);
    }

    #[test]
    fn test_is_syncing() {
        let genesis = Hash::blake3(b"genesis");
        let syncer = ChainSyncer::new(genesis);
        assert!(!syncer.is_syncing());
    }
}
