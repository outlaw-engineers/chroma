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

pub struct ChainSyncer {
    pub state: SyncState,
    pub best_height: u32,
    pub best_hash: Hash,
    sync_peer: Option<std::net::SocketAddr>,
}

impl ChainSyncer {
    pub fn new(genesis_hash: Hash) -> Self {
        ChainSyncer {
            state: SyncState::Idle,
            best_height: 0,
            best_hash: genesis_hash,
            sync_peer: None,
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
