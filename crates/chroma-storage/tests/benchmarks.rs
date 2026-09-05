//! Storage and state benchmarks.
//!
//! Run with:
//!   cargo test --release -p chroma-storage --test benchmarks -- --ignored --nocapture
//!
//! Marked `#[ignore]` so an ordinary `cargo test` stays fast. Written as tests
//! rather than a bench harness so they need no extra dependency and run on
//! stable.

use std::time::Instant;

use chroma_block::{Block, BlockHeader};
use chroma_core::hash::{Hash, Hash160};
use chroma_core::types::{Address, BlockHeight, CompactTarget};
use chroma_state::State;
use chroma_storage::Storage;

fn address(i: u32) -> Address {
    let mut h = [0u8; 20];
    h[..4].copy_from_slice(&i.to_le_bytes());
    Address::from_hash160(Hash160(h))
}

fn block(height: u32) -> Block {
    Block {
        header: BlockHeader {
            version: 1,
            previous_hash: Hash::blake3(&height.to_le_bytes()),
            state_root: Hash::ZERO,
            tx_merkle_root: Hash::ZERO,
            timestamp: 1_767_225_600 + height as u64 * 10,
            bits: CompactTarget::DIFFICULTY_1,
            height: BlockHeight(height),
            nonce: height as u64,
        },
        transactions: vec![],
    }
}

fn report(label: &str, total: std::time::Duration, ops: u32) {
    let per = total / ops;
    let rate = ops as f64 / total.as_secs_f64();
    println!("{:<40} {:>12?}/op {:>12.0} ops/s", label, per, rate);
}

#[test]
#[ignore]
fn bench_block_write_and_read() {
    let storage = Storage::open_temporary().unwrap();
    let n = 2_000u32;

    let start = Instant::now();
    for height in 1..=n {
        storage.put_block(&block(height)).unwrap();
    }
    storage.flush().unwrap();
    report("put_block", start.elapsed(), n);

    let start = Instant::now();
    for height in 1..=n {
        std::hint::black_box(storage.get_block_by_height(height).unwrap());
    }
    report("get_block_by_height", start.elapsed(), n);

    let hashes: Vec<Hash> = (1..=n).map(|h| block(h).hash()).collect();
    let start = Instant::now();
    for hash in &hashes {
        std::hint::black_box(storage.get_block_by_hash(hash).unwrap());
    }
    report("get_block_by_hash", start.elapsed(), n);

    let start = Instant::now();
    for hash in &hashes {
        std::hint::black_box(storage.get_height_for_hash(hash).unwrap());
    }
    report("get_height_for_hash (index only)", start.elapsed(), n);
}

#[test]
#[ignore]
fn bench_header_access() {
    let storage = Storage::open_temporary().unwrap();
    let n = 5_000u32;

    let start = Instant::now();
    for height in 1..=n {
        storage.put_header(height, &block(height).header).unwrap();
    }
    storage.flush().unwrap();
    report("put_header", start.elapsed(), n);

    let start = Instant::now();
    for height in 1..=n {
        std::hint::black_box(storage.get_header(height).unwrap());
    }
    report("get_header", start.elapsed(), n);
}

#[test]
#[ignore]
fn bench_state_persistence() {
    // put_state rewrites every account, so its cost decides whether persisting
    // after each block is affordable. load_state is what a restart pays
    // instead of revalidating the chain.
    for accounts in [100u32, 1_000, 10_000] {
        let storage = Storage::open_temporary().unwrap();
        let mut state = State::new();
        for i in 0..accounts {
            state.apply_subsidy(&address(i), i).unwrap();
        }

        let rounds = 5;
        let start = Instant::now();
        for _ in 0..rounds {
            storage.put_state(&state).unwrap();
        }
        report(
            &format!("put_state ({} accounts)", accounts),
            start.elapsed(),
            rounds,
        );

        let start = Instant::now();
        for _ in 0..rounds {
            std::hint::black_box(storage.load_state().unwrap());
        }
        report(
            &format!("load_state ({} accounts)", accounts),
            start.elapsed(),
            rounds,
        );
    }
}

#[test]
#[ignore]
fn bench_state_root() {
    // Recomputed for every block, and again for every block replayed during a
    // reorg.
    for accounts in [100u32, 1_000, 10_000] {
        let mut state = State::new();
        for i in 0..accounts {
            state.apply_subsidy(&address(i), i).unwrap();
        }
        let rounds = 20;
        let start = Instant::now();
        for _ in 0..rounds {
            std::hint::black_box(state.compute_state_root());
        }
        report(
            &format!("compute_state_root ({} accounts)", accounts),
            start.elapsed(),
            rounds,
        );
    }
}

#[test]
#[ignore]
fn bench_merkle_proof() {
    for accounts in [1_000u32, 10_000] {
        let mut state = State::new();
        for i in 0..accounts {
            state.apply_subsidy(&address(i), i).unwrap();
        }
        let rounds = 20;
        let start = Instant::now();
        for i in 0..rounds {
            std::hint::black_box(state.merkle_proof(&address(i)).unwrap());
        }
        report(
            &format!("merkle_proof ({} accounts)", accounts),
            start.elapsed(),
            rounds,
        );
    }
}
