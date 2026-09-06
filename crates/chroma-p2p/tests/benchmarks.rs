//! P2P benchmarks: wire codec and the framing loop.
//!
//! Run with:
//!   cargo test --release -p chroma-p2p --test benchmarks -- --ignored --nocapture
//!
//! Marked `#[ignore]` so an ordinary `cargo test` stays fast.

use std::time::Instant;

use chroma_core::hash::Hash;
use chroma_core::serialize::CanonicalEncode;
use chroma_p2p::wire::{
    decode_frame, FrameDecode, HeadersMessage, InvEntry, InvMessage, InvType, Message, MessageType,
};

fn report(label: &str, total: std::time::Duration, ops: u32) {
    let per = total / ops;
    let rate = ops as f64 / total.as_secs_f64();
    println!("{:<42} {:>12?}/op {:>12.0} ops/s", label, per, rate);
}

fn throughput(label: &str, total: std::time::Duration, bytes: usize) {
    let mib = bytes as f64 / (1024.0 * 1024.0);
    println!(
        "{:<42} {:>12?}       {:>9.1} MiB/s",
        label,
        total,
        mib / total.as_secs_f64()
    );
}

fn sample_header(height: u32) -> chroma_block::BlockHeader {
    use chroma_core::types::{BlockHeight, CompactTarget};
    chroma_block::BlockHeader {
        version: 1,
        previous_hash: Hash::blake3(&height.to_le_bytes()),
        state_root: Hash::blake3(b"state"),
        tx_merkle_root: Hash::blake3(b"txs"),
        timestamp: 1_767_225_600 + height as u64 * 10,
        bits: CompactTarget::DIFFICULTY_1,
        height: BlockHeight(height),
        nonce: height as u64,
    }
}

#[test]
#[ignore]
fn bench_frame_codec() {
    // A small message is the common case: pings, inventories, transactions.
    let msg = Message::new(MessageType::Ping, vec![0u8; 8]);
    let rounds = 100_000u32;

    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(msg.encode());
    }
    report("encode (8 byte payload)", start.elapsed(), rounds);

    let encoded = msg.encode();
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(decode_frame(&encoded).unwrap());
    }
    report("decode_frame (8 byte payload)", start.elapsed(), rounds);
}

#[test]
#[ignore]
fn bench_large_frame_codec() {
    // A full block is the worst case the framing loop has to handle.
    let payload = vec![0xABu8; chroma_core::constants::MAX_BLOCK_SIZE];
    let rounds = 200u32;

    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(Message::new(MessageType::Block, payload.clone()).encode());
    }
    let elapsed = start.elapsed();
    report("encode (1 MiB block)", elapsed, rounds);
    throughput("encode (1 MiB block)", elapsed, payload.len() * rounds as usize);

    let encoded = Message::new(MessageType::Block, payload.clone()).encode();
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(decode_frame(&encoded).unwrap());
    }
    let elapsed = start.elapsed();
    report("decode_frame (1 MiB block)", elapsed, rounds);
    throughput("decode_frame (1 MiB block)", elapsed, payload.len() * rounds as usize);
}

#[test]
#[ignore]
fn bench_streaming_reassembly() {
    // What the read loop actually does: bytes arrive in chunks and frames are
    // pulled out as they complete. This is the path that used to break on
    // anything over 8 KiB.
    let mut wire = Vec::new();
    for i in 0..200u64 {
        wire.extend_from_slice(&Message::new(MessageType::Ping, i.to_le_bytes().to_vec()).encode());
    }
    let big = Message::new(MessageType::Block, vec![7u8; 512 * 1024]).encode();
    wire.extend_from_slice(&big);

    let chunk_size = 16 * 1024;
    let rounds = 20u32;
    let start = Instant::now();
    for _ in 0..rounds {
        let mut acc: Vec<u8> = Vec::new();
        let mut decoded = 0;
        for chunk in wire.chunks(chunk_size) {
            acc.extend_from_slice(chunk);
            loop {
                match decode_frame(&acc).unwrap() {
                    FrameDecode::Complete { consumed, .. } => {
                        acc.drain(..consumed);
                        decoded += 1;
                    }
                    FrameDecode::Incomplete { .. } => break,
                }
            }
        }
        assert_eq!(decoded, 201);
    }
    let elapsed = start.elapsed();
    report("reassemble 201 frames (~1 MiB)", elapsed, rounds);
    throughput("reassemble 201 frames", elapsed, wire.len() * rounds as usize);
}

#[test]
#[ignore]
fn bench_message_payloads() {
    // Headers and inventories are the bulk messages of sync.
    let headers: Vec<_> = (0..2_000).map(sample_header).collect();
    let msg = HeadersMessage { headers };
    let rounds = 200u32;

    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(msg.encode());
    }
    report("encode 2000 headers", start.elapsed(), rounds);

    let encoded = msg.encode();
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(HeadersMessage::decode(&encoded).unwrap());
    }
    report("decode 2000 headers", start.elapsed(), rounds);

    let inv = InvMessage {
        inventory: (0..500u32)
            .map(|i| InvEntry {
                inv_type: InvType::Block,
                hash: Hash::blake3(&i.to_le_bytes()),
            })
            .collect(),
    };
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(inv.encode());
    }
    report("encode 500-entry inventory", start.elapsed(), rounds);
}

#[test]
#[ignore]
fn bench_transaction_codec() {
    use chroma_core::hash::Hash160;
    use chroma_core::types::{Address, Amount, Nonce};
    use chroma_crypto::hash::hash160;
    use chroma_crypto::schnorr::{PublicKey32, SecretKey32};

    let secret = SecretKey32::generate();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(hash160(&pubkey.0)));
    let tx = chroma_tx::create_transaction(
        &secret,
        sender,
        Address::from_hash160(Hash160([9u8; 20])),
        Amount(1_000),
        Nonce(0),
    )
    .unwrap();

    let rounds = 20_000u32;
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(tx.encode());
    }
    report("encode transaction", start.elapsed(), rounds);

    let encoded = tx.encode();
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(
            <chroma_tx::Transaction as chroma_core::serialize::CanonicalDecode>::decode(&encoded)
                .unwrap(),
        );
    }
    report("decode transaction", start.elapsed(), rounds);

    // Signature verification is what gates every relayed transaction.
    let rounds = 2_000u32;
    let start = Instant::now();
    for _ in 0..rounds {
        std::hint::black_box(tx.verify_signature());
    }
    report("verify_signature", start.elapsed(), rounds);
}
