//! P2P integration tests over real TCP sockets.
//!
//! These exercise the behaviours that unit tests on `PeerManager` and the wire
//! codec cannot reach: that a connection stays open and usable across many
//! messages, that a frame larger than one socket read is reassembled instead of
//! killing the peer, that received transactions reach the mempool, and that
//! shutdown actually stops.

use std::net::SocketAddr;
use std::time::Duration;

use chroma_core::hash::Hash160;
use chroma_core::serialize::CanonicalEncode;
use chroma_core::types::{Address, Amount, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_p2p::peer::PeerState;
use chroma_p2p::wire::{
    decode_frame, FrameDecode, Message, MessageType, PingMessage, VersionMessage,
};
use chroma_p2p::{Node, NodeConfig, NodeEvent, PROTOCOL_VERSION};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "chroma_p2p_it_{}_{}_{}",
        tag,
        std::process::id(),
        id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Start a node on an ephemeral port with mining off (these tests are about
/// networking, and the miner would only add noise and CPU load).
async fn start_node(tag: &str) -> (Node, SocketAddr, std::path::PathBuf) {
    let dir = temp_dir(tag);
    let genesis = chroma_consensus::build_genesis_block().hash();
    let config = NodeConfig::new("127.0.0.1:0".parse().unwrap(), genesis)
        .with_data_dir(dir.clone())
        .with_mining(false);
    let mut node = Node::new(config);
    node.run().await.expect("node failed to start");
    let addr = node.local_addr().expect("listener not bound");
    (node, addr, dir)
}

/// Start a regtest node. Regtest mining is effectively free, so a node can
/// actually produce blocks for propagation tests.
async fn start_regtest_node(
    tag: &str,
    mining: bool,
    connect: Vec<SocketAddr>,
) -> (Node, SocketAddr, std::path::PathBuf) {
    let dir = temp_dir(tag);
    let params = chroma_consensus::ChainParams::regtest();
    let config = NodeConfig::new("127.0.0.1:0".parse().unwrap(), chroma_core::hash::Hash::ZERO)
        .with_params(params)
        .with_data_dir(dir.clone())
        .with_mining(mining)
        .with_connect_addrs(connect);
    let mut node = Node::new(config);
    node.run().await.expect("node failed to start");
    let addr = node.local_addr().expect("listener not bound");
    (node, addr, dir)
}

/// A minimal peer implementation driven by the test, so we can control exactly
/// what goes on the wire and observe exactly what comes back.
pub struct RawPeer {
    stream: TcpStream,
    buf: Vec<u8>,
    listen_port: u16,
}

impl RawPeer {
    async fn connect(addr: SocketAddr, listen_port: u16) -> Self {
        let stream = TcpStream::connect(addr).await.expect("dial failed");
        RawPeer {
            stream,
            buf: Vec::new(),
            listen_port,
        }
    }

    async fn send(&mut self, msg: Message) {
        self.stream
            .write_all(&msg.encode())
            .await
            .expect("write failed");
    }

    /// Read until one full frame is decoded, or the deadline expires.
    async fn recv(&mut self) -> Option<Message> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            match decode_frame(&self.buf).expect("peer sent a malformed frame") {
                FrameDecode::Complete { message, consumed } => {
                    self.buf.drain(..consumed);
                    return Some(message);
                }
                FrameDecode::Incomplete { .. } => {}
            }
            let mut chunk = vec![0u8; 8192];
            let n = match tokio::time::timeout_at(deadline, self.stream.read(&mut chunk)).await {
                Ok(Ok(0)) => return None,
                Ok(Ok(n)) => n,
                _ => return None,
            };
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn recv_expect(&mut self, want: MessageType) -> Message {
        loop {
            let msg = self.recv().await.unwrap_or_else(|| {
                panic!("connection closed while waiting for {:?}", want);
            });
            if msg.msg_type == want {
                return msg;
            }
        }
    }

    /// Complete the version/verack handshake as the initiating side.
    async fn handshake(&mut self) {
        self.handshake_claiming_height(0).await
    }

    /// Handshake while advertising `height`, which is what makes the node
    /// decide whether it needs to sync from us.
    async fn handshake_claiming_height(&mut self, height: u32) {
        let version = VersionMessage {
            version: PROTOCOL_VERSION,
            services: 0,
            timestamp: 1_700_000_000,
            height,
            nonce: 0xFEED_BEEF_1234_5678,
            listen_port: self.listen_port,
        };
        self.send(Message::new(MessageType::Version, version.encode()))
            .await;

        // The node answers with its own version and a verack; order is not
        // guaranteed, so accept them in either order.
        let mut got_version = false;
        let mut got_verack = false;
        while !(got_version && got_verack) {
            match self.recv().await.expect("closed during handshake").msg_type {
                MessageType::Version => got_version = true,
                MessageType::VerAck => got_verack = true,
                _ => {}
            }
        }

        // Acknowledge theirs so the node marks us Ready.
        self.send(Message::new(MessageType::VerAck, vec![])).await;
    }
}

/// Poll a condition until it holds or the timeout expires.
async fn wait_for<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if f().await {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {}", what);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn signed_transaction(nonce: u64) -> chroma_tx::Transaction {
    let secret = SecretKey32::generate();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(hash160(&pubkey.0)));
    let recipient = Address::from_hash160(Hash160([0x77u8; 20]));
    chroma_tx::create_transaction(
        &secret,
        sender,
        recipient,
        Amount(1_000),
        Nonce(nonce),
    )
    .expect("failed to build transaction")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two real nodes: one dials the other, both reach Ready, and both report the
/// peer under its *listening* address rather than an ephemeral port.
#[tokio::test]
async fn two_nodes_complete_handshake() {
    let (node_a, addr_a, dir_a) = start_node("hs_a").await;

    let dir_b = temp_dir("hs_b");
    let genesis = chroma_consensus::build_genesis_block().hash();
    let config_b = NodeConfig::new("127.0.0.1:0".parse().unwrap(), genesis)
        .with_data_dir(dir_b.clone())
        .with_mining(false)
        .with_connect_addrs(vec![addr_a]);
    let mut node_b = Node::new(config_b);
    node_b.run().await.expect("node b failed to start");
    let addr_b = node_b.local_addr().unwrap();

    let pm_b = node_b.peer_manager();
    wait_for("node B to mark node A ready", || {
        let pm = pm_b.clone();
        async move {
            let pm = pm.read().await;
            pm.get_peer(&addr_a).map(|p| p.state == PeerState::Ready) == Some(true)
        }
    })
    .await;

    // The inbound side must have re-keyed node B from its ephemeral source
    // port to the port B actually listens on.
    let pm_a = node_a.peer_manager();
    wait_for("node A to key node B by its listen address", || {
        let pm = pm_a.clone();
        async move {
            let pm = pm.read().await;
            pm.get_peer(&addr_b).map(|p| p.state == PeerState::Ready) == Some(true)
        }
    })
    .await;

    let mut node_a = node_a;
    let mut node_b = node_b;
    node_a.shutdown().await;
    node_b.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// A frame far larger than one socket read must be reassembled, and the
/// connection must stay usable afterwards.
///
/// The old reader used a fixed 8 KiB buffer and treated a partial frame as a
/// fatal decode error, so anything over 8 KiB silently killed the peer.
#[tokio::test]
async fn large_frame_does_not_drop_the_connection() {
    let (mut node, addr, dir) = start_node("bigframe").await;

    let mut peer = RawPeer::connect(addr, 40_001).await;
    peer.handshake().await;

    // 900 KiB of payload: ~56 socket reads on the node's side, and far past
    // the old buffer. The payload is not a valid block, so the node will log a
    // decode error — the point is that the *connection* survives, proving the
    // frame was reassembled and consumed as one message.
    let big = vec![0x5Au8; 900 * 1024];
    peer.send(Message::new(MessageType::Block, big)).await;

    // Round-trip a ping afterwards: if framing had desynchronised or the
    // connection had been torn down, no pong would come back.
    peer.send(Message::new(
        MessageType::Ping,
        PingMessage { nonce: 0xABCD }.encode(),
    ))
    .await;
    let pong = peer.recv_expect(MessageType::Pong).await;
    assert_eq!(
        PingMessage::decode(&pong.payload).unwrap().nonce,
        0xABCD,
        "connection must still be framed correctly after a 900 KiB message"
    );

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Several messages must travel over the *same* connection. Previously each
/// outgoing message opened a fresh TCP connection, so a peer never saw more
/// than one message per socket.
#[tokio::test]
async fn many_messages_share_one_connection() {
    let (mut node, addr, dir) = start_node("persist").await;

    let mut peer = RawPeer::connect(addr, 40_002).await;
    peer.handshake().await;

    for i in 0..50u64 {
        peer.send(Message::new(
            MessageType::Ping,
            PingMessage { nonce: i }.encode(),
        ))
        .await;
        let pong = peer.recv_expect(MessageType::Pong).await;
        assert_eq!(
            PingMessage::decode(&pong.payload).unwrap().nonce,
            i,
            "pong {} came back on the same connection with the wrong nonce",
            i
        );
    }

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A transaction received from a peer must be verified and stored.
#[tokio::test]
async fn received_transaction_enters_mempool() {
    let (mut node, addr, dir) = start_node("mempool").await;
    let mut events = node.event_rx().expect("event receiver already taken");

    let mut peer = RawPeer::connect(addr, 40_003).await;
    peer.handshake().await;

    let tx = signed_transaction(0);
    let tx_hash = chroma_core::hash::Hash::blake3(&tx.encode());
    peer.send(Message::new(MessageType::Tx, tx.encode())).await;

    let pool = node.mempool();
    wait_for("transaction to reach the mempool", || {
        let pool = pool.clone();
        async move {
            let pool = pool.read().await;
            pool.has_transaction(&tx_hash)
        }
    })
    .await;

    {
        let pool = pool.read().await;
        assert_eq!(pool.len(), 1);
        assert_eq!(
            pool.get_transaction(&tx_hash).map(|t| t.amount),
            Some(Amount(1_000))
        );
    }

    // The node should have announced it.
    let mut saw_event = false;
    while let Ok(event) = events.try_recv() {
        if matches!(event, NodeEvent::TxReceived(h) if h == tx_hash) {
            saw_event = true;
        }
    }
    assert!(saw_event, "expected a TxReceived event for the accepted tx");

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A transaction whose signature does not verify must be rejected, not stored.
#[tokio::test]
async fn invalid_transaction_is_rejected() {
    let (mut node, addr, dir) = start_node("badtx").await;

    let mut peer = RawPeer::connect(addr, 40_004).await;
    peer.handshake().await;

    // Corrupt the signature while keeping the encoding structurally valid.
    let good = signed_transaction(0);
    let mut bytes = good.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered =
        <chroma_tx::Transaction as chroma_core::serialize::CanonicalDecode>::decode(&bytes)
            .expect("tampered tx should still decode");

    peer.send(Message::new(MessageType::Tx, tampered.encode()))
        .await;

    let reject = peer.recv_expect(MessageType::Reject).await;
    assert!(!reject.payload.is_empty());

    let pool = node.mempool();
    let pool = pool.read().await;
    assert_eq!(pool.len(), 0, "an invalid tx must not be stored");
    drop(pool);

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A second connection from a peer we are already connected to must be
/// dropped, leaving exactly one live connection.
#[tokio::test]
async fn duplicate_connection_is_refused() {
    let (mut node, addr, dir) = start_node("dupe").await;

    // Both raw peers claim the same listening port, so the node must treat
    // them as the same peer.
    let mut first = RawPeer::connect(addr, 40_005).await;
    first.handshake().await;

    let mut second = RawPeer::connect(addr, 40_005).await;
    let version = VersionMessage {
        version: PROTOCOL_VERSION,
        services: 0,
        timestamp: 1_700_000_000,
        height: 0,
        nonce: 0x1111_2222_3333_4444,
        listen_port: 40_005,
    };
    second
        .send(Message::new(MessageType::Version, version.encode()))
        .await;

    // The duplicate is closed without a handshake.
    assert!(
        second.recv().await.is_none(),
        "the node should have closed the duplicate connection"
    );

    // The original connection is untouched.
    first
        .send(Message::new(
            MessageType::Ping,
            PingMessage { nonce: 7 }.encode(),
        ))
        .await;
    let pong = first.recv_expect(MessageType::Pong).await;
    assert_eq!(PingMessage::decode(&pong.payload).unwrap().nonce, 7);

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A node that dials itself must notice via the identity nonce and hang up.
#[tokio::test]
async fn self_connection_is_dropped() {
    let (mut node, addr, dir) = start_node("selfconn").await;

    node.connect(addr);

    // Give the dial time to complete and be rejected.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let pm = node.peer_manager();
    let pm = pm.read().await;
    let ready = pm.ready_peers().len();
    drop(pm);
    assert_eq!(ready, 0, "a node must not end up peered with itself");

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A peer that advertises a longer chain must be asked for headers, and the
/// headers it serves must be validated and stored.
///
/// The raw peer plays the role of the node with the longer chain: it claims a
/// height in its version message, answers the resulting GetHeaders with a real
/// mined header chain, and then reports that it has nothing more.
#[tokio::test]
async fn node_syncs_headers_from_a_longer_peer() {
    let (mut node, addr, dir) = start_node("hdrsync").await;
    let mut events = node.event_rx().expect("event receiver already taken");

    // The node's genesis is the real one, at difficulty 1, which cannot be
    // mined in a test. So the chain we serve is built on that genesis but
    // cannot satisfy its target — which is exactly what lets this test also
    // confirm that unmineable headers are rejected rather than trusted.
    let genesis = chroma_consensus::build_genesis_block().header;
    let bogus = chroma_block::BlockHeader {
        version: 1,
        previous_hash: genesis.hash(),
        state_root: chroma_core::hash::Hash::ZERO,
        tx_merkle_root: chroma_core::hash::Hash::ZERO,
        timestamp: genesis.timestamp + 10,
        bits: genesis.bits,
        height: chroma_core::types::BlockHeight(1),
        nonce: 12345,
    };

    let mut peer = RawPeer::connect(addr, 40_007).await;
    peer.handshake_claiming_height(50).await;

    // The node should ask us for headers because we claimed height 50.
    let request = peer.recv_expect(MessageType::GetHeaders).await;
    let request = chroma_p2p::wire::GetHeadersMessage::decode(&request.payload).unwrap();
    assert_eq!(
        request.start_hash,
        genesis.hash(),
        "sync must start from the node's own best header"
    );

    peer.send(Message::new(
        MessageType::Headers,
        chroma_p2p::wire::HeadersMessage {
            headers: vec![bogus],
        }
        .encode(),
    ))
    .await;

    // A header that does not meet its target must be refused.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut refused = false;
    while std::time::Instant::now() < deadline && !refused {
        while let Ok(event) = events.try_recv() {
            if let NodeEvent::Error(msg) = &event {
                if msg.contains("does not meet its target") {
                    refused = true;
                }
            }
            if let NodeEvent::HeadersAccepted(n) = &event {
                panic!("node accepted {} unmineable header(s)", n);
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(refused, "expected the node to reject the invalid header");

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Shutdown must complete promptly, close peer connections, and release the
/// listening port.
#[tokio::test]
async fn shutdown_is_graceful_and_releases_the_port() {
    let (mut node, addr, dir) = start_node("shutdown").await;

    let mut peer = RawPeer::connect(addr, 40_006).await;
    peer.handshake().await;

    let started = std::time::Instant::now();
    node.shutdown().await;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "shutdown took {:?}, which suggests a task never observed the signal",
        elapsed
    );

    // The peer sees a clean EOF, promptly. `recv` reports a stalled
    // connection the same way it reports EOF, so the elapsed time is what
    // distinguishes "closed" from "left hanging until the idle timeout".
    let closed_at = std::time::Instant::now();
    assert!(
        peer.recv().await.is_none(),
        "peer connections should be closed by shutdown"
    );
    assert!(
        closed_at.elapsed() < Duration::from_secs(2),
        "peer waited {:?} for EOF — shutdown left the connection hanging",
        closed_at.elapsed()
    );

    // The port is free again, so the listener really stopped.
    wait_for("the listening port to be released", || async move {
        tokio::net::TcpListener::bind(addr).await.is_ok()
    })
    .await;

    // Shutting down twice must not panic.
    node.shutdown().await;

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Block propagation
// ---------------------------------------------------------------------------

/// The whole point of phase 4: a block mined on one node reaches another over
/// the wire and is validated there.
///
/// Nothing about this worked before — the miner never announced what it found,
/// GetData was ignored so nobody ever served a block, and Inv was answered by
/// asking for everything regardless of what we already had.
#[tokio::test]
async fn mined_block_propagates_to_a_peer() {
    // The listener mines; the dialer only follows.
    let (miner, miner_addr, dir_a) = start_regtest_node("prop_miner", true, vec![]).await;
    let (follower, _addr_b, dir_b) =
        start_regtest_node("prop_follower", false, vec![miner_addr]).await;

    let storage_height = follower.peer_manager();
    wait_for("the follower to connect", || {
        let pm = storage_height.clone();
        async move {
            let pm = pm.read().await;
            pm.get_peer(&miner_addr).map(|p| p.state == PeerState::Ready) == Some(true)
        }
    })
    .await;

    // The miner produces blocks and announces them; the follower should end up
    // holding the same chain without ever mining itself.
    wait_for("the follower to receive mined blocks", || async {
        follower.chain_height() >= 2
    })
    .await;

    let follower_height = follower.chain_height();
    let miner_height = miner.chain_height();
    assert!(
        follower_height >= 2,
        "follower should have followed the miner, got height {}",
        follower_height
    );
    assert!(
        miner_height >= follower_height,
        "the miner cannot be behind the node following it"
    );

    // The follower validated and stored them, not just counted them.
    let tip = follower
        .storage()
        .get_block_by_height(follower_height)
        .expect("storage read")
        .expect("follower should have stored the block at its tip");
    assert_eq!(tip.header.height.0, follower_height);
    assert!(tip.transactions[0].is_coinbase());

    let mut miner = miner;
    let mut follower = follower;
    miner.shutdown().await;
    follower.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// An announcement for a block we already have must not trigger a download.
#[tokio::test]
async fn duplicate_announcement_is_not_re_requested() {
    let (mut node, addr, dir) = start_regtest_node("dup_block", false, vec![]).await;

    let mut peer = RawPeer::connect(addr, 40_010).await;
    peer.handshake().await;

    // Genesis is the one block the node is guaranteed to hold.
    let genesis = chroma_consensus::build_genesis_block_with(
        &chroma_consensus::ChainParams::regtest(),
    );
    let inv = chroma_p2p::wire::InvMessage {
        inventory: vec![chroma_p2p::wire::InvEntry {
            inv_type: chroma_p2p::wire::InvType::Block,
            hash: genesis.hash(),
        }],
    };
    peer.send(Message::new(MessageType::Inv, inv.encode())).await;

    // Follow it with a ping. Replies go out in order on the one connection, so
    // once our pong comes back, any GetData the announcement provoked would
    // already have arrived. The node also sends pings of its own, so drain
    // until the pong rather than assuming what lands first.
    peer.send(Message::new(
        MessageType::Ping,
        PingMessage { nonce: 0x5150 }.encode(),
    ))
    .await;

    loop {
        let reply = peer.recv().await.expect("connection closed before the pong");
        assert_ne!(
            reply.msg_type,
            MessageType::GetData,
            "the node asked for a block it already had"
        );
        if reply.msg_type == MessageType::Pong
            && PingMessage::decode(&reply.payload).unwrap().nonce == 0x5150
        {
            break;
        }
    }

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// GetData for a block we hold must be answered with the block; for one we do
/// not, with NotFound.
#[tokio::test]
async fn getdata_serves_blocks_and_reports_misses() {
    let (mut node, addr, dir) = start_regtest_node("serve", false, vec![]).await;

    let mut peer = RawPeer::connect(addr, 40_011).await;
    peer.handshake().await;

    let genesis = chroma_consensus::build_genesis_block_with(
        &chroma_consensus::ChainParams::regtest(),
    );
    let req = chroma_p2p::wire::GetDataMessage {
        inventory: vec![chroma_p2p::wire::InvEntry {
            inv_type: chroma_p2p::wire::InvType::Block,
            hash: genesis.hash(),
        }],
    };
    peer.send(Message::new(MessageType::GetData, req.encode()))
        .await;

    let served = peer.recv_expect(MessageType::Block).await;
    let block = chroma_block::Block::decode_block(&served.payload).expect("served block decodes");
    assert_eq!(block.hash(), genesis.hash());

    // Now ask for something that does not exist.
    let req = chroma_p2p::wire::GetDataMessage {
        inventory: vec![chroma_p2p::wire::InvEntry {
            inv_type: chroma_p2p::wire::InvType::Block,
            hash: chroma_core::hash::Hash::blake3(b"no such block"),
        }],
    };
    peer.send(Message::new(MessageType::GetData, req.encode()))
        .await;
    let miss = peer.recv_expect(MessageType::NotFound).await;
    let miss = chroma_p2p::wire::InvMessage::decode(&miss.payload).unwrap();
    assert_eq!(miss.inventory.len(), 1);

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Transaction network
// ---------------------------------------------------------------------------

/// A transaction submitted to one node must reach another, and then be mined
/// into a block that both nodes accept.
///
/// This is the end-to-end path phase 3 is about: relay, inclusion, and the
/// balance actually moving.
#[tokio::test]
async fn transaction_reaches_a_peer_and_gets_mined() {
    use chroma_core::types::Amount;

    // The miner funds itself first, so it has something to spend.
    let secret = SecretKey32::generate();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let sender = Address::from_hash160(Hash160(hash160(&pubkey.0)));
    let recipient = Address::from_hash160(Hash160([0x5A; 20]));

    let dir_a = temp_dir("txnet_miner");
    let params = chroma_consensus::ChainParams::regtest();
    let config_a = NodeConfig::new("127.0.0.1:0".parse().unwrap(), chroma_core::hash::Hash::ZERO)
        .with_params(params)
        .with_data_dir(dir_a.clone())
        .with_mining(true)
        .with_miner_address(sender);
    let mut miner = Node::new(config_a);
    miner.run().await.expect("miner failed to start");
    let miner_addr = miner.local_addr().unwrap();

    let (relay, _relay_addr, dir_b) =
        start_regtest_node("txnet_relay", false, vec![miner_addr]).await;

    wait_for("the relay to connect", || async {
        let pm = relay.peer_manager();
        let pm = pm.read().await;
        pm.get_peer(&miner_addr).map(|p| p.state == PeerState::Ready) == Some(true)
    })
    .await;

    // Let the miner accumulate a balance to spend.
    wait_for("the miner to earn a reward", || async {
        miner.chain_height() >= 2
    })
    .await;

    // Submit to the relay, which does not mine: the transaction only gets
    // into a block if it is passed on.
    let tx = chroma_tx::create_transaction(
        &secret,
        sender,
        recipient,
        Amount(300_000),
        Nonce(0),
    )
    .unwrap();
    let tx_hash = chroma_core::hash::Hash::blake3(&tx.encode());
    {
        let pool = relay.mempool();
        let mut pool = pool.write().await;
        pool.add_transaction(tx).unwrap();
    }
    // Announce it the way a peer would.
    relay.broadcast_transaction(tx_hash);

    wait_for("the miner to receive the relayed transaction", || async {
        let pool = miner.mempool();
        let pool = pool.read().await;
        pool.has_transaction(&tx_hash)
    })
    .await;

    // ...and then to mine it, moving the balance.
    wait_for("the transfer to be mined", || async {
        let cs = miner.chain_state();
        let cs = cs.read().await;
        cs.state.get_account(&recipient).balance == 300_000
    })
    .await;

    {
        let cs = miner.chain_state();
        let cs = cs.read().await;
        assert_eq!(cs.state.get_account(&recipient).balance, 300_000);
        assert_eq!(cs.state.get_account(&sender).nonce, 1, "the sender's nonce advanced");
    }

    // Once mined it is no longer pending.
    let pool = miner.mempool();
    let pool = pool.read().await;
    assert!(
        !pool.has_transaction(&tx_hash),
        "a mined transaction must leave the mempool"
    );
    drop(pool);

    let mut miner = miner;
    let mut relay = relay;
    miner.shutdown().await;
    relay.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// A node joining an existing chain must fetch the history forward, driven by
/// the headers it just accepted.
///
/// Without that, blocks are only pulled in by the orphan handler asking for
/// each parent in turn: one round trip per block, walking backwards. The
/// ordering is what distinguishes the two, so that is what this asserts.
#[tokio::test]
async fn late_joining_node_downloads_history_in_order() {
    let secret = SecretKey32::generate();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let miner_payout = Address::from_hash160(Hash160(hash160(&pubkey.0)));

    let dir_a = temp_dir("catchup_miner");
    let params = chroma_consensus::ChainParams::regtest();
    let config_a = NodeConfig::new("127.0.0.1:0".parse().unwrap(), chroma_core::hash::Hash::ZERO)
        .with_params(params)
        .with_data_dir(dir_a.clone())
        .with_mining(true)
        .with_miner_address(miner_payout);
    let mut miner = Node::new(config_a);
    miner.run().await.expect("miner failed to start");
    let miner_addr = miner.local_addr().unwrap();

    // Build some history before the second node exists.
    wait_for("the miner to build a chain", || async {
        miner.chain_height() >= 4
    })
    .await;
    let history = miner.chain_height();

    let dir_b = temp_dir("catchup_joiner");
    let config_b = NodeConfig::new("127.0.0.1:0".parse().unwrap(), chroma_core::hash::Hash::ZERO)
        .with_params(params)
        .with_data_dir(dir_b.clone())
        .with_mining(false)
        .with_connect_addrs(vec![miner_addr]);
    let mut joiner = Node::new(config_b);
    let mut events = joiner.event_rx().expect("event receiver already taken");
    joiner.run().await.expect("joiner failed to start");

    wait_for("the joiner to catch up", || async {
        joiner.chain_height() >= history
    })
    .await;

    // The first blocks it took must be the bottom of the chain, in order.
    let mut heights = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let NodeEvent::BlockReceived(_, height) = event {
            heights.push(height);
        }
    }
    assert!(
        heights.len() >= history as usize,
        "expected at least {} blocks, saw {:?}",
        history,
        heights
    );
    let ordered: Vec<u32> = heights.iter().copied().take(history as usize).collect();
    let mut expected: Vec<u32> = (1..=history).collect();
    expected.truncate(ordered.len());
    assert_eq!(
        ordered, expected,
        "history should arrive oldest first; walking backwards would give {:?} reversed",
        expected
    );

    let mut miner = miner;
    let mut joiner = joiner;
    miner.shutdown().await;
    joiner.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
}

/// A restarted node must come back with the same chain and balances, without
/// revalidating every block it already accepted.
#[tokio::test]
async fn node_restart_restores_chain_and_balances() {
    let secret = SecretKey32::generate();
    let pubkey = PublicKey32::from_secret(&secret).unwrap();
    let payout = Address::from_hash160(Hash160(hash160(&pubkey.0)));

    let dir = temp_dir("restart");
    let params = chroma_consensus::ChainParams::regtest();
    let build = |mining: bool| {
        NodeConfig::new("127.0.0.1:0".parse().unwrap(), chroma_core::hash::Hash::ZERO)
            .with_params(params)
            .with_data_dir(dir.clone())
            .with_mining(mining)
            .with_miner_address(payout)
    };

    let mut node = Node::new(build(true));
    node.run().await.expect("node failed to start");
    wait_for("the node to mine a few blocks", || async {
        node.chain_height() >= 3
    })
    .await;

    let (height, tip, balance, supply) = {
        let cs = node.chain_state();
        let cs = cs.read().await;
        (
            cs.tip.height.0,
            cs.tip.hash,
            cs.state.get_account(&payout).balance,
            cs.state.total_supply(),
        )
    };
    assert!(balance > 0, "the miner should have earned something");
    node.shutdown().await;
    // sled holds the directory lock until the node is dropped, so the restart
    // cannot open it while the first node is still alive.
    drop(node);
    tokio::task::yield_now().await;

    // Reopen the same directory.
    let restarted = Node::new(build(false));
    let cs = restarted.chain_state();
    let cs = cs.read().await;
    assert_eq!(cs.tip.height.0, height, "height must survive a restart");
    assert_eq!(cs.tip.hash, tip, "the tip must survive a restart");
    assert_eq!(
        cs.state.get_account(&payout).balance,
        balance,
        "balances must survive a restart"
    );
    assert_eq!(cs.state.total_supply(), supply);
    assert_eq!(
        cs.state.compute_state_root(),
        cs.tip.header.state_root,
        "the restored state must match what the tip committed to"
    );
    drop(cs);

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Hardening
// ---------------------------------------------------------------------------

/// A peer announcing a protocol version we do not speak must be rejected
/// during the handshake, with a reason.
#[tokio::test]
async fn obsolete_protocol_version_is_rejected() {
    let (mut node, addr, dir) = start_regtest_node("oldver", false, vec![]).await;

    let mut peer = RawPeer::connect(addr, 40_020).await;
    let version = VersionMessage {
        version: 0, // below MIN_PROTOCOL_VERSION
        services: 0,
        timestamp: 1_700_000_000,
        height: 0,
        nonce: 0x1234_5678_9ABC_DEF0,
        listen_port: 40_020,
    };
    peer.send(Message::new(MessageType::Version, version.encode()))
        .await;

    let reject = peer.recv_expect(MessageType::Reject).await;
    let reject = chroma_p2p::wire::RejectMessage::decode(&reject.payload).unwrap();
    assert!(
        reject.reason.contains("version"),
        "unexpected reject reason: {}",
        reject.reason
    );

    // ...and the connection is closed rather than left half-open.
    assert!(peer.recv().await.is_none());

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A peer flooding messages must be cut off rather than allowed to make us
/// spend unbounded work.
#[tokio::test]
async fn message_flood_disconnects_the_peer() {
    let (mut node, addr, dir) = start_regtest_node("flood", false, vec![]).await;

    let mut peer = RawPeer::connect(addr, 40_021).await;
    peer.handshake().await;

    // Well past the per-second allowance, sent as fast as possible.
    let ping = Message::new(MessageType::Ping, PingMessage { nonce: 1 }.encode()).encode();
    let mut blast = Vec::new();
    for _ in 0..(chroma_p2p::peer::MSG_RATE_LIMIT * 3) {
        blast.extend_from_slice(&ping);
    }
    // A closed connection makes the write fail, which is itself the outcome we
    // are looking for.
    let _ = peer.stream.write_all(&blast).await;

    // The node should hang up.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut closed = false;
    while std::time::Instant::now() < deadline {
        if peer.recv().await.is_none() {
            closed = true;
            break;
        }
    }
    assert!(closed, "the node kept serving a peer that blew past its rate limit");

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Three nodes, but only two of them are told about anyone: C is given B's
/// address, B is given A's, and C must reach A through gossip alone.
///
/// This is what peer discovery is for — without it, every node has to be
/// configured with every other one by hand.
#[tokio::test]
async fn peers_are_discovered_through_gossip() {
    let (node_a, addr_a, dir_a) = start_regtest_node("gossip_a", false, vec![]).await;
    let (node_b, addr_b, dir_b) = start_regtest_node("gossip_b", false, vec![addr_a]).await;

    // Let B finish handshaking with A, so A is worth passing on.
    wait_for("B to connect to A", || async {
        let pm = node_b.peer_manager();
        let pm = pm.read().await;
        pm.get_peer(&addr_a).map(|p| p.state == PeerState::Ready) == Some(true)
    })
    .await;

    // C only knows about B.
    let (node_c, _addr_c, dir_c) = start_regtest_node("gossip_c", false, vec![addr_b]).await;

    wait_for("C to learn about A and connect", || async {
        let pm = node_c.peer_manager();
        let pm = pm.read().await;
        pm.get_peer(&addr_a).map(|p| p.state == PeerState::Ready) == Some(true)
    })
    .await;

    {
        let pm = node_c.peer_manager();
        let pm = pm.read().await;
        assert!(
            pm.get_peer(&addr_a).is_some(),
            "C should have learned A's address from B"
        );
        assert!(pm.ready_peers().len() >= 2, "C should be connected to both");
    }

    let mut node_a = node_a;
    let mut node_b = node_b;
    let mut node_c = node_c;
    node_a.shutdown().await;
    node_b.shutdown().await;
    node_c.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir_a);
    let _ = std::fs::remove_dir_all(&dir_b);
    let _ = std::fs::remove_dir_all(&dir_c);
}

/// A node must not hand a peer back its own address, and must only pass on
/// peers it actually completed a handshake with.
#[tokio::test]
async fn getaddr_shares_only_verified_peers() {
    let (mut node, addr, dir) = start_regtest_node("getaddr", false, vec![]).await;

    let mut peer = RawPeer::connect(addr, 40_030).await;
    peer.handshake().await;

    peer.send(Message::new(MessageType::GetAddr, vec![])).await;
    let reply = peer.recv_expect(MessageType::Addr).await;
    let addrs = chroma_p2p::wire::AddrMessage::decode(&reply.payload).unwrap();

    let own: SocketAddr = format!("127.0.0.1:{}", 40_030).parse().unwrap();
    assert!(
        !addrs.addrs.contains(&own),
        "a peer must not be told about itself, got {:?}",
        addrs.addrs
    );
    // The node has no other handshaked peers, so it has nothing to offer.
    assert!(
        addrs.addrs.is_empty(),
        "only handshaked peers should be shared, got {:?}",
        addrs.addrs
    );

    node.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
