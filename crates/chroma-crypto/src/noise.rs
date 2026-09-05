//! Noise Protocol Transport
//!
//! Spec §10: `Noise_XK_25519_ChaChaPoly_BLAKE2s`, with a node identified by
//! its static public key.
//!
//! What XK gives us:
//! - the initiator knows the responder's static key before connecting, so it
//!   authenticates the node it meant to reach rather than whoever answered
//!   the address
//! - the responder learns the initiator's static key during the handshake
//!   (the X), so both ends end up authenticated
//! - the ephemeral exchange gives forward secrecy: recording the traffic and
//!   later stealing a static key does not decrypt it
//!
//! This is not admission control. Anyone can generate an identity and connect;
//! what it provides is confidentiality, integrity, and knowing which node you
//! are talking to.

use getrandom::getrandom;
use snow::{Builder, HandshakeState, TransportState};

use crate::error::{CryptoError, CryptoResult as Result};

/// The handshake pattern and primitives the spec fixes.
pub const NOISE_PATTERN: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";

/// Largest plaintext a single Noise message can carry: the protocol caps a
/// message at 65535 bytes and 16 of those are the authentication tag.
pub const MAX_NOISE_PAYLOAD: usize = 65535 - 16;

/// Node identity: the static X25519 public key.
///
/// The spec writes "ed25519" for node identity while also fixing the Noise
/// suite to `25519`; the key that actually identifies a node in the handshake
/// is the X25519 static key, so that is what this holds.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    /// Generate a new random NodeId.
    ///
    /// Only useful for tests and placeholders; a real node's id comes from its
    /// keypair.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        getrandom(&mut bytes).expect("CSPRNG failure");
        NodeId(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NodeId(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| CryptoError::Noise(format!("invalid node id hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(CryptoError::Noise(format!(
                "node id must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(NodeId(out))
    }
}

/// A node's long-term identity.
pub struct NodeKeypair {
    secret: [u8; 32],
    public: NodeId,
}

impl NodeKeypair {
    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| CryptoError::Noise(format!("bad pattern: {}", e)))?;
        let keys = Builder::new(params)
            .generate_keypair()
            .map_err(|e| CryptoError::Noise(format!("keygen failed: {}", e)))?;

        let mut secret = [0u8; 32];
        let mut public = [0u8; 32];
        if keys.private.len() != 32 || keys.public.len() != 32 {
            return Err(CryptoError::Noise("unexpected key length".to_string()));
        }
        secret.copy_from_slice(&keys.private);
        public.copy_from_slice(&keys.public);

        Ok(NodeKeypair {
            secret,
            public: NodeId(public),
        })
    }

    /// Rebuild an identity from a stored secret, so a node keeps the same
    /// id across restarts.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self> {
        let public = x25519_public_from(&secret);
        Ok(NodeKeypair {
            secret,
            public: NodeId(public),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.public
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret
    }
}

/// Derive the X25519 public key for a secret.
fn x25519_public_from(secret: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    x25519_dalek::PublicKey::from(&s).to_bytes()
}

/// A Noise handshake in progress.
pub struct Handshake {
    state: HandshakeState,
}

impl Handshake {
    /// Start a handshake as the side that dialled, which must already know the
    /// node it is dialling.
    pub fn initiator(local: &NodeKeypair, remote: &NodeId) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| CryptoError::Noise(format!("bad pattern: {}", e)))?;
        let state = Builder::new(params)
            .local_private_key(&local.secret)
            .remote_public_key(&remote.0)
            .build_initiator()
            .map_err(|e| CryptoError::Noise(format!("initiator setup failed: {}", e)))?;
        Ok(Handshake { state })
    }

    /// Start a handshake as the side that was dialled.
    pub fn responder(local: &NodeKeypair) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| CryptoError::Noise(format!("bad pattern: {}", e)))?;
        let state = Builder::new(params)
            .local_private_key(&local.secret)
            .build_responder()
            .map_err(|e| CryptoError::Noise(format!("responder setup failed: {}", e)))?;
        Ok(Handshake { state })
    }

    /// Produce the next handshake message.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_NOISE_PAYLOAD + 16];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("handshake write failed: {}", e)))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume a handshake message from the peer.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_NOISE_PAYLOAD + 16];
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("handshake read failed: {}", e)))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Switch to transport mode once the handshake is complete.
    pub fn into_session(self) -> Result<Session> {
        let remote = self.state.get_remote_static().map(|key| {
            let mut out = [0u8; 32];
            out.copy_from_slice(&key[..32]);
            NodeId(out)
        });
        let state = self
            .state
            .into_transport_mode()
            .map_err(|e| CryptoError::Noise(format!("cannot enter transport mode: {}", e)))?;
        Ok(Session {
            state,
            remote: remote
                .ok_or_else(|| CryptoError::Noise("peer did not present a static key".into()))?,
        })
    }
}

/// An established, encrypted session with a peer.
pub struct Session {
    state: TransportState,
    remote: NodeId,
}

impl Session {
    /// The identity of the node on the other end, as proved by the handshake.
    pub fn remote_node_id(&self) -> NodeId {
        self.remote
    }

    /// Encrypt one chunk. The caller must keep chunks within
    /// [`MAX_NOISE_PAYLOAD`]; longer messages are split by
    /// [`Session::encrypt`].
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; plaintext.len() + 16];
        let n = self
            .state
            .write_message(plaintext, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("encrypt failed: {}", e)))?;
        buf.truncate(n);
        Ok(buf)
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .state
            .read_message(ciphertext, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("decrypt failed: {}", e)))?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Encrypt a message of any length.
    ///
    /// Noise caps a single message at 64 KiB, but a block can be a megabyte,
    /// so anything larger is split into chunks. Each chunk goes out with a
    /// 4-byte big-endian length so the reader knows where it ends.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + 64);
        for chunk in plaintext.chunks(MAX_NOISE_PAYLOAD) {
            let sealed = self.seal(chunk)?;
            out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
            out.extend_from_slice(&sealed);
        }
        // An empty message still needs one chunk, or it would vanish.
        if plaintext.is_empty() {
            let sealed = self.seal(&[])?;
            out.extend_from_slice(&(sealed.len() as u32).to_be_bytes());
            out.extend_from_slice(&sealed);
        }
        Ok(out)
    }

    /// Decrypt a message produced by [`Session::encrypt`].
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(ciphertext.len());
        let mut pos = 0usize;
        while pos < ciphertext.len() {
            if pos + 4 > ciphertext.len() {
                return Err(CryptoError::Noise("truncated chunk length".to_string()));
            }
            let len = u32::from_be_bytes([
                ciphertext[pos],
                ciphertext[pos + 1],
                ciphertext[pos + 2],
                ciphertext[pos + 3],
            ]) as usize;
            pos += 4;
            if len > MAX_NOISE_PAYLOAD + 16 {
                return Err(CryptoError::Noise(format!("chunk too large: {}", len)));
            }
            if pos + len > ciphertext.len() {
                return Err(CryptoError::Noise("truncated chunk".to_string()));
            }
            out.extend_from_slice(&self.open(&ciphertext[pos..pos + len])?);
            pos += len;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a full XK handshake and return both sides in transport mode.
    fn connected() -> (Session, Session, NodeId, NodeId) {
        let dialer = NodeKeypair::generate().unwrap();
        let listener = NodeKeypair::generate().unwrap();

        let mut ini = Handshake::initiator(&dialer, &listener.node_id()).unwrap();
        let mut res = Handshake::responder(&listener).unwrap();

        let m1 = ini.write_message(&[]).unwrap();
        res.read_message(&m1).unwrap();
        let m2 = res.write_message(&[]).unwrap();
        ini.read_message(&m2).unwrap();
        let m3 = ini.write_message(&[]).unwrap();
        res.read_message(&m3).unwrap();

        assert!(ini.is_finished() && res.is_finished());
        (
            ini.into_session().unwrap(),
            res.into_session().unwrap(),
            dialer.node_id(),
            listener.node_id(),
        )
    }

    #[test]
    fn test_handshake_completes_and_authenticates_both_sides() {
        let (dialer_session, listener_session, dialer_id, listener_id) = connected();
        assert_eq!(
            dialer_session.remote_node_id(),
            listener_id,
            "the dialer must end up talking to the node it asked for"
        );
        assert_eq!(
            listener_session.remote_node_id(),
            dialer_id,
            "the listener learns who dialled it (the X in XK)"
        );
    }

    #[test]
    fn test_round_trip() {
        let (mut a, mut b, _, _) = connected();
        let payload = b"chroma wire frame".to_vec();
        let sealed = a.encrypt(&payload).unwrap();
        assert_ne!(sealed, payload, "the payload must not travel in the clear");
        assert_eq!(b.decrypt(&sealed).unwrap(), payload);
    }

    #[test]
    fn test_round_trip_of_a_full_block() {
        // A block is far larger than a single Noise message, so this is the
        // case that needs chunking.
        let (mut a, mut b, _, _) = connected();
        let payload = vec![0xA5u8; chroma_core::constants::MAX_BLOCK_SIZE];
        let sealed = a.encrypt(&payload).unwrap();
        assert!(sealed.len() > payload.len(), "each chunk carries a tag");
        assert_eq!(b.decrypt(&sealed).unwrap(), payload);
    }

    #[test]
    fn test_empty_message_survives() {
        let (mut a, mut b, _, _) = connected();
        let sealed = a.encrypt(&[]).unwrap();
        assert!(!sealed.is_empty());
        assert!(b.decrypt(&sealed).unwrap().is_empty());
    }

    #[test]
    fn test_messages_are_ordered() {
        // Noise keys each message to a counter, so they have to be read in the
        // order they were written.
        let (mut a, mut b, _, _) = connected();
        let first = a.encrypt(b"one").unwrap();
        let second = a.encrypt(b"two").unwrap();

        assert!(
            b.decrypt(&second).is_err(),
            "reading out of order must fail rather than silently succeed"
        );
        let _ = first;
    }

    #[test]
    fn test_tampering_is_detected() {
        let (mut a, mut b, _, _) = connected();
        let mut sealed = a.encrypt(b"authentic").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(b.decrypt(&sealed).is_err(), "a modified frame must not decrypt");
    }

    #[test]
    fn test_dialing_the_wrong_key_fails() {
        // XK authenticates the responder: connecting to a node presenting a
        // different static key must not produce a session.
        let dialer = NodeKeypair::generate().unwrap();
        let listener = NodeKeypair::generate().unwrap();
        let impostor = NodeKeypair::generate().unwrap();

        let mut ini = Handshake::initiator(&dialer, &impostor.node_id()).unwrap();
        let mut res = Handshake::responder(&listener).unwrap();

        let m1 = ini.write_message(&[]).unwrap();
        // The responder cannot even read a message encrypted to another key.
        assert!(res.read_message(&m1).is_err());
    }

    #[test]
    fn test_two_sessions_differ() {
        // Fresh ephemerals per connection: the same plaintext must not produce
        // the same ciphertext twice.
        let (mut a1, _, _, _) = connected();
        let (mut a2, _, _, _) = connected();
        assert_ne!(
            a1.encrypt(b"same plaintext").unwrap(),
            a2.encrypt(b"same plaintext").unwrap()
        );
    }

    #[test]
    fn test_keypair_from_secret_reproduces_the_identity() {
        // A node must come back with the same id after a restart.
        let original = NodeKeypair::generate().unwrap();
        let reloaded = NodeKeypair::from_secret(original.secret_bytes()).unwrap();
        assert_eq!(reloaded.node_id(), original.node_id());

        // ...and the reloaded identity actually works in a handshake.
        let peer = NodeKeypair::generate().unwrap();
        let mut ini = Handshake::initiator(&peer, &reloaded.node_id()).unwrap();
        let mut res = Handshake::responder(&reloaded).unwrap();
        let m1 = ini.write_message(&[]).unwrap();
        res.read_message(&m1).expect("the derived public key must match the secret");
    }

    #[test]
    fn test_distinct_secrets_give_distinct_identities() {
        let a = NodeKeypair::generate().unwrap();
        let b = NodeKeypair::generate().unwrap();
        assert_ne!(a.node_id(), b.node_id());
        assert_ne!(a.secret_bytes(), b.secret_bytes());
    }

    #[test]
    fn test_node_id_hex_round_trip() {
        let id = NodeId::generate();
        assert_eq!(NodeId::from_hex(&id.to_hex()).unwrap(), id);
        assert!(NodeId::from_hex("nonsense").is_err());
        assert!(NodeId::from_hex("aabb").is_err());
    }

    #[test]
    fn test_decrypt_rejects_malformed_framing() {
        let (mut a, mut b, _, _) = connected();
        let sealed = a.encrypt(b"payload").unwrap();
        assert!(b.decrypt(&sealed[..3]).is_err(), "truncated length");
        assert!(
            b.decrypt(&sealed[..sealed.len() - 1]).is_err(),
            "truncated chunk"
        );
    }
}
