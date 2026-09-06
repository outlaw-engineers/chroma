//! Noise Protocol Transport
//!
//! Spec §10: `Noise_XK_25519_ChaChaPoly_BLAKE2s`, with a node identified by
//! its ed25519 public key.
//!
//! Two keys, because the spec names both and they cannot be the same key:
//! the node id is an ed25519 signing key, while the Noise suite is fixed to
//! `25519`, meaning X25519 Diffie-Hellman. So a node holds an ed25519
//! identity and a separate X25519 static key, and signs the latter with the
//! former ([`IdentityProof`]). The proof travels inside the handshake, in the
//! message that reveals the signer's static key.
//!
//! The identity is therefore the trust anchor and the X25519 key is only a
//! hint: handing someone the right node id with an attacker's static key does
//! not get the attacker a session, because it cannot sign its own key as that
//! identity. It also means the static key can be replaced without the node
//! changing identity.
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

/// Domain separator for the signature binding a static key to an identity.
///
/// Without it the signature would be over a bare 32-byte string, and any other
/// place a node signs 32 bytes could be made to produce a valid binding.
pub const STATIC_KEY_CONTEXT: &[u8] = b"chroma-noise-static-key-v1";

/// Context for deriving a node's X25519 static secret from its identity seed.
const NOISE_SECRET_CONTEXT: &str = "chroma noise static secret v1";

/// Size of an encoded [`IdentityProof`]: the ed25519 key and its signature.
pub const IDENTITY_PROOF_SIZE: usize = 32 + 64;

/// Node identity: the ed25519 public key (spec §10).
///
/// This is what a node is called — what peers pin, gossip and publish in a
/// seed record. It signs the node's X25519 static key but takes no part in the
/// Diffie-Hellman itself.
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

/// A node's X25519 static public key: the key the Noise handshake actually
/// performs Diffie-Hellman against.
///
/// Not an identity. It is authorised by a [`NodeId`], and which key a node
/// uses can change without the node becoming a different node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NoiseKey(pub [u8; 32]);

impl NoiseKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        NoiseKey(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)
            .map_err(|e| CryptoError::Noise(format!("invalid noise key hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(CryptoError::Noise(format!(
                "noise key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(NoiseKey(out))
    }
}

/// A node's claim that a given X25519 static key is its own: the identity, and
/// a signature by it over the static key.
///
/// Possession of the static key's secret is proved by the handshake itself, so
/// the signature only has to bind the two keys together.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdentityProof {
    pub node_id: NodeId,
    signature: [u8; 64],
}

impl IdentityProof {
    /// The bytes signed for a given static key.
    fn signed_message(key: &NoiseKey) -> Vec<u8> {
        let mut msg = Vec::with_capacity(STATIC_KEY_CONTEXT.len() + 32);
        msg.extend_from_slice(STATIC_KEY_CONTEXT);
        msg.extend_from_slice(&key.0);
        msg
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IDENTITY_PROOF_SIZE);
        out.extend_from_slice(&self.node_id.0);
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != IDENTITY_PROOF_SIZE {
            return Err(CryptoError::Noise(format!(
                "identity proof must be {} bytes, got {}",
                IDENTITY_PROOF_SIZE,
                bytes.len()
            )));
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&bytes[..32]);
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[32..]);
        Ok(IdentityProof {
            node_id: NodeId(node_id),
            signature,
        })
    }

    /// Check that this identity really did sign `key`.
    pub fn verify(&self, key: &NoiseKey) -> Result<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying = VerifyingKey::from_bytes(&self.node_id.0)
            .map_err(|e| CryptoError::Noise(format!("not an ed25519 node id: {}", e)))?;
        verifying
            .verify(
                &Self::signed_message(key),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| {
                CryptoError::Noise("static key is not signed by the claimed identity".to_string())
            })
    }
}

/// A node's long-term identity: the ed25519 signing key, plus the X25519
/// static key it authorises.
pub struct NodeKeypair {
    signing: ed25519_dalek::SigningKey,
    noise_secret: [u8; 32],
    noise_public: NoiseKey,
}

impl NodeKeypair {
    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom(&mut seed).expect("CSPRNG failure");
        Self::from_secret(seed)
    }

    /// Rebuild an identity from a stored seed, so a node keeps the same id
    /// across restarts.
    ///
    /// The X25519 static secret is derived from the same seed rather than
    /// stored beside it: it is a separate key — a different secret, a
    /// different public key, used for a different operation — but one backup
    /// restores the node whole. Rotating it separately would mean every peer
    /// holding the old address has to be told, so it is not something a node
    /// should do casually.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self> {
        let signing = ed25519_dalek::SigningKey::from_bytes(&secret);
        let noise_secret = blake3::derive_key(NOISE_SECRET_CONTEXT, &secret);
        let noise_public = NoiseKey(x25519_public_from(&noise_secret));
        Ok(NodeKeypair {
            signing,
            noise_secret,
            noise_public,
        })
    }

    /// The node's identity: its ed25519 public key.
    pub fn node_id(&self) -> NodeId {
        NodeId(self.signing.verifying_key().to_bytes())
    }

    /// The X25519 static key this node performs handshakes with.
    pub fn noise_key(&self) -> NoiseKey {
        self.noise_public
    }

    /// The seed to store. Everything else is derived from it.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Sign our own static key, for the peer to check against our node id.
    pub fn identity_proof(&self) -> IdentityProof {
        use ed25519_dalek::Signer;

        let signature = self
            .signing
            .sign(&IdentityProof::signed_message(&self.noise_public));
        IdentityProof {
            node_id: self.node_id(),
            signature: signature.to_bytes(),
        }
    }
}

/// Derive the X25519 public key for a secret.
fn x25519_public_from(secret: &[u8; 32]) -> [u8; 32] {
    let s = x25519_dalek::StaticSecret::from(*secret);
    x25519_dalek::PublicKey::from(&s).to_bytes()
}

/// A Noise handshake in progress.
///
/// The handshake owns its own payloads: each side puts its [`IdentityProof`]
/// in the message that reveals its static key, and checks the peer's proof on
/// the message that reveals theirs. Callers move messages between the two
/// ends and nothing else, so there is no way to forget the check.
pub struct Handshake {
    state: HandshakeState,
    initiator: bool,
    proof: Vec<u8>,
    /// XK message index, counting both directions.
    step: usize,
    /// The identity the dialer asked for. `None` on the listening side, which
    /// takes whoever arrives.
    expected: Option<NodeId>,
    /// Filled in once the peer's proof has been checked.
    remote: Option<NodeId>,
}

impl Handshake {
    /// Start a handshake as the side that dialled.
    ///
    /// The dialer must know both keys of the node it is dialling: XK does the
    /// Diffie-Hellman against `remote_key`, and the identity that key is
    /// checked against is `remote`. A mismatch between the two ends the
    /// handshake — that is the whole point of pinning an identity.
    pub fn initiator(local: &NodeKeypair, remote: &NodeId, remote_key: &NoiseKey) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| CryptoError::Noise(format!("bad pattern: {}", e)))?;
        let state = Builder::new(params)
            .local_private_key(&local.noise_secret)
            .remote_public_key(&remote_key.0)
            .build_initiator()
            .map_err(|e| CryptoError::Noise(format!("initiator setup failed: {}", e)))?;
        Ok(Handshake {
            state,
            initiator: true,
            proof: local.identity_proof().encode(),
            step: 0,
            expected: Some(*remote),
            remote: None,
        })
    }

    /// Start a handshake as the side that was dialled.
    pub fn responder(local: &NodeKeypair) -> Result<Self> {
        let params = NOISE_PATTERN
            .parse()
            .map_err(|e| CryptoError::Noise(format!("bad pattern: {}", e)))?;
        let state = Builder::new(params)
            .local_private_key(&local.noise_secret)
            .build_responder()
            .map_err(|e| CryptoError::Noise(format!("responder setup failed: {}", e)))?;
        Ok(Handshake {
            state,
            initiator: false,
            proof: local.identity_proof().encode(),
            step: 0,
            expected: None,
            remote: None,
        })
    }

    /// Produce the next handshake message.
    pub fn write_message(&mut self) -> Result<Vec<u8>> {
        // XK is `-> e, es` / `<- e, ee` / `-> s, se`. A side's static key is
        // revealed by the message it authenticates itself with: the
        // responder's is known from the start, so it proves itself in message
        // two; the initiator's travels in message three.
        let payload: &[u8] = if self.proof_step() == self.step {
            &self.proof
        } else {
            &[]
        };

        let mut buf = vec![0u8; MAX_NOISE_PAYLOAD + 16];
        let n = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("handshake write failed: {}", e)))?;
        buf.truncate(n);
        self.step += 1;
        Ok(buf)
    }

    /// Consume a handshake message from the peer, checking its proof when the
    /// message is the one that carries it.
    pub fn read_message(&mut self, message: &[u8]) -> Result<()> {
        let mut buf = vec![0u8; MAX_NOISE_PAYLOAD + 16];
        let n = self
            .state
            .read_message(message, &mut buf)
            .map_err(|e| CryptoError::Noise(format!("handshake read failed: {}", e)))?;
        buf.truncate(n);

        let expecting_proof = self.peer_proof_step() == self.step;
        self.step += 1;

        if !expecting_proof {
            // Nothing is defined for these payloads, so anything in one is a
            // peer doing something we did not agree on.
            if !buf.is_empty() {
                return Err(CryptoError::Noise(
                    "unexpected payload in handshake message".to_string(),
                ));
            }
            return Ok(());
        }

        let proof = IdentityProof::decode(&buf)?;
        let remote_key = self.remote_static()?;
        proof.verify(&remote_key)?;

        // The dialer asked for a specific node. Reaching the address of one
        // node and being answered by another is exactly what pinning is meant
        // to catch.
        if let Some(expected) = self.expected {
            if proof.node_id != expected {
                return Err(CryptoError::Noise(format!(
                    "expected node {} but the peer proved {}",
                    expected.to_hex(),
                    proof.node_id.to_hex()
                )));
            }
        }

        self.remote = Some(proof.node_id);
        Ok(())
    }

    /// The message index on which we send our own proof.
    fn proof_step(&self) -> usize {
        if self.initiator {
            2
        } else {
            1
        }
    }

    /// The message index on which the peer sends theirs.
    fn peer_proof_step(&self) -> usize {
        if self.initiator {
            1
        } else {
            2
        }
    }

    fn remote_static(&self) -> Result<NoiseKey> {
        let key = self
            .state
            .get_remote_static()
            .ok_or_else(|| CryptoError::Noise("peer did not present a static key".into()))?;
        if key.len() != 32 {
            return Err(CryptoError::Noise("bad static key length".to_string()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(key);
        Ok(NoiseKey(out))
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Switch to transport mode once the handshake is complete.
    ///
    /// Fails if the peer never proved an identity: a session whose far end is
    /// unauthenticated is not something a caller should be able to hold by
    /// accident.
    pub fn into_session(self) -> Result<Session> {
        let remote = self
            .remote
            .ok_or_else(|| CryptoError::Noise("peer did not prove an identity".into()))?;
        let remote_key = self.remote_static()?;
        let state = self
            .state
            .into_transport_mode()
            .map_err(|e| CryptoError::Noise(format!("cannot enter transport mode: {}", e)))?;
        Ok(Session {
            state,
            remote,
            remote_key,
        })
    }
}

/// An established, encrypted session with a peer.
pub struct Session {
    state: TransportState,
    remote: NodeId,
    remote_key: NoiseKey,
}

impl Session {
    /// The identity of the node on the other end, as proved by the handshake.
    pub fn remote_node_id(&self) -> NodeId {
        self.remote
    }

    /// The static key that identity authorised, which is what the encryption
    /// is actually keyed from.
    pub fn remote_noise_key(&self) -> NoiseKey {
        self.remote_key
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

    /// Drive a handshake to completion, returning both sides in transport
    /// mode. Returns the first error either side raises instead of panicking,
    /// so the failure cases can use it too.
    fn run(ini: &mut Handshake, res: &mut Handshake) -> Result<()> {
        let m1 = ini.write_message()?;
        res.read_message(&m1)?;
        let m2 = res.write_message()?;
        ini.read_message(&m2)?;
        let m3 = ini.write_message()?;
        res.read_message(&m3)?;
        Ok(())
    }

    /// Run a full XK handshake and return both sides in transport mode.
    fn connected() -> (Session, Session, NodeId, NodeId) {
        let dialer = NodeKeypair::generate().unwrap();
        let listener = NodeKeypair::generate().unwrap();

        let mut ini =
            Handshake::initiator(&dialer, &listener.node_id(), &listener.noise_key()).unwrap();
        let mut res = Handshake::responder(&listener).unwrap();
        run(&mut ini, &mut res).unwrap();

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

        let mut ini =
            Handshake::initiator(&dialer, &impostor.node_id(), &impostor.noise_key()).unwrap();
        let mut res = Handshake::responder(&listener).unwrap();

        let m1 = ini.write_message().unwrap();
        // The responder cannot even read a message encrypted to another key.
        assert!(res.read_message(&m1).is_err());
    }

    /// The identity is the trust anchor, not the static key. Pairing the
    /// right node id with somebody else's static key must fail: otherwise
    /// whoever hands out addresses could substitute a key of their own and
    /// sit in the middle.
    #[test]
    fn test_static_key_from_another_node_is_refused() {
        let dialer = NodeKeypair::generate().unwrap();
        let listener = NodeKeypair::generate().unwrap();
        let attacker = NodeKeypair::generate().unwrap();

        // The address names the listener, but carries the attacker's key, and
        // the attacker is the one answering.
        let mut ini =
            Handshake::initiator(&dialer, &listener.node_id(), &attacker.noise_key()).unwrap();
        let mut res = Handshake::responder(&attacker).unwrap();

        let err = run(&mut ini, &mut res).expect_err("substituted key must be caught");
        assert!(
            format!("{}", err).contains("expected node"),
            "unexpected error: {}",
            err
        );
    }

    /// The reverse substitution: the real node id, signing a key it does not
    /// hold. The signature is over the static key, so it cannot be lifted off
    /// one key and put on another.
    #[test]
    fn test_identity_proof_does_not_transfer_between_keys() {
        let node = NodeKeypair::generate().unwrap();
        let other = NodeKeypair::generate().unwrap();

        let proof = node.identity_proof();
        assert!(proof.verify(&node.noise_key()).is_ok());
        assert!(
            proof.verify(&other.noise_key()).is_err(),
            "a proof must only cover the key it was made for"
        );
    }

    #[test]
    fn test_identity_proof_round_trip() {
        let node = NodeKeypair::generate().unwrap();
        let proof = node.identity_proof();
        let encoded = proof.encode();
        assert_eq!(encoded.len(), IDENTITY_PROOF_SIZE);

        let decoded = IdentityProof::decode(&encoded).unwrap();
        assert_eq!(decoded.node_id, node.node_id());
        assert!(decoded.verify(&node.noise_key()).is_ok());

        assert!(IdentityProof::decode(&encoded[..IDENTITY_PROOF_SIZE - 1]).is_err());
        assert!(IdentityProof::decode(&[]).is_err());
    }

    /// A tampered signature must not verify, and a node id that is not a
    /// point on the curve must be rejected rather than panicking.
    #[test]
    fn test_identity_proof_rejects_tampering() {
        let node = NodeKeypair::generate().unwrap();
        let mut encoded = node.identity_proof().encode();
        let last = encoded.len() - 1;
        encoded[last] ^= 0x01;
        assert!(IdentityProof::decode(&encoded)
            .unwrap()
            .verify(&node.noise_key())
            .is_err());

        let mut encoded = node.identity_proof().encode();
        encoded[..32].copy_from_slice(&[0xFFu8; 32]);
        assert!(IdentityProof::decode(&encoded)
            .unwrap()
            .verify(&node.noise_key())
            .is_err());
    }

    /// The two keys are genuinely separate: the identity is ed25519, the
    /// handshake key is X25519, and neither is the other.
    #[test]
    fn test_identity_and_noise_keys_are_distinct() {
        let node = NodeKeypair::generate().unwrap();
        assert_ne!(node.node_id().0, node.noise_key().0);
        assert_ne!(node.node_id().0, node.secret_bytes());

        // Both are still reproducible from the one stored seed.
        let reloaded = NodeKeypair::from_secret(node.secret_bytes()).unwrap();
        assert_eq!(reloaded.node_id(), node.node_id());
        assert_eq!(reloaded.noise_key(), node.noise_key());
    }

    /// A session is only usable once the peer has proved who it is.
    #[test]
    fn test_session_requires_a_proved_identity() {
        let dialer = NodeKeypair::generate().unwrap();
        let listener = NodeKeypair::generate().unwrap();
        let mut ini =
            Handshake::initiator(&dialer, &listener.node_id(), &listener.noise_key()).unwrap();
        let mut res = Handshake::responder(&listener).unwrap();

        // Stop after the first message: neither side has seen a proof yet.
        let m1 = ini.write_message().unwrap();
        res.read_message(&m1).unwrap();
        assert!(res.into_session().is_err());
    }

    /// The listener ends up holding the dialer's identity, and both agree on
    /// which static key the traffic is keyed from.
    #[test]
    fn test_both_sides_agree_on_the_keys() {
        let dialer = NodeKeypair::generate().unwrap();
        let listener = NodeKeypair::generate().unwrap();
        let mut ini =
            Handshake::initiator(&dialer, &listener.node_id(), &listener.noise_key()).unwrap();
        let mut res = Handshake::responder(&listener).unwrap();
        run(&mut ini, &mut res).unwrap();

        let dialer_session = ini.into_session().unwrap();
        let listener_session = res.into_session().unwrap();
        assert_eq!(dialer_session.remote_node_id(), listener.node_id());
        assert_eq!(dialer_session.remote_noise_key(), listener.noise_key());
        assert_eq!(listener_session.remote_node_id(), dialer.node_id());
        assert_eq!(listener_session.remote_noise_key(), dialer.noise_key());
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
        let mut ini =
            Handshake::initiator(&peer, &reloaded.node_id(), &reloaded.noise_key()).unwrap();
        let mut res = Handshake::responder(&reloaded).unwrap();
        run(&mut ini, &mut res).expect("the derived keys must match the stored secret");
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
    fn test_noise_key_hex_round_trip() {
        let key = NodeKeypair::generate().unwrap().noise_key();
        assert_eq!(NoiseKey::from_hex(&key.to_hex()).unwrap(), key);
        assert!(NoiseKey::from_hex("nonsense").is_err());
        assert!(NoiseKey::from_hex("aabb").is_err());
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
