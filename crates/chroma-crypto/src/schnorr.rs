//! BIP-340 Schnorr Signatures over secp256k1
//!
//! Uses libsecp256k1 for the cryptographic primitive.
//! Implements BIP-340:
//! - x-only keys (32-byte compressed public key, Y=even)
//! - Schnorr signature: (r || s) = 64 bytes
//! - Deterministic nonce via RFC 6979

use secp256k1::{
    XOnlyPublicKey,
    Secp256k1,
    Message,
    SecretKey,
    KeyPair,
    schnorr::Signature as SchnorrSig,
};
use crate::hash::blake3;
use secp256k1::rand::thread_rng;

use crate::error::{CryptoError, CryptoResult as Result};

/// Secret key (32 bytes, valid secp256k1 private key)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SecretKey32(pub [u8; 32]);

impl SecretKey32 {
    /// Generate from existing 32-byte secret
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let _ = SecretKey::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidSecretKey(format!("{:?}", e)))?;
        Ok(SecretKey32(bytes))
    }

    /// Generate a new random secret key
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let (secret, _) = secp.generate_keypair(&mut thread_rng());
        let bytes = secret_to_bytes(&secret);
        SecretKey32(bytes)
    }

    /// Internal: get secp256k1 SecretKey
    pub(crate) fn to_secp(&self) -> Result<SecretKey> {
        SecretKey::from_slice(&self.0)
            .map_err(|e| CryptoError::InvalidSecretKey(format!("{:?}", e)))
    }
}

fn secret_to_bytes(secret: &SecretKey) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&secret[..]);
    arr
}

/// Public key (x-only, 32 bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey32(pub [u8; 32]);

impl PublicKey32 {
    /// Derive from secret key
    pub fn from_secret(secret: &SecretKey32) -> Result<Self> {
        let secp = Secp256k1::new();
        let sk = secret.to_secp()?;
        let keypair = KeyPair::from_secret_key(&secp, &sk);
        let xonly = keypair.x_only_public_key().0;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&xonly.serialize());
        Ok(PublicKey32(arr))
    }

    /// Parse from 32-byte x-only public key
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let _xonly = XOnlyPublicKey::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(format!("{:?}", e)))?;
        Ok(PublicKey32(bytes))
    }

    /// Internal: convert to secp256k1 XOnlyPublicKey
    pub(crate) fn to_secp(&self) -> Result<XOnlyPublicKey> {
        XOnlyPublicKey::from_slice(&self.0)
            .map_err(|e| CryptoError::InvalidPublicKey(format!("{:?}", e)))
    }
}

/// 64-byte Schnorr signature (r || s, each 32 bytes, big-endian)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature64(pub [u8; 64]);

impl Signature64 {
    /// Parse from 64-byte array
    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self> {
        let _ = SchnorrSig::from_slice(&bytes)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;
        Ok(Signature64(bytes))
    }

    /// Internal: convert to secp256k1 signature
    pub(crate) fn to_secp(&self) -> Result<SchnorrSig> {
        SchnorrSig::from_slice(&self.0)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))
    }
}

/// Sign a message hash with a secret key using BIP-340 Schnorr
/// Uses deterministic nonce derivation per BIP-340 spec
pub fn schnorr_sign(secret: &SecretKey32, msg_hash: &[u8; 32]) -> Result<Signature64> {
    let secp = Secp256k1::new();
    let sk = secret.to_secp()?;
    let keypair = KeyPair::from_secret_key(&secp, &sk);
    let msg = Message::from_slice(msg_hash)
        .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;

    let aux_rand = [0u8; 32];
    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&sig[..]);
    Ok(Signature64(bytes))
}

/// Verify a Schnorr signature
pub fn schnorr_verify(public_key: &PublicKey32, msg_hash: &[u8; 32], sig: &Signature64) -> bool {
    let secp = Secp256k1::new();

    let pk = match public_key.to_secp() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    let sig_obj = match sig.to_secp() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let msg = match Message::from_slice(msg_hash) {
        Ok(m) => m,
        Err(_) => return false,
    };

    secp.verify_schnorr(&sig_obj, &msg, &pk).is_ok()
}

/// Batch verify multiple signatures with the same message
pub fn schnorr_batch_verify(
    pubkeys: &[PublicKey32],
    msg_hash: &[u8; 32],
    sigs: &[Signature64],
) -> Result<bool> {
    if pubkeys.len() != sigs.len() {
        return Err(CryptoError::InvalidSignature("mismatched lengths".to_string()));
    }

    let results: Vec<bool> = pubkeys
        .iter()
        .zip(sigs.iter())
        .map(|(pk, sig)| schnorr_verify(pk, msg_hash, sig))
        .collect();

    Ok(results.iter().all(|&r| r))
}

/// Domain separation tag for transaction sighash
/// Prevents cross-protocol and cross-object signing ambiguity
const SIGHASH_DOMAIN: &[u8] = b"Chroma Transaction Signing v1";

/// Sighash computation for transactions
/// Domain-tagged: BLAKE3(domain_tag || sender || recipient || amount || nonce)
pub fn compute_sighash(
    sender: &[u8; 20],
    recipient: &[u8; 20],
    amount: u64,
    nonce: u64,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(SIGHASH_DOMAIN.len() + 52);
    data.extend_from_slice(SIGHASH_DOMAIN);
    data.extend_from_slice(sender);
    data.extend_from_slice(recipient);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    blake3(&data).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_and_signing() {
        let secret = SecretKey32::generate();
        let public = PublicKey32::from_secret(&secret).unwrap();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        assert!(schnorr_verify(&public, &msg, &sig));
    }

    #[test]
    fn test_signature_rejection() {
        let secret = SecretKey32::generate();
        let public = PublicKey32::from_secret(&secret).unwrap();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        let wrong_msg = [0x43u8; 32];
        assert!(!schnorr_verify(&public, &wrong_msg, &sig));
    }

    #[test]
    fn test_batch_verification() {
        let secret = SecretKey32::generate();
        let public = PublicKey32::from_secret(&secret).unwrap();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        assert!(schnorr_batch_verify(&[public], &msg, &[sig]).unwrap());
        assert!(schnorr_batch_verify(&[public], &msg, &[]).is_err());
    }

    #[test]
    fn test_signature_malleability() {
        let secret = SecretKey32::generate();

        let msg = [0x42u8; 32];
        let sig = schnorr_sign(&secret, &msg).unwrap();

        let sig2 = schnorr_sign(&secret, &msg).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_sighash() {
        let sender = [0x11u8; 20];
        let recipient = [0x22u8; 20];
        let amount = 1_000_000u64;
        let nonce = 42u64;

        let hash1 = compute_sighash(&sender, &recipient, amount, nonce);
        let hash2 = compute_sighash(&sender, &recipient, amount, nonce);
        assert_eq!(hash1, hash2);

        let hash3 = compute_sighash(&sender, &recipient, amount, 43);
        assert_ne!(hash1, hash3);

        // Verify domain separation: sighash differs from raw field hash
        let raw_data = {
            let mut d = Vec::with_capacity(52);
            d.extend_from_slice(&sender);
            d.extend_from_slice(&recipient);
            d.extend_from_slice(&amount.to_le_bytes());
            d.extend_from_slice(&nonce.to_le_bytes());
            blake3(&d).0
        };
        assert_ne!(hash1, raw_data, "sighash must differ from raw field hash (domain separation)");
    }
}