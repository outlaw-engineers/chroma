//! Chroma Cryptography
//!
//! Cryptographic primitives for Chroma:
//! - secp256k1 / BIP-340 Schnorr signatures
//! - BLAKE3, SHA-256, RIPEMD-160 hashing
//! - Bech32m address encoding (HRP: "chr")
//! - RandomX PoW (via FFI to reference implementation)
//! - Noise protocol transport (for P2P encryption)

pub mod address;
pub mod error;
pub mod hash;
pub mod randomx;
pub mod schnorr;
pub mod noise;

pub use address::*;
pub use error::*;
pub use hash::*;
pub use randomx::*;
pub use schnorr::*;
pub use noise::*;