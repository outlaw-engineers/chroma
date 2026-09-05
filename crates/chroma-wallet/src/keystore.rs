//! Encrypted wallet storage.
//!
//! A wallet's secret key is the wallet. Holding one in a file that anyone who
//! can read the disk can use is not storage, so the key is encrypted under a
//! passphrase before it ever reaches the filesystem.
//!
//! The passphrase is stretched with Argon2id and the key sealed with
//! ChaCha20-Poly1305. The header — version, KDF parameters, address — is
//! authenticated as associated data, so an edited header fails to decrypt
//! rather than silently changing how the file is read.

use chroma_core::error::{CoreError, Result};
use chroma_crypto::schnorr::SecretKey32;
use zeroize::Zeroize;

use crate::Wallet;

/// Format marker. A file that does not start with this is not ours, and a
/// later format gets a different number rather than a silent reinterpretation.
pub const KEYSTORE_VERSION: &str = "chroma-wallet-1";

/// Argon2id cost. Deliberately expensive: this is the only thing standing
/// between a stolen file and the key inside it. Written into the file so the
/// parameters can be raised later without orphaning existing wallets.
pub const ARGON2_MEMORY_KIB: u32 = 65536;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// 32-byte secret key plus the Poly1305 tag.
const SEALED_LEN: usize = 32 + 16;

/// The parts of a keystore file that are not the ciphertext.
struct Header {
    address: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Render the header exactly as it appears in the file. This is also the
    /// associated data, so the bytes a reader authenticates are the bytes it
    /// parsed — there is no second representation to disagree with.
    fn render(&self) -> String {
        format!(
            "{}\naddress: {}\nkdf: argon2id\nm: {}\nt: {}\np: {}\nsalt: {}\nnonce: {}\n",
            KEYSTORE_VERSION,
            self.address,
            self.memory_kib,
            self.iterations,
            self.parallelism,
            hex::encode(self.salt),
            hex::encode(self.nonce),
        )
    }
}

fn field<'a>(lines: &[&'a str], index: usize, name: &str) -> Result<&'a str> {
    let line = lines
        .get(index)
        .ok_or_else(|| CoreError::InvalidFormat(format!("keystore: missing {}", name)))?;
    line.strip_prefix(&format!("{}: ", name))
        .ok_or_else(|| {
            CoreError::InvalidFormat(format!("keystore: expected {}, got {:?}", name, line))
        })
}

fn parse_u32(text: &str, name: &str) -> Result<u32> {
    text.parse()
        .map_err(|_| CoreError::InvalidFormat(format!("keystore: bad {}: {:?}", name, text)))
}

fn parse_hex<const N: usize>(text: &str, name: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(text)
        .map_err(|_| CoreError::InvalidFormat(format!("keystore: {} is not hex", name)))?;
    if bytes.len() != N {
        return Err(CoreError::InvalidFormat(format!(
            "keystore: {} must be {} bytes, got {}",
            name,
            N,
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Stretch a passphrase into an encryption key.
fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    // A file could name parameters this machine cannot honour, or that would
    // take all day. Refusing is better than being made to allocate whatever a
    // file asks for.
    if memory_kib > 1_048_576 || iterations > 16 || parallelism > 16 {
        return Err(CoreError::InvalidFormat(
            "keystore: kdf parameters are beyond what we will run".to_string(),
        ));
    }

    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| CoreError::InvalidFormat(format!("keystore: bad kdf parameters: {}", e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CoreError::InvalidFormat(format!("keystore: key derivation failed: {}", e)))?;
    Ok(key)
}

/// Encrypt a wallet's secret key under a passphrase.
///
/// The result is text, so a keystore can be inspected, copied and diffed
/// without tooling. Everything secret in it is inside the ciphertext.
pub fn encrypt(wallet: &Wallet, passphrase: &str) -> Result<String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    if passphrase.is_empty() {
        return Err(CoreError::InvalidFormat(
            "refusing to encrypt a wallet with an empty passphrase".to_string(),
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).expect("CSPRNG failure");
    getrandom::getrandom(&mut nonce_bytes).expect("CSPRNG failure");

    let header = Header {
        address: crate::address_to_bech32(&wallet.address()),
        memory_kib: ARGON2_MEMORY_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
        salt,
        nonce: nonce_bytes,
    };
    let rendered = header.render();

    let mut key = derive_key(
        passphrase,
        &salt,
        header.memory_kib,
        header.iterations,
        header.parallelism,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut secret = wallet.secret_bytes();
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &secret,
                aad: rendered.as_bytes(),
            },
        )
        .map_err(|_| CoreError::InvalidFormat("keystore: encryption failed".to_string()));
    key.zeroize();
    secret.zeroize();

    Ok(format!("{}data: {}\n", rendered, hex::encode(sealed?)))
}

/// Decrypt a keystore back into a usable wallet.
pub fn decrypt(name: &str, encoded: &str, passphrase: &str) -> Result<Wallet> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

    let lines: Vec<&str> = encoded.lines().collect();
    match lines.first() {
        Some(&KEYSTORE_VERSION) => {}
        Some(other) => {
            return Err(CoreError::InvalidFormat(format!(
                "keystore: unknown format {:?}",
                other
            )))
        }
        None => return Err(CoreError::InvalidFormat("keystore: empty file".to_string())),
    }

    let address = field(&lines, 1, "address")?.to_string();
    let kdf = field(&lines, 2, "kdf")?;
    if kdf != "argon2id" {
        return Err(CoreError::InvalidFormat(format!(
            "keystore: unsupported kdf {:?}",
            kdf
        )));
    }
    let memory_kib = parse_u32(field(&lines, 3, "m")?, "m")?;
    let iterations = parse_u32(field(&lines, 4, "t")?, "t")?;
    let parallelism = parse_u32(field(&lines, 5, "p")?, "p")?;
    let salt: [u8; SALT_LEN] = parse_hex(field(&lines, 6, "salt")?, "salt")?;
    let nonce_bytes: [u8; NONCE_LEN] = parse_hex(field(&lines, 7, "nonce")?, "nonce")?;
    let sealed: [u8; SEALED_LEN] = parse_hex(field(&lines, 8, "data")?, "data")?;

    let header = Header {
        address,
        memory_kib,
        iterations,
        parallelism,
        salt,
        nonce: nonce_bytes,
    };

    let mut key = derive_key(passphrase, &salt, memory_kib, iterations, parallelism)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let opened = cipher.decrypt(
        Nonce::from_slice(&nonce_bytes),
        Payload {
            msg: &sealed,
            // Reconstructed from the parsed fields, so a header edited in the
            // file — a swapped address, weakened kdf parameters — does not
            // decrypt.
            aad: header.render().as_bytes(),
        },
    );
    key.zeroize();

    let mut secret_bytes = opened.map_err(|_| {
        CoreError::InvalidFormat("wrong passphrase, or the keystore has been altered".to_string())
    })?;
    if secret_bytes.len() != 32 {
        secret_bytes.zeroize();
        return Err(CoreError::InvalidFormat(
            "keystore: decrypted key is the wrong length".to_string(),
        ));
    }
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&secret_bytes);
    secret_bytes.zeroize();

    let secret = SecretKey32::from_bytes(key_array)
        .map_err(|e| CoreError::InvalidFormat(format!("keystore: {}", e)))?;
    key_array.zeroize();
    Wallet::from_secret_key(name, secret)
}

/// Read the address out of a keystore without the passphrase.
///
/// Checking a balance or receiving a payment should not need the key. The
/// value is authenticated, so a file whose address was edited will fail to
/// decrypt later — but it is not verified against the key here, which is why
/// this is separate from [`decrypt`].
pub fn address_of(encoded: &str) -> Result<String> {
    let lines: Vec<&str> = encoded.lines().collect();
    if lines.first() != Some(&KEYSTORE_VERSION) {
        return Err(CoreError::InvalidFormat(
            "keystore: unknown format".to_string(),
        ));
    }
    Ok(field(&lines, 1, "address")?.to_string())
}

/// Where a named wallet lives under a data directory.
pub fn wallet_path(data_dir: &std::path::Path, name: &str) -> Result<std::path::PathBuf> {
    // The name becomes a filename, so it may not be able to point somewhere
    // else. A wallet called `../../etc/passwd` should be a refusal, not a
    // surprise about which file gets written.
    if name.is_empty()
        || name.len() > 64
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CoreError::InvalidFormat(format!(
            "wallet name must be 1-64 characters of letters, digits, - or _, got {:?}",
            name
        )));
    }
    Ok(data_dir.join("wallets").join(format!("{}.wallet", name)))
}

/// Write an encrypted wallet, refusing to overwrite an existing one.
///
/// Overwriting is how a wallet gets destroyed: the file is the only copy of
/// the key, and a second `create` with the same name would take it out
/// without warning.
pub fn save(data_dir: &std::path::Path, wallet: &Wallet, passphrase: &str) -> Result<std::path::PathBuf> {
    let path = wallet_path(data_dir, wallet.name())?;
    if path.exists() {
        return Err(CoreError::InvalidFormat(format!(
            "{} already exists",
            path.display()
        )));
    }
    let encoded = encrypt(wallet, passphrase)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CoreError::InvalidFormat(format!("{}: {}", parent.display(), e)))?;
    }
    std::fs::write(&path, encoded)
        .map_err(|e| CoreError::InvalidFormat(format!("{}: {}", path.display(), e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

/// Read and decrypt a named wallet.
pub fn load(data_dir: &std::path::Path, name: &str, passphrase: &str) -> Result<Wallet> {
    let path = wallet_path(data_dir, name)?;
    let encoded = std::fs::read_to_string(&path)
        .map_err(|e| CoreError::InvalidFormat(format!("{}: {}", path.display(), e)))?;
    decrypt(name, &encoded, passphrase)
}

/// The address of a named wallet, without needing its passphrase.
pub fn load_address(data_dir: &std::path::Path, name: &str) -> Result<String> {
    let path = wallet_path(data_dir, name)?;
    let encoded = std::fs::read_to_string(&path)
        .map_err(|e| CoreError::InvalidFormat(format!("{}: {}", path.display(), e)))?;
    address_of(&encoded)
}

/// Names of the wallets stored under a data directory, sorted.
pub fn list(data_dir: &std::path::Path) -> Vec<String> {
    let dir = data_dir.join("wallets");
    let mut names: Vec<String> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let path = e.path();
                if path.extension()? != "wallet" {
                    return None;
                }
                Some(path.file_stem()?.to_string_lossy().into_owned())
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Argon2id at the real cost is deliberately slow, so tests that only care
    /// about the format use the cheapest parameters the library allows.
    fn cheap_encrypt(wallet: &Wallet, passphrase: &str) -> String {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let header = Header {
            address: crate::address_to_bech32(&wallet.address()),
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
            salt: [7u8; SALT_LEN],
            nonce: [9u8; NONCE_LEN],
        };
        let rendered = header.render();
        let key = derive_key(passphrase, &header.salt, 8, 1, 1).unwrap();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&header.nonce),
                Payload {
                    msg: &wallet.secret_bytes(),
                    aad: rendered.as_bytes(),
                },
            )
            .unwrap();
        format!("{}data: {}\n", rendered, hex::encode(sealed))
    }

    fn test_wallet() -> Wallet {
        Wallet::generate("test")
    }

    #[test]
    fn test_round_trip() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "correct horse battery staple");
        let restored = decrypt("test", &encoded, "correct horse battery staple").unwrap();
        assert_eq!(restored.secret_bytes(), wallet.secret_bytes());
        assert_eq!(restored.address(), wallet.address());
        assert_eq!(restored.name(), "test");
    }

    /// The secret must not be recoverable from the file itself.
    #[test]
    fn test_secret_is_not_in_the_file() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "passphrase");
        assert!(
            !encoded.contains(&hex::encode(wallet.secret_bytes())),
            "the secret key must not appear in the keystore"
        );
    }

    #[test]
    fn test_wrong_passphrase_is_refused() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "right");
        let err = decrypt("test", &encoded, "wrong").expect_err("must not decrypt");
        assert!(format!("{}", err).contains("wrong passphrase"));
        assert!(decrypt("test", &encoded, "").is_err());
    }

    /// The tag covers the ciphertext, so a flipped bit is a failure rather
    /// than a different key.
    #[test]
    fn test_tampered_ciphertext_is_refused() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "passphrase");
        let mut lines: Vec<String> = encoded.lines().map(|l| l.to_string()).collect();
        let data = lines.last().unwrap().strip_prefix("data: ").unwrap();
        let mut raw = hex::decode(data).unwrap();
        raw[0] ^= 0x01;
        *lines.last_mut().unwrap() = format!("data: {}", hex::encode(raw));
        assert!(decrypt("test", &format!("{}\n", lines.join("\n")), "passphrase").is_err());
    }

    /// The header is associated data, so editing it — swapping the displayed
    /// address, or weakening the KDF parameters to make a stolen file cheaper
    /// to attack — breaks decryption instead of taking effect.
    #[test]
    fn test_tampered_header_is_refused() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "passphrase");

        let other = crate::address_to_bech32(&Wallet::generate("other").address());
        let swapped: String = encoded
            .lines()
            .map(|l| {
                if l.starts_with("address: ") {
                    format!("address: {}", other)
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(decrypt("test", &format!("{}\n", swapped), "passphrase").is_err());

        let weakened: String = encoded
            .lines()
            .map(|l| if l.starts_with("t: ") { "t: 1".to_string() } else { l.to_string() })
            .collect::<Vec<_>>()
            .join("\n");
        // Same parameters here, but the point is that any edit is caught.
        let weakened = weakened.replace("m: 8", "m: 16");
        assert!(decrypt("test", &format!("{}\n", weakened), "passphrase").is_err());
    }

    /// Two encryptions of the same wallet under the same passphrase must
    /// differ: a fresh salt and nonce each time, or the files leak that two
    /// wallets are the same and reuse a nonce with the same key.
    #[test]
    fn test_each_encryption_is_unique() {
        let wallet = test_wallet();
        let a = encrypt(&wallet, "passphrase").unwrap();
        let b = encrypt(&wallet, "passphrase").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            decrypt("test", &a, "passphrase").unwrap().secret_bytes(),
            decrypt("test", &b, "passphrase").unwrap().secret_bytes()
        );
    }

    #[test]
    fn test_empty_passphrase_is_refused() {
        assert!(encrypt(&test_wallet(), "").is_err());
    }

    #[test]
    fn test_malformed_files_are_refused() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "passphrase");

        assert!(decrypt("test", "", "passphrase").is_err());
        assert!(decrypt("test", "not-a-keystore\n", "passphrase").is_err());
        assert!(decrypt("test", &encoded.replace("chroma-wallet-1", "chroma-wallet-2"), "passphrase").is_err());
        assert!(decrypt("test", &encoded.replace("kdf: argon2id", "kdf: pbkdf2"), "passphrase").is_err());
        assert!(decrypt("test", &encoded.replace("salt: ", "salt2: "), "passphrase").is_err());
        assert!(decrypt("test", &encoded.replace("m: 8", "m: eight"), "passphrase").is_err());

        // Truncated ciphertext, and a truncated file.
        let short = encoded.replace(
            encoded.lines().last().unwrap(),
            "data: 00112233445566778899aabbccddeeff",
        );
        assert!(decrypt("test", &short, "passphrase").is_err());
        assert!(decrypt("test", &encoded.lines().take(4).collect::<Vec<_>>().join("\n"), "passphrase").is_err());
    }

    /// A file naming absurd KDF parameters must be refused rather than obeyed:
    /// it would otherwise decide how much memory we allocate.
    #[test]
    fn test_outrageous_kdf_parameters_are_refused() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "passphrase");
        let huge = encoded.replace("m: 8", "m: 4294967295");
        let err = decrypt("test", &huge, "passphrase").expect_err("must refuse");
        assert!(format!("{}", err).contains("beyond what we will run"));
    }

    #[test]
    fn test_address_without_passphrase() {
        let wallet = test_wallet();
        let encoded = cheap_encrypt(&wallet, "passphrase");
        assert_eq!(
            address_of(&encoded).unwrap(),
            crate::address_to_bech32(&wallet.address())
        );
        assert!(address_of("nonsense").is_err());
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "chroma_keystore_{}_{}_{}",
            tag,
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_save_and_load() {
        let dir = temp_dir("saveload");
        let wallet = Wallet::generate("mine");
        let path = save(&dir, &wallet, "passphrase").unwrap();
        assert!(path.exists());

        assert_eq!(
            load(&dir, "mine", "passphrase").unwrap().secret_bytes(),
            wallet.secret_bytes()
        );
        assert_eq!(
            load_address(&dir, "mine").unwrap(),
            crate::address_to_bech32(&wallet.address())
        );
        assert_eq!(list(&dir), vec!["mine".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The file is the only copy of the key, so a second save under the same
    /// name must not quietly replace it.
    #[test]
    fn test_save_refuses_to_overwrite() {
        let dir = temp_dir("overwrite");
        let first = Wallet::generate("mine");
        save(&dir, &first, "passphrase").unwrap();

        let second = Wallet::generate("mine");
        assert!(save(&dir, &second, "passphrase").is_err());
        assert_eq!(
            load(&dir, "mine", "passphrase").unwrap().secret_bytes(),
            first.secret_bytes(),
            "the original wallet must survive"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A wallet name becomes a filename, so it must not be able to escape the
    /// wallets directory.
    #[test]
    fn test_wallet_names_cannot_traverse() {
        let dir = temp_dir("traverse");
        for bad in ["../escape", "a/b", "", "with space", "dot.dot", &"x".repeat(65)] {
            assert!(
                wallet_path(&dir, bad).is_err(),
                "must be refused as a name: {:?}",
                bad
            );
        }
        assert!(wallet_path(&dir, "good-name_1").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let wallet = Wallet::generate("mine");
        let path = save(&dir, &wallet, "passphrase").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "keystore must not be group or world readable");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
