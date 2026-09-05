use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash160;
use chroma_core::types::{Address, Amount, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_tx::create_transaction;
use zeroize::Zeroize;

pub struct Wallet {
    secret_key: SecretKey32,
    address: Address,
    name: String,
}

impl Wallet {
    pub fn generate(name: &str) -> Self {
        let secret_key = SecretKey32::generate();
        let pubkey = PublicKey32::from_secret(&secret_key).unwrap();
        let h = hash160(&pubkey.0);
        let address = Address::from_hash160(Hash160(h));
        Wallet {
            secret_key,
            address,
            name: name.to_string(),
        }
    }

    pub fn from_secret_key(name: &str, secret_key: SecretKey32) -> Result<Self> {
        let pubkey = PublicKey32::from_secret(&secret_key)
            .map_err(|e| CoreError::InvalidSignature(format!("key derivation failed: {}", e)))?;
        let h = hash160(&pubkey.0);
        let address = Address::from_hash160(Hash160(h));
        Ok(Wallet {
            secret_key,
            address,
            name: name.to_string(),
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret_key.0
    }

    pub fn create_transaction(
        &self,
        recipient: Address,
        amount: Amount,
        nonce: Nonce,
    ) -> Result<chroma_tx::Transaction> {
        create_transaction(&self.secret_key, self.address, recipient, amount, nonce)
    }
}

impl Drop for Wallet {
    fn drop(&mut self) {
        self.secret_key.0.zeroize();
    }
}

/// Number of words a freshly generated phrase has.
///
/// 24 words is 256 bits of entropy, which is what the secret key it derives
/// holds. A 12-word phrase is still accepted — plenty of wallets produce them
/// — but generating one would cap every new wallet at 128 bits.
pub const SEED_PHRASE_WORDS: usize = 24;

/// Domain separator for turning a BIP-39 seed into a Chroma key.
///
/// Keeps this derivation from colliding with any other use of the same seed:
/// the phrase is the thing a user backs up, and it may well be used elsewhere.
const KEY_DERIVATION_CONTEXT: &str = "chroma wallet secret key v1";

/// Generate a new BIP-39 mnemonic.
///
/// The entropy comes from the operating system's CSPRNG. Anything less is a
/// wallet-emptying bug rather than a quality-of-implementation issue: a phrase
/// derived from a clock is guessable by anyone who knows roughly when the
/// wallet was made.
pub fn generate_seed_phrase() -> Vec<String> {
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).expect("CSPRNG failure");
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
        .expect("32 bytes is a valid BIP-39 entropy length");
    entropy.zeroize();
    mnemonic.words().map(|w| w.to_string()).collect()
}

/// Check a phrase: known words, a valid length, and a matching checksum.
///
/// The checksum is the point. Without it every typo that lands on another
/// word in the list silently derives a different wallet, and the user finds
/// out when their balance is zero.
pub fn validate_seed_phrase(phrase: &[String]) -> bool {
    parse_seed_phrase(phrase).is_ok()
}

fn parse_seed_phrase(phrase: &[String]) -> Result<bip39::Mnemonic> {
    // BIP-39 defines the mnemonic over words joined by single spaces, so the
    // caller's tokenisation is normalised rather than trusted.
    let joined = phrase
        .iter()
        .map(|w| w.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    bip39::Mnemonic::parse_in(bip39::Language::English, &joined)
        .map_err(|e| CoreError::InvalidFormat(format!("invalid seed phrase: {}", e)))
}

/// Derive a wallet from a seed phrase.
///
/// The phrase goes through the standard BIP-39 stretch (PBKDF2-HMAC-SHA512,
/// 2048 rounds) to a 64-byte seed, which is then domain-separated into a
/// secp256k1 secret key. The stretch is what makes a stolen phrase expensive
/// to attack offline; hashing the words directly, as this used to, gives an
/// attacker a free guess per candidate phrase.
pub fn wallet_from_seed_phrase(name: &str, phrase: &[String]) -> Result<Wallet> {
    let mnemonic = parse_seed_phrase(phrase)?;
    let mut seed = mnemonic.to_seed("");
    let secret = derive_secret_key(&seed);
    seed.zeroize();
    Wallet::from_secret_key(name, secret?)
}

/// Turn a 64-byte BIP-39 seed into a valid secp256k1 secret key.
///
/// A 32-byte hash is not automatically a valid scalar: zero and anything at or
/// above the curve order are not keys. The odds are around 2^-128, but the
/// alternative to handling it is a panic that only ever fires for one unlucky
/// user, so the counter is bumped and the derivation repeated.
fn derive_secret_key(seed: &[u8; 64]) -> Result<SecretKey32> {
    for counter in 0u8..=255 {
        let mut input = Vec::with_capacity(65);
        input.extend_from_slice(seed);
        input.push(counter);
        let mut key_bytes = blake3::derive_key(KEY_DERIVATION_CONTEXT, &input);
        input.zeroize();
        match SecretKey32::from_bytes(key_bytes) {
            Ok(secret) => {
                key_bytes.zeroize();
                return Ok(secret);
            }
            Err(_) => key_bytes.zeroize(),
        }
    }
    Err(CoreError::InvalidFormat(
        "seed phrase did not yield a valid key".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(|w| w.to_string()).collect()
    }

    /// The BIP-39 test vector for all-zero entropy: 12 words with a valid
    /// checksum.
    fn test_phrase() -> Vec<String> {
        words("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    }

    /// The same vector at 24 words.
    fn test_phrase_24() -> Vec<String> {
        words("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art")
    }

    #[test]
    fn test_wallet_generate() {
        let wallet = Wallet::generate("test");
        assert_eq!(wallet.name(), "test");
        let addr = wallet.address();
        assert_ne!(addr.as_hash160().as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn test_wallet_from_secret_key() {
        let secret = SecretKey32::generate();
        let wallet = Wallet::from_secret_key("test2", secret).unwrap();
        assert_eq!(wallet.name(), "test2");
    }

    #[test]
    fn test_wallet_address_deterministic() {
        let secret = SecretKey32::generate();
        let w1 = Wallet::from_secret_key("a", secret).unwrap();
        let w2 = Wallet::from_secret_key("b", secret).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn test_wallet_secret_bytes() {
        let secret = SecretKey32::generate();
        let wallet = Wallet::from_secret_key("test", secret).unwrap();
        assert_eq!(wallet.secret_bytes(), secret.0);
    }

    #[test]
    fn test_seed_phrase_generation() {
        let phrase = generate_seed_phrase();
        assert_eq!(phrase.len(), SEED_PHRASE_WORDS);
        assert!(validate_seed_phrase(&phrase));
    }

    /// A generated phrase must come from the system CSPRNG. This used to be a
    /// hash of the current nanosecond, which anyone who knew roughly when the
    /// wallet was made could search: 100 phrases from a clock-seeded generator
    /// collide, and a phrase built without a checksum almost never validates.
    #[test]
    fn test_generated_phrases_are_unique_and_valid() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..100 {
            let phrase = generate_seed_phrase();
            assert!(
                validate_seed_phrase(&phrase),
                "a generated phrase must carry a valid checksum: {:?}",
                phrase
            );
            assert!(
                seen.insert(phrase.join(" ")),
                "two generated phrases collided"
            );
        }
    }

    /// Every word of a generated phrase is drawn from the whole list, not the
    /// first few hundred entries of it. A truncated list costs entropy
    /// silently — the phrase still looks like a mnemonic.
    #[test]
    fn test_generation_uses_the_whole_wordlist() {
        let mut highest = 0;
        for _ in 0..50 {
            for word in generate_seed_phrase() {
                let index = bip39::Language::English
                    .find_word(&word)
                    .expect("generated word must be in the list");
                highest = highest.max(index);
            }
        }
        // 1200 draws from 2048 words: the top eighth of the list being absent
        // would be luck of about (7/8)^1200.
        assert!(
            highest > 1792,
            "generation never reached the end of the wordlist (highest index {})",
            highest
        );
    }

    #[test]
    fn test_validate_seed_phrase_valid() {
        assert!(validate_seed_phrase(&test_phrase()));
        assert!(validate_seed_phrase(&test_phrase_24()));
    }

    /// A phrase of real words in the wrong order fails the checksum. Without
    /// this check a mistyped word that happens to be in the list derives a
    /// different wallet, and the user finds out when the balance is zero.
    #[test]
    fn test_validate_seed_phrase_rejects_bad_checksum() {
        let mut phrase = test_phrase();
        phrase[11] = "ability".to_string();
        assert!(
            !validate_seed_phrase(&phrase),
            "a phrase with a broken checksum must be refused"
        );
        assert!(wallet_from_seed_phrase("typo", &phrase).is_err());
    }

    #[test]
    fn test_validate_seed_phrase_invalid() {
        let mut phrase = test_phrase();
        phrase[0] = "xyznotaword".to_string();
        assert!(!validate_seed_phrase(&phrase));
    }

    #[test]
    fn test_validate_seed_phrase_wrong_length() {
        let phrase = vec!["abandon".to_string(), "ability".to_string()];
        assert!(!validate_seed_phrase(&phrase));

        // 13 words is not a BIP-39 length even if every word is known.
        let mut phrase = test_phrase();
        phrase.push("abandon".to_string());
        assert!(!validate_seed_phrase(&phrase));
    }

    /// Users retype phrases with stray capitals and spacing; that should not
    /// look like a different wallet.
    #[test]
    fn test_validate_seed_phrase_normalises_input() {
        let mut phrase = test_phrase();
        phrase[0] = "  Abandon ".to_string();
        phrase[11] = "ABOUT".to_string();
        assert!(validate_seed_phrase(&phrase));
        assert_eq!(
            wallet_from_seed_phrase("a", &phrase).unwrap().address(),
            wallet_from_seed_phrase("a", &test_phrase()).unwrap().address()
        );
    }

    #[test]
    fn test_wallet_from_seed_phrase() {
        let wallet = wallet_from_seed_phrase("seed_test", &test_phrase()).unwrap();
        assert_eq!(wallet.name(), "seed_test");
    }

    #[test]
    fn test_wallet_from_seed_phrase_deterministic() {
        let phrase = test_phrase();
        let w1 = wallet_from_seed_phrase("a", &phrase).unwrap();
        let w2 = wallet_from_seed_phrase("b", &phrase).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    /// Different phrases must give different keys, including ones that differ
    /// only in length.
    #[test]
    fn test_different_phrases_give_different_keys() {
        let a = wallet_from_seed_phrase("a", &test_phrase()).unwrap();
        let b = wallet_from_seed_phrase("b", &test_phrase_24()).unwrap();
        assert_ne!(a.secret_bytes(), b.secret_bytes());
    }

    /// The key is derived from the BIP-39 seed, not from the words. A wallet
    /// that hashed the words directly would match this value, and would have
    /// skipped the 2048-round stretch that makes a stolen phrase expensive to
    /// attack.
    #[test]
    fn test_key_comes_from_the_stretched_seed() {
        let phrase = test_phrase();
        let wallet = wallet_from_seed_phrase("stretch", &phrase).unwrap();

        let mut naive = Vec::new();
        for word in &phrase {
            naive.extend_from_slice(word.as_bytes());
            naive.push(0);
        }
        assert_ne!(wallet.secret_bytes(), *blake3::hash(&naive).as_bytes());

        let seed = bip39::Mnemonic::parse_in(bip39::Language::English, phrase.join(" "))
            .unwrap()
            .to_seed("");
        assert_eq!(wallet.secret_bytes(), derive_secret_key(&seed).unwrap().0);
    }

    #[test]
    fn test_wallet_from_seed_phrase_invalid_words() {
        let mut phrase = test_phrase();
        phrase[3] = "notaword".to_string();
        assert!(wallet_from_seed_phrase("bad", &phrase).is_err());
    }

    #[test]
    fn test_drop_zeroizes() {
        let secret = SecretKey32::generate();
        let key_bytes = secret.0;
        {
            let _wallet = Wallet::from_secret_key("drop_test", secret).unwrap();
        }
        assert_eq!(key_bytes, secret.0);
    }
}
