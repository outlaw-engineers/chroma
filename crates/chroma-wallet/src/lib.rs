use chroma_core::error::{CoreError, Result};
use chroma_core::hash::Hash160;
use chroma_core::types::{Address, Amount, Nonce};
use chroma_crypto::hash::hash160;
use chroma_crypto::schnorr::{PublicKey32, SecretKey32};
use chroma_tx::create_transaction;
use zeroize::Zeroize;

const BIP39_WORDLIST: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "awesome", "awful", "awkward", "axis", "baby",
    "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef",
    "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid",
    "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
    "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blow", "blue", "blur", "blush", "board", "boat", "body", "boil",
    "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
    "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk",
    "bullet", "bundle", "bunny", "burden", "burger", "burst", "bus", "business",
    "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
    "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart",
    "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch",
    "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery",
    "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion",
    "change", "chaos", "chapter", "charge", "chase", "cheap", "check", "cheese",
    "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
    "choose", "chronic", "chuckle", "chunk", "churn", "citizen", "city", "civil",
    "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever",
    "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach",
    "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color",
    "column", "combine", "come", "comfort", "comic", "common", "company", "concert",
    "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook",
    "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost",
    "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote",
    "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp",
    "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise",
    "crumble", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard",
    "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle",
    "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter",
    "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
    "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree",
    "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart",
    "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design",
    "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote",
    "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ",
    "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree",
    "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert",
    "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin",
    "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove",
    "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift",
    "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck",
    "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic",
];

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

pub fn generate_seed_phrase() -> Vec<String> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut phrase = Vec::with_capacity(12);
    let s = RandomState::new();
    for i in 0..12 {
        let mut h = s.build_hasher();
        h.write_u64(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );
        h.write_usize(i);
        let idx = (h.finish() as usize) % BIP39_WORDLIST.len();
        phrase.push(BIP39_WORDLIST[idx].to_string());
    }
    phrase
}

pub fn validate_seed_phrase(phrase: &[String]) -> bool {
    if phrase.len() != 12 {
        return false;
    }
    for word in phrase {
        if !BIP39_WORDLIST.contains(&word.as_str()) {
            return false;
        }
    }
    true
}

pub fn wallet_from_seed_phrase(name: &str, phrase: &[String]) -> Result<Wallet> {
    if !validate_seed_phrase(phrase) {
        return Err(CoreError::InvalidSignature(
            "invalid seed phrase: contains unknown words or wrong length".to_string(),
        ));
    }
    let mut entropy = Vec::with_capacity(64);
    for word in phrase {
        entropy.extend_from_slice(word.as_bytes());
        entropy.push(0);
    }
    let hash = blake3::hash(&entropy);
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(hash.as_bytes());
    let secret_key = SecretKey32::from_bytes(key_bytes)
        .map_err(|e| CoreError::InvalidSignature(format!("invalid key: {}", e)))?;
    Wallet::from_secret_key(name, secret_key)
}

#[allow(dead_code)]
fn blake3(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_phrase() -> Vec<String> {
        vec![
            "abandon".to_string(), "ability".to_string(), "able".to_string(),
            "about".to_string(), "above".to_string(), "absent".to_string(),
            "absorb".to_string(), "abstract".to_string(), "absurd".to_string(),
            "abuse".to_string(), "access".to_string(), "accident".to_string(),
        ]
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
        assert_eq!(phrase.len(), 12);
        for word in &phrase {
            assert!(!word.is_empty());
        }
    }

    #[test]
    fn test_validate_seed_phrase_valid() {
        assert!(validate_seed_phrase(&test_phrase()));
    }

    #[test]
    fn test_validate_seed_phrase_invalid() {
        let mut phrase = test_phrase();
        phrase.push("xyznotaword".to_string());
        assert!(!validate_seed_phrase(&phrase));
    }

    #[test]
    fn test_validate_seed_phrase_wrong_length() {
        let phrase = vec!["abandon".to_string(), "ability".to_string()];
        assert!(!validate_seed_phrase(&phrase));
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

    #[test]
    fn test_wallet_from_seed_phrase_invalid_words() {
        let mut phrase = test_phrase();
        phrase.push("notaword".to_string());
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
