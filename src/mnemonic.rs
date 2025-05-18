use anyhow::{anyhow, Result};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::shamir::Share;

/// A word list for generating memorable mnemonics
const WORD_LIST: &[&str] = &[
    // Common nouns (objects)
    "apple", "arrow", "bacon", "badge", "banana", "basket", "beach", "beard", "beetle", "bell", 
    "berry", "bird", "blade", "blanket", "blood", "boat", "bone", "book", "boot", "bottle", 
    "bowl", "box", "bread", "brick", "bridge", "brush", "bucket", "button", "cactus", "cake", 
    "camera", "candle", "candy", "cannon", "canvas", "card", "carpet", "carrot", "castle", "chain", 
    "chair", "chalk", "cheese", "cherry", "chest", "circle", "clock", "cloud", "clover", "club", 
    "coffee", "coin", "compass", "cookie", "coral", "corn", "cow", "crab", "crayon", "crown", 
    "crystal", "cube", "cup", "diamond", "dice", "dinosaur", "dog", "dolphin", "donut", "door", 
    "dragon", "drum", "eagle", "earth", "elephant", "emerald", "engine", "feather", "fence", "fire", 
    "fish", "flag", "flame", "flower", "flute", "forest", "fork", "fossil", "fountain", "fox", 
    
    // Common adjectives
    "able", "acid", "angry", "automatic", "average", "bad", "beautiful", "best", "better", "big", 
    "bitter", "black", "blue", "bold", "brave", "bright", "broken", "brown", "bumpy", "busy", 
    "careful", "cheap", "clean", "clear", "clever", "close", "cold", "cool", "crazy", "crispy", 
    "cruel", "curly", "curved", "damaged", "damp", "dark", "deep", "digital", "dirty", "dry", 
    "early", "easy", "elastic", "empty", "equal", "evil", "excited", "expensive", "fast", "fat", 
    "flat", "fluffy", "foolish", "fresh", "friendly", "full", "fuzzy", "gentle", "giant", "good", 
    "great", "green", "guilty", "hairy", "happy", "hard", "harsh", "healthy", "heavy", "high", 
    "hollow", "hot", "huge", "icy", "illegal", "intense", "itchy", "jealous", "joyful", "juicy", 
    "kind", "large", "late", "lazy", "light", "little", "lively", "lonely", "long", "loose", 
    "loud", "low", "lucky", "massive", "maximum", "mean", "mighty", "minimum", "modern", "moist", 
    
    // Common verbs
    "accept", "add", "admire", "admit", "advise", "afford", "agree", "alert", "allow", "amuse", 
    "analyse", "announce", "annoy", "answer", "apologise", "appear", "applaud", "appreciate", 
    "approve", "argue", "arrange", "arrest", "arrive", "ask", "attach", "attack", "attempt", 
    "attend", "attract", "avoid", "back", "bake", "balance", "ban", "bang", "bare", "bat", 
    "bathe", "battle", "beam", "beg", "behave", "belong", "bleach", "bless", "blind", "blink", 
    "blot", "blush", "boast", "boil", "bolt", "bomb", "book", "bore", "borrow", "bounce", 
    "bow", "box", "brake", "branch", "breathe", "brew", "brief", "bring", "broadcast", "bruise", 
    "brush", "bubble", "budget", "build", "bump", "burn", "bury", "buzz", "calculate", "call", 
];

/// A single word that corresponds to a Shamir share
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct MemorableWord {
    /// The actual Shamir share this represents
    #[zeroize(skip)]
    pub share: Share,
    /// The memorable word
    pub word: String,
    /// Index of this share (1-based for user display)
    pub index: usize,
}

impl fmt::Display for MemorableWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Word #{}: \"{}\"", self.index, self.word)
    }
}

/// Convert a share to a memorable word
pub fn share_to_word(share: &Share) -> Result<String> {
    let seed_bytes = bincode::serialize(share)?;
    let hash = blake3::hash(&seed_bytes);
    let hash_bytes = hash.as_bytes();
    
    // Use first 4 bytes of hash as a seed for word selection
    let mut seed = [0u8; 32];
    seed[0..4].copy_from_slice(&hash_bytes[0..4]);
    let mut rng = ChaCha20Rng::from_seed(seed);
    
    // Select a word from the list
    let word = WORD_LIST.choose(&mut rng).unwrap_or(&"default");
    
    Ok((*word).to_string())
}

/// Generate a memorable word for a Shamir share
pub fn generate_memorable_word(share: Share, index: usize) -> Result<MemorableWord> {
    let word = share_to_word(&share)?;
    
    Ok(MemorableWord {
        share,
        word,
        index,
    })
}

/// Try to recover a Shamir share from a memorable word
pub fn recover_share_from_word(
    word: &str, 
    available_shares: &[Share],
) -> Result<Share> {
    // Check each share to see if it maps to this word
    for share in available_shares {
        let share_word = share_to_word(share)?;
        
        if word.trim().to_lowercase() == share_word.to_lowercase() {
            return Ok(share.clone());
        }
    }
    
    Err(anyhow!("The provided word doesn't match any known share"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir;
    
    #[test]
    fn test_memorable_word_generation() {
        let secret = b"test secret";
        let shares = shamir::split(secret, 3, 2, None).unwrap();
        
        for (i, share) in shares.iter().enumerate() {
            let memorable = generate_memorable_word(share.clone(), i + 1).unwrap();
            
            // Verify the word is single
            assert!(!memorable.word.contains(" "));
            
            // Verify it can be matched back
            let recovered_word = share_to_word(share).unwrap();
            assert_eq!(memorable.word, recovered_word);
        }
    }
    
    #[test]
    fn test_share_recovery_from_word() {
        let secret = b"recovery test";
        let shares = shamir::split(secret, 3, 2, None).unwrap();
        
        // Generate a memorable word
        let memorable = generate_memorable_word(shares[0].clone(), 1).unwrap();
        
        // Recover from the word
        let recovered = recover_share_from_word(&memorable.word, &shares).unwrap();
        
        // Verify it's the same share
        assert_eq!(recovered.id, shares[0].id);
        assert_eq!(recovered.data, shares[0].data);
    }
}