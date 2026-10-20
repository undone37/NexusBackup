//! The written form of recovery keys (ADR-015): a 32-byte key as 24 words of the BIP39 English
//! list, the key followed by the first byte of its SHA-256 as checksum, 11 bits per word.
//! Used for the appliance recovery key (keyd) and the tenant recovery keys (catalog).

#![warn(missing_docs)]

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The BIP39 English word list (2048 words, sorted; SHA-256 2f5eed53...b24dbda, the file of
/// github.com/bitcoin/bips bip-0039/english.txt). Every word is unique in its first four letters.
const WORDLIST: &str = include_str!("bip39-english.txt");

/// Words of a recovery key: 256 bits plus an 8-bit checksum, 11 bits per word.
pub const WORDS: usize = 24;

fn wordlist() -> &'static [&'static str] {
    static W: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    W.get_or_init(|| WORDLIST.lines().collect())
}

/// Index of a typed word in the BIP39 list: the whole word, or its first four letters
/// (lower case). `None` for anything else.
pub fn word_index(typed: &str) -> Option<usize> {
    let w = wordlist();
    match w.binary_search(&typed) {
        Ok(i) => Some(i),
        Err(i) if typed.len() == 4 => w.get(i).filter(|x| x.starts_with(typed)).map(|_| i),
        Err(_) => None,
    }
}

/// `k` as 24 BIP39 English words separated by spaces, the BIP39 encoding of 256 bits.
pub fn format(k: &[u8; 32]) -> String {
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(k);
    bits[32] = Sha256::digest(k)[0];
    let w = wordlist();
    (0..WORDS)
        .map(|i| {
            w[(0..11).fold(0, |v, j| {
                v << 1 | usize::from(bits[(i * 11 + j) / 8] >> (7 - (i * 11 + j) % 8) & 1)
            })]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Inverse of [`format()`]: 24 words, each whole or its first four letters; case and separators
/// (spaces, dashes, line breaks, numbering) ignored. The error names the position of an
/// unknown word or a failed checksum, never the typed text.
pub fn parse(s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let typed: Vec<Zeroizing<String>> = s
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|t| !t.is_empty())
        .map(|t| Zeroizing::new(t.to_ascii_lowercase()))
        .collect();
    if typed.len() != WORDS {
        return Err(format!("recovery key: {WORDS} words expected, got {}", typed.len()));
    }
    let mut bits = Zeroizing::new([0u8; 33]);
    for (i, t) in typed.iter().enumerate() {
        let idx = word_index(t).ok_or_else(|| format!("recovery key: word {} is not in the BIP39 list", i + 1))?;
        for j in 0..11 {
            if idx >> (10 - j) & 1 == 1 {
                let p = i * 11 + j;
                bits[p / 8] |= 1 << (7 - p % 8);
            }
        }
    }
    if Sha256::digest(&bits[..32])[0] != bits[32] {
        return Err("recovery key: checksum does not match (a word is wrong, or two are swapped)".into());
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&bits[..32]);
    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors of BIP39 (trezor/python-mnemonic vectors.json, 256-bit entropy).
    #[test]
    fn bip39_vectors() {
        let zoo = format!("{}vote", "zoo ".repeat(23));
        let abandon = format!("{}art", "abandon ".repeat(23));
        let legal = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth \
                     useful legal winner thank year wave sausage worth title";
        for (k, words) in [
            ([0u8; 32], abandon.as_str()),
            ([0x7f; 32], legal),
            ([0xff; 32], zoo.as_str()),
        ] {
            assert_eq!(format(&k), words);
            assert_eq!(*parse(words).unwrap(), k);
        }
    }

    #[test]
    fn parsing() {
        let k = [0x5a; 32];
        let s = format(&k);
        let w: Vec<&str> = s.split(' ').collect();
        // numbering, line breaks, upper case and four-letter prefixes as written on paper
        let paper: String = w
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{:02}. {}\n", i + 1, &w.to_uppercase()[..w.len().min(4)]))
            .collect();
        assert_eq!(*parse(&paper).unwrap(), k);
        let e = |s: &str| parse(s).unwrap_err();
        assert!(e(&w[..23].join(" ")).contains("24 words expected, got 23"));
        let mut bad = w.clone();
        bad[6] = "abandonx";
        assert!(e(&bad.join(" ")).contains("word 7 is not"));
        bad[6] = "aba"; // neither a word nor a four-letter prefix
        assert!(e(&bad.join(" ")).contains("word 7 is not"));
        let mut swapped = w.clone();
        let j = (1..24).find(|&j| w[j] != w[0]).unwrap();
        swapped.swap(0, j);
        assert!(e(&swapped.join(" ")).contains("checksum"));
        assert_eq!(word_index("zoo"), Some(2047));
        assert_eq!(word_index("aban"), Some(0));
        assert_eq!(word_index("abandon"), Some(0));
        assert_eq!(word_index("xyzw"), None);
    }
}
