use std::collections::HashMap;

use super::wordlists::{BITS_PER_WORD, WORDS_PER_REF};
use crate::error::{CoreError, Result};

/// Decode a sequence of English words back to a 256-bit value.
pub fn decode_ref(
    words: &[String],
    _wordlists: &[Vec<String>; 4],
    reverse_lookups: &[HashMap<String, u16>; 4],
) -> Result<[u8; 32]> {
    if words.len() != WORDS_PER_REF {
        return Err(CoreError::SentenceEncoding(format!(
            "expected {WORDS_PER_REF} words, got {}",
            words.len()
        )));
    }

    let mut padded = [0u8; 33];

    for (i, word) in words.iter().enumerate() {
        let list_idx = i % 4;
        // mfa-L4: never echo the word. A mistyped recovery word is usually one
        // letter off the real one, and this error reaches terminals and logs.
        let index = reverse_lookups[list_idx].get(word).ok_or_else(|| {
            CoreError::SentenceEncoding(format!(
                "word {} of {WORDS_PER_REF} is not in the wordlist",
                i + 1
            ))
        })?;

        let bit_offset = i * BITS_PER_WORD;
        set_bits(&mut padded, bit_offset, BITS_PER_WORD, *index);
    }

    // Reject a non-canonical sentence.
    //
    // 22 words x 12 bits = 264 bits, but a root is only 256. `encode_ref` always
    // writes the trailing 8 bits as zero. Until this check existed they were
    // decoded and then discarded, which made the mapping 256-to-1: for any root
    // there were 256 distinct, fully valid 22-word sentences (the last word
    // ranging over every value that differs only in those pad bits) that all
    // decoded to the identical key. A sentence was therefore not a canonical
    // representation of the root it names.
    //
    // Refusing a non-zero pad restores a 1:1 mapping and costs nothing: no
    // sentence this encoder has ever produced has a non-zero pad, so no
    // legitimately issued recovery sentence is invalidated.
    if padded[32] != 0 {
        return Err(CoreError::SentenceEncoding(
            "non-canonical sentence reference: trailing pad bits are not zero".into(),
        ));
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&padded[..32]);
    Ok(result)
}

/// Decode a space-separated sentence string back to a 256-bit value.
pub fn decode_ref_string(
    sentence: &str,
    wordlists: &[Vec<String>; 4],
    reverse_lookups: &[HashMap<String, u16>; 4],
) -> Result<[u8; 32]> {
    let words: Vec<String> = sentence
        .split_whitespace()
        .map(std::string::ToString::to_string)
        .collect();
    decode_ref(&words, wordlists, reverse_lookups)
}

/// Set `count` bits starting at `bit_offset` in a byte array.
fn set_bits(data: &mut [u8], bit_offset: usize, count: usize, value: u16) {
    for i in 0..count {
        let byte_idx = (bit_offset + i) / 8;
        let bit_idx = 7 - ((bit_offset + i) % 8);
        if byte_idx < data.len() {
            if (value >> (count - 1 - i)) & 1 == 1 {
                data[byte_idx] |= 1 << bit_idx;
            } else {
                data[byte_idx] &= !(1 << bit_idx);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentence::encode::encode_ref;
    use crate::sentence::wordlists::{build_reverse_lookup, placeholder_wordlist};

    fn test_wordlists() -> [Vec<String>; 4] {
        [
            placeholder_wordlist(0),
            placeholder_wordlist(1),
            placeholder_wordlist(2),
            placeholder_wordlist(3),
        ]
    }

    fn test_reverse_lookups(wl: &[Vec<String>; 4]) -> [HashMap<String, u16>; 4] {
        [
            build_reverse_lookup(&wl[0]),
            build_reverse_lookup(&wl[1]),
            build_reverse_lookup(&wl[2]),
            build_reverse_lookup(&wl[3]),
        ]
    }

    #[test]
    fn encode_decode_roundtrip_zeros() {
        let data = [0u8; 32];
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let words = encode_ref(&data, &wl).unwrap();
        let decoded = decode_ref(&words, &wl, &rl).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_roundtrip_all_ones() {
        let data = [0xFF; 32];
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let words = encode_ref(&data, &wl).unwrap();
        let decoded = decode_ref(&words, &wl, &rl).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn encode_decode_roundtrip_random() {
        let data: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
        ];
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let words = encode_ref(&data, &wl).unwrap();
        let decoded = decode_ref(&words, &wl, &rl).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn wrong_word_count_errors() {
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let words = vec!["w0_0000".to_string(); 5];
        assert!(decode_ref(&words, &wl, &rl).is_err());
    }

    #[test]
    fn unknown_word_errors() {
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let mut words: Vec<String> = vec!["w0_0000".to_string(); WORDS_PER_REF];
        words[0] = "nonexistent_word".to_string();
        assert!(decode_ref(&words, &wl, &rl).is_err());
    }

    #[test]
    fn string_roundtrip() {
        let data = [0x42; 32];
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let sentence = crate::sentence::encode::encode_ref_string(&data, &wl).unwrap();
        let decoded = decode_ref_string(&sentence, &wl, &rl).unwrap();
        assert_eq!(decoded, data);
    }

    /// Roundtrip through the REAL production English wordlists, not the
    /// `w0_0000` placeholders every other test in this module uses.
    ///
    /// Until this existed, `production_wordlists()` was covered only for size
    /// and uniqueness, so a defect reachable solely on the shipped lists — a
    /// word repeated *across* two lists, say — would not have failed any test
    /// while `teagarden key export` is the only caller that uses them.
    #[test]
    fn production_wordlists_string_roundtrip() {
        let wl = crate::sentence::wordlists::production_wordlists();
        let rl = test_reverse_lookups(&wl);

        // A fixed non-trivial pattern plus the two extremes, so every 12-bit
        // window sees both all-zero and all-one inputs.
        for data in [[0x00u8; 32], [0xFFu8; 32], [0x9Au8; 32]] {
            let sentence = crate::sentence::encode::encode_ref_string(&data, &wl).unwrap();

            // It must be a real sentence of real words, not placeholder tokens.
            assert_eq!(sentence.split_whitespace().count(), WORDS_PER_REF);
            assert!(
                sentence.chars().all(|c| c.is_ascii_lowercase() || c == ' '),
                "production sentence must be lowercase ASCII words: {sentence}"
            );

            let decoded = decode_ref_string(&sentence, &wl, &rl).unwrap();
            assert_eq!(decoded, data, "roundtrip lost bytes for {data:?}");
        }
    }

    /// A mistyped word is refused rather than silently decoded to a wrong root.
    ///
    /// This is the negative case for the missing checksum documented in
    /// `docs/RECOVERY_SENTENCE_FORMAT.md` ("What the sentence does not have"): structural validation
    /// catches a word that is not in the expected list, but a typo that lands
    /// on another *valid* word cannot be caught here — only `key import`'s
    /// volume verification catches that.
    #[test]
    fn production_unknown_word_is_refused() {
        let wl = crate::sentence::wordlists::production_wordlists();
        let rl = test_reverse_lookups(&wl);
        let sentence = crate::sentence::encode::encode_ref_string(&[0x5Cu8; 32], &wl).unwrap();

        let mut words: Vec<String> = sentence
            .split_whitespace()
            .map(std::string::ToString::to_string)
            .collect();
        words[7] = "zzzzzznotaword".to_string();

        assert!(decode_ref(&words, &wl, &rl).is_err());
    }

    /// A sentence must name exactly one root — no aliases.
    ///
    /// Found by the independent Agy review on 2026-09-01 and confirmed by this
    /// test before the fix: word 22 carries 4 key bits and 8 pad bits, and the
    /// decoder discarded the pad. Every root therefore had **256** valid
    /// spellings. Anything that treated a sentence as an identifier — comparing
    /// two for equality, hashing one, or deduplicating a list of them — was
    /// wrong, because the same key could arrive under 256 different names.
    #[test]
    fn aliased_sentence_is_refused() {
        let wl = crate::sentence::wordlists::production_wordlists();
        let rl = test_reverse_lookups(&wl);
        let data = [0x11u8; 32];
        let sentence = crate::sentence::encode::encode_ref_string(&data, &wl).unwrap();
        let mut words: Vec<String> = sentence
            .split_whitespace()
            .map(std::string::ToString::to_string)
            .collect();

        // The canonical sentence still decodes.
        assert_eq!(decode_ref(&words, &wl, &rl).unwrap(), data);

        // Word 22 (index 21) is drawn from list 21 % 4 == 1. Its 12-bit index is
        // 4 real key bits followed by the 8 pad bits, so flipping only the low 8
        // bits yields a different, still-valid word that used to decode to the
        // very same root.
        let alias_idx = rl[1][&words[21]] ^ 0x00FF;
        words[21] = wl[1][alias_idx as usize].clone();
        assert_ne!(
            words[21],
            sentence.split_whitespace().nth(21).unwrap(),
            "the alias must actually be a different word, or this proves nothing"
        );

        let err = decode_ref(&words, &wl, &rl)
            .expect_err("a non-canonical sentence must be refused, not silently accepted");
        assert!(
            format!("{err}").contains("non-canonical"),
            "unexpected error: {err}"
        );
    }

    /// mfa-L4: a recovery sentence is a secret. A typo'd word is usually one
    /// letter off the real word, so echoing it into an error (which reaches
    /// terminals, logs and bug reports) leaks most of a recovery word. Report
    /// the position only.
    #[test]
    fn unknown_word_error_reports_position_not_the_word() {
        let wl = test_wordlists();
        let rl = test_reverse_lookups(&wl);
        let mut words = encode_ref(&[0x5A; 32], &wl).unwrap();
        words[6] = "zzsecretzz".to_string();
        let err = decode_ref(&words, &wl, &rl).expect_err("unknown word must be refused");
        let msg = format!("{err}");
        assert!(
            !msg.contains("zzsecretzz"),
            "the mistyped word leaked: {msg}"
        );
        assert!(
            msg.contains("word 7"),
            "the 1-based position must be reported: {msg}"
        );
    }
}
