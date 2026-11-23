use super::wordlists::WORDS_PER_REF;
use std::collections::HashMap;

/// Validate that a sentence reference has the correct structure.
///
/// # This is not on the decode path
///
/// Nothing in the workspace calls this outside its own tests — `decode_ref`
/// performs its own count, membership and canonicality checks, and it is what
/// `key import` and `RecoveryProtector` actually use. This function is a
/// structural pre-check for callers that want to reject a malformed sentence
/// before attempting to decode it.
///
/// It is deliberately kept in lockstep with `decode_ref`: it must never accept
/// a sentence that `decode_ref` would reject. A weaker validator is worse than
/// none, because a caller reasonably reads a passing `validate_sentence` as
/// "this sentence is well formed" and would then be surprised by the decode
/// failing.
pub fn validate_sentence(
    words: &[String],
    reverse_lookups: &[HashMap<String, u16>; 4],
) -> Result<(), String> {
    if words.len() != WORDS_PER_REF {
        return Err(format!(
            "expected {WORDS_PER_REF} words, got {}",
            words.len()
        ));
    }

    for (i, word) in words.iter().enumerate() {
        let list_idx = i % 4;
        if !reverse_lookups[list_idx].contains_key(word) {
            // Lockstep with `decode_ref` (mfa-L4): position only, never the word.
            return Err(format!(
                "word {} of {WORDS_PER_REF} is not in the wordlist",
                i + 1
            ));
        }
    }

    // Canonicality, matching `decode_ref`. The final word carries 4 key bits
    // followed by the 8 pad bits, so a canonical sentence has zero in the low
    // 8 bits of its last index. Without this, 256 distinct sentences per root
    // pass validation and only one of them decodes.
    let last = WORDS_PER_REF - 1;
    let last_index = reverse_lookups[last % 4][&words[last]];
    if last_index & 0x00FF != 0 {
        return Err("non-canonical sentence reference: trailing pad bits are not zero".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sentence::wordlists::{build_reverse_lookup, placeholder_wordlist};

    fn test_reverse_lookups() -> [HashMap<String, u16>; 4] {
        [
            build_reverse_lookup(&placeholder_wordlist(0)),
            build_reverse_lookup(&placeholder_wordlist(1)),
            build_reverse_lookup(&placeholder_wordlist(2)),
            build_reverse_lookup(&placeholder_wordlist(3)),
        ]
    }

    #[test]
    fn valid_sentence() {
        let rl = test_reverse_lookups();
        let words: Vec<String> = (0..WORDS_PER_REF)
            .map(|i| format!("w{}_0000", i % 4))
            .collect();
        assert!(validate_sentence(&words, &rl).is_ok());
    }

    #[test]
    fn wrong_count_rejected() {
        let rl = test_reverse_lookups();
        let words = vec!["w0_0000".to_string(); 5];
        assert!(validate_sentence(&words, &rl).is_err());
    }

    #[test]
    fn invalid_word_rejected() {
        let rl = test_reverse_lookups();
        let mut words: Vec<String> = (0..WORDS_PER_REF)
            .map(|i| format!("w{}_0000", i % 4))
            .collect();
        words[3] = "INVALID".to_string();
        assert!(validate_sentence(&words, &rl).is_err());
    }

    /// mfa-L4, lockstep with `decode_ref`: never echo a (possibly one-letter-off)
    /// recovery word into an error.
    #[test]
    fn invalid_word_error_reports_position_not_the_word() {
        let rl = test_reverse_lookups();
        let mut words: Vec<String> = (0..WORDS_PER_REF)
            .map(|i| format!("w{}_0000", i % 4))
            .collect();
        words[3] = "zzsecretzz".to_string();
        let msg = validate_sentence(&words, &rl).unwrap_err();
        assert!(
            !msg.contains("zzsecretzz"),
            "the mistyped word leaked: {msg}"
        );
        assert!(
            msg.contains("word 4"),
            "the 1-based position must be reported: {msg}"
        );
    }

    /// This validator must never be more permissive than the decoder.
    ///
    /// Before 2026-09-01 it was: it accepted the 256 pad-bit aliases of every
    /// root. A caller that gated on `validate_sentence` and then decoded would
    /// have seen a sentence pass validation and then fail to decode.
    #[test]
    fn agrees_with_decoder_on_non_canonical_sentences() {
        let wl = crate::sentence::wordlists::production_wordlists();
        let rl: [HashMap<String, u16>; 4] = core::array::from_fn(|i| build_reverse_lookup(&wl[i]));

        let data = [0x11u8; 32];
        let sentence = crate::sentence::encode::encode_ref_string(&data, &wl).unwrap();
        let mut words: Vec<String> = sentence
            .split_whitespace()
            .map(std::string::ToString::to_string)
            .collect();

        // Canonical: both accept.
        assert!(validate_sentence(&words, &rl).is_ok());
        assert!(crate::sentence::decode::decode_ref(&words, &wl, &rl).is_ok());

        // Pad-bit alias: both must reject.
        let last = WORDS_PER_REF - 1;
        let alias_idx = rl[last % 4][&words[last]] ^ 0x00FF;
        words[last] = wl[last % 4][alias_idx as usize].clone();

        assert!(
            validate_sentence(&words, &rl).is_err(),
            "validator accepted a sentence the decoder rejects"
        );
        assert!(crate::sentence::decode::decode_ref(&words, &wl, &rl).is_err());
    }
}
