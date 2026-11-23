/// Decode a sentence reference (word sequence) back to a 256-bit value.
pub mod decode;
/// Encode a 256-bit value as a sequence of English words.
pub mod encode;
/// Validate the structure of a sentence reference.
pub mod validate;
/// Wordlist parameters and accessor for the active wordlists.
pub mod wordlists;
/// Embedded production wordlist data (four 4096-word lists).
pub mod wordlists_data;
