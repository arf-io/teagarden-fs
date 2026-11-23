# Recovery sentence format

TeaGarden writes 256-bit secrets as sentences of 22 English words so that a person
can copy them onto paper. This document describes the encoding exactly.

Source: `crates/teagarden-core/src/sentence/` (`wordlists.rs`, `wordlists_data.rs`,
`encode.rs`, `decode.rs`).

## Where it is used

| Use | What the 22 words encode |
|---|---|
| The recovery slot of a key-protected volume (`volume create --key-protection`) | a fresh 256-bit random secret; the slot's key-encryption key is `BLAKE3 derive_key("teagarden.v2:kek:recovery", secret)` |
| `key export` / `key import` | the volume's 256-bit key-hierarchy root |

Both produce the same kind of sentence, but they are different secrets with
different uses (see [USER_GUIDE.md](USER_GUIDE.md#recovery-sentence)). A command's
`--recovery-file` accepts either for volume unlock, attach and single-object or
directory decrypt, including on key-protected volumes: it tries the sentence as
the volume's recovery slot first and, if that does not open it, as an exported root (`keyslot enroll`
and `keyslot remove-slot` accept only a slot's sentence).

## Encoding

- There are four word lists, each of exactly 4096 distinct lowercase English
  words. Each word therefore carries 12 bits.
- The 32-byte secret is extended with one zero byte to 33 bytes (264 bits).
- The 264 bits are read most-significant-bit first in 22 groups of 12 bits. Group
  `i` (counting from 0) is an index into word list `i mod 4`.
- The sentence is the 22 words joined by single spaces.

The last word carries the final 4 bits of the secret followed by the 8 bits of the
zero pad byte.

## Decoding

- The input is split on whitespace. Exactly 22 words are required.
- Each word must appear in the list for its position (`i mod 4`). Matching is
  exact and case-sensitive; the lists are lowercase.
- The 8 pad bits must be zero. A sentence whose last word sets any of them is
  refused as non-canonical, so each secret has exactly one valid sentence.
- An unknown word is reported by its position only ("word 7 of 22 is not in the
  wordlist"), never by the word itself, so a near-miss does not end up in
  terminals or logs.

## Fields the sentence omits

- **No checksum.** The pad bits are fixed at zero and detect only a wrong last
  word that sets them. A mistyped word that is still a valid word for its
  position decodes to a different secret. The mistake surfaces when that secret
  is used: the recovery slot fails to unwrap, or `key import` reports that the
  sentence opens no local volume.
- **No version or epoch.** The sentence carries only the 256 bits.

## Handling

A sentence is as strong as the secret it encodes, and it is a complete credential
on its own. TeaGarden accepts it only from a file with `--recovery-file PATH` (or
from standard input with `-`), never as a command-line argument.
Leading and trailing whitespace in the file is ignored.
