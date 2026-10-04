# How it works & technical caveats

[日本語 →](ARCHITECTURE.md) / [Back to README](../README-EN.md)

> [!CAUTION]
> This tool is a toy for everyday fun. Do not use it for real work. This document explains how it is built; it is not a security guarantee.

## Container format

```
[0, 512)     superblock: salt(16) | nonce(24) | sealed used-bytes(32) | comment area or random
[512, size)  data area: [length(8) | age ciphertext] records packed from the start; the rest is random
```

- **Fixed size, not sparse**: `init` writes random bytes over the whole file. Neither `ls` nor `du` changes after appending; the container's mtime is restored too
- **One file = one record**: metadata (name, size, mtime, mode, MIME type, added-at) and body are encrypted together with [age](https://age-encryption.org/) (X25519 + ChaCha20-Poly1305)
- **Mask layer**: the whole data area is XORed with an XChaCha20 keystream whose key is derived (HKDF) from the public key and a per-container salt, so age's text headers (`age-encryption.org/v1`, …) and record boundaries are indistinguishable from the random free space
- **Write offset**: sealed in the superblock with XChaCha20-Poly1305; there is no plaintext header. Appending rewrites only the first 72 bytes
- **Comment**: `init --comment` stores the note in plaintext from byte 72 of the superblock as `"WOTCNOTE" | version(1) | length(2) | CRC32(4) | text` (max 425 bytes), readable without any key. Without a comment the area stays random, so a false match of magic + CRC is practically impossible (this also covers capsules made by older versions). Running `add` with v1.0.3 or older overwrites the area with random bytes and erases the comment
- **Changing / removing the comment** (`vault comment add/edit/erase`): the whole comment area [72, 512) is refilled with random bytes before each write, so no remnant of an older, longer comment survives; after erasing, the container is indistinguishable from one that never had a comment. The public key must decrypt the superblock first (so other files are never overwritten), an exclusive lock is held, and the mtime is preserved
- **Opening**: derive the public key from the secret key → unmask → age-decrypt each record → extract. Directory components are stripped from file names (path traversal), duplicates become `name (1).ext`
- **No space**: `add` only says "容量不足" (no space). A partially written record never advances the offset, so existing records stay intact
- **Concurrency**: `add` takes an exclusive `flock` on the container and `open` a shared one, so simultaneous `add`s queue up instead of overwriting each other
- **Salvage**: if one file's ciphertext is corrupted, opening skips it and continues as long as its length field is readable; a corrupted length field makes the rest unreadable. `--and-destroy-key` never destroys a partially corrupted capsule
- **Foolproofing**: passing the capsule's own files (container, public key, `.tlock`) to `add` skips them (think `vault add *`); `init` refuses to overwrite an existing capsule
- **Destroy**: 3 random overwrite passes → truncate → rename to a random name → delete (own implementation since macOS has no `shred`). Targets: container, the key files used to open, `<container>.tlock`
- The format has no OS-dependent parts (integers are big endian), so containers can move between macOS and Linux

## Key splitting (Shamir's Secret Sharing)

Think of the secret key as the y-intercept of a line. For 2-of-3, draw a random line whose y-intercept is the key and hand out three points on it.
One point is consistent with infinitely many lines, so it tells you nothing; two points fix the line and therefore the key.
For 3-of-N a parabola is used instead, and so on. The key is not cut into pieces, so **fewer than K shares reveal nothing at all**.

- Implementation: the raw 32 bytes of the age secret key are split with [OpenBao's shamir package](https://github.com/openbao/openbao/tree/main/sdk/helper/shamir) (Shamir over GF(256))
- Share encoding: `version | K | N | index | capsule fingerprint (first 4 bytes of SHA-256 of the public key) | split ID (4 random bytes) | data`, bech32 with HRP `wotc-share-`, upper case. The checksum catches transcription errors; either case is accepted
- The fingerprint detects shares from another capsule; the split ID detects shares from an earlier split of the same key (re-splitting uses a new polynomial, so old and new shares cannot be combined)
- With `init --shares`, the full secret key is never written to disk. Reconstruction from the first K and last K shares is verified before writing
- While opening, the full key briefly exists in memory on that machine
- `--and-destroy-key` destroys only the share files used; the remaining shares are meaningless once the capsule is gone

## Time lock (drand / tlock)

"Cannot open before date X" cannot be built with a local date check — changing the clock, patching the code, or simply decrypting with plain `age` defeats it.
As long as the key is at hand, any check is decoration; instead, the key to open it must not exist anywhere before that date.

[drand](https://drand.love/) is a public randomness beacon jointly run by a dozen or so organisations (the League of Entropy: Cloudflare, universities, research institutes, …) that publishes a signature every 3 seconds.
The secret key is encrypted with [tlock](https://github.com/drand/tlock) (IBE on BLS12-381) so that only the signature of the round at the target time can decrypt it.
That signature is created only at that time by a threshold of the operators, so before the date the decryption key does not exist.

- The setup is "time lock **or** escape hatch": besides the time-lock key (`<container>.tlock`), the normal secret key or shares remain as an escape hatch
- The quicknet chain parameters (public key, genesis, period) are embedded, so locking works offline. Only opening contacts the drand HTTP mirrors (api.drand.sh / api2 / api3 / drand.cloudflare.com) in order
- The target round is the first one published at or after the requested time. The unlock time shown is computed from the age header stanza `-> tlock <round> <chainhash>`, not from comment lines
- If the local clock says it is too early, the network is not contacted. Moving the clock forward only skips this check; drand still refuses to return a future round's signature
- Computational time-lock puzzles (RSW) only guarantee a minimum amount of computation, not a calendar date, so they are not used

## Limitations

- **The writer can in theory compute the amount used**: to append, the program must know the next offset, which is sealed with a key derivable from the public key. Someone holding both the public key and the container could write code to learn the **number of used bytes** (never contents or file names). The CLI simply never exposes it; the container alone reveals nothing
- A "no space" error tells you that the file did not fit
- Overwriting cannot guarantee physical erasure on SSDs (wear leveling)
- Backups (Time Machine, cloud sync) of older versions can reveal where appends happened, and are not destroyed
- `--and-destroy-key` only affects files on the machine where it runs
- Original files remain unless `--delete-original` is used; editor autosaves and shell history are out of scope
- The time lock assumes drand still exists on that date; otherwise only the escape hatch can open the capsule
- A colluding threshold of drand operators could open early; whoever holds the escape hatch can open at any time
- No passphrase protection for the secret key. Side channels, memory dumps, etc. are out of scope

## Tests

```bash
make test                              # unit tests (includes live drand access; VAULT_OFFLINE=1 skips it)
make build && scripts/e2e.sh ./vault   # end-to-end CLI test (178 checks, ~1 min, needs drand)
```
