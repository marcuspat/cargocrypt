# CargoCrypt security notes

This describes what the code does today. It replaces an earlier document that
listed features which were never implemented (AES-256-GCM, timing jitter,
cache-line-aligned buffers, "post-quantum" claims).

CargoCrypt has had no independent security audit. Treat it accordingly.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository. Please do not file
a public issue for anything exploitable.

## What is protected

**File and secret contents at rest.** A file encrypted with a strong
passphrase is confidential and tamper-evident against someone who obtains the
ciphertext.

| | |
|---|---|
| Cipher | XChaCha20-Poly1305 (192-bit random nonce) |
| Key derivation | Argon2id v1.3, cost set by the profile and recorded in the file |
| Files | Streamed in 64 KiB chunks with the STREAM construction; reordering and truncation fail authentication |
| Headers and metadata | Authenticated as associated data |
| Output | Written to a temporary file with mode `0600`, synced, then renamed; removed on failure |
| Team keys | Sealed per member: ephemeral X25519, HKDF-SHA256, XChaCha20-Poly1305 |

Profiles: Fast 4 MiB / 1 pass / 1 lane (development only), Balanced
64 MiB / 3 / 4 (default), Secure 256 MiB / 5 / 8, Paranoid 1 GiB / 10 / 16.

Container formats, magic `CCRY`: version 3 (streaming files), version 2
(single-shot secrets). Version 1 files written by 0.2.3 and earlier are still
read; `cargocrypt rekey` converts them.

Implementations come from the RustCrypto crates (`chacha20poly1305`, `argon2`),
`x25519-dalek` and `ring`. The test suite pins them to published vectors:
RFC 8439, the XChaCha draft, RFC 7748, and an Argon2id value computed with the
reference C implementation.

## What is not protected

- **A weak passphrase.** Argon2id slows guessing; it does not rescue a short
  or reused password. The Fast profile is cheap to attack by design.
- **A compromised machine.** Malware or another user with access to your
  account can read plaintext, passwords and memory.
- **File names, sizes and timing.** An encrypted file's name, its approximate
  length and when it changed are visible.
- **The plaintext original.** `cargocrypt encrypt` writes an encrypted copy
  and leaves the original in place. Remove it yourself; on SSDs and
  copy-on-write filesystems "secure deletion" is not something a tool can
  promise. A secret that has already been committed to git must be rotated,
  not just encrypted.
- **Memory.** Keys and passwords held by CargoCrypt are zeroized on drop where
  the code owns them, but the library API still accepts passwords as `&str`,
  the allocator may leave copies, and nothing prevents swapping or core dumps.
- **Side channels.** Constant-time behaviour is whatever the underlying
  crates provide. CargoCrypt adds no timing jitter or cache countermeasures.
- **Team membership.** Member records, roles and the audit log are plain JSON
  in the repository and are not signed. Anyone who can push can add a member
  or change a role, so repository write access is equivalent to team
  administration. Removing a member does not revoke a key they have already
  read: rotate it. There is no command-line interface for team operations.
- **Post-quantum attackers.** X25519 key agreement is not post-quantum
  secure. Symmetric encryption with a 256-bit key is believed to be.

## Passwords

- Interactive prompt, `--password-file`, `CARGOCRYPT_PASSWORD_FILE`, or the
  first line of stdin with `--password-stdin`. Only one trailing newline is
  removed; other whitespace is part of the password.
- The git filters also accept `CARGOCRYPT_PASSWORD`. An environment variable
  is visible to other processes of the same user; prefer the file form.
- `git config cargocrypt.password` is no longer read. It stored the password
  in clear text in `.git/config`.
- Minimum length is 8 characters. That is a floor, not a recommendation: use
  a long passphrase.

## Secret scanning

`cargocrypt scan` is a heuristic. It will miss secrets it has no rule for and
will sometimes flag things that are not secrets. A clean scan is not proof
that a repository holds no credentials. Reports never contain the secret
itself: findings carry a four-character preview and a fingerprint.

## Known limitations of this release

- The monitoring dashboard (`cargocrypt monitor dashboard`) displays sample
  data and is not connected to live metrics.
- `monitor metrics`, `alerts`, `export` and `health` report on the current
  process only, which for a one-shot command is empty.
- The terminal UI was upgraded to a new `ratatui` release without interactive
  testing.
- `bincode` 1.x, used only to read version 1 containers, is unmaintained.
- GitHub Actions in CI are pinned by tag rather than by commit SHA.
