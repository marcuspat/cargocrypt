# CargoCrypt SOTA roadmap

Working branch: `claude/sota-loop`. One item per loop, in order.

## Loop contract

1. `cd cargocrypt/` (the crate lives one level below the repo root). If the
   checkout is gone, re-clone `marcuspat/cargocrypt` and check out
   `claude/sota-loop`.
2. Take the first unchecked item below. If it is too big for one loop, ship a
   coherent slice, split the remainder into a new item directly beneath it.
3. Every change ships with tests that fail without it.
4. Gates, judged by exit code, all must pass before committing:
   - `cargo fmt --check`
   - `cargo clippy -- -D warnings` (`--all-targets` once item 8 lands)
   - `cargo test`
5. Tick the item, add a line under "Log", commit, `git fetch origin main`,
   push, update the draft PR description.
6. Never merge to `main`. No paid API calls. No secrets in the repo. No
   `cargo publish`.
7. Anything that needs Marcus's decision is marked `[?]` and skipped.

## Baseline (2026-10-01, commit 4d33af4)

- 147 tests pass (135 unit, 5 integration, 7 doc); unit tests take ~200 s.
- `cargo clippy -- -D warnings` and `cargo fmt --check` pass.
- `cargo clippy --all-targets` does not compile: `benches/vs_rustyvault.rs`
  has 19 hard errors and the lib tests carry 12 lint errors. CI does not check
  those targets.

## Findings from the audit

Ordered by how badly they undercut what the README promises.

- **Git filters encrypted under a public constant.** With no password
  configured, `git filter-clean` fell back to the literal `"default-password"`.
  (Fixed, loop 1.)
- **Git filters never round-tripped.** Log lines were written to stdout, ahead
  of the ciphertext, so the smudge filter could not parse its own output and
  passed the corrupted blob through. (Fixed, loop 1.)
- **Security profiles do nothing.** `CryptoEngine::derive_key_with_profile`
  runs Argon2 with the profile's parameters, discards the result, then derives
  again with the hard-coded defaults. Fast, Secure and Paranoid all produce the
  Balanced key, and every operation pays for two KDF runs.
- **The file format cannot evolve.** A `.enc` file is a bare `bincode` struct:
  no magic bytes, no version, no KDF parameters, and the metadata is neither
  encrypted nor authenticated. Fixing the profile bug without a versioned
  header would make existing files undecryptable.
- **Random 96-bit nonces** with ChaCha20-Poly1305, and whole files buffered in
  memory. Current practice is XChaCha20 (192-bit nonce) and a chunked STREAM
  construction with a truncation-proof final chunk.
- **Secret detection has no CLI.** `detection/` is 4,400 lines and the only
  way to reach it is the git hook. No `scan`, no SARIF, no baseline.
- **Passwords are plain `String`s** end to end, `--password-stdin` trims
  whitespace out of the password, and the filter reads a password from
  `git config` (stored in clear in `.git/config`).
- **Unused network stack.** `reqwest`, `rustls`, `rustls-webpki`, `dialoguer`,
  `indicatif` and `console` are dependencies with no call sites. No
  `cargo-audit` / `cargo-deny` in CI.
- **Docs overstate.** `SECURITY.md` describes AES-256-GCM support,
  "post-quantum secure", cache-line alignment and timing jitter that the code
  does not implement; the README profile table disagrees with the code.
- **Repo hygiene.** `.swarm/memory.db*`, `test_output.log` and the dead
  `src/core_backup.rs` are committed. Issue #1 (exposed AWS key / GitHub PAT)
  is still open; the matches in the tree today are documentation example
  values used as scanner fixtures.

## Items

- [x] 1. Roadmap; git filters fail closed (no default password, no ciphertext
      pass-through on auth failure); logs to stderr.
- [x] 2. Versioned container format v2: magic + version + algorithm id + Argon2
      parameters in a header that is bound as AEAD associated data. Make the
      performance profile actually drive the KDF (one derivation, not two).
      v1 files stay readable. Tests: each profile yields a different key;
      header tampering fails authentication; v1 fixture still decrypts.
- [x] 3. XChaCha20-Poly1305 for v2 containers (24-byte nonce). Known-answer
      tests against the draft-irtf-cfrg-xchacha vector and RFC 8439.
- [x] 4. Streaming file encryption: 64 KiB chunked STREAM construction,
      constant memory, final-chunk flag so truncation is detected; atomic
      output (temp file, fsync, rename) with 0600 permissions.
- [ ] 5. `cargocrypt scan [paths]`: expose the detector, honour `.gitignore`,
      `--staged`, `--format text|json|sarif`, non-zero exit on findings.
- [ ] 6. Scan precision: `.cargocryptignore`, inline `cargocrypt:allow`,
      `--baseline` file; rules for current token formats (GitHub fine-grained
      `github_pat_`, `sk-ant-`, `sk-proj-`, Slack `xox*`, Stripe restricted
      keys); a labelled fixture corpus with measured precision/recall replacing
      the "not independently benchmarked" caveat.
- [ ] 7. Password handling: `Zeroizing<String>` through CLI and engine,
      `--password-file` / `CARGOCRYPT_PASSWORD_FILE`, stop trimming passwords,
      drop the `git config cargocrypt.password` source (warn if present).
      Also found in loop 4, same area: `.cargocrypt/config.toml` is written by
      `init` but never read (`CargoCrypt::new` always uses defaults), and
      `backup_originals` defaults to true, which leaves a world-readable
      plaintext `<file>.backup` beside every encrypted file. Load the config;
      make the backup opt-in.
- [ ] 8. Make every target compile and lint: repair or delete
      `benches/vs_rustyvault.rs`, fix test lints, CI runs
      `clippy --all-targets -D warnings`. (Test time is already handled:
      loop 2 took the unit suite from ~200 s to ~6 s.)
- [ ] 9. Supply chain: remove unused dependencies, add `deny.toml`, run
      `cargo-deny` and `cargo-audit` in CI, declare and test an MSRV, add
      Dependabot for cargo and actions, pin actions by SHA.
- [ ] 10. Property tests (round trip, tamper detection, truncation) and
      `cargo-fuzz` targets for the container parser; fuzz smoke job in CI.
- [ ] 11. `cargocrypt rekey` (change password / upgrade profile and format
      without exposing plaintext on disk) and `cargocrypt verify`.
- [ ] 12. Team sharing review (`git/team.rs`, 1,500 lines): threat-model it,
      then move to per-recipient X25519 envelopes so adding or removing a
      member does not mean re-sharing one password.
- [ ] 13. Hygiene and honesty: delete `.swarm/`, `test_output.log`,
      `core_backup.rs`; rewrite `SECURITY.md` and the README tables to match
      the code; write up issue #1 with evidence and the rotation checklist.
- [ ] 14. Release engineering: CHANGELOG through 0.3.0, shell completions and
      man page, release workflow building signed binaries with an SBOM and
      build provenance. No publish.
- [ ] 15. Wrap-up: all gates, CI green on the PR, final status block here,
      PR description rewritten as a full summary.

## Log

- Loop 1 (2026-10-01): removed the `"default-password"` fallback, smudge now
  errors on authentication failure, tracing writes to stderr. New
  `tests/git_filter_test.rs` (2 tests) covers both and is the first test to
  exercise the filters end to end.
- Loop 2 (2026-10-01): container format v2 (`CCRY` magic, version, AEAD and
  KDF ids, Argon2 parameters, salt, nonce, metadata) with the whole header
  bound as associated data. The performance profile now drives the KDF, with
  one derivation instead of two; decryption reads the parameters from the
  container. Parameters from an untrusted header are bounded (2 GiB, 64
  passes, 64 lanes). v1 containers still decrypt, checked against a fixture
  written by the 0.2.3 binary. `EncryptedSecret::set_metadata` was removed:
  it had no callers and metadata is now authenticated. All `bincode` call
  sites go through `to_bytes` / `from_bytes`. Argon2 and the cipher crates are
  optimised in dev builds: unit tests 203 s -> 6 s. 157 tests.
- Loop 3 (2026-10-01): v2 containers now use XChaCha20-Poly1305 with a
  24-byte random nonce (AEAD id 2); the 96-bit construction is kept only to
  read v1. The v2 layout from loop 2 never shipped, so id 1 is simply not a
  valid v2 algorithm. Known-answer tests: RFC 8439 2.8.2, the XChaCha draft
  A.3.1 vector, and an Argon2id output computed with the reference C
  implementation. `EncryptedSecret::nonce()` now returns `&[u8]`. 160 tests.
- Loop 4 (2026-10-01): `encrypt_file` writes a streaming container (format
  version 3): 64 KiB chunks, STREAM construction over XChaCha20-Poly1305 via
  the `aead` crate's `stream` module, header bound to every chunk, final-chunk
  flag so truncation at any length fails. Output goes through a new
  `AtomicFile` (random sibling temp, mode 0600, fsync, rename; removed on
  failure), so a failed decryption leaves nothing on disk. `decrypt_file`
  reads v3, v2 and v1. The builder ignored `config.performance_profile`; it
  now reaches the engine and the file header. Measured: 300 MB file, 80 MB
  peak RSS on decrypt (64 MiB of that is Argon2). Removed a working-directory
  race between two existing integration tests. 176 tests.
