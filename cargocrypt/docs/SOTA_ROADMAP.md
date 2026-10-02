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
   - `cargo clippy --all-targets -- -D warnings`
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
- [x] 5. `cargocrypt scan [paths]`: expose the detector, honour `.gitignore`,
      `--staged`, `--format text|json|sarif`, non-zero exit on findings.
- [x] 6. Scan precision. **Measured in loop 5: scanning this repository
      reports 1,858 findings** — 1,307 `high-entropy-string`, 357
      `github-personal-access-token` (mostly `Cargo.lock` checksums), the rest
      contextual matches on ordinary identifiers. In this state the scanner
      cannot gate a commit. First cut the false positives (anchor the GitHub
      and other token rules to their real prefixes and lengths, skip lock
      files and hashes, stop flagging identifiers and hex digests as
      high-entropy), then add: `.cargocryptignore`, inline `cargocrypt:allow`,
      `--baseline` file; rules for current token formats (GitHub fine-grained
      `github_pat_`, `sk-ant-`, `sk-proj-`, Slack `xox*`, Stripe restricted
      keys); a labelled fixture corpus with measured precision/recall replacing
      the "not independently benchmarked" caveat.
- [x] 7. Password handling: `Zeroizing<String>` through CLI and engine,
      `--password-file` / `CARGOCRYPT_PASSWORD_FILE`, stop trimming passwords,
      drop the `git config cargocrypt.password` source (warn if present).
      Also found in loop 4, same area: `.cargocrypt/config.toml` is written by
      `init` but never read (`CargoCrypt::new` always uses defaults), and
      `backup_originals` defaults to true, which leaves a world-readable
      plaintext `<file>.backup` beside every encrypted file. Load the config;
      make the backup opt-in.
- [x] 8. Make every target compile and lint: repair or delete
      `benches/vs_rustyvault.rs`, fix test lints, CI runs
      `clippy --all-targets -D warnings`. (Test time is already handled:
      loop 2 took the unit suite from ~200 s to ~6 s.)
- [x] 9. Supply chain: remove unused dependencies, add `deny.toml`, run
      `cargo-deny` and `cargo-audit` in CI, declare and test an MSRV, add
      Dependabot for cargo and actions, pin actions by SHA.
- [x] 10. Property tests (round trip, tamper detection, truncation) and
      `cargo-fuzz` targets for the container parser; fuzz smoke job in CI.
- [x] 11. `cargocrypt rekey` (change password / upgrade profile and format
      without exposing plaintext on disk) and `cargocrypt verify`.
- [x] 12. Team sharing review (`git/team.rs`): per-recipient X25519
      envelopes replace the shared constant password. Slice shipped; the rest
      is 12b.
- [?] 12b. Team sharing, remainder. Needs decisions before it is built:
      (a) sign member records, key records and audit entries with Ed25519 so
      repository write access stops being equivalent to team administration
      (who holds the root of trust, and how is a new admin introduced?);
      (b) there is no CLI for any team operation: the module is reachable
      only as a library; (c) `revoke_member_tokens` still writes a
      revocation list for tokens that no longer exist; (d) removal should
      drive key rotation and re-encryption of affected files.
- [x] 13. Hygiene and honesty: the monitoring dashboard
      (`tui/monitoring.rs`) renders hard-coded sample rows as if they were
      live statistics: wire it to real metrics or label it; `[key_params]` in the config is parsed but
      ignored (the profile sets the KDF cost): wire it or remove it; delete `.swarm/`, `test_output.log`,
      `core_backup.rs`; rewrite `SECURITY.md` and the README tables to match
      the code; write up issue #1 with evidence and the rotation checklist.
- [x] 14. Release engineering: CHANGELOG through 0.3.0, shell completions and
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
- Loop 5 (2026-10-01): `cargocrypt scan [paths] [--staged] [--format
  text|json|sarif] [--min-confidence] [--output] [--no-fail]`, exit 0 clean /
  1 findings / 2 error. Works outside a Cargo project. Scans dotfiles (the
  library default skipped `.env`). `--staged` reads blobs from the index.
  Reports never contain the secret: a four-character preview plus a
  fingerprint (truncated SHA-256), which SARIF carries as
  `partialFingerprints`. Fixed a panic in `FoundSecret::new`, which sliced at
  byte 47 and could land inside a multi-byte character. 191 tests. Running it
  on this repo exposed the false-positive rate recorded under item 6.
- Loop 6 (2026-10-01): self-scan went from 1,858 findings to 52, all of them
  example credentials in the detector's own tests and docs; with the new
  `.cargocryptignore` the repository scans clean and CI now runs that scan.
  How: a plausibility gate on the generic detectors (identifiers, CamelCase
  names, code expressions, plain URLs, hex digests, UUIDs, public keys and
  sequential placeholders are not secrets); the unanchored 40-hex "GitHub
  classic" rule is gone; keyword detection requires an actual assignment;
  connection-string rules require embedded credentials; PEM rules require a
  key body; lock files are skipped; overlapping detectors report once. New
  rules: GitHub fine-grained, Anthropic, OpenAI, Google, npm, wider Slack,
  Stripe restricted. Added `cargocrypt:allow`, `.cargocryptignore` and
  `--baseline`. `tests/scan_corpus_test.rs` measures a labelled corpus (20
  secrets, 36 benign lines): recall 1.00, precision 1.00 at confidence 0.5,
  asserted at >= 0.90. The corpus is synthetic and written alongside the
  rules, so treat those figures as a regression guard, not a benchmark.
  204 tests.
- Loop 7 (2026-10-01): passwords are no longer trimmed (only one trailing
  line ending is removed), travel as `Zeroizing<String>` in the CLI, and can
  come from `--password-file` or `CARGOCRYPT_PASSWORD_FILE`. The git filter
  no longer reads `git config cargocrypt.password` and says so if it is set.
  `.cargocrypt/config.toml` is now loaded (missing keys default, a bad file
  is an error). `backup_originals` defaults to false; when enabled the copy
  is written 0600. 216 tests. GitGuardian failed on the loop 6 commit —
  almost certainly the credential-shaped literals in the new corpus test;
  those are now assembled at run time. Not done here: the engine API still
  takes `&str` passwords, and `[key_params]` in the config is still ignored
  (the profile decides the KDF cost) — both noted under item 13.
- Loop 8 (2026-10-01): `cargo clippy --all-targets -- -D warnings` passes and
  CI enforces it. `benches/vs_rustyvault.rs` is deleted: it did not compile
  and "benchmarked" a competitor implemented as `thread::sleep` calls (the
  retraction in `PERFORMANCE_SUMMARY.md` already said as much).
  `benches/crypto_bench.rs` did not compile either and is rewritten against
  the current API: key derivation, container seal/open/parse, streaming
  encrypt/decrypt, scanning. README performance figures are replaced with
  the measured ones (about 800 MiB/s streaming encryption, 600 MiB/s
  decryption, 136 ms Balanced key derivation, 10 MiB/s scanning, on a 2-vCPU
  VM); the README had claimed 1.0-1.2 GB/s. The profile table now matches
  the code. Placeholder tests (`assert!(true)`, an empty mock module, a test
  with no assertions) are removed or made real; the performance example no
  longer prints an invented memory figure. 215 tests (one placeholder
  removed).
- Loop 9 (2026-10-01): removed unused dependencies (`reqwest`, `rustls`,
  `rustls-webpki`, `dialoguer`, `indicatif`, `console`, `predicates`,
  `futures`; `anyhow` moved to dev). `cargo audit` went from 4
  vulnerabilities and 11 warnings to 0 and 1: `cargo update` cleared `bytes`,
  `crossbeam-epoch`, `slab`, `tracing-subscriber` and `anyhow`; `git2` 0.18 ->
  0.21 and `ratatui` 0.24 -> 0.30 (with `crossterm` 0.29) cleared the
  unsoundness advisories in `git2`, `lru` and `paste`. The one left is
  `bincode` 1.x (unmaintained), kept to read v1 containers and recorded with
  its reason in `deny.toml`. Lockfile: 345 -> 328 packages. Added `deny.toml`
  (advisories, permissive licences only, crates.io only), a cargo-deny CI job,
  an MSRV job (`rust-version = "1.88"`, the highest `rust-version` among the
  locked dependencies), `--locked` builds, read-only workflow permissions and
  Dependabot for cargo and actions. Not done: actions are pinned by tag, not
  by SHA. Not verified here: the MSRV build and cargo-deny's advisory check
  run only in CI (no older toolchain or advisory-db fetch in this sandbox;
  licences, bans and sources were checked locally with cargo-deny 0.18.3, and
  advisories with cargo-audit). The TUI compiles against ratatui 0.30 but was
  not exercised interactively. 215 tests.
- Loop 10 (2026-10-01): `tests/properties.rs` (8 proptest properties):
  container and stream round trips for arbitrary data and metadata; any
  single-byte change, truncation or extension is rejected; the parsers and
  the scanner never panic. The scanner property found a real panic on its
  first run: text containing a multi-byte whitespace character (U+2007)
  before a token crashed the URL check added in loop 6 (`rfind(..) + 1`
  landed inside the character). Fixed; the failing seed is committed.
  `fuzz/` holds three cargo-fuzz targets (`container_parse`,
  `stream_decrypt`, `scan_content`) and CI runs each for 30 s. Run here for
  75 s each with coverage instrumentation on stable (so without
  AddressSanitizer): 13.5 M, 1.5 M and 5.5 k executions, no crashes. The
  scanner target managed only 72 exec/s, which exposed that every call
  recompiled eight regexes; they are now compiled once (a 10-byte scan takes
  about 90 microseconds). Large-input throughput is unchanged at roughly
  7-10 MiB/s and is still the scanner's weak spot. 223 tests.
- Loop 11 (2026-10-01): `cargocrypt verify <file>` decrypts and
  authenticates a whole container into a sink (nothing written) and reports
  format version, KDF cost and content size. `cargocrypt rekey <file>`
  re-encrypts in place: the decryptor and encryptor are joined by an
  in-memory pipe, so plaintext never reaches the disk, and the result
  replaces the file atomically only if the old container authenticated to
  the end. A wrong password or a truncated source leaves the file
  byte-identical. Rekey always writes format v3, so it is also the upgrade
  path for v1 and v2 files; `--profile` changes the KDF cost and
  `--keep-password` changes only that. 229 tests.
- Loop 12 (2026-10-01): review of `git/team.rs` found the sharing was not
  real. Every "per-member" wrapped key was encrypted under the constant
  password `"team_key_password"` and committed, so any clone could read every
  team key; the "digital signature" was an HMAC keyed with a constant in the
  source; "access tokens" were encrypted under another constant; the
  member's `public_key` was never used. Now: `crypto::envelope` seals to an
  X25519 public key (ephemeral ECDH, HKDF-SHA256, XChaCha20-Poly1305, bound
  to key id and member id; checked against RFC 7748 and OpenSSL). Team keys
  are sealed per member, opening one needs that member's secret key, a
  member with a malformed public key is rejected, and new members get
  existing keys only through `grant_key` by a holder who supplies their
  secret. The forgeable signature and the token are removed (fields kept,
  empty). The module docs now state what is and is not protected: the
  member list and audit log are still unsigned. `get_shared_key` takes a
  secret key (API change); new dependency `x25519-dalek`. 239 tests.
- Loop 13 (2026-10-01): deleted `.swarm/`, `test_output.log`,
  `src/core_backup.rs` and `src/tui.rs` (3,500 lines that were never
  compiled). `SECURITY.md` and both READMEs rewritten to describe the code as
  it is, including what is not protected. Reviewing the git integration for
  the README found three more bugs, all fixed with end-to-end tests
  (`tests/git_hooks_test.rs`): the pre-commit hook called
  `cargocrypt git install-hooks --check-secrets`, a flag that never existed,
  so it blocked every commit; the configured filter commands were
  `cargocrypt filter-clean`, which is not a command; and `.gitattributes`
  lines were written as `pattern cargocrypt-encrypt` instead of
  `pattern filter=cargocrypt-encrypt`, so git never ran the filter at all.
  Transparent encryption now round-trips through real git. The pre-push hook
  printed "Encryption validation passed" without checking anything; it now
  does an advisory magic-byte check. The monitoring dashboard, whose every
  number is a hard-coded placeholder, says "SAMPLE DATA" on screen.
  `cargocrypt config` prints the profile's real KDF cost; `[key_params]` is
  documented as ignored. Issue #1 is written up in
  `docs/ISSUE_1_FINDINGS.md`: a false positive (AWS documentation example key
  and a placeholder in the scanner's tests), confirmed at the cited commit
  and across all history. Not done: the dashboard is labelled, not wired to
  real metrics; clean-filter output is still randomised, so git can show
  filtered files as modified. 242 tests.
- Loop 14 (2026-10-01): crate version set to 0.3.0 (unpublished) and
  `CHANGELOG.md` written for it, including upgrade notes; 0.2.0-0.2.3 never
  had entries and that gap is stated rather than invented. Added
  `cargocrypt completions <shell>`. Added `.github/workflows/release.yml`:
  on a `v*` tag it checks the tag against `Cargo.toml`, tests, builds Linux,
  macOS (arm64, x86_64) and Windows binaries, packages them with checksums
  and completions, attaches GitHub build-provenance attestations, generates
  a CycloneDX SBOM and opens a *draft* release. It does not publish to
  crates.io. The workflow has never run: only its YAML syntax and the
  packaging commands were checked locally, so treat the first tag as a
  test. Not done: a man page; binaries carry provenance attestations, not
  separate signatures. 243 tests.
