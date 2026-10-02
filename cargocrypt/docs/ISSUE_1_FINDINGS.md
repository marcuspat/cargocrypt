# Issue #1: "Exposed API key(s) detected"

**Conclusion: false positive. No credential needs to be revoked.**

Issue #1 was opened by an automated scanner on 2026-03-14 and points at
`cargocrypt/src/detection/patterns.rs` at commit
`0896b4ddf82553a100dd01960841795cf1801fb4`, reporting an AWS access key and a
classic GitHub personal access token.

## What is in that file at that commit

Checked on 2026-10-01 by fetching the commit and reading the file:

| Line | Content | What it is |
|---|---|---|
| 353 | `r"(?i)(AKIA[0-9A-Z]{16})"` | The detection rule itself: a regular expression |
| 389 | `r"(?i)gh[pousr]_[A-Za-z0-9_]{36,255}"` | The detection rule itself |
| 605 | `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` | Unit-test input. This is the example key from AWS's own documentation |
| 615 | `GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678` | Unit-test input. A counting placeholder; real tokens of this type have 36 characters after the prefix, this has 40 |

The file is the secret scanner's rule set and its tests. The scanner that
opened the issue matched the fixtures the detector is tested against.

## The whole history

Every commit reachable from `main` (105 at the time) and from the
`claude/sota-loop` branch was searched for strings shaped like AWS access
keys or GitHub tokens (`AKIA` + 16 characters, `gh[pousr]_` + 36 or more).
The distinct values found, in total:

- `AKIAIOSFODNN7EXAMPLE` — AWS documentation example
- `AKIAI44QH8DHBEXAMPLE` — AWS documentation example
- `ghp_1234567890abcdef1234567890abcdef12345678` — placeholder

Other token shapes in history are likewise fixtures: a Stripe-style
`sk_live_` key made of `abcdef1234567890`, and PEM header lines with no key
material after them.

Not covered by this check: branches or forks that are not in this repository,
and credential types the search did not look for. If you know a real key was
ever committed, rotate it regardless of what is written here.

## Suggested resolution

Close issue #1 as a false positive, linking this file.

## If a real credential is ever committed

1. Revoke or rotate it at the provider first. Removing it from git does not
   un-leak it.
2. Check the provider's access logs for use you do not recognise.
3. Remove it from the working tree and commit.
4. Rewriting history (`git filter-repo`) is optional and disruptive; the
   credential is already dead after step 1.
5. Add a `cargocrypt scan --staged` pre-commit hook so the next one is caught
   before it is committed.
