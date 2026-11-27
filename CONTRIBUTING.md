# Contributing to Passback

Thanks for helping. Passback guards people's passwords and secrets, so the bar for
changes is high, but the process is simple.

## Before you start

- **Security issues:** never open a public issue or PR. Use
  [private reporting](https://github.com/rezmoss/Passback/security/advisories/new)
  (see [SECURITY.md](SECURITY.md)).
- **Bigger changes** (new features, crypto, format or protocol changes): open an issue
  first so we can agree on the design before you write code.
- Small fixes, tests, docs and typos: just send a PR.

## Setup

Install Rust with [rustup](https://rustup.rs); `rust-toolchain.toml` selects the right
version. Then:

```sh
cargo build --workspace
cargo test --workspace
```

## Before opening a PR

All of these must pass (CI runs them too):

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace && cargo test --workspace --release
cargo deny check advisories bans licenses sources
./scripts/check-no-network.sh
./formal/verify.sh            # if you touched protocol or crypto code (needs Docker)
```

## Rules for security-sensitive code

- **No new cryptography.** Use the existing constructions in `passback-crypto`. New
  primitives come only from established, audited Rust crates, and need known-answer
  tests from a published source.
- Every encryption goes through `aead::seal`/`open` with a fixed purpose label and
  associated data containing every id the object belongs to.
- Anything signed or hashed uses the canonical `wire` encoding, never a general
  serializer.
- Pinned test vectors (`crates/passback-crypto/tests/v1_vectors.rs`) must never change.
  If your change alters them, it needs a new crypto suite and a migration.
- Secrets stay in zeroizing types; never log them or put them in error messages.
- No `unsafe` outside `passback-harden`, and every `unsafe` block there needs a
  `// SAFETY:` comment.
- Every new parser of untrusted input gets a fuzz target in `fuzz/` and a robustness test.
- Every security property gets a negative test (wrong key, tampered data, rollback...).
- The default build must not link networking code.

## AI-assisted contributions

AI tools are welcome. Passback itself is built with them. But you are the author:

- Say in the PR description which parts were AI-assisted.
- Understand every line you submit, and be able to explain it in review.
- Never submit generated tests that just mirror the implementation; tests must check
  the behaviour that matters.

Every change, human or AI, gets human review before it is merged.

## Sign your work (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org). By
adding a `Signed-off-by` line to each commit, you certify that you wrote the change
or otherwise have the right to submit it under the project's license:

```sh
git commit -s -m "fix: reject truncated sealed boxes"
```

This adds `Signed-off-by: Your Name <you@example.com>` using your git name and email.
A CI check rejects PR commits without it. Signed commits (GPG/SSH) are also required on
`main`.

## License

Unless you explicitly state otherwise, any contribution you intentionally submit for
inclusion in Passback, as defined in the Apache-2.0 license, is dual-licensed as
[Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT), without any additional terms or
conditions.
