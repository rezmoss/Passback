# Passback

Open-source password and secrets manager for people and AI agents. One binary for
every platform that works as a CLI, as a local service with a web UI, or as a
self-hosted sync server.

> Status: early development. The cryptographic core, vault format, storage and
> release pipeline are in place; vault commands (add, get, edit, generate, import)
> come next.

## Why I'm building this

For years I trusted LastPass with my passwords. Then LastPass was breached, and
attackers walked away with copies of customers' encrypted vaults. I moved to
1Password, which was the best option at the time. Recently I read that 1Password had
its own security incident. They said our passwords were not compromised, and that
may well be true. But I had seen enough.

Passwords and secrets are not like other data. When they leak, the damage is
immediate: your email, your bank, your servers, your company. And you can't undo
it. You can rotate a password, but you can't un-leak it, and you can't know what
someone already did with it. An apology email from a vendor doesn't fix that.

The common problem is the model. A large password company keeps millions of vaults
in one place, which makes it one of the most valuable targets on the internet.
However good their engineers are, they are defending a prize that attackers will
keep coming back for. And their users have to take the vendor's word for how well
it is protected.

I want the opposite:

- **My vault, under my control.** It lives on my devices, or on a server I run. No
  central company sits on millions of vaults, so there is no single honeypot worth
  breaking into.
- **Nothing to take on trust.** It's 100% open source, with a public design,
  reproducible builds and signed releases, so anyone can check that the binary I
  run is the code I read.
- **Security I can see.** Post-quantum encryption, tamper-evident vaults that detect a
  malicious server, and a full audit of every access, for me and for the AI agents
  I work with.
- **Works everywhere I work.** One binary on Linux, macOS and Windows, used from the
  terminal, a local web UI, or a self-hosted server.
- **Built in the open, with others.** I want the community to review it, break it
  and make it better.

A note on how it's made: I'm a software developer, and I'm building Passback
together with AI coding agents (Claude, Codex, Gemini). That is exactly why nothing
here asks for blind trust. Passback invents no cryptography: it uses only standard,
published algorithms from established open-source libraries. Every construction is
pinned to published test vectors, the protocol is checked with formal models,
parsers are fuzzed, and everything is open for anyone to review. Cryptographers and
Rust developers: please try to break it. If you find a problem,
[report it](SECURITY.md).

Passback is not audited yet. Until it is, treat it as what it is: early,
open, and getting better in public.

## Why not Bitwarden or KeePassXC?

If you need a password manager today, use one of them. KeePassXC is mature and
local-first; Bitwarden is polished, audited and easy to share with. Passback is
early and not audited yet.

Passback is for a narrower threat model: you shouldn't have to trust whatever
stores your vault. Every change is a signed, hash-chained commit with a Merkle
root, so a sync server, shared folder or backup disk can't swap, drop or roll back
items without your devices noticing. Around that: one self-contained binary instead
of a server stack, post-quantum encryption for sharing, and (coming in a later
release) a way for scripts and AI agents to use a secret without ever seeing it.

## Design

- **Zero-knowledge:** everything, including item names, URLs and tags, is encrypted on your device.
- **Two-secret key derivation:** Argon2id(password) combined with a 128-bit Secret Key, so stolen vault data can't be cracked by guessing passwords.
- **Post-quantum from day one:** X-Wing (ML-KEM-768 + X25519) for sharing, and Ed25519 + ML-DSA-65 signatures where both must verify.
- **Tamper-evident vaults:** every change is a signed, hash-chained commit with a Merkle root. A sync server can't alter, drop, hide or roll back items without detection.
- **Committing AEAD:** XChaCha20-Poly1305 with key commitment; every ciphertext is bound to its purpose, vault, item and version.
- **Hardened process:** no core dumps, anti-debugger, locked and guarded secret memory, self-tests at every start.
- **No network unless you enable it:** the default binary links no networking code, and there is no telemetry.
- **Verifiable releases:** reproducible builds, Sigstore signatures, SLSA provenance and an SBOM.

## Build

```sh
cargo build --release -p passback
./target/release/passback security
```

## Commands

| Command | Purpose |
|---|---|
| `passback version` | Version, target, compiled-in features |
| `passback selftest` | Run the cryptographic self-tests |
| `passback security` | Hardening, network and crypto posture |
| `passback self-hash` | SHA-256 of the executable, for checking against release checksums |
| `passback bench-kdf` | Calibrate Argon2id for this machine |

Add `--json` to any command for machine-readable output.

## Workspace

| Crate | Purpose |
|---|---|
| `passback-crypto` | KDF, unlock keys, committing AEAD, X-Wing, composite signatures, key hierarchy, self-tests |
| `passback-format` | The `.pbv` vault file: account header, records, signed commits, Merkle state, rollback/fork checkpoints |
| `passback-vault` | The unlocked vault: one `.pbv` file, device state and rollback checkpoints |
| `passback-harden` | Process hardening and locked secret memory |
| `passback` | The binary |

## Verifying a release

Each release ships `SHA256SUMS`, a Sigstore bundle for it, GitHub build provenance
and a CycloneDX SBOM.

```sh
sha256sum --ignore-missing -c SHA256SUMS
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/rezmoss/Passback/.github/workflows/release.yml@refs/tags/v'
gh attestation verify passback-x86_64-unknown-linux-musl --repo rezmoss/Passback
```

Linux binaries are reproducible: check out the tag and run
`TARGET=x86_64-unknown-linux-musl USE_ZIG=true ./scripts/build-release.sh`; the
result must match `SHA256SUMS`. `passback self-hash` prints the hash of the
installed binary.

## Assurance

`cargo test` runs published known-answer vectors (RFC 9106, RFC 5869, RFC 8032,
XChaCha20-Poly1305, X-Wing), pinned vectors, property and tamper tests.
`fuzz/` holds libFuzzer targets for every decoder. `formal/verify.sh` runs ProVerif
models of two-secret unlock, hybrid sharing and composite signatures, each with a
broken twin that must show an attack.

## Contributing

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a
`Signed-off-by` line (`git commit -s`).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

Passback is dual-licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
