# Security Policy

Passback stores passwords and secrets, so we treat every security report as a
priority. Thank you for helping keep its users safe.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub:

**[Report a vulnerability](https://github.com/rezmoss/Passback/security/advisories/new)**

Include as much as you can:

- affected version or commit, platform and build features
- what an attacker can do, and what they need first (local access, a stolen vault file, a malicious sync server...)
- steps or a proof of concept
- any suggested fix

You can expect:

| Step | Target |
|---|---|
| Acknowledgement | within 3 business days |
| Initial assessment and severity | within 10 business days |
| Fix for critical/high issues | as fast as possible, normally within 30 days |
| Public advisory and credit | when the fix ships, or after 90 days, whichever is first, unless we agree otherwise |

We will keep you updated, credit you in the advisory (unless you prefer not), and
request a CVE for confirmed vulnerabilities.

## Supported versions

Passback is pre-1.0. Only the latest release and the `main` branch get security fixes.

## Scope

In scope: everything in this repository, including the cryptographic design, the
vault file format, storage, the binary, the fuzz targets, the formal models, and the
build and release pipeline (including reproducibility and signing).

Issues we especially want to hear about:

- recovering any secret, key or plaintext metadata without the unlock factors
- weakening the two-secret key derivation (attacking the password without the Secret Key)
- getting a device to accept data the vault owner didn't write: forged, swapped,
  dropped or rolled-back items or commits, forks, a tampered header or file
- ciphertexts accepted under the wrong key, purpose, vault, item or version
- panics, hangs or unbounded memory from crafted input
- secrets leaking to logs, errors, swap, core dumps or other processes
- networking code reaching the default build, or any unexpected network traffic
- release binaries that don't match the published source and checksums

Out of scope: attacks that need full control of an unlocked device while the vault is
open, social engineering, denial of service against infrastructure we don't run, and
findings in dependencies that are already public (report those upstream; tell us if
Passback is affected in a specific way).

## Safe harbor

Research done in good faith under this policy is authorized. We won't pursue legal
action for it, provided you only test against your own data and installations, don't
access or modify other people's data, don't degrade services for others, and give us
reasonable time to fix the issue before disclosure.

## Verifying what you run

See "Verifying a release" in the README: checksums, Sigstore signatures, build
provenance, reproducible Linux builds and `passback self-hash`.
