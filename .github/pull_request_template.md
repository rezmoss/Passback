## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`) and signed (GPG/SSH)
- [ ] `fmt`, `clippy -D warnings`, tests (debug and release), `cargo deny` and `check-no-network.sh` pass
- [ ] New parsers have a fuzz target and a robustness test; security properties have negative tests
- [ ] Pinned crypto vectors are unchanged (or a new suite and migration are included)
- [ ] Protocol or crypto changes: `formal/verify.sh` passes and the models are updated

## AI assistance

<!-- Which parts, if any, were AI-assisted? You must understand and be able to explain all of it. -->
