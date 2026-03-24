# modelledger-core

Rust implementation of the ModelLedger ML-SBOM specification.

## Status

**Current:** Python proof-of-concept (`modelledger_poc.py`) — fully working, 12 passing tests.
**In progress:** Rust library — architecture complete, implementation in progress.

## Python PoC

Run the proof-of-concept:

```bash
pip install cryptography
python3 modelledger_poc.py
```

Run the tests:

```bash
pip install pytest cryptography
python3 -m pytest modelledger_poc.py -v
```

Expected: `12 passed`

## Rust Library

```bash
cargo test
```

Primary crates: `ed25519-dalek 2.x`, `sha2`, `serde_json`, `jcs`.

## Why Both?

The Python PoC was written first to validate the protocol design before committing to a Rust implementation. The signing procedure, canonical JSON behaviour, and ML-SBOM format are all proven correct in Python. The Rust library provides the production-grade implementation for infrastructure tooling that requires performance and memory safety.
