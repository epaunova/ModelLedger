# ModelLedger

**Open Standard for Verifiable ML Model Bills of Materials**

ModelLedger defines a cryptographic provenance standard for machine learning models. A model publisher signs an ML-SBOM document recording all components that entered the model — datasets, base weights, fine-tuning corpora, and software libraries. Any researcher, auditor, or downstream user can verify the full component chain without trusting any intermediary.

This repository contains:

- `modelledger-spec/` — the ML-SBOM format specification
- `modelledger-core/` — reference implementation in Rust
- `modelledger-py/` — Python proof-of-concept and bindings (PyO3)
- `cli/` — command-line tool
- `test-vectors/` — conformance test vectors
- `docs/` — developer documentation

## The Problem

ML models are built from layers of components — training datasets, pre-trained weights, fine-tuning corpora, and software libraries — that circulate across repositories, registries, and distribution channels. When a model is published or deployed, the provenance of these components is rarely recorded in a verifiable, machine-readable form.

Existing SBOM formats (SPDX, CycloneDX) address software packages well but have no fields for ML-specific component types: dataset splits, weight checkpoints, fine-tuning proportions, or model adaptation layers.

## Design Goals

ModelLedger is designed to be minimal and composable. It defines one JSON format and one verification algorithm. It does not require a centralised registry, a network service, or a blockchain. Any tool can implement the standard using only the specification and the test vectors.

ModelLedger is composable with:
- [DataLedger](https://github.com/epaunova/DataLedger) — dataset component entries can reference DataLedger manifests
- SPDX — software dependency entries can reference SPDX documents
- Hugging Face model cards — `modelledger.sbom_hash` field in model card YAML

## Cryptographic Primitives

- Signatures: ed25519 (RFC 8032)
- Content hashing: SHA-256
- Serialisation for signing: RFC 8785 JSON Canonicalisation Scheme (JCS)

## Quick Start

```bash
pip install cryptography pytest
python3 modelledger-core/modelledger_poc.py
python3 -m pytest modelledger-core/modelledger_poc.py -v
```

Expected: `12 passed`

## Licence

Code: MIT or Apache 2.0, at your choice.
Specification and documentation: CC-BY 4.0.

## Contact

Eva Paunova — eva@modelledger.dev
GitHub: https://github.com/epaunova/ModelLedger
