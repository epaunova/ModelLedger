# ModelLedger Specification

**Version:** 0.1 (draft)
**Status:** Public review
**Licence:** CC-BY 4.0

---

## 1. Introduction

ModelLedger defines a cryptographic provenance standard for machine learning models. An ML-SBOM (Software Bill of Materials) document records all components that entered a model — datasets, base weights, fine-tuning corpora, and software libraries — in a signed, verifiable form.

The standard is designed to be:

- **Minimal** — one JSON format, one signing algorithm, one verification procedure
- **Composable** — integrates with SPDX, DataLedger, and Hugging Face model cards
- **Portable** — signed artifacts survive distribution across mirrors, forks, and platforms
- **Independently verifiable** — no trusted intermediary, no network access required

---

## 2. Scope and Non-Goals

**In scope:**
- ML-SBOM document format (JSON + ed25519 signature)
- Component types: datasets, base weights, fine-tuning corpora, software libraries
- Signing and verification algorithm
- Conformance test vectors

**Out of scope:**
- Automated licence enforcement or access control
- Model quality assessment or benchmarking
- Training data collection or curation
- Centralised model registries
- Runtime model monitoring

---

## 3. ML-SBOM Format

### 3.1 Top-level fields

```json
{
  "id": "uuid-v4",
  "version": "semver",
  "name": "Model name",
  "model_uri": "https://example.org/models/my-model-v1.tar.gz",
  "model_hash": "sha256:<hex>",
  "licence": "SPDX-identifier",
  "created_at": "RFC-3339",
  "publisher_key": "base64url-ed25519-public-key",
  "components": [ ... ],
  "signature": "base64url-ed25519-signature"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | UUID v4 — unique identifier for this ML-SBOM |
| `version` | string | yes | Semantic version of this ML-SBOM document |
| `name` | string | yes | Human-readable model name |
| `model_uri` | string | yes | Canonical URI of the model artifact |
| `model_hash` | string | yes | `sha256:<hex>` of the model artifact |
| `licence` | string | yes | SPDX licence identifier for the model |
| `created_at` | string | yes | RFC 3339 timestamp |
| `publisher_key` | string | yes | Base64url-encoded ed25519 public key |
| `components` | array | yes | List of component descriptors (see §3.2) |
| `signature` | string | yes | Base64url ed25519 signature over RFC 8785 canonical JSON |

### 3.2 Component descriptor

Each entry in `components` describes one input component:

```json
{
  "component_id": "uuid-v4",
  "type": "dataset | base_weights | finetuning_corpus | software_library",
  "name": "Component name",
  "version": "semver or commit hash",
  "source_uri": "https://example.org/component",
  "content_hash": "sha256:<hex>",
  "licence": "SPDX-identifier",
  "proportion": 0.6,
  "dataledger_manifest_id": "uuid-v4 (optional)",
  "spdx_id": "SPDXRef-... (optional)"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `component_id` | string | yes | UUID v4 |
| `type` | string | yes | One of: `dataset`, `base_weights`, `finetuning_corpus`, `software_library` |
| `name` | string | yes | Human-readable component name |
| `version` | string | yes | Version or commit hash |
| `source_uri` | string | yes | Canonical URI of this component |
| `content_hash` | string | yes | `sha256:<hex>` of the component artifact |
| `licence` | string | yes | SPDX licence identifier |
| `proportion` | float | no | Fractional contribution to the model (0.0–1.0) |
| `dataledger_manifest_id` | string | no | DataLedger manifest UUID if component is a dataset |
| `spdx_id` | string | no | SPDX element ID if component is a software library |

---

## 4. Signing Algorithm

1. Construct the ML-SBOM object with all required fields. Set `signature` to `""`.
2. Serialise to canonical JSON using RFC 8785 (JCS) — keys sorted lexicographically, no insignificant whitespace.
3. Sign the UTF-8 encoded canonical JSON bytes with the publisher's ed25519 private key (RFC 8032).
4. Base64url-encode the 64-byte signature. Store in `signature`.

---

## 5. Verification Algorithm

1. Decode the `publisher_key` field (base64url → 32-byte ed25519 public key).
2. Set `signature` to `""` in the document.
3. Serialise the modified document to canonical JSON using RFC 8785.
4. Decode the original `signature` field (base64url → 64 bytes).
5. Verify the ed25519 signature over the canonical bytes using the public key.
6. Return `OK` if valid, `INVALID` otherwise.

Verification is fully deterministic. No network access, no trusted intermediary, no CA required.

---

## 6. Tamper Detection

Any modification to any field in the ML-SBOM after signing causes verification to fail. This includes:

- Top-level fields: `name`, `version`, `model_uri`, `model_hash`, `licence`, `publisher_key`
- Any component field: `type`, `name`, `version`, `source_uri`, `content_hash`, `licence`, `proportion`
- Addition or removal of components

---

## 7. Composability

### 7.1 With DataLedger

Dataset components can reference a DataLedger manifest via `dataledger_manifest_id`. The DataLedger manifest provides split-level provenance and publisher signing independent of the ML-SBOM.

### 7.2 With SPDX

Software library components can reference an SPDX element via `spdx_id`. A full SPDX document can be attached as supplementary documentation.

### 7.3 With Hugging Face model cards

Add the following field to `model_info` in `README.md`:

```yaml
modelledger:
  sbom_uri: https://example.org/models/my-model-v1.sbom.json
  sbom_hash: sha256:<hex>
```

---

## 8. Test Vectors

See `test-vectors/` for conformance fixtures. All conforming implementations must pass all test vectors without modification.

---

## 9. Design Rationale

### 9.1 Why not SPDX or CycloneDX?

SPDX and CycloneDX are excellent formats for software dependency trees. They have no fields for ML-specific component types: dataset splits, weight checkpoints, fine-tuning proportions, or model adaptation layers. Extending them would require adding ML-specific semantics to a format designed for software packages.

### 9.2 Why not in-toto / SLSA Provenance?

in-toto and SLSA Provenance are designed for software build pipelines. The `materials[]` model tracks source files and build inputs but has no concept of dataset proportions, weight checkpoints, or fine-tuning corpora. A new in-toto predicate type for ML models would produce a document identical in scope to the ModelLedger specification.

### 9.3 Why plain JSON, not JSON-LD?

JSON-LD has no canonical serialisation — two semantically equivalent documents can have different byte representations. Signing a JSON-LD document requires either RDF Dataset Normalisation (complex, requires a full RDF processor) or committing to a specific serialisation (which conflicts with JSON-LD's design). ModelLedger uses plain JSON with RFC 8785 canonical serialisation — simple, deterministic, and compatible with lightweight ML pipeline tooling.

### 9.4 Why ed25519?

ed25519 is compact (32-byte public key, 64-byte signature), fast, and well-supported across languages. It is used in DataLedger, SSH, TLS 1.3, and Signal. The same key infrastructure can serve both DataLedger (dataset signing) and ModelLedger (model SBOM signing).
