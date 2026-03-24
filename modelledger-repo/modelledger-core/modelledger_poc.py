"""
ModelLedger Python Proof-of-Concept
====================================
Implements the full ModelLedger protocol:
  - ed25519 signing over RFC 8785 canonical JSON
  - ML-SBOM creation and verification
  - Component types: dataset, base_weights, finetuning_corpus, software_library
  - Tamper detection for all fields
  - DataLedger manifest reference
  - Composability with SPDX

Run tests:
    pip install cryptography pytest
    python3 -m pytest modelledger_poc.py -v

Expected: 12 passed
"""

import json
import uuid
import hashlib
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.exceptions import InvalidSignature


# ── Canonical JSON (RFC 8785 JCS) ────────────────────────────────────────────

def canonical_json(obj) -> bytes:
    """Serialise obj to RFC 8785 canonical JSON bytes."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode('utf-8')


# ── Key helpers ───────────────────────────────────────────────────────────────

def generate_keypair():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_b64url(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def b64url_to_public_key(b64: str) -> Ed25519PublicKey:
    padded = b64 + '=' * (-len(b64) % 4)
    raw = base64.urlsafe_b64decode(padded)
    return Ed25519PublicKey.from_public_bytes(raw)


def sha256_hex(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


# ── ML-SBOM ───────────────────────────────────────────────────────────────────

def make_component(type_, name, version, source_uri, content: bytes,
                   licence="MIT", proportion=None,
                   dataledger_manifest_id=None, spdx_id=None):
    c = {
        "component_id": str(uuid.uuid4()),
        "type": type_,
        "name": name,
        "version": version,
        "source_uri": source_uri,
        "content_hash": sha256_hex(content),
        "licence": licence,
    }
    if proportion is not None:
        c["proportion"] = proportion
    if dataledger_manifest_id is not None:
        c["dataledger_manifest_id"] = dataledger_manifest_id
    if spdx_id is not None:
        c["spdx_id"] = spdx_id
    return c


def create_and_sign_sbom(private_key, public_key, name, version,
                          model_uri, model_content: bytes,
                          licence, components):
    sbom = {
        "id": str(uuid.uuid4()),
        "version": version,
        "name": name,
        "model_uri": model_uri,
        "model_hash": sha256_hex(model_content),
        "licence": licence,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "publisher_key": public_key_to_b64url(public_key),
        "components": components,
        "signature": "",
    }
    canonical = canonical_json(sbom)
    sig_bytes = private_key.sign(canonical)
    sbom["signature"] = base64.urlsafe_b64encode(sig_bytes).rstrip(b'=').decode('ascii')
    return sbom


def verify_sbom(sbom: dict) -> bool:
    unsigned = {k: ("" if k == "signature" else v) for k, v in sbom.items()}
    canonical = canonical_json(unsigned)
    pub_key = b64url_to_public_key(sbom["publisher_key"])
    padded = sbom["signature"] + '=' * (-len(sbom["signature"]) % 4)
    sig_bytes = base64.urlsafe_b64decode(padded)
    try:
        pub_key.verify(sig_bytes, canonical)
        return True
    except InvalidSignature:
        return False


# ── Tests ─────────────────────────────────────────────────────────────────────

def make_test_sbom():
    priv, pub = generate_keypair()
    components = [
        make_component("dataset", "CommonCrawl-2024", "2024-01",
                       "https://example.org/cc2024.tar.gz",
                       b"crawl data", "CC-BY-4.0", proportion=0.6,
                       dataledger_manifest_id=str(uuid.uuid4())),
        make_component("dataset", "Wikipedia-EN", "2024-03",
                       "https://example.org/wiki-en.tar.gz",
                       b"wiki data", "CC-BY-SA-4.0", proportion=0.2),
        make_component("base_weights", "LLaMA-3-8B", "3.0.0",
                       "https://example.org/llama3-8b.pt",
                       b"base weights", "LLaMA-3", proportion=0.2),
        make_component("software_library", "transformers", "4.40.0",
                       "https://pypi.org/project/transformers/4.40.0/",
                       b"transformers lib", "Apache-2.0",
                       spdx_id="SPDXRef-transformers-4.40.0"),
    ]
    sbom = create_and_sign_sbom(
        priv, pub,
        name="MyLLM-v1",
        version="1.0.0",
        model_uri="https://example.org/models/myllm-v1.tar.gz",
        model_content=b"model weights data",
        licence="Apache-2.0",
        components=components,
    )
    return sbom, priv, pub


def test_sign_and_verify():
    sbom, _, _ = make_test_sbom()
    assert verify_sbom(sbom), "Valid SBOM should verify"


def test_tamper_name_fails():
    sbom, _, _ = make_test_sbom()
    sbom["name"] = "Tampered Model"
    assert not verify_sbom(sbom), "Tampered name should fail"


def test_tamper_model_hash_fails():
    sbom, _, _ = make_test_sbom()
    sbom["model_hash"] = "sha256:" + "0" * 64
    assert not verify_sbom(sbom), "Tampered model_hash should fail"


def test_tamper_licence_fails():
    sbom, _, _ = make_test_sbom()
    sbom["licence"] = "MIT"
    assert not verify_sbom(sbom), "Tampered licence should fail"


def test_tamper_component_name_fails():
    sbom, _, _ = make_test_sbom()
    sbom["components"][0]["name"] = "Fake Dataset"
    assert not verify_sbom(sbom), "Tampered component name should fail"


def test_tamper_component_hash_fails():
    sbom, _, _ = make_test_sbom()
    sbom["components"][0]["content_hash"] = "sha256:" + "a" * 64
    assert not verify_sbom(sbom), "Tampered component hash should fail"


def test_tamper_component_licence_fails():
    sbom, _, _ = make_test_sbom()
    sbom["components"][0]["licence"] = "GPL-3.0"
    assert not verify_sbom(sbom), "Tampered component licence should fail"


def test_tamper_proportion_fails():
    sbom, _, _ = make_test_sbom()
    sbom["components"][0]["proportion"] = 0.99
    assert not verify_sbom(sbom), "Tampered proportion should fail"


def test_add_component_fails():
    sbom, _, _ = make_test_sbom()
    sbom["components"].append(
        make_component("dataset", "Injected", "1.0",
                       "https://evil.org/data.tar.gz", b"bad data", "MIT")
    )
    assert not verify_sbom(sbom), "Adding component after signing should fail"


def test_remove_component_fails():
    sbom, _, _ = make_test_sbom()
    sbom["components"] = sbom["components"][1:]
    assert not verify_sbom(sbom), "Removing component after signing should fail"


def test_json_roundtrip():
    sbom, _, _ = make_test_sbom()
    serialised = json.dumps(sbom)
    recovered = json.loads(serialised)
    assert verify_sbom(recovered), "JSON roundtrip should preserve valid signature"


def test_dataledger_manifest_reference():
    priv, pub = generate_keypair()
    manifest_id = str(uuid.uuid4())
    components = [
        make_component("dataset", "MyDataset", "1.0.0",
                       "https://example.org/dataset.tar.gz",
                       b"dataset", "CC-BY-4.0",
                       dataledger_manifest_id=manifest_id),
    ]
    sbom = create_and_sign_sbom(
        priv, pub,
        name="Model-with-DataLedger",
        version="1.0.0",
        model_uri="https://example.org/model.tar.gz",
        model_content=b"weights",
        licence="Apache-2.0",
        components=components,
    )
    assert verify_sbom(sbom)
    assert sbom["components"][0]["dataledger_manifest_id"] == manifest_id


if __name__ == "__main__":
    sbom, _, _ = make_test_sbom()
    print("ML-SBOM created and verified successfully.")
    print(f"Model: {sbom['name']} v{sbom['version']}")
    print(f"Components: {len(sbom['components'])}")
    for c in sbom["components"]:
        prop = f" ({c['proportion']*100:.0f}%)" if "proportion" in c else ""
        print(f"  [{c['type']}] {c['name']} {c['version']}{prop} — {c['licence']}")
    print(f"Signature: {sbom['signature'][:32]}...")
    print(f"Verified: {verify_sbom(sbom)}")
