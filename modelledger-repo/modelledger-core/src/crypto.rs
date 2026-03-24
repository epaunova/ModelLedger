use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use sha2::{Sha256, Digest};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::error::ModelLedgerError;

pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    pub fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes())
    }

    pub fn sign_bytes(&self, data: &[u8]) -> String {
        let sig = self.signing_key.sign(data);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

pub fn verify(
    public_key_b64: &str,
    signature_b64: &str,
    message: &[u8],
) -> Result<(), ModelLedgerError> {
    let key_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64)
        .map_err(|e| ModelLedgerError::KeyError(e.to_string()))?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| ModelLedgerError::KeyError("key must be 32 bytes".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| ModelLedgerError::KeyError(e.to_string()))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| ModelLedgerError::KeyError(e.to_string()))?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| ModelLedgerError::KeyError("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(message, &signature)
        .map_err(|_| ModelLedgerError::InvalidSignature)
}
