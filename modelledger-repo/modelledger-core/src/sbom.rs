use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::Utc;
use crate::crypto::{verify, Keypair};
use crate::error::ModelLedgerError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    Dataset,
    BaseWeights,
    FinetuningCorpus,
    SoftwareLibrary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub component_id: String,
    #[serde(rename = "type")]
    pub component_type: ComponentType,
    pub name: String,
    pub version: String,
    pub source_uri: String,
    pub content_hash: String,
    pub licence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proportion: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataledger_manifest_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_id: Option<String>,
}

/// A signed ModelLedger ML-SBOM document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlSbom {
    pub id: String,
    pub version: String,
    pub name: String,
    pub model_uri: String,
    pub model_hash: String,
    pub licence: String,
    pub created_at: String,
    pub publisher_key: String,
    pub components: Vec<Component>,
    pub signature: String,
}

impl MlSbom {
    /// Verify the ML-SBOM signature.
    pub fn verify(&self) -> Result<(), ModelLedgerError> {
        let mut unsigned = self.clone();
        unsigned.signature = String::new();
        let json_value = serde_json::to_value(&unsigned)?;
        let canonical = jcs::to_string(&json_value)
            .map_err(|e| ModelLedgerError::CanonError(e.to_string()))?;
        verify(&self.publisher_key, &self.signature, canonical.as_bytes())
    }

    pub fn to_json_pretty(&self) -> Result<String, ModelLedgerError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(json: &str) -> Result<Self, ModelLedgerError> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Builder for constructing and signing an MlSbom.
#[derive(Default)]
pub struct SbomBuilder {
    version: Option<String>,
    name: Option<String>,
    model_uri: Option<String>,
    model_hash: Option<String>,
    licence: Option<String>,
    components: Vec<Component>,
}

impl SbomBuilder {
    pub fn new() -> Self { Self::default() }

    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into()); self
    }
    pub fn name(mut self, n: impl Into<String>) -> Self {
        self.name = Some(n.into()); self
    }
    pub fn model_uri(mut self, u: impl Into<String>) -> Self {
        self.model_uri = Some(u.into()); self
    }
    pub fn model_hash(mut self, h: impl Into<String>) -> Self {
        self.model_hash = Some(h.into()); self
    }
    pub fn licence(mut self, l: impl Into<String>) -> Self {
        self.licence = Some(l.into()); self
    }
    pub fn components(mut self, c: Vec<Component>) -> Self {
        self.components = c; self
    }

    pub fn build_and_sign(self, keypair: &Keypair) -> Result<MlSbom, ModelLedgerError> {
        let version    = self.version.ok_or(ModelLedgerError::MissingField("version"))?;
        let name       = self.name.ok_or(ModelLedgerError::MissingField("name"))?;
        let model_uri  = self.model_uri.ok_or(ModelLedgerError::MissingField("model_uri"))?;
        let model_hash = self.model_hash.ok_or(ModelLedgerError::MissingField("model_hash"))?;
        let licence    = self.licence.ok_or(ModelLedgerError::MissingField("licence"))?;

        let mut sbom = MlSbom {
            id: Uuid::new_v4().to_string(),
            version,
            name,
            model_uri,
            model_hash,
            licence,
            created_at: Utc::now().to_rfc3339(),
            publisher_key: keypair.public_key_base64url(),
            components: self.components,
            signature: String::new(),
        };

        let json_value = serde_json::to_value(&sbom)?;
        let canonical = jcs::to_string(&json_value)
            .map_err(|e| ModelLedgerError::CanonError(e.to_string()))?;
        sbom.signature = keypair.sign_bytes(canonical.as_bytes());
        Ok(sbom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_component() -> Component {
        Component {
            component_id: Uuid::new_v4().to_string(),
            component_type: ComponentType::Dataset,
            name: "Test Dataset".into(),
            version: "1.0.0".into(),
            source_uri: "https://example.org/dataset.tar.gz".into(),
            content_hash: "sha256:abc123".into(),
            licence: "CC-BY-4.0".into(),
            proportion: Some(1.0),
            dataledger_manifest_id: None,
            spdx_id: None,
        }
    }

    #[test]
    fn roundtrip_sign_and_verify() {
        let keypair = Keypair::generate();
        let sbom = SbomBuilder::new()
            .name("Test Model")
            .version("1.0.0")
            .model_uri("https://example.org/model.tar.gz")
            .model_hash("sha256:abc123")
            .licence("Apache-2.0")
            .components(vec![test_component()])
            .build_and_sign(&keypair)
            .expect("sign failed");
        assert!(sbom.verify().is_ok());
    }

    #[test]
    fn tampered_name_fails() {
        let keypair = Keypair::generate();
        let mut sbom = SbomBuilder::new()
            .name("Test Model")
            .version("1.0.0")
            .model_uri("https://example.org/model.tar.gz")
            .model_hash("sha256:abc123")
            .licence("Apache-2.0")
            .components(vec![test_component()])
            .build_and_sign(&keypair)
            .expect("sign failed");
        sbom.name = "Tampered".into();
        assert!(sbom.verify().is_err());
    }

    #[test]
    fn json_roundtrip() {
        let keypair = Keypair::generate();
        let sbom = SbomBuilder::new()
            .name("JSON Test")
            .version("0.1.0")
            .model_uri("https://example.org/model.tar.gz")
            .model_hash("sha256:abc123")
            .licence("MIT")
            .components(vec![test_component()])
            .build_and_sign(&keypair)
            .expect("sign failed");
        let json = sbom.to_json_pretty().expect("serialise failed");
        let recovered = MlSbom::from_json(&json).expect("deserialise failed");
        assert!(recovered.verify().is_ok());
    }
}
