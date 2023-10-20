#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Symmetric key creation from shared secret failed: {0}")]
    SymmetricKeyCreationFailed(String),
    #[error("Symmetric encryption failed: {0}")]
    SymmetricEncryptionFailed(String),
    #[error("Symmetric decryption failed: {0}")]
    SymmetricDecryptionFailed(String),
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
}
