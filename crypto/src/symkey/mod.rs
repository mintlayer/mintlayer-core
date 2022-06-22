use crate::random::{CryptoRng, Rng};

mod chacha20poly1305;

use parity_scale_codec::{Decode, Encode};

use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Error)]
pub enum Error {
    #[error("Encryption error: {0}")]
    EncryptionError(String),
    #[error("Cipher text is shorter than allowed: {0} < minimum {1}")]
    CipherTextTooShort(usize, usize),
    #[error("Decryption error: {0}")]
    DecryptionError(String),
}

use self::chacha20poly1305::Chacha20poly1305Key;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Decode, Encode)]
pub enum SymmetricKeyKind {
    XChacha20Poly1305,
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
enum SymmetricKeyHolder {
    #[codec(index = 0)]
    XChacha20Poly1305(Chacha20poly1305Key),
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct SymmetricKey {
    key: SymmetricKeyHolder,
}

impl SymmetricKey {
    pub fn new<R: Rng + CryptoRng>(kind: SymmetricKeyKind, rng: &mut R) -> Self {
        let key = match kind {
            SymmetricKeyKind::XChacha20Poly1305 => SymmetricKeyHolder::XChacha20Poly1305(
                Chacha20poly1305Key::new_from_array(rng.gen::<[u8; 32]>()),
            ),
        };
        Self { key }
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        match &self.key {
            SymmetricKeyHolder::XChacha20Poly1305(k) => {
                k.encrypt(message, rng, associated_data.unwrap_or(b""))
            }
        }
    }

    pub fn decrypt(
        &self,
        cipher_text: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        match &self.key {
            SymmetricKeyHolder::XChacha20Poly1305(k) => k.decrypt(cipher_text, associated_data),
        }
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;
    use parity_scale_codec::DecodeAll;

    use crate::random::make_true_rng;

    use super::*;

    #[test]
    fn encode_then_decode() {
        let mut rng = make_true_rng();
        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let encoded = key.encode();
        let decoded = SymmetricKey::decode_all(&mut encoded.as_slice()).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn encrypt_then_decrypt() {
        let mut rng = make_true_rng();
        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let message_len = 1 + rng.gen::<u32>() % 10000;
        let message = (0..message_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let encrypted = key.encrypt(&message, &mut rng, None).unwrap();
        let decrypted = key.decrypt(&encrypted, None).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn encrypt_then_decrypt_with_associated_data() {
        let mut rng = make_true_rng();
        let key = SymmetricKey::new(SymmetricKeyKind::XChacha20Poly1305, &mut rng);
        let message_len = 1 + rng.gen::<u32>() % 10000;
        let aead_len = 1 + rng.gen::<u32>() % 10000;
        let message = (0..message_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let aead = (0..aead_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let encrypted = key.encrypt(&message, &mut rng, Some(&aead)).unwrap();
        let decrypted = key.decrypt(&encrypted, Some(&aead)).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn select_text() {
        let message = b"Hello there! Great to see you!".as_slice();
        let key_hex = "00a824a1cff88c1acdbb481c75ee60c35e99f1edb0704b5eeb2684c469891a58fa";
        let key_bin = Vec::from_hex(key_hex).unwrap();
        let key = SymmetricKey::decode_all(&mut key_bin.as_slice()).unwrap();
        let encrypted_hex = "83ad5caae9782309d0d3b74be26629f879d331ab069e54b7d7079d24e509cf5af08ff9cecb8b50693bbd4aa0b0114b0d25bd0f0a079c66868b8b86a7c3e592d71ce3a9a47fd9";
        let encrypted = Vec::from_hex(encrypted_hex).unwrap();
        let decrypted = key.decrypt(&encrypted, None).unwrap();
        assert_eq!(message, decrypted);
    }
}
