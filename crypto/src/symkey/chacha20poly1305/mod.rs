use crate::random::{CryptoRng, Rng};
use crate::symkey::Error;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use parity_scale_codec::{Decode, Encode};

pub const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

#[must_use]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Chacha20poly1305Key {
    key_data: chacha20poly1305::Key,
}

impl Chacha20poly1305Key {
    #[allow(dead_code)]
    pub fn new_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let k = rng.gen::<[u8; KEY_LEN]>();

        Self { key_data: k.into() }
    }

    pub fn new_from_array(key_data: [u8; KEY_LEN]) -> Self {
        Self {
            key_data: key_data.into(),
        }
    }

    pub fn encrypt<T: AsRef<[u8]>, R: Rng + CryptoRng>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(&self.key_data);
        let nonce = rng.gen::<[u8; NONCE_LEN]>();
        let nonce = XNonce::from_slice(&nonce);
        let cipher_text = cipher
            .encrypt(nonce, message.as_ref())
            .map_err(|e| Error::EncryptionError(e.to_string()))?;
        let nonce: [u8; NONCE_LEN] = (*nonce).into();
        // concatenate the nonce + cipher as the result
        let result = nonce.into_iter().chain(cipher_text.into_iter()).collect::<Vec<_>>();
        Ok(result)
    }

    pub fn decrypt<T: AsRef<[u8]>>(&self, cipher_text_in: T) -> Result<Vec<u8>, Error> {
        if cipher_text_in.as_ref().len() < NONCE_LEN {
            return Err(Error::CipherTextTooShort(
                cipher_text_in.as_ref().len(),
                NONCE_LEN,
            ));
        }
        let nonce = &cipher_text_in.as_ref()[..NONCE_LEN];
        let cipher_text = &cipher_text_in.as_ref()[NONCE_LEN..];
        let cipher = XChaCha20Poly1305::new(&self.key_data);
        cipher
            .decrypt(nonce.into(), cipher_text)
            .map_err(|e| Error::DecryptionError(e.to_string()))
    }
}

impl Encode for Chacha20poly1305Key {
    fn size_hint(&self) -> usize {
        KEY_LEN
    }

    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        dest.write(self.key_data.as_slice())
    }

    fn encoded_size(&self) -> usize {
        KEY_LEN
    }
}

impl Decode for Chacha20poly1305Key {
    fn encoded_fixed_size() -> Option<usize> {
        Some(KEY_LEN)
    }

    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let v = <[u8; KEY_LEN]>::decode(input)?;
        let k = chacha20poly1305::Key::from_slice(&v);
        let result = Chacha20poly1305Key { key_data: *k };
        Ok(result)
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
        let key = Chacha20poly1305Key::new_from_rng(&mut rng);
        let encoded = key.encode();
        let decoded = Chacha20poly1305Key::decode_all(&mut encoded.as_slice()).unwrap();
        assert_eq!(key, decoded);
    }

    #[test]
    fn encrypt_then_decrypt() {
        let mut rng = make_true_rng();
        let key = Chacha20poly1305Key::new_from_rng(&mut rng);
        let message_len = 1 + rng.gen::<u32>() % 10000;
        let message = (0..message_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let encrypted = key.encrypt(&message, &mut rng).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn decrypt_too_short_cipher_text() {
        let mut rng = make_true_rng();
        let key = Chacha20poly1305Key::new_from_rng(&mut rng);
        let cipher_text_len = rng.gen::<usize>() % NONCE_LEN;
        let cipher_text = (0..cipher_text_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let decrypt_err = key.decrypt(&cipher_text).unwrap_err();
        assert_eq!(
            decrypt_err,
            Error::CipherTextTooShort(cipher_text_len, NONCE_LEN)
        );
    }

    #[test]
    fn select_text_with_decode() {
        let message = b"Hello there! Great to see you!".as_slice();
        let key_hex = "a824a1cff88c1acdbb481c75ee60c35e99f1edb0704b5eeb2684c469891a58fa";
        let key_bin = Vec::from_hex(key_hex).unwrap();
        let key = Chacha20poly1305Key::decode_all(&mut key_bin.as_slice()).unwrap();
        let encrypted_hex = "83ad5caae9782309d0d3b74be26629f879d331ab069e54b7d7079d24e509cf5af08ff9cecb8b50693bbd4aa0b0114b0d25bd0f0a079c66868b8b86a7c3e592d71ce3a9a47fd9";
        let encrypted = Vec::from_hex(encrypted_hex).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn select_text_with_new() {
        let message = b"Hello there! Great to see you!".as_slice();
        let key_hex = "a824a1cff88c1acdbb481c75ee60c35e99f1edb0704b5eeb2684c469891a58fa";
        let key_bin = Vec::from_hex(key_hex).unwrap();
        let key = Chacha20poly1305Key::new_from_array(key_bin.try_into().unwrap());
        let encrypted_hex = "83ad5caae9782309d0d3b74be26629f879d331ab069e54b7d7079d24e509cf5af08ff9cecb8b50693bbd4aa0b0114b0d25bd0f0a079c66868b8b86a7c3e592d71ce3a9a47fd9";
        let encrypted = Vec::from_hex(encrypted_hex).unwrap();
        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(message, decrypted);
    }
}
