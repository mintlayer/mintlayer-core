use crate::random::{CryptoRng, Rng};
use crate::symkey::Error;
use chacha20poly1305::aead::{AeadInPlace, NewAead};
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

    fn encrypt_with_nonce_and_aead<T: AsRef<[u8]>>(
        &self,
        nonce: &[u8],
        message: T,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(&self.key_data);
        let nonce = XNonce::from_slice(nonce);
        let mut cipher_text = message.as_ref().to_vec();
        cipher
            .encrypt_in_place(nonce, associated_data.unwrap_or(b""), &mut cipher_text)
            .map_err(|e| Error::EncryptionError(e.to_string()))?;
        let nonce: [u8; NONCE_LEN] = (*nonce).into();
        // concatenate the nonce + cipher as the result
        let result = nonce.into_iter().chain(cipher_text.into_iter()).collect::<Vec<_>>();
        Ok(result)
    }

    pub fn encrypt<T: AsRef<[u8]>, R: Rng + CryptoRng>(
        &self,
        message: T,
        rng: &mut R,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let nonce = rng.gen::<[u8; NONCE_LEN]>();
        self.encrypt_with_nonce_and_aead(&nonce, message, associated_data)
    }

    fn decrypt_with_nonce_and_aead<T: AsRef<[u8]>>(
        &self,
        nonce: &[u8],
        cipher_text: T,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let cipher = XChaCha20Poly1305::new(&self.key_data);
        let mut message = cipher_text.as_ref().to_vec();
        cipher
            .decrypt_in_place(nonce.into(), associated_data.unwrap_or(b""), &mut message)
            .map_err(|e| Error::DecryptionError(e.to_string()))?;
        Ok(message)
    }

    pub fn decrypt<T: AsRef<[u8]>>(
        &self,
        cipher_text_in: T,
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        if cipher_text_in.as_ref().len() < NONCE_LEN {
            return Err(Error::CipherTextTooShort(
                cipher_text_in.as_ref().len(),
                NONCE_LEN,
            ));
        }
        let nonce = &cipher_text_in.as_ref()[..NONCE_LEN];
        let cipher_text = &cipher_text_in.as_ref()[NONCE_LEN..];
        self.decrypt_with_nonce_and_aead(nonce, cipher_text, associated_data)
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
    use std::{
        collections::BTreeMap,
        io::{self, BufRead},
    };

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
        let encrypted = key.encrypt(&message, &mut rng, None).unwrap();
        let decrypted = key.decrypt(&encrypted, None).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn encrypt_then_decrypt_with_associated_data() {
        let mut rng = make_true_rng();
        let key = Chacha20poly1305Key::new_from_rng(&mut rng);
        let message_len = 1 + rng.gen::<u32>() % 10000;
        let aead_len = 1 + rng.gen::<u32>() % 10000;
        let message = (0..message_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let aead = (0..aead_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let encrypted = key.encrypt(&message, &mut rng, Some(&aead)).unwrap();
        let decrypted = key.decrypt(&encrypted, Some(&aead)).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn decrypt_too_short_cipher_text() {
        let mut rng = make_true_rng();
        let key = Chacha20poly1305Key::new_from_rng(&mut rng);
        let cipher_text_len = rng.gen::<usize>() % NONCE_LEN;
        let cipher_text = (0..cipher_text_len).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
        let decrypt_err = key.decrypt(&cipher_text, None).unwrap_err();
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
        let decrypted = key.decrypt(&encrypted, None).unwrap();
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
        let decrypted = key.decrypt(&encrypted, None).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn select_text_external_as_example() {
        let message = b"".as_slice();
        let key_hex = "0000000000000000000000000000000000000000000000000000000000000000";
        let aead_hex = "0102";
        let nonce_hex = "000102030405060708090a0b0c0d0e0f1011121314151617";
        let expected_encrypted_hex = "8d3324a3c4926d98b90af8e85b68fef1";
        let key_bin = Vec::from_hex(key_hex).unwrap();
        let aead = Vec::from_hex(aead_hex).unwrap();
        let nonce = Vec::from_hex(nonce_hex).unwrap();
        let key = Chacha20poly1305Key::new_from_array(key_bin.try_into().unwrap());
        let expected_encrypted = Vec::from_hex(expected_encrypted_hex).unwrap();
        let nonce_with_encrypted =
            key.encrypt_with_nonce_and_aead(&nonce, message, Some(&aead)).unwrap();
        let decrypted = key
            .decrypt_with_nonce_and_aead(&nonce, &nonce_with_encrypted[NONCE_LEN..], Some(&aead))
            .unwrap();
        assert_eq!(nonce_with_encrypted[NONCE_LEN..], expected_encrypted);
        assert_eq!(decrypted, message);
    }

    struct ExternalXChacha20Poly1305Data {
        key: Vec<u8>,
        ad: Vec<u8>,
        nonce: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
    }

    impl ExternalXChacha20Poly1305Data {
        fn from_map(map: BTreeMap<String, Vec<u8>>) -> Self {
            Self {
                key: map.get("Key").unwrap().clone(),
                ad: map.get("AD").unwrap_or(&Vec::new()).clone(),
                nonce: map.get("Nonce").unwrap_or(&Vec::new()).clone(),
                input: map.get("In").unwrap_or(&Vec::new()).clone(),
                output: map.get("Out").unwrap_or(&Vec::new()).clone(),
            }
        }
    }

    fn read_test_vectors_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Vec<ExternalXChacha20Poly1305Data> {
        let f = std::fs::File::open(path).unwrap();
        let lines = io::BufReader::new(f).lines();

        let mut result = Vec::new();

        let mut current_batch_map: BTreeMap<String, Vec<u8>> = Default::default();
        for (_line_num, line) in lines.into_iter().enumerate() {
            let line = line.unwrap();
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            // an empty line means we're starting a new test
            if line.is_empty() {
                if !current_batch_map.is_empty() {
                    result.push(ExternalXChacha20Poly1305Data::from_map(current_batch_map));
                }
                current_batch_map = Default::default();
                continue;
            }

            let split_parts = line.split('=').collect::<Vec<_>>();
            assert!(split_parts.len() == 2);
            if split_parts.len() == 2 {
                let k = split_parts[0].trim();
                let v = split_parts[1].trim();
                let el = Vec::from_hex(v).unwrap();
                current_batch_map.insert(k.to_owned(), el);
            }
        }
        result
    }

    fn test_external_data(data: ExternalXChacha20Poly1305Data) {
        let message = data.input;
        let cipher = data.output;
        let key_bin = data.key;
        let aead = data.ad;
        let nonce = data.nonce;
        let key = Chacha20poly1305Key::new_from_array(key_bin.try_into().unwrap());
        let nonce_with_encrypted = key
            .encrypt_with_nonce_and_aead(&nonce, message.as_slice(), Some(&aead))
            .unwrap();
        let decrypted = key
            .decrypt_with_nonce_and_aead(&nonce, &nonce_with_encrypted[NONCE_LEN..], Some(&aead))
            .unwrap();
        assert_eq!(nonce_with_encrypted[NONCE_LEN..], cipher);
        assert_eq!(decrypted, message);
    }

    #[test]
    fn select_text_external() {
        let test_vectors = read_test_vectors_file(
            std::path::Path::new("src")
                .join("symkey")
                .join("chacha20poly1305")
                .join("XCHACHA20_POLY1305_TEST_VECTORS_QIG_CRL_2019_10_17.tv"),
        );
        assert_eq!(test_vectors.len(), 1559);
        for test_vec in test_vectors {
            test_external_data(test_vec);
        }
    }
}
