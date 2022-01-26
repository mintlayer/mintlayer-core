pub use tari_crypto::ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey};
use tari_crypto::signatures::SchnorrSignature;
pub type RistrettoSchnorrSignature = SchnorrSignature<RistrettoPublicKey, RistrettoSecretKey>;

pub fn add_sigs(
    sig1: &RistrettoSchnorrSignature,
    sig2: &RistrettoSchnorrSignature,
) -> RistrettoSchnorrSignature {
    return sig1 + sig2;
}

#[cfg(test)]
mod test {
    use crate::hash::StreamHasher;
    use crate::hash::{Blake2b, Blake2b32Stream};

    fn blake2b_hash<T: AsRef<[u8]> + Clone>(data: T) -> Vec<u8> {
        let d = crate::hash::hash::<Blake2b, _>(&data);
        Vec::from_bytes(d.as_slice()).unwrap()
    }

    use tari_crypto::tari_utilities::ByteArray;
    use tari_crypto::{
        keys::{PublicKey, SecretKey},
        ristretto::{RistrettoPublicKey, RistrettoSchnorr, RistrettoSecretKey},
    };

    #[test]
    fn default() {
        let sig = RistrettoSchnorr::default();
        assert_eq!(sig.get_signature(), &RistrettoSecretKey::default());
        assert_eq!(sig.get_public_nonce(), &RistrettoPublicKey::default());
    }

    /// Create a signature, and then verify it. Also checks that some invalid signatures fail to verify
    #[test]
    #[allow(non_snake_case)]
    fn sign_and_verify_message() {
        let mut rng = rand::thread_rng();
        let (k, P) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r, R) = RistrettoPublicKey::random_keypair(&mut rng);
        let e = Blake2b32Stream::new()
            .write(P.as_bytes())
            .write(R.as_bytes())
            .write(b"Small Gods")
            .finalize();
        let e_key = RistrettoSecretKey::from_bytes(&e).unwrap();
        let s = &r + &e_key * &k;
        let sig = RistrettoSchnorr::sign(k, r, &e).unwrap();
        let R_calc = sig.get_public_nonce();
        assert_eq!(R, *R_calc);
        assert_eq!(sig.get_signature(), &s);
        assert!(sig.verify_challenge(&P, &e));
        // Doesn't work for invalid credentials
        assert!(!sig.verify_challenge(&R, &e));
        // Doesn't work for different challenge
        let wrong_challenge = blake2b_hash(b"Guards! Guards!");
        assert!(!sig.verify_challenge(&P, &wrong_challenge));
    }

    /// This test checks that the linearity of Schnorr signatures hold, i.e. that s = s1 + s2 is validated by R1 + R2
    /// and P1 + P2. We do this by hand here rather than using the APIs to guard against regressions
    #[test]
    #[allow(non_snake_case)]
    fn test_signature_addition() {
        let mut rng = rand::thread_rng();
        // Alice and Bob generate some keys and nonces
        let (k1, P1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r1, R1) = RistrettoPublicKey::random_keypair(&mut rng);
        let (k2, P2) = RistrettoPublicKey::random_keypair(&mut rng);
        let (r2, R2) = RistrettoPublicKey::random_keypair(&mut rng);
        // Each of them creates the Challenge = H(R1 || R2 || P1 || P2 || m)
        let e = Blake2b32Stream::new()
            .write(R1.as_bytes())
            .write(R2.as_bytes())
            .write(P1.as_bytes())
            .write(P2.as_bytes())
            .write(b"Moving Pictures")
            .finalize();
        // Calculate Alice's signature
        let s1 = RistrettoSchnorr::sign(k1, r1, &e).unwrap();
        // Calculate Bob's signature
        let s2 = RistrettoSchnorr::sign(k2, r2, &e).unwrap();
        // Now add the two signatures together
        let s_agg = &s1 + &s2;
        // Check that the multi-sig verifies
        assert!(s_agg.verify_challenge(&(P1 + P2), &e));
    }

    /// Ristretto scalars have a max value 2^255. This test checks that hashed messages above this value can still be
    /// signed as a result of applying modulo arithmetic on the challenge value
    #[test]
    fn challenge_from_invalid_scalar() {
        let mut rng = rand::thread_rng();
        let m = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
        let k = RistrettoSecretKey::random(&mut rng);
        let r = RistrettoSecretKey::random(&mut rng);
        assert!(RistrettoSchnorr::sign(k, r, &m).is_ok());
    }
}
