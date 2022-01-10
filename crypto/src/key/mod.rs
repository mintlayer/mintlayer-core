pub mod rschnorr;
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};
use rand::SeedableRng;

fn make_rng() -> rand::rngs::StdRng {
    rand::rngs::StdRng::from_entropy()
}

#[derive(Debug, PartialEq, Eq, Clone, DecodeDer, EncodeDer)]
pub enum KeyKind {
    RistrettoSchnorr,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct PrivateKey {
    key: PrivateKeyHolder,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub struct PublicKey {
    pub_key: PublicKeyHolder,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub(crate) enum PrivateKeyHolder {
    RistrettoSchnorr(rschnorr::MLRistrettoPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, DecodeDer, EncodeDer)]
pub(crate) enum PublicKeyHolder {
    RistrettoSchnorr(rschnorr::MLRistrettoPublicKey),
}

impl PrivateKey {
    pub fn new(key_kind: KeyKind) -> (PrivateKey, PublicKey) {
        let mut rng = make_rng();
        match key_kind {
            KeyKind::RistrettoSchnorr => {
                let k = rschnorr::MLRistrettoPrivateKey::new(&mut rng);
                (
                    PrivateKey {
                        key: PrivateKeyHolder::RistrettoSchnorr(k.0),
                    },
                    crate::key::PublicKey {
                        pub_key: PublicKeyHolder::RistrettoSchnorr(k.1),
                    },
                )
            }
        }
    }

    pub fn kind(&self) -> KeyKind {
        match self.key {
            PrivateKeyHolder::RistrettoSchnorr(_) => KeyKind::RistrettoSchnorr,
        }
    }

    pub(crate) fn get_internal_key(&self) -> &PrivateKeyHolder {
        &self.key
    }
}

impl PublicKey {
    pub fn from_private_key(private_key: &PrivateKey) -> Self {
        match private_key.get_internal_key() {
            PrivateKeyHolder::RistrettoSchnorr(ref k) => crate::key::PublicKey {
                pub_key: PublicKeyHolder::RistrettoSchnorr(
                    rschnorr::MLRistrettoPublicKey::from_private_key(k),
                ),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let (sk, pk) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        assert_eq!(sk.kind(), KeyKind::RistrettoSchnorr);
    }
}
