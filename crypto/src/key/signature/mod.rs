use std::io::BufWriter;

use crate::key::rschnorr::RistrettoSchnorrSignature;
use num_derive::FromPrimitive;
use serialization::{Decode, DecodeAll, Encode};
use tari_crypto::tari_utilities::message_format::MessageFormat;

#[derive(FromPrimitive)]
pub enum SignatureKind {
    RistrettoSchnorr = 0,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub enum Signature {
    RistrettoSchnorr(RistrettoSchnorrSignature),
}

impl Encode for Signature {
    fn encode(&self) -> Vec<u8> {
        let mut buf = BufWriter::new(Vec::new());
        self.encode_to(&mut buf);
        buf.into_inner().expect("Flushing should never fail")
    }

    fn encode_to<T: serialization::Output + ?Sized>(&self, dest: &mut T) {
        // format: enum index followed by data
        match &self {
            Signature::RistrettoSchnorr(s) => {
                dest.write(&[(SignatureKind::RistrettoSchnorr as u8)]);
                let sig_data = s.to_binary().expect("Signature serialization should never fail");
                sig_data.encode_to(dest);
            }
        }
    }
}

impl Decode for Signature {
    fn decode<I: serialization::Input>(input: &mut I) -> Result<Self, serialization::Error> {
        let sig_kind_raw = input.read_byte()?;
        let sig_kind: Option<SignatureKind> = num::FromPrimitive::from_u8(sig_kind_raw);
        let sig_kind =
            sig_kind.ok_or_else(|| serialization::Error::from("Invalid/Unknown signature kind"))?;
        let data = Vec::decode(input)?;

        match sig_kind {
            SignatureKind::RistrettoSchnorr => {
                let sig = RistrettoSchnorrSignature::from_binary(&data).map_err(|_| {
                    serialization::Error::from("Private Key deserialization failed")
                })?;
                Ok(Signature::RistrettoSchnorr(sig))
            }
        }
    }
}

impl Signature {
    pub fn from_data<T: AsRef<[u8]>>(data: T) -> Result<Self, serialization::Error> {
        let decoded_sig = Signature::decode_all(&mut data.as_ref())?;
        Ok(decoded_sig)
    }

    pub fn is_aggregable(&self) -> bool {
        match self {
            Self::RistrettoSchnorr(_) => true,
        }
    }

    pub fn kind(&self) -> SignatureKind {
        match self {
            Self::RistrettoSchnorr(_) => SignatureKind::RistrettoSchnorr,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{KeyKind, PrivateKey, PublicKey};
    use hex::FromHex;

    #[test]
    fn serialize() {
        let (sk, pk) = PrivateKey::new(KeyKind::RistrettoSchnorr);
        let msg = b"abc";
        let sig = sk.sign_message(msg).unwrap();
        assert!(pk.verify_message(&sig, msg));

        let encoded_sig = sig.encode();
        let decoded_sig = Signature::decode(&mut encoded_sig.as_slice()).unwrap();
        assert_eq!(decoded_sig, sig);
    }

    #[test]
    fn serialize_chosen_data() {
        let msg = b"abc";

        // we signed the message above and stored the encoded data. Now it has to work from decoded data
        let sig_hex = "00410120000000000000003854d817fa49c006007a1f39f819832275dcb183d56dbfdbb6d55fa22d612f7b20000000000000001d40bdad427aee222e1a52db065ffa116407c33b61a996d503c35f14b0c29001";
        let pk_hex = "0080342d7cadc2b58844d95e8f57f9b076918906e5770df97e79f9bcf7cf71dafc49";
        let sk_hex = "00808ce784285ffa840018142fdd63a424a6f79a11398f67f2197f62cd23989b5e0d";

        let sig_bin: Vec<u8> = FromHex::from_hex(sig_hex).unwrap();
        let pk_bin: Vec<u8> = FromHex::from_hex(pk_hex).unwrap();
        let sk_bin: Vec<u8> = FromHex::from_hex(sk_hex).unwrap();

        let decoded_pk = PublicKey::decode(&mut pk_bin.as_slice()).unwrap();
        let decoded_sk = PrivateKey::decode(&mut sk_bin.as_slice()).unwrap();
        let decoded_sig = Signature::decode(&mut sig_bin.as_slice()).unwrap();
        assert!(decoded_pk.verify_message(&decoded_sig, msg));
        assert_eq!(PublicKey::from_private_key(&decoded_sk), decoded_pk);
    }
}
