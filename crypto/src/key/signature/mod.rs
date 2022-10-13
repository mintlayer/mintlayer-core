// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::BufWriter;

use crate::key::rschnorr::RistrettoSchnorrSignature;
use num_derive::FromPrimitive;
use serialization::{Decode, DecodeAll, Encode};
use tari_crypto::tari_utilities::message_format::MessageFormat;

#[derive(FromPrimitive)]
pub enum SignatureKind {
    RistrettoSchnorr = 0,
    RistrettoSchnorr2 = 1,
}

// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Signature {
    RistrettoSchnorr(RistrettoSchnorrSignature),
    RistrettoSchnorr2(schnorrkel::Signature),
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
            Signature::RistrettoSchnorr2(s) => {
                dest.write(&[(SignatureKind::RistrettoSchnorr2 as u8)]);
                s.to_bytes().as_ref().encode_to(dest);
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
            SignatureKind::RistrettoSchnorr2 => {
                let sig = schnorrkel::Signature::from_bytes(&data).map_err(|_| {
                    serialization::Error::from("Private Key deserialization failed")
                })?;
                Ok(Signature::RistrettoSchnorr2(sig))
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
            Self::RistrettoSchnorr2(_) => true,
        }
    }

    pub fn kind(&self) -> SignatureKind {
        match self {
            Self::RistrettoSchnorr(_) => SignatureKind::RistrettoSchnorr,
            Self::RistrettoSchnorr2(_) => SignatureKind::RistrettoSchnorr2,
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
    fn serialize2() {
        let (sk, pk) = PrivateKey::new(KeyKind::RistrettoSchnorr2);
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

    #[test]
    fn serialize_chosen_data2() {
        let msg = b"abc";

        // we signed the message above and stored the encoded data. Now it has to work from decoded data
        let sig_hex = "010101aa39cdbb96b4eec724cac0400a30cf0d2b9a1040d3aa4f58a34a218d03349f730b8dc2e9b592c6eaac524bc7a5266815f47633aa6eb58708ee262667629a1b86";
        let pk_hex = "0180283462ee4f0840e21d6de7744ba42929d1b74b7a948e8229d9551e7760ec8c52";
        let sk_hex = "010101181b259bac04d8ec3f6ea2a86b37f39a353288a8410fc469b9f2d5c59ce30a36c10bfdc906c8343fe0fb42c2564d6b1d3bf8ae3d73f0f7e5424cb60a9639d7e0";

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
