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

use secp256k1;
use std::io::BufWriter;

use num_derive::FromPrimitive;
use serialization::{Decode, DecodeAll, Encode};

#[derive(FromPrimitive)]
pub enum SignatureKind {
    Secp256k1Schnorr = 0,
}

// #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Signature {
    Secp256k1Schnorr(secp256k1::schnorr::Signature),
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
            Signature::Secp256k1Schnorr(s) => {
                dest.write(&[(SignatureKind::Secp256k1Schnorr as u8)]);
                s.as_ref().encode_to(dest);
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

        match sig_kind {
            SignatureKind::Secp256k1Schnorr => {
                let data = <[u8; secp256k1::constants::SCHNORR_SIGNATURE_SIZE]>::decode(input)?;
                let sig = secp256k1::schnorr::Signature::from_slice(&data)
                    .map_err(|_| serialization::Error::from("Signature deserialization failed"))?;
                Ok(Signature::Secp256k1Schnorr(sig))
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
            Self::Secp256k1Schnorr(_) => false,
        }
    }

    pub fn kind(&self) -> SignatureKind {
        match self {
            Self::Secp256k1Schnorr(_) => SignatureKind::Secp256k1Schnorr,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::key::{KeyKind, PrivateKey, PublicKey};
    use hex::FromHex;
    use rstest::rstest;
    use test_utils::random::make_seedable_rng;
    use test_utils::random::Seed;

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn serialize_secp256k1(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);
        let (sk, pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
        let msg = b"abc";
        let sig = sk.sign_message(msg).unwrap();
        assert!(pk.verify_message(&sig, msg));

        let encoded_sig = sig.encode();
        let decoded_sig = Signature::decode_all(&mut encoded_sig.as_slice()).unwrap();
        assert_eq!(decoded_sig, sig);
    }

    #[test]
    fn serialize_chosen_data_secp256k1() {
        let msg = b"abc";

        // we signed the message above and stored the encoded data. Now it has to work from decoded data
        let sig_hex = "003c002dd5ea8f05240394eb109b8e9b52716db2720cebbc5dd66394afdf761d2ef76dc8a292d3a44e4d9f1f8fd8e17dc404e317082f5a2ce8adafde01e766aaa6";
        let pk_hex = "0002dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659";
        let sk_hex = "00b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef";

        let sig_bin: Vec<u8> = FromHex::from_hex(sig_hex).unwrap();
        let pk_bin: Vec<u8> = FromHex::from_hex(pk_hex).unwrap();
        let sk_bin: Vec<u8> = FromHex::from_hex(sk_hex).unwrap();

        let pk = PublicKey::decode_all(&mut pk_bin.as_slice()).unwrap();
        let sk = PrivateKey::decode_all(&mut sk_bin.as_slice()).unwrap();
        let sig = Signature::decode_all(&mut sig_bin.as_slice()).unwrap();

        assert_eq!(pk.kind(), KeyKind::Secp256k1Schnorr);
        assert_eq!(sk.kind(), KeyKind::Secp256k1Schnorr);

        assert!(pk.verify_message(&sig, msg));
        assert_eq!(PublicKey::from_private_key(&sk), pk);
    }
}
