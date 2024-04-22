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

use generic_array::{sequence::Split, typenum::U32, GenericArray};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroize;

use crate::key::hdkd::{
    chain_code::{ChainCode, CHAINCODE_LENGTH},
    derivable::DerivationError,
};

pub mod eq;

pub fn new_hmac_sha_512(key: &[u8]) -> Hmac<Sha512> {
    Hmac::<Sha512>::new_from_slice(key).expect("HMAC can take key of any size")
}

pub fn to_key_and_chain_code<SecretKey>(
    mac: Hmac<Sha512>,
    to_key: impl FnOnce(&[u8]) -> Result<SecretKey, DerivationError>,
) -> Result<(SecretKey, ChainCode), DerivationError> {
    // Finalize the hmac
    let mut result = mac.finalize().into_bytes();

    // Split in to two 32 byte arrays
    let (mut secret_key_bytes, mut chain_code_bytes): (
        GenericArray<u8, U32>,
        GenericArray<u8, U32>,
    ) = result.split();
    result.zeroize();

    // Create the secret key key
    let secret_key = to_key(secret_key_bytes.as_slice())?;
    secret_key_bytes.zeroize();

    // Chain code
    let chain_code: [u8; CHAINCODE_LENGTH] = chain_code_bytes.into();
    let chain_code = ChainCode::from(chain_code);
    chain_code_bytes.zeroize();

    Ok((secret_key, chain_code))
}

#[cfg(test)]
mod test {
    use super::*;
    use randomness::Rng;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    /// Test to prove that hmac-sha512 can be used with keys of any size, since there's an expect in it
    fn mac_key_of_any_size(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let key_size = rng.gen_range(0..=1000);

        let key = (0..key_size).map(|_| rng.gen::<u8>()).collect::<Vec<_>>();

        let _hmac = new_hmac_sha_512(&key);
    }
}
