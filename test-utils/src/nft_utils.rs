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

use std::sync::Arc;

use crate::random_string;
use common::{
    chain::{
        config::ChainConfig,
        tokens::{Metadata, NftIssuance, TokenCreator, TokenIssuance},
    },
    primitives::Amount,
};
use crypto::{
    key::{KeyKind, PrivateKey},
    random::Rng,
};
use serialization::extras::non_empty_vec::DataOrNoVec;

pub fn random_creator() -> TokenCreator {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    TokenCreator::from(public_key)
}

pub fn random_token_issuance(chain_config: Arc<ChainConfig>, rng: &mut impl Rng) -> TokenIssuance {
    let max_ticker_len = chain_config.token_max_ticker_len();
    let max_dec_count = chain_config.token_max_dec_count();
    let max_uri_len = chain_config.token_max_uri_len();

    TokenIssuance {
        token_ticker: random_string(rng, 1..max_ticker_len).as_bytes().to_vec(),
        amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
        number_of_decimals: rng.gen_range(1..max_dec_count),
        metadata_uri: random_string(rng, 1..max_uri_len).as_bytes().to_vec(),
    }
}

pub fn random_nft_issuance(chain_config: Arc<ChainConfig>, rng: &mut impl Rng) -> NftIssuance {
    let max_desc_len = chain_config.token_max_description_len();
    let max_name_len = chain_config.token_max_name_len();
    let max_ticker_len = chain_config.token_max_ticker_len();

    NftIssuance {
        metadata: Metadata {
            creator: Some(random_creator()),
            name: random_string(rng, 1..max_name_len).into_bytes(),
            description: random_string(rng, 1..max_desc_len).into_bytes(),
            ticker: random_string(rng, 1..max_ticker_len).into_bytes(),
            icon_uri: DataOrNoVec::from(None),
            additional_metadata_uri: DataOrNoVec::from(None),
            media_uri: DataOrNoVec::from(None),
            media_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0],
        },
    }
}
