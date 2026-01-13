// Copyright (c) 2021-2025 RBB S.r.l
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

use std::collections::BTreeSet;

use chainstate::{ChainstateError, PropertyQueryError};
use chainstate_storage::{BlockchainStorageRead as _, Transactional};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        make_token_id,
        tokens::{
            IsTokenFrozen, Metadata, NftIssuance, NftIssuanceV0, RPCFungibleTokenInfo,
            RPCNonFungibleTokenInfo, RPCTokenInfo, TokenAuxiliaryData, TokenId, TokenIssuance,
            TokenIssuanceV1,
        },
        Block, Transaction, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use randomness::{CryptoRng, Rng};
use test_utils::assert_matches_return_val;
use tokens_accounting::{FungibleTokenData, TokensAccountingStorageRead};

pub struct ExpectedFungibleTokenData {
    pub issuance: TokenIssuance,
    pub issuance_tx: Transaction,
    pub issuance_block_id: Id<Block>,
    pub circulating_supply: Option<Amount>,
    pub is_locked: bool,
    pub is_frozen: IsTokenFrozen,
}

pub fn make_expected_rpc_token_info_from_token_issuance(
    token_id: TokenId,
    issuance: &TokenIssuanceV1,
    circulating_supply: Amount,
    is_locked: bool,
    is_frozen: IsTokenFrozen,
) -> RPCTokenInfo {
    RPCTokenInfo::FungibleToken(RPCFungibleTokenInfo {
        token_id,
        token_ticker: issuance.token_ticker.clone().into(),
        number_of_decimals: issuance.number_of_decimals,
        metadata_uri: issuance.metadata_uri.clone().into(),
        circulating_supply,
        total_supply: issuance.total_supply.into(),
        is_locked,
        frozen: is_frozen.into(),
        authority: issuance.authority.clone(),
    })
}

pub fn check_fungible_token(
    tf: &TestFramework,
    rng: &mut (impl Rng + CryptoRng),
    token_id: &TokenId,
    expected_data: &ExpectedFungibleTokenData,
    no_other_tokens_present: bool,
) {
    let issuance_tx_id = expected_data.issuance_tx.get_id();
    let block = tf.block(expected_data.issuance_block_id);
    let block_index = tf.block_index(&expected_data.issuance_block_id);
    // Ensure the block actually has the transaction
    block
        .transactions()
        .iter()
        .find(|tx| tx.transaction().get_id() == issuance_tx_id)
        .unwrap();
    let expected_token_id = make_token_id(
        tf.chain_config(),
        block_index.block_height(),
        expected_data.issuance_tx.inputs(),
    )
    .unwrap();
    assert_eq!(token_id, &expected_token_id);

    let (expected_info_for_rpc, expected_token_data) = match &expected_data.issuance {
        TokenIssuance::V1(issuance) => {
            let expected_info_for_rpc = make_expected_rpc_token_info_from_token_issuance(
                *token_id,
                issuance,
                expected_data.circulating_supply.unwrap_or(Amount::ZERO),
                expected_data.is_locked,
                expected_data.is_frozen,
            );

            let expected_token_data =
                tokens_accounting::TokenData::FungibleToken(FungibleTokenData::new_unchecked(
                    issuance.token_ticker.clone(),
                    issuance.number_of_decimals,
                    issuance.metadata_uri.clone(),
                    issuance.total_supply,
                    expected_data.is_locked,
                    expected_data.is_frozen,
                    issuance.authority.clone(),
                ));

            (expected_info_for_rpc, expected_token_data)
        }
    };
    let expected_infos_for_rpc = vec![expected_info_for_rpc.clone()];

    let random_token_id = TokenId::random_using(rng);

    // Check ChainstateInterface::get_token_info_for_rpc
    let actual_info_for_rpc = tf.chainstate.get_token_info_for_rpc(*token_id).unwrap().unwrap();
    assert_eq!(actual_info_for_rpc, expected_info_for_rpc);
    assert_eq!(
        tf.chainstate.get_token_info_for_rpc(random_token_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_tokens_info_for_rpc
    let actual_infos_for_rpc = tf
        .chainstate
        .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id]))
        .unwrap();
    assert_eq!(actual_infos_for_rpc, expected_infos_for_rpc);
    assert_eq!(
        tf.chainstate.get_tokens_info_for_rpc(&BTreeSet::new()).unwrap(),
        vec![]
    );
    assert_eq!(
        tf.chainstate
            .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id, random_token_id]))
            .unwrap_err(),
        ChainstateError::FailedToReadProperty(PropertyQueryError::TokenInfoMissing(
            random_token_id
        ))
    );

    // Check ChainstateInterface::get_token_aux_data; currently it's only stored for NFTs,
    // so the result should be None.
    assert_eq!(tf.chainstate.get_token_aux_data(*token_id).unwrap(), None);

    // Check ChainstateInterface::get_token_id_from_issuance_tx; this only works for NFTs too.
    assert_eq!(
        tf.chainstate.get_token_id_from_issuance_tx(&issuance_tx_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_token_data
    let actual_token_data = tf.chainstate.get_token_data(token_id).unwrap().unwrap();
    assert_eq!(actual_token_data, expected_token_data);
    assert_eq!(
        tf.chainstate.get_token_data(&random_token_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_token_circulating_supply
    let actual_circulating_supply = tf.chainstate.get_token_circulating_supply(token_id).unwrap();
    assert_eq!(actual_circulating_supply, expected_data.circulating_supply);
    assert_eq!(
        tf.chainstate.get_token_circulating_supply(&random_token_id).unwrap(),
        None
    );

    // Check the storage directly
    {
        let storage_tx = tf.storage.transaction_ro().unwrap();

        let actual_token_data = storage_tx.get_token_data(token_id).unwrap().unwrap();
        assert_eq!(actual_token_data, expected_token_data);
        assert_eq!(storage_tx.get_token_data(&random_token_id).unwrap(), None);

        let actual_circulating_supply = storage_tx.get_circulating_supply(token_id).unwrap();
        assert_eq!(actual_circulating_supply, expected_data.circulating_supply);
        assert_eq!(
            storage_tx.get_circulating_supply(&random_token_id).unwrap(),
            None
        );

        let tokens_acc_data = storage_tx.read_tokens_accounting_data().unwrap();
        let token_data_from_acc_data = tokens_acc_data.token_data.get(token_id).unwrap();
        assert_eq!(token_data_from_acc_data, &expected_token_data);
        let circulating_supply_from_acc_data = tokens_acc_data.circulating_supply.get(token_id);
        assert_eq!(
            circulating_supply_from_acc_data,
            expected_data.circulating_supply.as_ref()
        );

        if no_other_tokens_present {
            assert_eq!(tokens_acc_data.token_data.len(), 1);
            assert_eq!(
                tokens_acc_data.circulating_supply.len(),
                if expected_data.circulating_supply.is_some() {
                    1
                } else {
                    0
                }
            );
        }

        // These correspond to ChainstateInterface::get_token_aux_data and
        // ChainstateInterface::get_token_id_from_issuance_tx respectively.
        assert_eq!(storage_tx.get_token_aux_data(token_id).unwrap(), None);
        assert_eq!(storage_tx.get_token_id(&issuance_tx_id).unwrap(), None);
    }
}

pub struct ExpectedNftData {
    pub metadata: Metadata,
    pub issuance_tx: Transaction,
    pub issuance_tx_output_index: u32,
    pub issuance_block_id: Id<Block>,
}

pub fn make_expected_rpc_token_info_from_nft_metadata(
    token_id: TokenId,
    issuance_tx_id: Id<Transaction>,
    issuance_block_id: Id<Block>,
    metadata: &Metadata,
) -> RPCTokenInfo {
    RPCTokenInfo::NonFungibleToken(Box::new(RPCNonFungibleTokenInfo {
        token_id,
        creation_tx_id: issuance_tx_id,
        creation_block_id: issuance_block_id,
        metadata: metadata.into(),
    }))
}

pub fn check_nft(
    tf: &TestFramework,
    rng: &mut (impl Rng + CryptoRng),
    token_id: &TokenId,
    expected_data: &ExpectedNftData,
) {
    let issuance_tx_id = expected_data.issuance_tx.get_id();
    let block = tf.block(expected_data.issuance_block_id);
    let block_index = tf.block_index(&expected_data.issuance_block_id);
    // Ensure the block actually has the transaction
    block
        .transactions()
        .iter()
        .find(|tx| tx.transaction().get_id() == issuance_tx_id)
        .unwrap();
    let expected_token_id = make_token_id(
        tf.chain_config(),
        block_index.block_height(),
        expected_data.issuance_tx.inputs(),
    )
    .unwrap();
    assert_eq!(token_id, &expected_token_id);

    let (token_id_in_txo, issuance_in_txo, _dest_in_txo) = assert_matches_return_val!(
        &expected_data.issuance_tx.outputs()[expected_data.issuance_tx_output_index as usize],
        TxOutput::IssueNft(id, issuance, dest),
        (id, issuance, dest)
    );
    let issuance_v0_in_txo = assert_matches_return_val!(
        issuance_in_txo.as_ref(),
        NftIssuance::V0(issuance),
        issuance
    );
    assert_eq!(token_id_in_txo, token_id);
    assert_eq!(
        issuance_v0_in_txo,
        &NftIssuanceV0 {
            metadata: expected_data.metadata.clone()
        }
    );

    let expected_info_for_rpc = make_expected_rpc_token_info_from_nft_metadata(
        *token_id,
        issuance_tx_id,
        expected_data.issuance_block_id,
        &expected_data.metadata,
    );
    let expected_infos_for_rpc = vec![expected_info_for_rpc.clone()];
    let expected_aux_data = TokenAuxiliaryData::new(
        expected_data.issuance_tx.clone(),
        expected_data.issuance_block_id,
    );

    let random_token_id = TokenId::random_using(rng);
    let random_tx_id = Id::<Transaction>::random_using(rng);

    // Check ChainstateInterface::get_token_info_for_rpc
    let actual_info_for_rpc = tf.chainstate.get_token_info_for_rpc(*token_id).unwrap().unwrap();
    assert_eq!(actual_info_for_rpc, expected_info_for_rpc);
    assert_eq!(
        tf.chainstate.get_token_info_for_rpc(random_token_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_tokens_info_for_rpc
    let actual_infos_for_rpc = tf
        .chainstate
        .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id]))
        .unwrap();
    assert_eq!(actual_infos_for_rpc, expected_infos_for_rpc);
    assert_eq!(
        tf.chainstate.get_tokens_info_for_rpc(&BTreeSet::new()).unwrap(),
        vec![]
    );
    assert_eq!(
        tf.chainstate
            .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id, random_token_id]))
            .unwrap_err(),
        ChainstateError::FailedToReadProperty(PropertyQueryError::TokenInfoMissing(
            random_token_id
        ))
    );

    // Check ChainstateInterface::get_token_aux_data
    let actual_aux_data = tf.chainstate.get_token_aux_data(*token_id).unwrap().unwrap();
    assert_eq!(actual_aux_data, expected_aux_data);
    assert_eq!(
        tf.chainstate.get_token_aux_data(random_token_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_token_id_from_issuance_tx
    let token_id_from_issuance_tx = tf
        .chainstate
        .get_token_id_from_issuance_tx(&expected_data.issuance_tx.get_id())
        .unwrap()
        .unwrap();
    assert_eq!(token_id_from_issuance_tx, *token_id);
    assert_eq!(
        tf.chainstate.get_token_id_from_issuance_tx(&random_tx_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_token_data - this is only available for fungible tokens
    // currently, so the result should be None.
    assert_eq!(tf.chainstate.get_token_data(token_id).unwrap(), None);

    // Check ChainstateInterface::get_token_circulating_supply - this is only available for
    // fungible tokens.
    assert_eq!(
        tf.chainstate.get_token_circulating_supply(token_id).unwrap(),
        None
    );

    // Check the storage directly
    {
        let storage_tx = tf.storage.transaction_ro().unwrap();

        assert_eq!(storage_tx.get_token_data(token_id).unwrap(), None);
        assert_eq!(storage_tx.get_circulating_supply(token_id).unwrap(), None);

        let tokens_acc_data = storage_tx.read_tokens_accounting_data().unwrap();
        assert_eq!(tokens_acc_data.token_data.get(token_id), None);
        assert_eq!(tokens_acc_data.circulating_supply.get(token_id), None);

        assert_eq!(
            storage_tx.get_token_aux_data(token_id).unwrap().unwrap(),
            expected_aux_data
        );
        assert_eq!(
            storage_tx.get_token_aux_data(&random_token_id).unwrap(),
            None
        );

        assert_eq!(
            storage_tx.get_token_id(&issuance_tx_id).unwrap().unwrap(),
            *token_id
        );
        assert_eq!(storage_tx.get_token_id(&random_tx_id).unwrap(), None);
    }
}

pub fn assert_token_missing(
    tf: &TestFramework,
    token_id: &TokenId,
    issuance_tx_id: &Id<Transaction>,
    no_other_tokens_present: bool,
) {
    // Check ChainstateInterface::get_token_info_for_rpc
    assert_eq!(
        tf.chainstate.get_token_info_for_rpc(*token_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_tokens_info_for_rpc
    assert_eq!(
        tf.chainstate
            .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id]))
            .unwrap_err(),
        ChainstateError::FailedToReadProperty(PropertyQueryError::TokenInfoMissing(*token_id))
    );

    // Check ChainstateInterface::get_token_aux_data
    assert_eq!(tf.chainstate.get_token_aux_data(*token_id).unwrap(), None);

    // Check ChainstateInterface::get_token_id_from_issuance_tx; this only works for NFTs too.
    assert_eq!(
        tf.chainstate.get_token_id_from_issuance_tx(issuance_tx_id).unwrap(),
        None
    );

    // Check ChainstateInterface::get_token_data
    assert_eq!(tf.chainstate.get_token_data(token_id).unwrap(), None);

    // Check ChainstateInterface::get_token_circulating_supply
    assert_eq!(
        tf.chainstate.get_token_circulating_supply(token_id).unwrap(),
        None
    );

    // Check the storage directly
    {
        let storage_tx = tf.storage.transaction_ro().unwrap();

        assert_eq!(storage_tx.get_token_data(token_id).unwrap(), None);
        assert_eq!(storage_tx.get_circulating_supply(token_id).unwrap(), None);

        let tokens_acc_data = storage_tx.read_tokens_accounting_data().unwrap();
        assert_eq!(tokens_acc_data.token_data.get(token_id), None);
        assert_eq!(tokens_acc_data.circulating_supply.get(token_id), None);

        if no_other_tokens_present {
            assert_eq!(tokens_acc_data.token_data.len(), 0);
            assert_eq!(tokens_acc_data.circulating_supply.len(), 0);
        }

        assert_eq!(storage_tx.get_token_aux_data(token_id).unwrap(), None);
        assert_eq!(storage_tx.get_token_id(issuance_tx_id).unwrap(), None);
    }
}
