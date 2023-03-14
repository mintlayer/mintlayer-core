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

use chainstate::ban_score::BanScore;
use common::{
    chain::{
        config::create_unit_test_config, signature::inputsig::InputWitness, tokens::OutputValue,
        OutPointSourceId, OutputPurpose, SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::Amount,
};
use mempool::error::{Error as MempoolError, TxValidationError};
use p2p_test_utils::start_subsystems;

use crate::{
    message::Announcement, sync::tests::helpers::SyncManagerHandle, types::peer_id::PeerId,
    P2pError,
};

#[tokio::test]
#[should_panic = "Received a message from unknown peer"]
async fn nonexistent_peer() {
    let mut handle = SyncManagerHandle::builder().build().await;

    let peer = PeerId::new();

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    let tx = SignedTransaction::new(tx.clone(), vec![]).unwrap();
    handle.make_announcement(peer, Announcement::Transaction(tx));

    handle.resume_panic().await;
}

#[tokio::test]
async fn invalid_transaction() {
    let mut handle = SyncManagerHandle::builder().build().await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    let tx = SignedTransaction::new(tx.clone(), vec![]).unwrap();
    handle.make_announcement(peer, Announcement::Transaction(tx));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::MempoolError(MempoolError::TxValidationError(TxValidationError::NoInputs))
            .ban_score()
    );
    handle.assert_no_event().await;
}

#[tokio::test]
async fn valid_transaction() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = Transaction::new(
        0x00,
        vec![TxInput::new(OutPointSourceId::from(chain_config.genesis_block_id()), 0)],
        vec![TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1)),
            OutputPurpose::Burn,
        )],
        0x01,
    )
    .unwrap();
    let tx = SignedTransaction::new(tx.clone(), vec![InputWitness::NoSignature(None)]).unwrap();

    handle.make_announcement(peer, Announcement::Transaction(tx));

    handle.assert_no_peer_manager_event().await;
    handle.assert_no_error().await;
}

#[tokio::test]
async fn tx_from_mempool() {
    let chain_config = Arc::new(create_unit_test_config());
    let (chainstate, mempool) = start_subsystems(Arc::clone(&chain_config));
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_subsystems(chainstate, mempool.clone())
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = Transaction::new(
        0x00,
        vec![TxInput::new(OutPointSourceId::from(chain_config.genesis_block_id()), 0)],
        vec![TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(1)),
            OutputPurpose::Burn,
        )],
        0x01,
    )
    .unwrap();
    let tx = SignedTransaction::new(tx.clone(), vec![InputWitness::NoSignature(None)]).unwrap();
    let tx_ = tx.clone();
    mempool.call_async_mut(|m| m.add_transaction(tx_)).await.unwrap().unwrap();

    assert_eq!(Announcement::Transaction(tx), handle.announcement().await);

    handle.assert_no_peer_manager_event().await;
    handle.assert_no_error().await;
}
