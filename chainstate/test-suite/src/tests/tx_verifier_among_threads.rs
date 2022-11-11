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

use chainstate_test_framework::{TestFramework, TestStore};
use common::chain::config::Builder as ConfigBuilder;
use common::{
    chain::OutPoint,
    primitives::{Id, H256},
};
use tx_verifier::transaction_verifier::{TransactionVerifier, TransactionVerifierConfig};
use utxo::{Utxo, UtxosView};

use super::helpers::in_memory_storage_wrapper::InMemoryStorageWrapper;

pub struct EmptyUtxosView;

impl UtxosView for EmptyUtxosView {
    fn utxo(&self, _outpoint: &OutPoint) -> Option<Utxo> {
        None
    }

    fn has_utxo(&self, _outpoint: &OutPoint) -> bool {
        false
    }

    fn best_block_hash(&self) -> Id<common::chain::GenBlock> {
        H256::zero().into()
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}

/// This test proves that a transaction verifier with this structure can be moved among threads
#[test]
fn transfer_tx_verifier_to_thread() {
    utils::concurrency::model(|| {
        let storage = TestStore::new_empty().unwrap();
        let _tf = TestFramework::builder().with_storage(storage.clone()).build();

        let chain_config = ConfigBuilder::test_chain().build();
        let storage = InMemoryStorageWrapper::new(storage, chain_config.clone());

        let utxos = EmptyUtxosView {};

        let verifier = TransactionVerifier::new_from_handle(
            &storage,
            &chain_config,
            utxos,
            TransactionVerifierConfig::new(false),
        );

        std::thread::scope(|s| {
            s.spawn(move || verifier.consume());
        });
    });
}
