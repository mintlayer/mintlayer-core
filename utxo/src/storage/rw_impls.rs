// Copyright (c) 2021-2022 RBB S.r.l
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

use super::{UtxosDB, UtxosStorageRead, UtxosStorageWrite};
use crate::Utxo;
use common::{
    chain::{GenBlock, UtxoOutPoint},
    primitives::Id,
};

impl<S: UtxosStorageWrite> UtxosStorageWrite for UtxosDB<S> {
    fn set_utxo(&mut self, outpoint: &UtxoOutPoint, entry: Utxo) -> Result<(), Self::Error> {
        self.0.set_utxo(outpoint, entry)
    }

    fn del_utxo(&mut self, outpoint: &UtxoOutPoint) -> Result<(), Self::Error> {
        self.0.del_utxo(outpoint)
    }

    fn set_best_block_for_utxos(&mut self, block_id: &Id<GenBlock>) -> Result<(), Self::Error> {
        self.0.set_best_block_for_utxos(block_id)
    }
}

impl<S: UtxosStorageRead> UtxosStorageRead for UtxosDB<S> {
    type Error = S::Error;

    fn get_utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        self.0.get_utxo(outpoint)
    }

    fn get_best_block_for_utxos(&self) -> Result<Id<GenBlock>, Self::Error> {
        self.0.get_best_block_for_utxos()
    }
}
