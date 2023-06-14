// Copyright (c) 2023 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    chain::{
        block::{consensus_data::PoSData, ConsensusData},
        config::EpochIndex,
        Block, ChainConfig, TxOutput,
    },
    primitives::BlockHeight,
};

use crate::EpochData;

pub trait EpochStorageRead {
    fn get_epoch_data(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::storage_result::Result<Option<EpochData>>;
}

pub trait EpochStorageWrite {
    fn set_epoch_data(
        &mut self,
        epoch_index: EpochIndex,
        epoch_data: &EpochData,
    ) -> crate::storage_result::Result<()>;

    fn del_epoch_data(&mut self, epoch_index: EpochIndex) -> crate::storage_result::Result<()>;
}

pub struct EpochDataCache<P> {
    parent: P,
    data: BTreeMap<EpochIndex, EpochData>,
}

impl<P: EpochStorageRead> EpochDataCache<P> {
    pub fn new(parent: P) -> Self {
        Self {
            parent,
            data: BTreeMap::new(),
        }
    }
}

impl<P: EpochStorageRead> EpochStorageRead for EpochDataCache<P> {
    fn get_epoch_data(
        &self,
        epoch_index: EpochIndex,
    ) -> crate::storage_result::Result<Option<EpochData>> {
        todo!()
    }
}

impl<P: EpochStorageWrite> EpochStorageWrite for EpochDataCache<P> {
    fn set_epoch_data(
        &mut self,
        epoch_index: u64,
        epoch_data: &EpochData,
    ) -> crate::storage_result::Result<()> {
        todo!()
    }

    fn del_epoch_data(&mut self, epoch_index: EpochIndex) -> crate::storage_result::Result<()> {
        todo!()
    }
}
