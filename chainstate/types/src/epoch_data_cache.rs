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

use std::{collections::BTreeMap, ops::Deref};

use common::chain::config::EpochIndex;

use crate::{storage_result, EpochData};

pub trait EpochStorageRead {
    fn get_epoch_data(&self, epoch_index: EpochIndex) -> storage_result::Result<Option<EpochData>>;
}

pub trait EpochStorageWrite: EpochStorageRead {
    fn set_epoch_data(
        &mut self,
        epoch_index: EpochIndex,
        epoch_data: &EpochData,
    ) -> storage_result::Result<()>;

    fn del_epoch_data(&mut self, epoch_index: EpochIndex) -> storage_result::Result<()>;
}

#[derive(Clone)]
enum DataEntry {
    Write(EpochData),
    Erase,
}

#[derive(Clone)]
pub struct EpochDataCache<P> {
    parent: P,
    data: BTreeMap<EpochIndex, DataEntry>,
}

impl<P: EpochStorageRead> EpochDataCache<P> {
    pub fn new(parent: P) -> Self {
        Self {
            parent,
            data: BTreeMap::new(),
        }
    }

    pub fn from_data(parent: P, data: ConsumedEpochDataCache) -> Self {
        Self {
            parent,
            data: data.data,
        }
    }

    pub fn consume(self) -> ConsumedEpochDataCache {
        ConsumedEpochDataCache { data: self.data }
    }
}

pub struct ConsumedEpochDataCache {
    data: BTreeMap<EpochIndex, DataEntry>,
}

impl ConsumedEpochDataCache {
    pub fn flush(self, storage: &mut impl EpochStorageWrite) -> storage_result::Result<()> {
        for (index, entry) in self.data {
            match entry {
                DataEntry::Write(data) => storage.set_epoch_data(index, &data)?,
                DataEntry::Erase => storage.del_epoch_data(index)?,
            }
        }
        Ok(())
    }
}

impl<P: EpochStorageRead> EpochStorageRead for EpochDataCache<P> {
    fn get_epoch_data(&self, epoch_index: EpochIndex) -> storage_result::Result<Option<EpochData>> {
        match self.data.get(&epoch_index) {
            Some(entry) => match entry {
                DataEntry::Write(data) => Ok(Some(data.clone())),
                DataEntry::Erase => Ok(None),
            },
            None => Ok(self.parent.get_epoch_data(epoch_index)?),
        }
    }
}

impl<T> EpochStorageRead for T
where
    T: Deref,
    <T as Deref>::Target: EpochStorageRead,
{
    fn get_epoch_data(&self, epoch_index: EpochIndex) -> storage_result::Result<Option<EpochData>> {
        self.deref().get_epoch_data(epoch_index)
    }
}

impl<P: EpochStorageRead> EpochStorageWrite for EpochDataCache<P> {
    fn set_epoch_data(
        &mut self,
        epoch_index: EpochIndex,
        epoch_data: &EpochData,
    ) -> storage_result::Result<()> {
        self.data.insert(epoch_index, DataEntry::Write(epoch_data.clone()));
        Ok(())
    }

    fn del_epoch_data(&mut self, epoch_index: EpochIndex) -> storage_result::Result<()> {
        self.data.insert(epoch_index, DataEntry::Erase);
        Ok(())
    }
}

// TODO: tests
