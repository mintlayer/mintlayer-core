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

//! Raw database representation for contents inspection purposes

use crate::{schema::Schema, Backend, Storage};
use std::collections::BTreeMap;
use storage_core::{backend::PrefixIter, DbIndex};

/// Raw database low-level representation
pub type RawDbContents = BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>;

/// Raw database contents
#[derive(Eq, PartialEq, Debug)]
pub struct RawDb(RawDbContents);

impl RawDb {
    /// Get raw database by dumping database data
    pub fn from_db<B: Backend, Sch: Schema>(storage: &Storage<B, Sch>) -> crate::Result<Self> {
        let dbtx = storage.transaction_ro()?;
        Sch::desc_iter()
            .enumerate()
            .map(|(idx, dbinfo)| {
                let items = dbtx.dbtx.prefix_iter(DbIndex::new(idx), Vec::new())?;
                Ok((dbinfo.name, items.collect()))
            })
            .collect::<crate::Result<RawDbContents>>()
            .map(RawDb)
    }

    /// Get database contents
    pub fn contents(&self) -> &RawDbContents {
        &self.0
    }

    /// Take database contents
    pub fn into_contents(self) -> RawDbContents {
        self.0
    }
}

impl From<RawDbContents> for RawDb {
    fn from(contents: RawDbContents) -> Self {
        RawDb(contents)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use storage_inmemory::InMemory;

    crate::decl_schema! {
        TestSchema {
            Db1: Map<u32, u32>,
            Db2: Map<u16, Vec<u8>>,
        }
    }

    #[test]
    fn basic_dump() {
        utils::concurrency::model(|| {
            let storage = Storage::<_, TestSchema>::new(InMemory::new()).unwrap();

            {
                // Check the DB dump is empty initially
                let contents = storage.dump_raw().unwrap().into_contents();
                assert_eq!(contents.keys().collect::<Vec<_>>(), vec!["Db1", "Db2"]);
                assert!(contents.iter().all(|x| x.1.is_empty()));
            }

            // Add some valuex, check the dump contents
            let mut dbtx = storage.transaction_rw().unwrap();
            dbtx.get_mut::<Db1, _>().put(42, 1337).unwrap();
            dbtx.get_mut::<Db2, _>().put(21, vec![1, 2, 3, 4]).unwrap();
            dbtx.commit().unwrap();

            {
                let contents = storage.dump_raw().unwrap().into_contents();
                assert_eq!(contents.keys().collect::<Vec<_>>(), vec!["Db1", "Db2"]);
                assert_eq!(contents["Db1"].len(), 1);
                assert_eq!(contents["Db1"][[42, 0, 0, 0].as_ref()], vec![57, 5, 0, 0]);
                assert_eq!(contents["Db2"].len(), 1);
                assert_eq!(contents["Db2"][[21, 0].as_ref()], vec![4 << 2, 1, 2, 3, 4]);
            }

            // More modifications, check contents
            let mut dbtx = storage.transaction_rw().unwrap();
            dbtx.get_mut::<Db1, _>().del(42).unwrap();
            dbtx.get_mut::<Db2, _>().put(22, vec![1, 2]).unwrap();
            dbtx.commit().unwrap();

            {
                let contents = storage.dump_raw().unwrap().into_contents();
                assert_eq!(contents.keys().collect::<Vec<_>>(), vec!["Db1", "Db2"]);
                assert_eq!(contents["Db1"].len(), 0);
                assert_eq!(contents["Db2"].len(), 2);
                assert_eq!(contents["Db2"][[21, 0].as_ref()], vec![4 << 2, 1, 2, 3, 4]);
                assert_eq!(contents["Db2"][[22, 0].as_ref()], vec![2 << 2, 1, 2]);
            }
        })
    }
}
