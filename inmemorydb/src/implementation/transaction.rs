use generic_array::GenericArray;
use storage::{DataType, Storage, DBError};
use crate::implementation::IndexType;
use std::collections::BTreeMap;

enum DBOperation<V: DataType> {
    UniqueSet(V),
    Append(Vec<V>),
    Erase,
}

impl<V: DataType> DBOperation<V> {
    #[allow(dead_code)]
    pub fn collapse_operations(&mut self, source: DBOperation<V>) {
        match source {
            Self::UniqueSet(val) => {
                *self = Self::UniqueSet(val);
            }
            Self::Erase => {
                *self = Self::Erase;
            }
            Self::Append(source_vals) => {
                match self {
                    Self::Erase => {
                        *self = Self::Append(source_vals);
                    },
                    Self::Append(dest_vals) => {
                        dest_vals.extend(source_vals.into_iter());
                    },
                    Self::UniqueSet(dest_val) => {
                        let mut new_vec: Vec<V> = vec![dest_val.clone()];
                        new_vec.extend(source_vals);
                        *self = Self::Append(new_vec);
                    },
                }
            }
        }
    }
}

struct Transaction {
    data: GenericArray<BTreeMap<Vec<u8>, Vec<DBOperation<Vec<u8>>>>, storage::DBIndexCountT>,
}

impl Storage<IndexType> for Transaction {
    fn duplicates_allowed(_db_index: IndexType) -> bool {
        return false;
    }

    fn set<K: DataType, V: DataType>(
        &mut self,
        db_index: IndexType,
        key: K,
        val: V,
    ) -> Result<(), DBError> {
        self.data[db_index]
            .insert(key.as_ref().to_vec(), vec![DBOperation::UniqueSet(val.as_ref().to_vec())]);
        Ok(())
    }

    fn get<K: DataType>(
        &mut self,
        db_index: IndexType,
        key: K,
        offset: usize,
        size: Option<usize>,
    ) -> Result<Option<Vec<u8>>, DBError> {
        let m = &self.data[db_index];
        let result = m.get(&key.as_ref().to_vec());
        match result {
            Some(vv) => {
                if vv.is_empty() {
                    return Ok(None);
                } else {
                    let v = &vv[0];
                    if offset > v.len() {
                        return Ok(Some(vec![]));
                    }
                    let v = &v[offset..];
                    match size {
                        None => return Ok(Some(v.to_vec())),
                        Some(sz) => {
                            if sz > v.len() {
                                return Ok(Some(v.to_vec()));
                            } else {
                                return Ok(Some(v[..sz].to_vec()));
                            }
                        }
                    }
                }
            }
            None => return Ok(None),
        };
    }

    fn get_multiple<K: DataType>(
        &mut self,
        db_index: IndexType,
        key: K,
    ) -> Result<Vec<Vec<u8>>, DBError> {
        let m = &self.data[db_index];
        let result = m.get(&key.as_ref().to_vec());
        match result {
            Some(r) => return Ok(r.clone()),
            None => return Ok(Vec::new()),
        }
    }

    fn get_all(&mut self, db_index: IndexType) -> Result<BTreeMap<Vec<u8>, Vec<Vec<u8>>>, DBError> {
        let m = &self.data[db_index];
        Ok(m.clone())
    }

    fn get_all_unique(
        &mut self,
        db_index: IndexType,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DBError> {
        let m = &self.data[db_index];
        let mut result: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        m.iter().for_each(|(k, vv)| {
            if !vv.is_empty() {
                result.insert(k.clone(), vv[0].clone());
            }
        });
        Ok(result)
    }

    fn exists<K: DataType>(&mut self, db_index: IndexType, key: K) -> Result<bool, DBError> {
        let m = &self.data[db_index];
        let result = m.get(&key.as_ref().to_vec()).is_some();
        Ok(result)
    }

    fn append<K: DataType, V: DataType>(
        &mut self,
        db_index: IndexType,
        key: K,
        val: V,
    ) -> Result<(), DBError> {
        let m = &mut self.data[db_index];
        m.entry(key.as_ref().to_vec()).or_default().push(val.as_ref().to_vec());
        Ok(())
    }

    fn erase_one<K: DataType, V: DataType>(
        &mut self,
        db_index: IndexType,
        key: K,
        val: V,
    ) -> Result<(), DBError> {
        let m = &mut self.data[db_index];
        let result = m.get_mut(&key.as_ref().to_vec());
        match result {
            Some(vv) => {
                vv.retain(|s| *s != val.as_ref().to_vec());
                return Ok(());
            }
            None => return Ok(()),
        }
    }

    fn erase<K: DataType>(&mut self, db_index: IndexType, key: K) -> Result<(), DBError> {
        let m = &mut self.data[db_index];
        m.remove(&key.as_ref().to_vec());
        Ok(())
    }

    fn clear_all(&mut self) -> Result<(), DBError> {
        self.data = GenericArray::default();
        Ok(())
    }

    fn clear_db(&mut self, db_index: IndexType) -> Result<(), DBError> {
        let m = &mut self.data[db_index];
        m.clear();
        Ok(())
    }

    fn begin_transaction(&mut self, _approximate_data_size: usize) -> Result<(), DBError> {
        panic!("Nested transactions are not allowed");
    }

    fn revert_transaction(&mut self) -> Result<(), DBError> {
        panic!("Nested transactions are not allowed");
    }

    fn commit_transaction(&mut self) -> Result<(), DBError> {
        panic!("Nested transactions are not allowed");
    }
}
