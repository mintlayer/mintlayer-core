use generic_array::GenericArray;
use std::collections::BTreeMap;
use std::sync::Mutex;
use storage::{DBError, Storage};

struct InMemoryDB {
    data: GenericArray<Mutex<BTreeMap<Vec<u8>, Vec<Vec<u8>>>>, storage::DBIndexCountT>,
}

#[allow(dead_code)]
impl InMemoryDB {
    pub fn new() -> Self {
        InMemoryDB {
            data: GenericArray::default()
        }
    }
}

type IndexType = usize;

const MTX_ERR: &str = "Mutex lock should never fail";

impl Storage<IndexType> for InMemoryDB {
    fn duplicates_allowed(_db_index: IndexType) -> bool {
        return false;
    }

    fn set<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db_index: IndexType,
        key: K,
        val: V,
    ) -> Result<(), DBError> {
        self.data[db_index]
            .lock()
            .expect(MTX_ERR)
            .insert(key.as_ref().to_vec(), vec![val.as_ref().to_vec()]);
        Ok(())
    }

    fn get<K: AsRef<[u8]>>(
        &mut self,
        db_index: IndexType,
        key: K,
        offset: usize,
        size: Option<usize>,
    ) -> Result<Option<Vec<u8>>, DBError> {
        let m = self.data[db_index].lock().expect(MTX_ERR);
        let result = m.get(&key.as_ref().to_vec());
        match result {
            Some(vv) => {
                if vv.is_empty() {
                    return Ok(None);
                } else {
                    let v = vv[0].as_slice();
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

    fn get_multiple<K: AsRef<[u8]>>(
        &mut self,
        db_index: IndexType,
        key: K,
    ) -> Result<Vec<Vec<u8>>, DBError> {
        let m = self.data[db_index].lock().expect(MTX_ERR);
        let result = m.get(&key.as_ref().to_vec());
        match result {
            Some(r) => return Ok(r.clone()),
            None => return Ok(Vec::new()),
        }
    }

    fn get_all(&mut self, db_index: IndexType) -> Result<BTreeMap<Vec<u8>, Vec<Vec<u8>>>, DBError> {
        let m = self.data[db_index].lock().expect(MTX_ERR);
        Ok(m.clone())
    }

    fn get_all_unique(
        &mut self,
        db_index: IndexType,
    ) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, DBError> {
        let m = self.data[db_index].lock().expect(MTX_ERR);
        let mut result: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        m.iter().for_each(|(k, vv)| {
            if !vv.is_empty() {
                result.insert(k.clone(), vv[0].clone());
            }
        });
        Ok(result)
    }

    fn exists<K: AsRef<[u8]>>(&mut self, db_index: IndexType, key: K) -> Result<bool, DBError> {
        let m = self.data[db_index].lock().expect(MTX_ERR);
        let result = m.get(&key.as_ref().to_vec()).is_some();
        Ok(result)
    }

    fn append<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db_index: IndexType,
        key: K,
        val: V,
    ) -> Result<(), DBError> {
        let mut m = self.data[db_index].lock().expect(MTX_ERR);
        m.entry(key.as_ref().to_vec()).or_default().push(val.as_ref().to_vec());
        Ok(())
    }

    fn erase_one<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        db_index: IndexType,
        key: K,
        val: V,
    ) -> Result<(), DBError> {
        let mut m = self.data[db_index].lock().expect(MTX_ERR);
        let result = m.get_mut(&key.as_ref().to_vec());
        match result {
            Some(vv) => {
                vv.retain(|s| *s != val.as_ref().to_vec());
                return Ok(());
            }
            None => return Ok(()),
        }
    }

    fn erase<K: AsRef<[u8]>>(&mut self, db_index: IndexType, key: K) -> Result<(), DBError> {
        let mut m = self.data[db_index].lock().expect(MTX_ERR);
        m.remove(&key.as_ref().to_vec());
        Ok(())
    }

    fn clear_all(&mut self) -> Result<(), DBError> {
        self.data = GenericArray::default();
        Ok(())
    }

    fn clear_db(&mut self, db_index: IndexType) -> Result<(), DBError> {
        let mut m = self.data[db_index].lock().expect(MTX_ERR);
        m.clear();
        Ok(())
    }

    fn begin_transaction(&mut self, _approximate_data_size: usize) -> Result<(), DBError> {
        Err(DBError::Unknown)
    }

    fn revert_transaction(&mut self) -> Result<(), DBError> {
        Err(DBError::Unknown)
    }

    fn commit_transaction(&mut self) -> Result<(), DBError> {
        Err(DBError::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use storage::Storage;

    use super::InMemoryDB;

    #[test]
    fn set_get_simple() {
        let mut db = InMemoryDB::new();
        assert!(db.set(0, vec![0x10, 0x20], vec![0x30, 0x40]).is_ok());
        assert_eq!(db.get(0, vec![0x10, 0x20], 0, None).unwrap(), Some(vec![0x30, 0x40]))
    }
}
