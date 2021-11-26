use storage::DataType;

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
