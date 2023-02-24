#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreeSize(usize);

const MAX_TREE_SIZE: usize = 1 << 31;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TreeSizeError {
    #[error("Zero is invalid size for tree")]
    ZeroSize,
    #[error("Tree size must be power of two minus one; this value was found: {0}")]
    InvalidSize(usize),
    #[error("Tree with this huge size is not supported: {0}")]
    HugeTreeUnsupported(usize),
}

impl TreeSize {
    pub fn get(&self) -> usize {
        self.0
    }

    pub fn leaf_count(&self) -> usize {
        (self.0 + 1) / 2
    }

    pub fn level_count(&self) -> usize {
        self.0.count_ones() as usize
    }

    pub fn from_value(value: usize) -> Result<Self, TreeSizeError> {
        Self::try_from(value)
    }
}

impl TryFrom<usize> for TreeSize {
    type Error = TreeSizeError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if value == 0 {
            Err(TreeSizeError::ZeroSize)
        } else if (value + 1).count_ones() != 1 {
            Err(TreeSizeError::InvalidSize(value))
        } else if value > MAX_TREE_SIZE {
            Err(TreeSizeError::HugeTreeUnsupported(value))
        } else {
            Ok(Self(value))
        }
    }
}

impl From<TreeSize> for usize {
    fn from(tree_size: TreeSize) -> Self {
        tree_size.0
    }
}

impl AsRef<usize> for TreeSize {
    fn as_ref(&self) -> &usize {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction() {
        assert_eq!(TreeSize::try_from(0), Err(TreeSizeError::ZeroSize));
        assert_eq!(TreeSize::try_from(1), Ok(TreeSize(1)));
        assert_eq!(TreeSize::try_from(2), Err(TreeSizeError::InvalidSize(2)));
        assert_eq!(TreeSize::try_from(3), Ok(TreeSize(3)));
        assert_eq!(TreeSize::try_from(4), Err(TreeSizeError::InvalidSize(4)));
        assert_eq!(TreeSize::try_from(5), Err(TreeSizeError::InvalidSize(5)));
        assert_eq!(TreeSize::try_from(6), Err(TreeSizeError::InvalidSize(6)));
        assert_eq!(TreeSize::try_from(7), Ok(TreeSize(7)));
        assert_eq!(TreeSize::try_from(8), Err(TreeSizeError::InvalidSize(8)));
        assert_eq!(TreeSize::try_from(9), Err(TreeSizeError::InvalidSize(9)));
        assert_eq!(TreeSize::try_from(10), Err(TreeSizeError::InvalidSize(10)));
        assert_eq!(TreeSize::try_from(11), Err(TreeSizeError::InvalidSize(11)));
        assert_eq!(TreeSize::try_from(12), Err(TreeSizeError::InvalidSize(12)));
        assert_eq!(TreeSize::try_from(13), Err(TreeSizeError::InvalidSize(13)));
        assert_eq!(TreeSize::try_from(14), Err(TreeSizeError::InvalidSize(14)));
        assert_eq!(TreeSize::try_from(15), Ok(TreeSize(15)));
        assert_eq!(TreeSize::try_from(16), Err(TreeSizeError::InvalidSize(16)));

        for i in 1..1000usize {
            if (i + 1).count_ones() == 1 {
                assert_eq!(TreeSize::try_from(i), Ok(TreeSize(i)));
                assert_eq!(TreeSize::from_value(i), Ok(TreeSize(i)));
            } else {
                assert_eq!(TreeSize::try_from(i), Err(TreeSizeError::InvalidSize(i)));
                assert_eq!(TreeSize::from_value(i), Err(TreeSizeError::InvalidSize(i)));
            }
        }
    }

    #[test]
    fn calculations() {
        let t1 = TreeSize::try_from(1).unwrap();
        assert_eq!(t1.leaf_count(), 1);
        assert_eq!(t1.level_count(), 1);

        let t3 = TreeSize::try_from(3).unwrap();
        assert_eq!(t3.leaf_count(), 2);
        assert_eq!(t3.level_count(), 2);

        let t7 = TreeSize::try_from(7).unwrap();
        assert_eq!(t7.leaf_count(), 4);
        assert_eq!(t7.level_count(), 3);

        let t15 = TreeSize::try_from(15).unwrap();
        assert_eq!(t15.leaf_count(), 8);
        assert_eq!(t15.level_count(), 4);

        let t31 = TreeSize::try_from(31).unwrap();
        assert_eq!(t31.leaf_count(), 16);
        assert_eq!(t31.level_count(), 5);

        let t63 = TreeSize::try_from(63).unwrap();
        assert_eq!(t63.leaf_count(), 32);
        assert_eq!(t63.level_count(), 6);

        let t127 = TreeSize::try_from(127).unwrap();
        assert_eq!(t127.leaf_count(), 64);
        assert_eq!(t127.level_count(), 7);

        let t255 = TreeSize::try_from(255).unwrap();
        assert_eq!(t255.leaf_count(), 128);
        assert_eq!(t255.level_count(), 8);
    }
}
