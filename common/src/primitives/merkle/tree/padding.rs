use crate::primitives::H256;

pub struct IncrementalPaddingIterator<I: Iterator<Item = H256>, F: Fn(&H256) -> H256> {
    leaves: I,
    padding_function: F,
    last_value: H256,
    current_index: usize,
}

impl<'a, I: Iterator<Item = H256>, F: Fn(&H256) -> H256> IncrementalPaddingIterator<I, F> {
    pub fn new(leaves: I, padding_function: F) -> Self {
        IncrementalPaddingIterator {
            leaves,
            padding_function,
            last_value: H256::zero(),
            current_index: 0,
        }
    }
}

impl<'a, I: Iterator<Item = H256>, F: Fn(&H256) -> H256> Iterator
    for IncrementalPaddingIterator<I, F>
{
    type Item = H256;

    fn next(&mut self) -> Option<H256> {
        match self.leaves.next() {
            None => {
                // index == 0 means that we have no leaves at all;
                // otherwise, we have to check if we have reached the next power of two to complete the padding.
                if self.current_index == self.current_index.next_power_of_two()
                    || self.current_index == 0
                {
                    None
                } else {
                    let res = (self.padding_function)(&self.last_value);
                    self.current_index = self.current_index + 1;
                    self.last_value = res;
                    Some(res)
                }
            }
            Some(leaf) => {
                self.current_index = self.current_index + 1;
                self.last_value = leaf.clone();
                Some(leaf)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::id::default_hash;

    use super::*;

    fn leaves_with_inc_padding(n: usize) -> Vec<H256> {
        let mut leaves = Vec::new();
        for i in 0..n {
            leaves.push(H256::from_low_u64_be(i as u64));
        }
        for _ in n..n.next_power_of_two() {
            leaves.push(default_hash(*leaves.last().unwrap()));
        }
        leaves
    }

    #[test]
    fn non_zero_size() {
        let f = |i: &H256| default_hash(i);

        for i in 1..130 {
            let all_leaves = leaves_with_inc_padding(i);
            let leaves = &leaves_with_inc_padding(i)[0..i];

            let vec =
                IncrementalPaddingIterator::new(leaves.to_vec().into_iter(), f).collect::<Vec<_>>();
            assert_eq!(vec, all_leaves);
        }
    }

    #[test]
    fn zero_size() {
        let f = |i: &H256| default_hash(i);

        let vec = IncrementalPaddingIterator::new(Vec::new().into_iter(), f).collect::<Vec<_>>();
        assert_eq!(vec, Vec::new());
    }
}
