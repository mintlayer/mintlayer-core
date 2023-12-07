// Copyright (c) 2021-2023 RBB S.r.l
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

#[derive(Clone, Debug)]
pub struct Array2d<T> {
    array: Vec<T>,
    rows_count: usize,
    cols_count: usize,
}

impl<T> Array2d<T> {
    pub fn new(rows_count: usize, cols_count: usize, init: T) -> Self
    where
        T: Clone,
    {
        Self {
            array: vec![init; rows_count * cols_count],
            rows_count,
            cols_count,
        }
    }

    pub fn rows_count(&self) -> usize {
        self.rows_count
    }

    pub fn cols_count(&self) -> usize {
        self.cols_count
    }

    pub fn rows(&self) -> impl Iterator<Item = &[T]> {
        self.array.chunks_exact(self.cols_count)
    }

    pub fn rows_mut(&mut self) -> impl Iterator<Item = &mut [T]> {
        self.array.chunks_exact_mut(self.cols_count)
    }
}

impl<T> std::ops::Index<usize> for Array2d<T> {
    type Output = [T];

    fn index(&self, row_idx: usize) -> &Self::Output {
        assert!(row_idx < self.rows_count);
        let start = row_idx * self.cols_count;
        let end = start + self.cols_count;
        &self.array[start..end]
    }
}

impl<T> std::ops::IndexMut<usize> for Array2d<T> {
    fn index_mut(&mut self, row_idx: usize) -> &mut Self::Output {
        assert!(row_idx < self.rows_count);
        let start = row_idx * self.cols_count;
        let end = start + self.cols_count;
        &mut self.array[start..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let mut array = Array2d::new(2, 3, 0u32);
        assert_eq!(array.array, vec![0u32; 6]);
        assert_eq!(array.rows_count, 2);
        assert_eq!(array.cols_count, 3);

        let rows = array.rows().map(<[_]>::as_ptr_range).collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], array.array[0..3].as_ptr_range());
        assert_eq!(rows[1], array.array[3..6].as_ptr_range());

        let rows_mut = array.rows_mut().map(<[_]>::as_mut_ptr_range).collect::<Vec<_>>();
        assert_eq!(rows_mut.len(), 2);
        assert_eq!(rows_mut[0], array.array[0..3].as_mut_ptr_range());
        assert_eq!(rows_mut[1], array.array[3..6].as_mut_ptr_range());

        array[0][0] = 1;
        array[0][1] = 2;
        array[0][2] = 3;
        array[1][0] = 4;
        array[1][1] = 5;
        array[1][2] = 6;
        assert_eq!(array.array, vec![1, 2, 3, 4, 5, 6]);

        let array = array;
        assert_eq!(array[0][0], 1);
        assert_eq!(array[0][1], 2);
        assert_eq!(array[0][2], 3);
        assert_eq!(array[1][0], 4);
        assert_eq!(array[1][1], 5);
        assert_eq!(array[1][2], 6);
    }

    #[test]
    #[should_panic]
    fn row_index_out_of_range() {
        let array = Array2d::new(2, 3, 0u32);
        let _ = array[2][0];
    }

    #[test]
    #[should_panic]
    fn col_index_out_of_range() {
        let array = Array2d::new(3, 2, 0u32);
        let _ = array[0][2];
    }
}
