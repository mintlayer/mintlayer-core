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

use std::marker::PhantomData;

use enum_iterator::{all, Sequence};
use num_traits::cast::ToPrimitive;
use serialization::{Decode, Encode};

/// The status enum.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Encode, Decode)]
pub enum Status {
    Good,
    Bad,
    Unknown,
}

impl Status {
    pub fn new() -> Self {
        Status::Unknown
    }

    /// Set itself to Good or Bad based on the passed Result and then return the same Result back.
    pub fn update_from_result<T, E>(&mut self, result: Result<T, E>) -> Result<T, E> {
        match &result {
            Ok(_) => *self = Self::Good,
            Err(_) => *self = Self::Bad,
        }
        result
    }
}

/// Ternary logic "and": the result is Good, if both values are Good, Bad if any of the values
/// is Bad, and Unknown otherwise.
impl std::ops::BitAnd for Status {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Bad, _) | (_, Self::Bad) => Self::Bad,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Good, Self::Good) => Self::Good,
        }
    }
}

/// Ternary logic "or": the result is Bad, if both values are Bad, Good if any of the values
/// is Good, and Unknown otherwise.
impl std::ops::BitOr for Status {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Self::Good, _) | (_, Self::Good) => Self::Good,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Bad, Self::Bad) => Self::Bad,
        }
    }
}

// FIXME: a few notes:
// The Statuses struct below came out less "elegant" than I expected it to be.
// The idea was that the user would parameterize it with a simple numeric enum that contains
// indices of "status" fields, and the implementation will then choose the appropriate amount
// of storage for that amount of fields. Unfortunately, it doesn't seem to be possible
// in Rust currently, given the information that the enum_iterator::Sequence trait provides
// (namely, it provides the cardinality of the enum via an associated constant, and it's
// practically impossible to do any kind of specialization based on it).
// So, the current implementation requires the user to specify the size of the underlying
// storage explicitly.
// The other ugly part is that the proper correspondence between the enum's elements count and
// the size of the storage is only asserted at runtime currently. But this can be fixed by
// introducing a custom static_assert macro (the available const_assert won't work, see
// another FIXME below).
// Finally, yet another ugly part is that I had to "uglify" certain parts of the implementation
// in order to be able to declare constants of the Statuses type. I don't like how it came out
// in the end, so I'll probably abandon this idea (see another FIXME below).

/// A set of [Status]'es.
///
/// `NUM_BYTES` specifies the size in bytes of the underlying array (each Status field
/// requires 2 bits of storage, so the maximum number of fields will be `NUM_BYTES * 4`).
/// `IndexType` is supposed to be a trivial enum type that will be used to access
/// the fields. The enum must implement [Copy], [Clone], [num_traits::cast::ToPrimitive]
/// and (optionally) [enum_iterator::Sequence]. E.g.
/// ```
/// // Note that the derive macro that implements `num_traits::cast::ToPrimitive`
/// // is in a different crate `num_derive`.
/// use num_derive::ToPrimitive;
/// use enum_iterator::Sequence;
/// use utils::status::{Status, Statuses};
///
/// #[derive(Copy, Clone, ToPrimitive, Sequence)]
/// enum MyStatusField {
///     A,
///     B,
/// }
///
/// type MyStatuses = Statuses<1, MyStatusField>;
///
/// fn do_stuff() {
///     let mut statuses = MyStatuses::new_unknown();
///     # assert_eq!(statuses.all_good(), Status::Unknown);
///     statuses.set(MyStatusField::A, Status::Good);
///     statuses.set(MyStatusField::B, Status::Bad);
///     # assert_eq!(statuses.all_good(), Status::Bad);
/// }
/// # fn main() {
/// #   do_stuff();
/// # }
/// ```
#[derive(Debug, Clone, Copy, Encode, Decode)]
pub struct Statuses<const NUM_BYTES: usize, IndexType>([u8; NUM_BYTES], PhantomData<IndexType>)
where
    IndexType: ToPrimitive + Copy;

impl<const NUM_BYTES: usize, IndexType> Statuses<NUM_BYTES, IndexType>
where
    IndexType: ToPrimitive + Copy,
{
    pub const MAX_FIELDS: usize = NUM_BYTES * Self::FIELDS_PER_BYTE;

    // FIXME: below I pass IndexType by value everywhere for simplicity, but because of this,
    // IndexType is required to implement Copy. Is it a good idea though?

    // FIXME: it would be nice to check below that Self::MAX_FIELDS is >= IndexType::CARDINALITY
    // (assuming that IndexType's elements will all have distinct values).
    // But "const_assert" won't compile here, because it's not usable with values that depend
    // on generic parameters.
    // The alternative could be to implement a custom macro, like suggested here:
    // https://github.com/nvzqz/static-assertions/issues/40#issuecomment-846228355
    // or here:
    // https://github.com/nvzqz/static-assertions/issues/50

    pub const fn new_unknown() -> Self {
        Self::new_with_same_status(Status::Unknown)
    }

    pub const fn new_good() -> Self {
        Self::new_with_same_status(Status::Good)
    }

    pub const fn new_bad() -> Self {
        Self::new_with_same_status(Status::Bad)
    }

    // Note: this function is kind of ugly, because it sets bits that may never be set
    // by the normal `set` method (which is kind of confusing when you see it in the debugger)
    // (another implication of this is that we can no longer derive Eq for Statuses).
    // A nicer way to implement it would be to iterate over all possible values of IndexType,
    // but then it wouldn't be const anymore.
    // FIXME: probably it's better to abandon the idea of making "new" functions const.
    // And constants like BLOCK_STATUS_ALL_GOOD in chainstate can become lazy_static.
    pub const fn new_with_same_status(status: Status) -> Self {
        let status = Self::status_to_num(status);
        assert!(status <= Self::FIELD_MASK);

        let mut byte: u8 = 0;
        let mut i = 0;
        while i < Self::FIELDS_PER_BYTE {
            byte = (byte << Self::BITS_PER_FIELD) | (status as u8);
            i += 1;
        }

        Self([byte; NUM_BYTES], PhantomData)
    }

    pub fn get(&self, index: IndexType) -> Status {
        let (byte_idx, field_idx) = Self::get_byte_field_idx(index);
        let bit_shift = field_idx * Self::BITS_PER_FIELD;

        let val = self.0[byte_idx] as usize >> bit_shift & Self::FIELD_MASK;

        // Note: this unwrap can only fail if the memory got corrupted.
        Self::num_to_status(val).unwrap()
    }

    pub fn set(&mut self, index: IndexType, status: Status) {
        let (byte_idx, field_idx) = Self::get_byte_field_idx(index);
        let bit_shift = field_idx * Self::BITS_PER_FIELD;
        let field_mask = Self::FIELD_MASK << bit_shift;

        let val = Self::status_to_num(status);
        assert!(val <= Self::FIELD_MASK);

        self.0[byte_idx] = ((self.0[byte_idx] as usize & !field_mask) | (val << bit_shift)) as u8;
    }

    pub fn update_from_result<T, E>(
        &mut self,
        index: IndexType,
        result: Result<T, E>,
    ) -> Result<T, E> {
        let mut status = self.get(index);
        let result = status.update_from_result(result);
        self.set(index, status);
        result
    }

    const BITS_PER_FIELD: usize = 2;
    const FIELD_MASK: usize = 0b11;
    const FIELDS_PER_BYTE: usize = 8 / Self::BITS_PER_FIELD;

    fn get_byte_field_idx(index: IndexType) -> (usize, usize) {
        let index = Self::validate_index(index);
        (index / Self::FIELDS_PER_BYTE, index % Self::FIELDS_PER_BYTE)
    }

    fn validate_index(index: IndexType) -> usize {
        // Note: this "expect" can only fail if the index is negative
        let index = index.to_usize().expect("can't convert the index to usize");
        assert!(index < Self::MAX_FIELDS);
        index
    }

    // Note: the whole purpose of implementing these functions by hand (instead of deriving
    // To/FromPrimitive for Status) was to be able to make status_to_num const (because the "new"
    // functions use it).
    // FIXME: remove them if "new" will be made non-const.
    const fn status_to_num(status: Status) -> usize {
        match status {
            Status::Good => 0,
            Status::Bad => 1,
            Status::Unknown => 2,
        }
    }

    fn num_to_status(num: usize) -> Option<Status> {
        match num {
            0 => Some(Status::Good),
            1 => Some(Status::Bad),
            2 => Some(Status::Unknown),
            _ => None,
        }
    }
}

/// Functions that are only available if IndexType implements `Sequence`.
impl<const NUM_BYTES: usize, IndexType> Statuses<NUM_BYTES, IndexType>
where
    IndexType: ToPrimitive + Copy + Sequence,
{
    // Note: the unwraps below can only fail if the enum has zero elements.

    // FIXME: it would be nice to check below that IndexType::CARDINALITY is bigger than 0,
    // in order to formally ensure that the unwrap cannot fail. But a custom static_assert
    // is needed to do that.

    /// Combine all fields with the `&` operator and return the result.
    pub fn all_good(&self) -> Status {
        all::<IndexType>().map(|idx| self.get(idx)).reduce(|acc, e| acc & e).unwrap()
    }

    /// Combine all fields with the `|` operator and return the result.
    pub fn any_good(&self) -> Status {
        all::<IndexType>().map(|idx| self.get(idx)).reduce(|acc, e| acc | e).unwrap()
    }
}

impl<const NUM_BYTES: usize, IndexType> PartialEq for Statuses<NUM_BYTES, IndexType>
where
    IndexType: ToPrimitive + Copy + Sequence,
{
    fn eq(&self, other: &Self) -> bool {
        all::<IndexType>()
            .map(|idx| self.get(idx) == other.get(idx))
            .fold(true, |acc, x| acc & x)
    }
}

impl<const NUM_BYTES: usize, IndexType> Eq for Statuses<NUM_BYTES, IndexType> where
    IndexType: ToPrimitive + Copy + Sequence
{
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_derive::ToPrimitive;

    #[test]
    fn test_status_operators() {
        assert_eq!(Status::Good & Status::Good, Status::Good);
        assert_eq!(Status::Good & Status::Unknown, Status::Unknown);
        assert_eq!(Status::Good & Status::Bad, Status::Bad);
        assert_eq!(Status::Unknown & Status::Good, Status::Unknown);
        assert_eq!(Status::Unknown & Status::Unknown, Status::Unknown);
        assert_eq!(Status::Unknown & Status::Bad, Status::Bad);
        assert_eq!(Status::Bad & Status::Good, Status::Bad);
        assert_eq!(Status::Bad & Status::Unknown, Status::Bad);
        assert_eq!(Status::Bad & Status::Bad, Status::Bad);

        assert_eq!(Status::Good | Status::Good, Status::Good);
        assert_eq!(Status::Good | Status::Unknown, Status::Good);
        assert_eq!(Status::Good | Status::Bad, Status::Good);
        assert_eq!(Status::Unknown | Status::Good, Status::Good);
        assert_eq!(Status::Unknown | Status::Unknown, Status::Unknown);
        assert_eq!(Status::Unknown | Status::Bad, Status::Unknown);
        assert_eq!(Status::Bad | Status::Good, Status::Good);
        assert_eq!(Status::Bad | Status::Unknown, Status::Unknown);
        assert_eq!(Status::Bad | Status::Bad, Status::Bad);
    }

    #[test]
    fn test_status_update_from_result() {
        let mut status = Status::Unknown;
        let result: Result<_, i32> = status.update_from_result(Ok(123));
        assert_eq!(result, Ok(123));
        assert_eq!(status, Status::Good);

        let mut status = Status::Unknown;
        let result: Result<i32, _> = status.update_from_result(Err(123));
        assert_eq!(result, Err(123));
        assert_eq!(status, Status::Bad);
    }

    #[derive(ToPrimitive, Copy, Clone, Sequence)]
    enum TestIndex {
        A,
        B,
        C,
        D,
        E,
    }

    type TestStatuses = Statuses<2, TestIndex>;

    #[test]
    fn test_statuses_status_num_conversion() {
        assert_eq!(
            TestStatuses::num_to_status(TestStatuses::status_to_num(Status::Good)).unwrap(),
            Status::Good
        );
        assert_eq!(
            TestStatuses::num_to_status(TestStatuses::status_to_num(Status::Bad)).unwrap(),
            Status::Bad
        );
        assert_eq!(
            TestStatuses::num_to_status(TestStatuses::status_to_num(Status::Unknown)).unwrap(),
            Status::Unknown
        );
    }

    #[test]
    fn test_statuses_new() {
        let statuses = TestStatuses::new_unknown();
        assert_eq!(statuses.get(TestIndex::A), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::B), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::C), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::D), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::E), Status::Unknown);

        let statuses = TestStatuses::new_good();
        assert_eq!(statuses.get(TestIndex::A), Status::Good);
        assert_eq!(statuses.get(TestIndex::B), Status::Good);
        assert_eq!(statuses.get(TestIndex::C), Status::Good);
        assert_eq!(statuses.get(TestIndex::D), Status::Good);
        assert_eq!(statuses.get(TestIndex::E), Status::Good);

        let statuses = TestStatuses::new_bad();
        assert_eq!(statuses.get(TestIndex::A), Status::Bad);
        assert_eq!(statuses.get(TestIndex::B), Status::Bad);
        assert_eq!(statuses.get(TestIndex::C), Status::Bad);
        assert_eq!(statuses.get(TestIndex::D), Status::Bad);
        assert_eq!(statuses.get(TestIndex::E), Status::Bad);
    }

    #[test]
    fn test_statuses() {
        let mut statuses = TestStatuses::new_unknown();

        statuses.set(TestIndex::B, Status::Good);
        statuses.set(TestIndex::E, Status::Bad);

        assert_eq!(statuses.get(TestIndex::A), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::B), Status::Good);
        assert_eq!(statuses.get(TestIndex::C), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::D), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::E), Status::Bad);
    }

    #[test]
    fn test_statuses_eq() {
        let unknown = TestStatuses::new_unknown();
        let good = TestStatuses::new_good();
        assert!(unknown != good);

        let mut good2 = unknown.clone();
        good2.set(TestIndex::A, Status::Good);
        good2.set(TestIndex::B, Status::Good);
        good2.set(TestIndex::C, Status::Good);
        good2.set(TestIndex::D, Status::Good);
        good2.set(TestIndex::E, Status::Good);

        assert!(unknown != good2);
        assert!(good == good2);
    }

    #[test]
    fn test_statuses_update_from_result() {
        let mut statuses = TestStatuses::new_unknown();

        let result: Result<_, i32> = statuses.update_from_result(TestIndex::B, Ok(123));
        assert_eq!(result, Ok(123));

        let result: Result<i32, _> = statuses.update_from_result(TestIndex::E, Err(123));
        assert_eq!(result, Err(123));

        assert_eq!(statuses.get(TestIndex::A), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::B), Status::Good);
        assert_eq!(statuses.get(TestIndex::C), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::D), Status::Unknown);
        assert_eq!(statuses.get(TestIndex::E), Status::Bad);
    }

    fn make_statuses(a: Status, b: Status, c: Status, d: Status, e: Status) -> TestStatuses {
        let mut statuses = TestStatuses::new_unknown();
        statuses.set(TestIndex::A, a);
        statuses.set(TestIndex::B, b);
        statuses.set(TestIndex::C, c);
        statuses.set(TestIndex::D, d);
        statuses.set(TestIndex::E, e);
        statuses
    }

    #[test]
    fn test_statuses_all_any() {
        use Status::*;

        assert_eq!(make_statuses(Good, Good, Good, Good, Good).all_good(), Good);
        assert_eq!(
            make_statuses(Good, Unknown, Good, Good, Good).all_good(),
            Unknown
        );
        assert_eq!(make_statuses(Good, Bad, Good, Good, Good).all_good(), Bad);

        assert_eq!(make_statuses(Bad, Bad, Bad, Bad, Bad).any_good(), Bad);
        assert_eq!(
            make_statuses(Bad, Unknown, Bad, Bad, Bad).any_good(),
            Unknown
        );
        assert_eq!(make_statuses(Bad, Good, Bad, Bad, Bad).any_good(), Good);
    }
}
