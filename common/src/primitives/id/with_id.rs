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

//! ID caching mechanism

use super::{Id, Idable};
use serialization::{WrapperTypeDecode, WrapperTypeEncode};

/// An object together with its pre-calculated ID.
///
/// This only allows immutable access to the underlying object to prevent it from going out of sync
/// with the ID, which is calculated for its contents. Getting an ID just returns the stored one.
#[derive(Clone, Debug)]
pub struct WithId<T: Idable> {
    id: Id<T::Tag>,
    object: T,
}

impl<T: Idable> WithId<T> {
    /// Get a reference to the underlying object
    pub fn get(this: &Self) -> &T {
        &this.object
    }

    /// Get the pre-calculated object ID
    pub fn id(this: &Self) -> Id<T::Tag> {
        this.id
    }

    /// Take ownership of the underlying object
    pub fn take(this: Self) -> T {
        this.object
    }
}

impl<T: Idable> WithId<T> {
    pub fn new(object: T) -> Self {
        let id = object.get_id();
        Self { id, object }
    }
}

impl<T: Idable> Idable for WithId<T> {
    type Tag = T::Tag;
    fn get_id(&self) -> Id<Self::Tag> {
        Self::id(self)
    }
}

impl<T: Idable> AsRef<T> for WithId<T> {
    fn as_ref(&self) -> &T {
        Self::get(self)
    }
}

// Implement Deref to the wrapped type but not DerefMut to prevent it from being modified.
impl<T: Idable> std::ops::Deref for WithId<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T: Idable> From<T> for WithId<T> {
    fn from(t: T) -> Self {
        WithId::new(t)
    }
}

/// Implement a marker trait for decoding WithId wrapper type.
/// The decoding of such type is assumed to be the same as
/// the wrapped type.
impl<T: Idable> WrapperTypeDecode for WithId<T> {
    type Wrapped = T;
}

/// Implement a marker trait that tells the encoder that
/// WithId is a wrapper type and only the wrapped T
/// would be encoded and not the id property.
impl<T: Idable> WrapperTypeEncode for WithId<T> {}

#[cfg(test)]
mod test {
    use super::*;
    use serialization::{Decode, DecodeAll, Encode};
    use typename::TypeName;

    #[derive(Eq, PartialEq, Debug, Clone, Encode, Decode, TypeName)]
    struct TestStruct {
        num: u64,
        blurb: String,
    }

    impl Idable for TestStruct {
        type Tag = TestStruct;
        fn get_id(&self) -> Id<Self::Tag> {
            Id::new(super::super::hash_encoded(self))
        }
    }

    #[test]
    fn serialization() {
        let data = TestStruct {
            num: 1337,
            blurb: "Hello!".into(),
        };

        let data_clone = data.clone();
        let encoded = WithId::new(data).encode();
        let decoded = WithId::<TestStruct>::decode_all(&mut encoded.as_slice()).unwrap();

        assert_eq!(data_clone.get_id(), decoded.get_id());
        assert_eq!(data_clone, WithId::take(decoded));
    }

    #[test]
    fn owned() {
        let data = TestStruct {
            num: 1337,
            blurb: "Hello!".into(),
        };

        let data_clone = data.clone();
        let wrapped = WithId::new(data);
        assert_eq!(data_clone.get_id(), wrapped.get_id());
        assert_eq!(data_clone, WithId::take(wrapped));
    }

    #[test]
    fn borrowed() {
        let data = TestStruct {
            num: 42,
            blurb: "Goodbye!".into(),
        };

        // Check it works with references too so IDs can be pre-calculated for borrowed data.
        let data_id = data.get_id();
        let wrapped: WithId<&TestStruct> = WithId::new(&data);
        assert_eq!(data_id, wrapped.get_id());
    }
}
