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

#[macro_export]
macro_rules! newtype {
    ($(#[$meta:meta])* $vis:vis struct $name:ident($wrapped:ty);) => {
        $(#[$meta])*
        $vis struct $name($wrapped);

        impl $name {
            #[allow(dead_code)]
            pub fn new(inner: $wrapped) -> Self {
                Self(inner)
            }

            #[allow(dead_code)]
            pub fn inner(&self) -> &$wrapped {
                &self.0
            }

            #[allow(dead_code)]
            pub fn inner_mut(&mut self) -> &mut $wrapped {
                &mut self.0
            }

            #[allow(dead_code)]
            pub fn take(self) -> $wrapped {
                self.0
            }
        }

        impl From<$name> for $wrapped {
            fn from(newtype_instance: $name) -> Self {
                newtype_instance.0
            }
        }

        impl From<$wrapped> for $name {
            fn from(inner: $wrapped) -> Self {
                Self(inner)
            }
        }

        impl std::ops::Deref for $name {
            type Target = $wrapped;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

#[cfg(test)]
mod tests {
    #[derive(Clone, Debug)]
    struct Inner {
        val: u32,
    }

    impl Inner {
        fn new() -> Self {
            Self { val: 0 }
        }

        fn set(&mut self, val: u32) {
            self.val = val
        }

        fn get(&self) -> u32 {
            self.val
        }
    }

    newtype! {
        #[derive(Clone, Debug)]
        struct Wrapper(Inner);
    }

    #[test]
    fn test_new_type() {
        let inner = Inner::new();
        let mut wrapper = Wrapper::from(inner);

        let val = 7;
        wrapper.set(val);
        assert_eq!(wrapper.get(), val);
        assert_eq!(wrapper.inner().get(), val);
        assert_eq!(wrapper.inner_mut().get(), val);

        let val = 8;
        wrapper.inner_mut().set(val);
        assert_eq!(wrapper.get(), val);
        assert_eq!(wrapper.inner().get(), val);
        assert_eq!(wrapper.inner_mut().get(), val);

        let wrapper_clone = wrapper.clone();
        let taken_inner = wrapper_clone.take();
        assert_eq!(taken_inner.get(), val);

        let inner_again = Inner::from(wrapper);
        assert_eq!(inner_again.get(), val);
    }
}
