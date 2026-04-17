// Copyright (c) 2026 RBB S.r.l
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

/// An adapter that implements `rand` v0.8's `RngCore` and `CryptoRng` if the wrapped type implements
/// `Rng` and `CryptoRng` respectively.
pub struct Rng08Adapter<R>(pub R);

impl<R: crate::Rng> rand_0_8::RngCore for Rng08Adapter<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_0_8::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: crate::CryptoRng> rand_0_8::CryptoRng for Rng08Adapter<R> {}

/// An adapter that implements `rand` v0.9's `RngCore` and `CryptoRng` if the wrapped type implements
/// `Rng` and `CryptoRng` respectively.
pub struct Rng09Adapter<R>(pub R);

impl<R: crate::Rng> rand_0_9::RngCore for Rng09Adapter<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
}

impl<R: crate::CryptoRng> rand_0_9::CryptoRng for Rng09Adapter<R> {}
