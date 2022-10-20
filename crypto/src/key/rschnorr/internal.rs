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

#[cfg(test)]
mod test {
    use crate::key::rschnorr::MLRistrettoPrivateKey;

    /// Ristretto scalars have a max value 2^255. This test checks that hashed messages above this value can still be
    /// signed as a result of applying modulo arithmetic on the challenge value
    #[test]
    fn challenge_from_invalid_scalar() {
        let mut rng = rand::thread_rng();
        let m = hex::decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .unwrap();
        let (s, _) = MLRistrettoPrivateKey::new(&mut rng);
        assert!(s.sign_message(&m).is_ok());
    }
}
