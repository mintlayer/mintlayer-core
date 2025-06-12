// Copyright (c) 2021-2025 RBB S.r.l
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

use randomness::{CryptoRng, Rng};

pub trait Secp256k1SchnorrAuxDataProvider {
    /// Return BIP-340's "auxiliary random data" that will eventually be passed as the `data` parameter
    /// to the `nonce_function_bip340` here:
    /// https://github.com/bitcoin-core/secp256k1/blob/f24b838bedffe19643fafd817b82fc49472d4877/src/modules/schnorrsig/main_impl.h#L52
    ///
    /// Note: using all-zeros array is safe and it's what Bitcoin Core does. Also, we do the same for Mintlayer in
    /// the Trezor firmware. But our software wallets use random aux data.
    /// TODO: consider using fixed aux data in software wallets too, so that they also produce deterministic signatures.
    fn get_secp256k1_schnorr_aux_data(&mut self) -> [u8; 32];
}

pub trait SigAuxDataProvider: Secp256k1SchnorrAuxDataProvider {}

impl<T> SigAuxDataProvider for T where T: Secp256k1SchnorrAuxDataProvider {}

impl<R> Secp256k1SchnorrAuxDataProvider for R
where
    R: Rng + CryptoRng,
{
    fn get_secp256k1_schnorr_aux_data(&mut self) -> [u8; 32] {
        self.gen()
    }
}

/// The aux data provider that returns all zeroes in its `get_secp256k1_schnorr_aux_data`.
pub struct PredefinedSigAuxDataProvider;

impl Secp256k1SchnorrAuxDataProvider for PredefinedSigAuxDataProvider {
    fn get_secp256k1_schnorr_aux_data(&mut self) -> [u8; 32] {
        [0; 32]
    }
}
