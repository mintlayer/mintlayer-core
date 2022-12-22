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

use crate::key::secp256k1::extended_keys::{
    Secp256k1ExtendedPrivateKey, Secp256k1ExtendedPublicKey,
};
use crate::key::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use serialization::{Decode, Encode};

use super::rschnorr::{MLRistrettoPrivateKey, MLRistrettoPublicKey};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum PrivateKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(Secp256k1PrivateKey),
    #[codec(index = 1)]
    RistrettoSchnorr(MLRistrettoPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub enum PublicKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(Secp256k1PublicKey),
    #[codec(index = 1)]
    RistrettoSchnorr(MLRistrettoPublicKey),
}

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub enum ExtendedPrivateKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(Secp256k1ExtendedPrivateKey),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Decode, Encode)]
pub enum ExtendedPublicKeyHolder {
    #[codec(index = 0)]
    Secp256k1Schnorr(Secp256k1ExtendedPublicKey),
}
