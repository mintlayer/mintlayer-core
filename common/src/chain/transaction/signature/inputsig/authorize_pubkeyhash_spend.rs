// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach & L. Kuklinek

use crypto::key::{PublicKey, Signature};
use parity_scale_codec::{Decode, DecodeAll, Encode};

use crate::{
    address::pubkeyhash::PublicKeyHash, chain::signature::TransactionSigError, primitives::H256,
};

#[derive(Debug, Encode, Decode)]
pub struct AuthorizedPublicKeyHashSpend {
    public_key: PublicKey,
    signature: Signature,
}

impl AuthorizedPublicKeyHashSpend {
    pub fn from_data<T: AsRef<[u8]>>(data: T) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedPublicKeyHashSpend::decode_all(&mut data.as_ref())
            .map_err(|e| TransactionSigError::AddressAuthDecodingFailed(e.to_string()))?;
        Ok(decoded)
    }

    pub fn new(public_key: PublicKey, signature: Signature) -> Self {
        Self {
            public_key,
            signature,
        }
    }
}

pub fn verify_address_spending(
    spendee_addr: &PublicKeyHash,
    sig_components: &AuthorizedPublicKeyHashSpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let calculated_addr = PublicKeyHash::from(&sig_components.public_key);
    if calculated_addr != *spendee_addr {
        return Err(TransactionSigError::PublicKeyToAddressMismatch);
    }
    let msg = sighash.encode();
    if !sig_components.public_key.verify_message(&sig_components.signature, &msg) {
        return Err(TransactionSigError::SignatureVerificationFailed);
    }
    Ok(())
}

pub fn sign_address_spending(
    private_key: &crypto::key::PrivateKey,
    spendee_addr: &PublicKeyHash,
    sighash: &H256,
) -> Result<AuthorizedPublicKeyHashSpend, TransactionSigError> {
    let public_key = crypto::key::PublicKey::from_private_key(private_key);
    let calculated_addr = PublicKeyHash::from(&public_key);
    if calculated_addr != *spendee_addr {
        return Err(TransactionSigError::PublicKeyToAddressMismatch);
    }
    let msg = sighash.encode();
    let signature = private_key
        .sign_message(&msg)
        .map_err(TransactionSigError::ProducingSignatureFailed)?;

    Ok(AuthorizedPublicKeyHashSpend::new(public_key, signature))
}

// TODO: tests
