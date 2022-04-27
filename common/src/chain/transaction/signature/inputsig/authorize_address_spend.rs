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
use parity_scale_codec::{Decode, Encode};

use crate::{
    address::Address,
    chain::{signature::TransactionSigError, ChainConfig},
    primitives::H256,
};

#[derive(Debug, Encode, Decode)]
pub struct AuthorizedAddressSpend {
    public_key: PublicKey,
    signature: Signature,
}

impl AuthorizedAddressSpend {
    pub fn from_data(data: &Vec<u8>) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedAddressSpend::decode(&mut data.as_slice())
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
    chain_config: &ChainConfig,
    spendee_addr: &crate::address::Address,
    sig_components: &AuthorizedAddressSpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let calculated_addr = Address::from_public_key(chain_config, &sig_components.public_key)
        .map_err(|e| TransactionSigError::PublicKeyToAddressConversionFailed(e))?;
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
    chain_config: &ChainConfig,
    spendee_addr: &crate::address::Address,
    sighash: &H256,
) -> Result<AuthorizedAddressSpend, TransactionSigError> {
    let public_key = crypto::key::PublicKey::from_private_key(private_key);
    let calculated_addr = Address::from_public_key(chain_config, &public_key)
        .map_err(TransactionSigError::PublicKeyToAddressConversionFailed)?;
    if calculated_addr != *spendee_addr {
        return Err(TransactionSigError::PublicKeyToAddressMismatch);
    }
    let msg = sighash.encode();
    let signature = private_key
        .sign_message(&msg)
        .map_err(TransactionSigError::ProducingSignatureFailed)?;

    Ok(AuthorizedAddressSpend::new(public_key, signature))
}

// TODO: tests
