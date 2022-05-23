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

use crypto::key::Signature;
use parity_scale_codec::{Decode, Encode};

use crate::{chain::signature::TransactionSigError, primitives::H256};

#[derive(Debug, Encode, Decode)]
pub struct AuthorizedPublicKeySpend {
    signature: Signature,
}

impl AuthorizedPublicKeySpend {
    pub fn from_data(data: &Vec<u8>) -> Result<Self, TransactionSigError> {
        let decoded = AuthorizedPublicKeySpend::decode(&mut data.as_slice())
            .map_err(|_| TransactionSigError::InvalidSignatureEncoding)?;
        Ok(decoded)
    }

    pub fn new(signature: Signature) -> Self {
        Self { signature }
    }
}

pub fn verify_public_key_spending(
    spendee_pubkey: &crypto::key::PublicKey,
    spender_signature: &AuthorizedPublicKeySpend,
    sighash: &H256,
) -> Result<(), TransactionSigError> {
    let msg = sighash.encode();
    if !spendee_pubkey.verify_message(&spender_signature.signature, &msg) {
        return Err(TransactionSigError::SignatureVerificationFailed);
    }
    Ok(())
}

pub fn sign_pubkey_spending(
    private_key: &crypto::key::PrivateKey,
    spendee_pubkey: &crypto::key::PublicKey,
    sighash: &H256,
) -> Result<AuthorizedPublicKeySpend, TransactionSigError> {
    let calculated_public_key = crypto::key::PublicKey::from_private_key(private_key);
    if *spendee_pubkey != calculated_public_key {
        return Err(TransactionSigError::SpendeePrivatePublicKeyMismatch);
    }
    let msg = sighash.encode();
    let signature = private_key
        .sign_message(&msg)
        .map_err(TransactionSigError::ProducingSignatureFailed)?;

    Ok(AuthorizedPublicKeySpend::new(signature))
}

// TODO: tests
