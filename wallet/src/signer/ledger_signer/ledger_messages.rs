// Copyright (c) 2025 RBB S.r.l
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

use std::{collections::BTreeMap, time::Duration};

use crypto::key::{
    extended::ExtendedPublicKey,
    hdkd::{
        chain_code::{ChainCode, CHAINCODE_LENGTH},
        derivation_path::DerivationPath,
    },
    secp256k1::{extended_keys::Secp256k1ExtendedPublicKey, Secp256k1PublicKey},
};
use ledger_lib::Exchange;
use serialization::{Decode, DecodeAll, Encode};
use utils::ensure;

use crate::signer::{ledger_signer::LedgerError, SignerError, SignerResult};

const MAX_MSG_SIZE: usize = (u8::MAX - 5) as usize; // 4 bytes for the header + 1 for len
const TIMEOUT_DUR: Duration = Duration::from_secs(100);
const OK_RESPONSE: u16 = 0x9000;
const CLA: u8 = 0xE0;
const TX_VERSION: u8 = 1;

#[derive(Clone, Copy)]
pub enum LedgerAddrType {
    PublicKey,
    PublicKeyHash,
}

impl From<LedgerAddrType> for u8 {
    fn from(addr_type: LedgerAddrType) -> u8 {
        match addr_type {
            LedgerAddrType::PublicKey => 0,
            LedgerAddrType::PublicKeyHash => 1,
        }
    }
}

struct Ins {}

impl Ins {
    const APP_NAME: u8 = 0x04;
    const PUB_KEY: u8 = 0x05;
    const SIGN_TX: u8 = 0x06;
    const SIGN_MSG: u8 = 0x07;
}

struct P1 {}

impl P1 {
    const TX_META: u8 = 0;
    const TX_INPUT: u8 = 1;
    const TX_COMMITMENT: u8 = 2;
    const TX_OUTPUT: u8 = 3;
    const TX_SIG: u8 = 4;
}

struct P2 {}

impl P2 {
    const DONE: u8 = 0x00;
    const MORE: u8 = 0x80;
}

#[derive(Encode)]
pub struct LedgerBip32Path(pub Vec<u32>);

pub struct LedgerTxInput {
    pub inp: Vec<u8>,
    pub address_paths: Vec<LedgerInputAddressPath>,
}

pub struct LedgerTxInputCommitment {
    pub commitment: Vec<u8>,
}

pub struct LedgerTxOutput {
    pub out: Vec<u8>,
}

#[derive(Encode, Debug)]
pub struct LedgerInputAddressPath {
    pub address_n: Vec<u32>,
    pub multisig_idx: Option<u32>,
}

#[derive(Decode)]
pub struct LedgerSignature {
    pub signature: [u8; 64],
    pub multisig_idx: Option<u32>,
}

struct SignatureResult {
    sig: LedgerSignature,
    input_idx: usize,
    has_more_signatures: bool,
}

/// Check that the response ends with the OK status code and return the rest of the response back
fn ok_response(resp: Vec<u8>) -> SignerResult<Vec<u8>> {
    let (resp, status_code) = resp.split_last_chunk().ok_or(LedgerError::InvalidResponse)?;
    let response_status = u16::from_be_bytes(*status_code);

    ensure!(
        response_status == OK_RESPONSE,
        LedgerError::ErrorResponse(response_status)
    );

    Ok(resp.to_vec())
}

/// send a message to the Ledger and check the respons status code is ok
async fn exchange_message<L: Exchange>(
    ledger: &mut L,
    msg_buf: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let resp = ledger
        .exchange(msg_buf, TIMEOUT_DUR)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;
    ok_response(resp)
}

/// Send a message in chunks to the ledger as the max size of a message can be 255 bytes
async fn send_chunked<L: Exchange>(
    ledger: &mut L,
    ins: u8,
    step: u8,
    message: &[u8],
) -> Result<Vec<u8>, SignerError> {
    let mut msg_buf = vec![];
    let mut chunks = message.chunks(MAX_MSG_SIZE).peekable();
    let mut resp = vec![];
    while let Some(chunk) = chunks.next() {
        msg_buf.clear();

        let p2 = if chunks.peek().is_some() {
            P2::MORE
        } else {
            P2::DONE
        };

        msg_buf.extend([CLA, ins, step, p2]);
        msg_buf.push(chunk.len() as u8);
        msg_buf.extend(chunk);
        resp = exchange_message(ledger, &msg_buf).await?;
    }

    Ok(resp)
}

pub async fn sign_challenge<L: Exchange>(
    ledger: &mut L,
    chain_type: u8,
    path: &LedgerBip32Path,
    addr_type: LedgerAddrType,
    message: &[u8],
) -> SignerResult<Vec<u8>> {
    let mut msg_buf = vec![];

    msg_buf.extend([CLA, Ins::SIGN_MSG, 0, P2::MORE]);
    let body = path.encode();
    msg_buf.push(body.len() as u8 + 2);
    msg_buf.push(chain_type);
    msg_buf.push(addr_type.into());
    msg_buf.extend(body);

    exchange_message(ledger, &msg_buf).await?;

    let resp = send_chunked(ledger, Ins::SIGN_MSG, 1, message).await?;

    let sig_len = *resp.first().ok_or(LedgerError::InvalidResponse)? as usize;
    let sig = resp.as_slice().get(1..1 + sig_len).ok_or(LedgerError::InvalidResponse)?;

    Ok(sig.to_vec())
}

pub async fn get_app_name<L: Exchange>(ledger: &mut L) -> Result<Vec<u8>, ledger_lib::Error> {
    let msg_buf = [CLA, Ins::APP_NAME, 0, P2::DONE];
    ledger.exchange(&msg_buf, Duration::from_millis(100)).await
}

#[allow(dead_code)]
pub async fn check_current_app<L: Exchange>(ledger: &mut L) -> SignerResult<()> {
    let resp = get_app_name(ledger)
        .await
        .map_err(|err| LedgerError::DeviceError(err.to_string()))?;
    let resp = ok_response(resp)?;
    let name = String::from_utf8(resp).map_err(|_| LedgerError::InvalidResponse)?;

    ensure!(
        name == "mintlayer-app",
        LedgerError::DifferentActiveApp(name)
    );

    Ok(())
}

pub async fn get_extended_public_key<L: Exchange>(
    ledger: &mut L,
    chain_type: u8,
    derivation_path: DerivationPath,
) -> SignerResult<ExtendedPublicKey> {
    let address_n = LedgerBip32Path(
        derivation_path.as_slice().iter().map(|c| c.into_encoded_index()).collect(),
    );

    let mut msg_buf = vec![];
    msg_buf.extend([CLA, Ins::PUB_KEY, 0, P2::DONE]);
    let encoded_path = address_n.encode();
    let size: u8 = encoded_path.len().try_into().map_err(|_| LedgerError::PathToLong)?;
    msg_buf.push(size + 1);
    msg_buf.push(chain_type);
    msg_buf.extend(encoded_path);

    let resp = exchange_message(ledger, &msg_buf).await?;

    let pk_len = *resp.first().ok_or(LedgerError::InvalidResponse)? as usize;
    let public_key = resp.as_slice().get(1..1 + pk_len).ok_or(LedgerError::InvalidResponse)?;
    let chain_code_len = *resp.get(1 + pk_len).ok_or(LedgerError::InvalidResponse)? as usize;
    let chain_code: [_; CHAINCODE_LENGTH] = resp
        .as_slice()
        .get(2 + pk_len..2 + pk_len + chain_code_len)
        .ok_or(LedgerError::InvalidResponse)?
        .try_into()
        .map_err(|_| LedgerError::InvalidKey)?;

    let extended_public_key = Secp256k1ExtendedPublicKey::new_unchecked(
        derivation_path,
        ChainCode::from(chain_code),
        Secp256k1PublicKey::from_bytes(public_key).map_err(|_| LedgerError::InvalidKey)?,
    );

    Ok(ExtendedPublicKey::new(extended_public_key))
}

pub async fn sign_tx<L: Exchange>(
    ledger: &mut L,
    chain_type: u8,
    inputs: &[LedgerTxInput],
    input_commitments: &[LedgerTxInputCommitment],
    outputs: &[LedgerTxOutput],
) -> SignerResult<BTreeMap<usize, Vec<LedgerSignature>>> {
    let mut msg_buf = Vec::with_capacity(15);

    msg_buf.extend([CLA, Ins::SIGN_TX, P1::TX_META, P2::MORE]);
    msg_buf.push(1 + 1 + 4 + 4); // data len coin + version + 2 u32 lens
    msg_buf.push(chain_type);
    msg_buf.push(TX_VERSION);
    msg_buf.extend((inputs.len() as u32).to_be_bytes());
    msg_buf.extend((outputs.len() as u32).to_be_bytes());

    exchange_message(ledger, &msg_buf).await?;

    for inp in inputs {
        let paths = inp.address_paths.encode();
        send_chunked(ledger, Ins::SIGN_TX, P1::TX_INPUT, &paths).await?;
        send_chunked(ledger, Ins::SIGN_TX, P1::TX_INPUT, &inp.inp).await?;
    }

    for c in input_commitments {
        send_chunked(ledger, Ins::SIGN_TX, P1::TX_COMMITMENT, &c.commitment).await?;
    }

    // the response from the last output will have the first signature returned
    let mut resp = vec![];
    for o in outputs {
        resp = send_chunked(ledger, Ins::SIGN_TX, P1::TX_OUTPUT, &o.out).await?;
    }

    let mut signatures: BTreeMap<_, Vec<_>> = BTreeMap::new();

    let msg_buf = [CLA, Ins::SIGN_TX, P1::TX_SIG, P2::DONE, 0];
    loop {
        let SignatureResult {
            sig,
            input_idx,
            has_more_signatures,
        } = decode_signature_response(&resp)?;

        signatures.entry(input_idx).or_default().push(sig);

        if !has_more_signatures {
            break;
        }

        resp = exchange_message(ledger, &msg_buf).await?;
    }

    Ok(signatures)
}

fn decode_signature_response(resp: &[u8]) -> Result<SignatureResult, LedgerError> {
    let input_idx = *resp.first().ok_or(LedgerError::InvalidResponse)? as usize;
    let has_more_signatures = *resp.last().ok_or(LedgerError::InvalidResponse)? == P2::MORE;

    let sig = LedgerSignature::decode_all(&mut &resp[..resp.len() - 1][1..])
        .map_err(|_| LedgerError::InvalidResponse)?;

    Ok(SignatureResult {
        sig,
        input_idx,
        has_more_signatures,
    })
}
