use std::collections::BTreeMap;

use bitcoin::secp256k1;
use protobuf::MessageField;

use super::Trezor;
use crate::{
    error::Result,
    protos::{
        self, mintlayer_tx_ack_output::MintlayerTxAckOutputWrapper,
        mintlayer_tx_ack_utxo_input::MintlayerTxAckInputWrapper,
        mintlayer_tx_request::MintlayerRequestType, MintlayerTxAckOutput, MintlayerTxAckUtxoInput,
        MintlayerTxInput, MintlayerTxOutput,
    },
    Error,
};

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode(pub [u8; 32]);

pub struct XPub {
    pub public_key: secp256k1::PublicKey,
    pub chain_code: ChainCode,
}

#[derive(Debug)]
pub struct MintlayerSignature {
    pub signature: Vec<u8>,
    pub multisig_idx: Option<u32>,
}

impl MintlayerSignature {
    fn new(signature: Vec<u8>, multisig_idx: Option<u32>) -> Self {
        Self { signature, multisig_idx }
    }
}

impl Trezor {
    // Mintlayer
    pub fn mintlayer_get_public_key(&mut self, path: Vec<u32>) -> Result<XPub> {
        let mut req = protos::MintlayerGetPublicKey::new();
        req.address_n = path;
        self.call::<_, _, protos::MintlayerPublicKey>(
            req,
            Box::new(|_, m| {
                Ok(XPub {
                    public_key: secp256k1::PublicKey::from_slice(m.public_key())?,
                    chain_code: ChainCode(
                        m.chain_code().try_into().map_err(|_| Error::InvalidChaincodeFromDevice)?,
                    ),
                })
            }),
        )?
        .ok()
    }

    pub fn mintlayer_sign_message(
        &mut self,
        path: Vec<u32>,
        address: String,
        message: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let mut req = protos::MintlayerSignMessage::new();
        req.address_n = path;
        req.set_message(message);
        req.set_address(address);
        let msg = self.call::<_, _, protos::MessageSignature>(
            req,
            Box::new(|_, m| Ok(m.signature().to_vec())),
        )?;
        msg.button_request()?.ack()?.button_request()?.ack()?.ok()
    }

    pub fn mintlayer_sign_tx(
        &mut self,
        inputs: Vec<MintlayerTxInput>,
        outputs: Vec<MintlayerTxOutput>,
        utxos: BTreeMap<[u8; 32], BTreeMap<u32, MintlayerTxOutput>>,
    ) -> Result<Vec<Vec<MintlayerSignature>>> {
        let mut req = protos::MintlayerSignTx::new();
        req.set_version(1);
        req.set_inputs_count(inputs.len() as u32);
        req.set_outputs_count(outputs.len() as u32);

        let mut msg = self.call::<_, _, protos::MintlayerTxRequest>(req, Box::new(|_, m| Ok(m)))?;
        let mut should_ack_button = 0;
        loop {
            if should_ack_button > 0 {
                msg = msg.button_request()?.ack()?;
                should_ack_button -= 1;
                continue;
            }

            let response = msg.ok()?;
            match response.request_type() {
                MintlayerRequestType::TXINPUT => {
                    let mut req = MintlayerTxAckInputWrapper::new();
                    req.input = MessageField::from_option(
                        inputs.get(response.details.request_index() as usize).cloned(),
                    );
                    let mut req2 = MintlayerTxAckUtxoInput::new();
                    req2.tx = MessageField::some(req);
                    msg = self
                        .call::<_, _, protos::MintlayerTxRequest>(req2, Box::new(|_, m| Ok(m)))?;
                }
                MintlayerRequestType::TXOUTPUT => {
                    let mut req = MintlayerTxAckOutputWrapper::new();
                    if response.details.has_tx_hash() {
                        let tx_id: [u8; 32] = response
                            .details
                            .tx_hash()
                            .try_into()
                            .map_err(|_| Error::InvalidChaincodeFromDevice)?;
                        let out = utxos
                            .get(&tx_id)
                            .and_then(|tx| tx.get(&response.details.request_index()));
                        req.output = MessageField::from_option(out.cloned());
                    } else {
                        req.output = MessageField::from_option(
                            outputs.get(response.details.request_index() as usize).cloned(),
                        );
                        should_ack_button += 2;
                        if response.details.request_index() as usize == outputs.len() - 1 {
                            should_ack_button += 1;
                        }
                    }
                    let mut req2 = MintlayerTxAckOutput::new();
                    req2.tx = MessageField::some(req);
                    msg = self
                        .call::<_, _, protos::MintlayerTxRequest>(req2, Box::new(|_, m| Ok(m)))?;
                }
                MintlayerRequestType::TXMETA => {
                    return Err(Error::MalformedMintlayerTxRequest(response))
                }
                MintlayerRequestType::TXFINISHED => {
                    return Ok(response
                        .serialized
                        .iter()
                        .map(|s| {
                            s.signatures
                                .iter()
                                .map(|s| {
                                    MintlayerSignature::new(s.signature().to_vec(), s.multisig_idx)
                                })
                                .collect()
                        })
                        .collect())
                }
            }
        }
    }
}
