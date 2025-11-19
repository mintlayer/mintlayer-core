// Copyright (c) 2021-2024 RBB S.r.l
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

use common::{chain::config::MagicBytes, primitives::time::Time};

use networking::error::{MessageCodecError, NetworkingError};
use p2p_types::services::Services;

use crate::{
    error::{ConnectionValidationError, P2pError},
    protocol::MIN_SUPPORTED_PROTOCOL_VERSION,
};

/// The reason why a peer is being disconnected. This will be converted to string and sent
/// to the peer in a WillDisconnect message.
///
/// Note: the purpose of WillDisconnect is to make it possible for an honest node operator
/// to figure out whether there is something wrong with their node when a peer disconnects,
/// e.g. whether the node's address has been discouraged due to misbehavior.
// TODO: currently we're sending too much info to the peer:
// 1) Info that reveals node operator's actions:
//    E.g. NetworkingDisabled, AddressBanned - disabling networking and banning a peer are always
//    manual operations, so we're basically reporting what the node operator is doing.
//    Perhaps it'd be better to send ManualDisconnect instead when these actions are performed.
//    And for the case when an incoming connection is being rejected due to networking being
//    disabled or the peer banned, we could have a separate vague reason, e.g. "Connection rejected
//    due to node configuration".
// 2) Info about automatic maintenance actions.
//    E.g. PeerEvicted, FeelerConnection, TooManyInboundPeersAndXXX - all of them don't indicate
//    any problems on the peer's side, they're basically diagnostic messages, which reveal information
//    about the node's current state. Perhaps it'd be better to squash them all into one
//    MaintenanceDisconnect.
// Another alternative would be to squash all non-error-related reasons (i.e. from 1 and 2) into
// one vague reason, which would basically say "We're disconnecting you for our own internal reasons".
#[derive(derive_more::Display, Debug, Clone, PartialEq, Eq)]
pub enum DisconnectionReason {
    #[display("Your address is banned")]
    AddressBanned,

    #[display("Your address is discouraged")]
    AddressDiscouraged,

    #[display("You are evicted")]
    PeerEvicted,

    #[display("This was a feeler connection")]
    FeelerConnection,

    #[display("We think you are a self-connection")]
    ConnectionFromSelf,

    #[display("Manual disconnection")]
    ManualDisconnect,

    #[display("You ignore our ping requests")]
    PingIgnored,

    #[display("You ignore our sync requests")]
    SyncRequestsIgnored,

    #[display("Too many inbound connections and your address is discouraged")]
    TooManyInboundPeersAndThisOneIsDiscouraged,

    #[display("Too many inbound connections that can't be evicted")]
    TooManyInboundPeersAndCannotEvictAnyone,

    #[display("Unsupported protocol version, our min version is {}", *MIN_SUPPORTED_PROTOCOL_VERSION as u32)]
    UnsupportedProtocol,

    #[display("Your time {remote_time:?} is out of the acceptable range {accepted_peer_time:?}")]
    TimeDiff {
        remote_time: Time,
        accepted_peer_time: std::ops::RangeInclusive<Time>,
    },

    #[display("Wrong network; our network is '{our_network}'")]
    DifferentNetwork { our_network: MagicBytes },

    #[display("No common services")]
    NoCommonServices,

    #[display("Insufficient services, we need {needed_services:?}")]
    InsufficientServices { needed_services: Services },

    #[display("Networking disabled")]
    NetworkingDisabled,

    // Note: after a hard fork, some messages sent by updated nodes may no longer be decodable
    // by legacy nodes, even though the protocol version hasn't changed; e.g. this may happen if
    // a new transaction input or output type has been added. We want to inform the peer about
    // this fact and also provide some info about the message that we failed to decode.
    #[display("Your message cannot be decoded ({details})")]
    MessageCannonBeDecoded { details: String },

    // Another possible reason for message decoding failure.
    #[display("Your message size {actual_size} exceeded the maximum size {max_size}")]
    MessageTooLarge { actual_size: usize, max_size: usize },
}

impl DisconnectionReason {
    pub fn from_result<T>(res: &crate::Result<T>) -> Option<Self> {
        match res {
            Ok(_) => None,
            Err(err) => Self::from_error(err),
        }
    }

    pub fn from_networking_error(err: &NetworkingError) -> Option<Self> {
        match err {
            NetworkingError::IoError(_)
            | NetworkingError::NoiseHandshakeError(_)
            | NetworkingError::ProxyError(_)
            | NetworkingError::ChannelTransportError(_) => None,

            NetworkingError::MessageCodecError(err) => match err {
                // Note: technically we could put the entire MessageCodecError inside
                // Self::MessageCannonBeDecoded and avoid having the separate variant Self::MessageTooLarge.
                // But it's better to have finer control on what can be sent to other nodes via
                // DisconnectionReason.
                MessageCodecError::InvalidEncodedData(err) => {
                    // The serialization error contains some info about the message that we've failed
                    // to decode and we'd like to include that into the disconnection reason.
                    // Also, it doesn't contain anything sensitive, so we can just "to_string" it.

                    // But first make sure we're indeed dealing with `serialization::Error` here.
                    let err: &serialization::Error = err;

                    // Note: `serialization::Error` prints itself in a fancy way, where nested
                    // errors are put on separate lines and indented by tabs.
                    // Here we remove the tabs and replace newlines with spaces.
                    // TODO: improve parity-scale-codec's error printing (e.g. provide the alternate
                    // form that would put everything on one line) or expose its internals, so that
                    // the message can be constructed by the user code.
                    let err_str = err
                        .to_string()
                        .trim()
                        .chars()
                        .filter_map(|ch| (ch != '\t').then_some(if ch == '\n' { ' ' } else { ch }))
                        .collect();

                    Some(Self::MessageCannonBeDecoded { details: err_str })
                }
                MessageCodecError::MessageTooLarge {
                    actual_size,
                    max_size,
                } => Some(Self::MessageTooLarge {
                    actual_size: *actual_size,
                    max_size: *max_size,
                }),
            },
        }
    }

    pub fn from_error(err: &P2pError) -> Option<Self> {
        match err {
            P2pError::NetworkingError(err) => Self::from_networking_error(err),
            P2pError::ProtocolError(_)
            | P2pError::DialError(_)
            | P2pError::ChannelClosed
            | P2pError::PeerError(_)
            | P2pError::SubsystemFailure
            | P2pError::ChainstateError(_)
            | P2pError::StorageFailure(_)
            | P2pError::NoiseHandshakeError(_)
            | P2pError::InvalidConfigurationValue(_)
            | P2pError::InvalidStorageState(_)
            | P2pError::PeerDbStorageVersionMismatch { .. }
            | P2pError::MempoolError(_)
            | P2pError::SyncError(_) => None,
            P2pError::ConnectionValidationFailed(err) => match err {
                ConnectionValidationError::UnsupportedProtocol {
                    peer_protocol_version: _,
                } => Some(Self::UnsupportedProtocol),
                ConnectionValidationError::TimeDiff {
                    remote_time,
                    accepted_peer_time,
                } => Some(Self::TimeDiff {
                    remote_time: *remote_time,
                    accepted_peer_time: accepted_peer_time.clone(),
                }),
                ConnectionValidationError::DifferentNetwork {
                    our_network,
                    their_network: _,
                } => Some(Self::DifferentNetwork {
                    our_network: *our_network,
                }),
                ConnectionValidationError::TooManyInboundPeersAndThisOneIsDiscouraged => {
                    Some(Self::TooManyInboundPeersAndThisOneIsDiscouraged)
                }
                ConnectionValidationError::TooManyInboundPeersAndCannotEvictAnyone => {
                    Some(Self::TooManyInboundPeersAndCannotEvictAnyone)
                }
                ConnectionValidationError::AddressBanned { address: _ } => {
                    Some(Self::AddressBanned)
                }
                ConnectionValidationError::AddressDiscouraged { address: _ } => {
                    Some(Self::AddressDiscouraged)
                }
                ConnectionValidationError::NoCommonServices => Some(Self::NoCommonServices),
                ConnectionValidationError::InsufficientServices {
                    needed_services,
                    available_services: _,
                } => Some(Self::InsufficientServices {
                    needed_services: *needed_services,
                }),
                ConnectionValidationError::NetworkingDisabled => Some(Self::NetworkingDisabled),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use common::{
        chain::{
            output_value::OutputValue, signature::inputsig::InputWitness, SignedTransaction,
            Transaction, TxInput, TxOutput,
        },
        primitives::{Amount, VersionTag},
    };
    use networking::transport::MessageCodec;
    use serialization::{Decode, Encode};

    use crate::{message::TransactionResponse, net::default_backend::types::Message};

    use super::*;

    // The purpose of the test is to ensure that DisconnectionReason::MessageCannonBeDecoded's
    // string representation looks adequate.
    #[test]
    fn message_decoding_failure_test() {
        use message_decoding_failure_test_details::*;

        // Sanity check - correct message can be decoded.
        {
            let message = TestMessage::TransactionResponse(TestTransactionResponse::Found(
                TestSignedTransaction {
                    transaction: TestTransaction::V1(TestTransactionV1 {
                        version: VersionTag::default(),
                        flags: 0,
                        inputs: Vec::new(),
                        outputs: vec![TestTxOutput::Burn(OutputValue::Coin(Amount::ZERO))],
                    }),
                    signatures: Vec::new(),
                },
            ));
            let encoded_message = encode_msg(&message);
            let decoded_message = decode_msg::<Message>(encoded_message).unwrap();
            assert_eq!(
                decoded_message,
                Message::TransactionResponse(TransactionResponse::Found(
                    SignedTransaction::new(
                        Transaction::new(
                            0,
                            Vec::new(),
                            vec![TxOutput::Burn(OutputValue::Coin(Amount::ZERO))],
                        )
                        .unwrap(),
                        Vec::new()
                    )
                    .unwrap()
                ))
            );
        }

        // Decode incorrect message, convert the error to DisconnectionReason, expect
        // a particular string.
        {
            let message = TestMessage::TransactionResponse(TestTransactionResponse::Found(
                TestSignedTransaction {
                    transaction: TestTransaction::V1(TestTransactionV1 {
                        version: VersionTag::default(),
                        flags: 0,
                        inputs: Vec::new(),
                        outputs: vec![TestTxOutput::UnknownVariant],
                    }),
                    signatures: Vec::new(),
                },
            ));
            let encoded_message = encode_msg(&message);
            let err = decode_msg::<Message>(encoded_message).unwrap_err();

            let disconn_reason = DisconnectionReason::from_networking_error(&err).unwrap();

            assert_eq!(
                disconn_reason,
                DisconnectionReason::MessageCannonBeDecoded {
                    details: concat!(
                        "Could not decode `Message::TransactionResponse.0`: ",
                        "Could not decode `TransactionResponse::Found.0`: ",
                        "Could not decode `TransactionV1::outputs`: ",
                        "Could not decode `TxOutput`, variant doesn't exist"
                    )
                    .to_owned()
                }
            );
        }
    }

    mod message_decoding_failure_test_details {
        use bytes::{Bytes, BytesMut};
        use tokio_util::codec::{Decoder, Encoder};

        use serialization::{DecodeAll, DirectDecode, DirectEncode, Tagged};

        use super::*;

        // TestMessage is encode-compatible with Message, except for the UnknownVariant inside
        // the tx output enum.
        #[derive(Encode, Decode)]
        pub enum TestMessage {
            #[codec(index = 12)]
            TransactionResponse(TestTransactionResponse),
        }

        #[derive(Encode, Decode)]
        pub enum TestTransactionResponse {
            #[codec(index = 1)]
            Found(TestSignedTransaction),
        }

        #[derive(Encode, Decode)]
        pub struct TestSignedTransaction {
            pub transaction: TestTransaction,
            pub signatures: Vec<InputWitness>,
        }

        #[derive(DirectEncode, DirectDecode)]
        pub enum TestTransaction {
            V1(TestTransactionV1),
        }

        #[derive(Encode, Decode, Tagged)]
        pub struct TestTransactionV1 {
            pub version: VersionTag<1>,
            #[codec(compact)]
            pub flags: u128,
            pub inputs: Vec<TxInput>,
            pub outputs: Vec<TestTxOutput>,
        }

        #[derive(Encode, Decode)]
        pub enum TestTxOutput {
            #[codec(index = 2)]
            Burn(OutputValue),

            #[codec(index = 222)]
            UnknownVariant,
        }

        pub fn encode_msg<Msg: Encode>(msg: Msg) -> Vec<u8> {
            let mut codec = MessageCodec::<Msg>::new(None);
            let mut dest = BytesMut::new();
            codec.encode(msg, &mut dest).unwrap();
            dest.into()
        }

        pub fn decode_msg<Msg: DecodeAll>(bytes: Vec<u8>) -> Result<Msg, NetworkingError> {
            let mut codec = MessageCodec::<Msg>::new(None);
            let bytes: Bytes = bytes.into();
            codec.decode(&mut bytes.into()).map(|opt| opt.unwrap())
        }
    }
}
