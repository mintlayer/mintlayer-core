// Copyright (c) 2021-2022 RBB S.r.l
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

//! Context provide interface between script engine and blockchain

/// Result of parsing data with possible future extensions.
#[derive(PartialEq, Eq, Debug)]
pub enum ParseResult<T> {
    /// Decoding successful
    Ok(T),
    /// Decoding failed
    Err,
    /// Reserved for future extensions
    Reserved,
}

impl<T> From<Option<T>> for ParseResult<T> {
    fn from(o: Option<T>) -> Self {
        o.map_or(ParseResult::Err, ParseResult::Ok)
    }
}

/// Context for the script interpreter.
///
/// This trait defines how the interpreter interfaces with the blockchain. It allows the client
/// to adjust the behaviour of the interpreter by having pluggable signature verification routines
/// and by selectively enabling various interpreter features. It is expected that all data the
/// interpreter takes as implicit inputs (such as transaction hashes that the signatures sign,
/// block height for time locks, etc.) are provided by a type that implements Context.
///
/// ## TODO
///
/// * This interface is currently rather monolithic. It may be sensible to break it down into
///   multiple smaller ones for greater flexibility in the future.
/// * The interface is not fully finalized. It is likely to change as new requirements come in. E.g.
///   it may be currently too limited to support signature batching.
/// * The constants may be turned into methods to allow chain forks.
pub trait Context {
    /// Maximum number of bytes pushable to the stack
    const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

    /// Maximum number of elements on the stack
    const MAX_STACK_ELEMENTS: usize = 1000;

    /// Maximum number of public keys per multisig
    const MAX_PUBKEYS_PER_MULTISIG: usize;

    /// Maximum script length in bytes
    const MAX_SCRIPT_SIZE: usize;

    /// Public key type.
    type Public;

    /// Data needed to verify a signature. This probably contains signature, public key, sighash
    /// if used and other data used for verification.
    type SignatureData;

    /// Extract a pubkey and check it is in the correct format.
    fn parse_pubkey(&self, pk: &[u8]) -> ParseResult<Self::Public>;

    /// Extract a signature and check it is in the correct format. Pubkey is provided since it may
    /// determine signature format and is likely to be included in the result.
    fn parse_signature(&self, pk: Self::Public, sig: &[u8]) -> Option<Self::SignatureData>;

    /// Verify signature.
    fn verify_signature(
        &self,
        sig: &Self::SignatureData,
        subscript: &[u8],
        codesep_idx: u32,
    ) -> bool;

    /// Check absolute time lock.
    fn check_lock_time(&self, _lock_time: i64) -> bool {
        true
    }

    /// Check relative time lock.
    fn check_sequence(&self, _sequence: i64) -> bool {
        true
    }

    /// Enforce minimal push.
    fn enforce_minimal_push(&self) -> bool {
        true
    }

    /// Force the condition for OP_(NOT)IF to be either `[]` or `[0x01]`, fail script otherwise.
    fn enforce_minimal_if(&self) -> bool {
        true
    }
}

// A test context implementation.
// Used for testing and as an example of what a Context might look like.
#[cfg(any(test, feature = "testcontext"))]
pub mod testcontext {

    use super::*;
    use crate::util::sha256;
    use core::convert::TryFrom;

    /// Test context.
    ///
    /// The Context implementation for testing. The transaction hash (just 4 bytes for testing) has
    /// to be provided explicitly as a byte string. Signature scheme is very simple: The bitwise xor
    /// of transaction hash, signature and public key has to be equal to zero. Not recommended for
    /// production.
    #[derive(Default)]
    pub struct TestContext {
        pub transaction: Vec<u8>,
        pub block_height: u64,
    }

    impl TestContext {
        /// New test context
        pub fn new(transaction: Vec<u8>) -> Self {
            Self {
                transaction,
                block_height: 0,
            }
        }

        /// New test context at particular block height
        pub fn new_at_height(transaction: Vec<u8>, block_height: u64) -> Self {
            Self {
                transaction,
                block_height,
            }
        }
    }

    impl Context for TestContext {
        const MAX_PUBKEYS_PER_MULTISIG: usize = 20;
        const MAX_SCRIPT_SIZE: usize = 10000;

        // Signatures, keys and transaction IDs are just 4-byte binary data each.
        type SignatureData = [u8; 4];
        type Public = [u8; 4];

        fn parse_signature(&self, pk: Self::Public, sig: &[u8]) -> Option<Self::SignatureData> {
            let res: Vec<_> = sig.iter().zip(pk.iter()).map(|(&s, &p)| s ^ p).collect();
            Self::SignatureData::try_from(&res[..]).ok()
        }

        fn parse_pubkey(&self, pk: &[u8]) -> ParseResult<Self::Public> {
            Self::Public::try_from(pk).ok().into()
        }

        fn verify_signature(&self, sig: &Self::SignatureData, subscript: &[u8], _ix: u32) -> bool {
            let msg = sha256(&[&self.transaction[..], subscript].concat());
            sig.iter().zip(msg.iter()).all(|(&s, &m)| (s ^ m) == 0)
        }

        fn check_lock_time(&self, lock_time: i64) -> bool {
            self.block_height >= lock_time as u64
        }
    }
}
