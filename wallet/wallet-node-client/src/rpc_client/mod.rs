// Copyright (c) 2023 RBB S.r.l
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

pub mod client_impl;
pub mod cold_wallet_client;

use std::sync::Arc;

use common::{
    address::AddressError, chain::ChainConfig, primitives::per_thousand::PerThousandParseError,
};
use rpc::{ClientError, ClientErrorExt as _, RpcAuthData, RpcWsClient, new_ws_client};

use crate::node_traits::{NodeInterface, NodeInterfaceError};

/// jsonrpsee's `CALL_EXECUTION_FAILED_CODE` (-32000): the code the mintlayer
/// RPC server reports for every application-level error (see
/// `rpc::handle_result` in the rpc crate).
const CALL_EXECUTION_FAILED_CODE: i32 = -32000;

#[derive(thiserror::Error, Debug)]
pub enum NodeRpcError {
    #[error("Initialization error: {0}")]
    InitializationError(Box<NodeRpcError>),
    #[error("Decoding error: {0}")]
    DecodingError(#[from] serialization::hex::HexError),
    #[error("Client creation error: {0}")]
    ClientCreationError(ClientError),
    #[error("Response error: {0}")]
    ResponseError(ClientError),
    #[error("Address error: {0}")]
    AddressError(#[from] AddressError),
    #[error("PerThousand parse error: {0}")]
    PerThousandParseError(#[from] PerThousandParseError),
}

/// Whether a mempool error means the transaction itself was deterministically
/// rejected by the node, as opposed to a transient/indeterminate outcome that
/// may succeed on a retry.
///
/// Classification is by error variants, not by Display text: the wire message
/// is prefixed with "Mempool error: ", so any keyword check against a string
/// built from this error would be vacuous. The JSON-RPC transport, which only
/// sees the wire message, mirrors this decision in
/// [`classify_mempool_error_message`]; the two must stay in sync (pinned by
/// tests).
pub(crate) fn is_deterministic_mempool_rejection(err: &mempool::error::Error) -> bool {
    use chainstate::tx_verifier::error::ConnectTransactionError;
    use mempool::error::{MempoolPolicyError, OrphanPoolError, TxValidationError};

    match err {
        // The transaction was evaluated and found invalid. The state- and
        // race-dependent exceptions below may succeed on a retry.
        mempool::error::Error::Validity(tx_error) => match tx_error {
            // The node was unhealthy or still syncing.
            TxValidationError::ChainstateError(_)
            | TxValidationError::SubsystemCallError(_)
            | TxValidationError::AddedDuringIBD => false,
            // Output-spent and account-nonce checks race with mempool
            // evictions and with the submission of this transaction's own
            // parents; the rest of this arm's variants are internal
            // chainstate/storage/accounting failures, not verdicts on the
            // transaction — a retry on a healthy node may succeed.
            TxValidationError::TxValidation(connect_error) => !matches!(
                connect_error,
                ConnectTransactionError::MissingOutputOrSpent(_)
                    | ConnectTransactionError::NonceIsNotIncremental(..)
                    | ConnectTransactionError::MissingTransactionNonce(_)
                    | ConnectTransactionError::FailedToIncrementAccountNonce
                    | ConnectTransactionError::StorageError(_)
                    | ConnectTransactionError::UtxoError(_)
                    | ConnectTransactionError::UtxoBlockUndoError(_)
                    | ConnectTransactionError::AccountingBlockUndoError(_)
                    | ConnectTransactionError::BlockIndexCouldNotBeLoaded(_)
                    | ConnectTransactionError::MissingTxUndo(_)
                    | ConnectTransactionError::MissingBlockUndo(_)
                    | ConnectTransactionError::MissingBlockRewardUndo(_)
                    | ConnectTransactionError::InvariantErrorHeaderCouldNotBeLoadedFromHeight(..)
                    | ConnectTransactionError::FailedToAddAllFeesOfBlock(_)
                    | ConnectTransactionError::RewardAdditionError(_)
                    | ConnectTransactionError::TransactionVerifierError(_)
                    | ConnectTransactionError::TxVerifierStorage
                    | ConnectTransactionError::UndoFetchFailure
                    | ConnectTransactionError::PoSAccountingError(_)
                    | ConnectTransactionError::TokensError(_)
                    | ConnectTransactionError::TokensAccountingError(_)
                    | ConnectTransactionError::OrdersAccountingError(_)
                    | ConnectTransactionError::StakerBalanceNotFound(_)
                    | ConnectTransactionError::RewardDistributionError(_)
                    | ConnectTransactionError::ConstrainedValueAccumulatorError(..)
            ),
        },
        // Fee, size, RBF and expiry policy rejections are deterministic for
        // the transaction as it is; mempool pressure, conflicts with other
        // mempool transactions, and store races may resolve on their own.
        mempool::error::Error::Policy(policy_error) => !matches!(
            policy_error,
            MempoolPolicyError::MempoolFull
                | MempoolPolicyError::Conflict(_)
                | MempoolPolicyError::MempoolStoreError(_)
                | MempoolPolicyError::MempoolStoreInvariantError(_)
        ),
        // Orphan-pool pressure, conflicts and nonce gaps may resolve on
        // their own; size and origin-policy rejections are deterministic.
        mempool::error::Error::Orphan(orphan_error) => !matches!(
            orphan_error,
            OrphanPoolError::Full
                | OrphanPoolError::LocalCapacityExceeded(_)
                | OrphanPoolError::Conflict(_)
                | OrphanPoolError::NonceGapTooLarge(_)
                | OrphanPoolError::MempoolConflict
        ),
        // Everything else is an interrupted or state-dependent evaluation.
        _ => false,
    }
}

/// Whether a (lowercased) JSON-RPC wire error message identifies a
/// deterministic mempool/tx rejection, as opposed to a transient/indeterminate
/// evaluation outcome, mempool pressure, or an unrelated failure.
///
/// This is the string-level mirror of [`is_deterministic_mempool_rejection`]
/// for the JSON-RPC transport, which only sees the message text; keep the two
/// in sync (the tests derive the wire strings from typed errors on both sides
/// so that a Display change in the mempool crate breaks the build instead of
/// silently flipping a pruning decision).
///
/// Only wrapper-prefixed messages are mempool-submission outcomes: on the
/// wire, `p2p::error::P2pError::MempoolError` ("Mempool error: {0}") and
/// `mempool::error::Error::Orphan` ("Orphan transaction error: {0}") are the
/// wrappers that can carry a mempool verdict. The positive prefix check avoids
/// false positives from unrelated application errors that merely mention
/// "mempool" or "orphan" somewhere in their text.
///
/// NOTE: text matching is inherently coupled to the Display strings of the
/// mempool/chainstate crates. The variant-count test in this module forces a
/// classifier review whenever a variant is added; the durable fix is a
/// structured (machine-readable) mempool verdict on the RPC error object, to
/// be done node-side.
fn classify_mempool_error_message(message: &str) -> bool {
    // Substrings of the Display strings of the variants excluded by
    // `is_deterministic_mempool_rejection`.
    const INDETERMINATE: &[&str] = &[
        "tip moved",
        "chainstate error",
        "subsystem call error",
        "reorg error",
        "transaction collection error",
        "mempool entry",
        "added during initial block download",
        "mempool is full",
        "orphan pool full",
        "local orphan capacity",
        "account nonces too distant",
        "nonce is not incremental",
        "nonce is not found",
        "failed to increment account nonce",
        "output is not found in the cache or database",
        "irreplaceable",
        "spends an unconfirmed input",
        "too many replacements",
        "blockchain storage error",
        "utxo error",
        "block undo error",
        "blockundo error",
        "undo info for transaction",
        "block undo info doesn't exist",
        "block reward undo info",
        "header found but header not found",
        "unable to find block index",
        "addition of all fees in block",
        "block reward addition error",
        "transactionverifierstorage",
        "cannot be zero",
        "verifier storage error",
        "fetching undo data failed",
        "staker balance of pool",
        "reward distribution error",
        "constrained value accumulator error",
        "pos accounting error",
        "tokens error",
        "tokens accounting error",
        "orders accounting error",
        "not found while traversing history",
        "could not obtain the best block for utxos",
        "could not find the previous tip index",
        "could not find the new tip index",
    ];
    (message.starts_with("mempool error:") || message.starts_with("orphan transaction error:"))
        && !INDETERMINATE.iter().any(|term| message.contains(term))
}

impl NodeInterfaceError for NodeRpcError {
    fn is_recoverable_mempool_error_during_block_production(&self) -> bool {
        match self {
            NodeRpcError::ResponseError(err) => match err {
                rpc::ClientError::Call(err_obj) => {
                    err_obj.message().contains(blockprod::RECOVERABLE_MEMPOOL_ERROR_MSG)
                }
                _ => false,
            },

            NodeRpcError::InitializationError(_)
            | NodeRpcError::DecodingError(_)
            | NodeRpcError::ClientCreationError(_)
            | NodeRpcError::AddressError(_)
            | NodeRpcError::PerThousandParseError(_) => false,
        }
    }

    fn is_node_rejection(&self) -> bool {
        // Mintlayer's RPC server reports every application-level error with
        // jsonrpsee's CALL_EXECUTION_FAILED code and the error's Display as
        // the message (`rpc::handle_result`), so only that exact code can
        // carry a mempool verdict; the message classification decides whether
        // it was a deterministic transaction rejection. Everything else —
        // other server codes (e.g. proxies reporting their own failures in
        // the reserved range), protocol errors (-326xx, e.g. internal errors,
        // where the transaction was never evaluated), transport failures,
        // and transient mempool outcomes — stays a delivery failure, so the
        // transaction is retried instead of pruned.
        match self {
            NodeRpcError::ResponseError(rpc::ClientError::Call(err)) => {
                err.code() == CALL_EXECUTION_FAILED_CODE
                    && classify_mempool_error_message(&err.message().to_ascii_lowercase())
            }
            _ => false,
        }
    }
}

impl NodeRpcError {
    /// Returns `true` if the error is caused by a connection-level problem between this client
    /// and the node, i.e. the connection is broken or cannot be established, as opposed to an
    /// application-level error reported by the node.
    ///
    /// Such errors are recoverable by dropping the client and establishing a new connection.
    ///
    /// Caution: connection-level does not mean that the failed request was not processed. A
    /// timeout or a lost response in particular leaves the outcome of the request unknown, so
    /// callers retrying non-idempotent node calls must account for that instead of blindly
    /// resending. (The scanner's sync and the mempool subscription are both idempotent: they
    /// resume from local state.)
    pub fn is_connection_error(&self) -> bool {
        match self {
            // The client could not be created or the call did not reach the node (or its
            // response was lost) because of a broken connection.
            NodeRpcError::ClientCreationError(err) | NodeRpcError::ResponseError(err) => {
                err.is_connection_error()
            }
            // The initial connection check failed; the cause is either a connection problem or
            // an application-level error, both classified by the wrapped error.
            NodeRpcError::InitializationError(err) => err.is_connection_error(),
            NodeRpcError::DecodingError(_)
            | NodeRpcError::AddressError(_)
            | NodeRpcError::PerThousandParseError(_) => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ColdWalletClient {
    chain_config: Arc<ChainConfig>,
}

impl ColdWalletClient {
    pub fn new(chain_config: Arc<ChainConfig>) -> Self {
        Self { chain_config }
    }
}

#[derive(Clone, Debug)]
pub struct NodeRpcClient {
    rpc_client: Arc<RpcWsClient>,
    chain_config: Arc<ChainConfig>,
}

impl NodeRpcClient {
    pub async fn new(
        chain_config: Arc<ChainConfig>,
        remote_socket_address: String,
        rpc_auth: RpcAuthData,
    ) -> Result<Self, NodeRpcError> {
        let host = format!("ws://{remote_socket_address}");

        let rpc_client =
            new_ws_client(host, rpc_auth).await.map_err(NodeRpcError::ClientCreationError)?;

        let client = Self {
            rpc_client: Arc::new(rpc_client),
            chain_config,
        };

        client
            .get_best_block_id()
            .await
            .map_err(|e| NodeRpcError::InitializationError(Box::new(e)))?;

        Ok(client)
    }

    /// Direct access to the underlying WebSocket RPC client, e.g. for subscriptions.
    pub fn ws_client(&self) -> &rpc::RpcWsClient {
        &self.rpc_client
    }
}

#[cfg(test)]
mod mempool_rejection_classification_tests {
    use super::NodeRpcError;
    use super::{classify_mempool_error_message, is_deterministic_mempool_rejection};
    use crate::node_traits::NodeInterfaceError as _;
    use chainstate::tx_verifier::error::ConnectTransactionError;
    use common::chain::OutPointSourceId;
    use common::chain::Transaction;
    use common::chain::tokens::TokenId;
    use common::primitives::{H256, Id};
    use mempool::error::{
        Error as MempoolError, MempoolConflictError, MempoolPolicyError, MempoolStoreError,
        MempoolStoreInvariantError, OrphanPoolError, TxValidationError,
    };

    fn test_id(n: u64) -> Id<Transaction> {
        H256::from_low_u64_be(n).into()
    }

    fn utxo_outpoint(n: u64) -> common::chain::UtxoOutPoint {
        common::chain::UtxoOutPoint::new(OutPointSourceId::Transaction(test_id(n)), 0)
    }

    #[test]
    fn deterministic_rejections_are_classified_as_such() {
        // Policy: fee, size and expiry rules are deterministic for the
        // transaction as it is.
        assert!(is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::NoInputs
        )));
        assert!(is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::TxSizeExceedsMaxBlockSize
        )));
        assert!(is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::DescendantOfExpiredTransaction
        )));
        // Orphan pool: size and origin-policy rejections are deterministic.
        assert!(is_deterministic_mempool_rejection(&MempoolError::Orphan(
            OrphanPoolError::TooLarge(1, 2)
        )));
        // Validity: genuinely invalid transactions (this one spends a burned
        // amount, which no retry can change).
        assert!(is_deterministic_mempool_rejection(&MempoolError::Validity(
            TxValidationError::TxValidation(ConnectTransactionError::AttemptToSpendBurnedAmount)
        )));
        assert!(is_deterministic_mempool_rejection(&MempoolError::Validity(
            TxValidationError::TxValidation(ConnectTransactionError::TotalFeeRequiredOverflow)
        )));
    }

    #[test]
    fn transient_and_state_dependent_errors_are_not_rejections() {
        // Interrupted or unhealthy-node outcomes (TipMoved, and the
        // chainstate/subsystem wrappers, which need error values from other
        // crates and are pinned via the wire-mirror tests below).
        assert!(!is_deterministic_mempool_rejection(&MempoolError::TipMoved));
        // The node was still syncing.
        assert!(!is_deterministic_mempool_rejection(
            &MempoolError::Validity(TxValidationError::AddedDuringIBD)
        ));
        // Races with mempool eviction and with this transaction's own parents.
        assert!(!is_deterministic_mempool_rejection(
            &MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::MissingOutputOrSpent(utxo_outpoint(1))
            ))
        ));
        // Mempool pressure.
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::MempoolFull
        )));
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Orphan(
            OrphanPoolError::Full
        )));
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Orphan(
            OrphanPoolError::LocalCapacityExceeded(1)
        )));
        // Conflicts with other mempool transactions may resolve on their own.
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::Conflict(MempoolConflictError::Irreplacable)
        )));
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Orphan(
            OrphanPoolError::MempoolConflict
        )));
        // Account-nonce gaps close when this transaction's own parents land.
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Orphan(
            OrphanPoolError::NonceGapTooLarge(3)
        )));
        // Mempool store races (ban score 0).
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::MempoolStoreError(MempoolStoreError::TxEntryNotFound(test_id(1)))
        )));
        assert!(!is_deterministic_mempool_rejection(&MempoolError::Policy(
            MempoolPolicyError::MempoolStoreInvariantError(
                MempoolStoreInvariantError::SupposedlyExistingEntryNotFound(test_id(1))
            )
        )));
    }

    /// The JSON-RPC transport only sees the wire message; its classifier must
    /// mirror the typed one above. The strings below are the real Display
    /// strings, wrapped the way the server sends them.
    #[test]
    fn wire_message_mirror_matches_typed_classification() {
        let indeterminate = [
            MempoolError::TipMoved,
            MempoolError::Policy(MempoolPolicyError::MempoolFull),
            MempoolError::Orphan(OrphanPoolError::Full),
            MempoolError::Orphan(OrphanPoolError::LocalCapacityExceeded(1)),
            MempoolError::Orphan(OrphanPoolError::NonceGapTooLarge(3)),
            MempoolError::Orphan(OrphanPoolError::MempoolConflict),
            MempoolError::Policy(MempoolPolicyError::Conflict(
                MempoolConflictError::Irreplacable,
            )),
            MempoolError::Policy(MempoolPolicyError::Conflict(
                MempoolConflictError::SpendsNewUnconfirmed,
            )),
            MempoolError::Policy(MempoolPolicyError::Conflict(
                MempoolConflictError::TooManyReplacements,
            )),
            MempoolError::Validity(TxValidationError::AddedDuringIBD),
            MempoolError::Validity(TxValidationError::ChainstateError(
                chainstate::ChainstateError::IoError("boom".to_string()),
            )),
            MempoolError::Validity(TxValidationError::SubsystemCallError(
                subsystem::error::CallError::Submission(
                    subsystem::error::SubmissionError::ChannelClosed,
                ),
            )),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::MissingOutputOrSpent(utxo_outpoint(1)),
            )),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::NonceIsNotIncremental(
                    common::chain::AccountType::Token(TokenId::new(H256::from_low_u64_be(1))),
                    common::chain::AccountNonce::new(1),
                    common::chain::AccountNonce::new(2),
                ),
            )),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::MissingTransactionNonce(
                    common::chain::AccountType::Token(TokenId::new(H256::from_low_u64_be(1))),
                ),
            )),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::FailedToIncrementAccountNonce,
            )),
            MempoolError::Orphan(OrphanPoolError::Conflict(
                MempoolConflictError::Irreplacable,
            )),
        ];
        for error in &indeterminate {
            // "Mempool error: {0}" / "Orphan transaction error: {0}" come from
            // the mempool and p2p crates' #[error] attributes.
            let wire = format!("Mempool error: {error}").to_ascii_lowercase();
            assert!(
                !classify_mempool_error_message(&wire),
                "wire message must be indeterminate: {wire}"
            );
        }
    }

    /// Pinning the variant counts: if one of these assertions fails, a
    /// variant was added to (or removed from) an error enum that feeds the
    /// mempool-rejection classification. Update
    /// [`is_deterministic_mempool_rejection`], the `INDETERMINATE` term list
    /// in `classify_mempool_error_message`, and the wire-mirror tests above
    /// in the same change — otherwise a transient outcome can silently turn
    /// into a pruning decision (or vice versa).
    #[test]
    fn classifier_covers_every_error_variant() {
        use strum::EnumCount as _;
        assert_eq!(MempoolError::COUNT, 9);
        assert_eq!(TxValidationError::COUNT, 4);
        assert_eq!(MempoolPolicyError::COUNT, 22);
        assert_eq!(OrphanPoolError::COUNT, 7);
        assert_eq!(ConnectTransactionError::COUNT, 40);
    }

    #[test]
    fn wire_prefixes_match_transport_wrappers() {
        // The prefixes used by `classify_mempool_error_message` are the
        // Display wrappers that actually carry mempool verdicts on the wire;
        // tie the literals to them so that a wrapper change in the p2p or
        // mempool crate breaks this test instead of silently reclassifying
        // every mempool error as a delivery failure.
        let mempool_wrapped =
            p2p::error::P2pError::MempoolError(MempoolError::TipMoved).to_string();
        assert!(mempool_wrapped.to_ascii_lowercase().starts_with("mempool error:"));

        let orphan_wrapped = MempoolError::Orphan(OrphanPoolError::Full).to_string();
        assert!(orphan_wrapped.to_ascii_lowercase().starts_with("orphan transaction error:"));
    }

    #[test]
    fn internal_chainstate_failures_are_not_rejections() {
        // Internal chainstate/storage/accounting failures are not verdicts on
        // the transaction; a retry on a healthy node may succeed.
        let internal = [
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::NonceIsNotIncremental(
                    common::chain::AccountType::Token(TokenId::new(H256::from_low_u64_be(1))),
                    common::chain::AccountNonce::new(1),
                    common::chain::AccountNonce::new(2),
                ),
            )),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::MissingTransactionNonce(
                    common::chain::AccountType::Token(TokenId::new(H256::from_low_u64_be(1))),
                ),
            )),
        ];
        for error in &internal {
            assert!(
                !is_deterministic_mempool_rejection(error),
                "internal/state failure must be indeterminate: {error}"
            );
        }
    }

    #[test]
    fn wire_message_mirror_matches_typed_deterministic_classification() {
        // The deterministic direction of the wire mirror, derived from typed
        // errors so that a Display change in the mempool crate breaks this
        // test instead of silently flipping a pruning decision.
        let deterministic = [
            MempoolError::Policy(MempoolPolicyError::NoInputs),
            MempoolError::Policy(MempoolPolicyError::TxSizeExceedsMaxBlockSize),
            MempoolError::Policy(MempoolPolicyError::DescendantOfExpiredTransaction),
            MempoolError::Orphan(OrphanPoolError::TooLarge(1, 2)),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::AttemptToSpendBurnedAmount,
            )),
            MempoolError::Validity(TxValidationError::TxValidation(
                ConnectTransactionError::TotalFeeRequiredOverflow,
            )),
        ];
        for error in &deterministic {
            assert!(is_deterministic_mempool_rejection(error));
            let wire = format!("Mempool error: {error}").to_ascii_lowercase();
            assert!(
                classify_mempool_error_message(&wire),
                "wire message must be a rejection: {wire}"
            );
        }
    }

    #[test]
    fn internal_failure_wire_terms_are_indeterminate() {
        // Every internal/state-dependent variant excluded by the typed
        // classifier must also be indeterminate on the wire, including the
        // ones whose Display carries no mempool keyword of its own.
        let internal_wire = [
            "Mempool error: Maximum cluster transaction count cannot be zero",
            "Mempool error: While disconnecting a block, undo info for transaction `abcd` doesn't exist",
            "Mempool error: While disconnecting a block, block undo info doesn't exist for block `abcd`",
            "Mempool error: While disconnecting a block, block reward undo info doesn't exist for block `abcd`",
            "Mempool error: Transaction index for header found but header not found",
            "Mempool error: Unable to find block index for block abcd",
            "Mempool error: Addition of all fees in block `abcd` failed",
            "Mempool error: Block reward addition error for block abcd",
            "Mempool error: utxo BlockUndo error: something",
            "Mempool error: Accounting BlockUndo error: something",
            "Mempool error: Error from TransactionVerifierStorage: something",
            "Mempool error: Reorg error: Could not obtain the best block for utxos",
            "Mempool error: Reorg error: Block BlockIndex(1) not found while traversing history",
        ];
        for message in internal_wire {
            assert!(
                !classify_mempool_error_message(&message.to_ascii_lowercase()),
                "internal failure must be indeterminate: {message}"
            );
        }
    }

    #[test]
    fn wire_message_deterministic_rejections() {
        let deterministic = [
            "mempool error: transaction has no inputs",
            "mempool error: transaction size exceeds the maximum block size",
            "mempool error: transaction is a descendant of expired transaction",
            "mempool error: transaction does not pay sufficient fees to be relayed (tx_fee: 1.00, min_relay_fee: 2.00)",
            "mempool error: orphan transaction error: transaction 1234 too large to be accepted into orphan pool (max 100)",
        ];
        for message in deterministic {
            assert!(
                classify_mempool_error_message(message),
                "wire message must be a rejection: {message}"
            );
        }
    }

    #[test]
    fn unrelated_wire_messages_are_not_rejections() {
        assert!(!classify_mempool_error_message("server busy"));
        assert!(!classify_mempool_error_message("internal error"));
        assert!(!classify_mempool_error_message(
            "method not found: chainstate_foo"
        ));
    }

    #[test]
    fn rpc_error_code_gate() {
        let rejection = |code: i32, message: &str| {
            NodeRpcError::ResponseError(rpc::ClientError::Call(rpc::Error::owned(
                code, message, None::<()>,
            )))
            .is_node_rejection()
        };

        // Mintlayer reports application errors with CALL_EXECUTION_FAILED
        // (-32000); a deterministic mempool rejection message on that code is
        // a node rejection.
        assert!(rejection(
            -32000,
            "Mempool error: transaction has no inputs"
        ));
        // Non-mempool application errors and transient mempool outcomes are
        // delivery failures.
        assert!(!rejection(-32000, "server busy"));
        assert!(!rejection(-32000, "Mempool error: Mempool is full"));
        assert!(!rejection(
            -32000,
            "Mempool error: Tip moved while trying to process transaction"
        ));
        // Protocol codes mean the transaction was never evaluated.
        assert!(!rejection(
            -32603,
            "Mempool error: transaction has no inputs"
        ));
        assert!(!rejection(-32700, "parse error"));
    }
}

#[cfg(test)]
mod connection_error_tests {
    use super::*;
    use rpc::test_support::CALL_EXECUTION_FAILED_CODE;

    /// The "background task closed ...; restart required" error reported by a WS client whose
    /// connection was closed by the node; this is the error seen by the scanner in production
    /// when the node drops the WebSocket connection.
    fn background_task_closed_error() -> ClientError {
        ClientError::RestartNeeded(Arc::new(ClientError::Transport(
            "Connection was closed".into(),
        )))
    }

    #[test]
    fn broken_connection_is_a_connection_error() {
        assert!(NodeRpcError::ResponseError(background_task_closed_error()).is_connection_error());
        assert!(
            NodeRpcError::ResponseError(ClientError::Transport("connection reset by peer".into()))
                .is_connection_error()
        );
        assert!(NodeRpcError::ResponseError(ClientError::RequestTimeout).is_connection_error());

        // A client that cannot be created at all (e.g. the node is simply down) is also a
        // connection-level failure.
        assert!(
            NodeRpcError::ClientCreationError(ClientError::Transport("Connection refused".into()))
                .is_connection_error()
        );

        // The initial connection check wraps the cause; the classification is inherited.
        assert!(
            NodeRpcError::InitializationError(Box::new(NodeRpcError::ResponseError(
                background_task_closed_error()
            )))
            .is_connection_error()
        );
    }

    #[test]
    fn node_reported_errors_are_not_connection_errors() {
        // A definitive application-level answer from the node must not trigger a reconnection.
        let call_error = ClientError::Call(rpc::Error::owned(
            CALL_EXECUTION_FAILED_CODE,
            "No such block",
            None::<serde_json::Value>,
        ));
        assert!(!NodeRpcError::ResponseError(call_error).is_connection_error());

        assert!(
            !NodeRpcError::DecodingError(serialization::hex::HexError::ScaleDecodeError(
                "decoding failed".into()
            ))
            .is_connection_error()
        );
    }
}
