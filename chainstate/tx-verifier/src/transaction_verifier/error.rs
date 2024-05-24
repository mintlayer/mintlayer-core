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

use chainstate_types::GetAncestorError;
use common::{
    chain::{
        block::{Block, GenBlock},
        signature::DestinationSigError,
        tokens::TokenId,
        AccountNonce, AccountType, OutPointSourceId, PoolId, Transaction, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id},
};
use thiserror::Error;

use crate::{timelock_check, CheckTransactionError, TransactionSource};

use super::{
    input_output_policy::IOPolicyError, reward_distribution,
    signature_destination_getter::SignatureDestinationGetterError,
    storage::TransactionVerifierStorageError,
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConnectTransactionError {
    #[error("Blockchain storage error: {0}")]
    StorageError(chainstate_storage::Error),
    #[error("While connecting a block, transaction number `{0}` does not exist in block `{1}`")]
    TxNumWrongInBlockOnConnect(usize, Id<Block>),
    #[error("While disconnecting a block, transaction number `{0}` does not exist in block `{1}`")]
    TxNumWrongInBlockOnDisconnect(usize, Id<Block>),
    #[error("Block disconnect already-unspent (invariant broken)")]
    InvariantBrokenAlreadyUnspent,
    #[error("Output is not found in the cache or database: {0:?}")]
    MissingOutputOrSpent(UtxoOutPoint),
    #[error("No inputs in a transaction")]
    MissingTxInputs,
    #[error("While disconnecting a block, undo info for transaction `{0}` doesn't exist ")]
    MissingTxUndo(Id<Transaction>),
    #[error("While disconnecting a block, block undo info doesn't exist for block `{0:?}`")]
    MissingBlockUndo(TransactionSource),
    #[error("While disconnecting a block, block reward undo info doesn't exist for block `{0}`")]
    MissingBlockRewardUndo(Id<GenBlock>),
    #[error("While disconnecting a mempool tx, undo info is missing")]
    MissingMempoolTxsUndo,
    #[error("Attempt to print money (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    AttemptToPrintMoney(Amount, Amount),
    #[error("Block reward inputs and outputs value mismatch (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    BlockRewardInputOutputMismatch(Amount, Amount),
    #[error("Fee calculation failed (total inputs: `{0:?}` vs total outputs `{1:?}`")]
    TxFeeTotalCalcFailed(Amount, Amount),
    #[error("Signature verification failed in transaction: {0}")]
    SignatureVerificationFailed(#[from] DestinationSigError),
    #[error("Error while calculating block height; possibly an overflow")]
    BlockHeightArithmeticError,
    #[error("Error while calculating timestamps; possibly an overflow")]
    BlockTimestampArithmeticError,
    #[error("Transaction index for header found but header not found")]
    InvariantErrorHeaderCouldNotBeLoaded(Id<GenBlock>),
    #[error("Transaction index for header found but header not found")]
    InvariantErrorHeaderCouldNotBeLoadedFromHeight(GetAncestorError, BlockHeight),
    #[error("Unable to find block index")]
    BlockIndexCouldNotBeLoaded(Id<GenBlock>),
    #[error("Addition of all fees in block `{0}` failed")]
    FailedToAddAllFeesOfBlock(Id<Block>),
    #[error("Block reward addition error for block {0}")]
    RewardAdditionError(Id<Block>),
    #[error("Timelock rules violated")]
    TimeLockViolation,
    #[error("Utxo error: {0}")]
    UtxoError(#[from] utxo::Error),
    #[error("Tokens error: {0}")]
    TokensError(#[from] TokensError),
    #[error("Error from TransactionVerifierStorage: {0}")]
    TransactionVerifierError(#[from] TransactionVerifierStorageError),
    #[error("utxo BlockUndo error: {0}")]
    UtxoBlockUndoError(#[from] utxo::UtxosBlockUndoError),
    #[error("Accounting BlockUndo error: {0}")]
    AccountingBlockUndoError(#[from] accounting::BlockUndoError),
    #[error("Failed to sum amounts of burns in transaction: {0}")]
    BurnAmountSumError(Id<Transaction>),
    #[error("Attempt to spend burned amount in transaction")]
    AttemptToSpendBurnedAmount,
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("Error during stake spending: {0}")]
    SpendStakeError(#[from] SpendStakeError),
    #[error("Staker balance of pool {0} not found")]
    StakerBalanceNotFound(PoolId),
    #[error("Data of pool {0} not found")]
    PoolDataNotFound(PoolId),
    #[error("Balance of pool {0} not found")]
    PoolBalanceNotFound(PoolId),
    #[error("Pool id provided in the tx output {0} doesn't match calculated pool id {1}")]
    UnexpectedPoolId(PoolId, PoolId),

    // TODO The following should contain more granular inner error information
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("Fetching undo data failed")]
    UndoFetchFailure,
    #[error("Some transaction verifier storage error")]
    TxVerifierStorage,

    #[error("Destination retrieval error for signature verification {0}")]
    DestinationRetrievalError(#[from] SignatureDestinationGetterError),
    #[error("Output timelock error: {0}")]
    OutputTimelockError(#[from] timelock_check::OutputMaturityError),
    #[error("Nonce is not incremental: {0:?}, expected nonce: {1}, got nonce: {2}")]
    NonceIsNotIncremental(AccountType, AccountNonce, AccountNonce),
    #[error("Nonce is not found: {0:?}")]
    MissingTransactionNonce(AccountType),
    #[error(
        "Transaction {0} has not enough pledge to create a stake pool: giver {1:?}, required {2:?}"
    )]
    NotEnoughPledgeToCreateStakePool(Id<Transaction>, Amount, Amount),
    #[error("Attempt to create stake pool from accounting inputs")]
    AttemptToCreateStakePoolFromAccounts,
    #[error("Attempt to create delegation from accounting inputs")]
    AttemptToCreateDelegationFromAccounts,
    #[error("Failed to increment account nonce")]
    FailedToIncrementAccountNonce,
    #[error("Input output policy error: `{0}` in : `{1:?}`")]
    IOPolicyError(IOPolicyError, OutPointSourceId),
    #[error("Constrained value accumulator error: `{0}` in : `{1:?}`")]
    ConstrainedValueAccumulatorError(constraints_value_accumulator::Error, OutPointSourceId),
    #[error("Tokens accounting error: {0}")]
    TokensAccountingError(#[from] tokens_accounting::Error),
    #[error("Total fee required overflow")]
    TotalFeeRequiredOverflow,
    #[error("Insufficient coins fee provided in a transaction: {0:?} actual, {1:?} required")]
    InsufficientCoinsFee(Amount, Amount),
    #[error("Cannot perform any operations for frozen token {0}")]
    AttemptToSpendFrozenToken(TokenId),
    #[error("Reward distribution error: {0}")]
    RewardDistributionError(#[from] reward_distribution::RewardDistributionError),
    #[error("Check transaction error: {0}")]
    CheckTransactionError(#[from] CheckTransactionError),
    #[error("Utxo requested for input that does not need one")]
    InvariantBrokenUtxoRequested,
    #[error("Threshold condition not met: {0}")]
    Threshold(#[from] mintscript::script::ThresholdError),
}

impl From<std::convert::Infallible> for ConnectTransactionError {
    fn from(value: std::convert::Infallible) -> Self {
        match value {}
    }
}

impl From<chainstate_storage::Error> for ConnectTransactionError {
    fn from(err: chainstate_storage::Error) -> Self {
        // On storage level called err.recoverable(), if an error is unrecoverable then it calls panic!
        // We don't need to cause panic here
        ConnectTransactionError::StorageError(err)
    }
}

impl From<mintscript::translate::TranslationError> for ConnectTransactionError {
    fn from(value: mintscript::translate::TranslationError) -> Self {
        SignatureDestinationGetterError::from(value).into()
    }
}

impl From<mintscript::translate::TranslationError> for SignatureDestinationGetterError {
    fn from(value: mintscript::translate::TranslationError) -> Self {
        use mintscript::translate::TranslationError as E;
        match value {
            E::Unspendable => Self::SigVerifyOfNotSpendableOutput,
            E::PoSAccounting(e) => Self::from(e),
            E::TokensAccounting(e) => Self::from(e),
            E::PoolNotFound(id) => Self::PoolDataNotFound(id),
            E::DelegationNotFound(id) => Self::DelegationDataNotFound(id),
            E::TokenNotFound(id) => Self::TokenDataNotFound(id),
        }
    }
}

impl From<mintscript::checker::TimelockError<ConnectTransactionError>> for ConnectTransactionError {
    fn from(value: mintscript::checker::TimelockError<ConnectTransactionError>) -> Self {
        use mintscript::checker::TimelockError as E;
        match value {
            E::Context(e) => e.into(),
            E::HeightArith => Self::BlockHeightArithmeticError,
            E::TimestampArith => Self::BlockTimestampArithmeticError,
            E::HeightLocked(_, _) => Self::TimeLockViolation,
            E::TimestampLocked(_, _) => Self::TimeLockViolation,
        }
    }
}

impl<SE, TE> From<mintscript::script::ScriptError<SE, TE>> for ConnectTransactionError
where
    Self: From<SE> + From<TE>,
{
    fn from(value: mintscript::script::ScriptError<SE, TE>) -> Self {
        match value {
            mintscript::script::ScriptError::Signature(e) => e.into(),
            mintscript::script::ScriptError::Timelock(e) => e.into(),
            mintscript::script::ScriptError::Threshold(e) => e.into(),
        }
    }
}

impl<SE> From<mintscript::VerificationError<SE>> for ConnectTransactionError
where
    Self: From<SE>,
{
    fn from(value: mintscript::VerificationError<SE>) -> Self {
        match value {
            mintscript::VerificationError::Translation(e) => e.into(),
            mintscript::VerificationError::Evaluation(e) => e.into(),
        }
    }
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TokenIssuanceError {
    #[error("Invalid name length")]
    IssueErrorInvalidNameLength,
    #[error("Invalid ticker length")]
    IssueErrorInvalidTickerLength,
    #[error("Invalid description length")]
    IssueErrorInvalidDescriptionLength,
    #[error("Invalid character in token ticker")]
    IssueErrorTickerHasNoneAlphaNumericChar,
    #[error("Invalid character in token name")]
    IssueErrorNameHasNoneAlphaNumericChar,
    #[error("Invalid character in token description")]
    IssueErrorDescriptionHasNoneAlphaNumericChar,
    #[error("Incorrect amount")]
    IssueAmountIsZero,
    #[error("Too many decimals")]
    IssueErrorTooManyDecimals,
    #[error("Incorrect metadata URI")]
    IssueErrorIncorrectMetadataURI,
    #[error("Incorrect icon URI")]
    IssueErrorIncorrectIconURI,
    #[error("Incorrect media URI")]
    IssueErrorIncorrectMediaURI,
    #[error("The media hash is too short")]
    MediaHashTooShort,
    #[error("The media hash is too long")]
    MediaHashTooLong,
    #[error("Token id {0} from issuance does not match calculated token id {1}")]
    TokenIdMismatch(TokenId, TokenId),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TokensError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Issuance error {0} in transaction {1}")]
    IssueError(TokenIssuanceError, Id<Transaction>),
    #[error("Too many tokens issuance in transaction {0}")]
    MultipleTokenIssuanceInTransaction(Id<Transaction>),
    #[error("Coin or token overflow {0:?}")]
    CoinOrTokenOverflow(CoinOrTokenId),
    #[error("Insufficient token issuance fee in transaction {0}")]
    InsufficientTokenFees(Id<Transaction>),
    #[error("Can't transfer zero tokens in transaction {0} in block {1}")]
    TransferZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Tokens ID can't be calculated")]
    TokenIdCantBeCalculated,
    #[error("Block reward can't be paid in tokens")]
    TokensInBlockReward,
    #[error("Invariant broken - attempt undo issuance on non-existent token {0}")]
    InvariantBrokenUndoIssuanceOnNonexistentToken(TokenId),
    #[error("Invariant broken - attempt register issuance on non-existent token {0}")]
    InvariantBrokenRegisterIssuanceWithDuplicateId(TokenId),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum SpendStakeError {
    #[error("Block reward output has no outputs")]
    NoBlockRewardOutputs,
    #[error("Block reward output has multiple outputs")]
    MultipleBlockRewardOutputs,
    #[error("Invalid output type used in block reward")]
    InvalidBlockRewardOutputType,
    #[error("Stake pool data in kernel doesn't match data in block reward output")]
    StakePoolDataMismatch,
    #[error("Pool id in kernel {0} doesn't match the expected pool id {1}")]
    StakePoolIdMismatch(PoolId, PoolId),
    #[error("Consensus PoS error: {0}")]
    ConsensusPoSError(#[from] consensus::ConsensusPoSError),
}
