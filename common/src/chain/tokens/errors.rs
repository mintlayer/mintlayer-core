use super::TokenId;
use crate::{
    chain::{Block, Transaction},
    primitives::Id,
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TokensError {
    #[error("Incorrect ticker in issue transaction {0} in block {1}")]
    IssueErrorIncorrectTicker(Id<Transaction>, Id<Block>),
    #[error("Incorrect amount in issue transaction {0} in block {1}")]
    IssueErrorIncorrectAmount(Id<Transaction>, Id<Block>),
    #[error("Too many decimals in issue transaction {0} in block {1}")]
    IssueErrorTooManyDecimals(Id<Transaction>, Id<Block>),
    #[error("Incorrect metadata URI in issue transaction {0} in block {1}")]
    IssueErrorIncorrectMetadataURI(Id<Transaction>, Id<Block>),
    #[error("Too many tokens issued in transaction {0} in block {1}")]
    MultipleTokenIssuanceInTransaction(Id<Transaction>, Id<Block>),
    #[error("Coin or token overflow")]
    CoinOrTokenOverflow,
    #[error("Tokens fees insuffience in transaction {0} in block {1}")]
    InsuffienceTokenFees(Id<Transaction>, Id<Block>),
    #[error("Tokens value in inputs insuffience in transaction {0} in block {1}")]
    InsuffienceTokenValueInInputs(Id<Transaction>, Id<Block>),
    #[error("Can't burn zero value in transaction {0} in block {1}")]
    BurnZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Can't transfer zero tokens in transaction {0} in block {1}")]
    TransferZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Some of the tokens are lost in transaction {0} in block {1}")]
    SomeTokensLost(Id<Transaction>, Id<Block>),
    #[error("Can't find tokens in inputs in transaction {0} in block {1}")]
    NoTokenInInputs(Id<Transaction>, Id<Block>),
    #[error("Can't fetch transaction inputs in main chain by outpoint")]
    NoTxInMainChainByOutpoint,
    #[error("Block reward output can't be used in tokens transaction")]
    BlockRewardOutputCantBeUsedInTokenTx,
    #[error("Tokens with ID: `{0}` are not registered")]
    TokensNotRegistered(TokenId),
    #[error("Tokens ID can't be calculated")]
    TokenIdCantBeCalculated,
}
