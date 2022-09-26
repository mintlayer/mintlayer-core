use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckTokensError {
    #[error("URL is invalid")]
    InvalidURI,
    #[error("Invalid character in the text")]
    InvalidCharancter,
    #[error("Invalid text length")]
    InvalidTextLength,
}
