use common::chain::tokens::TokenCreator;
use crypto::key::{KeyKind, PrivateKey};

pub fn random_creator() -> Option<TokenCreator> {
    let (_, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    Some(TokenCreator::from(public_key))
}
