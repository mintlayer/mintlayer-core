use crypto::key::PublicKey;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PoolData {
    decommission_public_key: PublicKey,
}
