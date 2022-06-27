use itertools::iproduct;

use crypto::key::{KeyKind, PrivateKey};

use super::utils::*;
use crate::chain::Destination;

// Create a transaction with a different signature hash type for every input.
// This test takes a long time to finish, so it is ignored by default.
#[ignore]
#[test]
fn mixed_sighash_types() {
    let (private_key, public_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let destination = Destination::PublicKey(public_key);

    // Test all combinations of signature hash types in every position.
    for sighash_types in iproduct!(
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types(),
        sig_hash_types()
    ) {
        let mut tx = generate_unsigned_tx(&destination, 6, 6).unwrap();

        for (input, sighash_type) in [
            sighash_types.0,
            sighash_types.1,
            sighash_types.2,
            sighash_types.3,
            sighash_types.4,
            sighash_types.5,
        ]
        .into_iter()
        .enumerate()
        {
            update_signature(
                &mut tx,
                input,
                &private_key,
                sighash_type,
                destination.clone(),
            )
            .unwrap();
        }

        assert_eq!(verify_signed_tx(&tx, &destination), Ok(()));
    }
}
