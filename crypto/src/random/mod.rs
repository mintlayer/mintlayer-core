pub use rand::prelude::SliceRandom;
pub use rand::{seq, Rng, RngCore, SeedableRng};

pub fn make_true_rng() -> impl rand::Rng + rand::CryptoRng {
    rand::rngs::StdRng::from_entropy()
}

pub fn make_pseudo_rng() -> impl rand::Rng {
    rand::rngs::ThreadRng::default()
}
