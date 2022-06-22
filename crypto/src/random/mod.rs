pub use rand::prelude::SliceRandom;
pub use rand::{seq, CryptoRng, Rng, RngCore, SeedableRng};

pub mod distributions {
    pub use rand::distributions::{Alphanumeric, Distribution, Standard};
}

pub mod rngs {
    pub use rand::rngs::OsRng;
}

pub fn make_true_rng() -> impl rand::Rng + rand::CryptoRng {
    rand::rngs::StdRng::from_entropy()
}

pub fn make_pseudo_rng() -> impl rand::Rng {
    rand::rngs::ThreadRng::default()
}
