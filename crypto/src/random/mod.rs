pub fn make_true_rng() -> impl rand::Rng + rand::CryptoRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::from_entropy()
}

pub fn make_pseudo_rng() -> impl rand::Rng {
    rand::rngs::ThreadRng::default()
}
