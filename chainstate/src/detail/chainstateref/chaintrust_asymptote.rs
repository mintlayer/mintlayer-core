use mockall::lazy_static;

/// An asymptote that with its limit to infinity, reaches the value one.
/// The function is normalized so that the limit as t goes to infinity is one.
///
/// Creation:
/// This function is created by integrating the function `alpha * exp(-alpha * x) dx` from 0 to t.
/// The parameter alpha controls the steepness of the curve; i.e., how fast the function converges.
///
/// Benefits:
/// This function is to be used to compute the accumulated weight of a chain for chain selection.
/// Having an asymptotic function that tends to one means that no matter how many empty time-slots
/// are in the chain, the weight will always be less than one, which is the weight of a single block.
/// This function can be used to programmatically prefer chains that have denser blocks in time.
fn asymptote_to_infinity_to_one<F>(t: u64, alpha: F) -> F
where
    F: num::Float + num::cast::FromPrimitive,
{
    let t = F::from_u64(t).expect("Cannot fail to convert u64 to F");
    let one = F::from_u64(1).expect("Cannot fail to create 1 as F");
    let weight = one - (-alpha * t).exp();
    weight
}

// The value of alpha, 0.025, is chosen such that when a block time is hit (120 seconds), there's 5% of the range of the asymptote left.
const ALPHA: f64 = 0.025;

fn precompute_asymptote_to_infinity_to_one<F>(alpha: F, size: u64) -> Vec<F>
where
    F: num::Float + num::cast::FromPrimitive,
{
    (0..size).map(|t| asymptote_to_infinity_to_one(t, alpha)).collect()
}

lazy_static! {
    static ref TIMESLOTS_WEIGHTS: Vec<f64> = precompute_asymptote_to_infinity_to_one(ALPHA, 240);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_asymptote_to_infinity_ends_at_one() {
        let t = 100000000; // a really large value
        let weight = asymptote_to_infinity_to_one(t, ALPHA);
        assert_eq!(weight, 1.);
    }
}
