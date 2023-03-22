pub trait PairHasher: Sized + Clone {
    type Type: Clone;

    fn hash_pair(left: &Self::Type, right: &Self::Type) -> Self::Type;
    fn hash_single(data: &Self::Type) -> Self::Type;
}
