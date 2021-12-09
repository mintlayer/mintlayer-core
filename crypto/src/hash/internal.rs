use digest::{generic_array::GenericArray, Digest};

pub fn hash<D: Digest, T: AsRef<[u8]>>(in_bytes: T) -> GenericArray<u8, <D as Digest>::OutputSize> {
    let mut hasher = D::new();
    hasher.update(in_bytes);
    hasher.finalize()
}

#[derive(Clone)]
pub struct InternalStreamHasher<D: Digest> {
    hasher: D,
}

impl<D: Digest> InternalStreamHasher<D> {
    pub fn new() -> Self {
        Self { hasher: D::new() }
    }

    pub fn write<T: AsRef<[u8]>>(&mut self, in_bytes: T) {
        self.hasher.update(in_bytes);
    }

    pub fn reset(&mut self) {
        self.hasher.reset()
    }

    pub fn finalize(&mut self) -> GenericArray<u8, <D as Digest>::OutputSize> {
        self.hasher.finalize_reset()
    }
}
