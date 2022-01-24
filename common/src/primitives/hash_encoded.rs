//! Hash an object by its encoding

use crypto::hash::StreamHasher;
use parity_scale_codec::Encode;

/// Feed an encoded version of the object into a stream hasher
pub fn hash_encoded_to<T: Encode, H: StreamHasher>(val: &T, hasher: &mut H) {
    val.encode_to(&mut HashWriter(hasher))
}

// A bridge from std::io::Write to HashStream. Private as to not expose the Writer methods
// externally to avoid exposing (potentially platform-specific) formatting methods.
struct HashWriter<'a, H: StreamHasher>(&'a mut H);

impl<'a, H: StreamHasher> std::io::Write for HashWriter<'a, H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
