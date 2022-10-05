use serialization_core::{Decode, Encode};

/// A wrapper that saves the extra byte coming from Option by assuming the Vec can never be empty
///
/// Description:
/// - If the Vec has data, it encodes to just the Vec, the Option is omitted
/// - If the Vec has no data, it encodes to None
/// - Some(vec![]) and None are equivalent when encoded, but when decoded result in None
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DataOrNoVec<T>(pub Option<Vec<T>>);

impl<U: Encode> Encode for DataOrNoVec<U> {
    fn encode_to<T: serialization_core::Output + ?Sized>(&self, dest: &mut T) {
        match &self.0 {
            Some(v) => v.encode_to(dest),
            None => Vec::<U>::new().encode_to(dest),
        }
    }

    fn encoded_size(&self) -> usize {
        match &self.0 {
            Some(v) => v.encoded_size(),
            None => Vec::encoded_size(&Vec::<U>::new()),
        }
    }
}

impl<U: Decode> Decode for DataOrNoVec<U> {
    fn decode<I: serialization_core::Input>(
        input: &mut I,
    ) -> Result<Self, serialization_core::Error> {
        let v = Vec::decode(input)?;
        if v.is_empty() {
            Ok(DataOrNoVec(None))
        } else {
            Ok(DataOrNoVec(Some(v)))
        }
    }
}

#[cfg(test)]
mod test {
    use serialization_core::DecodeAll;

    use super::*;

    #[test]
    fn empty_and_none_are_same() {
        let some_empty: DataOrNoVec<u8> = DataOrNoVec(Some(vec![]));
        let only_none: DataOrNoVec<u8> = DataOrNoVec(None);

        let some_empty_encoded = some_empty.encode();
        let only_none_encoded = only_none.encode();
        assert_eq!(some_empty_encoded, only_none_encoded);

        let some_empty_decoded = DataOrNoVec::<u8>::decode_all(&mut some_empty_encoded.as_slice());
        let only_none_decoded = DataOrNoVec::<u8>::decode_all(&mut only_none_encoded.as_slice());
        assert_eq!(some_empty_decoded, only_none_decoded);

        // they also decode to vectors!
        let some_empty_decoded = Vec::<u8>::decode_all(&mut some_empty_encoded.as_slice());
        let only_none_decoded = Vec::<u8>::decode_all(&mut only_none_encoded.as_slice());
        assert_eq!(some_empty_decoded, only_none_decoded);
    }

    #[test]
    fn non_empty() {
        let the_vec = vec![1, 2, 3];
        let data: DataOrNoVec<u8> = DataOrNoVec(Some(the_vec.clone()));

        let data_encoded = data.encode();
        let the_vec_encoded = the_vec.encode();
        assert_eq!(data_encoded, the_vec_encoded);

        // decoding should yield the same vec
        let data_decoded = DataOrNoVec::<u8>::decode_all(&mut data_encoded.as_slice());
        let the_vec_decoded = Vec::<u8>::decode_all(&mut the_vec_encoded.as_slice());
        assert_eq!(data_decoded.unwrap().0.unwrap(), the_vec_decoded.unwrap());
    }
}
