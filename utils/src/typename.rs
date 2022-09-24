pub trait TypeName {
    fn typename_str() -> &'static str {
        // This implementation is good enough, though it includes the full qualifiers of a typename, which may not be ideal
        std::any::type_name::<Self>()
    }
}

impl TypeName for () {}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Eq, PartialEq, Debug)]
    struct TestType1;

    impl TypeName for TestType1 {}

    #[derive(Eq, PartialEq, Debug)]
    struct TestType2;

    impl TypeName for TestType2 {
        fn typename_str() -> &'static str {
            "TestType2"
        }
    }

    #[test]
    fn typename() {
        assert!(TestType1::typename_str().ends_with("TestType1"));
        assert_eq!(TestType2::typename_str(), "TestType2");
    }
}
