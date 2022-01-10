use crate::pow::TARGET_TIMESPAN_SECS;
use common::primitives::Uint256;

#[derive(PartialEq, Eq, Debug)]
pub enum Network {
    MAIN,
    TEST_NET,
    SIG_NET,
    REG_TEST,
}

impl Network {
    pub fn no_retargeting(&self) -> bool {
        match self {
            Network::MAIN | Network::TEST_NET | Network::SIG_NET => false,
            Network::REG_TEST => true,
        }
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        match self {
            Network::MAIN | Network::SIG_NET => false,
            Network::TEST_NET | Network::REG_TEST => true,
        }
    }

    pub fn limit(&self) -> Uint256 {
        match self {
            Network::MAIN | Network::TEST_NET => Uint256([
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x00000000FFFFFFFF,
            ]),
            Network::SIG_NET => Uint256([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x00000377AE000000,
            ]),
            Network::REG_TEST => Uint256([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x7FFFFF0000000000,
            ]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_limit() {
        let x = Network::REG_TEST;
        let y = &x;

        let str_format = format!("{:?}", x.limit());
        assert_eq!(
            &str_format,
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }
}
