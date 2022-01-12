#![allow(dead_code)]

use common::primitives::Uint256;

#[derive(PartialEq, Eq, Debug)]
pub enum Network {
    MainNet,
    TestNet,
    SigNet,
    RegTest,
}

impl Network {
    pub fn no_retargeting(&self) -> bool {
        match self {
            Network::MainNet | Network::TestNet | Network::SigNet => false,
            Network::RegTest => true,
        }
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        match self {
            Network::MainNet | Network::SigNet => false,
            Network::TestNet | Network::RegTest => true,
        }
    }

    pub fn limit(&self) -> Uint256 {
        match self {
            Network::MainNet | Network::TestNet => Uint256([
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x00000000FFFFFFFF,
            ]),
            Network::SigNet => Uint256([
                0x0000000000000000,
                0x0000000000000000,
                0x0000000000000000,
                0x00000377AE000000,
            ]),
            Network::RegTest => Uint256([
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
        let x = Network::RegTest;
        let y = &x;

        let str_format = format!("{:?}", x.limit());
        assert_eq!(
            &str_format,
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }
}
