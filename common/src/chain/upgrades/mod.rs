mod netupgrade;

pub use netupgrade::*;

pub enum NetUpgradeError {
    GenerateConfigFailed,
}
