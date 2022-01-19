mod netupgrade;
mod pow;

pub use netupgrade::*;
pub use pow::POWConfig;

pub enum NetUpgradeError {
    GenerateConfigFailed,
}
