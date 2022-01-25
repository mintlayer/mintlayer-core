mod constants;
mod data;
mod helpers;
pub mod work;

pub enum POWError {
    BlockToMineError(String),
    ConversionError(String),
}
