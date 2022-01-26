mod constants;
mod data;
mod helpers;
mod temp;
pub mod work;

pub enum POWError {
    BlockToMineError(String),
    ConversionError(String),
}
