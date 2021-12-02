#![recursion_limit = "128"]
extern crate proc_macro;

// use codec::{Decode, Encode};
use parity_scale_codec_derive::{Decode, Encode};

#[proc_macro_derive(MintEncode)]
pub fn encode_derive(_input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    //     // dbg!(_input.to_string());
    "#[derive(Encode)]".parse().expect("Wrong input AST for MintEncode")
    //     // format!("#[derive(Encode)] {}", _input.to_string())
    //     //     .parse()
    //     //     .expect("Wrong input AST for MintEncode")
    // parity_scale_codec_derive::Encode(_input)
}
