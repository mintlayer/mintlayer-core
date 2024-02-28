// Copyright (c) 2021-2024 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use derive_more::Display;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_quote, Error, ItemFn, LitStr, ReturnType, Token,
};

#[proc_macro_attribute]
pub fn log_error(args: TokenStream, item: TokenStream) -> TokenStream {
    let args = syn::parse_macro_input!(args as Args);
    let func = syn::parse_macro_input!(item as ItemFn);

    let log_level_str = args.level.unwrap_or(Level::Error).to_string();
    let log_level_tok: proc_macro2::TokenStream = log_level_str.parse().unwrap();

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = func;

    let output = if sig.asyncness.is_none() {
        quote! {
            #[track_caller]
            #(#attrs)*
            #vis #sig {
                use utils::tap_error_log::LogError;
                #block.log_err_with_level(logging::log::Level::#log_level_tok)
            }
        }
    } else {
        // "track_caller" won't work in an async function, it has to be re-written as non-async
        // one returning `impl Future`.
        let mut sig = sig;
        sig.asyncness = None;
        sig.output = match sig.output {
            ReturnType::Default => {
                parse_quote! { -> impl std::future::Future<Output = () > }
            }
            ReturnType::Type(_, ret_type) => {
                parse_quote! { -> impl std::future::Future<Output = #ret_type > }
            }
        };

        // Note about the "fix_hidden_lifetime_bug" call:
        // Rewriting an async function as a non async one that returns `impl Future`
        // isn't always straightforward. E.g. consider this function:
        //      async fn a_func(x: &str, y: &str) {
        //          // Use x and y somehow.
        //          x.to_owned();
        //          y.to_owned();
        //      }
        // If you rewrite it as follows:
        //      fn func(x: &str, y: &str) -> impl Future<Output = ()> {
        //          async move {
        //             x.to_owned();
        //             y.to_owned();
        //          }
        //      }
        // you'll get the error: "hidden type for `impl Future<Output = ()>` captures lifetime
        // that does not appear in bounds".
        // The solution here is to introduce something like this:
        //      trait Captures<'a> { }
        //      impl<T: ?Sized> Captures<'a> for T { }
        // and re-write "func" as follows:
        //      fn func<'a, 'b>(x: &'a str, y: &'b str) ->
        //          impl Future<Output = ()> + Captures<(&'a (), &'b ())> { ...
        // And this is basically what "fix_hidden_lifetime_bug" does.
        //
        // P.S.: "hidden lifetime bug" refers to the issue https://github.com/rust-lang/rust/issues/63033
        // where async functions would fail to compile with the aforementioned "hidden type ...
        // captures lifetime" error. That issue has been fixed in 1.69, but non-async functions
        // that return `impl Future` still need this workaround as of Rust 1.76.
        quote! {
            #[track_caller]
            #[fix_hidden_lifetime_bug::fix_hidden_lifetime_bug]
            #(#attrs)*
            #vis #sig {
                use utils::tap_error_log::LogError;
                async move {#block.log_err_with_level(logging::log::Level::#log_level_tok)}
            }
        }
    };

    TokenStream::from(output)
}

#[derive(Display)]
enum Level {
    Trace,
    Debug,
    Info,
    Error,
    Warn,
}

impl Parse for Level {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let _ = input.parse::<kw::level>()?;
        let _ = input.parse::<Token![=]>()?;
        let str: LitStr = input.parse()?;
        match str.value() {
            s if s.eq_ignore_ascii_case("trace") => Ok(Level::Trace),
            s if s.eq_ignore_ascii_case("debug") => Ok(Level::Debug),
            s if s.eq_ignore_ascii_case("info") => Ok(Level::Info),
            s if s.eq_ignore_ascii_case("warn") => Ok(Level::Warn),
            s if s.eq_ignore_ascii_case("error") => Ok(Level::Error),
            _ => Err(Error::new(
                input.cursor().span(),
                "unknown verbosity level; expected one of \"trace\", \"debug\", \"info\", \
                    \"warn\", or \"error\" (case-insensitive)",
            )),
        }
    }
}

#[derive(Default)]
struct Args {
    level: Option<Level>,
}

impl Parse for Args {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut args = Self::default();

        while !input.is_empty() {
            let lookahead = input.lookahead1();

            if lookahead.peek(kw::level) {
                if args.level.is_some() {
                    return Err(input.error("duplicate `level` argument"));
                }
                args.level = Some(input.parse()?);
            } else {
                return Err(lookahead.error());
            }
        }

        Ok(args)
    }
}

mod kw {
    syn::custom_keyword!(level);
}
