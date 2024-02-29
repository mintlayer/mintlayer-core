// Copyright (c) 2024 RBB S.r.l
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

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_quote, spanned::Spanned, ItemTrait, TraitItem, TraitItemFn};

fn for_attr<'a>(
    name: &str,
    attrs: &'a [syn::Attribute],
    mut body: impl FnMut(&'a syn::Meta) -> syn::Result<()>,
) -> syn::Result<()> {
    attrs
        .iter()
        .filter(|a| a.path().segments.last().is_some_and(|n| n.ident == name))
        .try_for_each(|a| body(&a.meta))
}

fn gather_docs(attrs: &[syn::Attribute]) -> syn::Result<String> {
    let mut docs = String::new();
    for_attr("doc", attrs, |meta| {
        let syn::MetaNameValue { value, .. } = meta.require_name_value()?;
        let lit: syn::LitStr = syn::parse2(quote!(#value))?;
        let value = lit.value();
        let doc = value.strip_prefix(' ').unwrap_or(&value);
        docs.extend([doc, "\n"]);
        Ok(())
    })?;
    Ok(docs)
}

fn lookup_meta<'a>(
    name: &str,
    attrs: &'a [syn::Attribute],
) -> syn::Result<Option<&'a syn::MetaList>> {
    let mut meta = None;
    for_attr(name, attrs, |m| {
        let m = m.require_list()?;
        if meta.is_some() {
            return Err(syn::Error::new(m.span(), format!("Duplicate attr {name}")));
        }
        meta = Some(m);
        Ok(())
    })?;
    Ok(meta)
}

#[derive(Debug)]
enum MethodKindMeta<'a> {
    Method {
        return_type: Option<&'a syn::Type>,
    },
    Subscription {
        unsub: String,
        item_ty: Box<syn::Type>,
    },
}

#[derive(Debug)]
struct MethodMeta<'a> {
    name: String,
    docs: String,
    kind_meta: MethodKindMeta<'a>,
    params: Vec<(String, &'a syn::Type)>,
}

impl<'a> MethodMeta<'a> {
    fn from_item(namespace: &str, item: &'a TraitItemFn) -> syn::Result<Self> {
        let docs = gather_docs(&item.attrs)?;

        let method_info = lookup_meta("method", &item.attrs)?
            .map(|meta| {
                let mut name = String::new();
                meta.parse_nested_meta(|arg| {
                    if arg.path.is_ident("name") {
                        name = arg.value()?.parse::<syn::LitStr>()?.value();
                    }
                    Ok(())
                })?;
                Ok::<_, syn::Error>(name)
            })
            .transpose()?;

        let sub_info = lookup_meta("subscription", &item.attrs)?
            .map(|meta| {
                let mut name = String::new();
                let mut unsub_name = String::new();
                let mut item_ty = None;
                meta.parse_nested_meta(|arg| {
                    if arg.path.is_ident("name") {
                        name = arg.value()?.parse::<syn::LitStr>()?.value();
                    }
                    if arg.path.is_ident("unsubscribe") {
                        unsub_name = arg.value()?.parse::<syn::LitStr>()?.value();
                    }
                    if arg.path.is_ident("item") {
                        item_ty = Some(arg.value()?.parse::<syn::Type>()?);
                    }
                    Ok(())
                })?;
                let item_ty = item_ty.ok_or(syn::Error::new(meta.span(), "Item missing"))?;
                let unsub_name = match unsub_name.as_str() {
                    "" => match name.strip_prefix("subscribe") {
                        Some(name) => format!("unsubscribe{name}"),
                        None => return Err(syn::Error::new(meta.span(), "No unsubscibe")),
                    },
                    _ => unsub_name,
                };
                Ok::<_, syn::Error>((name, unsub_name, Box::new(item_ty)))
            })
            .transpose()?;

        let (name, kind_meta) = match (method_info, sub_info) {
            (None, None) => {
                return Err(syn::Error::new(
                    item.span(),
                    "Neither method nor subscribtion",
                ))
            }
            (Some(method_name), None) => {
                let return_type = match &item.sig.output {
                    syn::ReturnType::Default => None,
                    syn::ReturnType::Type(_, ty) => Some(ty.as_ref()),
                };
                (method_name, MethodKindMeta::Method { return_type })
            }
            (None, Some((name, unsub, item_ty))) => {
                let unsub = match namespace {
                    "" => unsub,
                    ns => format!("{ns}_{unsub}"),
                };
                (name, MethodKindMeta::Subscription { unsub, item_ty })
            }
            (Some(_), Some(_)) => {
                return Err(syn::Error::new(
                    item.span(),
                    "Method AND subscription at the same time",
                ))
            }
        };

        if name.is_empty() {
            return Err(syn::Error::new(item.span(), "Method without name"));
        }

        let name = match namespace {
            "" => name,
            ns => format!("{ns}_{name}"),
        };

        let params = item.sig.inputs.iter().skip(1);
        let params = params
            .map(|arg| {
                let arg = match arg {
                    syn::FnArg::Receiver(_) => panic!("Should have been skipped"),
                    syn::FnArg::Typed(ta) => ta,
                };
                let name = match arg.pat.as_ref() {
                    syn::Pat::Ident(id) => id.ident.to_string(),
                    _ => return Err(syn::Error::new(arg.pat.span(), "Should be identifier")),
                };
                Ok((name, arg.ty.as_ref()))
            })
            .collect::<syn::Result<Vec<_>>>()?;

        Ok(Self {
            name,
            docs,
            kind_meta,
            params,
        })
    }
}

impl quote::ToTokens for MethodMeta<'_> {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let Self {
            name,
            docs,
            params,
            kind_meta,
        } = self;

        let kind_data = match kind_meta {
            MethodKindMeta::Method { return_type } => {
                let unit: syn::Type = parse_quote!(());
                let ret = return_type.unwrap_or(&unit);
                quote! {
                    ::rpc::description::MethodKindData::Method {
                        return_type: <#ret as ::rpc::description::HasValueHint>::HINT,
                    }
                }
            }

            MethodKindMeta::Subscription { unsub, item_ty } => {
                quote! {
                    ::rpc::description::MethodKindData::Subscription {
                        unsubscribe_name: #unsub,
                        item_type: <#item_ty as ::rpc::description::HasValueHint>::HINT,
                    }
                }
            }
        };

        let params = params
            .iter()
            .map(|(n, t)| quote!((#n, &<#t as ::rpc::description::HasValueHint>::HINT)));

        tokens.extend(quote! {
            ::rpc::description::Method {
                name: #name,
                description: #docs,
                params: ::rpc::description::ValueHint::Object(&[#(#params),*]),
                kind_data: #kind_data,
            }
        })
    }
}

#[derive(Debug)]
struct ModuleMeta<'a> {
    trait_name: String,
    rpc_module: String,
    docs: String,
    methods: Vec<MethodMeta<'a>>,
}

impl<'a> ModuleMeta<'a> {
    fn from_item(item: &'a ItemTrait) -> syn::Result<Self> {
        let docs = gather_docs(&item.attrs)?;

        let rpc_module = lookup_meta("rpc", &item.attrs)?
            .map(|meta| {
                let mut namespace = String::new();
                meta.parse_nested_meta(|arg| {
                    if arg.path.is_ident("namespace") {
                        namespace = arg.value()?.parse::<syn::LitStr>()?.value();
                    }
                    Ok(())
                })?;
                Ok::<_, syn::Error>(namespace)
            })
            .transpose()?
            .ok_or(syn::Error::new(
                item.span(),
                "rpc::describe applied to non-rpc trait (describe must be before rpc)",
            ))?;

        let methods = item
            .items
            .iter()
            .filter_map(|item| match item {
                TraitItem::Fn(item) => Some(MethodMeta::from_item(&rpc_module, item)),
                _ => None,
            })
            .collect::<syn::Result<Vec<_>>>()?;

        Ok(Self {
            trait_name: item.ident.to_string(),
            rpc_module,
            docs,
            methods,
        })
    }
}

impl quote::ToTokens for ModuleMeta<'_> {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let Self {
            rpc_module,
            docs,
            methods,
            trait_name,
        } = self;

        let marker_name = quote::format_ident!("{trait_name}Description");

        let desc_name = match rpc_module.trim() {
            "" => trait_name.as_str(),
            _ => rpc_module.as_str(),
        };

        tokens.extend(quote! {
            #[derive(Clone, Copy, Debug)]
            pub struct #marker_name;

            impl ::rpc::description::Described for #marker_name {
                const DESCRIPTION: ::rpc::description::Module = ::rpc::description::Module {
                    name: #desc_name,
                    description: #docs,
                    methods: &[#(#methods,)*],
                };
            }
        });
    }
}

fn process_trait(rpc_trait: ItemTrait) -> Result<proc_macro2::TokenStream, syn::Error> {
    let module_meta = ModuleMeta::from_item(&rpc_trait)?;
    Ok(quote! {#rpc_trait #module_meta})
}

#[proc_macro_attribute]
pub fn describe(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item: ItemTrait = syn::parse(item).expect("rpc::description not applied to a trait");

    process_trait(item).unwrap_or_else(|e| e.to_compile_error()).into()
}
