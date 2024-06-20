//! Bindings for Trezor protobufs.

// Note: we do not use the generated `mod.rs` because we want to feature-gate some modules manually.
// This significantly improves compile times.
// See https://github.com/joshieDo/rust-trezor-api/pull/9 for more details.
#[allow(ambiguous_glob_reexports, unreachable_pub)]
#[allow(clippy::all)]
mod generated {
    macro_rules! modules {
        ($($($feature:literal =>)? $module:ident)+) => {$(
            $(#[cfg(feature = $feature)])?
            mod $module;
            $(#[cfg(feature = $feature)])?
            pub use self::$module::*;
        )+};
    }

    modules! {
        messages
        messages_bootloader
        messages_common
        messages_crypto
        messages_debug
        messages_management

        "bitcoin" => messages_bitcoin
        "ethereum" => messages_ethereum
        "ethereum" => messages_ethereum_eip712
        "ethereum" => messages_ethereum_definitions
        "binance" => messages_binance
        "cardano" => messages_cardano
        "eos" => messages_eos
        "monero" => messages_monero
        "nem" => messages_nem
        "ripple" => messages_ripple
        "solana" => messages_solana
        "stellar" => messages_stellar
        "tezos" => messages_tezos
        "webauthn" => messages_webauthn
        "mintlayer" => messages_mintlayer
    }
}

pub use generated::*;
