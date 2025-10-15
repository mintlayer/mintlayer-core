# Cargo-vet configuration

As its [documentation](https://mozilla.github.io/cargo-vet/index.html) says, `cargo-vet` is a tool to help projects
ensure that third-party Rust dependencies have been audited by a trusted entity.

It checks each crate in the project's dependency tree against a set of audits, which can be either performed
by the project authors themselves or imported from trusted organizations.\
Alternatively, a particular combination of crate/publisher can be marked as trusted, meaning that
any version of the crate released by the publisher will be considered audited.

Also, a particular version of a crate may be exempted from the check, this is done by putting it
into the `exemptions` table in `config.toml`. Initially (when `cargo vet init` was first run)
all crates in the dependency tree were put to `exemptions`. At the time of writing this,
a significant portion of our dependencies is still exempted from the check.

Note: normally neither `audit.toml` nor `config.toml` should be edited by hand, use an appropriate
`cargo vet` command instead.\
Also note that it's not even possible to add a custom comment to either of the files, because it
will be automatically removed by `cargo vet`, while `cargo vet --locked` will complain that
"A file in the store is not correctly formatted".

## Whom we trust

- First of all, there is an official list of trusted projects in the tool's
    [registry](https://raw.githubusercontent.com/bholley/cargo-vet/main/registry.toml).
    We imported all the projects that existed in the registry at the moment of the import -
    actix, bytecode-alliance, embark-studios, fermyon, google, isrg, mozilla, zcash.

- Secondly, the imported projects themselves trust certain well-known publishers and it's reasonable
    for us to trust them as well. In fact, `cargo vet suggest` makes suggestions about this, e.g.
    ```
    NOTE: isrg, mozilla, and bytecode-alliance trust David Tolnay (dtolnay) - consider cargo vet trust anyhow or cargo vet trust --all dtolnay
    ```
    So we added all the publishers that were suggested at the time, namely:
    - Alex Crichton (alexcrichton)
    - Alice Ryhl (Darksonn)
    - Amanieu d'Antras (Amanieu)
    - Andrew Gallant (BurntSushi)
    - Carl Lerche (carllerche, user-id = 10)
    - Dan Gohman (sunfishcode)
    - David Tolnay (dtolnay)
    - Ed Page (epage)
    - Jelte Fennema-Nio (JelteF)
    - Josh Stone (cuviper)
    - Kenny Kerr (kennykerr)
    - Manish Goregaokar (Manishearth)
    - Matt Brubeck (mbrubeck)
    - rust-lang-owner
    - Sean McArthur (seanmonstar)
    - Thomas de Zeeuw (Thomasdezeeuw)
    - Yuki Okushi (JohnTitor)

    Note that they were added by running `cargo vet trust --all publisher_name --allow-multiple-publishers`, which means
    that the same crate may be referenced multiple times, once for each trusted publisher. E.g.
    ```
    [[trusted.tokio]]
    criteria = "safe-to-deploy"
    user-id = 10
    start = "2019-03-02"
    end = "2026-10-15"

    [[trusted.tokio]]
    criteria = "safe-to-deploy"
    user-id = 6741 # Alice Ryhl (Darksonn)
    start = "2020-12-25"
    end = "2026-10-15"
    ```

    Also note that though normally the "user-id" will have a comment mentioning the publisher's name,
    this is not the case for "user-id = 10" for some reason (the id belongs to Carl Lerche).

- We also prefer to trust members of major GitHub organizations (such as tokio-rs), maintainers of popular crates, as
    well as people who are well-known among the developer community.

    Below is the table containing all the publishers that we currently trust (except those mentioned above).

    Note: when adding a new publisher as trusted, also add them to this table and provide some justification
    on why they should be considered trusted.

    | **Publisher** | **GitHub/crates.io username** | **Justification (what are they known for)** |
    |---------------|-------------------|-------------------|
    | Tony Arcieri | tarcieri | Member of `RustCrypto`, maintainer of many cryptography-related crates. |
    | Artyom Pavlov | newpavlov | Member of `RustCrypto`, maintainer of many cryptography-related crates. |
    | Andrew Poelstra | apoelstra | Member and maintainer of `rust-bitcoin`. |
    | Steven Roose | stevenroose | Member and maintainer of `rust-bitcoin`. |
    | Clark Moody | clarkmoody | Member of `rust-bitcoin`. It looks like he's not a maintainer anymore, but the latest versions of `bitcoin-bech32` were still published by him. |
    | Steven Fackler | sfackler | Long-time maintainer of many crates related to OpenSSL and Postgres. Former member of Rust library team. |
    | Paolo Barbolini | paolobarbolini | Member of `rust-postgres`. Maintainer of many Postgres-related crates, e.g. `tokio-postgres`. |
    | Alex Gaynor | alex | Maintains the `openssl` crate (together with Steven Fackler). Known for his contribution to open source, in particular in the Python community. |
    | Taiki Endo | taiki-e | Publisher of many crates in the `smol-rs` ecosystem. One of the owners of the `crossbeam` crate. |
    | Yoshua Wuyts | yoshuawuyts | Member of `http-rs`, one of the owners of `async-std`. |
    | Alex Kladov | matklad | Former main developer of Rust Analyzer. Maintainer of `once_cell`. |
    | Zeeshan Ali Khan | zeenix | Long-time GNOME developer, maintainer of the `zbus` crate. |
    | Benjamin Fry | bluejekyll | Maintainer of `hickory-dns`. |
    | Héctor Ramón Jiménez | hecrj | Maintainer of `iced`. |
    | Jack Wrenn | jswrenn | Maintains the `itertools` crate. One of the owners of the `zerocopy` crate. |
    | ? | gwenn | Maintainer of the widely-used `rusqlite` crate. |
    | Ashley Mannix | KodrAus | Maintains the `uuid` crate and some official rust-lang crates. Former member of Rust library team. |
    | Joshua Liebow-Feeser | joshlf | Publisher and one of the owners of the `zerocopy` crate. |
    | Lukas Kalbertodt | LukasKalbertodt | Maintainer of `libtest-mimic`. Former member of Rust library team. |
    | Jacob Pratt | jhpratt | Maintainer of the `time` crate. Regular contributor to the Rust standard library. |
    | Timon Post| TimonPost | Maintainer of the widely-used `crossterm` crate. |

- We also trust the crates that we've forked.

    Normally this is done by putting them to the `policy` table in `config.toml` and setting its
    `audit-as-crates-io` key to `false`.
