# Mintlayer core

Welcome to the official Github repository for Mintlayer, an innovative, open-source blockchain project. For detailed technical insights, we recommend visiting our [documentation](https://docs.mintlayer.org/).

Please note, the code in this repository is currently under active development. Consequently, it should not be deemed production-ready. Nonetheless, you're invited to test the code in our active testnet environment.

## Security 

Discovered a potential security issue? We urge you to contact us directly at security@mintlayer.org. When reporting, please encrypt your report using Ben's GPG key which can be found [here](https://www.mintlayer.org/assets/keys/ben).

Mintlayer runs a [bug bounty program](https://www.mintlayer.org/bug-bounties), meaning that if your report is valid, you could be eligible for a reward paid in MLT tokens. Please refrain from publicly disclosing any potential security issues until our core Mintlayer team has confirmed that the matter can be shared. Further information can be found in our [SECURITY.md](https://github.com/mintlayer/mintlayer-core/blob/master/SECURITY.md) guidelines.

## Bug Reporting

For non-security related bugs, please open an [issue](https://github.com/mintlayer/mintlayer-core/issues/new) in the core Mintlayer repository. When detailing the bug, please provide as much information as possible to aid our debugging efforts. If you wish to contribute to a bug's resolution, refer to our [contributing](https://github.com/mintlayer/mintlayer-core/blob/master/CONTRIBUTING.md) guidelines.

## Contributions

We welcome contributions from all developers. Please refer to our detailed [contributing guide](https://github.com/mintlayer/mintlayer-core/blob/master/CONTRIBUTING.md) before proceeding.

## Building

To compile the code, you will need to install Rust. Instructions for this can be found in our contributing guide. After installation, use the `cargo build` command to build the project and `cargo test` to run the tests.

## Joining the Testnet

To join the testnet, you have the option to use pre-built binaries or compile the code yourself. The build instructions are available [here](https://docs.mintlayer.org/testnet/node-setup-cli).

To run the node, use the following command: `cargo run --bin node-daemon -- testnet`. To launch the command line wallet, use this command: `cargo run --bin wallet-cli -- --network testnet`.

