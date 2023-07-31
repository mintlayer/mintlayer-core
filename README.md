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

To run the node, use the following command: `cargo run --bin node-daemon -- testnet`. To launch the command line wallet, use this command: `cargo run --bin wallet-cli -- --network testnet`. To launch the GUI wallet, use this command: `cargo run --bin node-gui`. You can get testnet coins from [the faucet](https://faucet.mintlayer.org/) in order to use the testnet, alternatively you can email opensource@mintlayer.org .

### Logging
The logging of mintlayer-core is configured via the `RUST_LOG` environment variable. All log messages are printed to the terminal screen; we prefer simplicity over complicated log machinery. For example, to see all logs of the `info` level and above (the default level for normal operation), you can run the node with `RUST_LOG=info cargo run --bin node-daemon -- testnet`. If you're facing an issue, it's recommended to use `RUST_LOG=debug` instead. We recommend using these commands that not only print the logs on the screen, but also write them to a file in case you face an issue. On Linux, this can be achieved using `tee` as shown below.

Here are the commands as recommended for different scenarios:

For normal operation
- Node daemon: `RUST_BACKTRACE=full RUST_LOG=info cargo run --bin node-daemon -- testnet 2>&1 | tee ../mintlayer.log`
- CLI Wallet:  `RUST_BACKTRACE=full RUST_LOG=info cargo run --bin wallet-cli -- --network testnet 2>&1 | tee ../wallet-cli.log`
- GUI:         `RUST_BACKTRACE=full RUST_LOG=info cargo run --bin node-gui 2>&1 | tee ../node-gui.log`

For heavy debugging operation
- Node daemon: `RUST_BACKTRACE=full RUST_LOG=debug cargo run --bin node-daemon -- testnet 2>&1 | tee ../mintlayer.log`
- CLI Wallet:  `RUST_BACKTRACE=full RUST_LOG=debug cargo run --bin wallet-cli -- --network testnet 2>&1 | tee ../wallet-cli.log`
- GUI:         `RUST_BACKTRACE=full RUST_LOG=debug cargo run --bin node-gui 2>&1 | tee ../node-gui.log`
