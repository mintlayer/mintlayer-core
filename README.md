# Mintlayer core

Welcome to the official Github repository for Mintlayer, an innovative, open-source blockchain project. For detailed technical insights, we recommend visiting our [documentation](https://docs.mintlayer.org/).

Please note, the code in this repository is currently under active development. Consequently, it should not be deemed production-ready. Nonetheless, you're invited to test the code in our active testnet environment.

## Security

Discovered a potential security issue? We urge you to contact us directly at security@mintlayer.org. When reporting, please encrypt your report using Ben's GPG key which can be found [here](https://www.mintlayer.org/assets/keys/ben).

Mintlayer runs a [bug bounty program](https://www.mintlayer.org/bug-bounties), meaning that if your report is valid, you could be eligible for a reward paid in ML tokens. Please refrain from publicly disclosing any potential security issues until our core Mintlayer team has confirmed that the matter can be shared. Further information can be found in our [SECURITY.md](https://github.com/mintlayer/mintlayer-core/blob/master/SECURITY.md) guidelines.

## Bug Reporting

For non-security related bugs, please open an [issue](https://github.com/mintlayer/mintlayer-core/issues/new) in the core Mintlayer repository. When detailing the bug, please provide as much information as possible to aid our debugging efforts. If you wish to contribute to a bug's resolution, refer to our [contributing](https://github.com/mintlayer/mintlayer-core/blob/master/CONTRIBUTING.md) guidelines.

## Contributions

We welcome contributions from all developers. Please refer to our detailed [contributing guide](https://github.com/mintlayer/mintlayer-core/blob/master/CONTRIBUTING.md) before proceeding.

## Running a node

To run a mainnet or testnet node, you have the option to use pre-built binaries (from the Mintlayer website, mintlayer.org) or compile the code yourself and build the software yourself.

### What executables exist?

You can see the full list of mintlayer executables by running `cargo run --bin`, assuming you have rust installed. Rust will list all the possible executables. The following are the most important:

- `node-daemon`: The node software as a command line software. This is the software that manages the blocks, p2p communication, and all the other important functions of the blockchain network. The `node-daemon` is at the center of all other executables, except for the GUI, which has an instance of the node included in it for simplicity.
- `node-gui`: The graphical user interface of the node for people who are not as tech-savvy and just want to run a node using the simplest means possible. The GUI is almost always behind in development compared to other tools, but it contains what is necessary to run a node, stake, delegate, and do other important tasks. The GUI also contains the machinery to run a wallet and create one. You can open multiple wallets with the GUI.
- `wallet-rpc-daemon`: A wallet that can be controlled remotely using RPC. This can be run as a service.
- `wallet-cli`: A command line interface for the wallet. All the newest features and functionalities of the wallet are available in this wallet. The `wallet-cli` is extremely ubiquitous and can be run in many modes, including a self-contained wallet, a controller of an RPC wallet, as an RPC wallet itself, and also as a cold wallet for air-gapped storage of coins and assets.

### Preparations for compiling the source code

- Install the rust compiler: https://www.rust-lang.org/tools/install
- Make sure to relaunch your terminal when you're done. To ensure the rust compiler is working, run: `cargo --version`, and it should return a version number. If you get a compilation failure, usually it means a dependency is missing.
- Install dependencies (for Linux/Debian/Ubuntu, you need `apt-get install build-essential`). For the GUI (Graphical User Interface) you also need `libgtk-3-dev`. Find the equivalent dependencies for your Linux distribution if it's not Debian-based.

### Ways to run the software when building from source

You can either keep running the code from source, using `cargo run --release --bin <program name>`, or you can just build with `cargo build --release --bin <program name>`, which will put the executable in the `target/release` directory.

### Running software and how to control logging

The logging of mintlayer-core is configured via the `RUST_LOG` environment variable. All log messages are printed to the terminal screen; we prefer simplicity over complicated log machinery. For example, to see all logs of the `info` level and above (the default level for normal operation), you can run the node with `RUST_LOG=info cargo run --bin node-daemon -- testnet`. If you're facing an issue, it's recommended to use `RUST_LOG=debug` instead. We recommend using these commands that not only print the logs on the screen, but also write them to a file in case you face an issue. On Linux, this can be achieved using `tee` as shown below.

Here are the commands as recommended for different scenarios:

For normal operation (replace testnet by mainnet to run the mainnet node)
Note: spaces don't matter, so these are aligned for readability
- Node daemon: `RUST_LOG=info cargo run --release --bin node-daemon       -- testnet 2>&1 | tee ../mintlayer.log`
- CLI Wallet:  `RUST_LOG=info cargo run --release --bin wallet-cli        -- testnet 2>&1 | tee ../wallet-cli.log`
- RPC Wallet:  `RUST_LOG=info cargo run --release --bin wallet-rpc-daemon -- testnet 2>&1 | tee ../wallet-cli.log`
- GUI:         `RUST_LOG=info cargo run --release --bin node-gui          -- testnet 2>&1 | tee ../node-gui.log`

For heavy debugging operation
- Node daemon: `RUST_LOG=debug cargo run --bin node-daemon       -- testnet 2>&1 | tee ../mintlayer.log`
- CLI Wallet:  `RUST_LOG=debug cargo run --bin wallet-cli        -- testnet 2>&1 | tee ../wallet-cli.log`
- RPC Wallet:  `RUST_LOG=debug cargo run --bin wallet-rpc-daemon -- testnet 2>&1 | tee ../wallet-cli.log`
- GUI:         `RUST_LOG=debug cargo run --bin node-gui          -- testnet 2>&1 | tee ../node-gui.log`

## The API server

The API server is a tool for indexing the blockchain. Its source code is contained in this repository and its [readme can be found in its directory](api-server/README.md).

## Communicating with the node and wallet

Communication with the node and the wallet is possible through RPC. Details on that can be found in:

- [Node RPC readme](rpc/README.md)
- [Wallet RPC readme](wallet/wallet-rpc-daemon/README.md)

## Security, and running a node in a rented public server or a Virtual Private Server (VPS)

Please read the documentation on the recommended security practices when running a public server:

- [Node service readme](build-tools/linux-systemd-service/README.md)
