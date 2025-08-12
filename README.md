# Mintlayer core

Welcome to the official Github repository for Mintlayer, an innovative, open-source blockchain project. For detailed technical insights, we recommend visiting our [documentation](https://docs.mintlayer.org/).

## Security

Discovered a potential security issue? We urge you to contact us directly at security@mintlayer.org. When reporting, please encrypt your report using Ben's GPG key which can be found [here](https://www.mintlayer.org/assets/keys/ben).

Mintlayer runs a [bug bounty program](https://www.mintlayer.org/bug-bounties), meaning that if your report is valid, you could be eligible for a reward paid in ML tokens. Please refrain from publicly disclosing any potential security issues until our core Mintlayer team has confirmed that the matter can be shared. Further information can be found in our [SECURITY.md](https://github.com/mintlayer/mintlayer-core/blob/master/SECURITY.md) guidelines.

## Bug Reporting

For non-security related bugs, please open an [issue](https://github.com/mintlayer/mintlayer-core/issues/new) in the core Mintlayer repository. When detailing the bug, please provide as much information as possible to aid our debugging efforts. If you wish to contribute to a bug's resolution, refer to our [contributing](https://github.com/mintlayer/mintlayer-core/blob/master/CONTRIBUTING.md) guidelines.

## Contributions

We welcome contributions from all developers. Please refer to our detailed [contributing guide](https://github.com/mintlayer/mintlayer-core/blob/master/CONTRIBUTING.md) before proceeding.

## Running a node

To run a mainnet or testnet node, you have the option to use pre-built binaries (from the Mintlayer website, mintlayer.org) or compile the code and build the software yourself.

### What executables exist?

You can see the full list of mintlayer executables by running `cargo run --bin`, assuming you have rust installed. Rust will list all the possible executables. The following are the most important:

- `node-daemon`: The node software as a command line tool. This is the software that manages the blocks, p2p communication, and all the other important functions of the blockchain network. The `node-daemon` is at the center of all other executables, except for the GUI, which has an instance of the node included in it for simplicity.
- `node-gui`: The graphical user interface of the node for people who are not as tech-savvy and just want to run a node using the simplest means possible. The GUI is almost always behind in development compared to other tools, but it contains what is necessary to run a node, stake, delegate, and do other important tasks. The GUI also contains the machinery to run a wallet and create one. You can open multiple wallets with the GUI.
- `wallet-rpc-daemon`: A wallet that can be controlled remotely using RPC. This can be run as a service.
- `wallet-cli`: A command line interface for the wallet. All the newest features and functionalities of the wallet are available in this wallet. The `wallet-cli` is extremely ubiquitous and can be run in many modes, including a self-contained wallet, a controller of an RPC wallet, as an RPC wallet itself, and also as a cold wallet for air-gapped storage of coins and assets.

### What do you need to run?

There are many ways you can manage running the components of mintlayer-core. The following are a few examples.

You can:

- Run node-daemon + wallet-cli to manage your coins, where wallet-cli owns your wallet file and manages your coins. wallet-cli itself can optionally act as an RPC server
- Run node-daemon + wallet-rpc-daemon + wallet-cli, where both daemons will be services in your system, wallet-rpc-daemon will own your wallet (and start staking automatically for you), and wallet-cli will just be an easy interface for communicating with your wallet
- Run only node-gui, where the GUI contains both the node and the wallet. This is a good option for non-techy users
- Run node-daemon with the API server components ([see this readme](api-server/README.md)) without a wallet, to manage your application

### Preparations for compiling the source code

- Install the rust compiler: https://www.rust-lang.org/tools/install
- Make sure to relaunch your terminal when you're done. To ensure the rust compiler is working, run: `cargo --version`, and it should return a version number. If you get a compilation failure, usually it means a dependency is missing.
- Install dependencies (for Linux/Debian/Ubuntu, you need `apt-get install build-essential`). Find the equivalent dependencies for your Linux distribution if it's not Debian-based.

### Ways to run the software when building from source

You can either keep running the code from source, using `cargo run --release --bin <program name>`, or you can just build with `cargo build --release --bin <program name>`, which will put the executable in the `target/release` directory.

### Running software and how to control logging

Normally, the logging of mintlayer-core is configured via the `RUST_LOG` environment variable and all log messages are printed to the terminal screen. For example, to see all logs of the `info` level and above (the default level for normal operation), you can run the node with `RUST_LOG=info cargo run --bin node-daemon -- testnet`. If you're facing an issue, it's recommended to use `RUST_LOG=debug` instead. We recommend using the commands that not only print the logs on the screen, but also write them to a file in case you face an issue. On Linux, this can be achieved using `tee` as shown below.

If the `RUST_LOG` environment variable is not specified, the log level `info` will be used by default.

Additionally, independent of what is printed to the console, node's logs may also be automatically written to the data directory (on Linux, they will be inside `~/.mintlayer/mainnet/logs/` and `~/.mintlayer/testnet/logs/` for mainnet and testnet respectively); this is controlled by the `--log-to-file` option (e.g. `--log-to-file true`), which is accepted by both node-daemon and node-gui. By default, its value is false for node-daemon and true for node-gui. The log files are rotated based on size, so older logs will be automatically deleted eventually. Also note that the log level used in this case is always `info`, regardless of the value of `RUST_LOG`.

Here are the commands as recommended for different scenarios:

#### Assuming you're using the source code

Every release has a tag and a release branch. Make sure you checkout the release you need. For example, if you need v1.0.0, you should first run the following to check out the release branch:

```sh
git checkout release-v1.0.0
```

or to checkout the tag:

```sh
git checkout tags/v1.0.0
```

Release branches are more recommended than tags, because they get necessary security patches, if any. Tags are just markers.

After having checked out the version you need, the following is how to run the software.

For normal operation (replace testnet by mainnet to run the mainnet node)
You don't need to specify RUST_LOG environment variable for logging, since it's by default set to be `INFO`.

Note: spaces don't matter, so these are aligned for readability

- Node daemon:
    ```sh
    cargo run --release --bin node-daemon       -- testnet 2>&1 | tee ../mintlayer.log
    ```
- CLI Wallet:
    ```sh
    cargo run --release --bin wallet-cli        -- testnet 2>&1 | tee ../wallet-cli.log
    ```
- RPC Wallet:
    ```sh
    cargo run --release --bin wallet-rpc-daemon -- testnet 2>&1 | tee ../wallet-cli.log
    ```
- GUI:
    ```sh
    cargo run --release --bin node-gui          -- testnet 2>&1 | tee ../node-gui.log
    ```

For heavy debugging operation
- Node daemon:
    ```sh
    RUST_LOG=debug cargo run --bin node-daemon       -- testnet 2>&1 | tee ../mintlayer.log
    ```
- CLI Wallet:
    ```sh
    RUST_LOG=debug cargo run --bin wallet-cli        -- testnet 2>&1 | tee ../wallet-cli.log
    ```
- RPC Wallet:
    ```sh
    RUST_LOG=debug cargo run --bin wallet-rpc-daemon -- testnet 2>&1 | tee ../wallet-cli.log
    ```
- GUI:
    ```sh
    RUST_LOG=debug cargo run --bin node-gui          -- testnet 2>&1 | tee ../node-gui.log
    ```

More complex log filtering is possible, e.g. you can filter out log lines produced by a certain crate or module, but this is out of scope of this document.

### Cross-compiling for Raspberry Pi (Arm64)

To cross-compile the source code for Raspberry Pi, or any Arm64 OS, assuming you don't want to build it there, a new target has to be added for the Rust compiler + dependencies/linker installed.

Note that Mintlayer only supports 64-bit systems. If your Raspberry Pi's current OS architecture is armhf (32-bit), which you can check using the command `dpkg --print-architecture`, you have to wipe it and start over with an Arm64/aarch64 OS.

#### Steps:

Install the target for the Rust compiler:

```
rustup target add aarch64-unknown-linux-gnu
```

Install the dependencies and linker (this is for Debian/Ubuntu, find the equivalent for your OS and run it):

```
sudo apt install gcc-aarch64-linux-gnu
```

Once these installations are successful, you can build all binaries for Arm64:

```
cargo build --all --target=aarch64-unknown-linux-gnu --release
```

Or build the individual binaries you choose:

```
cargo build --bin node-daemon --target=aarch64-unknown-linux-gnu --release
cargo build --bin wallet-cli --target=aarch64-unknown-linux-gnu --release
# ... etc
```

The artifacts can be found in `target/aarch64-unknown-linux-gnu/release`, or a similar directory name.

## Wallets

For more information about the wallets and their usage, [visit this readme file](wallet/README.md).

## Trezor support

Mintlayer wallets support Trezor hardware wallets, though it's still in Beta at this moment.

For details, [visit this readme file](wallet/TREZOR_SUPPORT.md).

## The API server

The API server is a tool for indexing the blockchain. Its source code is contained in this repository and its [readme can be found in its directory](api-server/README.md).

## Communicating with the node and wallet

Communication with the node and the wallet is possible through RPC. Details on that can be found in:

- [Node RPC readme](node-daemon/docs/README.md)
- [Wallet RPC readme](wallet/wallet-rpc-daemon/README.md)

## WASM wrappers/bindings

Using these wrappers is NOT recommended in general and should only be considered as last resort for developing applications that absolutely need it, such as light-wallets. We recommend using the RPC facilities to communicate with the node and wallet. This way, you have the best level of compatibility and safety.

Nevertheless... If you insist, in order to be able to perform basic operations with other programming languages, we provide WASM (web-assembly) wrappers.

- [WASM readme](wasm-wrappers/README.md)

## Security, and running a node in a rented public server or a Virtual Private Server (VPS)

Please read the documentation on the recommended security practices when running a public server:

- [Node service readme](build-tools/linux-systemd-service/README.md)
