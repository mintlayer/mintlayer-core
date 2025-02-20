## Mintlayer wallets

The mintlayer wallet is a separate entity from the node. Even though the GUI (node-gui, the Graphical User Interface) program comes embedded with the wallet, this is done through programming abstractions, where programmatically, the node and wallet are completely separate entities. Due to this separation, the design is extremely flexible, to the point where it warrants an explanation on what modes it can be used with.

### Assumptions

We assume here that you already have a mintlayer node running as a daemon. If you're using the GUI, all the information about that is included in the GUI itself. There is no need to get into this. This tutorial is more for those who would like to automate services or deal with CLI (Command Line Interface) design for rented VPS and root servers, or maybe on a Raspberry Pi in their basement.

### How are wallets stored?

Our wallets use BIP-39 for deriving a master key from seed words. It also uses BIP-32 for deriving child keys, and finally BIP-44 is used for path derivation. The path is `m/44'/'19788/'0/0/0` for mainnet and `m/44'/'1/'0/0/0` for testnet.

Wallets load the 12- or 24-word seed (and possibly the passphrase as well), then follow the above-mentioned standards for key derivation.

All the data of the wallet is stored in what is called a "wallet file". The wallet file may or may not contain the seed phrase, depending on the security settings.

### Authentication to RPC

The node, by default, simplifies RPC security by creating what is called a "cookie file". A cookie file is a file that is created in the data directory of the node. In order to prevent any users of the computer from accessing the node with no proper permissions, the cookie file is created with randomly generated passwords on every run of the node. The wallet can automatically detect the cookie file and attempt to use it to reach the node. This way, the experience for the users, especially novice users, is seamless and is also secure, where unauthorized access to another account in the machine does not entail a breach in the node.

In case a different mode of authentication is desired, the user can check the available security options by running the node with the `--help` command line argument. Using simple username and password is possible. It is also designed to be timing resistant, hence, brute-forcing the password will only work if the password is short. We recommend using very long and randomized passwords for good security.

### Port accessibility of RPC servers in the node (and wallet)

Assuming you have a node running with an accessible RPC port (default for mainnet is 3030, and for testnet is 13030), the wallet will communicate with the RPC node to read block data and recognize if any of the transactions (or the block reward) in the block belong to the wallet in question. A wallet without a node will not work. Hence, from here on we always assume there is a node reachable to the wallet.

Note that all the port numbers and bindings for the RPC, whether for the node or the wallet, are fully configurable. Run the node or wallet executables with `--help` option to see how to do that. The `bind` ports is what you are looking for in that case.


### Security

The security of the wallet and node is the responsibility of the node operator. Mintlayer does not bear any of the responsibility for the mismanagement of a node. For example, binding to the network address `0.0.0.0` without a firewall is an open invitation for bots to brute-force the server and attempt to break it. Please exercise good security practices when managing a node. More information can be found [here](/build-tools/linux-systemd-service/README.md).

### Modes of operation for the wallet

At a time, a wallet file can only be open by one program.

There are two distinct executables for the wallet:

#### wallet-cli

The command-line interface of the wallet. The wallet-cli can be simply started by running it, and a wallet can be created with the `wallet-create` or an existing wallet file opened with the command `wallet-open`. A wallet can also be opened automatically on launch using command line arguments. Run the wallet-cli with the `--help` command line argument to see what options are available.

The wallet-cli can be run in many modes. Please consult the `--help` command-line arguments to see how each of these are achieved. We do not list explicit command-line arguments here to ensure that information is never outdated. Here are the modes of operation:

1. It can be run as a simple wallet-file manager. It creates/opens a file, and the user interacts with it by keyboard.
2. In addition to a simple wallet-file manager, it can also be used as an RPC server (enabled with a command line argument), allowing the user to access the wallet from the outside.
3. Instead of the previous options, it can be used as a lightweight controller of a remote RPC wallet. Hence, you can run an RPC wallet, and get the wallet-cli to connect to that wallet using RPC, and use the easy commands of the wallet-cli to control that wallet. Notice that this option excludes the other ones.

#### wallet-rpc-daemon

The server that can be used as a service. The wallet-cli cannot be used as a systemd service, due to its requirement to have keyboard interactions. Hence, `wallet-rpc-daemon` can be set up on servers as a service.

The RPC for the wallet (whether from the daemon or cli) has the default port values 3034 for mainnet and 13034 for testnet. There are different modes of authentication similar to those of the node. Run the `wallet-rpc-daemon` with the command-line argument `--help` to see the available options.

Any http and websocket RPC client can communicate with the RPC daemon. To see examples, [visit this readme file](wallet-rpc-daemon/README.md).

#### Cold-wallet mode

Both the `wallet-cli` and `wallet-rpc-daemon` support a "cold wallet" mode, by using the command-line argument `--cold-wallet`. In this mode, the wallet does not attempt communication with a node. This wallet is assumed to not be connected to the internet.

It is highly recommended to not use the cold-wallet file for both cold- and hot-wallets. A cold-wallet file is assumed to only be used for the cold-wallet.
