Here we have helper docker files and an init script that allow us to run multiple `regtest` nodes
on the same machine in order to check that staking works as expected.

### Details

The init script `init_and_start_staking.py` expects a certain number of nodes (represented by
an equal number of `node-daemon` and `wallet-rpc-daemon` instances) to be already running;
it expects them to use specific port numbers for RPC (the corresponding values are hard-coded in
the script) and certain other arguments.

The expected `node-daemon` arguments are:
- `--blockprod-min-peers-to-produce-blocks=0`
- `--blockprod-use-current-time-if-non-pos`
- `--chain-pos-netupgrades=3`
- `--max-tip-age=1000000000`

  (The max tip age argument doesn't have to have exactly this value, but it should be big enough,
  so that `Regtest`'s genesis is not considered stale).

Also, you'd want to use the same initial difficulty for PoS that it used for `Mainnet` and `Testnet`,
to mimic the actual staking. To do so, specify:
- `--chain-initial-difficulty=419627008`

  (The value `419627008`, which equals `0x19260000` in hex, is the `Compact` representation of
  the difficulty used by `pos_initial_difficulty` in `common/src/chain/pos/mod.rs` for `Mainnet`
  and `Testnet`.)

> 📌 Note: the option `--chain-pos-netupgrades=3` must also be passed to `wallet-rpc-daemon`.

Upon startup, the init script will check whether the test is being started from scratch (by checking
whether the first node has any blocks above genesis); if so, it will create a couple of `IgnoreConsensus`
blocks where it will distribute some coins between nodes and create some pools and delegations.
After that, it will start staking on all nodes.

> 📌 Note: the provided `docker compose` files will start the required number of nodes using all the required arguments.
