# Wallet RPC

This crate provides the ability to control a Mintlayer wallet via RPC. It exposes methods
to generate addresses, query balances, submit transactions, stake coins and more.

At the moment, the wallet needs to connect to a full node to be operational.

The full set of methods is specified in [src/rpc/interface.rs](src/rpc/interface.rs).

## Accessing from command line

Using `curl` over HTTP (replace all caps placeholders as appropriate):

```sh
curl -H 'Content-Type: application/json' \
  -d '{"jsonrpc": "2.0", "id": ID, "method": METHOD, "params": [PARAM1, PARAM2, ...]}' \
  USER:PASS@HOST:PORT
```

Using `websocat` over WebSockets (replace all caps placeholders as appropriate):

```sh
websocat --jsonrpc USER:PASS@HOST:PORT
```

And then type in the method invocations one per line in the following format:
```
METHOD PARAM1 PARAM2 ...
```

## Value representations

* Wallet account IDs are represented as hex strings.
* Wallet addresses and pool IDs are represented as `bech32` strings
* Coin / token amounts are represented as strings containing the decimal number with the amount.
  This is to avoid the loss of precision due to internal number representation in Json libraries
  which is often a floating point number.

## Event notifications

**Important**: The event notification feature only works when connecting to the RPC via WebSockets.

It is often useful to be notified when state changes, e.g. the wallet receives a new transaction,
a transaction is confirmed or a new block arrives. For this, a special `subscribe_wallet_events`
RPC method has been introduced.

Events can be unsubscribed by calling the `unsubscribe_wallet_events` RPC method called with
the subscription ID as an argument.

The mechanism to subscribe to and to deliver events follows the [Ethereum pubsub spec][1].
However, the emitted events take slightly different shape.

To see how the events are defined in full detail, see the `Event` type
in [src/service/events.rs](src/service/events.rs).

### NewBlock

```json
{"NewBlock": {}}
```

New block has been connected to the best chain.

### TxUpdated

```json
{"TxUpdated": {
  "account_id": ACCOUNT_ID,
  "tx_id": TRANSACTION_ID,
  "state": TRANSACTION_STATE,
}}
```

Transaction state has been updated. This is also emitted for new transactions.

Here, `ACCOUNT_ID` is a unique string of wallet account ID.

### TxDropped

```json
{"TxDropped": {
  "account_id": ACCOUNT_ID,
  "tx_id": TRANSACTION_ID,
}}
```

The transaction is no longer tracked by the wallet.

### RewardAdded

```json
{"RewardAdded": {
  "account_id": ACCOUNT_ID,
  "block_id": BLOCK_ID,
  "height": BLOCK_HEIGHT,
  "timestamp": BLOCK_TIMESTAMP,
  "utxos": LIST_OF_REWARD_UTXOS,
  ...
}}
```

Wallet received a block reward.

### RewardDropped

```json
{"RewardDropped": {
  "account_id": ACCOUNT_ID,
  "block_id": BLOCK_ID,
}}
```

Reward dropped due to being reorged out.

[1]: https://geth.ethereum.org/docs/interacting-with-geth/rpc/pubsub
