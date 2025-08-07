# Node RPC

RPC is used to communicate with the node and retrieve data from it. For example, the wallet uses RPC to sync with the node and load relevant transactions.
The data can be simple information from the node, such as current block height, or can be a subscription to events happening in the node,
such as new block tip arriving in the node.

RPC server binds to one port for the node. By default, this port is 3030 (13030 for testnet) for the node.
This port is used for both http and websocket communication. However, websocket can do more than http; in addition to the simple request/response for http,
websocket supports also subscribing to events, where subscribers will receive notifications for events in the node.

## Example on using RPC with the command line

Using `curl` over HTTP (replace all caps placeholders as appropriate):

```sh
curl -H 'Content-Type: application/json' -d '{"jsonrpc": "2.0", "id": ID, "method": METHOD, "params": [PARAM1, PARAM2, ...]}' http://USER:PASS@HOST:PORT
```

for example, to get the current state of chainstate

```sh
curl -H 'Content-Type: application/json' -d '{"jsonrpc": "2.0", "id": 1, "method": "chainstate_info", "params": []}' http://username:password@127.0.0.1:3030
```

or if RPC cookies are enabled and you're on the same machine, you can use that directly for authentication (this example is for Linux; mac has a different data directory)

```sh
curl -H 'Content-Type: application/json' --user $(cat ~/.mintlayer/mainnet/.cookie) -d '{"jsonrpc": "2.0", "id": 1, "method": "chainstate_info", "params": []}' http://127.0.0.1:3030
```

where the cookie file will load your username and password.

For websocket, you can use `websocat` (replace all caps placeholders as appropriate):

```sh
websocat ws://USER:PASS@HOST:PORT
```

and then type in the method invocations one per line in the following format:

```
{"jsonrpc": "2.0", "id": ID, "method": METHOD, "params": [PARAM1, PARAM2, ...]}
```

for example, to get the current state of chainstate

```
{"jsonrpc": "2.0", "id": 1, "method": "chainstate_info", "params": []}
```

as another example, since this is websocket, you can also subscribe to events. So to do that, send the function:

```
{"jsonrpc": "2.0", "method": "chainstate_subscribe_to_events", "params":[{}], "id": 1}
```

which will return a confirmation with a result. Then, the node will notify you for events, like new blocks becoming the chainstate tip.
