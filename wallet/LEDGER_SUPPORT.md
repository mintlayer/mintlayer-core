## Using Mintlayer with Ledger

At this moment Mintlayer Ledger App is not among the official Ledger apps, so you'll have to build
and install it yourself. See https://github.com/mintlayer/mintlayer-ledger-app/blob/master/README.md
for the details on how to do it.

ℹ️ If you want to use a Mintlayer wallet with Mintlayer Ledger App running in the emulator (Speculos),
note that the wallet expects the emulator to be available on port 1237, while the instructions
in the app's README use port 9999. Make sure you pass 1237 as `--apdu-port` to Speculos, or, if you're
running it in the Docker container, map the host port 1237 to whatever you use inside the container,
e.g. `--publish 1237:9999`.
