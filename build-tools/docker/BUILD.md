# Building Docker Images for Mintlayer

This document outlines the steps to build Docker images for the Mintlayer node daemon, wallet-cli, and node-gui.

Before building make sure you clone the repository and change the current directory in the root of the repository.

# The python build script

Make sure you have python installed together with the `toml` package, you may want to create a specific environment:

```bash
python3 -m venv env
source env/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install toml
```

In order to build the images run:

```bash
python3 build-tools/docker/build.py
```

NOTE: to change the version of the images use the `-version` flag such as `--version=1.2.3`.

For verifying images are built with use the following command:

```bash
docker images | grep mintlayer
```

The result should similar to the following:

```
$ docker images |grep mintlayer
mintlayer/wallet-cli           0.4.3     57dcc4898a30   2 minutes ago   125MB
mintlayer/node-gui             0.4.3     a2ed3937e081   2 minutes ago   290MB
mintlayer/node-daemon          0.4.3     ad830bf576e3   3 minutes ago   119MB
```
