# Building Docker Images for Mintlayer

This document outlines the steps to build Docker images for the Mintlayer node daemon, wallet-cli, and node-gui. 

Before building make sure you clone the repository and change directory in the root of the repository.


## Building the Node Daemon Docker Image

To build the Docker image for the node daemon, follow these steps:

```bash
docker build -f docker/Dockerfile.node-daemon -t node-daemon .
```


## Building the Wallet-CLI Docker Image

To build the Docker image for the wallet-cli, follow these steps:

```bash
docker build -f docker/Dockerfile.wallet-cli -t wallet-cli .
```


## Building the Node-GUI Docker Image

Node-gui is a graphical interface that runs the node itself in the background. 
To build the Docker image for the node-gui, follow these steps:

```bash
docker build -f docker/Dockerfile.node-gui -t node-gui .
```



## Verify the builds 

Once the build process finishes, you can verify the image was created successfully by running:

```bash
docker images
```
