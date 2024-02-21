Here are some example `docker compose` scripts that run various Mintlayer binaries
inside Docker containers.

First, `cd` to this directory and then:

1. To start the node only, run:
    ```
    docker compose -f docker-compose.node.yml up
    ```

2. To start the API server, run:
    ```
    docker compose -f docker-compose.node.yml -f docker-compose.api.yml up
    ```
    Note that you have to specify `docker-compose.node.yml` too, because the api server needs
    the node and `docker compose` won't find its `.yml` file automatically.

---

> Note:
> - You can pass `-d` (or `--detach`) to `docker compose up` to run the containers in detached mode.
    To examine the logs in this case you can run `docker compose logs -f`.
> - To stop and remove the containers, run `docker compose down`.
    Note that this won't remove docker volumes that contain the binaries' data.

---

3. To run `wallet-cli`:
    ```
    docker compose -f docker-compose.wallet.yml -f docker-compose.node.yml run --rm wallet-cli
    ```
    Same as above, you need to specify `docker-compose.node.yml`, because the wallet needs a node.
    Note that if the node container is already running, it won't be started the second time, but
    you still have to specify its `.yml` file.
    Also note that here you use `docker compose run` instead of `up`.
