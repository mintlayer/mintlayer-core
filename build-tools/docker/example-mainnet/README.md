Here is an example `docker compose` project that runs various Mintlayer binaries
inside Docker containers.

How to use:
----------
1. Copy this directory to another location. Optionally, edit `docker-compose.yml`,
commenting out services that you won't need. Edit values in `.env` according to your needs.

    Then `cd` to the copied project directory.


2. To start the available services, run `docker compose up`.

    When the corresponding docker containers start, their `home` directories will be mounted
    to the `container_home` subdirectory of the project directory. You have to make sure
    that the directory is writable by a user with uid 1000.

    Note: this `container_home` directory will contain all the data produced by the containers
    except for the api-server's database, which will be stored in a dedicated docker volume.

    Additionally, you can pass `-d` (or `--detach`) to `docker compose up` to run the containers
    in detached mode.
    To examine the logs in this case you can run `docker compose logs -f`.

    Note: the `RUST_LOG` environment variable is propagated into the containers, so if you need
    more verbose logging, just set `RUST_LOG` on the host system, e.g. to `debug`.

    Finally, to stop and remove the containers, run `docker compose down`.

3. It's also possible to run `wallet-cli` interactively in a docker container as well.
    To do so, run the following after starting the services:
    ```
    docker compose exec node-daemon wallet-cli
    ```
