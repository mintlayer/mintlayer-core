Here is an example `docker compose` project that runs the DNS server inside a Docker container.

How to use:
----------
1. Copy this directory to another location. Edit the `.env` file, specifying the required settings.

2. `cd` to the copied project directory.

    To start the available services, run `docker compose up`.
    To shut it down, run `docket compose down`.

    (See `example-mainnet/README.md` for more info on what additional parameters can be specified for `docker compose` and how to make logging more verbose).