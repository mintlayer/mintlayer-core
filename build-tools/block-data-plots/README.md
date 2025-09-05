## A bunch of helper scripts to produce a target and a timestamp difference plots.

First run `collect_data.py` to collect data from an api server instance.

Then run `show_plots.py` to show the plots. By default, the script will plot the entire set of
data; use the `--recent-days` parameter to only plot the data from the last few days.

`api-server-docker-compose-mainnet` and `api-server-docker-compose-testnet` are helper
docker compose projects that spin up a node and an API server instance.\
They're basically copies of `build-tools/docker/example-mainnet` with unneeded executables removed.\
Use `build-tools/docker/build.py --latest` to build the images and tag them as `latest` (which is
expected by the projects' `.env` files).
