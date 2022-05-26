# Functional tests for Mintlayer

Based on `tests/functional` framework taken from Bitcoin.

## Cargo integration

Functional tests are marked as ignored so they do not run as part of full suite run.
To run the tests, it is necessary to pass the `--ignored` or `--include-ignored` options.

To run functional tests:

```sh
cargo test -p mintlayer-test --test functional -- --ignored
```

Extra command line arguments passed to `test_runner.py` are placed after another `--`:

```sh
cargo test -p mintlayer-test --test functional -- [harness args] -- [test_runner.py args]
```

If `test_runner.py` arguments are present (even empty), the `--ignored` flag is not needed.
The following will still run functional tests:

```sh
cargo test -p mintlayer-test --test functional -- -- [test_runner.py args]
```

It is handy to define an alias to run the tests:

```toml
[alias]
functional-tests = ['test', '-pmintlayer-test', '--test=functional', '--', '--ignored', '--']
```

Then the tests can be run simply like this:

```sh
cargo functional-tests [test_runner.py args]
```

## Running without Cargo

The Python test runner requires a config file. It can be created manually but it's more convenient
to run the tests once through Cargo as described above.

The file will appear in `target/tmp/config.ini`, unless a different target directory is specified.

TODO: In the future, the test generation will be done during build rather than on test run.

We can then run the tests directly:

```sh
./test/functional/test_runner.py --configfile ./target/tmp/config.ini
```
