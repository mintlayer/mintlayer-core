## node-daemon

For more information about the node-daemon, please visit [the main readme file](/README.md).

### RPC commands

You can find the documentation for all available RPC commands [in this readme file](RPC.md).

### RPC examples

To use the commands mentioned above, we provide simple examples on how to do it with CURL [in this readme file](/rpc/README.md).

### Logging

The node logs to stderr and, when `--log-to-file true` is given (the default for node-gui, off for node-daemon), also to a file.

Every logging option can be given on the command line, set with an environment variable (`ML_NODE_` followed by the option name in upper case with underscores) or written in the `[logging]` section of the `config.toml` file in the data directory. A command line value wins over the environment variable, which wins over the config file, which wins over the default.

| Option | Config file key | Default | Meaning |
|---|---|---|---|
| `--log-to-file <true\|false>` | `log_to_file` | `false` (`true` for node-gui) | also write the logs to a file |
| `--log-file-path <PATH>` | `log_file_path` | `<data dir>/logs/<executable name>.log` | location of the log file; a relative path is resolved against the data directory |
| `--log-file-format <text\|json>` | `log_file_format` | `text` | format of the log file |
| `--log-format <text\|json>` | `log_format` | unset | format of the stderr output; when unset, the `ML_LOG_STYLE` env variable applies as before |
| `--log-file-max-size-bytes <BYTES>` | `log_file_max_size_bytes` | `10000000` | size at which the log file is rotated |
| `--log-file-max-files <COUNT>` | `log_file_max_files` | `14` | number of files kept by the rotation, including the current one |
| `--log-fields <KEY=VALUE,...>` | `log_fields` | unset | extra `key=value` fields added to the log lines that carry the enrichment fields (see below) |
| `--log-source-location <true\|false>` | `log_source_location` | `false` | include the source file name and line number |
| `--log-thread-info <true\|false>` | `log_thread_info` | `false` | include the thread id and thread name |

Notes:

- Setting `--log-file-path` does not enable logging to a file; `--log-to-file true` is still required.
- The file always receives the logs of the `info` level and above, regardless of `RUST_LOG`. `RUST_LOG` and the default filter apply to stderr only.
- The log file is created with owner-only permissions on Linux and macOS; a file that already exists at `--log-file-path` with wider permissions is restricted to the owner when the node starts. Anything but a regular file at that path (a directory, a symbolic link, a device) is refused. A path that cannot be used (for example a directory that cannot be created) stops the node with an error before it starts.
- The file is rotated once a write has pushed its size past `--log-file-max-size-bytes`, so a line is never split between two files and every line of the json file stays a complete object.
- The `[logging]` section is new in this version: an older node rejects a `config.toml` that contains it, and the section itself rejects unknown keys.
- With none of these options set, the sinks are the same as before: text on stderr, and the optional text file in the default location. The enriched fields described below are added either way.

#### Enriched fields and the json format

The log lines of the node and its subsystems that run inside the node's span (see below) carry the node version, the chain type and the process id, plus the `--log-fields` entries. In the json format they are the first element of the `spans` array; with `--log-source-location` and `--log-thread-info` the location and thread fields are added to the line as well:

```json
{"timestamp":"2026-11-25T12:00:00.123456Z","level":"INFO","target":"chainstate",
 "fields":{"message":"Block processed"},
 "filename":"chainstate/src/lib.rs","line_number":123,"threadId":"ThreadId(2)","threadName":"tokio-rt-worker",
 "spans":[{"name":"node","version":"1.5.0","chain":"mainnet","pid":12345,"role":"seed"}]}
```

Each line is a complete json object, so the file can be consumed line by line by external tools. In the text format the same fields are printed as a span prefix in front of the target:

```
2026-11-25T12:00:00.123456Z  INFO node{version="1.5.0" chain="mainnet" pid=12345 role="seed"}: chainstate: Block processed
```

The fields come from a span that the node enters on the thread running its startup and that the node manager, which runs the subsystems, is run under explicitly. In node-daemon the lines emitted during the startup carry the fields as well; in node-gui the startup runs on an executor thread, so only the lines of the node manager and its subsystems are guaranteed to carry them. Lines emitted from threads started outside the node, such as blocking tasks, do not carry the fields either way. To leave the prefix out of the stderr output, disable the target of the enrichment span with `RUST_LOG=logging::enrichment=off`; the file sink cannot be configured this way.

#### `config.toml` example

```toml
[logging]
log_to_file = true
log_file_path = "logs/node.jsonl"
log_file_format = "json"
log_fields = ["role=seed", "dc=eu"]
log_thread_info = true
```
