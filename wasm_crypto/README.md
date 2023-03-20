### Basic wasm bindings for cryptography

##### Note: This was tested on x86_64 Linux, and may not work on other platforms. It didn't work on M1 Mac (particularly the build. A pre-built wasm binary works fine on a browser).

Make sure you have wasm-pack:

```
cargo install wasm-pack
```

To build the wasm package from the crate, run (in the wasm Cargo.toml directory):

```
wasm-pack build --target web
```

To test the wasm binary. First, install `http-server` web server (feel free to use any other web-server of your choosing):

```
cargo install http-server
```

Then run the http server, run the following then choose the `index.html` file:

```
http-server --port 8080 --verbose
```

If you're using a remote server, either tunnel to port 8080, or expose that port and run this (assuming you understand the security risks):

```
http-server --port 8080 --host 0.0.0.0 --verbose
```

The ported wasm functions are exported to the file `index.html` with a basic test/example in them using JavaScript. Use your browser's console to see the output.

### Further documentation

- https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm
- https://rustwasm.github.io/wasm-bindgen/introduction.html
