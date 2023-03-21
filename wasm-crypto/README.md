## Basic wasm bindings for cryptography

##### Note: This was tested on x86_64 Linux, and may not work on other platforms. It didn't work on M1 Mac (particularly the build. A pre-built wasm binary works fine on a browser).

### To run in a web browser

Make sure you have wasm-pack and the wasm32-unknown-unknown target installed:

```
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Also make sure you have `clang` installed. It's required.

To build the wasm package from the crate, run (in the wasm Cargo.toml directory):

```
wasm-pack build --target web
```

To test the wasm binary. First, install `http-server` web server (feel free to use any other web-server of your choosing):

```
cargo install http-server
```

Then run the http server, and then choose the file `js-bindings/index.html`:

```
http-server --port 8080 --verbose
```

If you're using a remote server, either tunnel to port 8080, or expose that port and run this (assuming you understand the security risks):

```
http-server --port 8080 --host 0.0.0.0 --verbose
```

The ported wasm functions are exported to the file `js-bindings/index.js` and used in the file `js-bindings/index.html` with a basic test/example in them using JavaScript. Use your browser's console to see the output.

### To run in Node.js

Make sure you have wasm-pack and the wasm32-unknown-unknown target installed:

```
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Also make sure you have `clang` installed. It's required.

To build the wasm package from the crate, run (in the wasm Cargo.toml directory):

```
wasm-pack build --target nodejs
```

Finally, to run the example, run:

```
node js-bindings/node-entry.js
```

### Further documentation

- https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm
- https://rustwasm.github.io/wasm-bindgen/introduction.html
