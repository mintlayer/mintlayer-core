# Basic wasm bindings for mintlayer

This module has different basic functionalities of mintlayer compiled into wasm for various purposes, primarily interfacing with other systems and languages without having to rewrite code.

##### Note: This was tested on x86_64 Linux, and may not work on other platforms. It didn't work on M1 Mac directly (particularly the build. A pre-built wasm binary works fine on a browser, see below for more information).

## Running the tests

### Preparation

Make sure you have wasm-pack and the wasm32-unknown-unknown target installed:

```
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

Also make sure you have `clang` installed. It's required.

**Note for mac users**: `llvm` installed by Xcode doesn't support wasm targets, but the homebrew version does, these commands may make it possible to compile to wasm targets. Note that using these commands could have other side effects on your toolchain. Please consider researching the clang toolchain and how it works before using them. We do not recommend copying and pasting commands without fully understanding the side-effects.
```
brew install llvm
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack build --target web
```

Also, install TypeScript:
```
npm install -g typescript
```

### Compile the tests via `tsc`

In the wasm Cargo.toml directory, run:
```
tsc --project js-bindings-test/tsconfig.json
```

### Running the tests in a web browser

To build the wasm package from the crate, run (in the wasm Cargo.toml directory):

```
wasm-pack build --target web
```

To test the wasm binary. First, install `http-server` web server (feel free to use any other web-server of your choosing):

```
cargo install http-server
```

Then run the http server, and then choose the file `js-bindings-test/index.html`:

```
http-server --port 8080
```

If you're using a remote server, either tunnel to port 8080, or expose that port and run this (assuming you understand the security risks):

```
http-server --port 8080 --host 0.0.0.0
```

The ported wasm functions are exported to the file `js-bindings-test/index.js` and used in the file `js-bindings-test/index.html` with a basic test/example in them using JavaScript. Use your browser's console to see the output.

### Running the tests in Node.js

To build the wasm package from the crate, run (in the wasm Cargo.toml directory):

```
wasm-pack build --target nodejs
```

Finally, to run the example, run:

```
node --enable-source-maps  js-bindings-test/node-entry.js
```

### Further documentation on wasm

- https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm
- https://rustwasm.github.io/wasm-bindgen/introduction.html

### Mintlayer WASM Wrappers Function API documentation

[You can find the public functions documentations here](WASM-API.md)
