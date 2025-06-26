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

### Build the wasm package

In the wasm Cargo.toml directory, execute one of the following:
  * for running the tests in a web browser:
    ```
    wasm-pack build --target web
    ```

  * for running the tests in Node.js:
    ```
    wasm-pack build --target nodejs
    ```

### Compile the tests via `tsc`

In the wasm Cargo.toml directory, run:
```
tsc --project js-bindings-test/tsconfig.json
```

### Run the tests in a web browser

To test the wasm binary, first install `http-server` web server (feel free to use any other web-server of your choosing):

```
cargo install http-server
```

Then run the http server:

```
http-server --port 8080
```

If you're using a remote server, either tunnel to port 8080, or expose that port and run this (assuming you understand the security risks):

```
http-server --port 8080 --host 0.0.0.0
```

To run the tests, choose the file `js-bindings-test/index.html` in the browser. Use browser's console to see the output.

### Run the tests in Node.js

In the wasm Cargo.toml directory, execute the following:
```
node --enable-source-maps js-bindings-test/node-entry.js
```

### Run `knip`

We use `knip` to make sure that there are no unused exports in `js-bindings-test/tests` (which could
mean that some of the tests are never run).

**Note: unused local definitions are caught by the TypeScript compiler itself, via the `noUnusedLocals` setting.**

To run `knip` locally, first install it:
```
npm install -g knip
```

And then run (in the wasm Cargo.toml directory):
```
(cd js-bindings-test && npx knip)
```

**Note: to explicitly exclude an export from `knip`'s report, annotate it with `/** @public */`.**

### Further documentation on wasm

- https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_wasm
- https://rustwasm.github.io/wasm-bindgen/introduction.html

### Mintlayer WASM Wrappers Function API documentation

[You can find the public functions documentations here](WASM-API.md)
