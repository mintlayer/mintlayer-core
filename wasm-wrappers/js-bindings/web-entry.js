import init from "../pkg/wasm_crypto.js";

import { run_test } from "./crypto_test.js";

async function web_run() {
  // Initialize the wasm module
  await init();
  await run_test();
}

web_run();
