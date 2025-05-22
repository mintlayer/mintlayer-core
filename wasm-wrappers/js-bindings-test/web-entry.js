import init from "../pkg/wasm_wrappers.js";

import { run_test } from "./test.js";

async function web_run() {
  // Initialize the wasm module
  await init();
  await run_test();
}

web_run();
