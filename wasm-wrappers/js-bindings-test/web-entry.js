import init from "../pkg/wasm_wrappers.js";

import { run_all_tests } from "./dist/main.js";

async function web_run() {
  // Initialize the wasm module
  await init();
  await run_all_tests();
}

web_run();
