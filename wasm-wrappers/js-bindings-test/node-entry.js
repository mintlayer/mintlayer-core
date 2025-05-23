import { run_all_tests } from "./dist/main.js";

async function node_run() {
  await run_all_tests();
}

node_run();
