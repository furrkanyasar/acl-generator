globalThis.localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
import { runFullTestSuite } from './test_runner_node.js';

const res = runFullTestSuite({ maskToWildcard: () => 'WRONG_WILDCARD' });
if (res.failedCount > 0) {
  console.log("INTENTIONAL FAILURE DETECTED! Setting exitCode = 1.");
  process.exitCode = 1;
}
