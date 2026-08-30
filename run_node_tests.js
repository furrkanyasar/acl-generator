/**
 * Launcher script for Node.js integration tests
 * Initializes environment mocks before importing ES modules
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import('./test_runner_node.js');
