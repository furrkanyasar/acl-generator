/**
 * Launcher for run_all_tests.js
 * Initializes environment mocks before importing ES modules
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import('./run_all_tests.js');
