/**
 * Launcher for run_mutation_tests.js
 * Initializes environment mocks before importing ES modules
 */

globalThis.localStorage = {
  getItem: () => null,
  setItem: () => {},
  removeItem: () => {}
};

import('./run_mutation_tests.js');
