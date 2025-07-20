// Global test setup
import { jest } from '@jest/globals';

// Mock fs and path for CLI tests
jest.mock('fs', () => ({
  existsSync: jest.fn(),
  mkdirSync: jest.fn(),
  writeFileSync: jest.fn(),
  readFileSync: jest.fn().mockReturnValue('{}'),
  promises: {
    readFile: jest.fn(),
    writeFile: jest.fn(),
    mkdir: jest.fn()
  }
}));

jest.mock('path', () => ({
  join: jest.fn((...paths) => paths.join('/')),
  resolve: jest.fn((...paths) => '/' + paths.join('/')),
  dirname: jest.fn(),
  basename: jest.fn()
}));

// Set longer timeout for async operations
jest.setTimeout(30000);