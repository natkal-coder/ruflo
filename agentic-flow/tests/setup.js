"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// Global test setup
const globals_1 = require("@jest/globals");
// Mock fs and path for CLI tests
globals_1.jest.mock('fs', () => ({
    existsSync: globals_1.jest.fn(),
    mkdirSync: globals_1.jest.fn(),
    writeFileSync: globals_1.jest.fn(),
    readFileSync: globals_1.jest.fn().mockReturnValue('{}'),
    promises: {
        readFile: globals_1.jest.fn(),
        writeFile: globals_1.jest.fn(),
        mkdir: globals_1.jest.fn()
    }
}));
globals_1.jest.mock('path', () => ({
    join: globals_1.jest.fn((...paths) => paths.join('/')),
    resolve: globals_1.jest.fn((...paths) => '/' + paths.join('/')),
    dirname: globals_1.jest.fn(),
    basename: globals_1.jest.fn()
}));
// Set longer timeout for async operations
globals_1.jest.setTimeout(30000);
//# sourceMappingURL=setup.js.map