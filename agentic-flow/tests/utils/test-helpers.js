"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateTestData = exports.expectAsync = exports.PerformanceTracker = exports.createMockWorkflow = exports.createMockMessageBus = exports.createMockMemoryStore = exports.createMockCliContext = exports.createMockTask = exports.createMockAgent = exports.createMockProvider = void 0;
const events_1 = require("events");
// Mock provider factory
const createMockProvider = (overrides = {}) => ({
    name: 'mock-provider',
    initialize: jest.fn().mockResolvedValue(true),
    generateResponse: jest.fn().mockResolvedValue({
        content: 'Mock response',
        usage: { inputTokens: 10, outputTokens: 20 },
    }),
    streamResponse: jest.fn().mockImplementation(async function* () {
        yield { content: 'Mock', usage: { inputTokens: 5, outputTokens: 10 } };
        yield { content: ' response', usage: { inputTokens: 5, outputTokens: 10 } };
    }),
    validateConfig: jest.fn().mockReturnValue(true),
    getCapabilities: jest.fn().mockReturnValue({
        streaming: true,
        functions: true,
        vision: false,
    }),
    ...overrides,
});
exports.createMockProvider = createMockProvider;
// Mock agent factory
const createMockAgent = (overrides = {}) => ({
    id: 'mock-agent-' + Math.random().toString(36).substr(2, 9),
    name: 'Mock Agent',
    type: 'researcher',
    status: 'idle',
    capabilities: ['analysis', 'research'],
    execute: jest.fn().mockResolvedValue({ success: true, result: 'Mock result' }),
    stop: jest.fn().mockResolvedValue(true),
    getMetrics: jest.fn().mockReturnValue({
        tasksCompleted: 0,
        averageExecutionTime: 0,
        successRate: 100,
    }),
    ...overrides,
});
exports.createMockAgent = createMockAgent;
// Mock task factory
const createMockTask = (overrides = {}) => ({
    id: 'task-' + Math.random().toString(36).substr(2, 9),
    name: 'Mock Task',
    type: 'analysis',
    priority: 'medium',
    status: 'pending',
    dependencies: [],
    metadata: {},
    createdAt: new Date(),
    execute: jest.fn().mockResolvedValue({ success: true, result: 'Task completed' }),
    ...overrides,
});
exports.createMockTask = createMockTask;
// Mock CLI context
const createMockCliContext = (overrides = {}) => ({
    args: [],
    options: {},
    command: 'test',
    stdout: {
        write: jest.fn(),
    },
    stderr: {
        write: jest.fn(),
    },
    stdin: new events_1.EventEmitter(),
    env: { ...process.env },
    ...overrides,
});
exports.createMockCliContext = createMockCliContext;
// Mock memory store
const createMockMemoryStore = (overrides = {}) => ({
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue(true),
    delete: jest.fn().mockResolvedValue(true),
    has: jest.fn().mockResolvedValue(false),
    list: jest.fn().mockResolvedValue([]),
    clear: jest.fn().mockResolvedValue(true),
    ...overrides,
});
exports.createMockMemoryStore = createMockMemoryStore;
// Mock message bus
const createMockMessageBus = () => {
    const bus = new events_1.EventEmitter();
    return {
        ...bus,
        publish: jest.fn((topic, message) => {
            bus.emit(topic, message);
        }),
        subscribe: jest.fn((topic, handler) => {
            bus.on(topic, handler);
            return () => bus.off(topic, handler);
        }),
        unsubscribe: jest.fn((topic, handler) => {
            bus.off(topic, handler);
        }),
    };
};
exports.createMockMessageBus = createMockMessageBus;
// Mock workflow
const createMockWorkflow = (overrides = {}) => ({
    id: 'workflow-' + Math.random().toString(36).substr(2, 9),
    name: 'Mock Workflow',
    steps: [
        { id: 'step-1', name: 'Initialize', type: 'init' },
        { id: 'step-2', name: 'Process', type: 'process' },
        { id: 'step-3', name: 'Complete', type: 'complete' },
    ],
    status: 'idle',
    execute: jest.fn().mockResolvedValue({ success: true, results: [] }),
    pause: jest.fn().mockResolvedValue(true),
    resume: jest.fn().mockResolvedValue(true),
    cancel: jest.fn().mockResolvedValue(true),
    ...overrides,
});
exports.createMockWorkflow = createMockWorkflow;
// Performance testing utilities
class PerformanceTracker {
    marks = new Map();
    measures = new Map();
    mark(name) {
        this.marks.set(name, performance.now());
    }
    measure(name, startMark, endMark) {
        const start = this.marks.get(startMark);
        const end = endMark ? this.marks.get(endMark) : performance.now();
        if (!start)
            throw new Error(`Start mark "${startMark}" not found`);
        if (endMark && !this.marks.has(endMark)) {
            throw new Error(`End mark "${endMark}" not found`);
        }
        const duration = (end || performance.now()) - start;
        if (!this.measures.has(name)) {
            this.measures.set(name, []);
        }
        this.measures.get(name).push(duration);
        return duration;
    }
    getStats(name) {
        const measures = this.measures.get(name) || [];
        if (measures.length === 0)
            return null;
        const sorted = [...measures].sort((a, b) => a - b);
        const sum = sorted.reduce((a, b) => a + b, 0);
        return {
            count: sorted.length,
            min: sorted[0],
            max: sorted[sorted.length - 1],
            avg: sum / sorted.length,
            median: sorted[Math.floor(sorted.length / 2)],
            p95: sorted[Math.floor(sorted.length * 0.95)],
            p99: sorted[Math.floor(sorted.length * 0.99)],
        };
    }
    reset() {
        this.marks.clear();
        this.measures.clear();
    }
}
exports.PerformanceTracker = PerformanceTracker;
// Async test utilities
const expectAsync = async (fn) => {
    let error = null;
    try {
        await fn();
    }
    catch (e) {
        error = e;
    }
    return {
        toThrow: (expected) => {
            if (!error) {
                throw new Error('Expected function to throw, but it did not');
            }
            if (expected) {
                if (typeof expected === 'string') {
                    expect(error.message).toContain(expected);
                }
                else if (expected instanceof RegExp) {
                    expect(error.message).toMatch(expected);
                }
                else {
                    expect(error).toBeInstanceOf(expected.constructor);
                }
            }
        },
        toResolve: () => {
            if (error) {
                throw error;
            }
        },
    };
};
exports.expectAsync = expectAsync;
// Test data generators
exports.generateTestData = {
    messages: (count) => Array.from({ length: count }, (_, i) => ({
        role: i % 2 === 0 ? 'user' : 'assistant',
        content: `Test message ${i + 1}`,
    })),
    agents: (count) => Array.from({ length: count }, (_, i) => (0, exports.createMockAgent)({
        id: `agent-${i}`,
        name: `Agent ${i + 1}`,
        type: ['researcher', 'coder', 'analyst'][i % 3],
    })),
    tasks: (count) => Array.from({ length: count }, (_, i) => (0, exports.createMockTask)({
        id: `task-${i}`,
        name: `Task ${i + 1}`,
        priority: ['low', 'medium', 'high'][i % 3],
    })),
};
//# sourceMappingURL=test-helpers.js.map