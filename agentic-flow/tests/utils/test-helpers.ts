import { EventEmitter } from 'events';

// Mock provider factory
export const createMockProvider = (overrides = {}) => ({
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

// Mock agent factory
export const createMockAgent = (overrides = {}) => ({
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

// Mock task factory
export const createMockTask = (overrides = {}) => ({
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

// Mock CLI context
export const createMockCliContext = (overrides = {}) => ({
  args: [],
  options: {},
  command: 'test',
  stdout: {
    write: jest.fn(),
  },
  stderr: {
    write: jest.fn(),
  },
  stdin: new EventEmitter(),
  env: { ...process.env },
  ...overrides,
});

// Mock memory store
export const createMockMemoryStore = (overrides = {}) => ({
  get: jest.fn().mockResolvedValue(null),
  set: jest.fn().mockResolvedValue(true),
  delete: jest.fn().mockResolvedValue(true),
  has: jest.fn().mockResolvedValue(false),
  list: jest.fn().mockResolvedValue([]),
  clear: jest.fn().mockResolvedValue(true),
  ...overrides,
});

// Mock message bus
export const createMockMessageBus = () => {
  const bus = new EventEmitter();
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

// Mock workflow
export const createMockWorkflow = (overrides = {}) => ({
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

// Performance testing utilities
export class PerformanceTracker {
  private marks: Map<string, number> = new Map();
  private measures: Map<string, number[]> = new Map();

  mark(name: string): void {
    this.marks.set(name, performance.now());
  }

  measure(name: string, startMark: string, endMark?: string): number {
    const start = this.marks.get(startMark);
    const end = endMark ? this.marks.get(endMark) : performance.now();
    
    if (!start) throw new Error(`Start mark "${startMark}" not found`);
    if (endMark && !this.marks.has(endMark)) {
      throw new Error(`End mark "${endMark}" not found`);
    }

    const duration = (end || performance.now()) - start;
    
    if (!this.measures.has(name)) {
      this.measures.set(name, []);
    }
    this.measures.get(name)!.push(duration);
    
    return duration;
  }

  getStats(name: string) {
    const measures = this.measures.get(name) || [];
    if (measures.length === 0) return null;

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

  reset(): void {
    this.marks.clear();
    this.measures.clear();
  }
}

// Async test utilities
export const expectAsync = async (fn: () => Promise<any>) => {
  let error: Error | null = null;
  try {
    await fn();
  } catch (e) {
    error = e as Error;
  }
  return {
    toThrow: (expected?: string | RegExp | Error) => {
      if (!error) {
        throw new Error('Expected function to throw, but it did not');
      }
      if (expected) {
        if (typeof expected === 'string') {
          expect(error.message).toContain(expected);
        } else if (expected instanceof RegExp) {
          expect(error.message).toMatch(expected);
        } else {
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

// Test data generators
export const generateTestData = {
  messages: (count: number) => Array.from({ length: count }, (_, i) => ({
    role: i % 2 === 0 ? 'user' : 'assistant',
    content: `Test message ${i + 1}`,
  })),
  
  agents: (count: number) => Array.from({ length: count }, (_, i) => 
    createMockAgent({
      id: `agent-${i}`,
      name: `Agent ${i + 1}`,
      type: ['researcher', 'coder', 'analyst'][i % 3],
    })
  ),
  
  tasks: (count: number) => Array.from({ length: count }, (_, i) => 
    createMockTask({
      id: `task-${i}`,
      name: `Task ${i + 1}`,
      priority: ['low', 'medium', 'high'][i % 3],
    })
  ),
};