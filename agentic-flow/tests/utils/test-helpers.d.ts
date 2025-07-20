import { EventEmitter } from 'events';
export declare const createMockProvider: (overrides?: {}) => {
    name: string;
    initialize: jest.Mock<any, any, any>;
    generateResponse: jest.Mock<any, any, any>;
    streamResponse: jest.Mock<any, any, any>;
    validateConfig: jest.Mock<any, any, any>;
    getCapabilities: jest.Mock<any, any, any>;
};
export declare const createMockAgent: (overrides?: {}) => {
    id: string;
    name: string;
    type: string;
    status: string;
    capabilities: string[];
    execute: jest.Mock<any, any, any>;
    stop: jest.Mock<any, any, any>;
    getMetrics: jest.Mock<any, any, any>;
};
export declare const createMockTask: (overrides?: {}) => {
    id: string;
    name: string;
    type: string;
    priority: string;
    status: string;
    dependencies: any[];
    metadata: {};
    createdAt: Date;
    execute: jest.Mock<any, any, any>;
};
export declare const createMockCliContext: (overrides?: {}) => {
    args: any[];
    options: {};
    command: string;
    stdout: {
        write: jest.Mock<any, any, any>;
    };
    stderr: {
        write: jest.Mock<any, any, any>;
    };
    stdin: EventEmitter<[never]>;
    env: {
        [key: string]: string;
        TZ?: string;
    };
};
export declare const createMockMemoryStore: (overrides?: {}) => {
    get: jest.Mock<any, any, any>;
    set: jest.Mock<any, any, any>;
    delete: jest.Mock<any, any, any>;
    has: jest.Mock<any, any, any>;
    list: jest.Mock<any, any, any>;
    clear: jest.Mock<any, any, any>;
};
export declare const createMockMessageBus: () => {
    publish: jest.Mock<void, [topic: any, message: any], any>;
    subscribe: jest.Mock<() => EventEmitter<[never]>, [topic: any, handler: any], any>;
    unsubscribe: jest.Mock<void, [topic: any, handler: any], any>;
    addListener<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    on<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    once<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    removeListener<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    off<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    removeAllListeners(eventName?: string | symbol): EventEmitter<[never]>;
    setMaxListeners(n: number): EventEmitter<[never]>;
    getMaxListeners(): number;
    listeners<K>(eventName: string | symbol): Function[];
    rawListeners<K>(eventName: string | symbol): Function[];
    emit<K>(eventName: string | symbol, ...args: any[]): boolean;
    listenerCount<K>(eventName: string | symbol, listener?: Function): number;
    prependListener<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    prependOnceListener<K>(eventName: string | symbol, listener: (...args: any[]) => void): EventEmitter<[never]>;
    eventNames(): (string | symbol)[];
};
export declare const createMockWorkflow: (overrides?: {}) => {
    id: string;
    name: string;
    steps: {
        id: string;
        name: string;
        type: string;
    }[];
    status: string;
    execute: jest.Mock<any, any, any>;
    pause: jest.Mock<any, any, any>;
    resume: jest.Mock<any, any, any>;
    cancel: jest.Mock<any, any, any>;
};
export declare class PerformanceTracker {
    private marks;
    private measures;
    mark(name: string): void;
    measure(name: string, startMark: string, endMark?: string): number;
    getStats(name: string): {
        count: number;
        min: number;
        max: number;
        avg: number;
        median: number;
        p95: number;
        p99: number;
    };
    reset(): void;
}
export declare const expectAsync: (fn: () => Promise<any>) => Promise<{
    toThrow: (expected?: string | RegExp | Error) => void;
    toResolve: () => void;
}>;
export declare const generateTestData: {
    messages: (count: number) => {
        role: string;
        content: string;
    }[];
    agents: (count: number) => {
        id: string;
        name: string;
        type: string;
        status: string;
        capabilities: string[];
        execute: jest.Mock<any, any, any>;
        stop: jest.Mock<any, any, any>;
        getMetrics: jest.Mock<any, any, any>;
    }[];
    tasks: (count: number) => {
        id: string;
        name: string;
        type: string;
        priority: string;
        status: string;
        dependencies: any[];
        metadata: {};
        createdAt: Date;
        execute: jest.Mock<any, any, any>;
    }[];
};
//# sourceMappingURL=test-helpers.d.ts.map