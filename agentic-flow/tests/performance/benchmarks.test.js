"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const test_helpers_1 = require("../utils/test-helpers");
const provider_manager_1 = require("../../src/providers/provider-manager");
const anthropic_provider_1 = require("../../src/providers/anthropic-provider");
const test_helpers_2 = require("../utils/test-helpers");
const mock_providers_1 = require("../utils/mock-providers");
// Mock providers for consistent benchmarking
jest.mock('@anthropic-ai/sdk', () => ({
    __esModule: true,
    default: jest.fn().mockImplementation(() => new mock_providers_1.MockAnthropicClient()),
}));
describe('Performance Benchmarks', () => {
    let tracker;
    beforeEach(() => {
        tracker = new test_helpers_1.PerformanceTracker();
    });
    afterEach(() => {
        tracker.reset();
    });
    describe('Provider Performance', () => {
        it('should benchmark single provider response time', async () => {
            const provider = new anthropic_provider_1.AnthropicProvider({
                apiKey: 'test-key',
                model: 'claude-3-opus-20240229',
            });
            await provider.initialize();
            const iterations = 100;
            const messages = [{ role: 'user', content: 'Hello' }];
            for (let i = 0; i < iterations; i++) {
                tracker.mark(`request-${i}-start`);
                await provider.generateResponse(messages);
                tracker.measure('single-response', `request-${i}-start`);
            }
            const stats = tracker.getStats('single-response');
            expect(stats).not.toBeNull();
            expect(stats.count).toBe(iterations);
            expect(stats.avg).toBeLessThan(50); // Should be fast with mocks
            expect(stats.p95).toBeLessThan(100);
            console.log('Single Provider Response Stats:', stats);
        });
        it('should benchmark streaming performance', async () => {
            const provider = new anthropic_provider_1.AnthropicProvider({
                apiKey: 'test-key',
                model: 'claude-3-opus-20240229',
            });
            await provider.initialize();
            const iterations = 50;
            const messages = [{ role: 'user', content: 'Stream test' }];
            for (let i = 0; i < iterations; i++) {
                tracker.mark(`stream-${i}-start`);
                const chunks = [];
                for await (const chunk of provider.streamResponse(messages)) {
                    chunks.push(chunk);
                }
                tracker.measure('stream-response', `stream-${i}-start`);
            }
            const stats = tracker.getStats('stream-response');
            expect(stats).not.toBeNull();
            expect(stats.avg).toBeLessThan(100);
            console.log('Streaming Performance Stats:', stats);
        });
        it('should benchmark provider switching overhead', async () => {
            const manager = new provider_manager_1.ProviderManager();
            // Register multiple providers
            for (let i = 0; i < 5; i++) {
                manager.registerProvider(`provider-${i}`, (0, test_helpers_2.createMockProvider)({ name: `provider-${i}` }));
            }
            const iterations = 100;
            for (let i = 0; i < iterations; i++) {
                const providerIndex = i % 5;
                tracker.mark(`switch-${i}-start`);
                await manager.setActiveProvider(`provider-${providerIndex}`);
                tracker.measure('provider-switch', `switch-${i}-start`);
            }
            const stats = tracker.getStats('provider-switch');
            expect(stats).not.toBeNull();
            expect(stats.avg).toBeLessThan(10); // Switching should be very fast
            console.log('Provider Switching Stats:', stats);
        });
    });
    describe('Message Processing Performance', () => {
        it('should benchmark message batching performance', async () => {
            const provider = (0, test_helpers_2.createMockProvider)();
            await provider.initialize();
            const batchSizes = [1, 10, 50, 100];
            const results = {};
            for (const batchSize of batchSizes) {
                const messages = test_helpers_2.generateTestData.messages(batchSize);
                tracker.mark(`batch-${batchSize}-start`);
                await provider.generateResponse(messages);
                const duration = tracker.measure(`batch-${batchSize}`, `batch-${batchSize}-start`);
                results[batchSize] = {
                    size: batchSize,
                    duration,
                    avgPerMessage: duration / batchSize,
                };
            }
            console.log('Message Batching Performance:', results);
            // Verify that larger batches have better per-message performance
            expect(results[100].avgPerMessage).toBeLessThan(results[1].avgPerMessage);
        });
        it('should benchmark concurrent request handling', async () => {
            const provider = (0, test_helpers_2.createMockProvider)();
            await provider.initialize();
            const concurrencyLevels = [1, 5, 10, 20];
            const results = {};
            for (const concurrency of concurrencyLevels) {
                tracker.mark(`concurrent-${concurrency}-start`);
                const promises = Array.from({ length: concurrency }, () => provider.generateResponse([{ role: 'user', content: 'Concurrent test' }]));
                await Promise.all(promises);
                const duration = tracker.measure(`concurrent-${concurrency}`, `concurrent-${concurrency}-start`);
                results[concurrency] = {
                    concurrency,
                    totalDuration: duration,
                    avgPerRequest: duration / concurrency,
                };
            }
            console.log('Concurrent Request Performance:', results);
            // Verify that concurrent requests are more efficient
            expect(results[10].avgPerRequest).toBeLessThan(results[1].avgPerRequest * 0.5);
        });
    });
    describe('Memory Performance', () => {
        it('should benchmark memory store operations', async () => {
            const memoryStore = {
                data: new Map(),
                get: jest.fn(async (key) => memoryStore.data.get(key)),
                set: jest.fn(async (key, value) => {
                    memoryStore.data.set(key, value);
                    return true;
                }),
                delete: jest.fn(async (key) => memoryStore.data.delete(key)),
                list: jest.fn(async () => Array.from(memoryStore.data.keys())),
            };
            const operations = 1000;
            // Write performance
            tracker.mark('write-start');
            for (let i = 0; i < operations; i++) {
                await memoryStore.set(`key-${i}`, { data: `value-${i}`, timestamp: Date.now() });
            }
            tracker.measure('memory-write', 'write-start');
            // Read performance
            tracker.mark('read-start');
            for (let i = 0; i < operations; i++) {
                await memoryStore.get(`key-${i}`);
            }
            tracker.measure('memory-read', 'read-start');
            // List performance
            tracker.mark('list-start');
            await memoryStore.list();
            tracker.measure('memory-list', 'list-start');
            const writeStats = tracker.getStats('memory-write');
            const readStats = tracker.getStats('memory-read');
            const listStats = tracker.getStats('memory-list');
            console.log('Memory Performance Stats:', {
                write: writeStats,
                read: readStats,
                list: listStats,
            });
            // Reads should be faster than writes
            expect(readStats.avg).toBeLessThan(writeStats.avg);
        });
        it('should benchmark memory search performance', async () => {
            const data = new Map();
            // Populate with test data
            for (let i = 0; i < 10000; i++) {
                data.set(`key-${i}`, {
                    id: i,
                    name: `Item ${i}`,
                    tags: [`tag-${i % 10}`, `tag-${i % 20}`],
                    content: `This is test content for item ${i}`,
                });
            }
            const searchPatterns = ['Item 5', 'tag-5', 'content for item 999'];
            for (const pattern of searchPatterns) {
                tracker.mark(`search-${pattern}-start`);
                const results = Array.from(data.entries()).filter(([key, value]) => JSON.stringify(value).includes(pattern));
                tracker.measure(`search-${pattern}`, `search-${pattern}-start`);
                console.log(`Search for "${pattern}": found ${results.length} items`);
            }
            const stats = tracker.getStats(`search-${searchPatterns[0]}`);
            expect(stats).not.toBeNull();
            expect(stats.avg).toBeLessThan(100); // Search should be reasonably fast
        });
    });
    describe('Agent Performance', () => {
        it('should benchmark agent creation and initialization', async () => {
            const agentTypes = ['researcher', 'coder', 'analyst', 'reviewer'];
            const results = {};
            for (const type of agentTypes) {
                tracker.mark(`agent-${type}-start`);
                const agent = {
                    id: `agent-${Math.random()}`,
                    type,
                    status: 'idle',
                    initialize: jest.fn().mockResolvedValue(true),
                    execute: jest.fn().mockResolvedValue({ success: true }),
                };
                await agent.initialize();
                tracker.measure(`agent-${type}-init`, `agent-${type}-start`);
                results[type] = tracker.getStats(`agent-${type}-init`);
            }
            console.log('Agent Initialization Performance:', results);
            Object.values(results).forEach(stats => {
                expect(stats.avg).toBeLessThan(50);
            });
        });
        it('should benchmark multi-agent coordination', async () => {
            const agentCount = 10;
            const agents = test_helpers_2.generateTestData.agents(agentCount);
            // Simulate coordination overhead
            tracker.mark('coordination-start');
            const coordinationTasks = agents.map(async (agent, index) => {
                // Simulate inter-agent communication
                const otherAgents = agents.filter((_, i) => i !== index);
                const messages = otherAgents.map(other => ({
                    from: agent.id,
                    to: other.id,
                    content: 'coordination message',
                }));
                // Simulate processing
                await new Promise(resolve => setTimeout(resolve, Math.random() * 10));
                return messages;
            });
            await Promise.all(coordinationTasks);
            tracker.measure('multi-agent-coordination', 'coordination-start');
            const stats = tracker.getStats('multi-agent-coordination');
            console.log('Multi-Agent Coordination Stats:', stats);
            expect(stats.avg).toBeLessThan(200);
        });
    });
    describe('Workflow Performance', () => {
        it('should benchmark workflow execution', async () => {
            const workflowSizes = [5, 10, 20, 50];
            const results = {};
            for (const size of workflowSizes) {
                const workflow = {
                    id: `workflow-${size}`,
                    steps: Array.from({ length: size }, (_, i) => ({
                        id: `step-${i}`,
                        name: `Step ${i}`,
                        execute: jest.fn().mockResolvedValue({ success: true }),
                    })),
                };
                tracker.mark(`workflow-${size}-start`);
                // Execute workflow steps
                for (const step of workflow.steps) {
                    await step.execute();
                }
                const duration = tracker.measure(`workflow-${size}`, `workflow-${size}-start`);
                results[size] = {
                    steps: size,
                    totalDuration: duration,
                    avgPerStep: duration / size,
                };
            }
            console.log('Workflow Execution Performance:', results);
            // Verify linear scaling
            const efficiency = results[50].avgPerStep / results[5].avgPerStep;
            expect(efficiency).toBeWithinRange(0.8, 1.2); // Should scale roughly linearly
        });
        it('should benchmark parallel vs sequential workflow execution', async () => {
            const stepCount = 20;
            const steps = Array.from({ length: stepCount }, (_, i) => ({
                id: `step-${i}`,
                execute: jest.fn().mockImplementation(async () => {
                    await new Promise(resolve => setTimeout(resolve, 10));
                    return { success: true };
                }),
            }));
            // Sequential execution
            tracker.mark('sequential-start');
            for (const step of steps) {
                await step.execute();
            }
            tracker.measure('sequential-workflow', 'sequential-start');
            // Parallel execution
            tracker.mark('parallel-start');
            await Promise.all(steps.map(step => step.execute()));
            tracker.measure('parallel-workflow', 'parallel-start');
            const sequentialStats = tracker.getStats('sequential-workflow');
            const parallelStats = tracker.getStats('parallel-workflow');
            console.log('Workflow Execution Comparison:', {
                sequential: sequentialStats,
                parallel: parallelStats,
                speedup: sequentialStats.avg / parallelStats.avg,
            });
            // Parallel should be significantly faster
            expect(parallelStats.avg).toBeLessThan(sequentialStats.avg * 0.2);
        });
    });
    describe('System Load Testing', () => {
        it('should handle high load scenarios', async () => {
            const provider = (0, test_helpers_2.createMockProvider)();
            await provider.initialize();
            const loadLevels = [
                { requests: 100, duration: 1000 },
                { requests: 500, duration: 5000 },
                { requests: 1000, duration: 10000 },
            ];
            for (const { requests, duration } of loadLevels) {
                const startTime = Date.now();
                let completedRequests = 0;
                let errors = 0;
                tracker.mark(`load-${requests}-start`);
                const promises = [];
                while (Date.now() - startTime < duration) {
                    promises.push(provider.generateResponse([{ role: 'user', content: 'Load test' }])
                        .then(() => { completedRequests++; })
                        .catch(() => { errors++; }));
                    if (promises.length >= requests) {
                        break;
                    }
                    // Simulate request rate
                    await new Promise(resolve => setTimeout(resolve, duration / requests));
                }
                await Promise.all(promises);
                const totalDuration = tracker.measure(`load-${requests}`, `load-${requests}-start`);
                const throughput = completedRequests / (totalDuration / 1000);
                const errorRate = (errors / requests) * 100;
                console.log(`Load Test - ${requests} requests:`, {
                    completedRequests,
                    errors,
                    errorRate: `${errorRate.toFixed(2)}%`,
                    throughput: `${throughput.toFixed(2)} req/s`,
                    avgLatency: totalDuration / completedRequests,
                });
                expect(errorRate).toBeLessThan(1); // Less than 1% error rate
                expect(throughput).toBeGreaterThan(10); // At least 10 req/s
            }
        });
    });
});
//# sourceMappingURL=benchmarks.test.js.map