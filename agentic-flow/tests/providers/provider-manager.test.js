"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const globals_1 = require("@jest/globals");
const manager_1 = require("../../src/providers/manager");
const types_1 = require("../../src/providers/types");
const anthropic_1 = require("../../src/providers/anthropic");
const openai_1 = require("../../src/providers/openai");
// Mock providers
globals_1.jest.mock('../../src/providers/anthropic');
globals_1.jest.mock('../../src/providers/openai');
const MockedAnthropicProvider = anthropic_1.AnthropicProvider;
const MockedOpenAIProvider = openai_1.OpenAIProvider;
(0, globals_1.describe)('ProviderManager', () => {
    let providerManager;
    let mockAnthropicProvider;
    let mockOpenAIProvider;
    (0, globals_1.beforeEach)(() => {
        // Reset mocks
        globals_1.jest.clearAllMocks();
        // Create mock provider instances
        mockAnthropicProvider = {
            name: types_1.LLMProvider.ANTHROPIC,
            isHealthy: globals_1.jest.fn().mockResolvedValue(true),
            complete: globals_1.jest.fn(),
            stream: globals_1.jest.fn(),
            getMetrics: globals_1.jest.fn().mockReturnValue({
                requestCount: 0,
                errorCount: 0,
                totalCost: 0,
                averageLatency: 0
            }),
            initialize: globals_1.jest.fn().mockResolvedValue(undefined),
            cleanup: globals_1.jest.fn().mockResolvedValue(undefined)
        };
        mockOpenAIProvider = {
            name: types_1.LLMProvider.OPENAI,
            isHealthy: globals_1.jest.fn().mockResolvedValue(true),
            complete: globals_1.jest.fn(),
            stream: globals_1.jest.fn(),
            getMetrics: globals_1.jest.fn().mockReturnValue({
                requestCount: 0,
                errorCount: 0,
                totalCost: 0,
                averageLatency: 0
            }),
            initialize: globals_1.jest.fn().mockResolvedValue(undefined),
            cleanup: globals_1.jest.fn().mockResolvedValue(undefined)
        };
        // Mock constructor calls
        MockedAnthropicProvider.mockImplementation(() => mockAnthropicProvider);
        MockedOpenAIProvider.mockImplementation(() => mockOpenAIProvider);
        // Create provider manager
        providerManager = new manager_1.ProviderManager({
            providers: {
                [types_1.LLMProvider.ANTHROPIC]: { apiKey: 'test-anthropic-key' },
                [types_1.LLMProvider.OPENAI]: { apiKey: 'test-openai-key' }
            },
            fallbackStrategy: types_1.FallbackStrategy.SEQUENTIAL,
            healthCheckInterval: 1000
        });
    });
    (0, globals_1.describe)('initialization', () => {
        (0, globals_1.it)('should initialize all configured providers', async () => {
            await providerManager.initialize();
            (0, globals_1.expect)(MockedAnthropicProvider).toHaveBeenCalledWith({ apiKey: 'test-anthropic-key' });
            (0, globals_1.expect)(MockedOpenAIProvider).toHaveBeenCalledWith({ apiKey: 'test-openai-key' });
            (0, globals_1.expect)(mockAnthropicProvider.initialize).toHaveBeenCalled();
            (0, globals_1.expect)(mockOpenAIProvider.initialize).toHaveBeenCalled();
        });
        (0, globals_1.it)('should handle provider initialization failures gracefully', async () => {
            mockAnthropicProvider.initialize.mockRejectedValue(new Error('Init failed'));
            await (0, globals_1.expect)(providerManager.initialize()).resolves.not.toThrow();
            (0, globals_1.expect)(mockOpenAIProvider.initialize).toHaveBeenCalled();
        });
    });
    (0, globals_1.describe)('complete', () => {
        const mockRequest = {
            model: 'claude-3-sonnet',
            messages: [{ role: 'user', content: 'Hello' }],
            temperature: 0.7
        };
        const mockResponse = {
            id: 'test-response-id',
            model: 'claude-3-sonnet',
            choices: [{
                    message: { role: 'assistant', content: 'Hello! How can I help you?' },
                    finishReason: 'stop'
                }],
            usage: { promptTokens: 10, completionTokens: 15, totalTokens: 25 },
            cost: 0.001
        };
        (0, globals_1.beforeEach)(async () => {
            await providerManager.initialize();
        });
        (0, globals_1.it)('should complete request with primary provider', async () => {
            mockAnthropicProvider.complete.mockResolvedValue(mockResponse);
            const result = await providerManager.complete(mockRequest);
            (0, globals_1.expect)(mockAnthropicProvider.complete).toHaveBeenCalledWith(mockRequest);
            (0, globals_1.expect)(result).toEqual(mockResponse);
        });
        (0, globals_1.it)('should fallback to secondary provider on failure', async () => {
            mockAnthropicProvider.complete.mockRejectedValue(new Error('Primary failed'));
            mockOpenAIProvider.complete.mockResolvedValue(mockResponse);
            const result = await providerManager.complete(mockRequest);
            (0, globals_1.expect)(mockAnthropicProvider.complete).toHaveBeenCalledWith(mockRequest);
            (0, globals_1.expect)(mockOpenAIProvider.complete).toHaveBeenCalledWith(mockRequest);
            (0, globals_1.expect)(result).toEqual(mockResponse);
        });
        (0, globals_1.it)('should throw error when all providers fail', async () => {
            mockAnthropicProvider.complete.mockRejectedValue(new Error('Anthropic failed'));
            mockOpenAIProvider.complete.mockRejectedValue(new Error('OpenAI failed'));
            await (0, globals_1.expect)(providerManager.complete(mockRequest)).rejects.toThrow();
        });
        (0, globals_1.it)('should respect cost limits', async () => {
            const expensiveRequest = { ...mockRequest, maxCost: 0.0005 };
            const expensiveResponse = { ...mockResponse, cost: 0.001 };
            mockAnthropicProvider.complete.mockResolvedValue(expensiveResponse);
            await (0, globals_1.expect)(providerManager.complete(expensiveRequest)).rejects.toThrow('Cost limit exceeded');
        });
    });
    (0, globals_1.describe)('stream', () => {
        const mockRequest = {
            model: 'claude-3-sonnet',
            messages: [{ role: 'user', content: 'Hello' }],
            stream: true
        };
        (0, globals_1.beforeEach)(async () => {
            await providerManager.initialize();
        });
        (0, globals_1.it)('should stream from primary provider', async () => {
            const mockStreamData = [
                { type: 'content', delta: { content: 'Hello' } },
                { type: 'content', delta: { content: '!' } },
                { type: 'done', usage: { totalTokens: 15 } }
            ];
            // Create async generator
            async function* mockStream() {
                for (const item of mockStreamData) {
                    yield item;
                }
            }
            mockAnthropicProvider.stream.mockReturnValue(mockStream());
            const results = [];
            for await (const chunk of providerManager.stream(mockRequest)) {
                results.push(chunk);
            }
            (0, globals_1.expect)(mockAnthropicProvider.stream).toHaveBeenCalledWith(mockRequest);
            (0, globals_1.expect)(results).toEqual(mockStreamData);
        });
        (0, globals_1.it)('should fallback on streaming failure', async () => {
            const mockStreamData = [
                { type: 'content', delta: { content: 'Fallback response' } }
            ];
            async function* mockStream() {
                for (const item of mockStreamData) {
                    yield item;
                }
            }
            mockAnthropicProvider.stream.mockImplementation(() => {
                throw new Error('Stream failed');
            });
            mockOpenAIProvider.stream.mockReturnValue(mockStream());
            const results = [];
            for await (const chunk of providerManager.stream(mockRequest)) {
                results.push(chunk);
            }
            (0, globals_1.expect)(mockOpenAIProvider.stream).toHaveBeenCalled();
            (0, globals_1.expect)(results).toEqual(mockStreamData);
        });
    });
    (0, globals_1.describe)('health monitoring', () => {
        (0, globals_1.beforeEach)(async () => {
            await providerManager.initialize();
        });
        (0, globals_1.it)('should check provider health', async () => {
            const health = await providerManager.getHealth();
            (0, globals_1.expect)(mockAnthropicProvider.isHealthy).toHaveBeenCalled();
            (0, globals_1.expect)(mockOpenAIProvider.isHealthy).toHaveBeenCalled();
            (0, globals_1.expect)(health).toHaveProperty(types_1.LLMProvider.ANTHROPIC);
            (0, globals_1.expect)(health).toHaveProperty(types_1.LLMProvider.OPENAI);
        });
        (0, globals_1.it)('should mark unhealthy providers', async () => {
            mockAnthropicProvider.isHealthy.mockResolvedValue(false);
            const health = await providerManager.getHealth();
            (0, globals_1.expect)(health[types_1.LLMProvider.ANTHROPIC].healthy).toBe(false);
            (0, globals_1.expect)(health[types_1.LLMProvider.OPENAI].healthy).toBe(true);
        });
    });
    (0, globals_1.describe)('metrics', () => {
        (0, globals_1.beforeEach)(async () => {
            await providerManager.initialize();
        });
        (0, globals_1.it)('should aggregate metrics from all providers', () => {
            mockAnthropicProvider.getMetrics.mockReturnValue({
                requestCount: 10,
                errorCount: 1,
                totalCost: 0.05,
                averageLatency: 150
            });
            mockOpenAIProvider.getMetrics.mockReturnValue({
                requestCount: 5,
                errorCount: 0,
                totalCost: 0.03,
                averageLatency: 120
            });
            const metrics = providerManager.getMetrics();
            (0, globals_1.expect)(metrics.totalRequests).toBe(15);
            (0, globals_1.expect)(metrics.totalErrors).toBe(1);
            (0, globals_1.expect)(metrics.totalCost).toBe(0.08);
            (0, globals_1.expect)(metrics.averageLatency).toBeCloseTo(140, 1);
        });
    });
    (0, globals_1.describe)('fallback strategies', () => {
        (0, globals_1.beforeEach)(async () => {
            await providerManager.initialize();
        });
        (0, globals_1.it)('should use sequential fallback strategy', async () => {
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Test' }]
            };
            mockAnthropicProvider.complete.mockRejectedValue(new Error('Failed'));
            mockOpenAIProvider.complete.mockResolvedValue({
                id: 'test',
                model: 'gpt-4',
                choices: [{ message: { role: 'assistant', content: 'Response' }, finishReason: 'stop' }],
                usage: { promptTokens: 5, completionTokens: 10, totalTokens: 15 },
                cost: 0.001
            });
            await providerManager.complete(request);
            (0, globals_1.expect)(mockAnthropicProvider.complete).toHaveBeenCalledTimes(1);
            (0, globals_1.expect)(mockOpenAIProvider.complete).toHaveBeenCalledTimes(1);
        });
        (0, globals_1.it)('should use cost optimization strategy', async () => {
            const costOptimizedManager = new manager_1.ProviderManager({
                providers: {
                    [types_1.LLMProvider.ANTHROPIC]: { apiKey: 'test-anthropic-key' },
                    [types_1.LLMProvider.OPENAI]: { apiKey: 'test-openai-key' }
                },
                fallbackStrategy: types_1.FallbackStrategy.COST_OPTIMIZE
            });
            await costOptimizedManager.initialize();
            // Mock cost estimates
            globals_1.jest.spyOn(costOptimizedManager, 'estimateCost')
                .mockImplementation((provider, request) => {
                return provider === types_1.LLMProvider.ANTHROPIC ? 0.001 : 0.002;
            });
            const request = {
                model: 'auto',
                messages: [{ role: 'user', content: 'Test' }]
            };
            mockAnthropicProvider.complete.mockResolvedValue({
                id: 'test',
                model: 'claude-3-sonnet',
                choices: [{ message: { role: 'assistant', content: 'Response' }, finishReason: 'stop' }],
                usage: { promptTokens: 5, completionTokens: 10, totalTokens: 15 },
                cost: 0.001
            });
            await costOptimizedManager.complete(request);
            // Should prefer Anthropic due to lower cost
            (0, globals_1.expect)(mockAnthropicProvider.complete).toHaveBeenCalled();
        });
    });
    (0, globals_1.describe)('model selection', () => {
        (0, globals_1.beforeEach)(async () => {
            await providerManager.initialize();
        });
        (0, globals_1.it)('should find best model for requirements', () => {
            const requirements = {
                maxCost: 0.01,
                minContextWindow: 32000,
                requiresVision: false
            };
            const bestModel = providerManager.findBestModel(requirements);
            (0, globals_1.expect)(bestModel).toBeDefined();
            (0, globals_1.expect)(bestModel.provider).toBe(types_1.LLMProvider.ANTHROPIC);
        });
        (0, globals_1.it)('should handle vision requirements', () => {
            const requirements = {
                requiresVision: true
            };
            const bestModel = providerManager.findBestModel(requirements);
            (0, globals_1.expect)(bestModel).toBeDefined();
            // Should find a model that supports vision
        });
        (0, globals_1.it)('should return null when no model meets requirements', () => {
            const requirements = {
                maxCost: 0.0001 // Impossibly low cost
            };
            const bestModel = providerManager.findBestModel(requirements);
            (0, globals_1.expect)(bestModel).toBeNull();
        });
    });
    (0, globals_1.describe)('cleanup', () => {
        (0, globals_1.it)('should cleanup all providers', async () => {
            await providerManager.initialize();
            await providerManager.cleanup();
            (0, globals_1.expect)(mockAnthropicProvider.cleanup).toHaveBeenCalled();
            (0, globals_1.expect)(mockOpenAIProvider.cleanup).toHaveBeenCalled();
        });
    });
});
// Integration tests with real providers (when API keys are available)
(0, globals_1.describe)('ProviderManager Integration', () => {
    const hasApiKeys = process.env.ANTHROPIC_API_KEY && process.env.OPENAI_API_KEY;
    // Skip integration tests if API keys are not available
    const testIf = hasApiKeys ? globals_1.it : globals_1.it.skip;
    testIf('should work with real providers', async () => {
        const realProviderManager = new manager_1.ProviderManager({
            providers: {
                [types_1.LLMProvider.ANTHROPIC]: { apiKey: process.env.ANTHROPIC_API_KEY },
                [types_1.LLMProvider.OPENAI]: { apiKey: process.env.OPENAI_API_KEY }
            },
            fallbackStrategy: types_1.FallbackStrategy.SEQUENTIAL
        });
        await realProviderManager.initialize();
        const request = {
            model: 'claude-3-haiku',
            messages: [{ role: 'user', content: 'Say hello in one word.' }],
            maxTokens: 10
        };
        const response = await realProviderManager.complete(request);
        (0, globals_1.expect)(response).toBeDefined();
        (0, globals_1.expect)(response.choices).toHaveLength(1);
        (0, globals_1.expect)(response.choices[0].message.content).toBeTruthy();
        (0, globals_1.expect)(response.cost).toBeGreaterThan(0);
        await realProviderManager.cleanup();
    }, 30000); // 30 second timeout for real API calls
    testIf('should stream with real providers', async () => {
        const realProviderManager = new manager_1.ProviderManager({
            providers: {
                [types_1.LLMProvider.ANTHROPIC]: { apiKey: process.env.ANTHROPIC_API_KEY }
            }
        });
        await realProviderManager.initialize();
        const request = {
            model: 'claude-3-haiku',
            messages: [{ role: 'user', content: 'Count from 1 to 5.' }],
            stream: true,
            maxTokens: 50
        };
        const chunks = [];
        for await (const chunk of realProviderManager.stream(request)) {
            chunks.push(chunk);
            if (chunk.type === 'done')
                break;
        }
        (0, globals_1.expect)(chunks.length).toBeGreaterThan(0);
        (0, globals_1.expect)(chunks[chunks.length - 1].type).toBe('done');
        await realProviderManager.cleanup();
    }, 30000);
});
//# sourceMappingURL=provider-manager.test.js.map