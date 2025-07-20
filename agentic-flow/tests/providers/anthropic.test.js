"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const globals_1 = require("@jest/globals");
const anthropic_1 = require("../../src/providers/anthropic");
// Mock the Anthropic SDK
globals_1.jest.mock('@anthropic-ai/sdk');
(0, globals_1.describe)('AnthropicProvider', () => {
    let provider;
    let mockAnthropic;
    (0, globals_1.beforeEach)(() => {
        // Reset mocks
        globals_1.jest.clearAllMocks();
        // Mock Anthropic constructor and methods
        const { Anthropic } = require('@anthropic-ai/sdk');
        mockAnthropic = {
            messages: {
                create: globals_1.jest.fn(),
                stream: globals_1.jest.fn()
            }
        };
        Anthropic.mockImplementation(() => mockAnthropic);
        const config = {
            apiKey: 'test-api-key',
            baseURL: 'https://api.anthropic.com'
        };
        provider = new anthropic_1.AnthropicProvider(config);
    });
    (0, globals_1.describe)('Initialization', () => {
        (0, globals_1.it)('should initialize with valid configuration', async () => {
            await (0, globals_1.expect)(provider.initialize()).resolves.not.toThrow();
            (0, globals_1.expect)(provider.name).toBe('anthropic');
        });
        (0, globals_1.it)('should handle initialization errors', async () => {
            const errorProvider = new anthropic_1.AnthropicProvider({ apiKey: '' });
            await (0, globals_1.expect)(errorProvider.initialize()).rejects.toThrow();
        });
    });
    (0, globals_1.describe)('Health Checks', () => {
        (0, globals_1.it)('should return healthy status when API is accessible', async () => {
            mockAnthropic.messages.create.mockResolvedValue({
                id: 'test-response',
                content: [{ text: 'test' }],
                usage: { input_tokens: 1, output_tokens: 1 }
            });
            await provider.initialize();
            const isHealthy = await provider.isHealthy();
            (0, globals_1.expect)(isHealthy).toBe(true);
        });
        (0, globals_1.it)('should return unhealthy status when API fails', async () => {
            mockAnthropic.messages.create.mockRejectedValue(new Error('API Error'));
            await provider.initialize();
            const isHealthy = await provider.isHealthy();
            (0, globals_1.expect)(isHealthy).toBe(false);
        });
    });
    (0, globals_1.describe)('Completion', () => {
        (0, globals_1.beforeEach)(async () => {
            await provider.initialize();
        });
        (0, globals_1.it)('should complete messages successfully', async () => {
            const mockResponse = {
                id: 'msg_123',
                content: [{ text: 'Hello! How can I help you?' }],
                usage: { input_tokens: 10, output_tokens: 8 },
                model: 'claude-3-sonnet-20240229'
            };
            mockAnthropic.messages.create.mockResolvedValue(mockResponse);
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Hello' }],
                maxTokens: 100,
                temperature: 0.7
            };
            const response = await provider.complete(request);
            (0, globals_1.expect)(response).toHaveProperty('id', 'msg_123');
            (0, globals_1.expect)(response).toHaveProperty('choices');
            (0, globals_1.expect)(response.choices).toHaveLength(1);
            (0, globals_1.expect)(response.choices[0].message.content).toBe('Hello! How can I help you?');
            (0, globals_1.expect)(response.usage.totalTokens).toBe(18);
            (0, globals_1.expect)(response.cost).toBeGreaterThan(0);
        });
        (0, globals_1.it)('should handle API errors gracefully', async () => {
            mockAnthropic.messages.create.mockRejectedValue(new Error('Rate limit exceeded'));
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Hello' }]
            };
            await (0, globals_1.expect)(provider.complete(request)).rejects.toThrow('Rate limit exceeded');
        });
        (0, globals_1.it)('should calculate costs correctly', async () => {
            const mockResponse = {
                id: 'msg_cost_test',
                content: [{ text: 'Response text' }],
                usage: { input_tokens: 1000, output_tokens: 500 },
                model: 'claude-3-sonnet-20240229'
            };
            mockAnthropic.messages.create.mockResolvedValue(mockResponse);
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Test message' }]
            };
            const response = await provider.complete(request);
            (0, globals_1.expect)(response.cost).toBeGreaterThan(0);
            // Cost should be calculated based on input and output tokens
            (0, globals_1.expect)(typeof response.cost).toBe('number');
        });
        (0, globals_1.it)('should handle different model variants', async () => {
            const models = ['claude-3-sonnet', 'claude-3-haiku', 'claude-3-opus'];
            for (const model of models) {
                mockAnthropic.messages.create.mockResolvedValue({
                    id: `msg_${model}`,
                    content: [{ text: `Response from ${model}` }],
                    usage: { input_tokens: 10, output_tokens: 10 },
                    model: model
                });
                const request = {
                    model,
                    messages: [{ role: 'user', content: 'Test' }]
                };
                const response = await provider.complete(request);
                (0, globals_1.expect)(response.model).toBe(model);
            }
        });
    });
    (0, globals_1.describe)('Streaming', () => {
        (0, globals_1.beforeEach)(async () => {
            await provider.initialize();
        });
        (0, globals_1.it)('should stream responses correctly', async () => {
            const mockStreamEvents = [
                { type: 'message_start', message: { id: 'msg_stream', usage: { input_tokens: 10 } } },
                { type: 'content_block_delta', delta: { text: 'Hello' } },
                { type: 'content_block_delta', delta: { text: ' world' } },
                { type: 'message_delta', delta: { usage: { output_tokens: 5 } } },
                { type: 'message_stop' }
            ];
            // Create async generator for streaming
            async function* mockStreamGenerator() {
                for (const event of mockStreamEvents) {
                    yield event;
                }
            }
            mockAnthropic.messages.stream.mockReturnValue(mockStreamGenerator());
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Hello' }],
                stream: true
            };
            const streamEvents = [];
            for await (const event of provider.stream(request)) {
                streamEvents.push(event);
            }
            (0, globals_1.expect)(streamEvents.length).toBeGreaterThan(0);
            // Check for content events
            const contentEvents = streamEvents.filter(e => e.type === 'content');
            (0, globals_1.expect)(contentEvents.length).toBeGreaterThan(0);
            // Check for completion event
            const doneEvents = streamEvents.filter(e => e.type === 'done');
            (0, globals_1.expect)(doneEvents.length).toBe(1);
        });
        (0, globals_1.it)('should handle streaming errors', async () => {
            async function* errorStreamGenerator() {
                yield { type: 'message_start', message: { id: 'msg_error' } };
                throw new Error('Stream error');
            }
            mockAnthropic.messages.stream.mockReturnValue(errorStreamGenerator());
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Test' }],
                stream: true
            };
            const streamGenerator = provider.stream(request);
            // Should emit error event
            const events = [];
            try {
                for await (const event of streamGenerator) {
                    events.push(event);
                }
            }
            catch (error) {
                (0, globals_1.expect)(error.message).toBe('Stream error');
            }
        });
    });
    (0, globals_1.describe)('Metrics', () => {
        (0, globals_1.beforeEach)(async () => {
            await provider.initialize();
        });
        (0, globals_1.it)('should track request metrics', async () => {
            mockAnthropic.messages.create.mockResolvedValue({
                id: 'msg_metrics',
                content: [{ text: 'Response' }],
                usage: { input_tokens: 10, output_tokens: 10 }
            });
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Test' }]
            };
            // Make multiple requests
            await provider.complete(request);
            await provider.complete(request);
            const metrics = provider.getMetrics();
            (0, globals_1.expect)(metrics.requestCount).toBe(2);
            (0, globals_1.expect)(metrics.totalCost).toBeGreaterThan(0);
            (0, globals_1.expect)(metrics.averageLatency).toBeGreaterThan(0);
        });
        (0, globals_1.it)('should track error metrics', async () => {
            mockAnthropic.messages.create
                .mockResolvedValueOnce({
                id: 'msg_success',
                content: [{ text: 'Success' }],
                usage: { input_tokens: 5, output_tokens: 5 }
            })
                .mockRejectedValueOnce(new Error('API Error'));
            const request = {
                model: 'claude-3-sonnet',
                messages: [{ role: 'user', content: 'Test' }]
            };
            // Successful request
            await provider.complete(request);
            // Failed request
            try {
                await provider.complete(request);
            }
            catch (error) {
                // Expected error
            }
            const metrics = provider.getMetrics();
            (0, globals_1.expect)(metrics.requestCount).toBe(2);
            (0, globals_1.expect)(metrics.errorCount).toBe(1);
        });
    });
    (0, globals_1.describe)('Cleanup', () => {
        (0, globals_1.it)('should cleanup resources', async () => {
            await provider.initialize();
            await (0, globals_1.expect)(provider.cleanup()).resolves.not.toThrow();
        });
    });
    (0, globals_1.describe)('Configuration Validation', () => {
        (0, globals_1.it)('should validate API key requirement', () => {
            (0, globals_1.expect)(() => new anthropic_1.AnthropicProvider({})).toThrow();
            (0, globals_1.expect)(() => new anthropic_1.AnthropicProvider({ apiKey: '' })).toThrow();
        });
        (0, globals_1.it)('should accept valid configuration', () => {
            const config = {
                apiKey: 'valid-key',
                baseURL: 'https://custom.anthropic.com',
                timeout: 30000
            };
            (0, globals_1.expect)(() => new anthropic_1.AnthropicProvider(config)).not.toThrow();
        });
    });
});
//# sourceMappingURL=anthropic.test.js.map