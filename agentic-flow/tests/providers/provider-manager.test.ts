import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { ProviderManager } from '../../src/providers/manager';
import { LLMProvider, FallbackStrategy, CompletionRequest } from '../../src/providers/types';
import { AnthropicProvider } from '../../src/providers/anthropic';
import { OpenAIProvider } from '../../src/providers/openai';

// Mock providers
jest.mock('../../src/providers/anthropic');
jest.mock('../../src/providers/openai');

const MockedAnthropicProvider = AnthropicProvider as jest.MockedClass<typeof AnthropicProvider>;
const MockedOpenAIProvider = OpenAIProvider as jest.MockedClass<typeof OpenAIProvider>;

describe('ProviderManager', () => {
  let providerManager: ProviderManager;
  let mockAnthropicProvider: jest.Mocked<AnthropicProvider>;
  let mockOpenAIProvider: jest.Mocked<OpenAIProvider>;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock provider instances
    mockAnthropicProvider = {
      name: LLMProvider.ANTHROPIC,
      isHealthy: jest.fn().mockResolvedValue(true),
      complete: jest.fn(),
      stream: jest.fn(),
      getMetrics: jest.fn().mockReturnValue({
        requestCount: 0,
        errorCount: 0,
        totalCost: 0,
        averageLatency: 0
      }),
      initialize: jest.fn().mockResolvedValue(undefined),
      cleanup: jest.fn().mockResolvedValue(undefined)
    } as any;

    mockOpenAIProvider = {
      name: LLMProvider.OPENAI,
      isHealthy: jest.fn().mockResolvedValue(true),
      complete: jest.fn(),
      stream: jest.fn(),
      getMetrics: jest.fn().mockReturnValue({
        requestCount: 0,
        errorCount: 0,
        totalCost: 0,
        averageLatency: 0
      }),
      initialize: jest.fn().mockResolvedValue(undefined),
      cleanup: jest.fn().mockResolvedValue(undefined)
    } as any;

    // Mock constructor calls
    MockedAnthropicProvider.mockImplementation(() => mockAnthropicProvider);
    MockedOpenAIProvider.mockImplementation(() => mockOpenAIProvider);

    // Create provider manager
    providerManager = new ProviderManager({
      providers: {
        [LLMProvider.ANTHROPIC]: { apiKey: 'test-anthropic-key' },
        [LLMProvider.OPENAI]: { apiKey: 'test-openai-key' }
      },
      fallbackStrategy: FallbackStrategy.SEQUENTIAL,
      healthCheckInterval: 1000
    });
  });

  describe('initialization', () => {
    it('should initialize all configured providers', async () => {
      await providerManager.initialize();

      expect(MockedAnthropicProvider).toHaveBeenCalledWith({ apiKey: 'test-anthropic-key' });
      expect(MockedOpenAIProvider).toHaveBeenCalledWith({ apiKey: 'test-openai-key' });
      expect(mockAnthropicProvider.initialize).toHaveBeenCalled();
      expect(mockOpenAIProvider.initialize).toHaveBeenCalled();
    });

    it('should handle provider initialization failures gracefully', async () => {
      mockAnthropicProvider.initialize.mockRejectedValue(new Error('Init failed'));

      await expect(providerManager.initialize()).resolves.not.toThrow();
      expect(mockOpenAIProvider.initialize).toHaveBeenCalled();
    });
  });

  describe('complete', () => {
    const mockRequest: CompletionRequest = {
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

    beforeEach(async () => {
      await providerManager.initialize();
    });

    it('should complete request with primary provider', async () => {
      mockAnthropicProvider.complete.mockResolvedValue(mockResponse);

      const result = await providerManager.complete(mockRequest);

      expect(mockAnthropicProvider.complete).toHaveBeenCalledWith(mockRequest);
      expect(result).toEqual(mockResponse);
    });

    it('should fallback to secondary provider on failure', async () => {
      mockAnthropicProvider.complete.mockRejectedValue(new Error('Primary failed'));
      mockOpenAIProvider.complete.mockResolvedValue(mockResponse);

      const result = await providerManager.complete(mockRequest);

      expect(mockAnthropicProvider.complete).toHaveBeenCalledWith(mockRequest);
      expect(mockOpenAIProvider.complete).toHaveBeenCalledWith(mockRequest);
      expect(result).toEqual(mockResponse);
    });

    it('should throw error when all providers fail', async () => {
      mockAnthropicProvider.complete.mockRejectedValue(new Error('Anthropic failed'));
      mockOpenAIProvider.complete.mockRejectedValue(new Error('OpenAI failed'));

      await expect(providerManager.complete(mockRequest)).rejects.toThrow();
    });

    it('should respect cost limits', async () => {
      const expensiveRequest = { ...mockRequest, maxCost: 0.0005 };
      const expensiveResponse = { ...mockResponse, cost: 0.001 };
      
      mockAnthropicProvider.complete.mockResolvedValue(expensiveResponse);

      await expect(providerManager.complete(expensiveRequest)).rejects.toThrow('Cost limit exceeded');
    });
  });

  describe('stream', () => {
    const mockRequest: CompletionRequest = {
      model: 'claude-3-sonnet',
      messages: [{ role: 'user', content: 'Hello' }],
      stream: true
    };

    beforeEach(async () => {
      await providerManager.initialize();
    });

    it('should stream from primary provider', async () => {
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

      expect(mockAnthropicProvider.stream).toHaveBeenCalledWith(mockRequest);
      expect(results).toEqual(mockStreamData);
    });

    it('should fallback on streaming failure', async () => {
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

      expect(mockOpenAIProvider.stream).toHaveBeenCalled();
      expect(results).toEqual(mockStreamData);
    });
  });

  describe('health monitoring', () => {
    beforeEach(async () => {
      await providerManager.initialize();
    });

    it('should check provider health', async () => {
      const health = await providerManager.getHealth();

      expect(mockAnthropicProvider.isHealthy).toHaveBeenCalled();
      expect(mockOpenAIProvider.isHealthy).toHaveBeenCalled();
      expect(health).toHaveProperty(LLMProvider.ANTHROPIC);
      expect(health).toHaveProperty(LLMProvider.OPENAI);
    });

    it('should mark unhealthy providers', async () => {
      mockAnthropicProvider.isHealthy.mockResolvedValue(false);

      const health = await providerManager.getHealth();

      expect(health[LLMProvider.ANTHROPIC].healthy).toBe(false);
      expect(health[LLMProvider.OPENAI].healthy).toBe(true);
    });
  });

  describe('metrics', () => {
    beforeEach(async () => {
      await providerManager.initialize();
    });

    it('should aggregate metrics from all providers', () => {
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

      expect(metrics.totalRequests).toBe(15);
      expect(metrics.totalErrors).toBe(1);
      expect(metrics.totalCost).toBe(0.08);
      expect(metrics.averageLatency).toBeCloseTo(140, 1);
    });
  });

  describe('fallback strategies', () => {
    beforeEach(async () => {
      await providerManager.initialize();
    });

    it('should use sequential fallback strategy', async () => {
      const request: CompletionRequest = {
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

      expect(mockAnthropicProvider.complete).toHaveBeenCalledTimes(1);
      expect(mockOpenAIProvider.complete).toHaveBeenCalledTimes(1);
    });

    it('should use cost optimization strategy', async () => {
      const costOptimizedManager = new ProviderManager({
        providers: {
          [LLMProvider.ANTHROPIC]: { apiKey: 'test-anthropic-key' },
          [LLMProvider.OPENAI]: { apiKey: 'test-openai-key' }
        },
        fallbackStrategy: FallbackStrategy.COST_OPTIMIZE
      });

      await costOptimizedManager.initialize();

      // Mock cost estimates
      jest.spyOn(costOptimizedManager as any, 'estimateCost')
        .mockImplementation((provider, request) => {
          return provider === LLMProvider.ANTHROPIC ? 0.001 : 0.002;
        });

      const request: CompletionRequest = {
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
      expect(mockAnthropicProvider.complete).toHaveBeenCalled();
    });
  });

  describe('model selection', () => {
    beforeEach(async () => {
      await providerManager.initialize();
    });

    it('should find best model for requirements', () => {
      const requirements = {
        maxCost: 0.01,
        minContextWindow: 32000,
        requiresVision: false
      };

      const bestModel = providerManager.findBestModel(requirements);

      expect(bestModel).toBeDefined();
      expect(bestModel.provider).toBe(LLMProvider.ANTHROPIC);
    });

    it('should handle vision requirements', () => {
      const requirements = {
        requiresVision: true
      };

      const bestModel = providerManager.findBestModel(requirements);

      expect(bestModel).toBeDefined();
      // Should find a model that supports vision
    });

    it('should return null when no model meets requirements', () => {
      const requirements = {
        maxCost: 0.0001 // Impossibly low cost
      };

      const bestModel = providerManager.findBestModel(requirements);

      expect(bestModel).toBeNull();
    });
  });

  describe('cleanup', () => {
    it('should cleanup all providers', async () => {
      await providerManager.initialize();
      await providerManager.cleanup();

      expect(mockAnthropicProvider.cleanup).toHaveBeenCalled();
      expect(mockOpenAIProvider.cleanup).toHaveBeenCalled();
    });
  });
});

// Integration tests with real providers (when API keys are available)
describe('ProviderManager Integration', () => {
  const hasApiKeys = process.env.ANTHROPIC_API_KEY && process.env.OPENAI_API_KEY;

  // Skip integration tests if API keys are not available
  const testIf = hasApiKeys ? it : it.skip;

  testIf('should work with real providers', async () => {
    const realProviderManager = new ProviderManager({
      providers: {
        [LLMProvider.ANTHROPIC]: { apiKey: process.env.ANTHROPIC_API_KEY! },
        [LLMProvider.OPENAI]: { apiKey: process.env.OPENAI_API_KEY! }
      },
      fallbackStrategy: FallbackStrategy.SEQUENTIAL
    });

    await realProviderManager.initialize();

    const request: CompletionRequest = {
      model: 'claude-3-haiku',
      messages: [{ role: 'user', content: 'Say hello in one word.' }],
      maxTokens: 10
    };

    const response = await realProviderManager.complete(request);

    expect(response).toBeDefined();
    expect(response.choices).toHaveLength(1);
    expect(response.choices[0].message.content).toBeTruthy();
    expect(response.cost).toBeGreaterThan(0);

    await realProviderManager.cleanup();
  }, 30000); // 30 second timeout for real API calls

  testIf('should stream with real providers', async () => {
    const realProviderManager = new ProviderManager({
      providers: {
        [LLMProvider.ANTHROPIC]: { apiKey: process.env.ANTHROPIC_API_KEY! }
      }
    });

    await realProviderManager.initialize();

    const request: CompletionRequest = {
      model: 'claude-3-haiku',
      messages: [{ role: 'user', content: 'Count from 1 to 5.' }],
      stream: true,
      maxTokens: 50
    };

    const chunks = [];
    for await (const chunk of realProviderManager.stream(request)) {
      chunks.push(chunk);
      if (chunk.type === 'done') break;
    }

    expect(chunks.length).toBeGreaterThan(0);
    expect(chunks[chunks.length - 1].type).toBe('done');

    await realProviderManager.cleanup();
  }, 30000);
});