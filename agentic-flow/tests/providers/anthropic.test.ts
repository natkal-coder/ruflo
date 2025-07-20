import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { AnthropicProvider } from '../../src/providers/anthropic';
import { CompletionRequest, ProviderConfig } from '../../src/providers/types';

// Mock the Anthropic SDK
jest.mock('@anthropic-ai/sdk');

describe('AnthropicProvider', () => {
  let provider: AnthropicProvider;
  let mockAnthropic: any;

  beforeEach(() => {
    // Reset mocks
    jest.clearAllMocks();

    // Mock Anthropic constructor and methods
    const { Anthropic } = require('@anthropic-ai/sdk');
    mockAnthropic = {
      messages: {
        create: jest.fn(),
        stream: jest.fn()
      }
    };
    Anthropic.mockImplementation(() => mockAnthropic);

    const config: ProviderConfig = {
      apiKey: 'test-api-key',
      baseURL: 'https://api.anthropic.com'
    };

    provider = new AnthropicProvider(config);
  });

  describe('Initialization', () => {
    it('should initialize with valid configuration', async () => {
      await expect(provider.initialize()).resolves.not.toThrow();
      expect(provider.name).toBe('anthropic');
    });

    it('should handle initialization errors', async () => {
      const errorProvider = new AnthropicProvider({ apiKey: '' });
      await expect(errorProvider.initialize()).rejects.toThrow();
    });
  });

  describe('Health Checks', () => {
    it('should return healthy status when API is accessible', async () => {
      mockAnthropic.messages.create.mockResolvedValue({
        id: 'test-response',
        content: [{ text: 'test' }],
        usage: { input_tokens: 1, output_tokens: 1 }
      });

      await provider.initialize();
      const isHealthy = await provider.isHealthy();
      expect(isHealthy).toBe(true);
    });

    it('should return unhealthy status when API fails', async () => {
      mockAnthropic.messages.create.mockRejectedValue(new Error('API Error'));

      await provider.initialize();
      const isHealthy = await provider.isHealthy();
      expect(isHealthy).toBe(false);
    });
  });

  describe('Completion', () => {
    beforeEach(async () => {
      await provider.initialize();
    });

    it('should complete messages successfully', async () => {
      const mockResponse = {
        id: 'msg_123',
        content: [{ text: 'Hello! How can I help you?' }],
        usage: { input_tokens: 10, output_tokens: 8 },
        model: 'claude-3-sonnet-20240229'
      };

      mockAnthropic.messages.create.mockResolvedValue(mockResponse);

      const request: CompletionRequest = {
        model: 'claude-3-sonnet',
        messages: [{ role: 'user', content: 'Hello' }],
        maxTokens: 100,
        temperature: 0.7
      };

      const response = await provider.complete(request);

      expect(response).toHaveProperty('id', 'msg_123');
      expect(response).toHaveProperty('choices');
      expect(response.choices).toHaveLength(1);
      expect(response.choices[0].message.content).toBe('Hello! How can I help you?');
      expect(response.usage.totalTokens).toBe(18);
      expect(response.cost).toBeGreaterThan(0);
    });

    it('should handle API errors gracefully', async () => {
      mockAnthropic.messages.create.mockRejectedValue(new Error('Rate limit exceeded'));

      const request: CompletionRequest = {
        model: 'claude-3-sonnet',
        messages: [{ role: 'user', content: 'Hello' }]
      };

      await expect(provider.complete(request)).rejects.toThrow('Rate limit exceeded');
    });

    it('should calculate costs correctly', async () => {
      const mockResponse = {
        id: 'msg_cost_test',
        content: [{ text: 'Response text' }],
        usage: { input_tokens: 1000, output_tokens: 500 },
        model: 'claude-3-sonnet-20240229'
      };

      mockAnthropic.messages.create.mockResolvedValue(mockResponse);

      const request: CompletionRequest = {
        model: 'claude-3-sonnet',
        messages: [{ role: 'user', content: 'Test message' }]
      };

      const response = await provider.complete(request);

      expect(response.cost).toBeGreaterThan(0);
      // Cost should be calculated based on input and output tokens
      expect(typeof response.cost).toBe('number');
    });

    it('should handle different model variants', async () => {
      const models = ['claude-3-sonnet', 'claude-3-haiku', 'claude-3-opus'];
      
      for (const model of models) {
        mockAnthropic.messages.create.mockResolvedValue({
          id: `msg_${model}`,
          content: [{ text: `Response from ${model}` }],
          usage: { input_tokens: 10, output_tokens: 10 },
          model: model
        });

        const request: CompletionRequest = {
          model,
          messages: [{ role: 'user', content: 'Test' }]
        };

        const response = await provider.complete(request);
        expect(response.model).toBe(model);
      }
    });
  });

  describe('Streaming', () => {
    beforeEach(async () => {
      await provider.initialize();
    });

    it('should stream responses correctly', async () => {
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

      const request: CompletionRequest = {
        model: 'claude-3-sonnet',
        messages: [{ role: 'user', content: 'Hello' }],
        stream: true
      };

      const streamEvents = [];
      for await (const event of provider.stream(request)) {
        streamEvents.push(event);
      }

      expect(streamEvents.length).toBeGreaterThan(0);
      
      // Check for content events
      const contentEvents = streamEvents.filter(e => e.type === 'content');
      expect(contentEvents.length).toBeGreaterThan(0);
      
      // Check for completion event
      const doneEvents = streamEvents.filter(e => e.type === 'done');
      expect(doneEvents.length).toBe(1);
    });

    it('should handle streaming errors', async () => {
      async function* errorStreamGenerator() {
        yield { type: 'message_start', message: { id: 'msg_error' } };
        throw new Error('Stream error');
      }

      mockAnthropic.messages.stream.mockReturnValue(errorStreamGenerator());

      const request: CompletionRequest = {
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
      } catch (error) {
        expect(error.message).toBe('Stream error');
      }
    });
  });

  describe('Metrics', () => {
    beforeEach(async () => {
      await provider.initialize();
    });

    it('should track request metrics', async () => {
      mockAnthropic.messages.create.mockResolvedValue({
        id: 'msg_metrics',
        content: [{ text: 'Response' }],
        usage: { input_tokens: 10, output_tokens: 10 }
      });

      const request: CompletionRequest = {
        model: 'claude-3-sonnet',
        messages: [{ role: 'user', content: 'Test' }]
      };

      // Make multiple requests
      await provider.complete(request);
      await provider.complete(request);

      const metrics = provider.getMetrics();
      
      expect(metrics.requestCount).toBe(2);
      expect(metrics.totalCost).toBeGreaterThan(0);
      expect(metrics.averageLatency).toBeGreaterThan(0);
    });

    it('should track error metrics', async () => {
      mockAnthropic.messages.create
        .mockResolvedValueOnce({
          id: 'msg_success',
          content: [{ text: 'Success' }],
          usage: { input_tokens: 5, output_tokens: 5 }
        })
        .mockRejectedValueOnce(new Error('API Error'));

      const request: CompletionRequest = {
        model: 'claude-3-sonnet',
        messages: [{ role: 'user', content: 'Test' }]
      };

      // Successful request
      await provider.complete(request);

      // Failed request
      try {
        await provider.complete(request);
      } catch (error) {
        // Expected error
      }

      const metrics = provider.getMetrics();
      
      expect(metrics.requestCount).toBe(2);
      expect(metrics.errorCount).toBe(1);
    });
  });

  describe('Cleanup', () => {
    it('should cleanup resources', async () => {
      await provider.initialize();
      await expect(provider.cleanup()).resolves.not.toThrow();
    });
  });

  describe('Configuration Validation', () => {
    it('should validate API key requirement', () => {
      expect(() => new AnthropicProvider({})).toThrow();
      expect(() => new AnthropicProvider({ apiKey: '' })).toThrow();
    });

    it('should accept valid configuration', () => {
      const config = {
        apiKey: 'valid-key',
        baseURL: 'https://custom.anthropic.com',
        timeout: 30000
      };

      expect(() => new AnthropicProvider(config)).not.toThrow();
    });
  });
});