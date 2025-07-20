/**
 * Base LLM Provider Abstract Class
 * Provides common functionality for all LLM providers
 */

import {
  ILLMProvider,
  LLMProvider,
  ModelInfo,
  ProviderConfig,
  CompletionOptions,
  CompletionResponse,
  StreamChunk,
  ProviderStatus,
  ProviderMetrics,
  ProviderEventEmitter,
  ProviderError,
  RateLimitError,
  AuthenticationError,
  TokenUsage
} from './types';

export abstract class BaseLLMProvider implements ILLMProvider {
  abstract readonly provider: LLMProvider;
  abstract readonly models: ModelInfo[];
  
  protected config: ProviderConfig = {};
  protected initialized = false;
  protected events = new ProviderEventEmitter();
  
  // Metrics tracking
  protected metrics: ProviderMetrics = {
    provider: this.provider,
    requestCount: 0,
    errorCount: 0,
    totalTokens: 0,
    totalCost: 0,
    averageLatency: 0,
    uptime: Date.now()
  };
  
  // Request tracking for latency calculation
  private latencyHistory: number[] = [];
  private maxLatencyHistory = 100;

  /**
   * Initialize the provider with configuration
   */
  async initialize(config: ProviderConfig): Promise<void> {
    this.config = { ...config };
    
    // Validate required configuration
    this.validateConfig();
    
    // Provider-specific initialization
    await this.doInitialize();
    
    this.initialized = true;
  }

  /**
   * Provider-specific initialization logic
   */
  protected abstract doInitialize(): Promise<void>;

  /**
   * Validate provider configuration
   */
  protected validateConfig(): void {
    if (!this.config.apiKey && this.provider !== LLMProvider.OLLAMA) {
      throw new AuthenticationError(this.provider, 'API key is required');
    }
  }

  /**
   * Complete a prompt with retry logic and error handling
   */
  async complete(options: CompletionOptions): Promise<CompletionResponse> {
    if (!this.initialized) {
      throw new ProviderError('Provider not initialized', this.provider);
    }

    const startTime = Date.now();
    this.metrics.requestCount++;
    
    try {
      this.events.emit('request:start', this.provider, options);
      
      // Validate model
      if (!this.validateModel(options.model)) {
        throw new ProviderError(
          `Model ${options.model} not supported by ${this.provider}`,
          this.provider,
          'INVALID_MODEL'
        );
      }
      
      // Execute with retry logic
      const response = await this.executeWithRetry(
        () => this.doComplete(options),
        this.config.maxRetries || 3,
        this.config.retryDelay || 1000
      );
      
      // Update metrics
      this.updateMetrics(response, startTime);
      
      this.events.emit('request:complete', this.provider, response);
      return response;
      
    } catch (error) {
      this.metrics.errorCount++;
      this.events.emit('request:error', this.provider, error as Error);
      throw this.wrapError(error);
    }
  }

  /**
   * Provider-specific completion logic
   */
  protected abstract doComplete(options: CompletionOptions): Promise<CompletionResponse>;

  /**
   * Stream a completion with error handling
   */
  async *stream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown> {
    if (!this.initialized) {
      throw new ProviderError('Provider not initialized', this.provider);
    }

    const startTime = Date.now();
    this.metrics.requestCount++;
    
    try {
      this.events.emit('stream:start', this.provider, options);
      
      // Validate model
      if (!this.validateModel(options.model)) {
        throw new ProviderError(
          `Model ${options.model} not supported by ${this.provider}`,
          this.provider,
          'INVALID_MODEL'
        );
      }
      
      // Stream with error handling
      let totalTokens = 0;
      const generator = this.doStream(options);
      
      for await (const chunk of generator) {
        this.events.emit('stream:chunk', this.provider, chunk);
        
        // Estimate tokens from chunk (provider-specific)
        totalTokens += this.estimateChunkTokens(chunk);
        
        yield chunk;
      }
      
      // Update metrics with estimated usage
      const estimatedUsage: TokenUsage = {
        promptTokens: 0, // Would need to estimate from input
        completionTokens: totalTokens,
        totalTokens: totalTokens
      };
      
      this.updateMetricsFromUsage(estimatedUsage, startTime);
      this.events.emit('stream:end', this.provider);
      
    } catch (error) {
      this.metrics.errorCount++;
      this.events.emit('stream:error', this.provider, error as Error);
      throw this.wrapError(error);
    }
  }

  /**
   * Provider-specific streaming logic
   */
  protected abstract doStream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown>;

  /**
   * Get provider status with health check
   */
  async getStatus(): Promise<ProviderStatus> {
    const startTime = Date.now();
    let healthy = false;
    let lastError: Error | undefined;
    
    try {
      // Perform health check
      await this.doHealthCheck();
      healthy = true;
    } catch (error) {
      lastError = error as Error;
    }
    
    const latency = Date.now() - startTime;
    const errorRate = this.metrics.requestCount > 0 
      ? this.metrics.errorCount / this.metrics.requestCount 
      : 0;
    
    const status: ProviderStatus = {
      provider: this.provider,
      available: this.initialized,
      healthy,
      latency,
      errorRate,
      lastError,
      lastChecked: new Date()
    };
    
    this.events.emit('health:check', this.provider, status);
    return status;
  }

  /**
   * Provider-specific health check
   */
  protected abstract doHealthCheck(): Promise<void>;

  /**
   * Get provider metrics
   */
  getMetrics(): ProviderMetrics {
    const metrics = { ...this.metrics };
    this.events.emit('metrics:update', this.provider, metrics);
    return metrics;
  }

  /**
   * Validate if a model is supported
   */
  validateModel(modelId: string): boolean {
    return this.models.some(model => model.id === modelId);
  }

  /**
   * Estimate token count for text
   */
  async estimateTokens(text: string): Promise<number> {
    // Default implementation - can be overridden by providers
    // Rough estimate: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }

  /**
   * Clean up provider resources
   */
  async cleanup(): Promise<void> {
    this.initialized = false;
    this.events.removeAllListeners();
  }

  /**
   * Execute function with retry logic
   */
  protected async executeWithRetry<T>(
    fn: () => Promise<T>,
    maxRetries: number,
    retryDelay: number
  ): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error as Error;
        
        // Don't retry on certain errors
        if (
          error instanceof AuthenticationError ||
          error instanceof ProviderError && error.code === 'INVALID_MODEL'
        ) {
          throw error;
        }
        
        // Handle rate limits with backoff
        if (error instanceof RateLimitError) {
          const delay = error.retryAfter || retryDelay * Math.pow(2, attempt);
          await this.delay(delay);
          continue;
        }
        
        // Retry other errors with exponential backoff
        if (attempt < maxRetries) {
          await this.delay(retryDelay * Math.pow(2, attempt));
          continue;
        }
      }
    }
    
    throw lastError!;
  }

  /**
   * Wrap provider-specific errors
   */
  protected wrapError(error: any): Error {
    if (error instanceof ProviderError) {
      return error;
    }
    
    // Common error patterns
    if (error.status === 429 || error.statusCode === 429) {
      return new RateLimitError(
        this.provider,
        error.headers?.['retry-after'],
        error
      );
    }
    
    if (error.status === 401 || error.statusCode === 401) {
      return new AuthenticationError(this.provider, error);
    }
    
    return new ProviderError(
      error.message || 'Unknown error',
      this.provider,
      error.code,
      error.status || error.statusCode,
      error
    );
  }

  /**
   * Update metrics after successful request
   */
  protected updateMetrics(response: CompletionResponse, startTime: number): void {
    const latency = Date.now() - startTime;
    this.updateLatency(latency);
    
    if (response.usage) {
      this.metrics.totalTokens += response.usage.totalTokens;
      
      if (response.usage.estimatedCost) {
        this.metrics.totalCost += response.usage.estimatedCost;
      }
    }
  }

  /**
   * Update metrics from token usage
   */
  protected updateMetricsFromUsage(usage: TokenUsage, startTime: number): void {
    const latency = Date.now() - startTime;
    this.updateLatency(latency);
    
    this.metrics.totalTokens += usage.totalTokens;
    
    if (usage.estimatedCost) {
      this.metrics.totalCost += usage.estimatedCost;
    }
  }

  /**
   * Update latency tracking
   */
  private updateLatency(latency: number): void {
    this.latencyHistory.push(latency);
    
    if (this.latencyHistory.length > this.maxLatencyHistory) {
      this.latencyHistory.shift();
    }
    
    const sum = this.latencyHistory.reduce((a, b) => a + b, 0);
    this.metrics.averageLatency = sum / this.latencyHistory.length;
  }

  /**
   * Estimate tokens in a stream chunk
   */
  protected estimateChunkTokens(chunk: StreamChunk): number {
    // Default implementation - providers can override
    let tokens = 0;
    
    for (const choice of chunk.choices) {
      if (choice.delta.content) {
        tokens += Math.ceil(choice.delta.content.length / 4);
      }
    }
    
    return tokens;
  }

  /**
   * Delay helper
   */
  protected delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get event emitter for external listeners
   */
  getEventEmitter(): ProviderEventEmitter {
    return this.events;
  }
}