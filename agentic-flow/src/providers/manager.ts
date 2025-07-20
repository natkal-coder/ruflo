/**
 * Provider Manager
 * Manages multiple LLM providers with fallback, load balancing, and cost optimization
 */

import {
  ILLMProvider,
  LLMProvider,
  ProviderManagerConfig,
  CompletionOptions,
  CompletionResponse,
  StreamChunk,
  ProviderStatus,
  ProviderMetrics,
  FallbackStrategy,
  ProviderError,
  ProviderUnavailableError,
  ModelInfo,
  ProviderEventEmitter
} from './types';
import { AnthropicProvider } from './anthropic';
import { OpenAIProvider } from './openai';
import { GoogleProvider } from './google';
import { OllamaProvider } from './ollama';

interface ProviderInstance {
  provider: ILLMProvider;
  priority: number;
  weight: number;
  lastUsed: Date;
  failures: number;
  successRate: number;
}

export class ProviderManager {
  private providers: Map<LLMProvider, ProviderInstance> = new Map();
  private config: ProviderManagerConfig;
  private healthCheckInterval?: NodeJS.Timeout;
  private events = new ProviderEventEmitter();
  private requestCount = 0;

  constructor(config: ProviderManagerConfig) {
    this.config = config;
  }

  /**
   * Initialize all configured providers
   */
  async initialize(): Promise<void> {
    const initPromises: Promise<void>[] = [];

    // Initialize configured providers
    for (const [providerType, providerConfig] of Object.entries(this.config.providers)) {
      const provider = this.createProvider(providerType as LLMProvider);
      if (provider) {
        initPromises.push(
          this.initializeProvider(provider, providerConfig, providerType as LLMProvider)
        );
      }
    }

    await Promise.allSettled(initPromises);

    // Start health monitoring if enabled
    if (this.config.healthCheckInterval) {
      this.startHealthMonitoring();
    }

    // Verify at least one provider is available
    if (this.providers.size === 0) {
      throw new Error('No providers could be initialized');
    }
  }

  /**
   * Create provider instance based on type
   */
  private createProvider(type: LLMProvider): ILLMProvider | null {
    switch (type) {
      case LLMProvider.ANTHROPIC:
        return new AnthropicProvider();
      case LLMProvider.OPENAI:
        return new OpenAIProvider();
      case LLMProvider.GOOGLE:
        return new GoogleProvider();
      case LLMProvider.OLLAMA:
        return new OllamaProvider();
      default:
        console.warn(`Unknown provider type: ${type}`);
        return null;
    }
  }

  /**
   * Initialize a single provider
   */
  private async initializeProvider(
    provider: ILLMProvider,
    config: any,
    type: LLMProvider
  ): Promise<void> {
    try {
      await provider.initialize(config);
      
      this.providers.set(type, {
        provider,
        priority: this.getProviderPriority(type),
        weight: 1,
        lastUsed: new Date(),
        failures: 0,
        successRate: 1
      });

      // Subscribe to provider events
      const emitter = (provider as any).getEventEmitter?.();
      if (emitter) {
        this.forwardProviderEvents(emitter, type);
      }

      console.log(`Initialized provider: ${type}`);
    } catch (error) {
      console.error(`Failed to initialize provider ${type}:`, error);
    }
  }

  /**
   * Get provider priority based on configuration and type
   */
  private getProviderPriority(type: LLMProvider): number {
    // Default priorities (lower is higher priority)
    const defaults: Record<LLMProvider, number> = {
      [LLMProvider.ANTHROPIC]: 1,
      [LLMProvider.OPENAI]: 2,
      [LLMProvider.GOOGLE]: 3,
      [LLMProvider.OLLAMA]: 4,
      [LLMProvider.COHERE]: 5,
      [LLMProvider.HUGGINGFACE]: 6
    };

    return defaults[type] || 99;
  }

  /**
   * Forward provider events to manager events
   */
  private forwardProviderEvents(emitter: ProviderEventEmitter, type: LLMProvider): void {
    // Forward all provider events
    const events = [
      'request:start', 'request:complete', 'request:error',
      'stream:start', 'stream:chunk', 'stream:end', 'stream:error',
      'health:check', 'metrics:update'
    ];

    for (const event of events) {
      emitter.on(event as any, (...args: any[]) => {
        this.events.emit(event as any, ...args);
      });
    }
  }

  /**
   * Complete a prompt using the configured fallback strategy
   */
  async complete(options: CompletionOptions): Promise<CompletionResponse> {
    this.requestCount++;
    
    const availableProviders = await this.getAvailableProviders(options.model);
    if (availableProviders.length === 0) {
      throw new ProviderUnavailableError(
        LLMProvider.ANTHROPIC, // Default for error
        'No providers available for model: ' + options.model
      );
    }

    const providers = this.sortProvidersByStrategy(availableProviders);
    let lastError: Error | undefined;

    for (const instance of providers) {
      try {
        const response = await instance.provider.complete(options);
        
        // Update success metrics
        this.updateProviderMetrics(instance, true);
        
        return response;
      } catch (error) {
        lastError = error as Error;
        
        // Update failure metrics
        this.updateProviderMetrics(instance, false);
        
        // Log error but continue to next provider
        console.error(`Provider ${instance.provider.provider} failed:`, error);
      }
    }

    throw lastError || new Error('All providers failed');
  }

  /**
   * Stream a completion using the configured fallback strategy
   */
  async *stream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown> {
    const availableProviders = await this.getAvailableProviders(options.model);
    if (availableProviders.length === 0) {
      throw new ProviderUnavailableError(
        LLMProvider.ANTHROPIC,
        'No providers available for model: ' + options.model
      );
    }

    const providers = this.sortProvidersByStrategy(availableProviders);
    let lastError: Error | undefined;

    for (const instance of providers) {
      try {
        const generator = instance.provider.stream(options);
        
        // Update metrics on successful start
        this.updateProviderMetrics(instance, true);
        
        yield* generator;
        return;
      } catch (error) {
        lastError = error as Error;
        
        // Update failure metrics
        this.updateProviderMetrics(instance, false);
        
        console.error(`Provider ${instance.provider.provider} streaming failed:`, error);
      }
    }

    throw lastError || new Error('All providers failed to stream');
  }

  /**
   * Get available providers that support the requested model
   */
  private async getAvailableProviders(modelId?: string): Promise<ProviderInstance[]> {
    const available: ProviderInstance[] = [];

    for (const instance of this.providers.values()) {
      // Check if provider supports the model
      if (modelId && !instance.provider.validateModel(modelId)) {
        continue;
      }

      // Check provider health
      try {
        const status = await instance.provider.getStatus();
        if (status.available && status.healthy) {
          available.push(instance);
        }
      } catch {
        // Provider unhealthy, skip
      }
    }

    return available;
  }

  /**
   * Sort providers based on fallback strategy
   */
  private sortProvidersByStrategy(providers: ProviderInstance[]): ProviderInstance[] {
    const strategy = this.config.fallbackStrategy || FallbackStrategy.SEQUENTIAL;

    switch (strategy) {
      case FallbackStrategy.SEQUENTIAL:
        // Sort by priority
        return [...providers].sort((a, b) => a.priority - b.priority);

      case FallbackStrategy.LOAD_BALANCE:
        // Sort by least recently used and weight
        return [...providers].sort((a, b) => {
          const scoreA = a.weight * (Date.now() - a.lastUsed.getTime());
          const scoreB = b.weight * (Date.now() - b.lastUsed.getTime());
          return scoreB - scoreA;
        });

      case FallbackStrategy.COST_OPTIMIZE:
        // Sort by cost (requires model info)
        return [...providers].sort((a, b) => {
          const costA = this.getProviderCost(a.provider);
          const costB = this.getProviderCost(b.provider);
          return costA - costB;
        });

      case FallbackStrategy.LATENCY_OPTIMIZE:
        // Sort by average latency
        return [...providers].sort((a, b) => {
          const metricsA = a.provider.getMetrics();
          const metricsB = b.provider.getMetrics();
          return metricsA.averageLatency - metricsB.averageLatency;
        });

      default:
        return providers;
    }
  }

  /**
   * Get average cost for a provider
   */
  private getProviderCost(provider: ILLMProvider): number {
    const models = provider.models;
    if (models.length === 0) return 999;

    let totalCost = 0;
    let count = 0;

    for (const model of models) {
      if (model.capabilities.costPer1kTokens) {
        totalCost += model.capabilities.costPer1kTokens.input + model.capabilities.costPer1kTokens.output;
        count += 2;
      }
    }

    return count > 0 ? totalCost / count : 999;
  }

  /**
   * Update provider metrics after request
   */
  private updateProviderMetrics(instance: ProviderInstance, success: boolean): void {
    instance.lastUsed = new Date();
    
    if (success) {
      instance.failures = 0;
      instance.successRate = (instance.successRate * 0.9) + 0.1; // Moving average
    } else {
      instance.failures++;
      instance.successRate = instance.successRate * 0.9; // Decay success rate
      
      // Reduce weight for repeated failures
      if (instance.failures > 3) {
        instance.weight = Math.max(0.1, instance.weight * 0.8);
      }
    }
  }

  /**
   * Start health monitoring
   */
  private startHealthMonitoring(): void {
    this.healthCheckInterval = setInterval(async () => {
      for (const [type, instance] of this.providers) {
        try {
          const status = await instance.provider.getStatus();
          
          // Reset weight for healthy providers
          if (status.healthy && instance.weight < 1) {
            instance.weight = Math.min(1, instance.weight * 1.2);
          }
        } catch (error) {
          console.error(`Health check failed for ${type}:`, error);
        }
      }
    }, this.config.healthCheckInterval);
  }

  /**
   * Get all provider statuses
   */
  async getAllStatuses(): Promise<Map<LLMProvider, ProviderStatus>> {
    const statuses = new Map<LLMProvider, ProviderStatus>();

    for (const [type, instance] of this.providers) {
      try {
        const status = await instance.provider.getStatus();
        statuses.set(type, status);
      } catch (error) {
        statuses.set(type, {
          provider: type,
          available: false,
          healthy: false,
          lastError: error as Error,
          lastChecked: new Date()
        });
      }
    }

    return statuses;
  }

  /**
   * Get all provider metrics
   */
  getAllMetrics(): Map<LLMProvider, ProviderMetrics> {
    const metrics = new Map<LLMProvider, ProviderMetrics>();

    for (const [type, instance] of this.providers) {
      metrics.set(type, instance.provider.getMetrics());
    }

    return metrics;
  }

  /**
   * Get all available models across providers
   */
  getAllModels(): ModelInfo[] {
    const models: ModelInfo[] = [];

    for (const instance of this.providers.values()) {
      models.push(...instance.provider.models);
    }

    return models;
  }

  /**
   * Find the best model for given constraints
   */
  findBestModel(constraints: {
    maxCost?: number;
    minContextWindow?: number;
    requiresVision?: boolean;
    requiresFunctionCalling?: boolean;
    preferredProvider?: LLMProvider;
  }): ModelInfo | null {
    let candidates = this.getAllModels();

    // Filter by constraints
    if (constraints.requiresVision) {
      candidates = candidates.filter(m => m.capabilities.vision);
    }

    if (constraints.requiresFunctionCalling) {
      candidates = candidates.filter(m => m.capabilities.functionCalling);
    }

    if (constraints.minContextWindow) {
      candidates = candidates.filter(m => m.capabilities.contextWindow >= constraints.minContextWindow);
    }

    if (constraints.maxCost !== undefined) {
      candidates = candidates.filter(m => {
        const cost = m.capabilities.costPer1kTokens;
        if (!cost) return true; // Free models
        return (cost.input + cost.output) / 2 <= constraints.maxCost;
      });
    }

    if (candidates.length === 0) return null;

    // Sort by preference and cost
    candidates.sort((a, b) => {
      // Prefer requested provider
      if (constraints.preferredProvider) {
        if (a.provider === constraints.preferredProvider && b.provider !== constraints.preferredProvider) return -1;
        if (b.provider === constraints.preferredProvider && a.provider !== constraints.preferredProvider) return 1;
      }

      // Then by cost
      const costA = a.capabilities.costPer1kTokens ? 
        (a.capabilities.costPer1kTokens.input + a.capabilities.costPer1kTokens.output) / 2 : 0;
      const costB = b.capabilities.costPer1kTokens ? 
        (b.capabilities.costPer1kTokens.input + b.capabilities.costPer1kTokens.output) / 2 : 0;

      return costA - costB;
    });

    return candidates[0];
  }

  /**
   * Get manager statistics
   */
  getStatistics(): {
    totalRequests: number;
    providerStats: Map<LLMProvider, {
      requests: number;
      failures: number;
      successRate: number;
      averageLatency: number;
      totalCost: number;
    }>;
  } {
    const providerStats = new Map();

    for (const [type, instance] of this.providers) {
      const metrics = instance.provider.getMetrics();
      providerStats.set(type, {
        requests: metrics.requestCount,
        failures: metrics.errorCount,
        successRate: instance.successRate,
        averageLatency: metrics.averageLatency,
        totalCost: metrics.totalCost
      });
    }

    return {
      totalRequests: this.requestCount,
      providerStats
    };
  }

  /**
   * Clean up resources
   */
  async cleanup(): Promise<void> {
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    for (const instance of this.providers.values()) {
      await instance.provider.cleanup();
    }

    this.providers.clear();
    this.events.removeAllListeners();
  }

  /**
   * Get event emitter for external listeners
   */
  getEventEmitter(): ProviderEventEmitter {
    return this.events;
  }
}