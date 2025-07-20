/**
 * Multi-LLM Provider System
 * Unified interface for multiple LLM providers with advanced features
 */

// Core types
export * from './types';

// Base provider
export { BaseLLMProvider } from './base';

// Provider implementations
export { AnthropicProvider } from './anthropic';
export { OpenAIProvider } from './openai';
export { GoogleProvider } from './google';
export { OllamaProvider } from './ollama';

// Provider manager
export { ProviderManager } from './manager';

// Utilities
export * from './utils';

// Configuration
export * from './config';

// Convenience exports
import { ProviderManager } from './manager';
import { createDefaultManagerConfig } from './config';
import {
  LLMProvider,
  CompletionOptions,
  CompletionResponse,
  StreamChunk,
  ProviderManagerConfig,
  ModelInfo
} from './types';

/**
 * Create a pre-configured provider manager
 */
export function createProviderManager(config?: Partial<ProviderManagerConfig>): ProviderManager {
  const defaultConfig = createDefaultManagerConfig();
  const finalConfig = {
    ...defaultConfig,
    ...config,
    providers: {
      ...defaultConfig.providers,
      ...config?.providers
    }
  };
  
  return new ProviderManager(finalConfig);
}

/**
 * Quick setup for single provider
 */
export async function createSingleProvider(
  provider: LLMProvider,
  apiKey?: string,
  baseUrl?: string
) {
  const { AnthropicProvider } = await import('./anthropic');
  const { OpenAIProvider } = await import('./openai');
  const { GoogleProvider } = await import('./google');
  const { OllamaProvider } = await import('./ollama');

  let instance;
  switch (provider) {
    case LLMProvider.ANTHROPIC:
      instance = new AnthropicProvider();
      break;
    case LLMProvider.OPENAI:
      instance = new OpenAIProvider();
      break;
    case LLMProvider.GOOGLE:
      instance = new GoogleProvider();
      break;
    case LLMProvider.OLLAMA:
      instance = new OllamaProvider();
      break;
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }

  await instance.initialize({
    apiKey,
    baseUrl
  });

  return instance;
}

/**
 * Provider feature detection
 */
export function getProviderCapabilities(provider: LLMProvider): {
  streaming: boolean;
  functionCalling: boolean;
  vision: boolean;
  local: boolean;
} {
  const { PROVIDER_FEATURES } = require('./config');
  const features = PROVIDER_FEATURES[provider];
  
  return {
    streaming: features.supportsStreaming,
    functionCalling: features.supportsFunctionCalling,
    vision: features.supportsVision,
    local: features.isLocal
  };
}

/**
 * Find best model for requirements
 */
export function findBestModel(
  models: ModelInfo[],
  requirements: {
    maxCost?: number;
    minContextWindow?: number;
    requiresVision?: boolean;
    requiresFunctionCalling?: boolean;
    preferLocal?: boolean;
  }
): ModelInfo | null {
  let candidates = [...models];

  // Filter by requirements
  if (requirements.requiresVision) {
    candidates = candidates.filter(m => m.capabilities.vision);
  }

  if (requirements.requiresFunctionCalling) {
    candidates = candidates.filter(m => m.capabilities.functionCalling);
  }

  if (requirements.minContextWindow) {
    candidates = candidates.filter(m => m.capabilities.contextWindow >= requirements.minContextWindow);
  }

  if (requirements.maxCost !== undefined) {
    candidates = candidates.filter(m => {
      const cost = m.capabilities.costPer1kTokens;
      if (!cost) return true; // Free models pass
      return (cost.input + cost.output) / 2 <= requirements.maxCost;
    });
  }

  if (candidates.length === 0) return null;

  // Sort by preferences
  candidates.sort((a, b) => {
    // Prefer local models if requested
    if (requirements.preferLocal) {
      const aIsLocal = a.provider === LLMProvider.OLLAMA;
      const bIsLocal = b.provider === LLMProvider.OLLAMA;
      if (aIsLocal && !bIsLocal) return -1;
      if (bIsLocal && !aIsLocal) return 1;
    }

    // Then by cost (lower is better)
    const costA = a.capabilities.costPer1kTokens ? 
      (a.capabilities.costPer1kTokens.input + a.capabilities.costPer1kTokens.output) / 2 : 0;
    const costB = b.capabilities.costPer1kTokens ? 
      (b.capabilities.costPer1kTokens.input + b.capabilities.costPer1kTokens.output) / 2 : 0;

    return costA - costB;
  });

  return candidates[0];
}

/**
 * Simple completion function with automatic provider selection
 */
export async function complete(
  prompt: string,
  options?: {
    model?: string;
    temperature?: number;
    maxTokens?: number;
    provider?: LLMProvider;
    apiKey?: string;
  }
): Promise<string> {
  const manager = createProviderManager();
  await manager.initialize();

  const completionOptions: CompletionOptions = {
    model: options?.model || 'gpt-3.5-turbo',
    messages: [
      { role: 'user', content: prompt }
    ],
    temperature: options?.temperature,
    maxTokens: options?.maxTokens
  };

  const response = await manager.complete(completionOptions);
  return response.choices[0]?.message.content || '';
}

/**
 * Simple streaming function
 */
export async function* stream(
  prompt: string,
  options?: {
    model?: string;
    temperature?: number;
    maxTokens?: number;
    provider?: LLMProvider;
    apiKey?: string;
  }
): AsyncGenerator<string, void, unknown> {
  const manager = createProviderManager();
  await manager.initialize();

  const completionOptions: CompletionOptions = {
    model: options?.model || 'gpt-3.5-turbo',
    messages: [
      { role: 'user', content: prompt }
    ],
    temperature: options?.temperature,
    maxTokens: options?.maxTokens,
    stream: true
  };

  for await (const chunk of manager.stream(completionOptions)) {
    const content = chunk.choices[0]?.delta?.content;
    if (content) {
      yield content;
    }
  }
}

/**
 * Export default provider manager instance
 */
let defaultManager: ProviderManager | null = null;

export function getDefaultManager(): ProviderManager {
  if (!defaultManager) {
    defaultManager = createProviderManager();
  }
  return defaultManager;
}

/**
 * Initialize default manager
 */
export async function initializeDefaultManager(config?: Partial<ProviderManagerConfig>): Promise<void> {
  defaultManager = createProviderManager(config);
  await defaultManager.initialize();
}

/**
 * Cleanup default manager
 */
export async function cleanupDefaultManager(): Promise<void> {
  if (defaultManager) {
    await defaultManager.cleanup();
    defaultManager = null;
  }
}

// Re-export commonly used types for convenience
export type {
  CompletionOptions,
  CompletionResponse,
  StreamChunk,
  Message,
  ModelInfo,
  ProviderStatus,
  ProviderMetrics,
  TokenUsage
} from './types';