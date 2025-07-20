/**
 * Multi-LLM Provider System Types
 * Unified interface for multiple LLM providers with streaming support
 */

import { EventEmitter } from 'events';

/**
 * Supported LLM providers
 */
export enum LLMProvider {
  ANTHROPIC = 'anthropic',
  OPENAI = 'openai',
  GOOGLE = 'google',
  OLLAMA = 'ollama',
  COHERE = 'cohere',
  HUGGINGFACE = 'huggingface'
}

/**
 * Model capabilities
 */
export interface ModelCapabilities {
  streaming: boolean;
  functionCalling: boolean;
  vision: boolean;
  maxTokens: number;
  contextWindow: number;
  costPer1kTokens?: {
    input: number;
    output: number;
  };
}

/**
 * Model information
 */
export interface ModelInfo {
  id: string;
  name: string;
  provider: LLMProvider;
  capabilities: ModelCapabilities;
  description?: string;
  deprecated?: boolean;
}

/**
 * Message role types
 */
export type MessageRole = 'system' | 'user' | 'assistant' | 'function';

/**
 * Message content types
 */
export interface TextContent {
  type: 'text';
  text: string;
}

export interface ImageContent {
  type: 'image';
  image: {
    url: string;
    detail?: 'low' | 'high' | 'auto';
  };
}

export type MessageContent = string | TextContent | ImageContent | (TextContent | ImageContent)[];

/**
 * Message structure
 */
export interface Message {
  role: MessageRole;
  content: MessageContent;
  name?: string;
  functionCall?: {
    name: string;
    arguments: string;
  };
}

/**
 * Function definition for function calling
 */
export interface FunctionDefinition {
  name: string;
  description?: string;
  parameters?: Record<string, any>;
}

/**
 * Completion options
 */
export interface CompletionOptions {
  model: string;
  messages: Message[];
  temperature?: number;
  maxTokens?: number;
  topP?: number;
  topK?: number;
  frequencyPenalty?: number;
  presencePenalty?: number;
  stopSequences?: string[];
  systemPrompt?: string;
  functions?: FunctionDefinition[];
  functionCall?: 'none' | 'auto' | { name: string };
  stream?: boolean;
  user?: string;
  metadata?: Record<string, any>;
}

/**
 * Completion response
 */
export interface CompletionResponse {
  id: string;
  model: string;
  choices: CompletionChoice[];
  usage: TokenUsage;
  created: number;
  provider: LLMProvider;
  metadata?: Record<string, any>;
}

/**
 * Completion choice
 */
export interface CompletionChoice {
  index: number;
  message: Message;
  finishReason?: 'stop' | 'length' | 'function_call' | 'content_filter' | 'null';
  logprobs?: any;
}

/**
 * Token usage information
 */
export interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCost?: number;
}

/**
 * Stream chunk for streaming responses
 */
export interface StreamChunk {
  id: string;
  model: string;
  choices: StreamChoice[];
  created: number;
  provider: LLMProvider;
}

/**
 * Stream choice
 */
export interface StreamChoice {
  index: number;
  delta: Partial<Message>;
  finishReason?: string;
}

/**
 * Provider configuration
 */
export interface ProviderConfig {
  apiKey?: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
  headers?: Record<string, string>;
  proxy?: {
    host: string;
    port: number;
    auth?: {
      username: string;
      password: string;
    };
  };
}

/**
 * Provider status
 */
export interface ProviderStatus {
  provider: LLMProvider;
  available: boolean;
  healthy: boolean;
  latency?: number;
  errorRate?: number;
  lastError?: Error;
  lastChecked: Date;
}

/**
 * Provider metrics
 */
export interface ProviderMetrics {
  provider: LLMProvider;
  requestCount: number;
  errorCount: number;
  totalTokens: number;
  totalCost: number;
  averageLatency: number;
  uptime: number;
}

/**
 * Fallback strategy
 */
export enum FallbackStrategy {
  SEQUENTIAL = 'sequential',
  LOAD_BALANCE = 'load_balance',
  COST_OPTIMIZE = 'cost_optimize',
  LATENCY_OPTIMIZE = 'latency_optimize'
}

/**
 * Provider manager configuration
 */
export interface ProviderManagerConfig {
  providers: Record<LLMProvider, ProviderConfig>;
  fallbackStrategy?: FallbackStrategy;
  healthCheckInterval?: number;
  metricsEnabled?: boolean;
  costThreshold?: number;
  latencyThreshold?: number;
}

/**
 * Base provider interface
 */
export interface ILLMProvider {
  readonly provider: LLMProvider;
  readonly models: ModelInfo[];
  
  /**
   * Initialize the provider
   */
  initialize(config: ProviderConfig): Promise<void>;
  
  /**
   * Complete a prompt
   */
  complete(options: CompletionOptions): Promise<CompletionResponse>;
  
  /**
   * Stream a completion
   */
  stream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown>;
  
  /**
   * Get provider status
   */
  getStatus(): Promise<ProviderStatus>;
  
  /**
   * Get provider metrics
   */
  getMetrics(): ProviderMetrics;
  
  /**
   * Validate model availability
   */
  validateModel(modelId: string): boolean;
  
  /**
   * Estimate token count
   */
  estimateTokens(text: string): Promise<number>;
  
  /**
   * Clean up resources
   */
  cleanup(): Promise<void>;
}

/**
 * Provider events
 */
export interface ProviderEvents {
  'request:start': (provider: LLMProvider, options: CompletionOptions) => void;
  'request:complete': (provider: LLMProvider, response: CompletionResponse) => void;
  'request:error': (provider: LLMProvider, error: Error) => void;
  'stream:start': (provider: LLMProvider, options: CompletionOptions) => void;
  'stream:chunk': (provider: LLMProvider, chunk: StreamChunk) => void;
  'stream:end': (provider: LLMProvider) => void;
  'stream:error': (provider: LLMProvider, error: Error) => void;
  'health:check': (provider: LLMProvider, status: ProviderStatus) => void;
  'metrics:update': (provider: LLMProvider, metrics: ProviderMetrics) => void;
}

/**
 * Provider event emitter
 */
export class ProviderEventEmitter extends EventEmitter {
  emit<K extends keyof ProviderEvents>(
    event: K,
    ...args: Parameters<ProviderEvents[K]>
  ): boolean {
    return super.emit(event, ...args);
  }

  on<K extends keyof ProviderEvents>(
    event: K,
    listener: ProviderEvents[K]
  ): this {
    return super.on(event, listener);
  }

  off<K extends keyof ProviderEvents>(
    event: K,
    listener: ProviderEvents[K]
  ): this {
    return super.off(event, listener);
  }
}

/**
 * Error types
 */
export class ProviderError extends Error {
  constructor(
    message: string,
    public provider: LLMProvider,
    public code?: string,
    public statusCode?: number,
    public details?: any
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

export class RateLimitError extends ProviderError {
  constructor(
    provider: LLMProvider,
    public retryAfter?: number,
    details?: any
  ) {
    super('Rate limit exceeded', provider, 'RATE_LIMIT', 429, details);
    this.name = 'RateLimitError';
  }
}

export class AuthenticationError extends ProviderError {
  constructor(provider: LLMProvider, details?: any) {
    super('Authentication failed', provider, 'AUTH_ERROR', 401, details);
    this.name = 'AuthenticationError';
  }
}

export class ModelNotFoundError extends ProviderError {
  constructor(provider: LLMProvider, modelId: string, details?: any) {
    super(`Model ${modelId} not found`, provider, 'MODEL_NOT_FOUND', 404, details);
    this.name = 'ModelNotFoundError';
  }
}

export class ProviderUnavailableError extends ProviderError {
  constructor(provider: LLMProvider, reason?: string, details?: any) {
    super(`Provider unavailable: ${reason || 'Unknown error'}`, provider, 'UNAVAILABLE', 503, details);
    this.name = 'ProviderUnavailableError';
  }
}