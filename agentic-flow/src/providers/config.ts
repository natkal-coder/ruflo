/**
 * Provider Configuration Types and Defaults
 * Configuration management for LLM providers
 */

import { LLMProvider, ProviderConfig, FallbackStrategy } from './types';

/**
 * Environment variable names for provider API keys
 */
export const API_KEY_ENV_VARS: Record<LLMProvider, string> = {
  [LLMProvider.ANTHROPIC]: 'ANTHROPIC_API_KEY',
  [LLMProvider.OPENAI]: 'OPENAI_API_KEY',
  [LLMProvider.GOOGLE]: 'GOOGLE_API_KEY',
  [LLMProvider.OLLAMA]: 'OLLAMA_HOST',
  [LLMProvider.COHERE]: 'COHERE_API_KEY',
  [LLMProvider.HUGGINGFACE]: 'HUGGINGFACE_API_KEY'
};

/**
 * Default base URLs for providers
 */
export const DEFAULT_BASE_URLS: Partial<Record<LLMProvider, string>> = {
  [LLMProvider.OLLAMA]: 'http://localhost:11434',
  [LLMProvider.ANTHROPIC]: 'https://api.anthropic.com',
  [LLMProvider.OPENAI]: 'https://api.openai.com/v1',
  [LLMProvider.GOOGLE]: 'https://generativelanguage.googleapis.com/v1'
};

/**
 * Default provider configurations
 */
export const DEFAULT_PROVIDER_CONFIGS: Record<LLMProvider, Partial<ProviderConfig>> = {
  [LLMProvider.ANTHROPIC]: {
    timeout: 60000,
    maxRetries: 3,
    retryDelay: 1000
  },
  [LLMProvider.OPENAI]: {
    timeout: 60000,
    maxRetries: 3,
    retryDelay: 1000
  },
  [LLMProvider.GOOGLE]: {
    timeout: 60000,
    maxRetries: 3,
    retryDelay: 1000
  },
  [LLMProvider.OLLAMA]: {
    timeout: 120000, // Longer timeout for local models
    maxRetries: 2,
    retryDelay: 500
  },
  [LLMProvider.COHERE]: {
    timeout: 60000,
    maxRetries: 3,
    retryDelay: 1000
  },
  [LLMProvider.HUGGINGFACE]: {
    timeout: 90000,
    maxRetries: 3,
    retryDelay: 2000
  }
};

/**
 * Provider feature flags
 */
export interface ProviderFeatures {
  supportsStreaming: boolean;
  supportsFunctionCalling: boolean;
  supportsVision: boolean;
  supportsSystemMessages: boolean;
  supportsMultiModal: boolean;
  requiresApiKey: boolean;
  isLocal: boolean;
}

/**
 * Provider feature configurations
 */
export const PROVIDER_FEATURES: Record<LLMProvider, ProviderFeatures> = {
  [LLMProvider.ANTHROPIC]: {
    supportsStreaming: true,
    supportsFunctionCalling: true,
    supportsVision: true,
    supportsSystemMessages: true,
    supportsMultiModal: true,
    requiresApiKey: true,
    isLocal: false
  },
  [LLMProvider.OPENAI]: {
    supportsStreaming: true,
    supportsFunctionCalling: true,
    supportsVision: true,
    supportsSystemMessages: true,
    supportsMultiModal: true,
    requiresApiKey: true,
    isLocal: false
  },
  [LLMProvider.GOOGLE]: {
    supportsStreaming: true,
    supportsFunctionCalling: true,
    supportsVision: true,
    supportsSystemMessages: false, // Gemini handles system messages differently
    supportsMultiModal: true,
    requiresApiKey: true,
    isLocal: false
  },
  [LLMProvider.OLLAMA]: {
    supportsStreaming: true,
    supportsFunctionCalling: true, // Depends on model
    supportsVision: true, // Depends on model
    supportsSystemMessages: true,
    supportsMultiModal: true, // Depends on model
    requiresApiKey: false,
    isLocal: true
  },
  [LLMProvider.COHERE]: {
    supportsStreaming: true,
    supportsFunctionCalling: false,
    supportsVision: false,
    supportsSystemMessages: true,
    supportsMultiModal: false,
    requiresApiKey: true,
    isLocal: false
  },
  [LLMProvider.HUGGINGFACE]: {
    supportsStreaming: true,
    supportsFunctionCalling: false,
    supportsVision: true, // Depends on model
    supportsSystemMessages: true,
    supportsMultiModal: true, // Depends on model
    requiresApiKey: true,
    isLocal: false
  }
};

/**
 * Rate limit configurations per provider
 */
export interface RateLimitConfig {
  requestsPerMinute: number;
  tokensPerMinute: number;
  requestsPerDay?: number;
  concurrentRequests: number;
}

/**
 * Default rate limits for providers
 */
export const DEFAULT_RATE_LIMITS: Record<LLMProvider, RateLimitConfig> = {
  [LLMProvider.ANTHROPIC]: {
    requestsPerMinute: 50,
    tokensPerMinute: 100000,
    concurrentRequests: 5
  },
  [LLMProvider.OPENAI]: {
    requestsPerMinute: 60,
    tokensPerMinute: 150000,
    requestsPerDay: 10000,
    concurrentRequests: 10
  },
  [LLMProvider.GOOGLE]: {
    requestsPerMinute: 60,
    tokensPerMinute: 100000,
    concurrentRequests: 5
  },
  [LLMProvider.OLLAMA]: {
    requestsPerMinute: 1000, // Local, no real limit
    tokensPerMinute: 1000000,
    concurrentRequests: 3 // Limited by local resources
  },
  [LLMProvider.COHERE]: {
    requestsPerMinute: 100,
    tokensPerMinute: 100000,
    concurrentRequests: 5
  },
  [LLMProvider.HUGGINGFACE]: {
    requestsPerMinute: 30,
    tokensPerMinute: 50000,
    concurrentRequests: 3
  }
};

/**
 * Create provider configuration from environment
 */
export function createProviderConfigFromEnv(provider: LLMProvider): ProviderConfig {
  const envVar = API_KEY_ENV_VARS[provider];
  const apiKey = process.env[envVar];
  
  const config: ProviderConfig = {
    ...DEFAULT_PROVIDER_CONFIGS[provider]
  };

  if (provider === LLMProvider.OLLAMA) {
    // Special handling for Ollama
    if (apiKey) {
      config.baseUrl = apiKey; // OLLAMA_HOST contains the base URL
    } else {
      config.baseUrl = DEFAULT_BASE_URLS[provider];
    }
  } else {
    config.apiKey = apiKey;
    if (DEFAULT_BASE_URLS[provider]) {
      config.baseUrl = process.env[`${provider.toUpperCase()}_BASE_URL`] || DEFAULT_BASE_URLS[provider];
    }
  }

  // Check for proxy configuration
  if (process.env.HTTP_PROXY || process.env.HTTPS_PROXY) {
    const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
    if (proxyUrl) {
      const url = new URL(proxyUrl);
      config.proxy = {
        host: url.hostname,
        port: parseInt(url.port) || 80
      };
      
      if (url.username && url.password) {
        config.proxy.auth = {
          username: url.username,
          password: url.password
        };
      }
    }
  }

  return config;
}

/**
 * Create default provider manager configuration
 */
export function createDefaultManagerConfig(): {
  providers: Record<LLMProvider, ProviderConfig>;
  fallbackStrategy: FallbackStrategy;
  healthCheckInterval: number;
  metricsEnabled: boolean;
} {
  const providers: Partial<Record<LLMProvider, ProviderConfig>> = {};

  // Auto-configure providers based on environment variables
  for (const provider of Object.values(LLMProvider)) {
    const config = createProviderConfigFromEnv(provider);
    
    // Only include providers that have API keys (or don't need them)
    if (config.apiKey || !PROVIDER_FEATURES[provider].requiresApiKey) {
      providers[provider] = config;
    }
  }

  return {
    providers: providers as Record<LLMProvider, ProviderConfig>,
    fallbackStrategy: FallbackStrategy.SEQUENTIAL,
    healthCheckInterval: 60000, // 1 minute
    metricsEnabled: true
  };
}

/**
 * Validate provider configuration
 */
export function validateProviderConfig(provider: LLMProvider, config: ProviderConfig): string[] {
  const errors: string[] = [];
  const features = PROVIDER_FEATURES[provider];

  if (features.requiresApiKey && !config.apiKey) {
    errors.push(`API key is required for ${provider}`);
  }

  if (config.timeout && config.timeout < 1000) {
    errors.push('Timeout must be at least 1000ms');
  }

  if (config.maxRetries && config.maxRetries < 0) {
    errors.push('Max retries must be non-negative');
  }

  if (config.retryDelay && config.retryDelay < 0) {
    errors.push('Retry delay must be non-negative');
  }

  return errors;
}

/**
 * Merge provider configurations
 */
export function mergeProviderConfig(
  base: ProviderConfig,
  override: Partial<ProviderConfig>
): ProviderConfig {
  const merged = { ...base, ...override };

  // Merge headers
  if (base.headers || override.headers) {
    merged.headers = {
      ...base.headers,
      ...override.headers
    };
  }

  // Merge proxy
  if (base.proxy || override.proxy) {
    merged.proxy = {
      ...base.proxy,
      ...override.proxy
    } as any;
    
    if (base.proxy?.auth || override.proxy?.auth) {
      merged.proxy!.auth = {
        ...base.proxy?.auth,
        ...override.proxy?.auth
      } as any;
    }
  }

  return merged;
}

/**
 * Cost optimization presets
 */
export interface CostPreset {
  name: string;
  description: string;
  preferredProviders: LLMProvider[];
  maxCostPer1kTokens: number;
  fallbackStrategy: FallbackStrategy;
}

export const COST_PRESETS: CostPreset[] = [
  {
    name: 'ultra-low-cost',
    description: 'Minimize costs using local models when possible',
    preferredProviders: [LLMProvider.OLLAMA, LLMProvider.GOOGLE, LLMProvider.OPENAI],
    maxCostPer1kTokens: 0.002,
    fallbackStrategy: FallbackStrategy.COST_OPTIMIZE
  },
  {
    name: 'balanced',
    description: 'Balance between cost and performance',
    preferredProviders: [LLMProvider.OPENAI, LLMProvider.ANTHROPIC, LLMProvider.GOOGLE],
    maxCostPer1kTokens: 0.02,
    fallbackStrategy: FallbackStrategy.LOAD_BALANCE
  },
  {
    name: 'high-performance',
    description: 'Prioritize performance and capabilities',
    preferredProviders: [LLMProvider.ANTHROPIC, LLMProvider.OPENAI],
    maxCostPer1kTokens: 0.1,
    fallbackStrategy: FallbackStrategy.LATENCY_OPTIMIZE
  }
];