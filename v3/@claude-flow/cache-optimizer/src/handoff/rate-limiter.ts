/**
 * @claude-flow/cache-optimizer - Rate Limiter
 *
 * Token bucket rate limiter with sliding window for API providers.
 * Prevents exceeding provider rate limits.
 */

import { EventEmitter } from 'events';

export interface RateLimiterConfig {
  /** Maximum requests per window */
  maxRequests: number;
  /** Time window in ms */
  windowMs: number;
  /** Maximum tokens per minute (for LLM APIs) */
  maxTokensPerMinute?: number;
  /** Delay between requests in ms (for spacing) */
  minRequestSpacing?: number;
}

export interface RateLimitStatus {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
  tokensRemaining?: number;
}

const DEFAULT_CONFIGS: Record<string, RateLimiterConfig> = {
  ollama: {
    maxRequests: 100,
    windowMs: 60000,
    minRequestSpacing: 0,
  },
  anthropic: {
    maxRequests: 60,
    windowMs: 60000,
    maxTokensPerMinute: 100000,
    minRequestSpacing: 100,
  },
  openai: {
    maxRequests: 60,
    windowMs: 60000,
    maxTokensPerMinute: 90000,
    minRequestSpacing: 100,
  },
  openrouter: {
    maxRequests: 50,
    windowMs: 60000,
    maxTokensPerMinute: 100000,
    minRequestSpacing: 200,
  },
};

/**
 * RateLimiter - Token bucket with sliding window
 */
export class RateLimiter extends EventEmitter {
  private config: RateLimiterConfig;
  private requests: number[] = [];
  private tokens: number = 0;
  private lastRequest: number = 0;

  constructor(
    public readonly name: string,
    config?: Partial<RateLimiterConfig>
  ) {
    super();
    const defaultConfig = DEFAULT_CONFIGS[name] || DEFAULT_CONFIGS.ollama;
    this.config = { ...defaultConfig, ...config };
  }

  /**
   * Check if request is allowed and consume a slot
   */
  acquire(): RateLimitStatus {
    this.cleanup();
    const now = Date.now();

    // Check minimum spacing
    if (this.config.minRequestSpacing) {
      const timeSinceLastRequest = now - this.lastRequest;
      if (timeSinceLastRequest < this.config.minRequestSpacing) {
        const retryAfter = this.config.minRequestSpacing - timeSinceLastRequest;
        return {
          allowed: false,
          remaining: Math.max(0, this.config.maxRequests - this.requests.length),
          resetAt: this.getResetTime(),
          retryAfter,
          tokensRemaining: this.config.maxTokensPerMinute ? this.config.maxTokensPerMinute - this.tokens : undefined,
        };
      }
    }

    // Check request count
    if (this.requests.length >= this.config.maxRequests) {
      const oldestRequest = this.requests[0];
      const retryAfter = oldestRequest + this.config.windowMs - now;

      this.emit('limited', { retryAfter, remaining: 0 });

      return {
        allowed: false,
        remaining: 0,
        resetAt: oldestRequest + this.config.windowMs,
        retryAfter,
        tokensRemaining: this.config.maxTokensPerMinute ? this.config.maxTokensPerMinute - this.tokens : undefined,
      };
    }

    // Allow request
    this.requests.push(now);
    this.lastRequest = now;

    return {
      allowed: true,
      remaining: this.config.maxRequests - this.requests.length,
      resetAt: this.getResetTime(),
      tokensRemaining: this.config.maxTokensPerMinute ? this.config.maxTokensPerMinute - this.tokens : undefined,
    };
  }

  /**
   * Record token usage
   */
  recordTokens(count: number): boolean {
    if (!this.config.maxTokensPerMinute) return true;

    // Update lastRequest to prevent cleanup from resetting tokens
    if (this.lastRequest === 0) {
      this.lastRequest = Date.now();
    }

    this.cleanup();

    if (this.tokens + count > this.config.maxTokensPerMinute) {
      this.emit('tokenLimited', { tokens: this.tokens, requested: count });
      return false;
    }

    this.tokens += count;
    this.lastRequest = Date.now();
    return true;
  }

  /**
   * Check status without consuming a slot
   */
  check(): RateLimitStatus {
    this.cleanup();

    return {
      allowed: this.requests.length < this.config.maxRequests,
      remaining: Math.max(0, this.config.maxRequests - this.requests.length),
      resetAt: this.getResetTime(),
      tokensRemaining: this.config.maxTokensPerMinute ? this.config.maxTokensPerMinute - this.tokens : undefined,
    };
  }

  /**
   * Wait until a slot is available
   */
  async waitForSlot(timeout: number = 60000): Promise<boolean> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const status = this.check();
      if (status.allowed) {
        return true;
      }

      const waitTime = Math.min(
        status.retryAfter || 1000,
        timeout - (Date.now() - startTime)
      );

      if (waitTime <= 0) break;

      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    return false;
  }

  /**
   * Get next reset time
   */
  private getResetTime(): number {
    if (this.requests.length === 0) {
      return Date.now() + this.config.windowMs;
    }
    return this.requests[0] + this.config.windowMs;
  }

  /**
   * Remove expired entries
   */
  private cleanup(): void {
    const cutoff = Date.now() - this.config.windowMs;
    this.requests = this.requests.filter(t => t > cutoff);

    // Reset tokens at minute boundary
    const oneMinuteAgo = Date.now() - 60000;
    if (this.lastRequest < oneMinuteAgo) {
      this.tokens = 0;
    }
  }

  /**
   * Get current stats
   */
  getStats(): {
    requests: number;
    remaining: number;
    tokens: number;
    tokensRemaining?: number;
  } {
    this.cleanup();

    return {
      requests: this.requests.length,
      remaining: Math.max(0, this.config.maxRequests - this.requests.length),
      tokens: this.tokens,
      tokensRemaining: this.config.maxTokensPerMinute ? this.config.maxTokensPerMinute - this.tokens : undefined,
    };
  }

  /**
   * Reset limiter
   */
  reset(): void {
    this.requests = [];
    this.tokens = 0;
    this.lastRequest = 0;
  }
}

/**
 * RateLimiterRegistry - Manages rate limiters for multiple providers
 */
export class RateLimiterRegistry {
  private limiters: Map<string, RateLimiter> = new Map();

  /**
   * Get or create a rate limiter
   */
  get(name: string, config?: Partial<RateLimiterConfig>): RateLimiter {
    let limiter = this.limiters.get(name);
    if (!limiter) {
      limiter = new RateLimiter(name, config);
      this.limiters.set(name, limiter);
    }
    return limiter;
  }

  /**
   * Check if provider can accept request
   */
  canRequest(name: string): boolean {
    const limiter = this.limiters.get(name);
    return limiter ? limiter.check().allowed : true;
  }

  /**
   * Acquire slot for provider
   */
  acquire(name: string): RateLimitStatus {
    const limiter = this.get(name);
    return limiter.acquire();
  }

  /**
   * Record token usage for provider
   */
  recordTokens(name: string, count: number): boolean {
    const limiter = this.get(name);
    return limiter.recordTokens(count);
  }

  /**
   * Get all stats
   */
  getAllStats(): Record<string, ReturnType<RateLimiter['getStats']>> {
    const stats: Record<string, ReturnType<RateLimiter['getStats']>> = {};
    for (const [name, limiter] of this.limiters) {
      stats[name] = limiter.getStats();
    }
    return stats;
  }

  /**
   * Reset all limiters
   */
  resetAll(): void {
    for (const limiter of this.limiters.values()) {
      limiter.reset();
    }
  }

  /**
   * Cleanup
   */
  destroy(): void {
    for (const limiter of this.limiters.values()) {
      limiter.removeAllListeners();
    }
    this.limiters.clear();
  }
}

export const defaultRateLimiterRegistry = new RateLimiterRegistry();
