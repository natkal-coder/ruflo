/**
 * @claude-flow/cache-optimizer - Webhook Handler
 *
 * Webhook callbacks for handoff completion notifications.
 * Supports HTTP POST callbacks with retry logic.
 */

import { EventEmitter } from 'events';
import type { HandoffResponse } from '../types.js';

export interface WebhookConfig {
  /** Webhook endpoint URL */
  url: string;
  /** HTTP method */
  method: 'POST' | 'PUT';
  /** Custom headers */
  headers?: Record<string, string>;
  /** Secret for HMAC signature */
  secret?: string;
  /** Timeout in ms */
  timeout: number;
  /** Retry configuration */
  retry: {
    maxRetries: number;
    baseDelay: number;
    maxDelay: number;
  };
  /** Events to trigger webhook */
  events: WebhookEvent[];
}

export type WebhookEvent =
  | 'handoff.completed'
  | 'handoff.failed'
  | 'handoff.timeout'
  | 'handoff.cancelled'
  | 'circuit.opened'
  | 'circuit.closed'
  | 'rate.limited';

export interface WebhookPayload {
  event: WebhookEvent;
  timestamp: number;
  data: {
    requestId?: string;
    provider?: string;
    response?: HandoffResponse;
    error?: string;
    metadata?: Record<string, unknown>;
  };
}

export interface WebhookResult {
  success: boolean;
  statusCode?: number;
  error?: string;
  attempts: number;
  durationMs: number;
}

const DEFAULT_CONFIG: WebhookConfig = {
  url: '',
  method: 'POST',
  timeout: 10000,
  retry: {
    maxRetries: 3,
    baseDelay: 1000,
    maxDelay: 10000,
  },
  events: ['handoff.completed', 'handoff.failed'],
};

/**
 * WebhookHandler - Manages webhook callbacks
 */
export class WebhookHandler extends EventEmitter {
  private webhooks: Map<string, WebhookConfig> = new Map();
  private pendingWebhooks: Map<string, { payload: WebhookPayload; attempts: number }> = new Map();

  constructor() {
    super();
  }

  /**
   * Register a webhook
   */
  register(id: string, config: Partial<WebhookConfig> & { url: string }): void {
    this.webhooks.set(id, { ...DEFAULT_CONFIG, ...config });
  }

  /**
   * Unregister a webhook
   */
  unregister(id: string): void {
    this.webhooks.delete(id);
  }

  /**
   * Get all registered webhooks
   */
  list(): Array<{ id: string; config: WebhookConfig }> {
    return Array.from(this.webhooks.entries()).map(([id, config]) => ({ id, config }));
  }

  /**
   * Trigger webhooks for an event
   */
  async trigger(event: WebhookEvent, data: WebhookPayload['data']): Promise<Map<string, WebhookResult>> {
    const results = new Map<string, WebhookResult>();
    const payload: WebhookPayload = {
      event,
      timestamp: Date.now(),
      data,
    };

    const promises: Promise<void>[] = [];

    for (const [id, config] of this.webhooks) {
      if (config.events.includes(event) && config.url) {
        promises.push(
          this.sendWebhook(id, config, payload).then(result => {
            results.set(id, result);
          })
        );
      }
    }

    await Promise.all(promises);
    return results;
  }

  /**
   * Send webhook with retry logic
   */
  private async sendWebhook(
    id: string,
    config: WebhookConfig,
    payload: WebhookPayload
  ): Promise<WebhookResult> {
    const startTime = Date.now();
    let lastError: string = '';

    for (let attempt = 0; attempt <= config.retry.maxRetries; attempt++) {
      try {
        const body = JSON.stringify(payload);
        const headers: Record<string, string> = {
          'Content-Type': 'application/json',
          'X-Webhook-Event': payload.event,
          'X-Webhook-Timestamp': String(payload.timestamp),
          ...config.headers,
        };

        // Add HMAC signature if secret is configured
        if (config.secret) {
          const signature = await this.generateSignature(body, config.secret);
          headers['X-Webhook-Signature'] = signature;
        }

        const response = await fetch(config.url, {
          method: config.method,
          headers,
          body,
          signal: AbortSignal.timeout(config.timeout),
        });

        if (response.ok) {
          this.emit('success', { id, event: payload.event, attempts: attempt + 1 });
          return {
            success: true,
            statusCode: response.status,
            attempts: attempt + 1,
            durationMs: Date.now() - startTime,
          };
        }

        lastError = `HTTP ${response.status}: ${response.statusText}`;

        // Don't retry on client errors (4xx)
        if (response.status >= 400 && response.status < 500) {
          break;
        }
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }

      // Wait before retry
      if (attempt < config.retry.maxRetries) {
        const delay = Math.min(
          config.retry.baseDelay * Math.pow(2, attempt),
          config.retry.maxDelay
        );
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    this.emit('failure', { id, event: payload.event, error: lastError });
    return {
      success: false,
      error: lastError,
      attempts: config.retry.maxRetries + 1,
      durationMs: Date.now() - startTime,
    };
  }

  /**
   * Generate HMAC-SHA256 signature
   */
  private async generateSignature(payload: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
    return 'sha256=' + Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Test a webhook
   */
  async test(id: string): Promise<WebhookResult> {
    const config = this.webhooks.get(id);
    if (!config) {
      return {
        success: false,
        error: 'Webhook not found',
        attempts: 0,
        durationMs: 0,
      };
    }

    const testPayload: WebhookPayload = {
      event: 'handoff.completed',
      timestamp: Date.now(),
      data: {
        requestId: 'test-' + Date.now(),
        metadata: { test: true },
      },
    };

    return this.sendWebhook(id, config, testPayload);
  }

  /**
   * Get pending webhooks count
   */
  getPendingCount(): number {
    return this.pendingWebhooks.size;
  }

  /**
   * Clear all webhooks
   */
  clear(): void {
    this.webhooks.clear();
    this.pendingWebhooks.clear();
  }
}

/**
 * Create webhook handler
 */
export function createWebhookHandler(): WebhookHandler {
  return new WebhookHandler();
}

// Global instance
export const defaultWebhookHandler = new WebhookHandler();
