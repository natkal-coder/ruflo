/**
 * Provider Utility Functions
 * Common utilities for LLM provider operations
 */

import {
  Message,
  MessageContent,
  TextContent,
  ImageContent,
  TokenUsage,
  ModelInfo,
  LLMProvider,
  CompletionOptions
} from './types';

/**
 * Extract text content from message content
 */
export function extractTextFromContent(content: MessageContent): string {
  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    return content
      .filter((item): item is TextContent => item.type === 'text')
      .map(item => item.text)
      .join('\n');
  }

  if (content.type === 'text') {
    return content.text;
  }

  return '';
}

/**
 * Extract images from message content
 */
export function extractImagesFromContent(content: MessageContent): ImageContent[] {
  const images: ImageContent[] = [];

  if (typeof content === 'string') {
    return images;
  }

  if (Array.isArray(content)) {
    for (const item of content) {
      if (item.type === 'image') {
        images.push(item);
      }
    }
  } else if (content.type === 'image') {
    images.push(content);
  }

  return images;
}

/**
 * Check if message content contains images
 */
export function hasImages(content: MessageContent): boolean {
  if (typeof content === 'string') {
    return false;
  }

  if (Array.isArray(content)) {
    return content.some(item => item.type === 'image');
  }

  return content.type === 'image';
}

/**
 * Convert base64 image to data URL
 */
export function base64ToDataUrl(base64: string, mimeType: string = 'image/jpeg'): string {
  if (base64.startsWith('data:')) {
    return base64;
  }
  return `data:${mimeType};base64,${base64}`;
}

/**
 * Extract base64 data from data URL
 */
export function extractBase64FromDataUrl(dataUrl: string): { data: string; mimeType: string } | null {
  const match = dataUrl.match(/^data:([^;]+);base64,(.+)$/);
  if (!match) {
    return null;
  }
  return {
    mimeType: match[1],
    data: match[2]
  };
}

/**
 * Estimate token count for text (rough approximation)
 */
export function estimateTokenCount(text: string, model?: string): number {
  // Different models have different tokenization
  let charsPerToken = 4; // Default

  if (model) {
    if (model.includes('claude')) {
      charsPerToken = 3.5;
    } else if (model.includes('gpt-4')) {
      charsPerToken = 3.8;
    } else if (model.includes('gpt-3.5')) {
      charsPerToken = 4;
    } else if (model.includes('gemini')) {
      charsPerToken = 4;
    }
  }

  return Math.ceil(text.length / charsPerToken);
}

/**
 * Calculate total message tokens
 */
export function calculateMessageTokens(messages: Message[], model?: string): number {
  let totalTokens = 0;

  for (const message of messages) {
    // Role tokens (approximate)
    totalTokens += 4;

    // Content tokens
    const text = extractTextFromContent(message.content);
    totalTokens += estimateTokenCount(text, model);

    // Image tokens (approximate)
    const images = extractImagesFromContent(message.content);
    totalTokens += images.length * 85; // Rough estimate for image tokens

    // Function call tokens
    if (message.functionCall) {
      totalTokens += estimateTokenCount(message.functionCall.name + message.functionCall.arguments, model);
    }
  }

  return totalTokens;
}

/**
 * Truncate messages to fit within token limit
 */
export function truncateMessages(
  messages: Message[],
  maxTokens: number,
  model?: string,
  keepSystemMessage: boolean = true
): Message[] {
  const truncated: Message[] = [];
  let currentTokens = 0;

  // Always keep system message if present and requested
  if (keepSystemMessage) {
    const systemMessage = messages.find(m => m.role === 'system');
    if (systemMessage) {
      truncated.push(systemMessage);
      currentTokens += calculateMessageTokens([systemMessage], model);
    }
  }

  // Add messages from the end (most recent first)
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    
    // Skip if already added (system message)
    if (truncated.some(m => m === message)) {
      continue;
    }

    const messageTokens = calculateMessageTokens([message], model);
    
    if (currentTokens + messageTokens <= maxTokens) {
      truncated.unshift(message);
      currentTokens += messageTokens;
    } else {
      break;
    }
  }

  return truncated;
}

/**
 * Format cost in dollars
 */
export function formatCost(cost: number): string {
  if (cost < 0.01) {
    return `$${cost.toFixed(4)}`;
  } else if (cost < 1) {
    return `$${cost.toFixed(3)}`;
  } else {
    return `$${cost.toFixed(2)}`;
  }
}

/**
 * Calculate estimated cost for a request
 */
export function estimateRequestCost(
  model: ModelInfo,
  promptTokens: number,
  completionTokens: number
): number {
  if (!model.capabilities.costPer1kTokens) {
    return 0;
  }

  const inputCost = (promptTokens / 1000) * model.capabilities.costPer1kTokens.input;
  const outputCost = (completionTokens / 1000) * model.capabilities.costPer1kTokens.output;

  return inputCost + outputCost;
}

/**
 * Format token usage for display
 */
export function formatTokenUsage(usage: TokenUsage): string {
  const parts = [
    `Prompt: ${usage.promptTokens}`,
    `Completion: ${usage.completionTokens}`,
    `Total: ${usage.totalTokens}`
  ];

  if (usage.estimatedCost !== undefined) {
    parts.push(`Cost: ${formatCost(usage.estimatedCost)}`);
  }

  return parts.join(' | ');
}

/**
 * Merge multiple token usages
 */
export function mergeTokenUsage(usages: TokenUsage[]): TokenUsage {
  return usages.reduce((total, usage) => ({
    promptTokens: total.promptTokens + usage.promptTokens,
    completionTokens: total.completionTokens + usage.completionTokens,
    totalTokens: total.totalTokens + usage.totalTokens,
    estimatedCost: (total.estimatedCost || 0) + (usage.estimatedCost || 0)
  }), {
    promptTokens: 0,
    completionTokens: 0,
    totalTokens: 0,
    estimatedCost: 0
  });
}

/**
 * Validate completion options
 */
export function validateCompletionOptions(options: CompletionOptions): string[] {
  const errors: string[] = [];

  if (!options.model) {
    errors.push('Model is required');
  }

  if (!options.messages || options.messages.length === 0) {
    errors.push('At least one message is required');
  }

  if (options.temperature !== undefined) {
    if (options.temperature < 0 || options.temperature > 2) {
      errors.push('Temperature must be between 0 and 2');
    }
  }

  if (options.topP !== undefined) {
    if (options.topP < 0 || options.topP > 1) {
      errors.push('Top-p must be between 0 and 1');
    }
  }

  if (options.maxTokens !== undefined) {
    if (options.maxTokens < 1) {
      errors.push('Max tokens must be at least 1');
    }
  }

  return errors;
}

/**
 * Create a retry delay with exponential backoff
 */
export function calculateRetryDelay(
  attempt: number,
  baseDelay: number = 1000,
  maxDelay: number = 30000
): number {
  const delay = Math.min(baseDelay * Math.pow(2, attempt), maxDelay);
  // Add jitter to avoid thundering herd
  const jitter = delay * 0.1 * Math.random();
  return Math.floor(delay + jitter);
}

/**
 * Parse rate limit headers
 */
export function parseRateLimitHeaders(headers: Record<string, any>): {
  limit?: number;
  remaining?: number;
  reset?: Date;
  retryAfter?: number;
} {
  const result: any = {};

  // Common rate limit headers
  if (headers['x-ratelimit-limit']) {
    result.limit = parseInt(headers['x-ratelimit-limit']);
  }
  if (headers['x-ratelimit-remaining']) {
    result.remaining = parseInt(headers['x-ratelimit-remaining']);
  }
  if (headers['x-ratelimit-reset']) {
    result.reset = new Date(parseInt(headers['x-ratelimit-reset']) * 1000);
  }
  if (headers['retry-after']) {
    result.retryAfter = parseInt(headers['retry-after']) * 1000;
  }

  return result;
}

/**
 * Create a timeout promise
 */
export function timeout<T>(promise: Promise<T>, ms: number, message?: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(message || `Timeout after ${ms}ms`)), ms)
    )
  ]);
}

/**
 * Chunk array into smaller arrays
 */
export function chunk<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Rate limiter for API calls
 */
export class RateLimiter {
  private queue: Array<() => void> = [];
  private running = 0;

  constructor(
    private maxConcurrent: number,
    private minInterval: number = 0
  ) {}

  async acquire(): Promise<void> {
    if (this.running >= this.maxConcurrent) {
      await new Promise<void>(resolve => this.queue.push(resolve));
    }
    this.running++;
  }

  release(): void {
    this.running--;
    const next = this.queue.shift();
    if (next) {
      setTimeout(next, this.minInterval);
    }
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}