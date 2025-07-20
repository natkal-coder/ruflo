/**
 * Anthropic Claude Provider
 * Implements support for Claude models with streaming
 */

import Anthropic from '@anthropic-ai/sdk';
import {
  LLMProvider,
  ModelInfo,
  CompletionOptions,
  CompletionResponse,
  StreamChunk,
  Message,
  MessageContent,
  TextContent,
  ImageContent,
  ProviderError,
  ModelCapabilities
} from './types';
import { BaseLLMProvider } from './base';

export class AnthropicProvider extends BaseLLMProvider {
  readonly provider = LLMProvider.ANTHROPIC;
  
  readonly models: ModelInfo[] = [
    {
      id: 'claude-3-opus-20240229',
      name: 'Claude 3 Opus',
      provider: LLMProvider.ANTHROPIC,
      capabilities: {
        streaming: true,
        functionCalling: true,
        vision: true,
        maxTokens: 4096,
        contextWindow: 200000,
        costPer1kTokens: {
          input: 0.015,
          output: 0.075
        }
      },
      description: 'Most capable Claude model for complex tasks'
    },
    {
      id: 'claude-3-sonnet-20240229',
      name: 'Claude 3 Sonnet',
      provider: LLMProvider.ANTHROPIC,
      capabilities: {
        streaming: true,
        functionCalling: true,
        vision: true,
        maxTokens: 4096,
        contextWindow: 200000,
        costPer1kTokens: {
          input: 0.003,
          output: 0.015
        }
      },
      description: 'Balanced performance and cost'
    },
    {
      id: 'claude-3-haiku-20240307',
      name: 'Claude 3 Haiku',
      provider: LLMProvider.ANTHROPIC,
      capabilities: {
        streaming: true,
        functionCalling: true,
        vision: true,
        maxTokens: 4096,
        contextWindow: 200000,
        costPer1kTokens: {
          input: 0.00025,
          output: 0.00125
        }
      },
      description: 'Fastest and most affordable Claude model'
    },
    {
      id: 'claude-2.1',
      name: 'Claude 2.1',
      provider: LLMProvider.ANTHROPIC,
      capabilities: {
        streaming: true,
        functionCalling: false,
        vision: false,
        maxTokens: 4096,
        contextWindow: 100000,
        costPer1kTokens: {
          input: 0.008,
          output: 0.024
        }
      },
      description: 'Previous generation Claude model',
      deprecated: true
    }
  ];
  
  private client?: Anthropic;

  protected async doInitialize(): Promise<void> {
    this.client = new Anthropic({
      apiKey: this.config.apiKey!,
      baseURL: this.config.baseUrl,
      timeout: this.config.timeout || 60000,
      maxRetries: 0, // We handle retries ourselves
      defaultHeaders: this.config.headers
    });
  }

  protected async doComplete(options: CompletionOptions): Promise<CompletionResponse> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    const anthropicMessages = this.convertMessages(options.messages);
    const systemPrompt = this.extractSystemPrompt(options);

    try {
      const response = await this.client.messages.create({
        model: options.model,
        messages: anthropicMessages,
        system: systemPrompt,
        max_tokens: options.maxTokens || 4096,
        temperature: options.temperature,
        top_p: options.topP,
        top_k: options.topK,
        stop_sequences: options.stopSequences,
        metadata: options.metadata as any
      });

      return this.convertResponse(response, options);
    } catch (error: any) {
      throw this.handleAnthropicError(error);
    }
  }

  protected async *doStream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    const anthropicMessages = this.convertMessages(options.messages);
    const systemPrompt = this.extractSystemPrompt(options);

    try {
      const stream = await this.client.messages.create({
        model: options.model,
        messages: anthropicMessages,
        system: systemPrompt,
        max_tokens: options.maxTokens || 4096,
        temperature: options.temperature,
        top_p: options.topP,
        top_k: options.topK,
        stop_sequences: options.stopSequences,
        metadata: options.metadata as any,
        stream: true
      });

      for await (const chunk of stream) {
        if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text_delta') {
          yield {
            id: 'stream-' + Date.now(),
            model: options.model,
            choices: [{
              index: 0,
              delta: {
                content: chunk.delta.text
              }
            }],
            created: Date.now(),
            provider: this.provider
          };
        } else if (chunk.type === 'message_stop') {
          yield {
            id: 'stream-' + Date.now(),
            model: options.model,
            choices: [{
              index: 0,
              delta: {},
              finishReason: 'stop'
            }],
            created: Date.now(),
            provider: this.provider
          };
        }
      }
    } catch (error: any) {
      throw this.handleAnthropicError(error);
    }
  }

  protected async doHealthCheck(): Promise<void> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    // Simple health check - try to validate the cheapest model
    try {
      await this.client.messages.create({
        model: 'claude-3-haiku-20240307',
        messages: [{ role: 'user', content: 'Hi' }],
        max_tokens: 1
      });
    } catch (error: any) {
      throw this.handleAnthropicError(error);
    }
  }

  /**
   * Convert messages to Anthropic format
   */
  private convertMessages(messages: Message[]): Anthropic.MessageParam[] {
    return messages
      .filter(msg => msg.role !== 'system') // System messages handled separately
      .map(msg => ({
        role: msg.role === 'assistant' ? 'assistant' : 'user',
        content: this.convertMessageContent(msg.content)
      }));
  }

  /**
   * Convert message content to Anthropic format
   */
  private convertMessageContent(content: MessageContent): string | Anthropic.ContentBlock[] {
    if (typeof content === 'string') {
      return content;
    }

    if (Array.isArray(content)) {
      return content.map(item => this.convertContentItem(item));
    }

    return [this.convertContentItem(content)];
  }

  /**
   * Convert single content item
   */
  private convertContentItem(item: TextContent | ImageContent): Anthropic.ContentBlock {
    if (item.type === 'text') {
      return {
        type: 'text',
        text: item.text
      };
    } else {
      return {
        type: 'image',
        source: {
          type: 'base64',
          media_type: 'image/jpeg', // TODO: Detect from URL
          data: item.image.url.split(',')[1] || item.image.url
        }
      };
    }
  }

  /**
   * Extract system prompt from messages or options
   */
  private extractSystemPrompt(options: CompletionOptions): string | undefined {
    // Check explicit system prompt
    if (options.systemPrompt) {
      return options.systemPrompt;
    }

    // Extract from messages
    const systemMessage = options.messages.find(msg => msg.role === 'system');
    if (systemMessage && typeof systemMessage.content === 'string') {
      return systemMessage.content;
    }

    return undefined;
  }

  /**
   * Convert Anthropic response to standard format
   */
  private convertResponse(response: Anthropic.Message, options: CompletionOptions): CompletionResponse {
    const content = response.content
      .map(block => block.type === 'text' ? block.text : '')
      .join('');

    const usage = {
      promptTokens: response.usage.input_tokens,
      completionTokens: response.usage.output_tokens,
      totalTokens: response.usage.input_tokens + response.usage.output_tokens,
      estimatedCost: this.calculateCost(
        response.usage.input_tokens,
        response.usage.output_tokens,
        options.model
      )
    };

    return {
      id: response.id,
      model: response.model,
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content
        },
        finishReason: response.stop_reason as any
      }],
      usage,
      created: Date.now(),
      provider: this.provider
    };
  }

  /**
   * Calculate cost based on token usage
   */
  private calculateCost(inputTokens: number, outputTokens: number, model: string): number {
    const modelInfo = this.models.find(m => m.id === model);
    if (!modelInfo?.capabilities.costPer1kTokens) {
      return 0;
    }

    const inputCost = (inputTokens / 1000) * modelInfo.capabilities.costPer1kTokens.input;
    const outputCost = (outputTokens / 1000) * modelInfo.capabilities.costPer1kTokens.output;

    return inputCost + outputCost;
  }

  /**
   * Handle Anthropic-specific errors
   */
  private handleAnthropicError(error: any): Error {
    if (error instanceof Anthropic.APIError) {
      return this.wrapError({
        message: error.message,
        status: error.status,
        code: error.type,
        headers: error.headers
      });
    }
    
    return this.wrapError(error);
  }

  /**
   * Estimate tokens using Claude's tokenizer approximation
   */
  async estimateTokens(text: string): Promise<number> {
    // Claude uses a similar tokenizer to GPT models
    // Rough estimate: 1 token ≈ 3.5 characters for English text
    return Math.ceil(text.length / 3.5);
  }
}