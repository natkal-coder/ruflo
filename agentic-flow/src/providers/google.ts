/**
 * Google Gemini Provider
 * Implements support for Gemini models with streaming
 */

import { GoogleGenerativeAI, GenerativeModel, Part, Content } from '@google/generative-ai';
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
  ProviderError
} from './types';
import { BaseLLMProvider } from './base';

export class GoogleProvider extends BaseLLMProvider {
  readonly provider = LLMProvider.GOOGLE;
  
  readonly models: ModelInfo[] = [
    {
      id: 'gemini-pro',
      name: 'Gemini Pro',
      provider: LLMProvider.GOOGLE,
      capabilities: {
        streaming: true,
        functionCalling: true,
        vision: false,
        maxTokens: 8192,
        contextWindow: 32768,
        costPer1kTokens: {
          input: 0.0005,
          output: 0.0015
        }
      },
      description: 'Best performing model for text-based tasks'
    },
    {
      id: 'gemini-pro-vision',
      name: 'Gemini Pro Vision',
      provider: LLMProvider.GOOGLE,
      capabilities: {
        streaming: true,
        functionCalling: false,
        vision: true,
        maxTokens: 4096,
        contextWindow: 16384,
        costPer1kTokens: {
          input: 0.0005,
          output: 0.0015
        }
      },
      description: 'Multimodal model for text and image understanding'
    },
    {
      id: 'gemini-ultra',
      name: 'Gemini Ultra',
      provider: LLMProvider.GOOGLE,
      capabilities: {
        streaming: true,
        functionCalling: true,
        vision: true,
        maxTokens: 8192,
        contextWindow: 32768,
        costPer1kTokens: {
          input: 0.001,
          output: 0.003
        }
      },
      description: 'Most capable Gemini model (preview access required)'
    }
  ];
  
  private client?: GoogleGenerativeAI;
  private modelCache: Map<string, GenerativeModel> = new Map();

  protected async doInitialize(): Promise<void> {
    if (!this.config.apiKey) {
      throw new ProviderError('API key is required for Google provider', this.provider);
    }

    this.client = new GoogleGenerativeAI(this.config.apiKey);
  }

  protected async doComplete(options: CompletionOptions): Promise<CompletionResponse> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      const model = this.getModel(options.model);
      const contents = this.convertMessagesToContents(options.messages);
      
      // Configure generation
      const generationConfig = {
        temperature: options.temperature,
        topP: options.topP,
        topK: options.topK,
        maxOutputTokens: options.maxTokens,
        stopSequences: options.stopSequences
      };

      // Generate content
      const result = await model.generateContent({
        contents,
        generationConfig
      });

      const response = await result.response;
      return this.convertResponse(response, options);
    } catch (error: any) {
      throw this.handleGoogleError(error);
    }
  }

  protected async *doStream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      const model = this.getModel(options.model);
      const contents = this.convertMessagesToContents(options.messages);
      
      // Configure generation
      const generationConfig = {
        temperature: options.temperature,
        topP: options.topP,
        topK: options.topK,
        maxOutputTokens: options.maxTokens,
        stopSequences: options.stopSequences
      };

      // Stream content
      const result = await model.generateContentStream({
        contents,
        generationConfig
      });

      let chunkIndex = 0;
      for await (const chunk of result.stream) {
        const text = chunk.text();
        if (text) {
          yield {
            id: 'stream-' + Date.now() + '-' + chunkIndex++,
            model: options.model,
            choices: [{
              index: 0,
              delta: {
                content: text
              }
            }],
            created: Date.now(),
            provider: this.provider
          };
        }
      }

      // Final chunk to indicate completion
      yield {
        id: 'stream-' + Date.now() + '-final',
        model: options.model,
        choices: [{
          index: 0,
          delta: {},
          finishReason: 'stop'
        }],
        created: Date.now(),
        provider: this.provider
      };
    } catch (error: any) {
      throw this.handleGoogleError(error);
    }
  }

  protected async doHealthCheck(): Promise<void> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      const model = this.getModel('gemini-pro');
      await model.generateContent('Hello');
    } catch (error: any) {
      throw this.handleGoogleError(error);
    }
  }

  /**
   * Get or create a model instance
   */
  private getModel(modelId: string): GenerativeModel {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    let model = this.modelCache.get(modelId);
    if (!model) {
      model = this.client.getGenerativeModel({ model: modelId });
      this.modelCache.set(modelId, model);
    }
    return model;
  }

  /**
   * Convert messages to Google Gemini format
   */
  private convertMessagesToContents(messages: Message[]): Content[] {
    const contents: Content[] = [];
    
    // Group consecutive messages by role
    let currentRole: string | null = null;
    let currentParts: Part[] = [];

    for (const message of messages) {
      const role = this.mapRole(message.role);
      const parts = this.convertMessageContent(message.content);

      if (currentRole !== role && currentParts.length > 0) {
        contents.push({
          role: currentRole!,
          parts: currentParts
        });
        currentParts = [];
      }

      currentRole = role;
      currentParts.push(...parts);
    }

    if (currentParts.length > 0 && currentRole) {
      contents.push({
        role: currentRole,
        parts: currentParts
      });
    }

    return contents;
  }

  /**
   * Map standard roles to Gemini roles
   */
  private mapRole(role: string): string {
    switch (role) {
      case 'system':
      case 'user':
        return 'user';
      case 'assistant':
        return 'model';
      default:
        return 'user';
    }
  }

  /**
   * Convert message content to Gemini parts
   */
  private convertMessageContent(content: MessageContent): Part[] {
    if (typeof content === 'string') {
      return [{ text: content }];
    }

    if (Array.isArray(content)) {
      return content.flatMap(item => this.convertContentItem(item));
    }

    return this.convertContentItem(content);
  }

  /**
   * Convert single content item to parts
   */
  private convertContentItem(item: TextContent | ImageContent): Part[] {
    if (item.type === 'text') {
      return [{ text: item.text }];
    } else {
      // For images, we need to convert to inline data
      const base64Data = item.image.url.includes('base64,')
        ? item.image.url.split('base64,')[1]
        : item.image.url;

      return [{
        inlineData: {
          mimeType: 'image/jpeg', // TODO: Detect from URL
          data: base64Data
        }
      }];
    }
  }

  /**
   * Convert Gemini response to standard format
   */
  private convertResponse(response: any, options: CompletionOptions): CompletionResponse {
    const text = response.text();
    const usage = response.usageMetadata || {};

    return {
      id: 'gemini-' + Date.now(),
      model: options.model,
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: text || ''
        },
        finishReason: response.finishReason || 'stop'
      }],
      usage: {
        promptTokens: usage.promptTokenCount || 0,
        completionTokens: usage.candidatesTokenCount || 0,
        totalTokens: usage.totalTokenCount || 0,
        estimatedCost: this.calculateCost(
          usage.promptTokenCount || 0,
          usage.candidatesTokenCount || 0,
          options.model
        )
      },
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
   * Handle Google-specific errors
   */
  private handleGoogleError(error: any): Error {
    // Map Google errors to our error types
    if (error.status === 403 || error.message?.includes('API key')) {
      return this.wrapError({
        message: 'Invalid API key or insufficient permissions',
        status: 403,
        code: 'PERMISSION_DENIED'
      });
    }

    if (error.status === 429 || error.message?.includes('quota')) {
      return this.wrapError({
        message: 'Rate limit or quota exceeded',
        status: 429,
        code: 'RESOURCE_EXHAUSTED'
      });
    }

    return this.wrapError(error);
  }

  /**
   * Estimate tokens for Gemini models
   */
  async estimateTokens(text: string): Promise<number> {
    // Gemini uses a similar tokenization to other models
    // Rough estimate: 1 token ≈ 4 characters
    return Math.ceil(text.length / 4);
  }

  /**
   * Clean up resources
   */
  async cleanup(): Promise<void> {
    this.modelCache.clear();
    await super.cleanup();
  }
}