/**
 * Ollama Provider
 * Implements support for local LLM models via Ollama
 */

import axios, { AxiosInstance } from 'axios';
import {
  LLMProvider,
  ModelInfo,
  CompletionOptions,
  CompletionResponse,
  StreamChunk,
  Message,
  ProviderError,
  ModelCapabilities
} from './types';
import { BaseLLMProvider } from './base';

interface OllamaModel {
  name: string;
  modified_at: string;
  size: number;
  digest: string;
  details?: {
    format: string;
    family: string;
    families: string[];
    parameter_size: string;
    quantization_level: string;
  };
}

interface OllamaGenerateRequest {
  model: string;
  prompt?: string;
  system?: string;
  template?: string;
  context?: number[];
  stream?: boolean;
  raw?: boolean;
  format?: 'json';
  options?: {
    temperature?: number;
    top_p?: number;
    top_k?: number;
    num_predict?: number;
    stop?: string[];
    seed?: number;
  };
}

interface OllamaChatRequest {
  model: string;
  messages: Array<{
    role: string;
    content: string;
    images?: string[];
  }>;
  stream?: boolean;
  format?: 'json';
  options?: OllamaGenerateRequest['options'];
}

interface OllamaResponse {
  model: string;
  created_at: string;
  message?: {
    role: string;
    content: string;
  };
  done: boolean;
  total_duration?: number;
  load_duration?: number;
  prompt_eval_count?: number;
  prompt_eval_duration?: number;
  eval_count?: number;
  eval_duration?: number;
}

export class OllamaProvider extends BaseLLMProvider {
  readonly provider = LLMProvider.OLLAMA;
  
  // Models will be populated dynamically from Ollama
  models: ModelInfo[] = [];
  
  private client?: AxiosInstance;
  private baseUrl: string = 'http://localhost:11434';

  protected async doInitialize(): Promise<void> {
    this.baseUrl = this.config.baseUrl || 'http://localhost:11434';
    
    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: this.config.timeout || 120000, // Longer timeout for local models
      headers: {
        'Content-Type': 'application/json',
        ...this.config.headers
      }
    });

    // Load available models
    await this.loadModels();
  }

  /**
   * Load available models from Ollama
   */
  private async loadModels(): Promise<void> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      const response = await this.client.get<{ models: OllamaModel[] }>('/api/tags');
      
      this.models = response.data.models.map(model => ({
        id: model.name,
        name: this.formatModelName(model.name),
        provider: this.provider,
        capabilities: this.inferCapabilities(model),
        description: this.generateDescription(model)
      }));
    } catch (error: any) {
      throw new ProviderError(
        'Failed to load Ollama models. Is Ollama running?',
        this.provider,
        'CONNECTION_ERROR',
        undefined,
        error
      );
    }
  }

  /**
   * Format model name for display
   */
  private formatModelName(modelId: string): string {
    const parts = modelId.split(':');
    const baseName = parts[0];
    const tag = parts[1] || 'latest';
    
    return `${baseName.charAt(0).toUpperCase() + baseName.slice(1)} (${tag})`;
  }

  /**
   * Infer model capabilities based on model info
   */
  private inferCapabilities(model: OllamaModel): ModelCapabilities {
    const name = model.name.toLowerCase();
    const hasVision = name.includes('vision') || name.includes('llava');
    
    // Extract parameter size for context estimation
    let contextWindow = 4096; // Default
    if (model.details?.parameter_size) {
      const size = model.details.parameter_size;
      if (size.includes('70b') || size.includes('65b')) {
        contextWindow = 8192;
      } else if (size.includes('34b') || size.includes('30b')) {
        contextWindow = 8192;
      } else if (size.includes('13b') || size.includes('7b')) {
        contextWindow = 4096;
      }
    }

    return {
      streaming: true,
      functionCalling: name.includes('mistral') || name.includes('llama'),
      vision: hasVision,
      maxTokens: 4096,
      contextWindow,
      // Local models have no cost
      costPer1kTokens: {
        input: 0,
        output: 0
      }
    };
  }

  /**
   * Generate model description
   */
  private generateDescription(model: OllamaModel): string {
    const size = model.details?.parameter_size || 'Unknown size';
    const quant = model.details?.quantization_level || 'Unknown quantization';
    const family = model.details?.family || 'Unknown family';
    
    return `${family} model (${size}, ${quant})`;
  }

  protected async doComplete(options: CompletionOptions): Promise<CompletionResponse> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      const startTime = Date.now();
      
      // Use chat endpoint for better compatibility
      const request: OllamaChatRequest = {
        model: options.model,
        messages: this.convertMessages(options.messages),
        stream: false,
        options: {
          temperature: options.temperature,
          top_p: options.topP,
          top_k: options.topK,
          num_predict: options.maxTokens,
          stop: options.stopSequences
        }
      };

      const response = await this.client.post<OllamaResponse>('/api/chat', request);
      const duration = Date.now() - startTime;

      return this.convertResponse(response.data, options, duration);
    } catch (error: any) {
      throw this.handleOllamaError(error);
    }
  }

  protected async *doStream(options: CompletionOptions): AsyncGenerator<StreamChunk, void, unknown> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      const request: OllamaChatRequest = {
        model: options.model,
        messages: this.convertMessages(options.messages),
        stream: true,
        options: {
          temperature: options.temperature,
          top_p: options.topP,
          top_k: options.topK,
          num_predict: options.maxTokens,
          stop: options.stopSequences
        }
      };

      const response = await this.client.post('/api/chat', request, {
        responseType: 'stream'
      });

      let buffer = '';
      for await (const chunk of response.data) {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.trim()) {
            try {
              const data = JSON.parse(line) as OllamaResponse;
              
              if (data.message?.content) {
                yield {
                  id: 'stream-' + Date.now(),
                  model: options.model,
                  choices: [{
                    index: 0,
                    delta: {
                      content: data.message.content
                    }
                  }],
                  created: Date.now(),
                  provider: this.provider
                };
              }

              if (data.done) {
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
            } catch (e) {
              // Skip invalid JSON lines
            }
          }
        }
      }
    } catch (error: any) {
      throw this.handleOllamaError(error);
    }
  }

  protected async doHealthCheck(): Promise<void> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      await this.client.get('/api/tags');
    } catch (error: any) {
      throw this.handleOllamaError(error);
    }
  }

  /**
   * Convert messages to Ollama format
   */
  private convertMessages(messages: Message[]): OllamaChatRequest['messages'] {
    return messages.map(msg => {
      const ollamaMsg: OllamaChatRequest['messages'][0] = {
        role: msg.role === 'assistant' ? 'assistant' : 'user',
        content: typeof msg.content === 'string' ? msg.content : this.extractTextContent(msg.content)
      };

      // Handle images if present
      if (typeof msg.content !== 'string') {
        const images = this.extractImages(msg.content);
        if (images.length > 0) {
          ollamaMsg.images = images;
        }
      }

      return ollamaMsg;
    });
  }

  /**
   * Extract text content from complex message content
   */
  private extractTextContent(content: any): string {
    if (Array.isArray(content)) {
      return content
        .filter(item => item.type === 'text')
        .map(item => item.text)
        .join('\n');
    }
    
    if (content.type === 'text') {
      return content.text;
    }
    
    return '';
  }

  /**
   * Extract image data from message content
   */
  private extractImages(content: any): string[] {
    const images: string[] = [];
    
    if (Array.isArray(content)) {
      for (const item of content) {
        if (item.type === 'image' && item.image?.url) {
          // Extract base64 data
          const base64Match = item.image.url.match(/^data:image\/[^;]+;base64,(.+)$/);
          if (base64Match) {
            images.push(base64Match[1]);
          }
        }
      }
    } else if (content.type === 'image' && content.image?.url) {
      const base64Match = content.image.url.match(/^data:image\/[^;]+;base64,(.+)$/);
      if (base64Match) {
        images.push(base64Match[1]);
      }
    }
    
    return images;
  }

  /**
   * Convert Ollama response to standard format
   */
  private convertResponse(response: OllamaResponse, options: CompletionOptions, duration: number): CompletionResponse {
    const promptTokens = response.prompt_eval_count || 0;
    const completionTokens = response.eval_count || 0;

    return {
      id: 'ollama-' + Date.now(),
      model: options.model,
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: response.message?.content || ''
        },
        finishReason: 'stop'
      }],
      usage: {
        promptTokens,
        completionTokens,
        totalTokens: promptTokens + completionTokens,
        estimatedCost: 0 // Local models are free
      },
      created: Date.now(),
      provider: this.provider,
      metadata: {
        totalDuration: response.total_duration,
        loadDuration: response.load_duration,
        promptEvalDuration: response.prompt_eval_duration,
        evalDuration: response.eval_duration,
        requestDuration: duration
      }
    };
  }

  /**
   * Handle Ollama-specific errors
   */
  private handleOllamaError(error: any): Error {
    if (error.code === 'ECONNREFUSED') {
      return new ProviderError(
        'Cannot connect to Ollama. Make sure Ollama is running.',
        this.provider,
        'CONNECTION_ERROR',
        undefined,
        error
      );
    }

    if (error.response?.status === 404) {
      return new ProviderError(
        'Model not found. Pull the model first with: ollama pull <model>',
        this.provider,
        'MODEL_NOT_FOUND',
        404,
        error
      );
    }

    return this.wrapError(error);
  }

  /**
   * Pull a model if not available
   */
  async pullModel(modelName: string): Promise<void> {
    if (!this.client) {
      throw new ProviderError('Client not initialized', this.provider);
    }

    try {
      await this.client.post('/api/pull', { name: modelName });
      // Reload models after pulling
      await this.loadModels();
    } catch (error: any) {
      throw this.handleOllamaError(error);
    }
  }

  /**
   * List available models (refresh)
   */
  async listModels(): Promise<ModelInfo[]> {
    await this.loadModels();
    return this.models;
  }

  /**
   * Validate config - Ollama doesn't need API key
   */
  protected validateConfig(): void {
    // Ollama doesn't require API key
  }
}