// Mock implementations for testing provider system

export class MockAnthropicClient {
  messages = {
    create: jest.fn().mockResolvedValue({
      id: 'msg_test',
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: 'Mock Anthropic response' }],
      model: 'claude-3-opus-20240229',
      stop_reason: 'end_turn',
      stop_sequence: null,
      usage: {
        input_tokens: 10,
        output_tokens: 20,
      },
    }),
    stream: jest.fn().mockImplementation(async function* () {
      yield {
        type: 'message_start',
        message: {
          id: 'msg_test',
          type: 'message',
          role: 'assistant',
          content: [],
          model: 'claude-3-opus-20240229',
          stop_reason: null,
          stop_sequence: null,
          usage: { input_tokens: 10, output_tokens: 0 },
        },
      };
      yield {
        type: 'content_block_delta',
        delta: { type: 'text_delta', text: 'Mock ' },
        usage: { output_tokens: 5 },
      };
      yield {
        type: 'content_block_delta',
        delta: { type: 'text_delta', text: 'Anthropic response' },
        usage: { output_tokens: 15 },
      };
      yield {
        type: 'message_delta',
        delta: { stop_reason: 'end_turn' },
        usage: { output_tokens: 20 },
      };
    }),
  };
}

export class MockOpenAIClient {
  chat = {
    completions: {
      create: jest.fn().mockResolvedValue({
        id: 'chatcmpl-test',
        object: 'chat.completion',
        created: Date.now(),
        model: 'gpt-4',
        choices: [{
          index: 0,
          message: {
            role: 'assistant',
            content: 'Mock OpenAI response',
          },
          finish_reason: 'stop',
        }],
        usage: {
          prompt_tokens: 10,
          completion_tokens: 20,
          total_tokens: 30,
        },
      }),
      stream: jest.fn().mockImplementation(async function* () {
        yield {
          id: 'chatcmpl-test',
          object: 'chat.completion.chunk',
          created: Date.now(),
          model: 'gpt-4',
          choices: [{
            index: 0,
            delta: { content: 'Mock ' },
            finish_reason: null,
          }],
        };
        yield {
          id: 'chatcmpl-test',
          object: 'chat.completion.chunk',
          created: Date.now(),
          model: 'gpt-4',
          choices: [{
            index: 0,
            delta: { content: 'OpenAI response' },
            finish_reason: null,
          }],
        };
        yield {
          id: 'chatcmpl-test',
          object: 'chat.completion.chunk',
          created: Date.now(),
          model: 'gpt-4',
          choices: [{
            index: 0,
            delta: {},
            finish_reason: 'stop',
          }],
          usage: {
            prompt_tokens: 10,
            completion_tokens: 20,
            total_tokens: 30,
          },
        };
      }),
    },
  };
}

export class MockGoogleClient {
  generateContent = jest.fn().mockResolvedValue({
    response: {
      text: () => 'Mock Google response',
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 20,
        totalTokenCount: 30,
      },
    },
  });

  generateContentStream = jest.fn().mockImplementation(async function* () {
    yield {
      text: () => 'Mock ',
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 5,
        totalTokenCount: 15,
      },
    };
    yield {
      text: () => 'Google response',
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 20,
        totalTokenCount: 30,
      },
    };
  });
}

export class MockCohereClient {
  chat = jest.fn().mockResolvedValue({
    text: 'Mock Cohere response',
    meta: {
      tokens: {
        input_tokens: 10,
        output_tokens: 20,
      },
    },
  });

  chatStream = jest.fn().mockImplementation(async function* () {
    yield {
      event_type: 'text-generation',
      text: 'Mock ',
    };
    yield {
      event_type: 'text-generation',
      text: 'Cohere response',
    };
    yield {
      event_type: 'stream-end',
      response: {
        meta: {
          tokens: {
            input_tokens: 10,
            output_tokens: 20,
          },
        },
      },
    };
  });
}

export class MockOllamaClient {
  chat = jest.fn().mockResolvedValue({
    message: {
      role: 'assistant',
      content: 'Mock Ollama response',
    },
    eval_count: 20,
    prompt_eval_count: 10,
  });

  streamingChat = jest.fn().mockImplementation(async function* () {
    yield {
      message: {
        role: 'assistant',
        content: 'Mock ',
      },
    };
    yield {
      message: {
        role: 'assistant',
        content: 'Ollama response',
      },
    };
    yield {
      done: true,
      eval_count: 20,
      prompt_eval_count: 10,
    };
  });
}

// Mock error scenarios
export const mockProviderErrors = {
  networkError: () => new Error('Network error: Unable to connect to API'),
  
  rateLimitError: () => {
    const error = new Error('Rate limit exceeded');
    (error as any).status = 429;
    (error as any).headers = { 'retry-after': '60' };
    return error;
  },
  
  authenticationError: () => {
    const error = new Error('Invalid API key');
    (error as any).status = 401;
    return error;
  },
  
  invalidRequestError: () => {
    const error = new Error('Invalid request parameters');
    (error as any).status = 400;
    return error;
  },
  
  serverError: () => {
    const error = new Error('Internal server error');
    (error as any).status = 500;
    return error;
  },
};

// Helper to create mock provider with error scenarios
export const createMockProviderWithErrors = (errorType: keyof typeof mockProviderErrors) => ({
  name: 'error-provider',
  initialize: jest.fn().mockRejectedValue(mockProviderErrors[errorType]()),
  generateResponse: jest.fn().mockRejectedValue(mockProviderErrors[errorType]()),
  streamResponse: jest.fn().mockRejectedValue(mockProviderErrors[errorType]()),
  validateConfig: jest.fn().mockReturnValue(false),
  getCapabilities: jest.fn().mockReturnValue({
    streaming: false,
    functions: false,
    vision: false,
  }),
});