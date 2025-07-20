export declare class MockAnthropicClient {
    messages: {
        create: jest.Mock<any, any, any>;
        stream: jest.Mock<any, any, any>;
    };
}
export declare class MockOpenAIClient {
    chat: {
        completions: {
            create: jest.Mock<any, any, any>;
            stream: jest.Mock<any, any, any>;
        };
    };
}
export declare class MockGoogleClient {
    generateContent: jest.Mock<any, any, any>;
    generateContentStream: jest.Mock<any, any, any>;
}
export declare class MockCohereClient {
    chat: jest.Mock<any, any, any>;
    chatStream: jest.Mock<any, any, any>;
}
export declare class MockOllamaClient {
    chat: jest.Mock<any, any, any>;
    streamingChat: jest.Mock<any, any, any>;
}
export declare const mockProviderErrors: {
    networkError: () => Error;
    rateLimitError: () => Error;
    authenticationError: () => Error;
    invalidRequestError: () => Error;
    serverError: () => Error;
};
export declare const createMockProviderWithErrors: (errorType: keyof typeof mockProviderErrors) => {
    name: string;
    initialize: jest.Mock<any, any, any>;
    generateResponse: jest.Mock<any, any, any>;
    streamResponse: jest.Mock<any, any, any>;
    validateConfig: jest.Mock<any, any, any>;
    getCapabilities: jest.Mock<any, any, any>;
};
//# sourceMappingURL=mock-providers.d.ts.map