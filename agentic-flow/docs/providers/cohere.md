# Cohere Provider Integration

Complete guide for integrating Cohere's language models with Agentic Flow.

## Overview

The Cohere provider enables access to:
- **Command**: Text generation and conversation
- **Command-R**: Retrieval-augmented generation
- **Command-R+**: Enhanced RAG with citations
- **Embed**: Multilingual embeddings
- **Rerank**: Document reranking
- **Classify**: Text classification

## Installation

```bash
# Agentic Flow includes Cohere provider by default
npm install agentic-flow

# Or install provider separately
npm install @agentic-flow/provider-cohere
```

## Configuration

### Basic Configuration

```yaml
# .agentic/config.yaml
providers:
  cohere:
    type: cohere
    apiKey: ${COHERE_API_KEY}
    defaultModel: command
    timeout: 30000
```

### Advanced Configuration

```yaml
providers:
  cohere:
    type: cohere
    apiKey: ${COHERE_API_KEY}
    
    # Model configurations
    models:
      command:
        maxTokens: 4000
        temperature: 0.7
        k: 0
        p: 0.75
        frequencyPenalty: 0
        presencePenalty: 0
        
      command-r:
        maxTokens: 4000
        temperature: 0.3
        searchQueriesOnly: false
        documents: []
        
      embed-english-v3.0:
        inputType: search_document
        truncate: END
    
    # Rate limiting
    rateLimits:
      requestsPerMinute: 100
      tokensPerMinute: 150000
```

### Environment Variables

```bash
# Required
export COHERE_API_KEY=your-api-key

# Optional
export COHERE_API_URL=https://api.cohere.ai
```

## Usage Examples

### Basic Text Generation

```javascript
import { Agent } from 'agentic-flow';

const agent = new Agent({
  name: 'cohere-assistant',
  provider: 'cohere',
  model: 'command',
  temperature: 0.7
});

// Simple generation
const result = await agent.execute({
  action: 'generate',
  input: 'Write a product description for eco-friendly water bottles'
});

// With parameters
const result = await agent.execute({
  action: 'generate',
  input: 'Explain machine learning',
  params: {
    maxTokens: 500,
    temperature: 0.3,
    k: 0,
    p: 0.75,
    stopSequences: ['\n\n']
  }
});
```

### RAG with Command-R

```javascript
const ragAgent = new Agent({
  provider: 'cohere',
  model: 'command-r',
  ragEnabled: true
});

// With documents
const result = await ragAgent.execute({
  action: 'generate',
  input: 'What are the key features of our product?',
  documents: [
    {
      title: 'Product Manual',
      text: 'Our product features include...'
    },
    {
      title: 'FAQ',
      text: 'Frequently asked questions about...'
    }
  ]
});

// With web search
const result = await ragAgent.execute({
  action: 'generate',
  input: 'Latest developments in renewable energy',
  params: {
    searchQueriesOnly: false,
    webSearch: true
  }
});
```

### Embeddings

```javascript
const embedder = new Agent({
  provider: 'cohere',
  model: 'embed-english-v3.0'
});

// Generate embeddings
const embeddings = await embedder.embed([
  'First document',
  'Second document',
  'Third document'
], {
  inputType: 'search_document',
  truncate: 'END'
});

// Search query embedding
const queryEmbedding = await embedder.embed(
  'search query',
  { inputType: 'search_query' }
);
```

### Document Reranking

```javascript
const reranker = new Agent({
  provider: 'cohere',
  model: 'rerank-english-v2.0'
});

const reranked = await reranker.rerank({
  query: 'best practices for machine learning',
  documents: [
    'Document about ML basics',
    'Advanced ML techniques',
    'ML best practices guide',
    'Introduction to deep learning'
  ],
  topN: 3
});

// Returns documents ordered by relevance
```

### Text Classification

```javascript
const classifier = new Agent({
  provider: 'cohere',
  model: 'classify'
});

// With examples
const result = await classifier.classify({
  inputs: ['This product is amazing!', 'Terrible experience'],
  examples: [
    { text: 'I love it', label: 'positive' },
    { text: 'Not worth it', label: 'negative' }
  ]
});

// Pre-trained classifiers
const sentiment = await classifier.classify({
  inputs: ['Great service!'],
  model: 'sentiment-analysis'
});
```

### Chat Conversations

```javascript
const chatAgent = new Agent({
  provider: 'cohere',
  model: 'command',
  chatMode: true
});

// Conversational interaction
const chat = chatAgent.createChat({
  preamble: 'You are a helpful shopping assistant'
});

const response1 = await chat.send('I need a new laptop');
const response2 = await chat.send('What about gaming laptops?');
const response3 = await chat.send('Under $1500?');
```

## Workflow Integration

### RAG Pipeline

```yaml
name: rag-pipeline
agents:
  embedder:
    provider: cohere
    model: embed-english-v3.0
    
  searcher:
    provider: cohere
    model: command-r
    ragEnabled: true
    
  reranker:
    provider: cohere
    model: rerank-english-v2.0
    
  generator:
    provider: cohere
    model: command
    temperature: 0.7

workflow:
  # Embed query
  - agent: embedder
    action: embed
    input: "{{ query }}"
    params:
      inputType: search_query
  
  # Search documents
  - agent: searcher
    action: search
    embedding: "{{ previous.output }}"
    topK: 20
  
  # Rerank results
  - agent: reranker
    action: rerank
    query: "{{ query }}"
    documents: "{{ previous.output }}"
    topN: 5
  
  # Generate response
  - agent: generator
    action: generate
    input: "{{ query }}"
    context: "{{ previous.output }}"
```

### Multi-Language Support

```yaml
name: multilingual-analysis
agents:
  detector:
    provider: cohere
    model: detect-language
    
  translator:
    provider: cohere
    model: command
    systemPrompt: "You are a translator"
    
  analyzer:
    provider: cohere
    model: command
    
  embedder:
    provider: cohere
    model: embed-multilingual-v3.0

workflow:
  # Detect language
  - agent: detector
    action: detect
    text: "{{ input }}"
  
  # Translate if needed
  - type: conditional
    if: "{{ previous.language != 'en' }}"
    then:
      - agent: translator
        action: translate
        text: "{{ input }}"
        targetLang: en
  
  # Analyze
  - agent: analyzer
    action: analyze
    text: "{{ translated_or_original }}"
  
  # Create multilingual embedding
  - agent: embedder
    action: embed
    text: "{{ input }}"
    language: "{{ detected_language }}"
```

## Best Practices

### 1. Model Selection

```javascript
// For general text generation
const generalAgent = new Agent({
  provider: 'cohere',
  model: 'command',
  temperature: 0.7
});

// For RAG applications
const ragAgent = new Agent({
  provider: 'cohere',
  model: 'command-r',
  temperature: 0.3,
  citationQuality: 'accurate'
});

// For embeddings
const embedAgent = new Agent({
  provider: 'cohere',
  model: 'embed-english-v3.0',
  dimensions: 1024  // Can reduce for efficiency
});
```

### 2. RAG Optimization

```javascript
// Optimize retrieval
const ragAgent = new Agent({
  provider: 'cohere',
  model: 'command-r',
  ragConfig: {
    chunkSize: 512,
    chunkOverlap: 128,
    retrievalStrategy: 'hybrid',
    rerankingEnabled: true,
    citationsEnabled: true
  }
});

// Process with citations
const result = await ragAgent.execute({
  action: 'generate',
  input: query,
  documents: documents,
  returnCitations: true
});

// Access citations
result.citations.forEach(citation => {
  console.log(`Source: ${citation.document_id}`);
  console.log(`Text: ${citation.text}`);
  console.log(`Confidence: ${citation.confidence}`);
});
```

### 3. Embedding Strategies

```javascript
// Document embeddings
const docEmbeddings = await embedder.embed(documents, {
  inputType: 'search_document',
  truncate: 'END'
});

// Query embeddings (different space)
const queryEmbedding = await embedder.embed(query, {
  inputType: 'search_query'
});

// Clustering embeddings
const clusteringEmbeddings = await embedder.embed(texts, {
  inputType: 'clustering'
});

// Classification embeddings
const classificationEmbeddings = await embedder.embed(texts, {
  inputType: 'classification'
});
```

### 4. Error Handling

```javascript
try {
  const result = await agent.execute(task);
} catch (error) {
  if (error.status === 429) {
    // Rate limit
    console.log('Rate limited, waiting...');
    await sleep(error.retryAfter * 1000);
    return agent.execute(task);
  } else if (error.status === 400) {
    // Invalid request
    console.error('Invalid request:', error.message);
    // Adjust parameters and retry
  } else if (error.status === 401) {
    // Authentication error
    console.error('Check your API key');
  }
  throw error;
}
```

## Performance Optimization

### 1. Batching

```javascript
// Batch embeddings
const batchEmbedder = new Agent({
  provider: 'cohere',
  model: 'embed-english-v3.0',
  batchSize: 96  // Max batch size
});

const embeddings = await batchEmbedder.batchEmbed(largeTextArray);

// Batch classification
const classifications = await classifier.batchClassify({
  inputs: texts,
  batchSize: 32
});
```

### 2. Caching

```yaml
providers:
  cohere:
    cache:
      enabled: true
      ttl: 3600
      strategy: embedding  # Cache embeddings
      similarity: 0.99    # Cache threshold
```

### 3. Token Optimization

```javascript
// Efficient token usage
const agent = new Agent({
  provider: 'cohere',
  model: 'command',
  tokenOptimization: {
    truncateInput: true,
    maxInputTokens: 2000,
    compressionRatio: 0.7
  }
});
```

## Advanced Features

### 1. Custom Connectors

```javascript
// Add custom data sources
const ragAgent = new Agent({
  provider: 'cohere',
  model: 'command-r',
  connectors: [
    {
      id: 'company-docs',
      type: 'database',
      config: {
        connection: process.env.DB_URL,
        table: 'documents'
      }
    },
    {
      id: 'web-search',
      type: 'web',
      config: {
        domains: ['example.com']
      }
    }
  ]
});
```

### 2. Fine-tuning Integration

```javascript
// Use fine-tuned model
const customAgent = new Agent({
  provider: 'cohere',
  model: 'ft-command-abc123',  // Your fine-tuned model ID
  baseModel: 'command'
});
```

### 3. Streaming with RAG

```javascript
// Stream RAG responses
const stream = ragAgent.stream({
  action: 'generate',
  input: query,
  documents: documents,
  streamCitations: true
});

for await (const event of stream) {
  if (event.type === 'text') {
    process.stdout.write(event.text);
  } else if (event.type === 'citation') {
    console.log('\nCitation:', event.citation);
  }
}
```

## Cost Management

### Token Usage

```javascript
// Monitor usage
agent.on('usage', (usage) => {
  console.log(`Input tokens: ${usage.inputTokens}`);
  console.log(`Output tokens: ${usage.outputTokens}`);
  console.log(`Search units: ${usage.searchUnits}`);
});

// Pricing calculator
const calculateCost = (usage) => {
  const rates = {
    command: { input: 0.0015, output: 0.002 },
    embed: { perToken: 0.0001 },
    rerank: { perSearch: 0.002 }
  };
  
  return calculateTotalCost(usage, rates);
};
```

### Optimization Strategies

```yaml
# Cost-efficient workflow
agents:
  screener:
    model: command  # Cheaper
    maxTokens: 100
    
  detailed:
    model: command-r  # More expensive
    condition: "{{ screener.score > 0.8 }}"
    
  embedder:
    model: embed-english-v3.0
    dimensions: 512  # Reduced dimensions for cost
```

## Security

### API Key Security

```javascript
// Secure configuration
const agent = new Agent({
  provider: 'cohere',
  apiKey: process.env.COHERE_API_KEY,
  security: {
    maskApiKey: true,
    logSensitive: false
  }
});
```

### Content Filtering

```javascript
// Input sanitization
const sanitize = (input) => {
  return input
    .replace(/<[^>]*>/g, '')  // Remove HTML
    .replace(/[^\w\s]/gi, '') // Remove special chars
    .trim();
};

agent.use({
  beforeExecute: (task) => {
    task.input = sanitize(task.input);
    return task;
  }
});
```

## Troubleshooting

### Debug Mode

```javascript
const agent = new Agent({
  provider: 'cohere',
  model: 'command',
  debug: true,
  logging: {
    requests: true,
    responses: true,
    timing: true
  }
});
```

### Common Issues

1. **Invalid API Key**
   ```bash
   # Test API key
   curl --request POST \
     --url https://api.cohere.ai/v1/generate \
     --header "Authorization: Bearer $COHERE_API_KEY" \
     --header "Content-Type: application/json" \
     --data '{"prompt": "Hello", "max_tokens": 10}'
   ```

2. **Model Not Found**
   ```javascript
   // List available models
   const models = await provider.listModels();
   console.log('Available models:', models);
   ```

3. **Truncation Issues**
   ```javascript
   // Handle truncation
   if (error.message.includes('truncated')) {
     const truncated = truncateText(input, 2000);
     return agent.execute({ ...task, input: truncated });
   }
   ```

## Migration from Cohere SDK

```javascript
// Old: Direct Cohere SDK
import cohere from 'cohere-ai';
cohere.init(apiKey);
const response = await cohere.generate({
  model: 'command',
  prompt: 'Hello world',
  max_tokens: 100
});

// New: Agentic Flow
import { Agent } from 'agentic-flow';
const agent = new Agent({
  provider: 'cohere',
  model: 'command',
  maxTokens: 100
});
const result = await agent.execute({
  action: 'generate',
  input: 'Hello world'
});
```

## Resources

- [Cohere API Documentation](https://docs.cohere.com)
- [Model Information](https://docs.cohere.com/docs/models)
- [Pricing](https://cohere.com/pricing)
- [LLM University](https://docs.cohere.com/docs/llmu)