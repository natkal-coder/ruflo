# OpenAI Provider Integration

Complete guide for integrating OpenAI models (GPT-4, GPT-3.5, DALL-E, Whisper) with Agentic Flow.

## Overview

The OpenAI provider enables access to:
- **Text Generation**: GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
- **Image Generation**: DALL-E 3, DALL-E 2
- **Audio**: Whisper (transcription), TTS (text-to-speech)
- **Embeddings**: text-embedding-3-large, text-embedding-3-small
- **Vision**: GPT-4 Vision

## Installation

```bash
# Agentic Flow includes OpenAI provider by default
npm install agentic-flow

# Or install provider separately
npm install @agentic-flow/provider-openai
```

## Configuration

### Basic Configuration

```yaml
# .agentic/config.yaml
providers:
  openai:
    type: openai
    apiKey: ${OPENAI_API_KEY}
    organization: org-xxxxx  # Optional
    defaultModel: gpt-4
    timeout: 30000
    maxRetries: 3
```

### Advanced Configuration

```yaml
providers:
  openai:
    type: openai
    apiKey: ${OPENAI_API_KEY}
    organization: ${OPENAI_ORG_ID}
    baseURL: https://api.openai.com/v1  # For proxies/custom endpoints
    
    # Model-specific settings
    models:
      gpt-4:
        maxTokens: 8192
        temperature: 0.7
        topP: 1
        frequencyPenalty: 0
        presencePenalty: 0
      
      gpt-3.5-turbo:
        maxTokens: 4096
        temperature: 0.9
    
    # Rate limiting
    rateLimits:
      requestsPerMinute: 60
      tokensPerMinute: 90000
    
    # Retry configuration
    retry:
      maxAttempts: 3
      initialDelay: 1000
      maxDelay: 10000
      exponentialBase: 2
```

### Environment Variables

```bash
# Required
export OPENAI_API_KEY=sk-proj-xxxxx

# Optional
export OPENAI_ORG_ID=org-xxxxx
export OPENAI_BASE_URL=https://api.openai.com/v1
```

## Usage Examples

### Basic Text Generation

```javascript
import { Agent } from 'agentic-flow';

const agent = new Agent({
  name: 'assistant',
  provider: 'openai',
  model: 'gpt-4',
  systemPrompt: 'You are a helpful assistant.',
  temperature: 0.7
});

// Simple completion
const result = await agent.execute({
  action: 'complete',
  input: 'Explain quantum computing in simple terms'
});

// Chat conversation
const chat = await agent.chat('Hello! How are you?', previousMessages);
```

### Streaming Responses

```javascript
// Stream for real-time output
const stream = agent.stream({
  action: 'complete',
  input: 'Write a long story about space exploration'
});

for await (const chunk of stream) {
  process.stdout.write(chunk);
}
```

### Function Calling

```javascript
const agent = new Agent({
  provider: 'openai',
  model: 'gpt-4',
  functions: [
    {
      name: 'get_weather',
      description: 'Get weather for a location',
      parameters: {
        type: 'object',
        properties: {
          location: { type: 'string' },
          unit: { type: 'string', enum: ['celsius', 'fahrenheit'] }
        },
        required: ['location']
      }
    }
  ]
});

const result = await agent.execute({
  action: 'complete',
  input: 'What\'s the weather in New York?'
});

// Handle function calls
if (result.functionCall) {
  const { name, arguments } = result.functionCall;
  // Execute function and continue conversation
}
```

### Vision (GPT-4V)

```javascript
const visionAgent = new Agent({
  provider: 'openai',
  model: 'gpt-4-vision-preview',
  maxTokens: 4096
});

const result = await visionAgent.execute({
  action: 'analyze',
  input: {
    text: 'What do you see in this image?',
    images: ['base64_image_data_or_url']
  }
});
```

### Image Generation (DALL-E)

```javascript
const imageAgent = new Agent({
  provider: 'openai',
  model: 'dall-e-3',
  imageSettings: {
    size: '1024x1024',
    quality: 'hd',
    style: 'vivid'
  }
});

const result = await imageAgent.execute({
  action: 'generate-image',
  input: 'A futuristic city with flying cars at sunset'
});

// result.images contains generated image URLs
```

### Audio Transcription (Whisper)

```javascript
const transcriber = new Agent({
  provider: 'openai',
  model: 'whisper-1'
});

const result = await transcriber.execute({
  action: 'transcribe',
  input: {
    audio: 'path/to/audio.mp3',
    language: 'en'
  }
});
```

### Embeddings

```javascript
const embedder = new Agent({
  provider: 'openai',
  model: 'text-embedding-3-large'
});

const embeddings = await embedder.embed([
  'Text to embed 1',
  'Text to embed 2',
  'Text to embed 3'
]);

// Use embeddings for similarity search
const similarity = cosineSimilarity(embeddings[0], embeddings[1]);
```

## Workflow Integration

### Multi-Model Workflow

```yaml
name: content-generation
agents:
  researcher:
    provider: openai
    model: gpt-4
    temperature: 0.3
    systemPrompt: "Research assistant focused on accuracy"
  
  writer:
    provider: openai
    model: gpt-4
    temperature: 0.8
    systemPrompt: "Creative content writer"
  
  illustrator:
    provider: openai
    model: dall-e-3
    imageSettings:
      size: "1024x1024"
      quality: "hd"
  
  narrator:
    provider: openai
    model: tts-1-hd
    voice: alloy

workflow:
  - agent: researcher
    action: research
    topic: "{{ input.topic }}"
  
  - agent: writer
    action: write
    content: "{{ previous.output }}"
  
  - agent: illustrator
    action: generate-image
    prompt: "{{ previous.summary }}"
  
  - agent: narrator
    action: text-to-speech
    text: "{{ writer.output }}"
```

### Parallel Processing

```yaml
workflow:
  - type: parallel
    agents:
      - name: analyst1
        provider: openai
        model: gpt-4
        task: "Analyze market trends"
      
      - name: analyst2
        provider: openai
        model: gpt-3.5-turbo
        task: "Analyze competitor data"
      
      - name: analyst3
        provider: openai
        model: gpt-4
        task: "Analyze customer feedback"
  
  - type: aggregate
    agent: synthesizer
    model: gpt-4
    task: "Combine all analyses"
```

## Best Practices

### 1. Model Selection

```javascript
// Use GPT-4 for complex reasoning
const complexAgent = new Agent({
  provider: 'openai',
  model: 'gpt-4',
  temperature: 0.3  // Lower for consistency
});

// Use GPT-3.5 for simple tasks (cost-effective)
const simpleAgent = new Agent({
  provider: 'openai',
  model: 'gpt-3.5-turbo',
  temperature: 0.7
});

// Use GPT-4 Turbo for long context
const longContextAgent = new Agent({
  provider: 'openai',
  model: 'gpt-4-turbo-preview',
  maxTokens: 128000  // 128k context
});
```

### 2. Error Handling

```javascript
try {
  const result = await agent.execute(task);
} catch (error) {
  if (error.code === 'rate_limit_exceeded') {
    // Wait and retry
    await sleep(error.retryAfter * 1000);
    return agent.execute(task);
  } else if (error.code === 'model_not_available') {
    // Fallback to different model
    agent.model = 'gpt-3.5-turbo';
    return agent.execute(task);
  }
  throw error;
}
```

### 3. Token Management

```javascript
// Track token usage
const result = await agent.execute(task);
console.log(`Tokens used: ${result.usage.totalTokens}`);
console.log(`Cost: $${result.usage.cost}`);

// Limit tokens
const agent = new Agent({
  provider: 'openai',
  model: 'gpt-4',
  maxTokens: 1000,  // Limit response length
  truncatePrompt: true  // Auto-truncate if too long
});
```

### 4. Prompt Engineering

```javascript
// Structured prompts
const agent = new Agent({
  provider: 'openai',
  model: 'gpt-4',
  systemPrompt: `You are an expert assistant.
    
    Guidelines:
    - Be concise and clear
    - Use bullet points for lists
    - Cite sources when applicable
    - Ask for clarification if needed`
});

// Few-shot examples
const examples = [
  { input: "Translate: Hello", output: "Hola" },
  { input: "Translate: Goodbye", output: "Adiós" }
];

const result = await agent.execute({
  action: 'complete',
  input: 'Translate: Good morning',
  examples: examples
});
```

## Performance Optimization

### 1. Batching Requests

```javascript
// Batch multiple completions
const batchResults = await agent.batch([
  { action: 'complete', input: 'Task 1' },
  { action: 'complete', input: 'Task 2' },
  { action: 'complete', input: 'Task 3' }
]);
```

### 2. Caching Responses

```yaml
providers:
  openai:
    cache:
      enabled: true
      ttl: 3600  # 1 hour
      maxSize: 1000  # entries
      keyGenerator: 'hash'  # or 'semantic'
```

### 3. Connection Pooling

```yaml
providers:
  openai:
    connection:
      poolSize: 10
      keepAlive: true
      timeout: 30000
```

## Cost Management

### Usage Tracking

```javascript
// Track costs across sessions
const costTracker = new CostTracker();

agent.on('usage', (usage) => {
  costTracker.add({
    model: usage.model,
    tokens: usage.totalTokens,
    cost: usage.cost
  });
});

// Get reports
const report = costTracker.getMonthlyReport();
```

### Cost Optimization

```yaml
# Use different models based on task complexity
agents:
  quick_response:
    model: gpt-3.5-turbo  # $0.002/1K tokens
    maxTokens: 500
  
  deep_analysis:
    model: gpt-4  # $0.03/1K tokens
    maxTokens: 2000
  
  bulk_processing:
    model: gpt-3.5-turbo-16k  # For long context
    batchSize: 10  # Process in batches
```

## Troubleshooting

### Common Issues

1. **API Key Invalid**
   ```bash
   # Verify API key
   curl https://api.openai.com/v1/models \
     -H "Authorization: Bearer $OPENAI_API_KEY"
   ```

2. **Rate Limits**
   ```javascript
   // Implement exponential backoff
   const result = await retryWithBackoff(
     () => agent.execute(task),
     { maxAttempts: 5 }
   );
   ```

3. **Context Length Exceeded**
   ```javascript
   // Automatically handle long inputs
   const agent = new Agent({
     provider: 'openai',
     model: 'gpt-4',
     contextStrategy: 'truncate',  // or 'summarize'
     maxContextTokens: 8000
   });
   ```

### Debug Mode

```javascript
// Enable debug logging
const agent = new Agent({
  provider: 'openai',
  debug: true,
  logLevel: 'verbose'
});

// Log all API calls
agent.on('request', (req) => console.log('Request:', req));
agent.on('response', (res) => console.log('Response:', res));
```

## Security Best Practices

1. **Never hardcode API keys**
   ```javascript
   // Bad
   const apiKey = 'sk-proj-xxxxx';
   
   // Good
   const apiKey = process.env.OPENAI_API_KEY;
   ```

2. **Use organization IDs**
   ```yaml
   providers:
     openai:
       organization: ${OPENAI_ORG_ID}
       allowedModels: ['gpt-4', 'gpt-3.5-turbo']
   ```

3. **Implement rate limiting**
   ```javascript
   const rateLimiter = new RateLimiter({
     requestsPerMinute: 50,
     tokensPerMinute: 40000
   });
   
   agent.use(rateLimiter);
   ```

## Migration from Direct OpenAI SDK

```javascript
// Old: Direct OpenAI SDK
import OpenAI from 'openai';
const openai = new OpenAI({ apiKey });
const completion = await openai.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }]
});

// New: Agentic Flow
import { Agent } from 'agentic-flow';
const agent = new Agent({
  provider: 'openai',
  model: 'gpt-4'
});
const result = await agent.chat('Hello');
```

## Resources

- [OpenAI API Documentation](https://platform.openai.com/docs)
- [Model Pricing](https://openai.com/pricing)
- [Rate Limits](https://platform.openai.com/docs/guides/rate-limits)
- [Best Practices](https://platform.openai.com/docs/guides/best-practices)