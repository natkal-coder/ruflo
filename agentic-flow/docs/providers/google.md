# Google AI Provider Integration

Complete guide for integrating Google AI models (Gemini, PaLM, Vertex AI) with Agentic Flow.

## Overview

The Google AI provider enables access to:
- **Gemini Pro**: Advanced reasoning and multimodal capabilities
- **Gemini Pro Vision**: Image understanding and analysis
- **Gemini Ultra**: Most capable model (when available)
- **PaLM 2**: Text generation and chat
- **Vertex AI Models**: Enterprise-grade AI platform
- **Embeddings**: Gecko text embeddings

## Installation

```bash
# Agentic Flow includes Google provider by default
npm install agentic-flow

# Or install provider separately
npm install @agentic-flow/provider-google

# For Vertex AI support
npm install @google-cloud/aiplatform
```

## Configuration

### Basic Configuration (Google AI Studio)

```yaml
# .agentic/config.yaml
providers:
  google:
    type: google
    apiKey: ${GOOGLE_AI_API_KEY}
    defaultModel: gemini-pro
    region: us-central1  # Optional
```

### Vertex AI Configuration

```yaml
providers:
  google-vertex:
    type: google
    platform: vertex
    projectId: ${GCP_PROJECT_ID}
    location: us-central1
    credentials: ${GOOGLE_APPLICATION_CREDENTIALS}
    defaultModel: gemini-pro
    
    # Model-specific settings
    models:
      gemini-pro:
        temperature: 0.7
        topK: 40
        topP: 0.95
        maxOutputTokens: 2048
      
      gemini-pro-vision:
        temperature: 0.4
        maxOutputTokens: 4096
    
    # Safety settings
    safety:
      harmBlockThreshold: BLOCK_MEDIUM_AND_ABOVE
      categories:
        - HARM_CATEGORY_HARASSMENT
        - HARM_CATEGORY_HATE_SPEECH
        - HARM_CATEGORY_SEXUALLY_EXPLICIT
        - HARM_CATEGORY_DANGEROUS_CONTENT
```

### Environment Variables

```bash
# For Google AI Studio
export GOOGLE_AI_API_KEY=YOUR_API_KEY

# For Vertex AI
export GCP_PROJECT_ID=your-project-id
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

## Usage Examples

### Basic Text Generation

```javascript
import { Agent } from 'agentic-flow';

const agent = new Agent({
  name: 'gemini-assistant',
  provider: 'google',
  model: 'gemini-pro',
  systemPrompt: 'You are a helpful AI assistant powered by Gemini.',
  temperature: 0.7
});

// Simple completion
const result = await agent.execute({
  action: 'complete',
  input: 'Explain quantum entanglement in simple terms'
});

// With parameters
const result = await agent.execute({
  action: 'complete',
  input: 'Write a creative story',
  params: {
    temperature: 0.9,
    topK: 50,
    topP: 0.95,
    maxOutputTokens: 1000
  }
});
```

### Multimodal Capabilities (Gemini Pro Vision)

```javascript
const visionAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro-vision'
});

// Single image analysis
const result = await visionAgent.execute({
  action: 'analyze',
  input: {
    text: 'What is happening in this image?',
    images: [{
      path: 'path/to/image.jpg',
      mimeType: 'image/jpeg'
    }]
  }
});

// Multiple images
const result = await visionAgent.execute({
  action: 'compare',
  input: {
    text: 'Compare these architectural styles',
    images: [
      { url: 'https://example.com/building1.jpg' },
      { url: 'https://example.com/building2.jpg' }
    ]
  }
});

// Image with base64
const result = await visionAgent.execute({
  action: 'analyze',
  input: {
    text: 'Describe this chart',
    images: [{
      data: base64ImageData,
      mimeType: 'image/png'
    }]
  }
});
```

### Streaming Responses

```javascript
// Stream text generation
const stream = agent.stream({
  action: 'complete',
  input: 'Tell me about the history of computing'
});

for await (const chunk of stream) {
  process.stdout.write(chunk);
}

// Stream with safety filters
const safeStream = agent.stream({
  action: 'complete',
  input: prompt,
  safety: {
    enabled: true,
    threshold: 'BLOCK_LOW_AND_ABOVE'
  }
});
```

### Chat Conversations

```javascript
const chatAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  chatMode: true
});

// Start conversation
const chat = chatAgent.createChat();

// Send messages
const response1 = await chat.send('Hello! What can you help me with?');
const response2 = await chat.send('Can you explain how solar panels work?');
const response3 = await chat.send('What are the environmental benefits?');

// Access history
const history = chat.getHistory();
```

### Embeddings

```javascript
const embedder = new Agent({
  provider: 'google',
  model: 'embedding-001'  // Gecko
});

// Generate embeddings
const embeddings = await embedder.embed([
  'First text to embed',
  'Second text to embed',
  'Third text to embed'
]);

// Use for similarity search
const similarity = cosineSimilarity(embeddings[0], embeddings[1]);
```

### Function Calling

```javascript
const agent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  functions: [
    {
      name: 'get_weather',
      description: 'Get current weather for a location',
      parameters: {
        type: 'object',
        properties: {
          location: {
            type: 'string',
            description: 'City and state'
          },
          unit: {
            type: 'string',
            enum: ['celsius', 'fahrenheit']
          }
        },
        required: ['location']
      }
    }
  ]
});

const result = await agent.execute({
  action: 'complete',
  input: 'What\'s the weather like in San Francisco?'
});

// Handle function calls
if (result.functionCall) {
  const weatherData = await getWeather(result.functionCall.args);
  const finalResult = await agent.execute({
    action: 'complete',
    input: result.functionCall,
    functionResponse: weatherData
  });
}
```

## Workflow Integration

### Multi-Model Workflow

```yaml
name: content-analysis-pipeline
agents:
  text_analyzer:
    provider: google
    model: gemini-pro
    temperature: 0.3
    systemPrompt: "Detailed text analyzer"
  
  visual_analyzer:
    provider: google
    model: gemini-pro-vision
    temperature: 0.4
    systemPrompt: "Visual content expert"
  
  summarizer:
    provider: google
    model: gemini-pro
    temperature: 0.5
    maxOutputTokens: 500

workflow:
  - agent: text_analyzer
    action: analyze
    document: "{{ input.text }}"
  
  - agent: visual_analyzer
    action: analyze
    images: "{{ input.images }}"
    context: "{{ text_analyzer.output }}"
  
  - agent: summarizer
    action: summarize
    inputs:
      text_analysis: "{{ text_analyzer.output }}"
      visual_analysis: "{{ visual_analyzer.output }}"
```

### Vertex AI Batch Processing

```yaml
name: batch-processing
provider: google-vertex
configuration:
  platform: vertex
  batchSize: 100
  parallelism: 10

agents:
  processor:
    model: gemini-pro
    temperature: 0.5

workflow:
  - type: batch
    agent: processor
    inputs: "{{ data.items }}"
    options:
      timeout: 300000  # 5 minutes per batch
      retries: 3
```

## Best Practices

### 1. Model Selection

```javascript
// For complex reasoning and analysis
const complexAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  temperature: 0.3,
  topK: 20  // More focused
});

// For creative tasks
const creativeAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  temperature: 0.9,
  topK: 50,
  topP: 0.95
});

// For visual tasks
const visualAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro-vision',
  temperature: 0.4
});
```

### 2. Safety Configuration

```javascript
// Strict safety settings
const safeAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  safety: {
    harmBlockThreshold: 'BLOCK_LOW_AND_ABOVE',
    categories: [
      'HARM_CATEGORY_HARASSMENT',
      'HARM_CATEGORY_HATE_SPEECH',
      'HARM_CATEGORY_SEXUALLY_EXPLICIT',
      'HARM_CATEGORY_DANGEROUS_CONTENT'
    ]
  }
});

// Custom safety handling
agent.on('safety_rating', (rating) => {
  if (rating.probability > 0.7) {
    console.warn('High probability of harmful content:', rating.category);
  }
});
```

### 3. Prompt Engineering for Gemini

```javascript
// Structured prompts for Gemini
const agent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  systemPrompt: `You are a helpful assistant. Follow these guidelines:

1. Structure: Use clear headings and bullet points
2. Reasoning: Think step-by-step for complex problems
3. Examples: Provide concrete examples when helpful
4. Clarity: Be concise but comprehensive
5. Safety: Avoid harmful or biased content`
});

// Multi-turn prompting
const result = await agent.execute({
  action: 'complete',
  input: `Task: Analyze this data and provide insights

Data:
${JSON.stringify(data, null, 2)}

Requirements:
- Identify key patterns
- Calculate relevant statistics
- Provide actionable recommendations
- Include confidence levels`,
  
  examples: [
    {
      input: 'Sample data...',
      output: 'Sample analysis...'
    }
  ]
});
```

### 4. Context Window Management

```javascript
// Gemini Pro supports 32K tokens
const agent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  contextWindow: 32768,
  contextStrategy: {
    method: 'sliding',  // or 'truncate', 'summarize'
    preserveRecent: 0.7  // Keep 70% recent context
  }
});

// For very long contexts
const result = await agent.execute({
  action: 'analyze',
  input: longDocument,
  params: {
    chunkSize: 20000,
    overlap: 1000,
    aggregation: 'hierarchical'
  }
});
```

## Performance Optimization

### 1. Caching Strategy

```yaml
providers:
  google:
    cache:
      enabled: true
      backend: redis
      ttl: 3600
      keyStrategy: semantic  # Cache semantically similar queries
      similarityThreshold: 0.95
```

### 2. Batch Processing

```javascript
// Efficient batch processing
const batchAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  batchMode: true,
  batchSize: 25  // Gemini supports up to 25 requests per batch
});

const results = await batchAgent.batch([
  { action: 'classify', input: 'Text 1' },
  { action: 'classify', input: 'Text 2' },
  // ... up to 25 items
]);
```

### 3. Rate Limit Management

```javascript
// Built-in rate limiting
const agent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  rateLimits: {
    requestsPerMinute: 60,
    requestsPerDay: 1000,
    strategy: 'sliding-window'
  }
});

// Monitor limits
agent.on('rate_limit_approaching', (info) => {
  console.log(`${info.remaining} requests remaining`);
});
```

## Vertex AI Integration

### Setup Vertex AI

```javascript
// Vertex AI configuration
const vertexAgent = new Agent({
  provider: 'google',
  platform: 'vertex',
  projectId: 'your-project-id',
  location: 'us-central1',
  model: 'gemini-pro',
  
  // Service account auth
  credentials: {
    type: 'service_account',
    project_id: 'your-project-id',
    private_key: process.env.GCP_PRIVATE_KEY,
    client_email: process.env.GCP_CLIENT_EMAIL
  }
});
```

### Model Deployment

```javascript
// Deploy custom model
const deployment = await vertexAgent.deployModel({
  model: 'custom-model',
  endpoint: 'my-endpoint',
  resources: {
    minReplicas: 1,
    maxReplicas: 10,
    machineType: 'n1-standard-4'
  }
});

// Use deployed model
const customAgent = new Agent({
  provider: 'google',
  platform: 'vertex',
  endpoint: deployment.endpoint,
  model: 'custom-model'
});
```

## Error Handling

### Common Errors

```javascript
try {
  const result = await agent.execute(task);
} catch (error) {
  switch (error.code) {
    case 'INVALID_API_KEY':
      console.error('Invalid API key. Check your configuration.');
      break;
      
    case 'QUOTA_EXCEEDED':
      console.log('Quota exceeded. Waiting...');
      await sleep(error.retryAfter || 60000);
      return agent.execute(task);
      
    case 'SAFETY_BLOCK':
      console.log('Content blocked by safety filters');
      // Try with adjusted prompt
      task.input = adjustPromptForSafety(task.input);
      return agent.execute(task);
      
    case 'INVALID_IMAGE':
      console.error('Image format not supported');
      // Convert or resize image
      break;
      
    case 'CONTEXT_LENGTH_EXCEEDED':
      console.log('Context too long, chunking...');
      return processInChunks(task);
      
    default:
      throw error;
  }
}
```

### Retry Strategy

```javascript
const resilientAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  retry: {
    maxAttempts: 5,
    backoff: {
      initial: 1000,
      max: 32000,
      multiplier: 2
    },
    retryableErrors: [
      'RATE_LIMIT_EXCEEDED',
      'RESOURCE_EXHAUSTED',
      'INTERNAL_ERROR'
    ]
  }
});
```

## Cost Management

### Pricing Tiers

```javascript
// Track costs by model
const pricing = {
  'gemini-pro': {
    input: 0.00025,  // per 1K characters
    output: 0.00125  // per 1K characters
  },
  'gemini-pro-vision': {
    input: 0.00025,
    output: 0.00125,
    image: 0.0025  // per image
  }
};

agent.on('usage', (usage) => {
  const cost = calculateCost(usage, pricing);
  console.log(`Request cost: $${cost.toFixed(4)}`);
});
```

### Optimization Strategies

```yaml
# Cost-optimized workflow
agents:
  quick_filter:
    model: gemini-pro
    maxOutputTokens: 100  # Minimal output
    temperature: 0.3
  
  detailed_analysis:
    model: gemini-pro
    maxOutputTokens: 2000
    condition: "{{ quick_filter.score > 0.7 }}"
  
  visual_check:
    model: gemini-pro-vision
    condition: "{{ has_images }}"
```

## Security Best Practices

### 1. Authentication

```javascript
// Secure credential management
const agent = new Agent({
  provider: 'google',
  platform: 'vertex',
  credentials: {
    // Use environment variables
    projectId: process.env.GCP_PROJECT_ID,
    // Or use default credentials
    useDefaultCredentials: true
  }
});
```

### 2. Data Privacy

```javascript
// Enable data processing options
const privateAgent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  privacy: {
    logPrompts: false,
    logResponses: false,
    dataResidency: 'us',
    encryption: true
  }
});
```

### 3. Content Filtering

```javascript
// Pre-filter content
const filterAndExecute = async (task) => {
  const filtered = await contentFilter.check(task.input);
  
  if (filtered.safe) {
    return agent.execute(task);
  } else {
    throw new Error(`Content blocked: ${filtered.reason}`);
  }
};
```

## Troubleshooting

### Debug Mode

```javascript
// Enable comprehensive logging
const agent = new Agent({
  provider: 'google',
  model: 'gemini-pro',
  debug: true,
  logging: {
    requests: true,
    responses: true,
    errors: true,
    performance: true
  }
});

// Monitor all events
agent.on('debug', (data) => {
  console.log('[DEBUG]', data);
});
```

### Common Issues

1. **API Key Issues**
   ```bash
   # Test API key
   curl -X POST https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent \
     -H "Content-Type: application/json" \
     -H "x-goog-api-key: $GOOGLE_AI_API_KEY" \
     -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
   ```

2. **Vertex AI Authentication**
   ```bash
   # Verify service account
   gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
   gcloud auth list
   ```

3. **Image Size Limits**
   ```javascript
   // Resize images before sending
   const resizeImage = async (image) => {
     const maxSize = 4 * 1024 * 1024; // 4MB
     if (image.size > maxSize) {
       return await compressImage(image, { maxSize });
     }
     return image;
   };
   ```

## Resources

- [Google AI Studio](https://makersuite.google.com)
- [Vertex AI Documentation](https://cloud.google.com/vertex-ai/docs)
- [Gemini API Reference](https://ai.google.dev/api/rest)
- [Pricing](https://ai.google.dev/pricing)
- [Model Cards](https://ai.google.dev/gemini-api/docs/models/gemini)