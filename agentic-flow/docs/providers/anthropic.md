# Anthropic Provider Integration

Complete guide for integrating Anthropic's Claude models with Agentic Flow.

## Overview

The Anthropic provider enables access to:
- **Claude 3 Opus**: Most capable model for complex tasks
- **Claude 3 Sonnet**: Balanced performance and speed
- **Claude 3 Haiku**: Fast and efficient for simple tasks
- **Claude 2.1**: Previous generation (200k context)
- **Claude Instant**: Low-latency responses

## Installation

```bash
# Agentic Flow includes Anthropic provider by default
npm install agentic-flow

# Or install provider separately
npm install @agentic-flow/provider-anthropic
```

## Configuration

### Basic Configuration

```yaml
# .agentic/config.yaml
providers:
  anthropic:
    type: anthropic
    apiKey: ${ANTHROPIC_API_KEY}
    defaultModel: claude-3-opus-20240229
    maxTokens: 4096
```

### Advanced Configuration

```yaml
providers:
  anthropic:
    type: anthropic
    apiKey: ${ANTHROPIC_API_KEY}
    baseURL: https://api.anthropic.com  # For proxies
    version: 2024-02-29  # API version
    
    # Model-specific settings
    models:
      claude-3-opus:
        maxTokens: 4096
        temperature: 0.7
        topP: 1
        topK: 40
      
      claude-3-sonnet:
        maxTokens: 4096
        temperature: 0.8
      
      claude-3-haiku:
        maxTokens: 4096
        temperature: 0.9
    
    # Safety settings
    safety:
      blockHarmfulContent: true
      moderationLevel: standard
    
    # Rate limiting
    rateLimits:
      requestsPerMinute: 50
      tokensPerMinute: 100000
    
    # Retry configuration
    retry:
      maxAttempts: 3
      backoffMultiplier: 2
      maxDelay: 10000
```

### Environment Variables

```bash
# Required
export ANTHROPIC_API_KEY=sk-ant-api03-xxxxx

# Optional
export ANTHROPIC_BASE_URL=https://api.anthropic.com
export ANTHROPIC_VERSION=2024-02-29
```

## Usage Examples

### Basic Text Generation

```javascript
import { Agent } from 'agentic-flow';

const agent = new Agent({
  name: 'claude-assistant',
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  systemPrompt: 'You are Claude, a helpful AI assistant.',
  temperature: 0.7
});

// Simple completion
const result = await agent.execute({
  action: 'complete',
  input: 'Explain the theory of relativity'
});

// With specific parameters
const result = await agent.execute({
  action: 'complete',
  input: 'Write a poem about nature',
  params: {
    maxTokens: 500,
    temperature: 0.9,
    stopSequences: ['\n\n']
  }
});
```

### Streaming Responses

```javascript
// Stream for real-time output
const stream = agent.stream({
  action: 'complete',
  input: 'Tell me a long story about adventure'
});

for await (const chunk of stream) {
  process.stdout.write(chunk);
}

// With metadata
const stream = agent.streamWithMetadata({
  action: 'complete',
  input: prompt
});

for await (const event of stream) {
  if (event.type === 'content') {
    process.stdout.write(event.content);
  } else if (event.type === 'metadata') {
    console.log('Token usage:', event.usage);
  }
}
```

### Vision Capabilities

```javascript
const visionAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229'
});

// Analyze image
const result = await visionAgent.execute({
  action: 'analyze',
  input: {
    text: 'What do you see in this image? Describe in detail.',
    images: [{
      type: 'base64',
      mediaType: 'image/jpeg',
      data: 'base64_encoded_image_data'
    }]
  }
});

// Multiple images
const result = await visionAgent.execute({
  action: 'compare',
  input: {
    text: 'Compare these two images',
    images: [
      { type: 'url', url: 'https://example.com/image1.jpg' },
      { type: 'url', url: 'https://example.com/image2.jpg' }
    ]
  }
});
```

### Long Context Handling

```javascript
// Claude 3 supports up to 200k tokens
const longContextAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  maxTokens: 4096,
  contextWindow: 200000
});

// Process long document
const result = await longContextAgent.execute({
  action: 'analyze',
  input: {
    document: veryLongDocument, // Up to ~150k words
    query: 'Summarize the key points and findings'
  }
});

// With context caching
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  cacheContext: true  // Cache long contexts
});
```

### Structured Output

```javascript
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  outputFormat: 'json'
});

const result = await agent.execute({
  action: 'extract',
  input: 'Extract person details from: John Doe, 30 years old, engineer',
  schema: {
    type: 'object',
    properties: {
      name: { type: 'string' },
      age: { type: 'number' },
      occupation: { type: 'string' }
    }
  }
});

// result.output will be parsed JSON
```

## Workflow Integration

### Multi-Model Strategy

```yaml
name: document-processing
agents:
  analyzer:
    provider: anthropic
    model: claude-3-opus-20240229
    temperature: 0.3
    systemPrompt: "Careful document analyzer"
  
  summarizer:
    provider: anthropic
    model: claude-3-sonnet-20240229
    temperature: 0.5
    systemPrompt: "Concise summarizer"
  
  quick_response:
    provider: anthropic
    model: claude-3-haiku-20240307
    temperature: 0.7
    systemPrompt: "Quick response generator"

workflow:
  # Use Opus for complex analysis
  - agent: analyzer
    action: analyze
    document: "{{ input.document }}"
  
  # Use Sonnet for balanced summarization  
  - agent: summarizer
    action: summarize
    content: "{{ previous.output }}"
  
  # Use Haiku for quick responses
  - agent: quick_response
    action: respond
    query: "{{ input.question }}"
```

### Parallel Processing

```yaml
workflow:
  - type: parallel
    agents:
      - name: researcher1
        provider: anthropic
        model: claude-3-sonnet-20240229
        task: "Research market trends"
      
      - name: researcher2
        provider: anthropic
        model: claude-3-sonnet-20240229
        task: "Research competitors"
      
      - name: researcher3
        provider: anthropic
        model: claude-3-sonnet-20240229
        task: "Research technology"
  
  - type: synthesize
    agent: synthesis_expert
    provider: anthropic
    model: claude-3-opus-20240229
    task: "Synthesize all research findings"
```

## Best Practices

### 1. Model Selection Guide

```javascript
// Complex reasoning, coding, analysis
const opusAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  temperature: 0.3,
  use_cases: ['coding', 'analysis', 'complex_reasoning']
});

// Balanced tasks, general purpose
const sonnetAgent = new Agent({
  provider: 'anthropic', 
  model: 'claude-3-sonnet-20240229',
  temperature: 0.5,
  use_cases: ['chat', 'writing', 'summarization']
});

// Fast responses, simple tasks
const haikuAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-haiku-20240307',
  temperature: 0.7,
  use_cases: ['classification', 'extraction', 'quick_answers']
});
```

### 2. Prompt Engineering for Claude

```javascript
// Claude-optimized prompts
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  systemPrompt: `You are Claude, an AI assistant created by Anthropic.
    
    Core principles:
    - Be helpful, harmless, and honest
    - Think step by step for complex problems
    - Acknowledge uncertainty when appropriate
    - Provide balanced perspectives
    
    For this conversation:
    - Focus on accuracy and clarity
    - Use examples when helpful
    - Ask for clarification if needed`
});

// Using XML tags for structure
const result = await agent.execute({
  action: 'complete',
  input: `<task>
    Analyze this code and provide feedback
  </task>
  
  <code>
  ${codeToAnalyze}
  </code>
  
  <requirements>
  - Check for bugs
  - Suggest improvements
  - Review performance
  </requirements>`
});
```

### 3. Handling Refusals

```javascript
try {
  const result = await agent.execute(task);
} catch (error) {
  if (error.type === 'refusal') {
    // Claude refused the request
    console.log('Request refused:', error.message);
    
    // Try rephrasing or adjusting the request
    const adjustedTask = {
      ...task,
      input: rephrase(task.input)
    };
    
    return agent.execute(adjustedTask);
  }
  throw error;
}
```

### 4. Context Management

```javascript
// Efficient context usage
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  contextStrategy: {
    maxTokens: 150000,
    compression: 'smart',  // Compress less important parts
    prioritization: 'recent'  // Keep recent context
  }
});

// Manual context control
const result = await agent.execute({
  action: 'complete',
  input: 'Continue the analysis',
  context: {
    previous_analysis: previousResult,
    relevantData: filteredData,
    trimOld: true
  }
});
```

## Performance Optimization

### 1. Batching Requests

```javascript
// Batch multiple prompts
const batchAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-haiku-20240307',
  batchMode: true
});

const results = await batchAgent.batch([
  { input: 'Classify: Happy customer' },
  { input: 'Classify: Angry complaint' },
  { input: 'Classify: Neutral feedback' }
]);
```

### 2. Caching Strategies

```yaml
providers:
  anthropic:
    cache:
      enabled: true
      strategy: 'semantic'  # Cache similar queries
      ttl: 7200  # 2 hours
      maxSize: 500  # MB
```

### 3. Token Optimization

```javascript
// Optimize token usage
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-sonnet-20240229',
  tokenOptimization: {
    trimWhitespace: true,
    compressPrompts: true,
    removeRedundancy: true
  }
});

// Monitor usage
agent.on('token_usage', (usage) => {
  console.log(`Input: ${usage.inputTokens}`);
  console.log(`Output: ${usage.outputTokens}`);
  console.log(`Cost: $${usage.estimatedCost}`);
});
```

## Error Handling

### Common Errors

```javascript
// Comprehensive error handling
try {
  const result = await agent.execute(task);
} catch (error) {
  switch (error.type) {
    case 'rate_limit':
      console.log(`Rate limited. Retry after: ${error.retryAfter}s`);
      await sleep(error.retryAfter * 1000);
      return agent.execute(task);
    
    case 'invalid_api_key':
      console.error('Invalid API key. Check configuration.');
      break;
    
    case 'model_not_found':
      console.error(`Model ${error.model} not available`);
      agent.model = 'claude-3-sonnet-20240229';  // Fallback
      return agent.execute(task);
    
    case 'context_too_long':
      console.log('Context too long, truncating...');
      task.input = truncateContext(task.input);
      return agent.execute(task);
    
    case 'overloaded':
      console.log('API overloaded, using fallback...');
      return fallbackAgent.execute(task);
    
    default:
      throw error;
  }
}
```

### Retry Logic

```javascript
// Custom retry with backoff
const resilientAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  retry: {
    maxAttempts: 5,
    backoff: 'exponential',
    onRetry: (attempt, error) => {
      console.log(`Retry ${attempt} after error: ${error.message}`);
    }
  }
});
```

## Cost Management

### Usage Tracking

```javascript
// Track costs per model
const costTracker = {
  'claude-3-opus': { input: 0.015, output: 0.075 },  // per 1K tokens
  'claude-3-sonnet': { input: 0.003, output: 0.015 },
  'claude-3-haiku': { input: 0.00025, output: 0.00125 }
};

agent.on('usage', (usage) => {
  const model = usage.model;
  const inputCost = (usage.inputTokens / 1000) * costTracker[model].input;
  const outputCost = (usage.outputTokens / 1000) * costTracker[model].output;
  const totalCost = inputCost + outputCost;
  
  console.log(`Cost: $${totalCost.toFixed(4)}`);
});
```

### Optimization Strategies

```yaml
# Cost-optimized workflow
agents:
  initial_filter:
    model: claude-3-haiku-20240307  # Cheap, fast
    maxTokens: 100
  
  main_processor:
    model: claude-3-sonnet-20240229  # Balanced
    maxTokens: 1000
  
  final_review:
    model: claude-3-opus-20240229  # Only for critical tasks
    maxTokens: 2000
    condition: "{{ importance > 0.8 }}"
```

## Security Best Practices

### 1. API Key Security

```javascript
// Never hardcode keys
const agent = new Agent({
  provider: 'anthropic',
  apiKey: process.env.ANTHROPIC_API_KEY,
  // Optional: key rotation
  keyRotation: {
    enabled: true,
    interval: 86400000  // 24 hours
  }
});
```

### 2. Content Filtering

```javascript
// Built-in safety
const safeAgent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  safety: {
    blockHarmful: true,
    filterPersonalInfo: true,
    redactSensitive: true
  }
});
```

### 3. Audit Logging

```javascript
// Log all interactions
agent.on('request', (req) => {
  auditLog.record({
    timestamp: new Date(),
    user: req.userId,
    prompt: req.input,
    model: req.model
  });
});
```

## Migration from Claude SDK

```javascript
// Old: Direct Anthropic SDK
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic({ apiKey });
const message = await anthropic.messages.create({
  model: 'claude-3-opus-20240229',
  messages: [{ role: 'user', content: 'Hello' }],
  max_tokens: 1024
});

// New: Agentic Flow
import { Agent } from 'agentic-flow';
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  maxTokens: 1024
});
const result = await agent.chat('Hello');
```

## Troubleshooting

### Debug Mode

```javascript
// Enable detailed logging
const agent = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus-20240229',
  debug: true,
  logLevel: 'verbose'
});

// Monitor all events
agent.on('*', (event, data) => {
  console.log(`Event: ${event}`, data);
});
```

### Common Issues

1. **API Key Format**
   ```bash
   # Verify key format (should start with sk-ant-)
   echo $ANTHROPIC_API_KEY | grep "^sk-ant-"
   ```

2. **Model Availability**
   ```javascript
   // Check available models
   const models = await provider.listModels();
   console.log('Available:', models);
   ```

3. **Context Length**
   ```javascript
   // Handle context limits gracefully
   if (error.type === 'context_too_long') {
     const compressed = await compressContext(input);
     return agent.execute({ ...task, input: compressed });
   }
   ```

## Resources

- [Anthropic API Documentation](https://docs.anthropic.com)
- [Model Card](https://www.anthropic.com/claude)
- [Pricing](https://www.anthropic.com/api-pricing)
- [Safety Guidelines](https://www.anthropic.com/safety)