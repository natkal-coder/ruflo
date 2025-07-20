# API Reference

Complete API documentation for Agentic Flow, covering all modules, classes, and functions.

## Table of Contents

- [Core API](#core-api)
- [Provider API](#provider-api)
- [Agent API](#agent-api)
- [Workflow API](#workflow-api)
- [Memory API](#memory-api)
- [Event API](#event-api)
- [CLI API](#cli-api)
- [Plugin API](#plugin-api)

## Core API

### AgenticFlow

The main entry point for the Agentic Flow framework.

```typescript
import { AgenticFlow } from 'agentic-flow';

const flow = new AgenticFlow(config?: AgenticConfig);
```

#### Methods

##### `initialize(options?: InitOptions): Promise<void>`

Initialize the Agentic Flow instance.

```typescript
await flow.initialize({
  providers: ['openai', 'anthropic'],
  memory: true,
  plugins: ['custom-plugin']
});
```

##### `run(workflow: string | Workflow, context?: Context): Promise<Result>`

Execute a workflow.

```typescript
const result = await flow.run('workflows/my-workflow.yaml', {
  input: 'Process this text',
  params: { temperature: 0.7 }
});
```

##### `stop(): Promise<void>`

Gracefully stop all running workflows.

```typescript
await flow.stop();
```

### Configuration

#### AgenticConfig

```typescript
interface AgenticConfig {
  // Core settings
  projectDir?: string;
  configFile?: string;
  environment?: 'development' | 'production' | 'test';
  
  // Provider settings
  providers?: ProviderConfig[];
  defaultProvider?: string;
  
  // Memory settings
  memory?: MemoryConfig;
  
  // Workflow settings
  workflows?: WorkflowConfig;
  
  // Plugin settings
  plugins?: string[] | PluginConfig[];
  
  // Logging
  logging?: LogConfig;
}
```

#### Example Configuration

```typescript
const config: AgenticConfig = {
  projectDir: './my-project',
  environment: 'production',
  providers: [
    {
      name: 'openai',
      type: 'openai',
      apiKey: process.env.OPENAI_API_KEY,
      defaultModel: 'gpt-4'
    }
  ],
  memory: {
    enabled: true,
    backend: 'postgresql',
    connection: process.env.DATABASE_URL
  },
  logging: {
    level: 'info',
    format: 'json'
  }
};
```

## Provider API

### BaseProvider

Abstract base class for all providers.

```typescript
abstract class BaseProvider {
  abstract initialize(): Promise<void>;
  abstract complete(prompt: string, options?: CompletionOptions): Promise<CompletionResult>;
  abstract chat(messages: Message[], options?: ChatOptions): Promise<ChatResult>;
  abstract embed(text: string): Promise<number[]>;
}
```

### Provider Registry

```typescript
import { ProviderRegistry } from 'agentic-flow/providers';

// Register custom provider
ProviderRegistry.register('custom', CustomProvider);

// Get provider instance
const provider = ProviderRegistry.get('openai');
```

### Built-in Providers

#### OpenAIProvider

```typescript
import { OpenAIProvider } from 'agentic-flow/providers';

const provider = new OpenAIProvider({
  apiKey: 'sk-...',
  organization: 'org-...',
  defaultModel: 'gpt-4',
  timeout: 30000,
  maxRetries: 3
});

// Completion
const result = await provider.complete('Generate a story about', {
  maxTokens: 1000,
  temperature: 0.8
});

// Chat
const chat = await provider.chat([
  { role: 'system', content: 'You are a helpful assistant' },
  { role: 'user', content: 'Hello!' }
]);

// Embeddings
const embeddings = await provider.embed('Text to embed');
```

#### AnthropicProvider

```typescript
import { AnthropicProvider } from 'agentic-flow/providers';

const provider = new AnthropicProvider({
  apiKey: 'sk-ant-...',
  defaultModel: 'claude-3-opus',
  maxTokens: 4096
});

const result = await provider.complete('Analyze this code:', {
  systemPrompt: 'You are a code reviewer',
  temperature: 0.3
});
```

#### Custom Provider

```typescript
import { BaseProvider, ProviderConfig } from 'agentic-flow/providers';

class CustomProvider extends BaseProvider {
  constructor(config: ProviderConfig) {
    super(config);
  }
  
  async initialize(): Promise<void> {
    // Initialize your provider
  }
  
  async complete(prompt: string, options?: CompletionOptions): Promise<CompletionResult> {
    // Implement completion logic
    return {
      text: 'Generated text',
      usage: { promptTokens: 10, completionTokens: 20 },
      metadata: {}
    };
  }
  
  async chat(messages: Message[], options?: ChatOptions): Promise<ChatResult> {
    // Implement chat logic
  }
  
  async embed(text: string): Promise<number[]> {
    // Implement embedding logic
  }
}
```

## Agent API

### Agent

Core agent class for AI-powered task execution.

```typescript
import { Agent } from 'agentic-flow/agents';

const agent = new Agent({
  name: 'researcher',
  provider: 'openai',
  model: 'gpt-4',
  systemPrompt: 'You are a research assistant',
  temperature: 0.7,
  maxTokens: 2000
});
```

#### Methods

##### `execute(task: Task): Promise<TaskResult>`

Execute a single task.

```typescript
const result = await agent.execute({
  action: 'research',
  input: 'Latest developments in quantum computing',
  context: { depth: 'detailed' }
});
```

##### `chat(message: string, history?: Message[]): Promise<string>`

Interactive chat with the agent.

```typescript
const response = await agent.chat('What do you think about AI?', previousMessages);
```

##### `stream(task: Task): AsyncGenerator<string>`

Stream responses for real-time output.

```typescript
for await (const chunk of agent.stream(task)) {
  console.log(chunk);
}
```

### AgentManager

Manage multiple agents.

```typescript
import { AgentManager } from 'agentic-flow/agents';

const manager = new AgentManager();

// Register agents
manager.register(agent1);
manager.register(agent2);

// Get agent
const agent = manager.get('researcher');

// List agents
const agents = manager.list();

// Execute with best agent
const result = await manager.executeBest(task);
```

### Agent Types

```typescript
// Specialized agent types
import { 
  ResearchAgent,
  CodingAgent,
  AnalysisAgent,
  CreativeAgent 
} from 'agentic-flow/agents';

const researcher = new ResearchAgent({
  name: 'deep-researcher',
  searchEngines: ['google', 'arxiv'],
  maxSources: 10
});

const coder = new CodingAgent({
  name: 'senior-developer',
  languages: ['typescript', 'python'],
  linter: true,
  formatter: true
});
```

## Workflow API

### Workflow

Define and execute complex AI workflows.

```typescript
import { Workflow } from 'agentic-flow/workflows';

const workflow = new Workflow({
  name: 'content-pipeline',
  version: '1.0.0',
  description: 'Content creation pipeline'
});
```

#### Building Workflows

```typescript
// Sequential workflow
workflow
  .step('research', researchAgent)
  .step('write', writerAgent)
  .step('edit', editorAgent)
  .step('publish', publisherAgent);

// Parallel workflow
workflow
  .parallel([
    { name: 'task1', agent: agent1 },
    { name: 'task2', agent: agent2 },
    { name: 'task3', agent: agent3 }
  ])
  .aggregate(coordinatorAgent);

// Conditional workflow
workflow
  .condition(
    (context) => context.confidence > 0.8,
    workflow => workflow.step('approve', approverAgent),
    workflow => workflow.step('review', reviewerAgent)
  );

// Loop workflow
workflow
  .forEach('items', itemProcessorAgent)
  .collect(aggregatorAgent);
```

#### Execution

```typescript
const result = await workflow.execute({
  input: 'Create blog post about AI',
  params: {
    style: 'technical',
    length: 'long'
  }
});
```

### WorkflowBuilder

Fluent API for building workflows.

```typescript
import { WorkflowBuilder } from 'agentic-flow/workflows';

const workflow = WorkflowBuilder
  .create('my-workflow')
  .withAgent('researcher', { provider: 'openai' })
  .withAgent('writer', { provider: 'anthropic' })
  .sequential()
    .step('research')
    .step('write')
  .build();
```

### Workflow Templates

```typescript
import { WorkflowTemplates } from 'agentic-flow/workflows';

// Use pre-built template
const ragWorkflow = WorkflowTemplates.RAG({
  vectorStore: 'pinecone',
  embedder: 'openai',
  retriever: { topK: 5 }
});

// Custom template
const customTemplate = WorkflowTemplates.create({
  name: 'custom-template',
  params: ['param1', 'param2'],
  build: (params) => {
    // Build workflow based on params
  }
});
```

## Memory API

### MemoryManager

Persistent memory for agents and workflows.

```typescript
import { MemoryManager } from 'agentic-flow/memory';

const memory = new MemoryManager({
  backend: 'postgresql',
  connection: 'postgresql://localhost/agentic',
  namespace: 'project1'
});
```

#### Methods

##### `store(key: string, value: any, metadata?: Metadata): Promise<void>`

Store data in memory.

```typescript
await memory.store('user_preferences', {
  theme: 'dark',
  language: 'en'
}, {
  ttl: 86400, // 24 hours
  tags: ['user', 'preferences']
});
```

##### `retrieve(key: string): Promise<any>`

Retrieve data from memory.

```typescript
const preferences = await memory.retrieve('user_preferences');
```

##### `search(query: SearchQuery): Promise<MemoryItem[]>`

Search memory with complex queries.

```typescript
const results = await memory.search({
  tags: ['conversation'],
  timeRange: { start: '2024-01-01', end: '2024-12-31' },
  limit: 10
});
```

##### `vectorSearch(embedding: number[], options?: VectorSearchOptions): Promise<MemoryItem[]>`

Semantic search using embeddings.

```typescript
const similar = await memory.vectorSearch(queryEmbedding, {
  threshold: 0.8,
  limit: 5
});
```

### Memory Backends

```typescript
// SQLite (default)
const sqliteMemory = new MemoryManager({
  backend: 'sqlite',
  path: './memory.db'
});

// PostgreSQL
const pgMemory = new MemoryManager({
  backend: 'postgresql',
  connection: process.env.DATABASE_URL
});

// Redis
const redisMemory = new MemoryManager({
  backend: 'redis',
  connection: {
    host: 'localhost',
    port: 6379
  }
});

// In-memory (testing)
const inMemory = new MemoryManager({
  backend: 'memory'
});
```

## Event API

### EventEmitter

Event-driven architecture for Agentic Flow.

```typescript
import { EventEmitter } from 'agentic-flow/events';

const events = new EventEmitter();

// Subscribe to events
events.on('workflow.started', (data) => {
  console.log('Workflow started:', data.workflowId);
});

events.on('agent.completed', (data) => {
  console.log('Agent completed:', data.agentName, data.duration);
});

// Emit events
events.emit('custom.event', { data: 'value' });
```

### Built-in Events

```typescript
// Workflow events
'workflow.started'
'workflow.completed'
'workflow.failed'
'workflow.step.started'
'workflow.step.completed'

// Agent events
'agent.started'
'agent.completed'
'agent.failed'
'agent.token.usage'

// Provider events
'provider.request'
'provider.response'
'provider.error'
'provider.retry'

// Memory events
'memory.stored'
'memory.retrieved'
'memory.deleted'
'memory.search'

// System events
'system.ready'
'system.error'
'system.shutdown'
```

### Event Handlers

```typescript
// Async event handlers
events.on('workflow.completed', async (data) => {
  await saveResults(data);
  await notifyUser(data);
});

// Error handling
events.on('error', (error) => {
  logger.error('System error:', error);
  // Handle error
});

// Once listeners
events.once('system.ready', () => {
  console.log('System initialized');
});

// Remove listeners
const handler = (data) => console.log(data);
events.on('event', handler);
events.off('event', handler);
```

## CLI API

### Command Registration

```typescript
import { CLI } from 'agentic-flow/cli';

// Register custom command
CLI.registerCommand({
  name: 'custom',
  description: 'Custom command',
  options: [
    { name: 'option', type: 'string', description: 'An option' }
  ],
  action: async (options) => {
    // Command implementation
  }
});
```

### Programmatic CLI Usage

```typescript
import { CLI } from 'agentic-flow/cli';

// Execute CLI commands programmatically
const result = await CLI.execute(['run', 'workflow.yaml', '--input', 'test']);

// Parse arguments
const args = CLI.parse(['--provider', 'openai', '--model', 'gpt-4']);
```

## Plugin API

### Creating Plugins

```typescript
import { Plugin } from 'agentic-flow/plugins';

export class MyPlugin implements Plugin {
  name = 'my-plugin';
  version = '1.0.0';
  
  async initialize(flow: AgenticFlow): Promise<void> {
    // Plugin initialization
    flow.events.on('workflow.started', this.onWorkflowStart);
  }
  
  async destroy(): Promise<void> {
    // Cleanup
  }
  
  // Plugin methods
  private onWorkflowStart = (data) => {
    console.log('Workflow started:', data);
  };
}
```

### Plugin Lifecycle

```typescript
interface Plugin {
  name: string;
  version: string;
  dependencies?: string[];
  
  // Lifecycle methods
  initialize(flow: AgenticFlow): Promise<void>;
  destroy(): Promise<void>;
  
  // Optional hooks
  beforeWorkflow?(workflow: Workflow): Promise<void>;
  afterWorkflow?(workflow: Workflow, result: any): Promise<void>;
  beforeAgent?(agent: Agent, task: Task): Promise<void>;
  afterAgent?(agent: Agent, result: any): Promise<void>;
}
```

### Using Plugins

```typescript
// In configuration
const config = {
  plugins: [
    'agentic-plugin-logger',
    'agentic-plugin-metrics',
    { 
      name: 'custom-plugin',
      options: { debug: true }
    }
  ]
};

// Programmatically
import { MyPlugin } from './my-plugin';

flow.usePlugin(new MyPlugin());
```

## Type Definitions

### Core Types

```typescript
interface Context {
  input?: any;
  params?: Record<string, any>;
  memory?: Record<string, any>;
  metadata?: Record<string, any>;
}

interface Result {
  output: any;
  usage?: Usage;
  duration?: number;
  metadata?: Record<string, any>;
}

interface Usage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cost?: number;
}

interface Message {
  role: 'system' | 'user' | 'assistant';
  content: string;
  metadata?: Record<string, any>;
}

interface Task {
  action: string;
  input: any;
  context?: Context;
  timeout?: number;
}

interface TaskResult {
  success: boolean;
  output?: any;
  error?: Error;
  usage?: Usage;
}
```

## Error Handling

### Error Types

```typescript
import { 
  AgenticError,
  ProviderError,
  WorkflowError,
  ValidationError,
  MemoryError 
} from 'agentic-flow/errors';

try {
  await flow.run('workflow.yaml');
} catch (error) {
  if (error instanceof ProviderError) {
    // Handle provider-specific errors
    console.error('Provider error:', error.provider, error.message);
  } else if (error instanceof WorkflowError) {
    // Handle workflow errors
    console.error('Workflow error:', error.workflow, error.step);
  }
}
```

### Custom Errors

```typescript
class CustomError extends AgenticError {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'CustomError';
  }
}

throw new CustomError('Something went wrong', 'CUSTOM_001');
```

## Best Practices

1. **Always handle errors** - Use try-catch blocks for async operations
2. **Set timeouts** - Prevent hanging operations
3. **Use memory wisely** - Clean up old data regularly
4. **Monitor token usage** - Track costs and limits
5. **Implement retries** - Handle transient failures
6. **Log appropriately** - Use structured logging
7. **Version workflows** - Maintain backward compatibility
8. **Test thoroughly** - Unit and integration tests

## Examples

See the [examples directory](./examples/) for complete working examples of all API features.