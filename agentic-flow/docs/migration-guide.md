# Migration Guide: Claude Flow to Agentic Flow

This comprehensive guide will help you migrate your existing Claude Flow projects to Agentic Flow. While Agentic Flow maintains backward compatibility for most features, it introduces new capabilities and some architectural changes.

## Overview

Agentic Flow is the next evolution of Claude Flow, offering:
- Multi-provider AI support (not just Anthropic)
- Enhanced plugin architecture
- Improved performance and scalability
- Better error handling and recovery
- Extended workflow capabilities

## Migration Paths

### Quick Migration (Recommended for Simple Projects)

```bash
# Install migration tool
npm install -g agentic-flow-migrate

# Run automated migration
agentic-migrate run ./my-claude-flow-project

# Test the migrated project
cd ./my-claude-flow-project
agentic test
```

### Manual Migration (For Complex Projects)

Follow the step-by-step guide below for full control over the migration process.

## Pre-Migration Checklist

- [ ] Backup your Claude Flow project
- [ ] Document custom modifications
- [ ] Note any deprecated features in use
- [ ] Update Node.js to version 18+
- [ ] Review breaking changes below

## Breaking Changes

### 1. Configuration Format

**Claude Flow (old):**
```json
{
  "claudeApiKey": "sk-ant-...",
  "model": "claude-3-opus",
  "maxTokens": 4096
}
```

**Agentic Flow (new):**
```yaml
providers:
  anthropic:
    type: anthropic
    apiKey: ${ANTHROPIC_API_KEY}
    defaultModel: claude-3-opus
    maxTokens: 4096
  
  # Additional providers
  openai:
    type: openai
    apiKey: ${OPENAI_API_KEY}
    defaultModel: gpt-4
```

### 2. Agent Definition

**Claude Flow:**
```javascript
const agent = new ClaudeAgent({
  name: 'assistant',
  prompt: 'You are a helpful assistant'
});
```

**Agentic Flow:**
```javascript
const agent = new Agent({
  name: 'assistant',
  provider: 'anthropic', // or 'openai', 'google', etc.
  model: 'claude-3-opus',
  systemPrompt: 'You are a helpful assistant'
});
```

### 3. Workflow Syntax

**Claude Flow:**
```yaml
workflow:
  - agent: researcher
    task: research
    input: "{{ query }}"
  
  - agent: writer
    task: write
    input: "{{ previous }}"
```

**Agentic Flow:**
```yaml
workflow:
  - type: sequential
    steps:
      - agent: researcher
        action: research
        input: "{{ query }}"
      
      - agent: writer
        action: write
        input: "{{ previous.output }}"
```

### 4. Memory API

**Claude Flow:**
```javascript
memory.set('key', 'value');
const value = memory.get('key');
```

**Agentic Flow:**
```javascript
await memory.store('key', 'value');
const value = await memory.retrieve('key');
```

## Step-by-Step Migration

### Step 1: Install Agentic Flow

```bash
# Install globally
npm install -g agentic-flow

# Or add to your project
npm install agentic-flow
```

### Step 2: Initialize Migration

```bash
# In your Claude Flow project directory
agentic-migrate init

# This creates:
# - .agentic/migration.json (migration configuration)
# - .agentic/backup/ (backup of original files)
```

### Step 3: Update Configuration

Convert your Claude Flow configuration to Agentic Flow format:

```bash
# Automated conversion
agentic-migrate convert-config

# Or manually create .agentic/config.yaml
```

Example configuration migration:

```yaml
# .agentic/config.yaml
version: 2.0
compatibility:
  claudeFlow: true  # Enable compatibility mode

providers:
  # Keep using Anthropic as primary
  anthropic:
    type: anthropic
    apiKey: ${ANTHROPIC_API_KEY}
    defaultModel: claude-3-opus
    maxTokens: 4096
  
  # Add new providers as needed
  openai:
    type: openai
    apiKey: ${OPENAI_API_KEY}
    defaultModel: gpt-4

# Map old Claude Flow settings
aliases:
  claude: anthropic  # Map 'claude' references to 'anthropic'

# Migrate memory settings
memory:
  backend: sqlite  # Or your current backend
  path: ./memory/claude-flow.db
  migration:
    importFrom: ./claude-flow-data.json
```

### Step 4: Update Agent Definitions

**Automated:**
```bash
agentic-migrate update-agents
```

**Manual Example:**

```javascript
// Old Claude Flow agent
const researchAgent = new ClaudeAgent({
  name: 'researcher',
  prompt: 'You are a research assistant',
  temperature: 0.7
});

// New Agentic Flow agent
const researchAgent = new Agent({
  name: 'researcher',
  provider: 'anthropic',
  model: 'claude-3-opus',
  systemPrompt: 'You are a research assistant',
  temperature: 0.7
});
```

### Step 5: Migrate Workflows

**Automated:**
```bash
agentic-migrate update-workflows
```

**Manual Workflow Migration:**

```yaml
# Old Claude Flow workflow
name: research-workflow
agents:
  - name: researcher
    prompt: "Research assistant"
  - name: writer
    prompt: "Content writer"

workflow:
  - agent: researcher
    task: "Research topic"
  - agent: writer
    task: "Write article"

# New Agentic Flow workflow
name: research-workflow
version: 1.0.0

agents:
  researcher:
    provider: anthropic
    model: claude-3-opus
    systemPrompt: "Research assistant"
  
  writer:
    provider: anthropic
    model: claude-3-opus
    systemPrompt: "Content writer"

workflow:
  - type: sequential
    steps:
      - agent: researcher
        action: execute
        task: "Research topic"
      
      - agent: writer
        action: execute
        task: "Write article based on {{ previous.output }}"
```

### Step 6: Update API Calls

**Memory API:**
```javascript
// Old Claude Flow
memory.set('user_prefs', prefs);
const prefs = memory.get('user_prefs');
memory.delete('user_prefs');

// New Agentic Flow
await memory.store('user_prefs', prefs);
const prefs = await memory.retrieve('user_prefs');
await memory.delete('user_prefs');
```

**Agent Execution:**
```javascript
// Old Claude Flow
const result = agent.execute(task);

// New Agentic Flow
const result = await agent.execute({
  action: 'process',
  input: task,
  context: { /* optional context */ }
});
```

**Workflow Execution:**
```javascript
// Old Claude Flow
const flow = new ClaudeFlow(config);
flow.run(workflow, input);

// New Agentic Flow
const flow = new AgenticFlow(config);
await flow.run(workflow, {
  input: input,
  params: { /* optional parameters */ }
});
```

### Step 7: Update Dependencies

Update your `package.json`:

```json
{
  "dependencies": {
    // Remove
    "claude-flow": "^1.x.x",
    
    // Add
    "agentic-flow": "^2.0.0"
  }
}
```

Update imports:

```javascript
// Old
import { ClaudeFlow, ClaudeAgent } from 'claude-flow';

// New
import { AgenticFlow, Agent } from 'agentic-flow';
```

### Step 8: Test Migration

```bash
# Run migration tests
agentic-migrate test

# Run your test suite
npm test

# Test specific workflows
agentic test workflow ./workflows/my-workflow.yaml
```

## Compatibility Mode

Agentic Flow includes a compatibility mode for gradual migration:

```yaml
# .agentic/config.yaml
compatibility:
  claudeFlow: true
  deprecationWarnings: true
  strictMode: false
```

This allows you to:
- Use old Claude Flow syntax
- Get warnings about deprecated features
- Gradually update your codebase

## Feature Mapping

| Claude Flow Feature | Agentic Flow Equivalent | Notes |
|-------------------|------------------------|-------|
| ClaudeAgent | Agent | Now supports multiple providers |
| ClaudeFlow | AgenticFlow | Enhanced with plugin support |
| memory.set/get | memory.store/retrieve | Now async |
| Swarm coordination | Enhanced swarm mode | Better performance |
| SPARC modes | SPARC+ modes | Extended capabilities |
| Terminal integration | Terminal manager | Improved isolation |

## New Features Available

After migration, you gain access to:

### 1. Multi-Provider Support
```javascript
// Use different providers for different tasks
const researcher = new Agent({
  provider: 'openai',
  model: 'gpt-4'
});

const writer = new Agent({
  provider: 'anthropic',
  model: 'claude-3-opus'
});
```

### 2. Enhanced Workflows
```yaml
workflow:
  # Parallel execution
  - type: parallel
    agents: [agent1, agent2, agent3]
  
  # Conditional branching
  - type: condition
    if: "{{ score > 0.8 }}"
    then: highConfidenceFlow
    else: reviewFlow
  
  # Loop processing
  - type: foreach
    items: "{{ data_array }}"
    agent: processor
```

### 3. Plugin System
```javascript
// Use plugins for extended functionality
flow.use(new MetricsPlugin());
flow.use(new LoggingPlugin());
flow.use(new CustomPlugin());
```

### 4. Better Error Handling
```javascript
try {
  await flow.run(workflow);
} catch (error) {
  if (error instanceof ProviderError) {
    // Handle provider-specific errors
  } else if (error instanceof WorkflowError) {
    // Handle workflow errors
  }
}
```

## Migration Tools

### CLI Commands

```bash
# Analyze project for migration readiness
agentic-migrate analyze

# Generate migration report
agentic-migrate report

# Perform dry run
agentic-migrate run --dry-run

# Run migration with specific options
agentic-migrate run --skip-backup --update-imports

# Rollback migration
agentic-migrate rollback
```

### Validation Tools

```bash
# Validate migrated configuration
agentic validate config

# Validate workflows
agentic validate workflows

# Check compatibility
agentic check compatibility
```

## Common Migration Issues

### Issue 1: API Key Configuration

**Problem:** API keys not found after migration

**Solution:**
```bash
# Set environment variables
export ANTHROPIC_API_KEY=sk-ant-...
export OPENAI_API_KEY=sk-...

# Or update config
agentic config set provider.anthropic.apiKey YOUR_KEY
```

### Issue 2: Memory Data Loss

**Problem:** Previous memory data not accessible

**Solution:**
```yaml
# In .agentic/config.yaml
memory:
  migration:
    importFrom: ./claude-flow-data.json
    importFormat: claudeflow-v1
```

### Issue 3: Workflow Syntax Errors

**Problem:** Old workflow syntax not recognized

**Solution:**
```bash
# Enable compatibility mode
agentic config set compatibility.claudeFlow true

# Or update workflow syntax
agentic-migrate update-workflow ./workflows/old-workflow.yaml
```

## Performance Improvements

After migration, optimize performance:

```yaml
# .agentic/config.yaml
performance:
  # Enable caching
  cache:
    enabled: true
    ttl: 3600
  
  # Connection pooling
  connections:
    poolSize: 10
    timeout: 30000
  
  # Parallel execution
  execution:
    maxConcurrent: 5
    batchSize: 10
```

## Rollback Procedure

If you need to rollback:

```bash
# Restore from backup
agentic-migrate rollback

# Or manually restore
cp -r .agentic/backup/* .
npm install claude-flow
```

## Support and Resources

### Documentation
- [Agentic Flow Docs](https://docs.agentic-flow.com)
- [API Reference](./api-reference.md)
- [Examples](./examples/)

### Community
- [Discord Server](https://discord.gg/agentic-flow)
- [GitHub Discussions](https://github.com/agentic-flow/agentic-flow/discussions)
- [Stack Overflow Tag](https://stackoverflow.com/questions/tagged/agentic-flow)

### Professional Support
- Email: support@agentic-flow.com
- Enterprise support available

## Next Steps

1. **Explore New Features**: Try multi-provider capabilities
2. **Optimize Performance**: Implement caching and parallel execution
3. **Add Monitoring**: Use the metrics plugin
4. **Join Community**: Share your migration experience

Congratulations on migrating to Agentic Flow! Enjoy the enhanced capabilities and improved performance.