# Quick Start Guide

Get up and running with Agentic Flow in just 5 minutes! This guide will walk you through installation, configuration, and running your first AI workflow.

## Prerequisites

- Node.js 18+ or Python 3.8+
- npm or yarn package manager
- API keys for at least one AI provider (OpenAI, Anthropic, etc.)

## Installation

### Using npm (Recommended)

```bash
# Install globally
npm install -g agentic-flow

# Or install in your project
npm install agentic-flow
```

### Using yarn

```bash
# Install globally
yarn global add agentic-flow

# Or install in your project
yarn add agentic-flow
```

### Using Python

```bash
# Install via pip
pip install agentic-flow

# Or using poetry
poetry add agentic-flow
```

## Initial Setup

### 1. Initialize Your Project

```bash
# Create a new project
agentic init my-ai-project
cd my-ai-project

# Or initialize in existing directory
agentic init .
```

This creates:
```
my-ai-project/
├── .agentic/           # Configuration directory
│   ├── config.yaml     # Main configuration
│   └── providers.yaml  # Provider settings
├── workflows/          # Workflow definitions
├── agents/            # Agent definitions
├── memory/            # Persistent memory
└── README.md          # Project documentation
```

### 2. Configure Providers

```bash
# Interactive configuration
agentic config

# Or set directly
agentic config set provider.openai.key sk-your-api-key
agentic config set provider.anthropic.key sk-ant-your-key
```

### 3. Verify Installation

```bash
# Check version
agentic --version

# Test provider connection
agentic test providers

# View configuration
agentic config list
```

## Your First Workflow

### Simple Chat Example

Create `workflows/hello-chat.yaml`:

```yaml
name: hello-chat
description: Simple interactive chat workflow
version: 1.0.0

agents:
  assistant:
    provider: openai
    model: gpt-4
    system_prompt: |
      You are a helpful AI assistant. Be concise and friendly.

workflow:
  - type: chat
    agent: assistant
    initial_message: "Hello! How can I help you today?"
```

Run it:
```bash
agentic run workflows/hello-chat.yaml
```

### Task Processing Example

Create `workflows/task-processor.yaml`:

```yaml
name: task-processor
description: Process tasks with multiple agents
version: 1.0.0

agents:
  analyzer:
    provider: openai
    model: gpt-4
    system_prompt: "Analyze tasks and break them into steps"
  
  executor:
    provider: anthropic
    model: claude-3-opus
    system_prompt: "Execute task steps and provide results"

workflow:
  - type: sequential
    steps:
      - agent: analyzer
        action: analyze
        input: "{{ task }}"
      
      - agent: executor
        action: execute
        input: "{{ previous.output }}"
```

Run with input:
```bash
agentic run workflows/task-processor.yaml --input "Create a Python web scraper"
```

## Core Commands

### Project Management

```bash
# Initialize project
agentic init [directory]

# Clone example project
agentic clone examples/multi-agent-rag

# Update dependencies
agentic update
```

### Configuration

```bash
# Interactive configuration
agentic config

# Set configuration values
agentic config set <key> <value>

# Get configuration value
agentic config get <key>

# List all configuration
agentic config list
```

### Workflow Execution

```bash
# Run a workflow
agentic run <workflow-file>

# Run with inputs
agentic run <workflow> --input "Your input text"

# Run with parameters
agentic run <workflow> --param key=value

# Run in watch mode (auto-reload)
agentic run <workflow> --watch
```

### Agent Management

```bash
# List available agents
agentic agents list

# Create new agent
agentic agents create <name>

# Test agent
agentic agents test <name>

# Deploy agent
agentic agents deploy <name>
```

## Basic Workflow Patterns

### 1. Sequential Processing

```yaml
workflow:
  - type: sequential
    steps:
      - agent: researcher
        action: search
        query: "{{ topic }}"
      
      - agent: writer
        action: summarize
        content: "{{ previous.output }}"
      
      - agent: editor
        action: review
        text: "{{ previous.output }}"
```

### 2. Parallel Execution

```yaml
workflow:
  - type: parallel
    agents:
      - name: agent1
        task: "Process data set A"
      - name: agent2
        task: "Process data set B"
      - name: agent3
        task: "Process data set C"
    
  - type: aggregate
    agent: coordinator
    inputs: "{{ parallel.outputs }}"
```

### 3. Conditional Branching

```yaml
workflow:
  - type: condition
    if: "{{ confidence > 0.8 }}"
    then:
      - agent: executor
        action: proceed
    else:
      - agent: reviewer
        action: verify
```

### 4. Loop Processing

```yaml
workflow:
  - type: foreach
    items: "{{ data_items }}"
    do:
      - agent: processor
        action: process
        item: "{{ item }}"
```

## Provider Configuration

### OpenAI

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    organization: your-org-id
    default_model: gpt-4
    timeout: 30
    max_retries: 3
```

### Anthropic

```yaml
providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    default_model: claude-3-opus
    max_tokens: 4096
```

### Multiple Providers

```yaml
providers:
  primary:
    type: openai
    api_key: ${OPENAI_API_KEY}
    model: gpt-4
  
  fallback:
    type: anthropic
    api_key: ${ANTHROPIC_API_KEY}
    model: claude-3-sonnet
  
  local:
    type: ollama
    base_url: http://localhost:11434
    model: llama2
```

## Memory and State

### Enable Memory

```yaml
memory:
  enabled: true
  type: persistent
  backend: sqlite
  path: ./memory/project.db
```

### Use in Workflows

```yaml
workflow:
  - type: remember
    key: user_preference
    value: "{{ input.preference }}"
  
  - type: recall
    key: user_preference
    as: stored_preference
  
  - agent: assistant
    prompt: "Based on preference: {{ stored_preference }}"
```

## Environment Variables

Create `.env` file:

```bash
# Provider API Keys
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GOOGLE_AI_KEY=...
COHERE_API_KEY=...

# Agentic Flow Settings
AGENTIC_LOG_LEVEL=info
AGENTIC_MEMORY_BACKEND=sqlite
AGENTIC_CACHE_DIR=./.agentic/cache
```

## Next Steps

Now that you have Agentic Flow running:

1. **Explore Examples**: Check out the [examples directory](./examples/) for more workflows
2. **Learn Providers**: Read about [provider integration](./providers/)
3. **Advanced Features**: Explore [advanced patterns](./examples/advanced-patterns.md)
4. **Build Custom Agents**: See [agent development guide](./agents/development.md)

## Common Issues

### Provider Connection Failed

```bash
# Test provider connection
agentic test provider openai

# Check configuration
agentic config get provider.openai
```

### Workflow Not Found

```bash
# List available workflows
agentic workflows list

# Validate workflow
agentic validate workflows/my-workflow.yaml
```

### Memory Errors

```bash
# Reset memory
agentic memory clear

# Check memory status
agentic memory status
```

## Getting Help

- Run `agentic help` for command documentation
- Check [troubleshooting guide](./troubleshooting.md)
- Join our [Discord community](https://discord.gg/agentic-flow)
- Report issues on [GitHub](https://github.com/agentic-flow/agentic-flow/issues)