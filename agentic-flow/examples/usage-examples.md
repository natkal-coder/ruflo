# Agentic Flow CLI Usage Examples

## Project Initialization

### Basic Project
```bash
agentic-flow init my-ai-project
```

### Advanced Project with TypeScript and API
```bash
agentic-flow init advanced-project --template advanced --git
```

### Custom Configuration
```bash
agentic-flow init enterprise-app --skip-install --force
```

## Agent Management

### Spawn Different Agent Types
```bash
# Research agent
agentic-flow agent spawn researcher --name "Data Researcher"

# Development agent with specific capabilities
agentic-flow agent spawn developer --name "Code Generator" --capabilities "code-generation,testing,documentation"

# Multiple parallel agents
agentic-flow agent spawn analyst --parallel 3 --auto-start

# Custom agent
agentic-flow agent spawn custom --name "Custom Bot" --model "gpt-4"
```

### Agent Operations
```bash
# List all agents
agentic-flow agent list

# Filter by status
agentic-flow agent list --status running

# Get detailed info
agentic-flow agent info researcher-01

# Start/stop agents
agentic-flow agent start researcher-01
agentic-flow agent stop researcher-01 --force

# Remove agent
agentic-flow agent remove researcher-01
```

## Workflow Management

### Create Workflows
```bash
# Interactive workflow creation
agentic-flow workflow create

# From YAML file
agentic-flow workflow create --file examples/workflow-example.yaml

# Using template
agentic-flow workflow create --template data-pipeline
```

### Workflow Operations
```bash
# List workflows
agentic-flow workflow list

# Run workflow
agentic-flow workflow run data-analysis-pipeline

# Run with parameters
agentic-flow workflow run analysis --params '{"apiKey": "xxx", "dataSource": "prod"}'

# Activate/deactivate
agentic-flow workflow activate analysis-pipeline
agentic-flow workflow deactivate analysis-pipeline

# Export workflow
agentic-flow workflow export analysis --format yaml -o my-workflow.yaml
```

## Help and Documentation

### Get Help
```bash
# General help
agentic-flow help

# Command-specific help
agentic-flow help agent
agentic-flow help workflow
agentic-flow help init

# Detailed help
agentic-flow agent --help
agentic-flow workflow create --help
```

## Advanced Usage

### Debug Mode
```bash
agentic-flow --debug agent spawn researcher
agentic-flow --debug workflow run analysis
```

### Quiet Mode
```bash
agentic-flow --quiet workflow list
```

### JSON Output
```bash
agentic-flow agent list --json
agentic-flow workflow list --json
```

## Configuration Examples

### Project Structure After Init
```
my-ai-project/
├── .agentic-flow/
│   ├── config.json
│   ├── logs/
│   ├── cache/
│   └── data/
├── src/
│   ├── agents/
│   ├── workflows/
│   ├── lib/
│   └── utils/
├── package.json
├── tsconfig.json (if TypeScript)
├── README.md
└── .env.example
```

### Sample Configuration
```json
{
  "version": "1.0",
  "project": {
    "id": "uuid-here",
    "name": "my-ai-project",
    "framework": "claude-flow",
    "features": ["workflows", "monitoring", "memory"]
  },
  "agents": {
    "researcher-01": {
      "id": "researcher-01",
      "name": "Data Researcher",
      "type": "researcher",
      "status": "running",
      "capabilities": ["research", "data-analysis"],
      "model": "claude-3"
    }
  },
  "workflows": {
    "analysis-pipeline": {
      "id": "analysis-pipeline",
      "name": "Data Analysis Pipeline",
      "status": "active",
      "trigger": { "type": "schedule", "schedule": "0 9 * * 1" }
    }
  },
  "settings": {
    "logLevel": "info",
    "maxConcurrentAgents": 10,
    "memoryBackend": "sqlite",
    "apiPort": 3000
  }
}
```

## Error Handling Examples

### Common Errors and Solutions
```bash
# Error: No configuration found
$ agentic-flow agent list
Error: No Agentic Flow configuration found
Suggestions:
  • Run "agentic-flow init" to initialize a project
  • Make sure you are in an Agentic Flow project directory

# Error: Agent not found
$ agentic-flow agent start invalid-id
Error: Agent not found: invalid-id
Suggestions:
  • List available agents with "agentic-flow agent list"
  • Create a new agent with "agentic-flow agent spawn"

# Error: Workflow execution failed
$ agentic-flow workflow run broken-workflow
Error: Workflow execution failed: Step validation failed
Suggestions:
  • Check workflow definition for syntax errors
  • Ensure all referenced agents exist
  • Validate step dependencies
```

## Best Practices

### 1. Project Organization
- Use descriptive names for agents and workflows
- Organize workflows by domain or purpose
- Maintain clean configuration files

### 2. Agent Management
- Start with simple agent types before creating custom ones
- Monitor agent performance and resource usage
- Use parallel agents for independent tasks

### 3. Workflow Design
- Break complex workflows into smaller, manageable steps
- Use conditional steps for optional operations
- Implement proper error handling and recovery

### 4. Development Workflow
```bash
# 1. Initialize project
agentic-flow init my-project && cd my-project

# 2. Create agents
agentic-flow agent spawn researcher --name "Data Collector"
agentic-flow agent spawn analyst --name "Data Processor"

# 3. Create workflow
agentic-flow workflow create data-pipeline

# 4. Test workflow
agentic-flow workflow run data-pipeline --watch

# 5. Activate for production
agentic-flow workflow activate data-pipeline
```