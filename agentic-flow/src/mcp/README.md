# Agentic Flow MCP Server

A comprehensive Model Context Protocol (MCP) server that provides advanced AI agent orchestration, workflow management, goal decomposition, and machine learning capabilities for Claude Code and other MCP-compatible clients.

## Features

### 🤖 Agent Management
- **Agent Spawning**: Create specialized AI agents with custom capabilities
- **Agent Coordination**: Orchestrate multiple agents for complex tasks
- **Inter-Agent Communication**: Enable agents to exchange messages and data
- **Agent Monitoring**: Track performance, status, and health metrics

### 🔄 Workflow Engine
- **Workflow Creation**: Define complex multi-step workflows with dependencies
- **Workflow Execution**: Run workflows asynchronously with real-time monitoring
- **Template System**: Use predefined templates for common workflow patterns
- **Trigger Management**: Schedule workflows or trigger based on events

### 🎯 Goal Management
- **Goal Parsing**: Convert natural language descriptions into structured goals
- **Goal Decomposition**: Break down complex goals into manageable subgoals
- **Progress Tracking**: Monitor goal completion with detailed metrics
- **Hierarchy Management**: Maintain goal relationships and dependencies

### 🧠 Learning Engine
- **Model Training**: Train ML models with various algorithms and architectures
- **Prediction**: Make predictions using trained models
- **Model Management**: Export, import, and version control models
- **Performance Analytics**: Detailed metrics and benchmarking

## Installation

```bash
cd agentic-flow/src/mcp
npm install
```

## Development

```bash
# Build the project
npm run build

# Run in development mode
npm run dev

# Type checking
npm run type-check
```

## Usage

### Starting the Server

```bash
# Production
npm start

# Development with auto-reload
npm run dev
```

### Integration with Claude Code

Add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "agentic-flow": {
      "command": "node",
      "args": ["/path/to/agentic-flow/src/mcp/dist/index.js"],
      "env": {
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

## Available Tools

### Agent Tools

- `agent_spawn` - Create new AI agents
- `agent_coordinate` - Coordinate multiple agents
- `agent_communicate` - Send messages between agents
- `agent_list` - List all agents
- `agent_status` - Get agent details
- `agent_metrics` - Get agent performance metrics
- `agent_terminate` - Terminate agents

### Workflow Tools

- `workflow_create` - Create new workflows
- `workflow_execute` - Execute workflows
- `workflow_list` - List all workflows
- `workflow_status` - Get workflow details
- `workflow_delete` - Delete workflows
- `workflow_execution` - Get execution details
- `workflow_template` - Create from templates

### Goal Tools

- `goal_parse` - Parse natural language goals
- `goal_decompose` - Break down goals into subgoals
- `goal_list` - List all goals
- `goal_status` - Get goal details
- `goal_update` - Update goal status/metrics
- `goal_metrics` - Get goal performance data
- `goal_hierarchy` - Get goal hierarchy

### Learning Tools

- `learning_train` - Train ML models
- `learning_predict` - Make predictions
- `model_list` - List all models
- `model_status` - Get model details
- `model_metrics` - Get model performance
- `model_export` - Export models
- `model_import` - Import models
- `model_delete` - Delete models

## Examples

### Creating and Coordinating Agents

```javascript
// Spawn a coordinator agent
const coordinator = await agent_spawn({
  name: "Task Coordinator",
  type: "coordinator",
  capabilities: ["orchestration", "task-distribution"]
});

// Spawn executor agents
const executor1 = await agent_spawn({
  name: "Code Executor",
  type: "executor",
  capabilities: ["code-execution", "testing"]
});

const executor2 = await agent_spawn({
  name: "Data Processor",
  type: "executor", 
  capabilities: ["data-processing", "analysis"]
});

// Coordinate agents for a task
await agent_coordinate({
  agents: [coordinator.id, executor1.id, executor2.id],
  task: "Build and test a data processing pipeline",
  strategy: "hierarchical"
});
```

### Creating Workflows

```javascript
// Create a CI/CD workflow
const workflow = await workflow_create({
  name: "CI/CD Pipeline",
  description: "Continuous integration and deployment",
  steps: [
    {
      name: "Code Checkout",
      type: "agent_action",
      config: { capability: "version-control", action: "checkout" }
    },
    {
      name: "Build",
      type: "agent_action", 
      config: { capability: "build-system", action: "build" },
      dependencies: ["code-checkout"]
    },
    {
      name: "Test",
      type: "parallel",
      config: {
        steps: [
          {
            name: "Unit Tests",
            type: "agent_action",
            config: { capability: "testing", action: "unit-test" }
          },
          {
            name: "Integration Tests", 
            type: "agent_action",
            config: { capability: "testing", action: "integration-test" }
          }
        ]
      },
      dependencies: ["build"]
    }
  ]
});

// Execute the workflow
await workflow_execute({
  workflowId: workflow.id,
  async: true
});
```

### Goal Management

```javascript
// Parse a complex goal
const goal = await goal_parse({
  description: "Build a scalable web application with user authentication, real-time messaging, and analytics dashboard within 3 months",
  context: {
    priority: "high",
    constraints: ["budget: $50k", "team: 5 developers"]
  }
});

// Decompose into subgoals
const subgoals = await goal_decompose({
  goalId: goal.id,
  strategy: "functional",
  maxDepth: 3
});

// Track progress
await goal_update({
  goalId: goal.id,
  progress: 25,
  metrics: [
    { name: "Completion", value: 25 },
    { name: "Quality", value: 90 }
  ]
});
```

### Machine Learning

```javascript
// Train a classification model
const model = await learning_train({
  type: "classification",
  data: {
    features: [[1, 2, 3], [4, 5, 6], [7, 8, 9]],
    labels: ["class_a", "class_b", "class_a"]
  },
  parameters: {
    epochs: 100,
    batchSize: 32,
    learningRate: 0.001
  }
});

// Make predictions
const prediction = await learning_predict({
  modelId: model.id,
  input: [2, 3, 4]
});
```

## Architecture

### Core Components

- **AgentManager**: Handles agent lifecycle, communication, and coordination
- **WorkflowEngine**: Manages workflow creation, execution, and monitoring  
- **GoalManager**: Processes goal parsing, decomposition, and tracking
- **LearningEngine**: Provides ML training, prediction, and model management

### Tool Handlers

- **AgentTools**: Implements agent-related MCP tools
- **WorkflowTools**: Implements workflow-related MCP tools
- **GoalTools**: Implements goal-related MCP tools
- **LearningTools**: Implements learning-related MCP tools

### Integration Points

The components are designed to work together:

- Goals can automatically create workflows for execution
- Workflow completion updates related goal progress
- Agent performance data feeds into learning models
- Learning models can optimize agent coordination strategies

## Configuration

### Environment Variables

- `LOG_LEVEL`: Set logging level (debug, info, warn, error)
- `NODE_ENV`: Environment mode (development, production)

### Logging

Logs are written to:
- Console (formatted with colors in development)
- `logs/combined.log` - All logs
- `logs/error.log` - Error logs only
- `logs/exceptions.log` - Uncaught exceptions

## Performance

The MCP server is optimized for concurrent operations:

- **Parallel Tool Execution**: Multiple tools can run simultaneously
- **Asynchronous Operations**: Non-blocking execution for long-running tasks
- **Efficient Memory Management**: Automatic cleanup and resource management
- **Scalable Architecture**: Supports hundreds of concurrent agents and workflows

## Error Handling

Comprehensive error handling includes:

- **Graceful Degradation**: System continues operating when components fail
- **Detailed Error Messages**: Clear descriptions for troubleshooting
- **Automatic Recovery**: Self-healing for transient failures
- **Logging Integration**: All errors are logged with context

## Security

Security features include:

- **Input Validation**: All tool parameters are validated with Zod schemas
- **Resource Limits**: Prevents resource exhaustion attacks
- **Isolation**: Agents and workflows run in isolated contexts
- **Audit Logging**: All operations are logged for security review

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.