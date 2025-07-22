// MCP Integration for Mastra - Connecting claude-flow and agentic-flow MCP servers
import { createMcpClient } from '@mastra/mcp';
import { z } from 'zod';

// Claude Flow MCP Server Configuration
export const claudeFlowMcpConfig = {
  name: 'claude-flow-mcp',
  description: 'Claude Flow MCP Server - Advanced AI orchestration and swarm intelligence',
  command: 'npx',
  args: ['claude-flow', 'mcp', 'start'],
  env: {
    CLAUDE_FLOW_MODE: 'mcp',
    CLAUDE_FLOW_PORT: '5001'
  }
};

// Agentic Flow MCP Server Configuration
export const agenticFlowMcpConfig = {
  name: 'agentic-flow-mcp',
  description: 'Agentic Flow MCP Server - Multi-agent orchestration platform',
  command: 'node',
  args: ['../../src/mcp/dist/index.js'],
  env: {
    AGENTIC_FLOW_MODE: 'mcp',
    AGENTIC_FLOW_PORT: '5002'
  }
};

// Create MCP client configurations
export const createMcpClients = async () => {
  const clients = {};
  
  try {
    // Claude Flow MCP Client
    clients.claudeFlow = await createMcpClient({
      name: 'claude-flow',
      version: '1.0.0',
      serverConfig: claudeFlowMcpConfig,
      capabilities: [
        'swarm_init',
        'agent_spawn',
        'task_orchestrate',
        'neural_train',
        'memory_usage',
        'performance_report'
      ]
    });
    
    // Agentic Flow MCP Client  
    clients.agenticFlow = await createMcpClient({
      name: 'agentic-flow',
      version: '1.0.0',
      serverConfig: agenticFlowMcpConfig,
      capabilities: [
        'team_create',
        'team_coordinate',
        'workflow_execute',
        'learning_capture',
        'metric_track',
        'simulation_run'
      ]
    });
    
    console.log('✅ MCP clients initialized successfully');
  } catch (error) {
    console.error('❌ Failed to initialize MCP clients:', error);
  }
  
  return clients;
};

// MCP Tool Schemas
export const mcpToolSchemas = {
  // Claude Flow Tools
  swarmInit: z.object({
    topology: z.enum(['hierarchical', 'mesh', 'ring', 'star']),
    maxAgents: z.number().min(1).max(100).default(8),
    strategy: z.enum(['auto', 'manual', 'adaptive']).default('auto')
  }),
  
  agentSpawn: z.object({
    type: z.enum(['coordinator', 'researcher', 'coder', 'analyst', 'architect']),
    capabilities: z.array(z.string()).optional(),
    swarmId: z.string().optional()
  }),
  
  taskOrchestrate: z.object({
    task: z.string(),
    priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
    dependencies: z.array(z.string()).optional(),
    strategy: z.enum(['parallel', 'sequential', 'adaptive']).default('adaptive')
  }),
  
  // Agentic Flow Tools
  teamCreate: z.object({
    name: z.string(),
    members: z.array(z.object({
      role: z.string(),
      capabilities: z.array(z.string())
    })),
    goal: z.string()
  }),
  
  workflowExecute: z.object({
    workflowId: z.string(),
    input: z.record(z.any()),
    config: z.object({
      timeout: z.number().optional(),
      retries: z.number().optional()
    }).optional()
  }),
  
  learningCapture: z.object({
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(['success', 'failure', 'insight']).default('insight')
  })
};

// MCP Tool Wrappers for Mastra
export const createMcpTools = (mcpClients) => {
  const tools = {};
  
  if (mcpClients.claudeFlow) {
    // Claude Flow MCP Tools
    tools.claudeFlowSwarmInit = {
      id: 'claude-flow-swarm-init',
      description: 'Initialize a Claude Flow swarm with specified topology',
      inputSchema: mcpToolSchemas.swarmInit,
      execute: async ({ context }) => {
        return await mcpClients.claudeFlow.callTool('swarm_init', context);
      }
    };
    
    tools.claudeFlowAgentSpawn = {
      id: 'claude-flow-agent-spawn',
      description: 'Spawn specialized agents in Claude Flow',
      inputSchema: mcpToolSchemas.agentSpawn,
      execute: async ({ context }) => {
        return await mcpClients.claudeFlow.callTool('agent_spawn', context);
      }
    };
    
    tools.claudeFlowTaskOrchestrate = {
      id: 'claude-flow-task-orchestrate',
      description: 'Orchestrate complex tasks with Claude Flow',
      inputSchema: mcpToolSchemas.taskOrchestrate,
      execute: async ({ context }) => {
        return await mcpClients.claudeFlow.callTool('task_orchestrate', context);
      }
    };
  }
  
  if (mcpClients.agenticFlow) {
    // Agentic Flow MCP Tools
    tools.agenticFlowTeamCreate = {
      id: 'agentic-flow-team-create',
      description: 'Create a team in Agentic Flow',
      inputSchema: mcpToolSchemas.teamCreate,
      execute: async ({ context }) => {
        return await mcpClients.agenticFlow.callTool('team_create', context);
      }
    };
    
    tools.agenticFlowWorkflowExecute = {
      id: 'agentic-flow-workflow-execute',
      description: 'Execute a workflow in Agentic Flow',
      inputSchema: mcpToolSchemas.workflowExecute,
      execute: async ({ context }) => {
        return await mcpClients.agenticFlow.callTool('workflow_execute', context);
      }
    };
    
    tools.agenticFlowLearningCapture = {
      id: 'agentic-flow-learning-capture',
      description: 'Capture learning experiences in Agentic Flow',
      inputSchema: mcpToolSchemas.learningCapture,
      execute: async ({ context }) => {
        return await mcpClients.agenticFlow.callTool('learning_capture', context);
      }
    };
  }
  
  return tools;
};

// MCP Resource Access
export const createMcpResources = (mcpClients) => {
  const resources = {};
  
  if (mcpClients.claudeFlow) {
    resources.claudeFlowStatus = {
      id: 'claude-flow-status',
      description: 'Get Claude Flow system status',
      execute: async () => {
        return await mcpClients.claudeFlow.getResource('system/status');
      }
    };
    
    resources.claudeFlowAgents = {
      id: 'claude-flow-agents',
      description: 'List active Claude Flow agents',
      execute: async () => {
        return await mcpClients.claudeFlow.getResource('agents/list');
      }
    };
  }
  
  if (mcpClients.agenticFlow) {
    resources.agenticFlowTeams = {
      id: 'agentic-flow-teams',
      description: 'List Agentic Flow teams',
      execute: async () => {
        return await mcpClients.agenticFlow.getResource('teams/list');
      }
    };
    
    resources.agenticFlowWorkflows = {
      id: 'agentic-flow-workflows',
      description: 'List available Agentic Flow workflows',
      execute: async () => {
        return await mcpClients.agenticFlow.getResource('workflows/list');
      }
    };
  }
  
  return resources;
};

// Export MCP integration utilities
export const mcpIntegration = {
  configs: {
    claudeFlow: claudeFlowMcpConfig,
    agenticFlow: agenticFlowMcpConfig
  },
  createClients: createMcpClients,
  createTools: createMcpTools,
  createResources: createMcpResources,
  schemas: mcpToolSchemas
};

export default mcpIntegration;