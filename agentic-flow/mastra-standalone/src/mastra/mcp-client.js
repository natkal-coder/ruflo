// MCP Client Configuration for Mastra
import { MCPClient } from '@mastra/mcp';
import { createTool } from '@mastra/core';
import { z } from 'zod';

// Initialize MCP Client with servers
export const mcpClient = new MCPClient({
  servers: {
    // Claude Flow MCP Server (stdio-based)
    claudeFlow: {
      command: 'npx',
      args: ['claude-flow', 'mcp', 'start'],
      env: {
        CLAUDE_FLOW_MODE: 'mcp',
        CLAUDE_FLOW_PORT: '5001'
      },
      enableServerLogs: true
    },
    
    // Agentic Flow MCP Server (stdio-based)
    agenticFlow: {
      command: 'node',
      args: ['../../src/mcp/dist/index.js'],
      env: {
        AGENTIC_FLOW_MODE: 'mcp',
        AGENTIC_FLOW_PORT: '5002'
      },
      enableServerLogs: true
    }
  }
});

// Create MCP-aware tools for Mastra
export const createMcpTools = async () => {
  try {
    // Get all tools from MCP servers
    const mcpTools = await mcpClient.getTools();
    
    // Get toolsets grouped by server
    const toolsets = await mcpClient.getToolsets();
    
    console.log('📡 MCP Tools discovered:', Object.keys(mcpTools).length);
    console.log('🔧 MCP Toolsets:', Object.keys(toolsets));
    
    // Create Mastra-compatible tools from MCP tools
    const mastraTools = {};
    
    // Map Claude Flow MCP tools
    if (toolsets.claudeFlow) {
      // Swarm initialization tool
      if (toolsets.claudeFlow.swarm_init) {
        mastraTools.claudeFlowSwarmInit = createTool({
          id: 'claude-flow-swarm-init',
          description: 'Initialize a Claude Flow swarm with specified topology',
          inputSchema: z.object({
            topology: z.enum(['hierarchical', 'mesh', 'ring', 'star']),
            maxAgents: z.number().min(1).max(100).default(8),
            strategy: z.enum(['auto', 'manual', 'adaptive']).default('auto')
          }),
          execute: async ({ context }) => {
            return await toolsets.claudeFlow.swarm_init(context);
          }
        });
      }
      
      // Agent spawning tool
      if (toolsets.claudeFlow.agent_spawn) {
        mastraTools.claudeFlowAgentSpawn = createTool({
          id: 'claude-flow-agent-spawn',
          description: 'Spawn specialized agents in Claude Flow',
          inputSchema: z.object({
            type: z.enum(['coordinator', 'researcher', 'coder', 'analyst']),
            capabilities: z.array(z.string()).optional(),
            swarmId: z.string().optional()
          }),
          execute: async ({ context }) => {
            return await toolsets.claudeFlow.agent_spawn(context);
          }
        });
      }
      
      // Task orchestration tool
      if (toolsets.claudeFlow.task_orchestrate) {
        mastraTools.claudeFlowTaskOrchestrate = createTool({
          id: 'claude-flow-task-orchestrate',
          description: 'Orchestrate complex tasks with Claude Flow',
          inputSchema: z.object({
            task: z.string(),
            priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
            strategy: z.enum(['parallel', 'sequential', 'adaptive']).default('adaptive')
          }),
          execute: async ({ context }) => {
            return await toolsets.claudeFlow.task_orchestrate(context);
          }
        });
      }
    }
    
    // Map Agentic Flow MCP tools
    if (toolsets.agenticFlow) {
      // Team creation tool
      if (toolsets.agenticFlow.team_create) {
        mastraTools.agenticFlowTeamCreate = createTool({
          id: 'agentic-flow-team-create',
          description: 'Create a team in Agentic Flow',
          inputSchema: z.object({
            name: z.string(),
            members: z.array(z.object({
              role: z.string(),
              capabilities: z.array(z.string())
            })),
            goal: z.string()
          }),
          execute: async ({ context }) => {
            return await toolsets.agenticFlow.team_create(context);
          }
        });
      }
      
      // Workflow execution tool
      if (toolsets.agenticFlow.workflow_execute) {
        mastraTools.agenticFlowWorkflowExecute = createTool({
          id: 'agentic-flow-workflow-execute',
          description: 'Execute a workflow in Agentic Flow',
          inputSchema: z.object({
            workflowId: z.string(),
            input: z.record(z.any()),
            config: z.object({
              timeout: z.number().optional(),
              retries: z.number().optional()
            }).optional()
          }),
          execute: async ({ context }) => {
            return await toolsets.agenticFlow.workflow_execute(context);
          }
        });
      }
    }
    
    return mastraTools;
  } catch (error) {
    console.error('❌ Failed to create MCP tools:', error);
    return {};
  }
};

// Initialize MCP connection
export const initializeMcp = async () => {
  try {
    console.log('🔌 Initializing MCP connections...');
    
    // The MCPClient will automatically connect to servers when tools are requested
    const tools = await createMcpTools();
    
    console.log('✅ MCP initialization complete');
    console.log(`📦 ${Object.keys(tools).length} MCP tools registered`);
    
    return tools;
  } catch (error) {
    console.error('❌ MCP initialization failed:', error);
    return {};
  }
};

export default {
  client: mcpClient,
  createTools: createMcpTools,
  initialize: initializeMcp
};