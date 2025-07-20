/**
 * Agent-related MCP tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { AgentManager } from '../core/agent-manager';
import {
  AgentSpawnSchema,
  AgentCoordinateSchema,
  AgentCommunicateSchema,
  ToolResponse,
  AgentType,
  MessageType,
  Priority,
  CoordinationStrategy,
  SynchronizationType,
  TaskStatus
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';

export class AgentTools {
  constructor(private agentManager: AgentManager) {}

  /**
   * Get all agent-related tools
   */
  getTools(): Tool[] {
    return [
      this.getAgentSpawnTool(),
      this.getAgentCoordinateTool(),
      this.getAgentCommunicateTool(),
      this.getAgentListTool(),
      this.getAgentStatusTool(),
      this.getAgentMetricsTool(),
      this.getAgentTerminateTool()
    ];
  }

  /**
   * Agent spawn tool
   */
  private getAgentSpawnTool(): Tool {
    return {
      name: 'agent_spawn',
      description: 'Create and spawn a new AI agent with specified capabilities',
      inputSchema: {
        type: 'object',
        properties: {
          name: {
            type: 'string',
            description: 'Name of the agent'
          },
          type: {
            type: 'string',
            enum: Object.values(AgentType),
            description: 'Type of agent to create'
          },
          capabilities: {
            type: 'array',
            items: { type: 'string' },
            description: 'List of specific capabilities for the agent'
          },
          config: {
            type: 'object',
            description: 'Additional configuration for the agent'
          }
        },
        required: ['name', 'type']
      }
    };
  }

  /**
   * Agent coordinate tool
   */
  private getAgentCoordinateTool(): Tool {
    return {
      name: 'agent_coordinate',
      description: 'Coordinate multiple agents to work on a shared task',
      inputSchema: {
        type: 'object',
        properties: {
          agents: {
            type: 'array',
            items: { type: 'string' },
            description: 'List of agent IDs to coordinate'
          },
          task: {
            type: 'string',
            description: 'Description of the task to coordinate'
          },
          strategy: {
            type: 'string',
            enum: Object.values(CoordinationStrategy),
            description: 'Coordination strategy to use'
          },
          timeout: {
            type: 'number',
            description: 'Timeout in milliseconds for the coordination'
          }
        },
        required: ['agents', 'task']
      }
    };
  }

  /**
   * Agent communicate tool
   */
  private getAgentCommunicateTool(): Tool {
    return {
      name: 'agent_communicate',
      description: 'Send messages between agents for inter-agent communication',
      inputSchema: {
        type: 'object',
        properties: {
          from: {
            type: 'string',
            description: 'Sender agent ID'
          },
          to: {
            oneOf: [
              { type: 'string' },
              { type: 'array', items: { type: 'string' } }
            ],
            description: 'Recipient agent ID(s)'
          },
          type: {
            type: 'string',
            enum: Object.values(MessageType),
            description: 'Type of message'
          },
          content: {
            description: 'Message content'
          },
          priority: {
            type: 'string',
            enum: Object.values(Priority),
            description: 'Message priority level'
          },
          requiresResponse: {
            type: 'boolean',
            description: 'Whether the message requires a response'
          }
        },
        required: ['from', 'to', 'type', 'content']
      }
    };
  }

  /**
   * Agent list tool
   */
  private getAgentListTool(): Tool {
    return {
      name: 'agent_list',
      description: 'List all agents or filter by type/capability',
      inputSchema: {
        type: 'object',
        properties: {
          type: {
            type: 'string',
            enum: Object.values(AgentType),
            description: 'Filter agents by type'
          },
          capability: {
            type: 'string',
            description: 'Filter agents by capability'
          }
        }
      }
    };
  }

  /**
   * Agent status tool
   */
  private getAgentStatusTool(): Tool {
    return {
      name: 'agent_status',
      description: 'Get detailed status information for an agent',
      inputSchema: {
        type: 'object',
        properties: {
          agentId: {
            type: 'string',
            description: 'Agent ID to get status for'
          }
        },
        required: ['agentId']
      }
    };
  }

  /**
   * Agent metrics tool
   */
  private getAgentMetricsTool(): Tool {
    return {
      name: 'agent_metrics',
      description: 'Get performance metrics for an agent',
      inputSchema: {
        type: 'object',
        properties: {
          agentId: {
            type: 'string',
            description: 'Agent ID to get metrics for'
          }
        },
        required: ['agentId']
      }
    };
  }

  /**
   * Agent terminate tool
   */
  private getAgentTerminateTool(): Tool {
    return {
      name: 'agent_terminate',
      description: 'Terminate an agent and clean up its resources',
      inputSchema: {
        type: 'object',
        properties: {
          agentId: {
            type: 'string',
            description: 'Agent ID to terminate'
          },
          reason: {
            type: 'string',
            description: 'Reason for termination'
          }
        },
        required: ['agentId']
      }
    };
  }

  /**
   * Handle tool calls
   */
  async handleToolCall(name: string, args: any): Promise<ToolResponse> {
    try {
      switch (name) {
        case 'agent_spawn':
          return await this.handleAgentSpawn(args);
        case 'agent_coordinate':
          return await this.handleAgentCoordinate(args);
        case 'agent_communicate':
          return await this.handleAgentCommunicate(args);
        case 'agent_list':
          return await this.handleAgentList(args);
        case 'agent_status':
          return await this.handleAgentStatus(args);
        case 'agent_metrics':
          return await this.handleAgentMetrics(args);
        case 'agent_terminate':
          return await this.handleAgentTerminate(args);
        default:
          throw new Error(`Unknown agent tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Agent tool error: ${name} - ${error}`);
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Handle agent spawn
   */
  private async handleAgentSpawn(args: any): Promise<ToolResponse> {
    const validated = AgentSpawnSchema.parse(args);
    
    const agent = await this.agentManager.spawnAgent(
      validated.name,
      validated.type,
      validated.capabilities,
      validated.config
    );

    return {
      success: true,
      data: {
        agent: {
          id: agent.id,
          name: agent.name,
          type: agent.type,
          capabilities: agent.capabilities,
          status: agent.status,
          createdAt: agent.createdAt
        }
      },
      metadata: {
        operation: 'agent_spawn',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle agent coordination
   */
  private async handleAgentCoordinate(args: any): Promise<ToolResponse> {
    const validated = AgentCoordinateSchema.parse(args);

    // Validate all agents exist
    for (const agentId of validated.agents) {
      const agent = this.agentManager.getAgent(agentId);
      if (!agent) {
        throw new Error(`Agent ${agentId} not found`);
      }
    }

    // Create coordination task
    const coordinationTask = {
      id: uuidv4(),
      name: `Coordination: ${validated.task}`,
      agents: validated.agents,
      strategy: validated.strategy || CoordinationStrategy.ROUND_ROBIN,
      synchronization: SynchronizationType.ASYNC,
      timeout: validated.timeout || 30000,
      status: TaskStatus.QUEUED,
      results: new Map()
    };

    // Send coordination messages to all agents
    for (const agentId of validated.agents) {
      await this.agentManager.sendMessage({
        id: uuidv4(),
        from: 'system',
        to: agentId,
        type: MessageType.COMMAND,
        content: {
          action: 'coordinate',
          task: validated.task,
          coordinationId: coordinationTask.id,
          strategy: coordinationTask.strategy,
          participants: validated.agents
        },
        timestamp: new Date(),
        priority: Priority.HIGH,
        requiresResponse: true,
        responseTimeout: coordinationTask.timeout
      });
    }

    return {
      success: true,
      data: {
        coordinationTask: {
          id: coordinationTask.id,
          agents: coordinationTask.agents,
          task: validated.task,
          strategy: coordinationTask.strategy,
          status: coordinationTask.status
        }
      },
      metadata: {
        operation: 'agent_coordinate',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle agent communication
   */
  private async handleAgentCommunicate(args: any): Promise<ToolResponse> {
    const validated = AgentCommunicateSchema.parse(args);

    // Validate sender exists
    const sender = this.agentManager.getAgent(validated.from);
    if (!sender) {
      throw new Error(`Sender agent ${validated.from} not found`);
    }

    // Validate recipients exist
    const recipients = Array.isArray(validated.to) ? validated.to : [validated.to];
    for (const recipientId of recipients) {
      const recipient = this.agentManager.getAgent(recipientId);
      if (!recipient) {
        throw new Error(`Recipient agent ${recipientId} not found`);
      }
    }

    // Send message
    const message = {
      id: uuidv4(),
      from: validated.from,
      to: validated.to,
      type: validated.type,
      content: validated.content,
      timestamp: new Date(),
      priority: validated.priority || Priority.MEDIUM,
      requiresResponse: validated.requiresResponse || false
    };

    await this.agentManager.sendMessage(message);

    return {
      success: true,
      data: {
        message: {
          id: message.id,
          from: message.from,
          to: message.to,
          type: message.type,
          timestamp: message.timestamp,
          priority: message.priority
        }
      },
      metadata: {
        operation: 'agent_communicate',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle agent list
   */
  private async handleAgentList(args: any): Promise<ToolResponse> {
    let agents = this.agentManager.getAllAgents();

    // Apply filters
    if (args.type) {
      agents = agents.filter(agent => agent.type === args.type);
    }

    if (args.capability) {
      agents = agents.filter(agent => agent.capabilities.includes(args.capability));
    }

    const agentSummaries = agents.map(agent => ({
      id: agent.id,
      name: agent.name,
      type: agent.type,
      capabilities: agent.capabilities,
      status: agent.status,
      connectionCount: agent.connections.length,
      lastActive: agent.lastActive
    }));

    return {
      success: true,
      data: {
        agents: agentSummaries,
        count: agentSummaries.length
      },
      metadata: {
        operation: 'agent_list',
        timestamp: new Date().toISOString(),
        filters: { type: args.type, capability: args.capability }
      }
    };
  }

  /**
   * Handle agent status
   */
  private async handleAgentStatus(args: any): Promise<ToolResponse> {
    const agent = this.agentManager.getAgent(args.agentId);
    if (!agent) {
      throw new Error(`Agent ${args.agentId} not found`);
    }

    const messages = this.agentManager.getMessages(args.agentId, false);
    const connections = agent.connections.map(id => {
      const connected = this.agentManager.getAgent(id);
      return connected ? { id: connected.id, name: connected.name, status: connected.status } : null;
    }).filter(Boolean);

    return {
      success: true,
      data: {
        agent: {
          id: agent.id,
          name: agent.name,
          type: agent.type,
          capabilities: agent.capabilities,
          status: agent.status,
          createdAt: agent.createdAt,
          lastActive: agent.lastActive,
          connections,
          messageQueueSize: messages.length,
          memorySize: agent.memory.size
        }
      },
      metadata: {
        operation: 'agent_status',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle agent metrics
   */
  private async handleAgentMetrics(args: any): Promise<ToolResponse> {
    const metrics = this.agentManager.getAgentMetrics(args.agentId);

    return {
      success: true,
      data: { metrics },
      metadata: {
        operation: 'agent_metrics',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle agent termination
   */
  private async handleAgentTerminate(args: any): Promise<ToolResponse> {
    const agent = this.agentManager.getAgent(args.agentId);
    if (!agent) {
      throw new Error(`Agent ${args.agentId} not found`);
    }

    await this.agentManager.terminateAgent(args.agentId);

    return {
      success: true,
      data: {
        terminatedAgent: {
          id: agent.id,
          name: agent.name,
          reason: args.reason || 'Manual termination'
        }
      },
      metadata: {
        operation: 'agent_terminate',
        timestamp: new Date().toISOString()
      }
    };
  }
}