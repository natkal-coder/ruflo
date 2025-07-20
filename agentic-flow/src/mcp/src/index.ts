/**
 * Agentic Flow MCP Server
 * Main entry point for the Model Context Protocol server
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';

// Core managers
import { AgentManager } from './core/agent-manager.js';
import { WorkflowEngine } from './core/workflow-engine.js';
import { GoalManager } from './core/goal-manager.js';
import { LearningEngine } from './core/learning-engine.js';

// Tool handlers
import { AgentTools } from './tools/agent-tools.js';
import { WorkflowTools } from './tools/workflow-tools.js';
import { GoalTools } from './tools/goal-tools.js';
import { LearningTools } from './tools/learning-tools.js';

// Utilities
import { logger } from './utils/logger.js';

/**
 * Main MCP Server class
 */
class AgenticFlowMCPServer {
  private server: Server;
  private agentManager: AgentManager;
  private workflowEngine: WorkflowEngine;
  private goalManager: GoalManager;
  private learningEngine: LearningEngine;
  
  private agentTools: AgentTools;
  private workflowTools: WorkflowTools;
  private goalTools: GoalTools;
  private learningTools: LearningTools;

  constructor() {
    // Initialize core managers
    this.agentManager = new AgentManager();
    this.workflowEngine = new WorkflowEngine(this.agentManager);
    this.goalManager = new GoalManager();
    this.learningEngine = new LearningEngine();

    // Initialize tool handlers
    this.agentTools = new AgentTools(this.agentManager);
    this.workflowTools = new WorkflowTools(this.workflowEngine);
    this.goalTools = new GoalTools(this.goalManager);
    this.learningTools = new LearningTools(this.learningEngine);

    // Initialize MCP server
    this.server = new Server(
      {
        name: 'agentic-flow-mcp',
        version: '1.0.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupHandlers();
    this.setupEventListeners();
  }

  /**
   * Setup MCP request handlers
   */
  private setupHandlers(): void {
    // List tools handler
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const tools: Tool[] = [
        ...this.agentTools.getTools(),
        ...this.workflowTools.getTools(),
        ...this.goalTools.getTools(),
        ...this.learningTools.getTools()
      ];

      logger.info(`Listing ${tools.length} available tools`);
      return { tools };
    });

    // Call tool handler
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      logger.info(`Tool called: ${name} with args: ${JSON.stringify(args)}`);

      try {
        let result;

        // Route to appropriate tool handler
        if (this.isAgentTool(name)) {
          result = await this.agentTools.handleToolCall(name, args);
        } else if (this.isWorkflowTool(name)) {
          result = await this.workflowTools.handleToolCall(name, args);
        } else if (this.isGoalTool(name)) {
          result = await this.goalTools.handleToolCall(name, args);
        } else if (this.isLearningTool(name)) {
          result = await this.learningTools.handleToolCall(name, args);
        } else {
          throw new Error(`Unknown tool: ${name}`);
        }

        logger.info(`Tool ${name} completed successfully`);
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      } catch (error) {
        logger.error(`Tool ${name} failed: ${error}`);
        
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                success: false,
                error: error instanceof Error ? error.message : String(error),
                tool: name,
                timestamp: new Date().toISOString()
              }, null, 2)
            }
          ],
          isError: true
        };
      }
    });
  }

  /**
   * Setup event listeners for cross-component coordination
   */
  private setupEventListeners(): void {
    // Agent events
    this.agentManager.on('agent:spawned', (agent) => {
      logger.info(`Agent spawned: ${agent.name} (${agent.id})`);
    });

    this.agentManager.on('agent:terminated', (agentId) => {
      logger.info(`Agent terminated: ${agentId}`);
    });

    // Workflow events
    this.workflowEngine.on('workflow:created', (workflow) => {
      logger.info(`Workflow created: ${workflow.name} (${workflow.id})`);
    });

    this.workflowEngine.on('workflow:execution:completed', (execution) => {
      logger.info(`Workflow execution completed: ${execution.id}`);
    });

    this.workflowEngine.on('workflow:execution:failed', ({ execution, error }) => {
      logger.error(`Workflow execution failed: ${execution.id} - ${error}`);
    });

    // Goal events
    this.goalManager.on('goal:parsed', (goal) => {
      logger.info(`Goal parsed: ${goal.description} (${goal.id})`);
    });

    this.goalManager.on('goal:completed', (goal) => {
      logger.info(`Goal completed: ${goal.description} (${goal.id})`);
    });

    // Learning events
    this.learningEngine.on('training:complete', ({ model }) => {
      logger.info(`Model training completed: ${model.name} (${model.id})`);
    });

    this.learningEngine.on('training:failed', ({ model, error }) => {
      logger.error(`Model training failed: ${model.name} - ${error}`);
    });

    // Cross-component integrations
    this.setupCrossComponentIntegrations();
  }

  /**
   * Setup integrations between different components
   */
  private setupCrossComponentIntegrations(): void {
    // When a goal is decomposed, create workflow steps
    this.goalManager.on('goal:decomposed', async ({ goal, subgoals }) => {
      try {
        const workflowSteps = subgoals.map((subgoal: any, index: number) => ({
          name: subgoal.description,
          type: 'agent_action' as const,
          config: {
            capability: 'task-execution',
            action: 'execute',
            goalId: subgoal.id
          },
          dependencies: index > 0 ? [subgoals[index - 1].id] : []
        }));

        await this.workflowEngine.createWorkflow(
          `Goal Execution: ${goal.description}`,
          `Automated workflow for goal: ${goal.description}`,
          workflowSteps
        );

        logger.info(`Created workflow for decomposed goal: ${goal.id}`);
      } catch (error) {
        logger.error(`Failed to create workflow for goal ${goal.id}: ${error}`);
      }
    });

    // When a workflow completes, update related goal status
    this.workflowEngine.on('workflow:execution:completed', async (execution) => {
      // Find related goals and update their progress
      const workflow = this.workflowEngine.getWorkflow(execution.workflowId);
      if (workflow && workflow.name.startsWith('Goal Execution:')) {
        // Extract goal ID from workflow results or metadata
        // This is a simplified implementation
        logger.debug(`Workflow completed for goal-related execution: ${execution.id}`);
      }
    });

    // When agent performance data is available, use it for learning
    this.agentManager.on('agent:metrics', async (metrics) => {
      try {
        // Collect agent performance data for learning
        const features = [
          metrics.uptime,
          metrics.messageQueueSize,
          metrics.connectionCount,
          metrics.memorySize
        ];

        // Use this data to train performance prediction models
        logger.debug(`Collected agent metrics for learning: ${metrics.id}`);
      } catch (error) {
        logger.error(`Failed to process agent metrics for learning: ${error}`);
      }
    });
  }

  /**
   * Check if tool is an agent tool
   */
  private isAgentTool(name: string): boolean {
    return name.startsWith('agent_');
  }

  /**
   * Check if tool is a workflow tool
   */
  private isWorkflowTool(name: string): boolean {
    return name.startsWith('workflow_');
  }

  /**
   * Check if tool is a goal tool
   */
  private isGoalTool(name: string): boolean {
    return name.startsWith('goal_');
  }

  /**
   * Check if tool is a learning tool
   */
  private isLearningTool(name: string): boolean {
    return name.startsWith('learning_') || name.startsWith('model_');
  }

  /**
   * Start the MCP server
   */
  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    
    logger.info('Starting Agentic Flow MCP Server...');
    
    try {
      await this.server.connect(transport);
      logger.info('Agentic Flow MCP Server started successfully');
      
      // Setup graceful shutdown
      process.on('SIGINT', () => this.shutdown());
      process.on('SIGTERM', () => this.shutdown());
      
    } catch (error) {
      logger.error(`Failed to start MCP server: ${error}`);
      process.exit(1);
    }
  }

  /**
   * Shutdown the server gracefully
   */
  private async shutdown(): Promise<void> {
    logger.info('Shutting down Agentic Flow MCP Server...');
    
    try {
      // Terminate all agents
      const agents = this.agentManager.getAllAgents();
      for (const agent of agents) {
        await this.agentManager.terminateAgent(agent.id);
      }

      // Clean up workflows
      const workflows = this.workflowEngine.getAllWorkflows();
      for (const workflow of workflows) {
        this.workflowEngine.updateWorkflowStatus(workflow.id, 'paused' as any);
      }

      logger.info('Agentic Flow MCP Server shutdown complete');
      process.exit(0);
    } catch (error) {
      logger.error(`Error during shutdown: ${error}`);
      process.exit(1);
    }
  }

  /**
   * Get server statistics
   */
  getStats(): Record<string, any> {
    return {
      agents: {
        total: this.agentManager.getAllAgents().length,
        active: this.agentManager.getAllAgents().filter(a => a.status === 'active').length
      },
      workflows: {
        total: this.workflowEngine.getAllWorkflows().length,
        active: this.workflowEngine.getAllWorkflows().filter(w => w.status === 'active').length
      },
      goals: {
        total: this.goalManager.getAllGoals().length,
        completed: this.goalManager.getGoalsByStatus('completed' as any).length
      },
      models: {
        total: this.learningEngine.getAllModels().length
      },
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage()
    };
  }
}

/**
 * Main entry point
 */
async function main(): Promise<void> {
  // Setup environment
  if (process.env.NODE_ENV !== 'production') {
    process.env.LOG_LEVEL = 'debug';
  }

  // Create and start server
  const server = new AgenticFlowMCPServer();
  await server.start();
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Start the server if this file is run directly
if (require.main === module) {
  main().catch((error) => {
    logger.error('Failed to start server:', error);
    process.exit(1);
  });
}

export { AgenticFlowMCPServer };
export default AgenticFlowMCPServer;