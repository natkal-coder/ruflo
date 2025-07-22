// MCP-integrated workflows demonstrating MCP server usage
import { createWorkflow, createStep } from '@mastra/core';
import { z } from 'zod';

// MCP Swarm Orchestration Workflow
export const mcpSwarmOrchestrationWorkflow = createWorkflow({
  id: 'mcp-swarm-orchestration',
  description: 'Orchestrate AI swarms using MCP servers',
  inputSchema: z.object({
    objective: z.string(),
    scale: z.enum(['small', 'medium', 'large']).default('medium'),
    useClaudeFlow: z.boolean().default(true),
    useAgenticFlow: z.boolean().default(true)
  }),
  outputSchema: z.object({
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    orchestrationResults: z.object({
      claudeFlow: z.any().optional(),
      agenticFlow: z.any().optional()
    }),
    summary: z.string()
  })
})
.then(createStep({
  id: 'initialize-swarms',
  description: 'Initialize swarms via MCP servers',
  inputSchema: z.object({
    objective: z.string(),
    scale: z.enum(['small', 'medium', 'large']),
    useClaudeFlow: z.boolean(),
    useAgenticFlow: z.boolean()
  }),
  outputSchema: z.object({
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    initialized: z.array(z.string())
  }),
  execute: async ({ context, mastra }) => {
    const { objective, scale, useClaudeFlow, useAgenticFlow } = context;
    const initialized = [];
    let swarmId, teamId;
    
    // Determine swarm configuration based on scale
    const swarmConfig = {
      small: { topology: 'star', maxAgents: 5 },
      medium: { topology: 'mesh', maxAgents: 20 },
      large: { topology: 'hierarchical', maxAgents: 50 }
    }[scale];
    
    // Initialize Claude Flow swarm if requested
    if (useClaudeFlow) {
      const claudeFlowSwarmInit = mastra.getTools().claudeFlowSwarmInit;
      if (claudeFlowSwarmInit) {
        try {
          const result = await claudeFlowSwarmInit.execute({
            context: {
              topology: swarmConfig.topology,
              maxAgents: swarmConfig.maxAgents,
              strategy: 'adaptive'
            }
          });
          swarmId = result.swarmId;
          initialized.push('Claude Flow swarm');
        } catch (error) {
          console.error('Claude Flow initialization failed:', error);
        }
      }
    }
    
    // Initialize Agentic Flow team if requested
    if (useAgenticFlow) {
      const agenticFlowTeamCreate = mastra.getTools().agenticFlowTeamCreate;
      if (agenticFlowTeamCreate) {
        try {
          const result = await agenticFlowTeamCreate.execute({
            context: {
              name: `Team-${objective.substring(0, 20)}`,
              members: [
                { role: 'coordinator', capabilities: ['planning', 'delegation'] },
                { role: 'executor', capabilities: ['implementation', 'testing'] },
                { role: 'analyst', capabilities: ['monitoring', 'optimization'] }
              ],
              goal: objective
            }
          });
          teamId = result.teamId;
          initialized.push('Agentic Flow team');
        } catch (error) {
          console.error('Agentic Flow initialization failed:', error);
        }
      }
    }
    
    return { swarmId, teamId, initialized };
  }
}))
.then(createStep({
  id: 'orchestrate-tasks',
  description: 'Orchestrate tasks across MCP servers',
  inputSchema: z.object({
    objective: z.string(),
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    initialized: z.array(z.string()),
    useClaudeFlow: z.boolean(),
    useAgenticFlow: z.boolean()
  }),
  outputSchema: z.object({
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    orchestrationResults: z.object({
      claudeFlow: z.any().optional(),
      agenticFlow: z.any().optional()
    }),
    summary: z.string()
  }),
  execute: async ({ context, mastra }) => {
    const { objective, swarmId, teamId, initialized, useClaudeFlow, useAgenticFlow } = context;
    const orchestrationResults = {};
    
    // Orchestrate with Claude Flow
    if (useClaudeFlow && swarmId) {
      const claudeFlowTaskOrchestrate = mastra.getTools().claudeFlowTaskOrchestrate;
      if (claudeFlowTaskOrchestrate) {
        try {
          orchestrationResults.claudeFlow = await claudeFlowTaskOrchestrate.execute({
            context: {
              task: objective,
              priority: 'high',
              strategy: 'adaptive'
            }
          });
        } catch (error) {
          orchestrationResults.claudeFlow = { error: error.message };
        }
      }
    }
    
    // Execute workflow with Agentic Flow
    if (useAgenticFlow && teamId) {
      const agenticFlowWorkflowExecute = mastra.getTools().agenticFlowWorkflowExecute;
      if (agenticFlowWorkflowExecute) {
        try {
          orchestrationResults.agenticFlow = await agenticFlowWorkflowExecute.execute({
            context: {
              workflowId: 'problem-solving',
              input: { problem: objective, teamId },
              config: { timeout: 30000 }
            }
          });
        } catch (error) {
          orchestrationResults.agenticFlow = { error: error.message };
        }
      }
    }
    
    const summary = `MCP orchestration completed. Initialized: ${initialized.join(', ')}. ` +
                   `Results: ${Object.keys(orchestrationResults).length} server(s) processed the objective.`;
    
    return {
      swarmId,
      teamId,
      orchestrationResults,
      summary
    };
  }
}))
.commit();

// MCP Learning and Adaptation Workflow
export const mcpLearningWorkflow = createWorkflow({
  id: 'mcp-learning-adaptation',
  description: 'Capture and apply learning across MCP servers',
  inputSchema: z.object({
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(['success', 'failure', 'insight']).default('insight')
  }),
  outputSchema: z.object({
    learningCaptured: z.boolean(),
    adaptations: z.array(z.string()),
    recommendations: z.array(z.string())
  })
})
.then(createStep({
  id: 'capture-learning',
  description: 'Capture learning experience via MCP',
  inputSchema: z.object({
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(['success', 'failure', 'insight'])
  }),
  outputSchema: z.object({
    learningCaptured: z.boolean(),
    captureResult: z.any().optional()
  }),
  execute: async ({ context, mastra }) => {
    const { experience, category } = context;
    
    const agenticFlowLearningCapture = mastra.getTools().agenticFlowLearningCapture;
    if (agenticFlowLearningCapture) {
      try {
        const result = await agenticFlowLearningCapture.execute({
          context: { experience, category }
        });
        return {
          learningCaptured: true,
          captureResult: result
        };
      } catch (error) {
        console.error('Learning capture failed:', error);
        return {
          learningCaptured: false,
          captureResult: { error: error.message }
        };
      }
    }
    
    return {
      learningCaptured: false,
      captureResult: { error: 'MCP learning tool not available' }
    };
  }
}))
.then(createStep({
  id: 'apply-adaptations',
  description: 'Apply learned adaptations',
  inputSchema: z.object({
    learningCaptured: z.boolean(),
    captureResult: z.any().optional(),
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(['success', 'failure', 'insight'])
  }),
  outputSchema: z.object({
    learningCaptured: z.boolean(),
    adaptations: z.array(z.string()),
    recommendations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { learningCaptured, experience, category } = context;
    
    const adaptations = [];
    const recommendations = [];
    
    if (learningCaptured) {
      if (category === 'success') {
        adaptations.push('Reinforce successful patterns');
        adaptations.push('Increase confidence in similar approaches');
        recommendations.push(`Continue using ${experience.action} for similar contexts`);
      } else if (category === 'failure') {
        adaptations.push('Adjust approach to avoid similar failures');
        adaptations.push('Update risk assessment models');
        recommendations.push(`Avoid ${experience.action} in similar contexts`);
        recommendations.push('Consider alternative strategies');
      } else { // insight
        adaptations.push('Integrate new insight into knowledge base');
        adaptations.push('Update decision-making heuristics');
        recommendations.push('Apply insight to related problems');
      }
    }
    
    return {
      learningCaptured,
      adaptations,
      recommendations
    };
  }
}))
.commit();

// MCP Multi-Server Coordination Workflow
export const mcpMultiServerWorkflow = createWorkflow({
  id: 'mcp-multi-server-coordination',
  description: 'Coordinate actions across multiple MCP servers',
  inputSchema: z.object({
    task: z.string(),
    servers: z.array(z.enum(['claude-flow', 'agentic-flow'])).default(['claude-flow', 'agentic-flow']),
    coordinationMode: z.enum(['sequential', 'parallel', 'hierarchical']).default('parallel')
  }),
  outputSchema: z.object({
    results: z.record(z.any()),
    coordinationSummary: z.string(),
    performance: z.object({
      duration: z.number(),
      serversUsed: z.number()
    })
  })
})
.then(createStep({
  id: 'coordinate-servers',
  description: 'Coordinate task execution across MCP servers',
  inputSchema: z.object({
    task: z.string(),
    servers: z.array(z.enum(['claude-flow', 'agentic-flow'])),
    coordinationMode: z.enum(['sequential', 'parallel', 'hierarchical'])
  }),
  outputSchema: z.object({
    results: z.record(z.any()),
    coordinationSummary: z.string(),
    performance: z.object({
      duration: z.number(),
      serversUsed: z.number()
    })
  }),
  execute: async ({ context, mastra }) => {
    const { task, servers, coordinationMode } = context;
    const startTime = Date.now();
    const results = {};
    
    if (coordinationMode === 'parallel') {
      // Execute on all servers in parallel
      const promises = [];
      
      if (servers.includes('claude-flow')) {
        const claudeFlowPromise = (async () => {
          const tool = mastra.getTools().claudeFlowTaskOrchestrate;
          if (tool) {
            try {
              results['claude-flow'] = await tool.execute({
                context: { task, priority: 'high', strategy: 'adaptive' }
              });
            } catch (error) {
              results['claude-flow'] = { error: error.message };
            }
          }
        })();
        promises.push(claudeFlowPromise);
      }
      
      if (servers.includes('agentic-flow')) {
        const agenticFlowPromise = (async () => {
          const tool = mastra.getTools().agenticFlowWorkflowExecute;
          if (tool) {
            try {
              results['agentic-flow'] = await tool.execute({
                context: {
                  workflowId: 'adaptive-problem-solving',
                  input: { problem: task },
                  config: { timeout: 30000 }
                }
              });
            } catch (error) {
              results['agentic-flow'] = { error: error.message };
            }
          }
        })();
        promises.push(agenticFlowPromise);
      }
      
      await Promise.all(promises);
    } else {
      // Sequential execution
      for (const server of servers) {
        if (server === 'claude-flow') {
          const tool = mastra.getTools().claudeFlowTaskOrchestrate;
          if (tool) {
            try {
              results['claude-flow'] = await tool.execute({
                context: { task, priority: 'high', strategy: 'adaptive' }
              });
            } catch (error) {
              results['claude-flow'] = { error: error.message };
            }
          }
        } else if (server === 'agentic-flow') {
          const tool = mastra.getTools().agenticFlowWorkflowExecute;
          if (tool) {
            try {
              results['agentic-flow'] = await tool.execute({
                context: {
                  workflowId: 'adaptive-problem-solving',
                  input: { problem: task },
                  config: { timeout: 30000 }
                }
              });
            } catch (error) {
              results['agentic-flow'] = { error: error.message };
            }
          }
        }
      }
    }
    
    const duration = Date.now() - startTime;
    const serversUsed = Object.keys(results).length;
    
    const coordinationSummary = `Coordinated task "${task}" across ${serversUsed} MCP servers in ${coordinationMode} mode. ` +
                               `Execution completed in ${duration}ms.`;
    
    return {
      results,
      coordinationSummary,
      performance: {
        duration,
        serversUsed
      }
    };
  }
}))
.commit();

// Export all MCP workflows
export const mcpWorkflows = {
  mcpSwarmOrchestrationWorkflow,
  mcpLearningWorkflow,
  mcpMultiServerWorkflow
};

export default mcpWorkflows;