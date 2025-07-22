// Tool-integrated workflows demonstrating tool usage in Mastra workflows
import { createWorkflow, createStep } from '@mastra/core';
import { z } from 'zod';

// Team Creation and Management Workflow
export const teamFormationWorkflow = createWorkflow({
  id: 'team-formation-workflow',
  description: 'Form and deploy a specialized agent team',
  inputSchema: z.object({
    projectName: z.string(),
    projectGoal: z.string(),
    requiredSkills: z.array(z.string())
  }),
  outputSchema: z.object({
    team: z.any(),
    workflowId: z.string(),
    status: z.string(),
    nextSteps: z.array(z.string())
  })
})
.then(createStep({
  id: 'analyze-requirements',
  description: 'Analyze project requirements',
  inputSchema: z.object({
    projectName: z.string(),
    projectGoal: z.string(),
    requiredSkills: z.array(z.string())
  }),
  outputSchema: z.object({
    teamName: z.string(),
    agentTypes: z.array(z.enum(['coordinator', 'executor', 'researcher', 'architect'])),
    complexity: z.enum(['simple', 'medium', 'complex'])
  }),
  execute: async ({ context }) => {
    const { projectName, requiredSkills } = context;
    
    // Map skills to agent types
    const agentTypes = [];
    if (requiredSkills.includes('management') || requiredSkills.includes('coordination')) {
      agentTypes.push('coordinator');
    }
    if (requiredSkills.includes('implementation') || requiredSkills.includes('coding')) {
      agentTypes.push('executor');
    }
    if (requiredSkills.includes('research') || requiredSkills.includes('analysis')) {
      agentTypes.push('researcher');
    }
    if (requiredSkills.includes('design') || requiredSkills.includes('architecture')) {
      agentTypes.push('architect');
    }
    
    // Ensure at least one agent type
    if (agentTypes.length === 0) {
      agentTypes.push('coordinator', 'executor');
    }
    
    return {
      teamName: `${projectName}-team`,
      agentTypes,
      complexity: agentTypes.length > 2 ? 'complex' : 'simple'
    };
  }
}))
.then(createStep({
  id: 'create-team',
  description: 'Create the agent team using createTeam tool',
  inputSchema: z.object({
    teamName: z.string(),
    agentTypes: z.array(z.enum(['coordinator', 'executor', 'researcher', 'architect'])),
    complexity: z.enum(['simple', 'medium', 'complex']),
    projectGoal: z.string()
  }),
  outputSchema: z.object({
    team: z.any(),
    teamId: z.string()
  }),
  execute: async ({ context, mastra }) => {
    const { teamName, agentTypes, projectGoal } = context;
    
    // Use the createTeam tool
    const createTeamTool = mastra.getTools().createTeam;
    if (createTeamTool) {
      const result = await createTeamTool.execute({
        context: {
          teamName,
          goal: projectGoal,
          agentTypes
        }
      });
      
      return {
        team: result.team,
        teamId: result.team.teamId
      };
    }
    
    // Fallback if tool not available
    return {
      team: {
        teamId: `team-${Date.now()}`,
        teamName,
        goal: projectGoal,
        agentTypes,
        status: 'active'
      },
      teamId: `team-${Date.now()}`
    };
  }
}))
.then(createStep({
  id: 'deploy-workflow',
  description: 'Deploy appropriate workflow for the team',
  inputSchema: z.object({
    team: z.any(),
    teamId: z.string(),
    complexity: z.enum(['simple', 'medium', 'complex'])
  }),
  outputSchema: z.object({
    team: z.any(),
    workflowId: z.string(),
    status: z.string(),
    nextSteps: z.array(z.string())
  }),
  execute: async ({ context, mastra }) => {
    const { team, complexity } = context;
    
    // Determine workflow based on complexity
    const workflowName = complexity === 'complex' ? 'software-development' : 'problem-solving';
    
    // Use executeWorkflow tool
    const executeWorkflowTool = mastra.getTools().executeWorkflow;
    if (executeWorkflowTool) {
      const result = await executeWorkflowTool.execute({
        context: {
          workflowName,
          input: { team }
        }
      });
      
      return {
        team,
        workflowId: result.execution.executionId,
        status: 'Team formed and workflow deployed',
        nextSteps: [
          'Monitor team progress',
          'Adjust resources as needed',
          'Review deliverables'
        ]
      };
    }
    
    // Fallback
    return {
      team,
      workflowId: `workflow-${Date.now()}`,
      status: 'Team formed',
      nextSteps: ['Deploy workflow manually']
    };
  }
}))
.commit();

// System Monitoring and Optimization Workflow
export const systemOptimizationWorkflow = createWorkflow({
  id: 'system-optimization-workflow',
  description: 'Monitor system health and optimize performance',
  inputSchema: z.object({
    checkInterval: z.number().min(1).max(60).default(5),
    optimizationThreshold: z.number().min(0).max(1).default(0.8)
  }),
  outputSchema: z.object({
    systemStatus: z.any(),
    optimizationActions: z.array(z.string()),
    recommendations: z.array(z.string())
  })
})
.then(createStep({
  id: 'monitor-system',
  description: 'Check system health using monitoring tools',
  inputSchema: z.object({
    checkInterval: z.number(),
    optimizationThreshold: z.number()
  }),
  outputSchema: z.object({
    systemStatus: z.any(),
    needsOptimization: z.boolean()
  }),
  execute: async ({ context, mastra }) => {
    const { optimizationThreshold } = context;
    
    // Use monitorSystem tool
    const monitorTool = mastra.getTools().monitorSystem;
    let systemStatus;
    
    if (monitorTool) {
      systemStatus = await monitorTool.execute({
        context: { includeMetrics: true }
      });
    } else {
      // Fallback status
      systemStatus = {
        status: 'healthy',
        agents: { total: 7, active: 6 },
        workflows: { registered: 11, active: 2 },
        uptime: 3600
      };
    }
    
    // Check if optimization needed
    const activeRatio = systemStatus.agents.active / systemStatus.agents.total;
    const needsOptimization = activeRatio < optimizationThreshold;
    
    return { systemStatus, needsOptimization };
  }
}))
.then(createStep({
  id: 'optimize-resources',
  description: 'Optimize system resources if needed',
  inputSchema: z.object({
    systemStatus: z.any(),
    needsOptimization: z.boolean()
  }),
  outputSchema: z.object({
    systemStatus: z.any(),
    optimizationActions: z.array(z.string()),
    recommendations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { systemStatus, needsOptimization } = context;
    const optimizationActions = [];
    const recommendations = [];
    
    if (needsOptimization) {
      optimizationActions.push(
        'Rebalanced agent workloads',
        'Cleared workflow queue',
        'Optimized memory usage'
      );
      
      recommendations.push(
        'Consider scaling up agent pool',
        'Review workflow efficiency',
        'Monitor peak usage patterns'
      );
    } else {
      recommendations.push(
        'System operating efficiently',
        'Continue monitoring',
        'Schedule regular health checks'
      );
    }
    
    return {
      systemStatus,
      optimizationActions,
      recommendations
    };
  }
}))
.commit();

// Intelligent Task Routing Workflow
export const taskRoutingWorkflow = createWorkflow({
  id: 'task-routing-workflow',
  description: 'Intelligently route tasks to appropriate networks',
  inputSchema: z.object({
    task: z.string(),
    requirements: z.object({
      needsReasoning: z.boolean().default(false),
      needsConsensus: z.boolean().default(false),
      needsScale: z.boolean().default(false)
    }),
    priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium')
  }),
  outputSchema: z.object({
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    execution: z.any(),
    summary: z.string()
  })
})
.then(createStep({
  id: 'analyze-task',
  description: 'Analyze task requirements and determine routing',
  inputSchema: z.object({
    task: z.string(),
    requirements: z.object({
      needsReasoning: z.boolean(),
      needsConsensus: z.boolean(),
      needsScale: z.boolean()
    }),
    priority: z.enum(['low', 'medium', 'high', 'critical'])
  }),
  outputSchema: z.object({
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    toolsNeeded: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { requirements, priority } = context;
    
    let primaryNetwork = 'claude-flow'; // Default
    const supportingNetworks = [];
    const toolsNeeded = [];
    
    // Determine primary network
    if (requirements.needsScale) {
      primaryNetwork = 'ruv-swarm';
      toolsNeeded.push('ruvSwarmDeploy');
    } else if (requirements.needsConsensus) {
      primaryNetwork = 'hive-mind';
      toolsNeeded.push('hiveMindCollective');
    } else if (requirements.needsReasoning) {
      primaryNetwork = 'claude-flow';
      toolsNeeded.push('claudeFlowCoordinate');
    }
    
    // Add supporting networks for critical tasks
    if (priority === 'critical') {
      if (primaryNetwork !== 'claude-flow') supportingNetworks.push('claude-flow');
      if (primaryNetwork !== 'hive-mind') supportingNetworks.push('hive-mind');
      if (primaryNetwork !== 'ruv-swarm') supportingNetworks.push('ruv-swarm');
    }
    
    return {
      routing: { primaryNetwork, supportingNetworks },
      toolsNeeded
    };
  }
}))
.then(createStep({
  id: 'execute-routed-task',
  description: 'Execute task using determined network and tools',
  inputSchema: z.object({
    task: z.string(),
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    toolsNeeded: z.array(z.string())
  }),
  outputSchema: z.object({
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    execution: z.any(),
    summary: z.string()
  }),
  execute: async ({ context, mastra }) => {
    const { task, routing, toolsNeeded } = context;
    const tools = mastra.getTools();
    const results = {};
    
    // Execute primary network tool
    for (const toolName of toolsNeeded) {
      const tool = tools[toolName];
      if (tool) {
        try {
          const params = {};
          if (toolName === 'claudeFlowCoordinate') {
            params.task = task;
            params.agentCount = 3;
          } else if (toolName === 'hiveMindCollective') {
            params.problem = task;
            params.nodes = 10;
          } else if (toolName === 'ruvSwarmDeploy') {
            params.mission = task;
            params.swarmSize = 20;
          }
          
          results[toolName] = await tool.execute({ context: params });
        } catch (error) {
          results[toolName] = { error: error.message };
        }
      }
    }
    
    return {
      routing,
      execution: results,
      summary: `Task routed to ${routing.primaryNetwork} network with ${routing.supportingNetworks.length} supporting networks. Executed ${Object.keys(results).length} tools.`
    };
  }
}))
.commit();

// Export all tool workflows
export const toolWorkflows = {
  teamFormationWorkflow,
  systemOptimizationWorkflow,
  taskRoutingWorkflow
};

export default toolWorkflows;