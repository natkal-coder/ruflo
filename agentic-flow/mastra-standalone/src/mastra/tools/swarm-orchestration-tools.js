import { createTool } from '@mastra/core';
import { z } from 'zod';

// Swarm state management
const swarmRegistry = new Map();
const agentRegistry = new Map();
const taskQueue = new Map();
const metricsStore = new Map();

// Tool 1: Initialize a new swarm with configuration
export const swarmInit = createTool({
  id: 'swarm-init',
  name: 'Swarm Initialize',
  description: 'Initialize a new swarm with specified topology and configuration',
  inputSchema: z.object({
    swarmId: z.string().optional().describe('Unique swarm identifier (auto-generated if not provided)'),
    topology: z.enum(['hierarchical', 'mesh', 'ring', 'star']).describe('Swarm topology type'),
    maxAgents: z.number().min(1).max(100).default(10).describe('Maximum number of agents'),
    strategy: z.enum(['auto', 'manual', 'hybrid']).default('auto').describe('Agent management strategy'),
    metadata: z.object({
      name: z.string().optional(),
      description: z.string().optional(),
      tags: z.array(z.string()).optional()
    }).optional()
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    topology: z.string(),
    status: z.enum(['initialized', 'failed']),
    config: z.object({
      maxAgents: z.number(),
      strategy: z.string(),
      createdAt: z.string()
    }),
    message: z.string()
  }),
  execute: async ({ topology, maxAgents, strategy, metadata, swarmId }) => {
    console.log(`[SwarmInit] Initializing swarm with topology: ${topology}`);
    
    const id = swarmId || `swarm-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    
    if (swarmRegistry.has(id)) {
      console.log(`[SwarmInit] Swarm ${id} already exists`);
      return {
        swarmId: id,
        topology,
        status: 'failed',
        config: { maxAgents, strategy, createdAt: new Date().toISOString() },
        message: `Swarm ${id} already exists`
      };
    }
    
    const swarmConfig = {
      id,
      topology,
      maxAgents,
      strategy,
      metadata: metadata || {},
      agents: new Set(),
      tasks: new Set(),
      status: 'active',
      createdAt: new Date().toISOString(),
      metrics: {
        tasksCompleted: 0,
        tasksFailed: 0,
        avgCompletionTime: 0,
        uptime: 0
      }
    };
    
    swarmRegistry.set(id, swarmConfig);
    console.log(`[SwarmInit] Swarm ${id} initialized successfully`);
    
    return {
      swarmId: id,
      topology,
      status: 'initialized',
      config: {
        maxAgents,
        strategy,
        createdAt: swarmConfig.createdAt
      },
      message: `Swarm ${id} initialized with ${topology} topology, max agents: ${maxAgents}`
    };
  }
});

// Tool 2: Spawn specialized agents dynamically
export const agentSpawn = createTool({
  id: 'agent-spawn',
  name: 'Agent Spawn',
  description: 'Spawn specialized agents dynamically within a swarm',
  inputSchema: z.object({
    swarmId: z.string().describe('Target swarm ID'),
    agentType: z.enum([
      'coordinator', 'researcher', 'coder', 'analyst', 
      'architect', 'tester', 'reviewer', 'optimizer',
      'documenter', 'monitor', 'specialist'
    ]).describe('Type of agent to spawn'),
    name: z.string().optional().describe('Agent name'),
    capabilities: z.array(z.string()).optional().describe('Agent capabilities'),
    priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
    resources: z.object({
      cpu: z.number().min(0.1).max(4).default(1),
      memory: z.number().min(256).max(8192).default(1024),
      timeout: z.number().min(1000).max(300000).default(60000)
    }).optional()
  }),
  outputSchema: z.object({
    agentId: z.string(),
    swarmId: z.string(),
    type: z.string(),
    status: z.enum(['spawned', 'failed']),
    capabilities: z.array(z.string()),
    message: z.string()
  }),
  execute: async ({ swarmId, agentType, name, capabilities, priority, resources }) => {
    console.log(`[AgentSpawn] Spawning ${agentType} agent for swarm ${swarmId}`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[AgentSpawn] Swarm ${swarmId} not found`);
      return {
        agentId: '',
        swarmId,
        type: agentType,
        status: 'failed',
        capabilities: [],
        message: `Swarm ${swarmId} not found`
      };
    }
    
    if (swarm.agents.size >= swarm.maxAgents) {
      console.log(`[AgentSpawn] Swarm ${swarmId} has reached max agents limit`);
      return {
        agentId: '',
        swarmId,
        type: agentType,
        status: 'failed',
        capabilities: [],
        message: `Swarm has reached maximum agent limit (${swarm.maxAgents})`
      };
    }
    
    const agentId = `agent-${agentType}-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const agentCapabilities = capabilities || getDefaultCapabilities(agentType);
    
    const agent = {
      id: agentId,
      swarmId,
      type: agentType,
      name: name || `${agentType}-${agentId.substring(0, 8)}`,
      capabilities: agentCapabilities,
      priority,
      resources: resources || { cpu: 1, memory: 1024, timeout: 60000 },
      status: 'active',
      tasks: new Set(),
      metrics: {
        tasksCompleted: 0,
        tasksFailed: 0,
        avgResponseTime: 0,
        utilization: 0
      },
      spawnedAt: new Date().toISOString()
    };
    
    agentRegistry.set(agentId, agent);
    swarm.agents.add(agentId);
    
    console.log(`[AgentSpawn] Agent ${agentId} spawned successfully`);
    
    return {
      agentId,
      swarmId,
      type: agentType,
      status: 'spawned',
      capabilities: agentCapabilities,
      message: `${agentType} agent spawned with ID: ${agentId}`
    };
  }
});

// Tool 3: Orchestrate complex tasks across agents
export const taskOrchestrate = createTool({
  id: 'task-orchestrate',
  name: 'Task Orchestrate',
  description: 'Orchestrate complex tasks across multiple agents in a swarm',
  inputSchema: z.object({
    swarmId: z.string().describe('Target swarm ID'),
    task: z.string().describe('Task description'),
    strategy: z.enum(['parallel', 'sequential', 'adaptive', 'balanced']).default('balanced'),
    priority: z.enum(['low', 'medium', 'high', 'critical']).default('medium'),
    dependencies: z.array(z.string()).optional().describe('Task dependencies'),
    subtasks: z.array(z.object({
      description: z.string(),
      requiredCapabilities: z.array(z.string()).optional(),
      estimatedTime: z.number().optional()
    })).optional(),
    timeout: z.number().min(1000).max(3600000).default(300000)
  }),
  outputSchema: z.object({
    taskId: z.string(),
    swarmId: z.string(),
    status: z.enum(['orchestrated', 'failed']),
    strategy: z.string(),
    assignedAgents: z.array(z.string()),
    estimatedCompletion: z.string(),
    message: z.string()
  }),
  execute: async ({ swarmId, task, strategy, priority, dependencies, subtasks, timeout }) => {
    console.log(`[TaskOrchestrate] Orchestrating task for swarm ${swarmId}: ${task}`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[TaskOrchestrate] Swarm ${swarmId} not found`);
      return {
        taskId: '',
        swarmId,
        status: 'failed',
        strategy,
        assignedAgents: [],
        estimatedCompletion: '',
        message: `Swarm ${swarmId} not found`
      };
    }
    
    const taskId = `task-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    const availableAgents = Array.from(swarm.agents).map(id => agentRegistry.get(id)).filter(a => a && a.status === 'active');
    
    if (availableAgents.length === 0) {
      console.log(`[TaskOrchestrate] No available agents in swarm ${swarmId}`);
      return {
        taskId: '',
        swarmId,
        status: 'failed',
        strategy,
        assignedAgents: [],
        estimatedCompletion: '',
        message: 'No available agents in swarm'
      };
    }
    
    // Determine task breakdown
    const taskBreakdown = subtasks || [{
      description: task,
      requiredCapabilities: [],
      estimatedTime: timeout / availableAgents.length
    }];
    
    // Assign agents based on strategy
    const assignments = assignAgentsToTasks(availableAgents, taskBreakdown, strategy);
    const assignedAgentIds = assignments.map(a => a.agentId);
    
    const taskConfig = {
      id: taskId,
      swarmId,
      description: task,
      strategy,
      priority,
      dependencies: dependencies || [],
      subtasks: taskBreakdown,
      assignments,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      estimatedCompletion: new Date(Date.now() + timeout).toISOString(),
      timeout
    };
    
    taskQueue.set(taskId, taskConfig);
    swarm.tasks.add(taskId);
    
    // Update agent assignments
    assignments.forEach(({ agentId, subtask }) => {
      const agent = agentRegistry.get(agentId);
      if (agent) {
        agent.tasks.add(taskId);
        agent.metrics.utilization = Math.min(100, agent.metrics.utilization + 20);
      }
    });
    
    console.log(`[TaskOrchestrate] Task ${taskId} orchestrated with ${assignedAgentIds.length} agents`);
    
    return {
      taskId,
      swarmId,
      status: 'orchestrated',
      strategy,
      assignedAgents: assignedAgentIds,
      estimatedCompletion: taskConfig.estimatedCompletion,
      message: `Task orchestrated with ${strategy} strategy across ${assignedAgentIds.length} agents`
    };
  }
});

// Tool 4: Get comprehensive swarm status
export const swarmStatus = createTool({
  id: 'swarm-status',
  name: 'Swarm Status',
  description: 'Get comprehensive status and metrics for a swarm',
  inputSchema: z.object({
    swarmId: z.string().describe('Swarm ID to check status'),
    includeAgents: z.boolean().default(true).describe('Include agent details'),
    includeTasks: z.boolean().default(true).describe('Include task details'),
    includeMetrics: z.boolean().default(true).describe('Include performance metrics')
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    status: z.enum(['active', 'paused', 'degraded', 'inactive', 'not_found']),
    topology: z.string().optional(),
    agents: z.object({
      total: z.number(),
      active: z.number(),
      idle: z.number(),
      busy: z.number(),
      details: z.array(z.object({
        id: z.string(),
        type: z.string(),
        status: z.string(),
        utilization: z.number()
      })).optional()
    }),
    tasks: z.object({
      total: z.number(),
      inProgress: z.number(),
      completed: z.number(),
      failed: z.number(),
      queued: z.number()
    }),
    metrics: z.object({
      uptime: z.string(),
      avgTaskCompletionTime: z.number(),
      successRate: z.number(),
      throughput: z.number()
    }).optional(),
    message: z.string()
  }),
  execute: async ({ swarmId, includeAgents, includeTasks, includeMetrics }) => {
    console.log(`[SwarmStatus] Checking status for swarm ${swarmId}`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[SwarmStatus] Swarm ${swarmId} not found`);
      return {
        swarmId,
        status: 'not_found',
        agents: { total: 0, active: 0, idle: 0, busy: 0 },
        tasks: { total: 0, inProgress: 0, completed: 0, failed: 0, queued: 0 },
        message: `Swarm ${swarmId} not found`
      };
    }
    
    // Calculate agent statistics
    const agents = Array.from(swarm.agents).map(id => agentRegistry.get(id)).filter(Boolean);
    const agentStats = {
      total: agents.length,
      active: agents.filter(a => a.status === 'active').length,
      idle: agents.filter(a => a.status === 'active' && a.tasks.size === 0).length,
      busy: agents.filter(a => a.status === 'active' && a.tasks.size > 0).length,
      details: includeAgents ? agents.map(a => ({
        id: a.id,
        type: a.type,
        status: a.status,
        utilization: a.metrics.utilization
      })) : undefined
    };
    
    // Calculate task statistics
    const tasks = Array.from(swarm.tasks).map(id => taskQueue.get(id)).filter(Boolean);
    const taskStats = {
      total: tasks.length,
      inProgress: tasks.filter(t => t.status === 'in_progress').length,
      completed: tasks.filter(t => t.status === 'completed').length,
      failed: tasks.filter(t => t.status === 'failed').length,
      queued: tasks.filter(t => t.status === 'queued').length
    };
    
    // Calculate metrics
    const uptime = Date.now() - new Date(swarm.createdAt).getTime();
    const metrics = includeMetrics ? {
      uptime: `${Math.floor(uptime / 1000 / 60)} minutes`,
      avgTaskCompletionTime: swarm.metrics.avgCompletionTime,
      successRate: swarm.metrics.tasksCompleted > 0 
        ? (swarm.metrics.tasksCompleted / (swarm.metrics.tasksCompleted + swarm.metrics.tasksFailed)) * 100 
        : 0,
      throughput: swarm.metrics.tasksCompleted / (uptime / 1000 / 60) // tasks per minute
    } : undefined;
    
    // Determine overall status
    let status = 'active';
    if (agentStats.active === 0) status = 'inactive';
    else if (agentStats.active < swarm.maxAgents * 0.5) status = 'degraded';
    else if (taskStats.failed > taskStats.completed) status = 'degraded';
    
    console.log(`[SwarmStatus] Swarm ${swarmId} status: ${status}`);
    
    return {
      swarmId,
      status,
      topology: swarm.topology,
      agents: agentStats,
      tasks: taskStats,
      metrics,
      message: `Swarm ${swarmId} is ${status} with ${agentStats.active} active agents and ${taskStats.inProgress} tasks in progress`
    };
  }
});

// Tool 5: Dynamic swarm scaling
export const swarmScale = createTool({
  id: 'swarm-scale',
  name: 'Swarm Scale',
  description: 'Dynamically scale swarm by adjusting agent count',
  inputSchema: z.object({
    swarmId: z.string().describe('Swarm ID to scale'),
    targetSize: z.number().min(0).max(100).describe('Target number of agents'),
    scaleType: z.enum(['up', 'down', 'auto']).default('auto').describe('Scaling direction'),
    agentTypes: z.array(z.enum([
      'coordinator', 'researcher', 'coder', 'analyst',
      'architect', 'tester', 'reviewer', 'optimizer',
      'documenter', 'monitor', 'specialist'
    ])).optional().describe('Preferred agent types for scaling up'),
    preserveAgents: z.array(z.string()).optional().describe('Agent IDs to preserve during scale down')
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    previousSize: z.number(),
    currentSize: z.number(),
    scaledAgents: z.array(z.object({
      action: z.enum(['added', 'removed']),
      agentId: z.string(),
      agentType: z.string()
    })),
    status: z.enum(['scaled', 'partial', 'failed']),
    message: z.string()
  }),
  execute: async ({ swarmId, targetSize, scaleType, agentTypes, preserveAgents }) => {
    console.log(`[SwarmScale] Scaling swarm ${swarmId} to ${targetSize} agents`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[SwarmScale] Swarm ${swarmId} not found`);
      return {
        swarmId,
        previousSize: 0,
        currentSize: 0,
        scaledAgents: [],
        status: 'failed',
        message: `Swarm ${swarmId} not found`
      };
    }
    
    const currentAgents = Array.from(swarm.agents).map(id => agentRegistry.get(id)).filter(Boolean);
    const previousSize = currentAgents.length;
    const scaledAgents = [];
    
    // Determine actual scaling action
    let actualScaleType = scaleType;
    if (scaleType === 'auto') {
      actualScaleType = targetSize > previousSize ? 'up' : 'down';
    }
    
    if (actualScaleType === 'up' && targetSize > previousSize) {
      // Scale up: spawn new agents
      const agentsToAdd = Math.min(targetSize - previousSize, swarm.maxAgents - previousSize);
      const typesToUse = agentTypes || ['researcher', 'coder', 'analyst', 'tester'];
      
      for (let i = 0; i < agentsToAdd; i++) {
        const agentType = typesToUse[i % typesToUse.length];
        const agentId = `agent-${agentType}-${Date.now()}-${Math.random().toString(36).substring(7)}`;
        
        const agent = {
          id: agentId,
          swarmId,
          type: agentType,
          name: `${agentType}-${agentId.substring(0, 8)}`,
          capabilities: getDefaultCapabilities(agentType),
          priority: 'medium',
          resources: { cpu: 1, memory: 1024, timeout: 60000 },
          status: 'active',
          tasks: new Set(),
          metrics: {
            tasksCompleted: 0,
            tasksFailed: 0,
            avgResponseTime: 0,
            utilization: 0
          },
          spawnedAt: new Date().toISOString()
        };
        
        agentRegistry.set(agentId, agent);
        swarm.agents.add(agentId);
        scaledAgents.push({ action: 'added', agentId, agentType });
        
        console.log(`[SwarmScale] Added agent ${agentId} (${agentType})`);
      }
    } else if (actualScaleType === 'down' && targetSize < previousSize) {
      // Scale down: remove agents
      const agentsToRemove = previousSize - targetSize;
      const preserveSet = new Set(preserveAgents || []);
      
      // Sort agents by utilization (remove least utilized first)
      const removableCandidates = currentAgents
        .filter(a => !preserveSet.has(a.id) && a.tasks.size === 0)
        .sort((a, b) => a.metrics.utilization - b.metrics.utilization);
      
      const agentsRemoved = removableCandidates.slice(0, agentsToRemove);
      
      agentsRemoved.forEach(agent => {
        swarm.agents.delete(agent.id);
        agentRegistry.delete(agent.id);
        scaledAgents.push({ action: 'removed', agentId: agent.id, agentType: agent.type });
        console.log(`[SwarmScale] Removed agent ${agent.id} (${agent.type})`);
      });
    }
    
    const currentSize = swarm.agents.size;
    const status = currentSize === targetSize ? 'scaled' : 'partial';
    
    console.log(`[SwarmScale] Swarm ${swarmId} scaled from ${previousSize} to ${currentSize} agents`);
    
    return {
      swarmId,
      previousSize,
      currentSize,
      scaledAgents,
      status,
      message: `Swarm scaled from ${previousSize} to ${currentSize} agents (target: ${targetSize})`
    };
  }
});

// Tool 6: Gracefully shutdown swarm
export const swarmDestroy = createTool({
  id: 'swarm-destroy',
  name: 'Swarm Destroy',
  description: 'Gracefully shutdown and destroy a swarm',
  inputSchema: z.object({
    swarmId: z.string().describe('Swarm ID to destroy'),
    force: z.boolean().default(false).describe('Force destroy even with active tasks'),
    preserveData: z.boolean().default(true).describe('Preserve swarm data for analysis'),
    timeout: z.number().min(0).max(60000).default(5000).describe('Graceful shutdown timeout in ms')
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    status: z.enum(['destroyed', 'failed', 'timeout']),
    finalMetrics: z.object({
      totalAgents: z.number(),
      totalTasks: z.number(),
      completedTasks: z.number(),
      failedTasks: z.number(),
      uptime: z.string()
    }),
    preservedData: z.boolean(),
    message: z.string()
  }),
  execute: async ({ swarmId, force, preserveData, timeout }) => {
    console.log(`[SwarmDestroy] Initiating shutdown for swarm ${swarmId}`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[SwarmDestroy] Swarm ${swarmId} not found`);
      return {
        swarmId,
        status: 'failed',
        finalMetrics: {
          totalAgents: 0,
          totalTasks: 0,
          completedTasks: 0,
          failedTasks: 0,
          uptime: '0 minutes'
        },
        preservedData: false,
        message: `Swarm ${swarmId} not found`
      };
    }
    
    // Check for active tasks
    const activeTasks = Array.from(swarm.tasks)
      .map(id => taskQueue.get(id))
      .filter(t => t && t.status === 'in_progress');
    
    if (activeTasks.length > 0 && !force) {
      console.log(`[SwarmDestroy] Swarm has ${activeTasks.length} active tasks, use force=true to destroy`);
      return {
        swarmId,
        status: 'failed',
        finalMetrics: {
          totalAgents: swarm.agents.size,
          totalTasks: swarm.tasks.size,
          completedTasks: swarm.metrics.tasksCompleted,
          failedTasks: swarm.metrics.tasksFailed,
          uptime: `${Math.floor((Date.now() - new Date(swarm.createdAt).getTime()) / 1000 / 60)} minutes`
        },
        preservedData: false,
        message: `Cannot destroy swarm with ${activeTasks.length} active tasks (use force=true)`
      };
    }
    
    // Graceful shutdown: notify agents
    const agents = Array.from(swarm.agents).map(id => agentRegistry.get(id)).filter(Boolean);
    console.log(`[SwarmDestroy] Shutting down ${agents.length} agents`);
    
    // Simulate graceful shutdown with timeout
    await new Promise(resolve => setTimeout(resolve, Math.min(timeout, 1000)));
    
    // Collect final metrics
    const finalMetrics = {
      totalAgents: swarm.agents.size,
      totalTasks: swarm.tasks.size,
      completedTasks: swarm.metrics.tasksCompleted,
      failedTasks: swarm.metrics.tasksFailed,
      uptime: `${Math.floor((Date.now() - new Date(swarm.createdAt).getTime()) / 1000 / 60)} minutes`
    };
    
    // Preserve data if requested
    if (preserveData) {
      const swarmData = {
        ...swarm,
        agents: agents.map(a => ({ ...a, tasks: Array.from(a.tasks) })),
        tasks: Array.from(swarm.tasks).map(id => taskQueue.get(id)).filter(Boolean),
        destroyedAt: new Date().toISOString()
      };
      metricsStore.set(`destroyed-${swarmId}`, swarmData);
      console.log(`[SwarmDestroy] Swarm data preserved for analysis`);
    }
    
    // Clean up registries
    agents.forEach(agent => {
      agentRegistry.delete(agent.id);
    });
    
    swarm.tasks.forEach(taskId => {
      taskQueue.delete(taskId);
    });
    
    swarmRegistry.delete(swarmId);
    
    console.log(`[SwarmDestroy] Swarm ${swarmId} destroyed successfully`);
    
    return {
      swarmId,
      status: 'destroyed',
      finalMetrics,
      preservedData,
      message: `Swarm ${swarmId} destroyed after ${finalMetrics.uptime} of operation`
    };
  }
});

// Tool 7: Optimize swarm topology
export const topologyOptimize = createTool({
  id: 'topology-optimize',
  name: 'Topology Optimize',
  description: 'Optimize swarm topology based on current workload and performance',
  inputSchema: z.object({
    swarmId: z.string().describe('Swarm ID to optimize'),
    targetMetric: z.enum(['latency', 'throughput', 'resilience', 'efficiency']).default('efficiency'),
    constraints: z.object({
      maxLatency: z.number().optional(),
      minThroughput: z.number().optional(),
      maxResourceUsage: z.number().min(0).max(100).optional()
    }).optional()
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    previousTopology: z.string(),
    recommendedTopology: z.string(),
    optimizationScore: z.number().min(0).max(100),
    changes: z.array(z.object({
      type: z.enum(['topology', 'connection', 'hierarchy']),
      description: z.string()
    })),
    projectedImprovement: z.object({
      metric: z.string(),
      currentValue: z.number(),
      projectedValue: z.number(),
      improvementPercent: z.number()
    }),
    status: z.enum(['optimized', 'no_change_needed', 'failed']),
    message: z.string()
  }),
  execute: async ({ swarmId, targetMetric, constraints }) => {
    console.log(`[TopologyOptimize] Optimizing topology for swarm ${swarmId} targeting ${targetMetric}`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[TopologyOptimize] Swarm ${swarmId} not found`);
      return {
        swarmId,
        previousTopology: '',
        recommendedTopology: '',
        optimizationScore: 0,
        changes: [],
        projectedImprovement: {
          metric: targetMetric,
          currentValue: 0,
          projectedValue: 0,
          improvementPercent: 0
        },
        status: 'failed',
        message: `Swarm ${swarmId} not found`
      };
    }
    
    const agents = Array.from(swarm.agents).map(id => agentRegistry.get(id)).filter(Boolean);
    const tasks = Array.from(swarm.tasks).map(id => taskQueue.get(id)).filter(Boolean);
    
    // Analyze current performance
    const currentMetrics = analyzeSwarmMetrics(swarm, agents, tasks);
    
    // Determine optimal topology based on workload characteristics
    const workloadProfile = {
      agentCount: agents.length,
      taskComplexity: tasks.filter(t => t.subtasks && t.subtasks.length > 1).length / Math.max(tasks.length, 1),
      parallelism: tasks.filter(t => t.strategy === 'parallel').length / Math.max(tasks.length, 1),
      communicationIntensity: calculateCommunicationIntensity(agents, tasks)
    };
    
    let recommendedTopology = swarm.topology;
    const changes = [];
    
    // Topology recommendations based on target metric
    if (targetMetric === 'latency') {
      if (workloadProfile.communicationIntensity > 0.7) {
        recommendedTopology = 'mesh';
        changes.push({
          type: 'topology',
          description: 'Switch to mesh topology for lower latency with high communication needs'
        });
      } else if (workloadProfile.agentCount > 20) {
        recommendedTopology = 'hierarchical';
        changes.push({
          type: 'topology',
          description: 'Use hierarchical topology to reduce communication overhead'
        });
      }
    } else if (targetMetric === 'throughput') {
      if (workloadProfile.parallelism > 0.6) {
        recommendedTopology = 'star';
        changes.push({
          type: 'topology',
          description: 'Star topology recommended for high parallelism workloads'
        });
      }
    } else if (targetMetric === 'resilience') {
      recommendedTopology = 'mesh';
      changes.push({
        type: 'topology',
        description: 'Mesh topology provides best resilience through redundant connections'
      });
    } else if (targetMetric === 'efficiency') {
      if (workloadProfile.agentCount < 10) {
        recommendedTopology = 'star';
        changes.push({
          type: 'topology',
          description: 'Star topology is most efficient for small swarms'
        });
      } else if (workloadProfile.taskComplexity > 0.5) {
        recommendedTopology = 'hierarchical';
        changes.push({
          type: 'topology',
          description: 'Hierarchical topology efficiently handles complex task decomposition'
        });
      }
    }
    
    // Add connection optimizations
    if (workloadProfile.communicationIntensity > 0.5) {
      changes.push({
        type: 'connection',
        description: 'Increase connection pooling between frequently communicating agents'
      });
    }
    
    // Calculate optimization score and projected improvement
    const optimizationScore = calculateOptimizationScore(swarm.topology, recommendedTopology, workloadProfile);
    const currentValue = currentMetrics[targetMetric] || 50;
    const projectedValue = currentValue * (1 + optimizationScore / 100);
    
    const status = recommendedTopology !== swarm.topology || changes.length > 0 ? 'optimized' : 'no_change_needed';
    
    console.log(`[TopologyOptimize] Optimization complete: ${swarm.topology} -> ${recommendedTopology}`);
    
    return {
      swarmId,
      previousTopology: swarm.topology,
      recommendedTopology,
      optimizationScore,
      changes,
      projectedImprovement: {
        metric: targetMetric,
        currentValue,
        projectedValue,
        improvementPercent: ((projectedValue - currentValue) / currentValue) * 100
      },
      status,
      message: status === 'optimized' 
        ? `Topology optimization can improve ${targetMetric} by ${Math.round(optimizationScore)}%`
        : 'Current topology is already optimal for the workload'
    };
  }
});

// Tool 8: Distribute tasks efficiently
export const loadBalance = createTool({
  id: 'load-balance',
  name: 'Load Balance',
  description: 'Distribute tasks efficiently across swarm agents',
  inputSchema: z.object({
    swarmId: z.string().describe('Swarm ID'),
    tasks: z.array(z.object({
      id: z.string(),
      description: z.string(),
      requiredCapabilities: z.array(z.string()).optional(),
      estimatedLoad: z.number().min(0).max(100).optional(),
      priority: z.enum(['low', 'medium', 'high', 'critical']).optional()
    })).describe('Tasks to distribute'),
    strategy: z.enum(['round-robin', 'least-loaded', 'capability-match', 'adaptive']).default('adaptive')
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    distributions: z.array(z.object({
      taskId: z.string(),
      assignedAgent: z.string(),
      agentType: z.string(),
      currentLoad: z.number(),
      estimatedNewLoad: z.number()
    })),
    balanceScore: z.number().min(0).max(100),
    strategy: z.string(),
    status: z.enum(['balanced', 'partial', 'failed']),
    message: z.string()
  }),
  execute: async ({ swarmId, tasks, strategy }) => {
    console.log(`[LoadBalance] Balancing ${tasks.length} tasks across swarm ${swarmId} using ${strategy} strategy`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[LoadBalance] Swarm ${swarmId} not found`);
      return {
        swarmId,
        distributions: [],
        balanceScore: 0,
        strategy,
        status: 'failed',
        message: `Swarm ${swarmId} not found`
      };
    }
    
    const agents = Array.from(swarm.agents)
      .map(id => agentRegistry.get(id))
      .filter(a => a && a.status === 'active');
    
    if (agents.length === 0) {
      console.log(`[LoadBalance] No active agents available in swarm`);
      return {
        swarmId,
        distributions: [],
        balanceScore: 0,
        strategy,
        status: 'failed',
        message: 'No active agents available for task distribution'
      };
    }
    
    const distributions = [];
    const agentLoads = new Map(agents.map(a => [a.id, a.metrics.utilization || 0]));
    
    // Sort tasks by priority
    const sortedTasks = [...tasks].sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return (priorityOrder[b.priority || 'medium'] || 2) - (priorityOrder[a.priority || 'medium'] || 2);
    });
    
    for (const task of sortedTasks) {
      let selectedAgent = null;
      
      switch (strategy) {
        case 'round-robin':
          // Simple round-robin distribution
          const index = distributions.length % agents.length;
          selectedAgent = agents[index];
          break;
          
        case 'least-loaded':
          // Assign to agent with lowest current load
          selectedAgent = agents.reduce((min, agent) => 
            (agentLoads.get(agent.id) || 0) < (agentLoads.get(min.id) || 0) ? agent : min
          );
          break;
          
        case 'capability-match':
          // Match task requirements with agent capabilities
          if (task.requiredCapabilities && task.requiredCapabilities.length > 0) {
            const capableAgents = agents.filter(agent =>
              task.requiredCapabilities.every(cap => agent.capabilities.includes(cap))
            );
            if (capableAgents.length > 0) {
              selectedAgent = capableAgents.reduce((min, agent) =>
                (agentLoads.get(agent.id) || 0) < (agentLoads.get(min.id) || 0) ? agent : min
              );
            }
          }
          if (!selectedAgent) {
            selectedAgent = agents[0]; // Fallback
          }
          break;
          
        case 'adaptive':
        default:
          // Adaptive strategy: combination of capability matching and load balancing
          let candidateAgents = agents;
          
          // Filter by capabilities if specified
          if (task.requiredCapabilities && task.requiredCapabilities.length > 0) {
            const capableAgents = agents.filter(agent =>
              task.requiredCapabilities.some(cap => agent.capabilities.includes(cap))
            );
            if (capableAgents.length > 0) {
              candidateAgents = capableAgents;
            }
          }
          
          // Select least loaded from candidates
          selectedAgent = candidateAgents.reduce((best, agent) => {
            const agentScore = calculateAgentScore(agent, task, agentLoads.get(agent.id) || 0);
            const bestScore = calculateAgentScore(best, task, agentLoads.get(best.id) || 0);
            return agentScore > bestScore ? agent : best;
          });
          break;
      }
      
      const currentLoad = agentLoads.get(selectedAgent.id) || 0;
      const taskLoad = task.estimatedLoad || 10;
      const newLoad = Math.min(100, currentLoad + taskLoad);
      
      distributions.push({
        taskId: task.id,
        assignedAgent: selectedAgent.id,
        agentType: selectedAgent.type,
        currentLoad,
        estimatedNewLoad: newLoad
      });
      
      agentLoads.set(selectedAgent.id, newLoad);
    }
    
    // Calculate balance score (lower standard deviation = better balance)
    const loads = Array.from(agentLoads.values());
    const avgLoad = loads.reduce((sum, load) => sum + load, 0) / loads.length;
    const variance = loads.reduce((sum, load) => sum + Math.pow(load - avgLoad, 2), 0) / loads.length;
    const stdDev = Math.sqrt(variance);
    const balanceScore = Math.max(0, 100 - stdDev);
    
    console.log(`[LoadBalance] Distributed ${distributions.length} tasks with balance score ${balanceScore.toFixed(2)}`);
    
    return {
      swarmId,
      distributions,
      balanceScore,
      strategy,
      status: distributions.length === tasks.length ? 'balanced' : 'partial',
      message: `Distributed ${distributions.length} tasks across ${agents.length} agents with ${strategy} strategy`
    };
  }
});

// Tool 9: Synchronize agent coordination
export const coordinationSync = createTool({
  id: 'coordination-sync',
  name: 'Coordination Sync',
  description: 'Synchronize coordination state across all agents in swarm',
  inputSchema: z.object({
    swarmId: z.string().describe('Swarm ID'),
    syncType: z.enum(['full', 'incremental', 'selective']).default('incremental'),
    syncData: z.object({
      sharedState: z.record(z.any()).optional(),
      taskUpdates: z.array(z.object({
        taskId: z.string(),
        status: z.string(),
        progress: z.number().optional()
      })).optional(),
      agentUpdates: z.array(z.object({
        agentId: z.string(),
        status: z.string(),
        capabilities: z.array(z.string()).optional()
      })).optional()
    }).optional()
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    syncedAgents: z.number(),
    syncType: z.string(),
    syncTimestamp: z.string(),
    conflicts: z.array(z.object({
      type: z.string(),
      description: z.string(),
      resolution: z.string()
    })),
    status: z.enum(['synced', 'partial', 'failed']),
    message: z.string()
  }),
  execute: async ({ swarmId, syncType, syncData }) => {
    console.log(`[CoordinationSync] Synchronizing swarm ${swarmId} with ${syncType} sync`);
    
    const swarm = swarmRegistry.get(swarmId);
    if (!swarm) {
      console.log(`[CoordinationSync] Swarm ${swarmId} not found`);
      return {
        swarmId,
        syncedAgents: 0,
        syncType,
        syncTimestamp: new Date().toISOString(),
        conflicts: [],
        status: 'failed',
        message: `Swarm ${swarmId} not found`
      };
    }
    
    const agents = Array.from(swarm.agents)
      .map(id => agentRegistry.get(id))
      .filter(a => a && a.status === 'active');
    
    const conflicts = [];
    let syncedCount = 0;
    
    // Process sync based on type
    if (syncType === 'full' || syncType === 'incremental') {
      // Sync shared state
      if (syncData?.sharedState) {
        swarm.sharedState = { ...swarm.sharedState, ...syncData.sharedState };
        console.log(`[CoordinationSync] Updated shared state with ${Object.keys(syncData.sharedState).length} entries`);
      }
      
      // Sync task updates
      if (syncData?.taskUpdates) {
        syncData.taskUpdates.forEach(update => {
          const task = taskQueue.get(update.taskId);
          if (task) {
            const previousStatus = task.status;
            task.status = update.status;
            if (update.progress !== undefined) {
              task.progress = update.progress;
            }
            
            // Check for conflicts
            if (previousStatus === 'completed' && update.status !== 'completed') {
              conflicts.push({
                type: 'task_status',
                description: `Task ${update.taskId} status conflict: ${previousStatus} -> ${update.status}`,
                resolution: 'Kept new status'
              });
            }
          }
        });
      }
      
      // Sync agent updates
      if (syncData?.agentUpdates) {
        syncData.agentUpdates.forEach(update => {
          const agent = agentRegistry.get(update.agentId);
          if (agent && swarm.agents.has(update.agentId)) {
            agent.status = update.status;
            if (update.capabilities) {
              agent.capabilities = update.capabilities;
            }
            syncedCount++;
          }
        });
      }
    }
    
    // Broadcast sync to all agents
    const syncTimestamp = new Date().toISOString();
    agents.forEach(agent => {
      agent.lastSync = syncTimestamp;
      syncedCount++;
    });
    
    // Update swarm sync metadata
    swarm.lastSync = syncTimestamp;
    swarm.syncVersion = (swarm.syncVersion || 0) + 1;
    
    console.log(`[CoordinationSync] Synchronized ${syncedCount} agents with ${conflicts.length} conflicts`);
    
    return {
      swarmId,
      syncedAgents: syncedCount,
      syncType,
      syncTimestamp,
      conflicts,
      status: conflicts.length === 0 ? 'synced' : 'partial',
      message: `Synchronized ${syncedCount} agents in swarm with ${syncType} sync`
    };
  }
});

// Tool 10: Get detailed agent metrics
export const agentMetrics = createTool({
  id: 'agent-metrics',
  name: 'Agent Metrics',
  description: 'Get detailed performance metrics for a specific agent',
  inputSchema: z.object({
    agentId: z.string().describe('Agent ID'),
    timeRange: z.enum(['1h', '6h', '24h', '7d', 'all']).default('24h'),
    includeTaskHistory: z.boolean().default(true),
    includeResourceUsage: z.boolean().default(true)
  }),
  outputSchema: z.object({
    agentId: z.string(),
    agentType: z.string(),
    status: z.string(),
    uptime: z.string(),
    performance: z.object({
      tasksCompleted: z.number(),
      tasksFailed: z.number(),
      successRate: z.number(),
      avgResponseTime: z.number(),
      throughput: z.number()
    }),
    resourceUsage: z.object({
      cpuUtilization: z.number(),
      memoryUsage: z.number(),
      activeConnections: z.number(),
      queueDepth: z.number()
    }).optional(),
    taskHistory: z.array(z.object({
      taskId: z.string(),
      status: z.string(),
      startTime: z.string(),
      endTime: z.string().optional(),
      duration: z.number().optional()
    })).optional(),
    capabilities: z.array(z.string()),
    health: z.enum(['healthy', 'degraded', 'unhealthy']),
    message: z.string()
  }),
  execute: async ({ agentId, timeRange, includeTaskHistory, includeResourceUsage }) => {
    console.log(`[AgentMetrics] Retrieving metrics for agent ${agentId} (${timeRange})`);
    
    const agent = agentRegistry.get(agentId);
    if (!agent) {
      console.log(`[AgentMetrics] Agent ${agentId} not found`);
      return {
        agentId,
        agentType: 'unknown',
        status: 'not_found',
        uptime: '0 minutes',
        performance: {
          tasksCompleted: 0,
          tasksFailed: 0,
          successRate: 0,
          avgResponseTime: 0,
          throughput: 0
        },
        capabilities: [],
        health: 'unhealthy',
        message: `Agent ${agentId} not found`
      };
    }
    
    // Calculate uptime
    const uptimeMs = Date.now() - new Date(agent.spawnedAt).getTime();
    const uptimeMinutes = Math.floor(uptimeMs / 1000 / 60);
    const uptime = uptimeMinutes >= 60 
      ? `${Math.floor(uptimeMinutes / 60)} hours ${uptimeMinutes % 60} minutes`
      : `${uptimeMinutes} minutes`;
    
    // Calculate performance metrics
    const totalTasks = agent.metrics.tasksCompleted + agent.metrics.tasksFailed;
    const successRate = totalTasks > 0 
      ? (agent.metrics.tasksCompleted / totalTasks) * 100 
      : 0;
    const throughput = uptimeMinutes > 0 
      ? agent.metrics.tasksCompleted / uptimeMinutes 
      : 0;
    
    const performance = {
      tasksCompleted: agent.metrics.tasksCompleted,
      tasksFailed: agent.metrics.tasksFailed,
      successRate,
      avgResponseTime: agent.metrics.avgResponseTime || 0,
      throughput
    };
    
    // Resource usage (simulated)
    const resourceUsage = includeResourceUsage ? {
      cpuUtilization: agent.metrics.utilization || 0,
      memoryUsage: Math.min(100, (agent.tasks.size * 15) + 20),
      activeConnections: agent.tasks.size,
      queueDepth: Math.max(0, agent.tasks.size - 1)
    } : undefined;
    
    // Task history (simulated)
    const taskHistory = includeTaskHistory ? Array.from(agent.tasks).map(taskId => {
      const task = taskQueue.get(taskId);
      return {
        taskId,
        status: task?.status || 'unknown',
        startTime: task?.createdAt || new Date().toISOString(),
        endTime: task?.status === 'completed' ? new Date().toISOString() : undefined,
        duration: task?.status === 'completed' ? Math.floor(Math.random() * 30000) + 5000 : undefined
      };
    }).slice(0, 10) : undefined;
    
    // Determine health status
    let health = 'healthy';
    if (agent.status !== 'active') health = 'unhealthy';
    else if (successRate < 80 || agent.metrics.utilization > 90) health = 'degraded';
    
    console.log(`[AgentMetrics] Agent ${agentId} health: ${health}, success rate: ${successRate.toFixed(2)}%`);
    
    return {
      agentId,
      agentType: agent.type,
      status: agent.status,
      uptime,
      performance,
      resourceUsage,
      taskHistory,
      capabilities: agent.capabilities,
      health,
      message: `Agent ${agentId} (${agent.type}) is ${health} with ${successRate.toFixed(2)}% success rate`
    };
  }
});

// Helper functions
function getDefaultCapabilities(agentType) {
  const capabilityMap = {
    coordinator: ['task-orchestration', 'agent-management', 'resource-allocation'],
    researcher: ['data-gathering', 'analysis', 'pattern-recognition'],
    coder: ['code-generation', 'debugging', 'refactoring', 'testing'],
    analyst: ['data-analysis', 'reporting', 'visualization', 'insights'],
    architect: ['system-design', 'pattern-implementation', 'documentation'],
    tester: ['unit-testing', 'integration-testing', 'performance-testing'],
    reviewer: ['code-review', 'quality-assurance', 'best-practices'],
    optimizer: ['performance-optimization', 'resource-optimization', 'algorithm-optimization'],
    documenter: ['documentation', 'api-docs', 'tutorials', 'guides'],
    monitor: ['system-monitoring', 'alerting', 'metrics-collection'],
    specialist: ['domain-expertise', 'custom-logic', 'integration']
  };
  
  return capabilityMap[agentType] || ['general-processing'];
}

function assignAgentsToTasks(agents, tasks, strategy) {
  const assignments = [];
  
  if (strategy === 'parallel') {
    // Assign each task to a different agent if possible
    tasks.forEach((task, index) => {
      const agent = agents[index % agents.length];
      assignments.push({ agentId: agent.id, subtask: task });
    });
  } else if (strategy === 'sequential') {
    // Assign all tasks to the most capable agent
    const bestAgent = agents.reduce((best, agent) => 
      agent.metrics.successRate > best.metrics.successRate ? agent : best
    );
    tasks.forEach(task => {
      assignments.push({ agentId: bestAgent.id, subtask: task });
    });
  } else {
    // Balanced or adaptive strategy
    tasks.forEach(task => {
      const capableAgents = task.requiredCapabilities && task.requiredCapabilities.length > 0
        ? agents.filter(agent => 
            task.requiredCapabilities.some(cap => agent.capabilities.includes(cap))
          )
        : agents;
      
      const selectedAgent = capableAgents.length > 0
        ? capableAgents.reduce((least, agent) => 
            agent.metrics.utilization < least.metrics.utilization ? agent : least
          )
        : agents[0];
      
      assignments.push({ agentId: selectedAgent.id, subtask: task });
    });
  }
  
  return assignments;
}

function analyzeSwarmMetrics(swarm, agents, tasks) {
  const activeTasks = tasks.filter(t => t.status === 'in_progress').length;
  const avgUtilization = agents.reduce((sum, a) => sum + a.metrics.utilization, 0) / Math.max(agents.length, 1);
  
  return {
    latency: 100 - avgUtilization, // Simplified metric
    throughput: swarm.metrics.tasksCompleted / Math.max((Date.now() - new Date(swarm.createdAt).getTime()) / 1000 / 60, 1),
    resilience: agents.filter(a => a.status === 'active').length / Math.max(agents.length, 1) * 100,
    efficiency: (swarm.metrics.tasksCompleted / Math.max(swarm.metrics.tasksCompleted + swarm.metrics.tasksFailed, 1)) * 100
  };
}

function calculateCommunicationIntensity(agents, tasks) {
  // Simplified calculation based on task parallelism and agent count
  const parallelTasks = tasks.filter(t => t.strategy === 'parallel').length;
  const totalTasks = Math.max(tasks.length, 1);
  const agentRatio = Math.min(agents.length / 10, 1);
  
  return (parallelTasks / totalTasks) * agentRatio;
}

function calculateOptimizationScore(currentTopology, recommendedTopology, workloadProfile) {
  if (currentTopology === recommendedTopology) return 0;
  
  // Base improvement score
  let score = 20;
  
  // Additional points based on workload fit
  if (recommendedTopology === 'mesh' && workloadProfile.communicationIntensity > 0.6) score += 15;
  if (recommendedTopology === 'hierarchical' && workloadProfile.taskComplexity > 0.5) score += 15;
  if (recommendedTopology === 'star' && workloadProfile.agentCount < 10) score += 10;
  if (recommendedTopology === 'ring' && workloadProfile.parallelism < 0.3) score += 10;
  
  return Math.min(score, 50); // Cap at 50% improvement
}

function calculateAgentScore(agent, task, currentLoad) {
  let score = 100 - currentLoad; // Start with inverse of current load
  
  // Bonus for capability match
  if (task.requiredCapabilities) {
    const matchingCaps = task.requiredCapabilities.filter(cap => 
      agent.capabilities.includes(cap)
    ).length;
    score += matchingCaps * 10;
  }
  
  // Bonus for agent performance
  score += agent.metrics.successRate * 0.2;
  
  // Penalty for high utilization
  if (agent.metrics.utilization > 80) score -= 20;
  
  return score;
}

// Export all tools
// export const swarmOrchestrationTools = [
//   swarmInit,
//   agentSpawn,
//   taskOrchestrate,
//   swarmStatus,
//   swarmScale,
//   swarmDestroy,
//   topologyOptimize,
//   loadBalance,
//   coordinationSync,
//   agentMetrics
// ];

// Export as object for consistency
export const swarmOrchestrationTools = {
  swarmInit,
  agentSpawn,
  taskOrchestrate,
  swarmStatus,
  swarmScale,
  swarmDestroy,
  topologyOptimize,
  loadBalance,
  coordinationSync,
  agentMetrics
};
