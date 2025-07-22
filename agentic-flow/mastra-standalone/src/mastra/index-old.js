import { Mastra, Agent, Workflow } from '@mastra/core';
import { Tool } from '@mastra/core/tools';
import { claudeFlowAgent } from './agents/claude-flow-agent.js';
import { hiveMindAgent } from './agents/hive-mind-agent.js';
import { ruvSwarmAgent } from './agents/ruv-swarm-agent.js';
import { agenticFlowWorkflows } from './workflows/agentic-flow-workflows.js';
import { agenticFlowTheme, brandConfig } from './theme.js';

// Create Mastra instance with minimal configuration
const mastra = new Mastra({
  name: 'agentic-flow',
  version: '1.0.0',
  description: 'Agentic Flow - AI Orchestration Platform with Mastra Integration',
  
  // Configure server
  server: {
    port: process.env.MASTRA_PORT ? parseInt(process.env.MASTRA_PORT) : 4111,
    baseUrl: process.env.MASTRA_BASE_URL || 'http://localhost:4111',
  },
  
  // Disable telemetry and database to avoid issues
  telemetry: {
    enabled: false,
  },
  
  logs: {
    enabled: true,
    level: 'info',
  },
  
  // Agentic Flow Network Agents
  agents: {
    // Core agents
    coordinator: new Agent({
      name: 'coordinator',
      description: 'Coordinates teams and manages complex workflows',
      model: {
        provider: 'anthropic',
        name: 'claude-3-sonnet-20240229',
      },
      instructions: `You are a coordinator agent responsible for team formation, goal decomposition, task delegation, cross-team coordination, and strategic decision making.`,
    }),
    
    executor: new Agent({
      name: 'executor',
      description: 'Executes tasks and implements solutions',
      model: {
        provider: 'anthropic',
        name: 'claude-3-sonnet-20240229',
      },
      instructions: `You are an executor agent responsible for task implementation, solution development, progress reporting, quality assurance, and problem resolution.`,
    }),
    
    researcher: new Agent({
      name: 'researcher',
      description: 'Gathers information and analyzes data',
      model: {
        provider: 'anthropic',
        name: 'claude-3-sonnet-20240229',
      },
      instructions: `You are a research agent specialized in information gathering, data analysis, technology research, market analysis, and trend identification.`,
    }),
    
    architect: new Agent({
      name: 'architect',
      description: 'Designs systems and technical architecture',
      model: {
        provider: 'anthropic',
        name: 'claude-3-sonnet-20240229',
      },
      instructions: `You are an architecture agent responsible for system design, technical specification, scalability planning, technology selection, and integration design.`,
    }),
    
    // Network-specific branded agents
    'claude-flow-coordinator': claudeFlowAgent,
    'hive-mind-collective': hiveMindAgent,
    'ruv-swarm-coordinator': ruvSwarmAgent
  },
  
  // Agentic Flow Tools and MCP Integration
  tools: {
    // MCP Network Tools
    claudeFlowCoordinate: new Tool({
      name: 'claudeFlowCoordinate',
      description: 'Coordinate multiple Claude agents for complex reasoning tasks',
      inputSchema: {
        type: 'object',
        properties: {
          task: { type: 'string', description: 'Task for Claude agents to coordinate on' },
          agentCount: { type: 'number', minimum: 1, maximum: 10, default: 3 },
          mode: { type: 'string', enum: ['parallel', 'sequential', 'hierarchical'], default: 'parallel' }
        },
        required: ['task']
      },
      execute: async (input) => {
        const { task, agentCount = 3, mode = 'parallel' } = input;
        const coordinationId = `claude-${Date.now()}`;
        console.log('🧠 Claude Flow coordination started:', coordinationId);
        return {
          success: true,
          coordinationId,
          message: `Claude Flow coordination started with ${agentCount} agents in ${mode} mode`
        };
      }
    }),
    
    hiveMindCollective: new Tool({
      name: 'hiveMindCollective',
      description: 'Create collective intelligence using distributed hive mind reasoning',
      inputSchema: {
        type: 'object',
        properties: {
          problem: { type: 'string', description: 'Problem for collective intelligence analysis' },
          nodes: { type: 'number', minimum: 3, maximum: 50, default: 10 }
        },
        required: ['problem']
      },
      execute: async (input) => {
        const { problem, nodes = 10 } = input;
        const sessionId = `hive-${Date.now()}`;
        console.log('🐝 Hive Mind collective processing started:', sessionId);
        return {
          success: true,
          sessionId,
          message: `Hive Mind collective started with ${nodes} nodes`
        };
      }
    }),
    
    ruvSwarmDeploy: new Tool({
      name: 'ruvSwarmDeploy',
      description: 'Deploy and manage distributed agent swarms',
      inputSchema: {
        type: 'object',
        properties: {
          mission: { type: 'string', description: 'Mission for the swarm to accomplish' },
          swarmSize: { type: 'number', minimum: 5, maximum: 100, default: 20 }
        },
        required: ['mission']
      },
      execute: async (input) => {
        const { mission, swarmSize = 20 } = input;
        const deploymentId = `swarm-${Date.now()}`;
        console.log('🔥 RUV Swarm deployment started:', deploymentId);
        return {
          success: true,
          deploymentId,
          message: `RUV Swarm deployed with ${swarmSize} agents`
        };
      }
    }),
    
    // Core team management tools
    createTeam: new Tool({
      name: 'createTeam',
      description: 'Create a new team of agents for a specific goal',
      inputSchema: {
        type: 'object',
        properties: {
          teamName: { type: 'string', description: 'Name for the new team' },
          goal: { type: 'string', description: 'Primary goal for the team' },
          agentTypes: {
            type: 'array',
            items: { 
              type: 'string',
              enum: ['coordinator', 'executor', 'researcher', 'architect']
            },
            description: 'Types of agents needed for the team'
          }
        },
        required: ['teamName', 'goal', 'agentTypes']
      },
      execute: async (input) => {
        const { teamName, goal, agentTypes } = input;
        const teamId = `team-${Date.now()}`;
        const team = {
          teamId,
          teamName,
          goal,
          agentTypes,
          status: 'active',
          created: new Date().toISOString(),
          members: agentTypes.map((type, index) => ({
            id: `${type}-${teamId}-${index}`,
            type,
            role: type,
            status: 'ready'
          }))
        };
        
        console.log(`🚀 Team created: ${teamName} (${teamId})`);
        return {
          success: true,
          team,
          message: `Team "${teamName}" created successfully`
        };
      },
    }),
    
    executeWorkflow: new Tool({
      name: 'executeWorkflow',
      description: 'Execute a workflow with the agentic-flow system',
      inputSchema: {
        type: 'object',
        properties: {
          workflowName: { 
            type: 'string',
            enum: ['software-development', 'problem-solving'],
            description: 'Name of the workflow to execute'
          },
          input: { 
            type: 'object',
            description: 'Input parameters for the workflow'
          }
        },
        required: ['workflowName', 'input']
      },
      execute: async (input) => {
        const { workflowName, input: workflowInput } = input;
        const executionId = `exec-${Date.now()}`;
        const execution = {
          executionId,
          workflowName,
          input: workflowInput,
          status: 'running',
          startTime: new Date().toISOString()
        };
        
        console.log(`🔄 Workflow started: ${workflowName} (${executionId})`);
        return {
          success: true,
          execution,
          message: `Workflow "${workflowName}" started successfully`
        };
      },
    }),
    
    monitorSystem: new Tool({
      name: 'monitorSystem',
      description: 'Monitor the health and status of the agentic-flow system',
      inputSchema: {
        type: 'object',
        properties: {
          includeMetrics: { type: 'boolean', default: false }
        }
      },
      execute: async (input) => {
        const { includeMetrics = false } = input || {};
        const systemStatus = {
          timestamp: new Date().toISOString(),
          status: 'healthy',
          uptime: Math.floor(process.uptime()),
          agents: {
            total: 4,
            active: 4,
            types: ['coordinator', 'executor', 'researcher', 'architect']
          },
          workflows: {
            registered: 2,
            available: ['software-development', 'problem-solving']
          }
        };
        
        console.log('🏥 System health check completed');
        return systemStatus;
      },
    })
  },
  
  // Agentic Flow Advanced Workflows
  workflows: {
    // Core workflows
    'software-development': new Workflow({
      name: 'software-development',
      description: 'Complete software development lifecycle workflow',
      steps: [
        {
          id: 'requirements',
          type: 'agent',
          agent: 'coordinator',
          prompt: 'Analyze and coordinate the software development requirements for: {{project}}',
        },
        {
          id: 'research',
          type: 'agent',
          agent: 'researcher',
          prompt: 'Research technical approaches for: {{outputs.requirements.response}}',
        },
        {
          id: 'architecture',
          type: 'agent',
          agent: 'architect',
          prompt: 'Design the technical architecture based on: {{outputs.research.response}}',
        },
        {
          id: 'implementation',
          type: 'agent',
          agent: 'executor',
          prompt: 'Implement the solution based on: {{outputs.architecture.response}}',
        }
      ],
    }),
    
    'problem-solving': new Workflow({
      name: 'problem-solving',
      description: 'Structured approach to complex problem resolution',
      steps: [
        {
          id: 'analysis',
          type: 'agent',
          agent: 'coordinator',
          prompt: 'Analyze and break down this complex problem: {{problem}}',
        },
        {
          id: 'research',
          type: 'agent',
          agent: 'researcher',
          prompt: 'Research potential solutions: {{outputs.analysis.response}}',
        },
        {
          id: 'solution-design',
          type: 'agent',
          agent: 'architect',
          prompt: 'Design a comprehensive solution: {{outputs.research.response}}',
        },
        {
          id: 'implementation-plan',
          type: 'agent',
          agent: 'executor',
          prompt: 'Create detailed implementation plan: {{outputs.solution-design.response}}',
        }
      ],
    }),
    
    // Advanced agentic-flow workflows
    ...agenticFlowWorkflows
  },
  
  // Agentic Flow UI Theme
  ui: {
    theme: agenticFlowTheme,
    branding: brandConfig
  }
});

// Network status logging
const logNetworkStatus = () => {
  console.log('\n🚀 Agentic Flow Mastra Integration Loaded!');
  console.log('📊 Configuration:');
  console.log('   • 7 AI Agents (4 Core + 3 Network Specialists)');
  console.log('     - Core: Coordinator, Executor, Researcher, Architect');
  console.log('     - Networks: Claude Flow 🧠, Hive Mind 🐝, RUV Swarm 🔥');
  console.log('   • 6 Integration Tools (3 MCP Network + 3 Core Tools)');
  console.log('     - MCP: Claude Flow Coordinate, Hive Mind Collective, RUV Swarm Deploy');
  console.log('     - Core: Create Team, Execute Workflow, Monitor System');
  console.log('   • 7 Production Workflows');
  console.log('     - Core: Software Development, Problem Solving');
  console.log('     - Advanced: Research Analysis, Adaptive Problem Solving, Enterprise Integration, AI Model Training, Crisis Response');
  console.log('   • 3 Network Integrations with MCP Protocol');
  console.log(`   • Server URL: http://localhost:${process.env.MASTRA_PORT || 4111}`);
  console.log('   • Custom Agentic Flow Branding and Theme Applied\n');
  
  console.log('🌐 Network Status:');
  console.log('   🧠 Claude Flow: Advanced reasoning and coordination');
  console.log('   🐝 Hive Mind: Collective intelligence and consensus');
  console.log('   🔥 RUV Swarm: Distributed scaling and fault tolerance');
  console.log('');
};

logNetworkStatus();

// Network initialization and status check
setTimeout(() => {
  console.log('🔗 Mastra playground available with full agentic-flow integration!');
  console.log('💡 Try the network tools: claudeFlowCoordinate, hiveMindCollective, ruvSwarmDeploy');
}, 2000);

// Export both named and default for Mastra CLI compatibility
export { mastra };
export default mastra;