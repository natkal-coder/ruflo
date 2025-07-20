import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../cli/utils/logger';

export interface Agent {
  id: string;
  name: string;
  type: string;
  status: 'idle' | 'running' | 'stopped' | 'error';
  capabilities: string[];
  model: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  createdAt: string;
  startedAt?: string;
  stoppedAt?: string;
  lastTaskAt?: string;
  metrics: {
    tasksCompleted: number;
    successRate: number;
    avgResponseTime: number;
  };
}

export class AgentManager extends EventEmitter {
  private agents: Map<string, Agent> = new Map();
  private runningAgents: Set<string> = new Set();

  constructor() {
    super();
  }

  async createAgent(config: Partial<Agent>): Promise<Agent> {
    const agent: Agent = {
      id: config.id || uuidv4(),
      name: config.name || `agent-${Date.now()}`,
      type: config.type || 'generic',
      status: 'idle',
      capabilities: config.capabilities || [],
      model: config.model || 'claude-3',
      priority: config.priority || 'medium',
      createdAt: new Date().toISOString(),
      metrics: {
        tasksCompleted: 0,
        successRate: 100,
        avgResponseTime: 0,
      },
      ...config,
    };

    this.agents.set(agent.id, agent);
    this.emit('agent:created', agent);
    
    logger.info('Agent created', { agentId: agent.id, name: agent.name });
    
    return agent;
  }

  async startAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    if (agent.status === 'running') {
      throw new Error(`Agent ${agent.name} is already running`);
    }

    agent.status = 'running';
    agent.startedAt = new Date().toISOString();
    this.runningAgents.add(agentId);
    
    this.emit('agent:started', agent);
    logger.info('Agent started', { agentId, name: agent.name });

    // Simulate agent initialization
    await this.simulateAgentWork(agent);
  }

  async stopAgent(agentId: string, force: boolean = false): Promise<void> {
    const agent = this.agents.get(agentId);
    
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    if (agent.status !== 'running') {
      throw new Error(`Agent ${agent.name} is not running`);
    }

    if (!force) {
      // Graceful shutdown
      this.emit('agent:stopping', agent);
      await this.waitForTaskCompletion(agent);
    }

    agent.status = 'stopped';
    agent.stoppedAt = new Date().toISOString();
    this.runningAgents.delete(agentId);
    
    this.emit('agent:stopped', agent);
    logger.info('Agent stopped', { agentId, name: agent.name, force });
  }

  async removeAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    if (agent.status === 'running') {
      await this.stopAgent(agentId, true);
    }

    this.agents.delete(agentId);
    this.emit('agent:removed', agent);
    
    logger.info('Agent removed', { agentId, name: agent.name });
  }

  getAgent(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }

  getRunningAgents(): Agent[] {
    return Array.from(this.runningAgents)
      .map(id => this.agents.get(id))
      .filter((agent): agent is Agent => agent !== undefined);
  }

  async assignTask(agentId: string, task: any): Promise<any> {
    const agent = this.agents.get(agentId);
    
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    if (agent.status !== 'running') {
      throw new Error(`Agent ${agent.name} is not running`);
    }

    this.emit('task:assigned', { agent, task });
    logger.info('Task assigned to agent', { agentId, task });

    // Simulate task execution
    const startTime = Date.now();
    
    try {
      const result = await this.executeTask(agent, task);
      
      // Update metrics
      agent.lastTaskAt = new Date().toISOString();
      agent.metrics.tasksCompleted++;
      const responseTime = Date.now() - startTime;
      agent.metrics.avgResponseTime = 
        (agent.metrics.avgResponseTime * (agent.metrics.tasksCompleted - 1) + responseTime) / 
        agent.metrics.tasksCompleted;
      
      this.emit('task:completed', { agent, task, result });
      logger.info('Task completed', { agentId, duration: responseTime });
      
      return result;
    } catch (error) {
      // Update failure metrics
      agent.metrics.successRate = 
        (agent.metrics.successRate * agent.metrics.tasksCompleted) / 
        (agent.metrics.tasksCompleted + 1);
      
      this.emit('task:failed', { agent, task, error });
      logger.error('Task failed', { agentId, error: error.message });
      
      throw error;
    }
  }

  private async simulateAgentWork(agent: Agent): Promise<void> {
    // Simulate agent doing background work
    const interval = setInterval(() => {
      if (agent.status !== 'running') {
        clearInterval(interval);
        return;
      }
      
      this.emit('agent:heartbeat', agent);
    }, 5000);
  }

  private async waitForTaskCompletion(agent: Agent): Promise<void> {
    // Wait for any ongoing tasks to complete
    return new Promise(resolve => {
      setTimeout(resolve, 1000); // Simulate graceful shutdown delay
    });
  }

  private async executeTask(agent: Agent, task: any): Promise<any> {
    // Simulate task execution based on agent type
    await new Promise(resolve => setTimeout(resolve, Math.random() * 2000 + 1000));
    
    // Return simulated result based on agent type
    switch (agent.type) {
      case 'researcher':
        return {
          success: true,
          findings: [`Research result for: ${task.description || task}`],
          sources: ['source1', 'source2'],
        };
      
      case 'developer':
        return {
          success: true,
          code: `// Generated code for: ${task.description || task}\nfunction solution() { return true; }`,
          language: 'javascript',
        };
      
      case 'analyst':
        return {
          success: true,
          analysis: `Analysis of: ${task.description || task}`,
          insights: ['insight1', 'insight2'],
          recommendations: ['recommendation1'],
        };
      
      default:
        return {
          success: true,
          result: `Task completed: ${task.description || task}`,
        };
    }
  }
}