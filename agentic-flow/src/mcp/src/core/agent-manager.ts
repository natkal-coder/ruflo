/**
 * Agent Manager - Core agent lifecycle and management
 */

import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';
import { Agent, AgentType, AgentStatus, Message, MessageType, Priority } from '../types';
import { logger } from '../utils/logger';

export class AgentManager extends EventEmitter {
  private agents: Map<string, Agent> = new Map();
  private messageQueue: Map<string, Message[]> = new Map();

  constructor() {
    super();
    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    this.on('agent:message', this.handleAgentMessage.bind(this));
    this.on('agent:status', this.handleStatusChange.bind(this));
  }

  /**
   * Create a new agent
   */
  async spawnAgent(
    name: string,
    type: AgentType,
    capabilities: string[] = [],
    config: Record<string, any> = {}
  ): Promise<Agent> {
    const agent: Agent = {
      id: uuidv4(),
      name,
      type,
      capabilities,
      status: AgentStatus.IDLE,
      memory: new Map(),
      connections: [],
      createdAt: new Date(),
      lastActive: new Date()
    };

    // Initialize agent-specific capabilities
    switch (type) {
      case AgentType.COORDINATOR:
        agent.capabilities.push('orchestration', 'task-distribution', 'consensus-building');
        break;
      case AgentType.EXECUTOR:
        agent.capabilities.push('task-execution', 'parallel-processing', 'resource-management');
        break;
      case AgentType.ANALYZER:
        agent.capabilities.push('data-analysis', 'pattern-recognition', 'insight-generation');
        break;
      case AgentType.LEARNER:
        agent.capabilities.push('model-training', 'prediction', 'adaptation');
        break;
      case AgentType.MONITOR:
        agent.capabilities.push('health-monitoring', 'alerting', 'metrics-collection');
        break;
      case AgentType.SPECIALIST:
        agent.capabilities = [...agent.capabilities, ...capabilities];
        break;
    }

    // Apply configuration
    if (config.memory) {
      Object.entries(config.memory).forEach(([key, value]) => {
        agent.memory.set(key, value);
      });
    }

    this.agents.set(agent.id, agent);
    this.messageQueue.set(agent.id, []);

    logger.info(`Agent spawned: ${agent.name} (${agent.id}) - Type: ${agent.type}`);
    this.emit('agent:spawned', agent);

    return agent;
  }

  /**
   * Get agent by ID
   */
  getAgent(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  /**
   * Get all agents
   */
  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }

  /**
   * Get agents by type
   */
  getAgentsByType(type: AgentType): Agent[] {
    return this.getAllAgents().filter(agent => agent.type === type);
  }

  /**
   * Get agents by capability
   */
  getAgentsByCapability(capability: string): Agent[] {
    return this.getAllAgents().filter(agent => 
      agent.capabilities.includes(capability)
    );
  }

  /**
   * Update agent status
   */
  updateAgentStatus(agentId: string, status: AgentStatus): void {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    agent.status = status;
    agent.lastActive = new Date();
    this.emit('agent:status', { agentId, status });
  }

  /**
   * Send message between agents
   */
  async sendMessage(message: Message): Promise<void> {
    const recipients = Array.isArray(message.to) ? message.to : [message.to];

    for (const recipientId of recipients) {
      const queue = this.messageQueue.get(recipientId);
      if (queue) {
        queue.push(message);
        this.emit('agent:message', { recipientId, message });
      }
    }

    logger.debug(`Message sent from ${message.from} to ${recipients.join(', ')}`);
  }

  /**
   * Get messages for an agent
   */
  getMessages(agentId: string, clear: boolean = true): Message[] {
    const queue = this.messageQueue.get(agentId) || [];
    const messages = [...queue];

    if (clear) {
      this.messageQueue.set(agentId, []);
    }

    return messages;
  }

  /**
   * Connect agents
   */
  connectAgents(agentId1: string, agentId2: string): void {
    const agent1 = this.agents.get(agentId1);
    const agent2 = this.agents.get(agentId2);

    if (!agent1 || !agent2) {
      throw new Error('One or both agents not found');
    }

    if (!agent1.connections.includes(agentId2)) {
      agent1.connections.push(agentId2);
    }
    if (!agent2.connections.includes(agentId1)) {
      agent2.connections.push(agentId1);
    }

    this.emit('agents:connected', { agentId1, agentId2 });
  }

  /**
   * Terminate agent
   */
  async terminateAgent(agentId: string): Promise<void> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    // Update status
    agent.status = AgentStatus.TERMINATED;

    // Clean up connections
    for (const connectedId of agent.connections) {
      const connected = this.agents.get(connectedId);
      if (connected) {
        connected.connections = connected.connections.filter(id => id !== agentId);
      }
    }

    // Clean up message queue
    this.messageQueue.delete(agentId);

    // Remove agent
    this.agents.delete(agentId);

    logger.info(`Agent terminated: ${agent.name} (${agentId})`);
    this.emit('agent:terminated', agentId);
  }

  /**
   * Handle incoming messages
   */
  private handleAgentMessage({ recipientId, message }: { recipientId: string; message: Message }) {
    const agent = this.agents.get(recipientId);
    if (!agent) return;

    // Update last active
    agent.lastActive = new Date();

    // Process based on message type
    switch (message.type) {
      case MessageType.COMMAND:
        this.processCommand(agent, message);
        break;
      case MessageType.QUERY:
        this.processQuery(agent, message);
        break;
      case MessageType.EVENT:
        this.processEvent(agent, message);
        break;
    }
  }

  /**
   * Handle status changes
   */
  private handleStatusChange({ agentId, status }: { agentId: string; status: AgentStatus }) {
    logger.debug(`Agent ${agentId} status changed to ${status}`);
    
    // Notify connected agents
    const agent = this.agents.get(agentId);
    if (agent) {
      for (const connectedId of agent.connections) {
        this.sendMessage({
          id: uuidv4(),
          from: 'system',
          to: connectedId,
          type: MessageType.EVENT,
          content: { agentId, status },
          timestamp: new Date(),
          priority: Priority.MEDIUM,
          requiresResponse: false
        });
      }
    }
  }

  private processCommand(agent: Agent, message: Message) {
    // Command processing logic
    logger.debug(`Processing command for agent ${agent.id}: ${JSON.stringify(message.content)}`);
  }

  private processQuery(agent: Agent, message: Message) {
    // Query processing logic
    logger.debug(`Processing query for agent ${agent.id}: ${JSON.stringify(message.content)}`);
  }

  private processEvent(agent: Agent, message: Message) {
    // Event processing logic
    logger.debug(`Processing event for agent ${agent.id}: ${JSON.stringify(message.content)}`);
  }

  /**
   * Get agent metrics
   */
  getAgentMetrics(agentId: string): Record<string, any> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }

    const messages = this.messageQueue.get(agentId) || [];
    const uptime = Date.now() - agent.createdAt.getTime();

    return {
      id: agent.id,
      name: agent.name,
      type: agent.type,
      status: agent.status,
      uptime,
      messageQueueSize: messages.length,
      connectionCount: agent.connections.length,
      memorySize: agent.memory.size,
      lastActive: agent.lastActive
    };
  }
}