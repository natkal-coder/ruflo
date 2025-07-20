import { AgentId, Message } from '../types';
import { Logger } from '../utils/logger';

/**
 * Message router for determining message recipients
 */
export class MessageRouter {
  private readonly logger: Logger;
  private readonly agents: Map<string, AgentId>;
  private readonly topics: Map<string, Set<string>>;
  private readonly routingRules: RoutingRule[];

  constructor() {
    this.logger = new Logger('MessageRouter');
    this.agents = new Map();
    this.topics = new Map();
    this.routingRules = [];
    
    this.initializeDefaultRules();
  }

  /**
   * Initialize default routing rules
   */
  private initializeDefaultRules(): void {
    // Broadcast rule
    this.addRule({
      name: 'broadcast',
      condition: (message) => Array.isArray(message.to) && message.to.length === 0,
      route: (message) => Array.from(this.agents.values()).filter(
        agent => this.getAgentKey(agent) !== this.getAgentKey(message.from)
      )
    });
    
    // Direct message rule
    this.addRule({
      name: 'direct',
      condition: (message) => !Array.isArray(message.to) && message.to !== null,
      route: (message) => [message.to as AgentId]
    });
    
    // Multi-cast rule
    this.addRule({
      name: 'multicast',
      condition: (message) => Array.isArray(message.to) && message.to.length > 0,
      route: (message) => message.to as AgentId[]
    });
  }

  /**
   * Register an agent
   */
  public registerAgent(agentId: AgentId): void {
    const key = this.getAgentKey(agentId);
    this.agents.set(key, agentId);
    this.logger.debug('Agent registered with router', { agentId: key });
  }

  /**
   * Unregister an agent
   */
  public unregisterAgent(agentId: AgentId): void {
    const key = this.getAgentKey(agentId);
    this.agents.delete(key);
    
    // Remove from all topics
    this.topics.forEach((subscribers, topic) => {
      subscribers.delete(key);
    });
    
    this.logger.debug('Agent unregistered from router', { agentId: key });
  }

  /**
   * Subscribe an agent to a topic
   */
  public subscribeTopic(agentId: AgentId, topic: string): void {
    const key = this.getAgentKey(agentId);
    
    if (!this.topics.has(topic)) {
      this.topics.set(topic, new Set());
    }
    
    this.topics.get(topic)!.add(key);
    this.logger.debug('Agent subscribed to topic', { agentId: key, topic });
  }

  /**
   * Unsubscribe an agent from a topic
   */
  public unsubscribeTopic(agentId: AgentId, topic: string): void {
    const key = this.getAgentKey(agentId);
    const subscribers = this.topics.get(topic);
    
    if (subscribers) {
      subscribers.delete(key);
      
      if (subscribers.size === 0) {
        this.topics.delete(topic);
      }
    }
    
    this.logger.debug('Agent unsubscribed from topic', { agentId: key, topic });
  }

  /**
   * Route a message to recipients
   */
  public async route(message: Message): Promise<AgentId[]> {
    try {
      // Check routing rules
      for (const rule of this.routingRules) {
        if (rule.condition(message)) {
          const recipients = rule.route(message);
          
          // Filter out non-existent agents
          const validRecipients = recipients.filter(recipient => {
            const key = this.getAgentKey(recipient);
            return this.agents.has(key);
          });
          
          this.logger.debug('Message routed', { 
            messageId: message.id, 
            rule: rule.name,
            recipients: validRecipients.length 
          });
          
          return validRecipients;
        }
      }
      
      // Topic-based routing
      if (message.content.topic) {
        const topicSubscribers = this.getTopicSubscribersInternal(message.content.topic);
        if (topicSubscribers.length > 0) {
          return topicSubscribers.filter(
            agent => this.getAgentKey(agent) !== this.getAgentKey(message.from)
          );
        }
      }
      
      this.logger.warn('No routing rule matched', { messageId: message.id });
      return [];
    } catch (error) {
      this.logger.error('Failed to route message', error);
      return [];
    }
  }

  /**
   * Add a custom routing rule
   */
  public addRule(rule: RoutingRule): void {
    this.routingRules.push(rule);
    this.logger.info('Added routing rule', { name: rule.name });
  }

  /**
   * Remove a routing rule
   */
  public removeRule(name: string): void {
    const index = this.routingRules.findIndex(rule => rule.name === name);
    if (index >= 0) {
      this.routingRules.splice(index, 1);
      this.logger.info('Removed routing rule', { name });
    }
  }

  /**
   * Get subscribers for a topic (internal)
   */
  private getTopicSubscribersInternal(topic: string): AgentId[] {
    const subscribers = this.topics.get(topic);
    if (!subscribers) {
      return [];
    }
    
    return Array.from(subscribers).map(key => this.agents.get(key)!).filter(Boolean);
  }

  /**
   * Get agent key for consistent identification
   */
  private getAgentKey(agentId: AgentId): string {
    return `${agentId.namespace || 'default'}:${agentId.id}`;
  }

  /**
   * Get all registered agents
   */
  public getRegisteredAgents(): AgentId[] {
    return Array.from(this.agents.values());
  }

  /**
   * Get all topics
   */
  public getTopics(): string[] {
    return Array.from(this.topics.keys());
  }

  /**
   * Get topic subscribers
   */
  public getTopicSubscribers(topic: string): AgentId[] {
    const subscribers = this.topics.get(topic);
    if (!subscribers) {
      return [];
    }
    
    return Array.from(subscribers)
      .map(key => this.agents.get(key))
      .filter((agent): agent is AgentId => agent !== undefined);
  }
}

/**
 * Routing rule interface
 */
interface RoutingRule {
  name: string;
  condition: (message: Message) => boolean;
  route: (message: Message) => AgentId[];
}