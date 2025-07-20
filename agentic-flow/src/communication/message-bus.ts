import { EventEmitter } from 'eventemitter3';
import { v4 as uuidv4 } from 'uuid';
import {
  Message,
  AgentId,
  MessageType,
  MessagePriority,
  MessageContent
} from '../types';
import { Logger } from '../utils/logger';
import { MessageRouter } from './message-router';
import { MessageQueue } from './message-queue';

/**
 * Central message bus for inter-agent communication
 */
export class MessageBus extends EventEmitter {
  private static instance: MessageBus;
  private readonly logger: Logger;
  private readonly router: MessageRouter;
  private readonly queues: Map<string, MessageQueue>;
  private readonly subscribers: Map<string, (message: Message) => Promise<void>>;
  private readonly messageHistory: Message[];
  private readonly maxHistorySize: number = 1000;

  private constructor() {
    super();
    this.logger = new Logger('MessageBus');
    this.router = new MessageRouter();
    this.queues = new Map();
    this.subscribers = new Map();
    this.messageHistory = [];
  }

  /**
   * Get singleton instance
   */
  public static getInstance(): MessageBus {
    if (!MessageBus.instance) {
      MessageBus.instance = new MessageBus();
    }
    return MessageBus.instance;
  }

  /**
   * Register an agent with the message bus
   */
  public async registerAgent(agentId: AgentId): Promise<void> {
    const key = this.getAgentKey(agentId);
    
    if (this.queues.has(key)) {
      throw new Error(`Agent already registered: ${key}`);
    }
    
    // Create message queue for agent
    const queue = new MessageQueue(agentId);
    this.queues.set(key, queue);
    
    // Register with router
    this.router.registerAgent(agentId);
    
    this.logger.info('Agent registered', { agentId: key });
    this.emit('agent:registered', agentId);
  }

  /**
   * Unregister an agent from the message bus
   */
  public async unregisterAgent(agentId: AgentId): Promise<void> {
    const key = this.getAgentKey(agentId);
    
    // Remove queue
    const queue = this.queues.get(key);
    if (queue) {
      queue.clear();
      this.queues.delete(key);
    }
    
    // Remove subscriber
    this.subscribers.delete(key);
    
    // Unregister from router
    this.router.unregisterAgent(agentId);
    
    this.logger.info('Agent unregistered', { agentId: key });
    this.emit('agent:unregistered', agentId);
  }

  /**
   * Subscribe to messages for an agent
   */
  public subscribe(
    agentId: AgentId,
    handler: (message: Message) => Promise<void>
  ): void {
    const key = this.getAgentKey(agentId);
    this.subscribers.set(key, handler);
    
    // Process any queued messages
    const queue = this.queues.get(key);
    if (queue) {
      this.processQueuedMessages(agentId, handler);
    }
  }

  /**
   * Unsubscribe from messages
   */
  public unsubscribe(agentId: AgentId): void {
    const key = this.getAgentKey(agentId);
    this.subscribers.delete(key);
  }

  /**
   * Send a message
   */
  public async send(message: Message): Promise<void> {
    try {
      // Validate message
      this.validateMessage(message);
      
      // Add to history
      this.addToHistory(message);
      
      // Route message
      const recipients = await this.router.route(message);
      
      if (recipients.length === 0) {
        this.logger.warn('No recipients found for message', { messageId: message.id });
        this.emit('message:undelivered', message);
        return;
      }
      
      // Deliver to recipients
      for (const recipient of recipients) {
        await this.deliverMessage(message, recipient);
      }
      
      this.logger.debug('Message sent', { 
        messageId: message.id, 
        recipientCount: recipients.length 
      });
      
      this.emit('message:sent', message);
    } catch (error) {
      this.logger.error('Failed to send message', error);
      this.emit('message:error', { message, error });
      throw error;
    }
  }

  /**
   * Broadcast a message to all agents
   */
  public async broadcast(
    from: AgentId,
    type: MessageType,
    content: MessageContent,
    priority: MessagePriority = MessagePriority.NORMAL
  ): Promise<void> {
    const message: Message = {
      id: uuidv4(),
      from,
      to: [], // Empty array indicates broadcast
      type,
      content,
      timestamp: new Date(),
      priority
    };
    
    await this.send(message);
  }

  /**
   * Reply to a message
   */
  public async reply(
    originalMessage: Message,
    from: AgentId,
    type: MessageType,
    content: MessageContent,
    priority?: MessagePriority
  ): Promise<void> {
    const replyMessage: Message = {
      id: uuidv4(),
      from,
      to: originalMessage.from,
      type,
      content,
      timestamp: new Date(),
      replyTo: originalMessage.id,
      priority: priority || originalMessage.priority
    };
    
    await this.send(replyMessage);
  }

  /**
   * Deliver message to recipient
   */
  private async deliverMessage(message: Message, recipient: AgentId): Promise<void> {
    const key = this.getAgentKey(recipient);
    const handler = this.subscribers.get(key);
    
    if (handler) {
      // Direct delivery
      try {
        await handler(message);
        this.emit('message:delivered', { message, recipient });
      } catch (error) {
        this.logger.error('Handler failed to process message', error);
        this.emit('message:handlerError', { message, recipient, error });
      }
    } else {
      // Queue for later delivery
      const queue = this.queues.get(key);
      if (queue) {
        queue.enqueue(message);
        this.logger.debug('Message queued for offline agent', { 
          messageId: message.id, 
          agentId: key 
        });
        this.emit('message:queued', { message, recipient });
      } else {
        this.logger.warn('No queue found for recipient', { agentId: key });
        this.emit('message:undeliverable', { message, recipient });
      }
    }
  }

  /**
   * Process queued messages for an agent
   */
  private async processQueuedMessages(
    agentId: AgentId,
    handler: (message: Message) => Promise<void>
  ): Promise<void> {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    
    if (!queue) return;
    
    const messages = queue.dequeueAll();
    this.logger.info('Processing queued messages', { 
      agentId: key, 
      count: messages.length 
    });
    
    for (const message of messages) {
      try {
        await handler(message);
        this.emit('message:delivered', { message, recipient: agentId });
      } catch (error) {
        this.logger.error('Failed to process queued message', error);
        this.emit('message:handlerError', { message, recipient: agentId, error });
      }
    }
  }

  /**
   * Validate message
   */
  private validateMessage(message: Message): void {
    if (!message.id) {
      throw new Error('Message must have an ID');
    }
    
    if (!message.from) {
      throw new Error('Message must have a sender');
    }
    
    if (!message.type) {
      throw new Error('Message must have a type');
    }
    
    if (!message.content) {
      throw new Error('Message must have content');
    }
  }

  /**
   * Add message to history
   */
  private addToHistory(message: Message): void {
    this.messageHistory.push(message);
    
    // Trim history if needed
    if (this.messageHistory.length > this.maxHistorySize) {
      this.messageHistory.shift();
    }
  }

  /**
   * Get message history
   */
  public getHistory(filter?: {
    from?: AgentId;
    to?: AgentId;
    type?: MessageType;
    since?: Date;
  }): Message[] {
    let history = [...this.messageHistory];
    
    if (filter) {
      if (filter.from) {
        const fromKey = this.getAgentKey(filter.from);
        history = history.filter(m => this.getAgentKey(m.from) === fromKey);
      }
      
      if (filter.to) {
        const toKey = this.getAgentKey(filter.to);
        history = history.filter(m => {
          if (Array.isArray(m.to)) {
            return m.to.some(t => this.getAgentKey(t) === toKey);
          }
          return this.getAgentKey(m.to) === toKey;
        });
      }
      
      if (filter.type) {
        history = history.filter(m => m.type === filter.type);
      }
      
      if (filter.since) {
        history = history.filter(m => m.timestamp >= filter.since!);
      }
    }
    
    return history;
  }

  /**
   * Get agent key for consistent identification
   */
  private getAgentKey(agentId: AgentId): string {
    return `${agentId.namespace || 'default'}:${agentId.id}`;
  }

  /**
   * Get queue status for an agent
   */
  public getQueueStatus(agentId: AgentId): { size: number; messages: Message[] } {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    
    if (!queue) {
      return { size: 0, messages: [] };
    }
    
    return {
      size: queue.size(),
      messages: queue.peek()
    };
  }

  /**
   * Clear all messages for an agent
   */
  public clearAgentMessages(agentId: AgentId): void {
    const key = this.getAgentKey(agentId);
    const queue = this.queues.get(key);
    
    if (queue) {
      queue.clear();
    }
  }

  /**
   * Get registered agents
   */
  public getRegisteredAgents(): AgentId[] {
    return this.router.getRegisteredAgents();
  }
}