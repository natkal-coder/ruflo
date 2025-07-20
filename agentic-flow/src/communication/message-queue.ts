import { Message, AgentId, MessagePriority } from '../types';
import { Logger } from '../utils/logger';

/**
 * Message queue for storing messages for offline agents
 */
export class MessageQueue {
  private readonly agentId: AgentId;
  private readonly logger: Logger;
  private readonly messages: PriorityQueue<Message>;
  private readonly maxSize: number;

  constructor(agentId: AgentId, maxSize: number = 1000) {
    this.agentId = agentId;
    this.logger = new Logger(`MessageQueue:${agentId.id}`);
    this.messages = new PriorityQueue<Message>(this.compareMessages);
    this.maxSize = maxSize;
  }

  /**
   * Add a message to the queue
   */
  public enqueue(message: Message): void {
    if (this.messages.size() >= this.maxSize) {
      this.logger.warn('Queue is full, dropping oldest message');
      // In a priority queue, we need to remove the lowest priority message
      const allMessages = this.messages.toArray();
      allMessages.sort(this.compareMessages).reverse();
      allMessages.pop(); // Remove lowest priority
      this.messages.clear();
      allMessages.forEach(m => this.messages.enqueue(m));
    }
    
    this.messages.enqueue(message);
    this.logger.debug('Message enqueued', { messageId: message.id });
  }

  /**
   * Get the next message without removing it
   */
  public peek(): Message[] {
    return this.messages.toArray();
  }

  /**
   * Remove and return the next message
   */
  public dequeue(): Message | undefined {
    return this.messages.dequeue();
  }

  /**
   * Remove and return all messages
   */
  public dequeueAll(): Message[] {
    const messages: Message[] = [];
    while (!this.messages.isEmpty()) {
      const message = this.messages.dequeue();
      if (message) {
        messages.push(message);
      }
    }
    return messages;
  }

  /**
   * Get queue size
   */
  public size(): number {
    return this.messages.size();
  }

  /**
   * Check if queue is empty
   */
  public isEmpty(): boolean {
    return this.messages.isEmpty();
  }

  /**
   * Clear all messages
   */
  public clear(): void {
    this.messages.clear();
    this.logger.debug('Queue cleared');
  }

  /**
   * Compare messages for priority ordering
   */
  private compareMessages(a: Message, b: Message): number {
    // Priority comparison
    const priorityWeight = {
      [MessagePriority.URGENT]: 4,
      [MessagePriority.HIGH]: 3,
      [MessagePriority.NORMAL]: 2,
      [MessagePriority.LOW]: 1
    };
    
    const priorityDiff = priorityWeight[b.priority] - priorityWeight[a.priority];
    if (priorityDiff !== 0) return priorityDiff;
    
    // Timestamp comparison (older messages first)
    return a.timestamp.getTime() - b.timestamp.getTime();
  }

  /**
   * Remove expired messages
   */
  public removeExpired(): number {
    const now = Date.now();
    const messages = this.messages.toArray();
    const validMessages = messages.filter(message => {
      if (message.ttl) {
        const expiryTime = message.timestamp.getTime() + message.ttl;
        return expiryTime > now;
      }
      return true;
    });
    
    const removedCount = messages.length - validMessages.length;
    
    if (removedCount > 0) {
      this.messages.clear();
      validMessages.forEach(m => this.messages.enqueue(m));
      this.logger.info('Removed expired messages', { count: removedCount });
    }
    
    return removedCount;
  }

  /**
   * Get messages by type
   */
  public getByType(type: string): Message[] {
    return this.messages.toArray().filter(m => m.type === type);
  }

  /**
   * Get messages by priority
   */
  public getByPriority(priority: MessagePriority): Message[] {
    return this.messages.toArray().filter(m => m.priority === priority);
  }
}

/**
 * Priority Queue implementation
 */
class PriorityQueue<T> {
  private items: T[] = [];
  private compare: (a: T, b: T) => number;

  constructor(compareFunction: (a: T, b: T) => number) {
    this.compare = compareFunction;
  }

  enqueue(item: T): void {
    this.items.push(item);
    this.items.sort(this.compare);
  }

  dequeue(): T | undefined {
    return this.items.shift();
  }

  peek(): T | undefined {
    return this.items[0];
  }

  isEmpty(): boolean {
    return this.items.length === 0;
  }

  size(): number {
    return this.items.length;
  }

  clear(): void {
    this.items = [];
  }

  toArray(): T[] {
    return [...this.items];
  }
}