import { EventEmitter } from 'eventemitter3';
import { v4 as uuidv4 } from 'uuid';
import {
  AgentId,
  AgentProfile,
  AgentType,
  AgentState,
  AgentCapability,
  Goal,
  Message,
  Task,
  AgentConfig,
  AgentLifecycleHooks,
  PerformanceMetrics
} from '../types';
import { Logger } from '../utils/logger';
import { MessageBus } from '../communication/message-bus';
import { GoalEngine } from '../goal-engine/goal-engine';

/**
 * Base class for all autonomous agents in the Agentic Flow framework
 */
export abstract class BaseAgent extends EventEmitter {
  protected readonly id: AgentId;
  protected readonly logger: Logger;
  protected profile: AgentProfile;
  protected config: AgentConfig;
  protected hooks: AgentLifecycleHooks;
  protected messageBus: MessageBus;
  protected goalEngine: GoalEngine;
  protected activeTasks: Map<string, Task>;
  protected messageHandlers: Map<string, (message: Message) => Promise<void>>;

  constructor(
    name: string,
    type: AgentType,
    config: AgentConfig = {},
    hooks: AgentLifecycleHooks = {}
  ) {
    super();
    
    this.id = {
      id: uuidv4(),
      namespace: 'default'
    };
    
    this.logger = new Logger(`Agent:${name}`);
    this.config = this.mergeConfig(config);
    this.hooks = hooks;
    this.activeTasks = new Map();
    this.messageHandlers = new Map();
    
    this.profile = this.createProfile(name, type);
    this.messageBus = MessageBus.getInstance();
    this.goalEngine = new GoalEngine(this.id);
    
    this.setupMessageHandlers();
    this.setupEventListeners();
  }

  /**
   * Create the agent's profile
   */
  private createProfile(name: string, type: AgentType): AgentProfile {
    const now = new Date();
    return {
      id: this.id,
      name,
      type,
      capabilities: this.defineCapabilities(),
      goals: [],
      state: AgentState.IDLE,
      metadata: {
        createdAt: now,
        updatedAt: now,
        version: '1.0.0',
        tags: [],
        performance: {
          tasksCompleted: 0,
          successRate: 0,
          averageResponseTime: 0,
          resourceUtilization: 0,
          communicationEfficiency: 0
        }
      }
    };
  }

  /**
   * Define agent capabilities - must be implemented by subclasses
   */
  protected abstract defineCapabilities(): AgentCapability[];

  /**
   * Process incoming goals - must be implemented by subclasses
   */
  protected abstract processGoal(goal: Goal): Promise<void>;

  /**
   * Execute a task - must be implemented by subclasses
   */
  protected abstract executeTask(task: Task): Promise<any>;

  /**
   * Initialize the agent
   */
  public async initialize(): Promise<void> {
    try {
      this.logger.info('Initializing agent...', { id: this.id });
      
      // Register with message bus
      await this.messageBus.registerAgent(this.id);
      
      // Run initialization hook
      if (this.hooks.onInit) {
        await this.hooks.onInit();
      }
      
      this.updateState(AgentState.IDLE);
      this.emit('initialized', this.profile);
      
      this.logger.info('Agent initialized successfully', { id: this.id });
    } catch (error) {
      this.logger.error('Failed to initialize agent', error);
      this.updateState(AgentState.ERROR);
      throw error;
    }
  }

  /**
   * Start the agent
   */
  public async start(): Promise<void> {
    try {
      this.logger.info('Starting agent...', { id: this.id });
      
      // Subscribe to messages
      this.messageBus.subscribe(this.id, this.handleMessage.bind(this));
      
      // Run start hook
      if (this.hooks.onStart) {
        await this.hooks.onStart();
      }
      
      this.updateState(AgentState.IDLE);
      this.emit('started', this.profile);
      
      this.logger.info('Agent started successfully', { id: this.id });
    } catch (error) {
      this.logger.error('Failed to start agent', error);
      this.updateState(AgentState.ERROR);
      throw error;
    }
  }

  /**
   * Stop the agent
   */
  public async stop(): Promise<void> {
    try {
      this.logger.info('Stopping agent...', { id: this.id });
      
      // Cancel active tasks
      for (const [, task] of this.activeTasks) {
        task.status = TaskStatus.CANCELLED;
        this.emit('task:cancelled', task);
      }
      this.activeTasks.clear();
      
      // Unsubscribe from messages
      this.messageBus.unsubscribe(this.id);
      
      // Run stop hook
      if (this.hooks.onStop) {
        await this.hooks.onStop();
      }
      
      this.updateState(AgentState.TERMINATED);
      this.emit('stopped', this.profile);
      
      this.logger.info('Agent stopped successfully', { id: this.id });
    } catch (error) {
      this.logger.error('Failed to stop agent', error);
      throw error;
    }
  }

  /**
   * Add a new goal to the agent
   */
  public async addGoal(goal: Goal): Promise<void> {
    try {
      this.logger.info('Adding new goal', { goalId: goal.id });
      
      // Add to goal engine
      await this.goalEngine.addGoal(goal);
      
      // Add to profile
      this.profile.goals.push(goal);
      
      // Run goal received hook
      if (this.hooks.onGoalReceived) {
        await this.hooks.onGoalReceived(goal);
      }
      
      // Process the goal
      this.updateState(AgentState.THINKING);
      await this.processGoal(goal);
      
      this.emit('goal:added', goal);
    } catch (error) {
      this.logger.error('Failed to add goal', error);
      throw error;
    }
  }

  /**
   * Send a message to another agent or broadcast
   */
  public async sendMessage(
    to: AgentId | AgentId[],
    type: MessageType,
    content: MessageContent,
    priority: MessagePriority = MessagePriority.NORMAL
  ): Promise<void> {
    const message: Message = {
      id: uuidv4(),
      from: this.id,
      to,
      type,
      content,
      timestamp: new Date(),
      priority
    };
    
    this.updateState(AgentState.COMMUNICATING);
    await this.messageBus.send(message);
    this.updateState(AgentState.IDLE);
    
    this.emit('message:sent', message);
  }

  /**
   * Reply to a message
   */
  public async reply(
    originalMessage: Message,
    type: MessageType,
    content: MessageContent,
    priority?: MessagePriority
  ): Promise<void> {
    const replyMessage: Message = {
      id: uuidv4(),
      from: this.id,
      to: originalMessage.from,
      type,
      content,
      timestamp: new Date(),
      replyTo: originalMessage.id,
      priority: priority || originalMessage.priority
    };
    
    await this.messageBus.send(replyMessage);
    this.emit('message:sent', replyMessage);
  }

  /**
   * Handle incoming messages
   */
  private async handleMessage(message: Message): Promise<void> {
    try {
      this.logger.debug('Received message', { messageId: message.id, type: message.type });
      
      // Run message hook
      if (this.hooks.onMessage) {
        await this.hooks.onMessage(message);
      }
      
      // Check for registered handler
      const handler = this.messageHandlers.get(message.type);
      if (handler) {
        await handler(message);
      } else {
        await this.handleUnknownMessage(message);
      }
      
      this.emit('message:received', message);
    } catch (error) {
      this.logger.error('Failed to handle message', error);
      this.emit('message:error', { message, error });
    }
  }

  /**
   * Handle unknown message types
   */
  protected async handleUnknownMessage(message: Message): Promise<void> {
    this.logger.warn('Received unknown message type', { type: message.type });
  }

  /**
   * Register a message handler
   */
  protected registerMessageHandler(
    type: MessageType,
    handler: (message: Message) => Promise<void>
  ): void {
    this.messageHandlers.set(type, handler);
  }

  /**
   * Update agent state
   */
  protected updateState(state: AgentState): void {
    const previousState = this.profile.state;
    this.profile.state = state;
    this.profile.metadata.updatedAt = new Date();
    
    this.emit('state:changed', { previous: previousState, current: state });
  }

  /**
   * Update performance metrics
   */
  protected updatePerformanceMetrics(updates: Partial<PerformanceMetrics>): void {
    Object.assign(this.profile.metadata.performance, updates);
    this.emit('metrics:updated', this.profile.metadata.performance);
  }

  /**
   * Setup message handlers
   */
  private setupMessageHandlers(): void {
    // Default handlers can be overridden by subclasses
    this.registerMessageHandler(MessageType.QUERY, async (message) => {
      await this.handleQueryMessage(message);
    });
    
    this.registerMessageHandler(MessageType.COMMAND, async (message) => {
      await this.handleCommandMessage(message);
    });
  }

  /**
   * Setup event listeners
   */
  private setupEventListeners(): void {
    this.on('error', (error) => {
      this.logger.error('Agent error', error);
      if (this.hooks.onError) {
        this.hooks.onError(error).catch(err => 
          this.logger.error('Error in error hook', err)
        );
      }
    });
  }

  /**
   * Handle query messages
   */
  protected async handleQueryMessage(message: Message): Promise<void> {
    // Default implementation - can be overridden
    this.logger.debug('Handling query message', { content: message.content });
  }

  /**
   * Handle command messages
   */
  protected async handleCommandMessage(message: Message): Promise<void> {
    // Default implementation - can be overridden
    this.logger.debug('Handling command message', { content: message.content });
  }

  /**
   * Merge configuration with defaults
   */
  private mergeConfig(config: AgentConfig): AgentConfig {
    return {
      maxConcurrentTasks: 5,
      communicationTimeout: 30000,
      retryAttempts: 3,
      memoryLimit: 100 * 1024 * 1024, // 100MB
      learningRate: 0.01,
      ...config
    };
  }

  /**
   * Get agent profile
   */
  public getProfile(): AgentProfile {
    return { ...this.profile };
  }

  /**
   * Get agent ID
   */
  public getId(): AgentId {
    return { ...this.id };
  }

  /**
   * Get current state
   */
  public getState(): AgentState {
    return this.profile.state;
  }

  /**
   * Get active goals
   */
  public getGoals(): Goal[] {
    return [...this.profile.goals];
  }

  /**
   * Get capabilities
   */
  public getCapabilities(): AgentCapability[] {
    return [...this.profile.capabilities];
  }
}

// Re-export types needed by task execution
import { TaskStatus, MessageType, MessageContent, MessagePriority } from '../types';