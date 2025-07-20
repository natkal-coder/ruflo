import { BaseAgent } from '../core/agent.base';
import {
  AgentType,
  AgentCapability,
  Goal,
  Task,
  TaskStatus,
  Message,
  MessageType
} from '../types';

/**
 * Executor agent responsible for executing specific tasks
 */
export class ExecutorAgent extends BaseAgent {
  private executionQueue: Task[];
  private executionHistory: Map<string, any>;

  constructor(name: string = 'Executor') {
    super(name, AgentType.EXECUTOR, {
      maxConcurrentTasks: 3,
      communicationTimeout: 30000
    });
    
    this.executionQueue = [];
    this.executionHistory = new Map();
    
    this.setupExecutorHandlers();
  }

  /**
   * Define executor capabilities
   */
  protected defineCapabilities(): AgentCapability[] {
    return [
      {
        name: 'task-execution',
        description: 'Execute assigned tasks'
      },
      {
        name: 'resource-management',
        description: 'Manage execution resources'
      },
      {
        name: 'status-reporting',
        description: 'Report execution status and progress'
      },
      {
        name: 'error-handling',
        description: 'Handle execution errors gracefully'
      }
    ];
  }

  /**
   * Process incoming goals
   */
  protected async processGoal(goal: Goal): Promise<void> {
    try {
      this.logger.info('Processing executor goal', { goalId: goal.id });
      
      // Convert goal to tasks
      const tasks = await this.goalEngine.goalToTasks(goal);
      
      // Add tasks to execution queue
      tasks.forEach(task => {
        task.status = TaskStatus.ASSIGNED;
        this.executionQueue.push(task);
        this.activeTasks.set(task.id, task);
      });
      
      // Start execution
      await this.processExecutionQueue();
      
      // Update goal status
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.ACTIVE);
    } catch (error) {
      this.logger.error('Failed to process goal', error);
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.FAILED);
      throw error;
    }
  }

  /**
   * Execute a specific task
   */
  protected async executeTask(task: Task): Promise<any> {
    try {
      this.logger.debug('Executing task', { taskId: task.id });
      
      task.status = TaskStatus.IN_PROGRESS;
      task.startedAt = new Date();
      
      // Simulate task execution based on description
      const result = await this.performTaskExecution(task);
      
      task.status = TaskStatus.COMPLETED;
      task.completedAt = new Date();
      task.result = result;
      
      // Store in history
      this.executionHistory.set(task.id, result);
      
      // Report completion
      await this.reportTaskCompletion(task);
      
      // Update performance metrics
      this.updatePerformanceMetrics({
        tasksCompleted: this.profile.metadata.performance.tasksCompleted + 1,
        successRate: this.calculateSuccessRate()
      });
      
      if (this.hooks.onTaskCompleted) {
        await this.hooks.onTaskCompleted(task);
      }
      
      return result;
    } catch (error) {
      this.logger.error('Task execution failed', error);
      task.status = TaskStatus.FAILED;
      task.error = error as Error;
      task.completedAt = new Date();
      
      await this.reportTaskFailure(task);
      throw error;
    }
  }

  /**
   * Perform actual task execution
   */
  private async performTaskExecution(task: Task): Promise<any> {
    // Simulate different types of task execution
    const executionTime = Math.random() * 5000 + 1000; // 1-6 seconds
    
    await new Promise(resolve => setTimeout(resolve, executionTime));
    
    // Return mock result based on task description
    if (task.description.includes('calculate')) {
      return { calculation: Math.random() * 100 };
    } else if (task.description.includes('analyze')) {
      return { analysis: 'Completed analysis', confidence: 0.85 };
    } else if (task.description.includes('process')) {
      return { processed: true, items: Math.floor(Math.random() * 50) };
    }
    
    return { executed: true, timestamp: new Date() };
  }

  /**
   * Process execution queue
   */
  private async processExecutionQueue(): Promise<void> {
    while (this.executionQueue.length > 0 && 
           this.activeTasks.size < this.config.maxConcurrentTasks!) {
      const task = this.executionQueue.shift();
      if (task) {
        // Execute task asynchronously
        this.executeTask(task).catch(error => {
          this.logger.error('Queue processing error', error);
        });
      }
    }
  }

  /**
   * Report task completion
   */
  private async reportTaskCompletion(task: Task): Promise<void> {
    // Report to coordinator or requester
    await this.sendMessage(
      task.assignedTo,
      MessageType.INFORM,
      {
        topic: 'task:completed',
        body: {
          taskId: task.id,
          goalId: task.goalId,
          result: task.result,
          executionTime: task.completedAt!.getTime() - task.startedAt!.getTime()
        }
      }
    );
  }

  /**
   * Report task failure
   */
  private async reportTaskFailure(task: Task): Promise<void> {
    await this.sendMessage(
      task.assignedTo,
      MessageType.INFORM,
      {
        topic: 'task:failed',
        body: {
          taskId: task.id,
          goalId: task.goalId,
          error: task.error?.message,
          executionTime: task.completedAt!.getTime() - task.startedAt!.getTime()
        }
      }
    );
  }

  /**
   * Calculate success rate
   */
  private calculateSuccessRate(): number {
    const completed = Array.from(this.executionHistory.keys()).length;
    const failed = Array.from(this.activeTasks.values())
      .filter(t => t.status === TaskStatus.FAILED).length;
    
    const total = completed + failed;
    return total > 0 ? completed / total : 0;
  }

  /**
   * Setup executor-specific message handlers
   */
  private setupExecutorHandlers(): void {
    // Handle task assignments
    this.registerMessageHandler(MessageType.COMMAND, async (message) => {
      if (message.content.topic === 'task:assignment') {
        await this.handleTaskAssignment(message);
      }
    });
    
    // Handle status queries
    this.registerMessageHandler(MessageType.QUERY, async (message) => {
      if (message.content.topic === 'status') {
        await this.handleStatusQuery(message);
      } else if (message.content.topic === 'progress') {
        await this.handleProgressQuery(message);
      }
    });
  }

  /**
   * Handle task assignment from coordinator
   */
  private async handleTaskAssignment(message: Message): Promise<void> {
    const { tasks, goal } = message.content.body;
    
    // Add goal if provided
    if (goal) {
      await this.addGoal(goal);
    }
    
    // Add tasks to queue
    for (const taskData of tasks) {
      const task: Task = {
        id: taskData.id || uuidv4(),
        goalId: taskData.goalId,
        assignedTo: this.id,
        description: taskData.description,
        status: TaskStatus.ASSIGNED
      };
      
      this.executionQueue.push(task);
      this.activeTasks.set(task.id, task);
    }
    
    // Process queue
    await this.processExecutionQueue();
    
    // Acknowledge assignment
    await this.reply(
      message,
      MessageType.ACKNOWLEDGE,
      {
        topic: 'task:acknowledged',
        body: { tasksReceived: tasks.length }
      }
    );
  }

  /**
   * Handle status query
   */
  private async handleStatusQuery(message: Message): Promise<void> {
    const status = {
      state: this.getState(),
      activeTasks: this.activeTasks.size,
      queuedTasks: this.executionQueue.length,
      completedTasks: this.executionHistory.size,
      performance: this.profile.metadata.performance
    };
    
    await this.reply(
      message,
      MessageType.RESPONSE,
      {
        topic: 'status:report',
        body: status
      }
    );
  }

  /**
   * Handle progress query
   */
  private async handleProgressQuery(message: Message): Promise<void> {
    const totalTasks = this.activeTasks.size + 
                      this.executionQueue.length + 
                      this.executionHistory.size;
    
    const progress = totalTasks > 0 
      ? this.executionHistory.size / totalTasks 
      : 0;
    
    await this.reply(
      message,
      MessageType.INFORM,
      {
        topic: 'progress:report',
        body: { progress }
      }
    );
  }

  /**
   * Get execution history
   */
  public getExecutionHistory(): Map<string, any> {
    return new Map(this.executionHistory);
  }

  /**
   * Clear execution history
   */
  public clearHistory(): void {
    this.executionHistory.clear();
  }

  /**
   * Get queue status
   */
  public getQueueStatus(): { queued: number; active: number; completed: number } {
    return {
      queued: this.executionQueue.length,
      active: this.activeTasks.size,
      completed: this.executionHistory.size
    };
  }
}

// Re-export necessary types
import { v4 as uuidv4 } from 'uuid';
import { GoalStatus } from '../types';