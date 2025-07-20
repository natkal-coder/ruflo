// Human-in-the-loop task management system

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  HumanTask,
  HumanTaskStatus,
  HumanTaskForm,
  FormField,
  WorkflowInstance
} from '../types';
import { WorkflowPersistence } from '../persistence/workflow-persistence';

export interface TaskAssignment {
  taskId: string;
  assigneeId: string;
  assignedAt: Date;
  deadline?: Date;
  priority: 'low' | 'medium' | 'high' | 'urgent';
}

export interface TaskNotification {
  id: string;
  taskId: string;
  recipientId: string;
  type: 'assignment' | 'reminder' | 'escalation' | 'completion';
  message: string;
  sentAt: Date;
  read: boolean;
}

export interface EscalationRule {
  id: string;
  condition: 'timeout' | 'priority' | 'custom';
  threshold: number; // minutes for timeout
  action: 'reassign' | 'notify' | 'delegate';
  targetId?: string;
  enabled: boolean;
}

export interface TaskFilter {
  assignee?: string;
  status?: HumanTaskStatus | HumanTaskStatus[];
  priority?: string;
  instanceId?: string;
  dateRange?: { from: Date; to: Date };
  tags?: string[];
}

export class HumanTaskManager extends EventEmitter {
  private persistence: WorkflowPersistence;
  private assignments = new Map<string, TaskAssignment>();
  private notifications = new Map<string, TaskNotification>();
  private escalationRules: EscalationRule[] = [];
  private escalationTimer: NodeJS.Timeout | null = null;

  constructor(persistence: WorkflowPersistence) {
    super();
    this.persistence = persistence;
    this.startEscalationMonitoring();
  }

  // Task lifecycle management
  async createTask(
    instanceId: string,
    nodeId: string,
    config: {
      title: string;
      description?: string;
      assignee?: string;
      inputs?: Record<string, any>;
      form?: HumanTaskForm;
      deadline?: Date;
      priority?: 'low' | 'medium' | 'high' | 'urgent';
      tags?: string[];
    }
  ): Promise<HumanTask> {
    const task: HumanTask = {
      id: uuidv4(),
      nodeId,
      instanceId,
      title: config.title,
      description: config.description,
      assignee: config.assignee,
      inputs: config.inputs || {},
      form: config.form,
      status: config.assignee ? 'assigned' : 'pending',
      createdAt: new Date()
    };

    await this.persistence.saveHumanTask(task);

    // Create assignment if assignee specified
    if (config.assignee) {
      await this.assignTask(task.id, config.assignee, {
        deadline: config.deadline,
        priority: config.priority || 'medium'
      });
    }

    this.emit('task:created', task);
    return task;
  }

  async assignTask(
    taskId: string,
    assigneeId: string,
    options: {
      deadline?: Date;
      priority?: 'low' | 'medium' | 'high' | 'urgent';
      notify?: boolean;
    } = {}
  ): Promise<void> {
    const task = await this.persistence.getHumanTask(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    if (task.status === 'completed') {
      throw new Error(`Cannot assign completed task ${taskId}`);
    }

    // Update task
    task.assignee = assigneeId;
    task.status = 'assigned';
    await this.persistence.updateHumanTask(task);

    // Create assignment record
    const assignment: TaskAssignment = {
      taskId,
      assigneeId,
      assignedAt: new Date(),
      deadline: options.deadline,
      priority: options.priority || 'medium'
    };

    this.assignments.set(taskId, assignment);

    // Send notification if requested
    if (options.notify !== false) {
      await this.sendNotification({
        taskId,
        recipientId: assigneeId,
        type: 'assignment',
        message: `You have been assigned task: ${task.title}`
      });
    }

    this.emit('task:assigned', { task, assigneeId });
  }

  async reassignTask(
    taskId: string,
    newAssigneeId: string,
    reason?: string
  ): Promise<void> {
    const task = await this.persistence.getHumanTask(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    const oldAssignee = task.assignee;
    await this.assignTask(taskId, newAssigneeId, { notify: true });

    // Notify old assignee
    if (oldAssignee && oldAssignee !== newAssigneeId) {
      await this.sendNotification({
        taskId,
        recipientId: oldAssignee,
        type: 'assignment',
        message: `Task "${task.title}" has been reassigned${reason ? `: ${reason}` : ''}`
      });
    }

    this.emit('task:reassigned', { taskId, oldAssignee, newAssignee: newAssigneeId, reason });
  }

  async startTask(taskId: string, userId: string): Promise<void> {
    const task = await this.persistence.getHumanTask(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    if (task.assignee !== userId) {
      throw new Error(`User ${userId} is not assigned to task ${taskId}`);
    }

    if (task.status !== 'assigned') {
      throw new Error(`Cannot start task in status ${task.status}`);
    }

    task.status = 'in_progress';
    await this.persistence.updateHumanTask(task);

    this.emit('task:started', { taskId, userId });
  }

  async completeTask(
    taskId: string,
    userId: string,
    response: Record<string, any>
  ): Promise<void> {
    const task = await this.persistence.getHumanTask(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    if (task.assignee !== userId) {
      throw new Error(`User ${userId} is not assigned to task ${taskId}`);
    }

    if (task.status === 'completed') {
      throw new Error(`Task ${taskId} is already completed`);
    }

    // Validate response against form if present
    if (task.form) {
      this.validateResponse(response, task.form);
    }

    // Update task
    task.status = 'completed';
    task.completedAt = new Date();
    task.response = response;
    await this.persistence.updateHumanTask(task);

    // Clean up assignment
    this.assignments.delete(taskId);

    this.emit('task:completed', { task, response });
  }

  async cancelTask(taskId: string, reason?: string): Promise<void> {
    const task = await this.persistence.getHumanTask(taskId);
    if (!task) {
      throw new Error(`Task ${taskId} not found`);
    }

    if (task.status === 'completed') {
      throw new Error(`Cannot cancel completed task ${taskId}`);
    }

    task.status = 'cancelled';
    task.completedAt = new Date();
    await this.persistence.updateHumanTask(task);

    // Notify assignee if any
    if (task.assignee) {
      await this.sendNotification({
        taskId,
        recipientId: task.assignee,
        type: 'completion',
        message: `Task "${task.title}" has been cancelled${reason ? `: ${reason}` : ''}`
      });
    }

    // Clean up assignment
    this.assignments.delete(taskId);

    this.emit('task:cancelled', { taskId, reason });
  }

  // Task querying
  async getTasks(filter: TaskFilter = {}): Promise<HumanTask[]> {
    let tasks = await this.persistence.listHumanTasks(filter.instanceId);

    // Apply filters
    if (filter.assignee) {
      tasks = tasks.filter(t => t.assignee === filter.assignee);
    }

    if (filter.status) {
      const statuses = Array.isArray(filter.status) ? filter.status : [filter.status];
      tasks = tasks.filter(t => statuses.includes(t.status));
    }

    if (filter.dateRange) {
      tasks = tasks.filter(t => 
        t.createdAt >= filter.dateRange!.from && 
        t.createdAt <= filter.dateRange!.to
      );
    }

    // Apply priority filter through assignments
    if (filter.priority) {
      const priorityTasks = new Set();
      for (const [taskId, assignment] of this.assignments) {
        if (assignment.priority === filter.priority) {
          priorityTasks.add(taskId);
        }
      }
      tasks = tasks.filter(t => priorityTasks.has(t.id));
    }

    return tasks;
  }

  async getTasksForUser(userId: string, includeCompleted = false): Promise<HumanTask[]> {
    const statuses: HumanTaskStatus[] = ['assigned', 'in_progress'];
    if (includeCompleted) {
      statuses.push('completed');
    }

    return this.getTasks({
      assignee: userId,
      status: statuses
    });
  }

  async getTaskById(taskId: string): Promise<HumanTask | null> {
    return this.persistence.getHumanTask(taskId);
  }

  // Form validation
  private validateResponse(response: Record<string, any>, form: HumanTaskForm): void {
    const errors: string[] = [];

    for (const field of form.fields) {
      const value = response[field.name];

      // Check required fields
      if (field.required && (value === undefined || value === null || value === '')) {
        errors.push(`Field ${field.label} is required`);
        continue;
      }

      // Type validation
      if (value !== undefined && value !== null) {
        switch (field.type) {
          case 'number':
            if (typeof value !== 'number' && isNaN(Number(value))) {
              errors.push(`Field ${field.label} must be a number`);
            }
            break;
          case 'boolean':
            if (typeof value !== 'boolean') {
              errors.push(`Field ${field.label} must be true or false`);
            }
            break;
          case 'date':
            if (!(value instanceof Date) && isNaN(Date.parse(value))) {
              errors.push(`Field ${field.label} must be a valid date`);
            }
            break;
          case 'select':
          case 'multiselect':
            if (field.options) {
              const validValues = field.options.map(opt => opt.value);
              if (field.type === 'multiselect') {
                if (!Array.isArray(value) || !value.every(v => validValues.includes(v))) {
                  errors.push(`Field ${field.label} contains invalid options`);
                }
              } else {
                if (!validValues.includes(value)) {
                  errors.push(`Field ${field.label} has invalid option`);
                }
              }
            }
            break;
        }
      }

      // Custom validation
      if (field.validation && value !== undefined) {
        try {
          const isValid = new Function('value', field.validation)(value);
          if (!isValid) {
            errors.push(`Field ${field.label} validation failed`);
          }
        } catch (error) {
          errors.push(`Field ${field.label} validation error: ${error.message}`);
        }
      }
    }

    if (errors.length > 0) {
      throw new Error(`Form validation failed: ${errors.join(', ')}`);
    }
  }

  // Notifications
  async sendNotification(notification: Omit<TaskNotification, 'id' | 'sentAt' | 'read'>): Promise<void> {
    const fullNotification: TaskNotification = {
      id: uuidv4(),
      sentAt: new Date(),
      read: false,
      ...notification
    };

    this.notifications.set(fullNotification.id, fullNotification);
    this.emit('notification:sent', fullNotification);
  }

  async getNotifications(userId: string, unreadOnly = false): Promise<TaskNotification[]> {
    const notifications = Array.from(this.notifications.values())
      .filter(n => n.recipientId === userId);

    if (unreadOnly) {
      return notifications.filter(n => !n.read);
    }

    return notifications;
  }

  async markNotificationRead(notificationId: string): Promise<void> {
    const notification = this.notifications.get(notificationId);
    if (notification) {
      notification.read = true;
      this.emit('notification:read', notification);
    }
  }

  // Escalation management
  addEscalationRule(rule: Omit<EscalationRule, 'id'>): string {
    const fullRule: EscalationRule = {
      id: uuidv4(),
      ...rule
    };

    this.escalationRules.push(fullRule);
    this.emit('escalation:rule_added', fullRule);
    
    return fullRule.id;
  }

  removeEscalationRule(ruleId: string): void {
    const index = this.escalationRules.findIndex(r => r.id === ruleId);
    if (index !== -1) {
      this.escalationRules.splice(index, 1);
      this.emit('escalation:rule_removed', ruleId);
    }
  }

  private startEscalationMonitoring(): void {
    this.escalationTimer = setInterval(() => {
      this.checkEscalations().catch(err => {
        this.emit('error', err);
      });
    }, 60000); // Check every minute
  }

  private async checkEscalations(): Promise<void> {
    const now = new Date();

    for (const [taskId, assignment] of this.assignments) {
      const task = await this.persistence.getHumanTask(taskId);
      if (!task || task.status === 'completed' || task.status === 'cancelled') {
        continue;
      }

      for (const rule of this.escalationRules) {
        if (!rule.enabled) continue;

        let shouldEscalate = false;

        switch (rule.condition) {
          case 'timeout':
            if (assignment.deadline) {
              shouldEscalate = now > assignment.deadline;
            } else {
              const timeoutDate = new Date(assignment.assignedAt.getTime() + rule.threshold * 60000);
              shouldEscalate = now > timeoutDate;
            }
            break;

          case 'priority':
            shouldEscalate = assignment.priority === 'urgent' && 
              (now.getTime() - assignment.assignedAt.getTime()) > rule.threshold * 60000;
            break;

          case 'custom':
            // Custom escalation logic would be implemented here
            break;
        }

        if (shouldEscalate) {
          await this.executeEscalation(task, assignment, rule);
        }
      }
    }
  }

  private async executeEscalation(
    task: HumanTask,
    assignment: TaskAssignment,
    rule: EscalationRule
  ): Promise<void> {
    switch (rule.action) {
      case 'reassign':
        if (rule.targetId) {
          await this.reassignTask(
            task.id,
            rule.targetId,
            `Escalated due to ${rule.condition}`
          );
        }
        break;

      case 'notify':
        if (rule.targetId) {
          await this.sendNotification({
            taskId: task.id,
            recipientId: rule.targetId,
            type: 'escalation',
            message: `Task "${task.title}" requires attention (escalated due to ${rule.condition})`
          });
        }
        break;

      case 'delegate':
        if (rule.targetId) {
          // Create a new task for the delegate while keeping original
          await this.createTask(task.instanceId, task.nodeId, {
            title: `[ESCALATED] ${task.title}`,
            description: `Escalated from ${task.assignee}: ${task.description}`,
            assignee: rule.targetId,
            inputs: task.inputs,
            form: task.form,
            priority: 'urgent'
          });
        }
        break;
    }

    this.emit('escalation:executed', { task, rule });
  }

  // Analytics and reporting
  async getTaskMetrics(timeRange?: { from: Date; to: Date }): Promise<{
    total: number;
    completed: number;
    pending: number;
    overdue: number;
    averageCompletionTime: number;
    completionRate: number;
  }> {
    const tasks = await this.getTasks(timeRange ? { dateRange: timeRange } : {});
    
    const total = tasks.length;
    const completed = tasks.filter(t => t.status === 'completed').length;
    const pending = tasks.filter(t => ['pending', 'assigned', 'in_progress'].includes(t.status)).length;
    
    // Calculate overdue tasks
    let overdue = 0;
    const now = new Date();
    for (const task of tasks) {
      const assignment = this.assignments.get(task.id);
      if (assignment?.deadline && now > assignment.deadline && task.status !== 'completed') {
        overdue++;
      }
    }

    // Calculate average completion time
    const completedTasks = tasks.filter(t => t.status === 'completed' && t.completedAt);
    const totalCompletionTime = completedTasks.reduce((sum, task) => {
      return sum + (task.completedAt!.getTime() - task.createdAt.getTime());
    }, 0);

    const averageCompletionTime = completedTasks.length > 0 
      ? totalCompletionTime / completedTasks.length 
      : 0;

    const completionRate = total > 0 ? (completed / total) * 100 : 0;

    return {
      total,
      completed,
      pending,
      overdue,
      averageCompletionTime,
      completionRate
    };
  }

  async getUserMetrics(userId: string): Promise<{
    assigned: number;
    completed: number;
    pending: number;
    averageCompletionTime: number;
  }> {
    const tasks = await this.getTasksForUser(userId, true);
    
    const assigned = tasks.length;
    const completed = tasks.filter(t => t.status === 'completed').length;
    const pending = tasks.filter(t => ['assigned', 'in_progress'].includes(t.status)).length;

    const completedTasks = tasks.filter(t => t.status === 'completed' && t.completedAt);
    const totalCompletionTime = completedTasks.reduce((sum, task) => {
      return sum + (task.completedAt!.getTime() - task.createdAt.getTime());
    }, 0);

    const averageCompletionTime = completedTasks.length > 0 
      ? totalCompletionTime / completedTasks.length 
      : 0;

    return {
      assigned,
      completed,
      pending,
      averageCompletionTime
    };
  }

  async shutdown(): Promise<void> {
    if (this.escalationTimer) {
      clearInterval(this.escalationTimer);
    }
    this.removeAllListeners();
  }
}