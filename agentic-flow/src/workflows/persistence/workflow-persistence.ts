// Workflow persistence layer for durable execution

import { EventEmitter } from 'events';
import {
  WorkflowDefinition,
  WorkflowInstance,
  WorkflowSnapshot,
  WorkflowEvent,
  HumanTask,
  WorkflowTemplate
} from '../types';

export interface PersistenceAdapter {
  // Workflow definitions
  saveWorkflow(workflow: WorkflowDefinition): Promise<void>;
  getWorkflow(id: string): Promise<WorkflowDefinition | null>;
  listWorkflows(): Promise<WorkflowDefinition[]>;
  deleteWorkflow(id: string): Promise<void>;

  // Workflow instances
  saveInstance(instance: WorkflowInstance): Promise<void>;
  getInstance(id: string): Promise<WorkflowInstance | null>;
  listInstances(workflowId?: string): Promise<WorkflowInstance[]>;
  updateInstance(instance: WorkflowInstance): Promise<void>;
  deleteInstance(id: string): Promise<void>;

  // Snapshots
  saveSnapshot(snapshot: WorkflowSnapshot): Promise<void>;
  getSnapshot(instanceId: string, timestamp: Date): Promise<WorkflowSnapshot | null>;
  listSnapshots(instanceId: string): Promise<WorkflowSnapshot[]>;
  deleteSnapshots(instanceId: string, before?: Date): Promise<void>;

  // Events
  saveEvent(event: WorkflowEvent): Promise<void>;
  getEvents(instanceId: string, after?: Date): Promise<WorkflowEvent[]>;
  deleteEvents(instanceId: string, before?: Date): Promise<void>;

  // Human tasks
  saveHumanTask(task: HumanTask): Promise<void>;
  getHumanTask(id: string): Promise<HumanTask | null>;
  listHumanTasks(instanceId?: string): Promise<HumanTask[]>;
  updateHumanTask(task: HumanTask): Promise<void>;
  deleteHumanTask(id: string): Promise<void>;

  // Templates
  saveTemplate(template: WorkflowTemplate): Promise<void>;
  getTemplate(id: string): Promise<WorkflowTemplate | null>;
  listTemplates(): Promise<WorkflowTemplate[]>;
  deleteTemplate(id: string): Promise<void>;
}

// In-memory adapter for development
export class InMemoryAdapter implements PersistenceAdapter {
  private workflows = new Map<string, WorkflowDefinition>();
  private instances = new Map<string, WorkflowInstance>();
  private snapshots = new Map<string, WorkflowSnapshot[]>();
  private events = new Map<string, WorkflowEvent[]>();
  private humanTasks = new Map<string, HumanTask>();
  private templates = new Map<string, WorkflowTemplate>();

  async saveWorkflow(workflow: WorkflowDefinition): Promise<void> {
    this.workflows.set(workflow.id, JSON.parse(JSON.stringify(workflow)));
  }

  async getWorkflow(id: string): Promise<WorkflowDefinition | null> {
    const workflow = this.workflows.get(id);
    return workflow ? JSON.parse(JSON.stringify(workflow)) : null;
  }

  async listWorkflows(): Promise<WorkflowDefinition[]> {
    return Array.from(this.workflows.values()).map(w => 
      JSON.parse(JSON.stringify(w))
    );
  }

  async deleteWorkflow(id: string): Promise<void> {
    this.workflows.delete(id);
  }

  async saveInstance(instance: WorkflowInstance): Promise<void> {
    this.instances.set(instance.id, JSON.parse(JSON.stringify(instance)));
  }

  async getInstance(id: string): Promise<WorkflowInstance | null> {
    const instance = this.instances.get(id);
    return instance ? JSON.parse(JSON.stringify(instance)) : null;
  }

  async listInstances(workflowId?: string): Promise<WorkflowInstance[]> {
    const instances = Array.from(this.instances.values());
    if (workflowId) {
      return instances
        .filter(i => i.workflowId === workflowId)
        .map(i => JSON.parse(JSON.stringify(i)));
    }
    return instances.map(i => JSON.parse(JSON.stringify(i)));
  }

  async updateInstance(instance: WorkflowInstance): Promise<void> {
    this.instances.set(instance.id, JSON.parse(JSON.stringify(instance)));
  }

  async deleteInstance(id: string): Promise<void> {
    this.instances.delete(id);
    this.snapshots.delete(id);
    this.events.delete(id);
  }

  async saveSnapshot(snapshot: WorkflowSnapshot): Promise<void> {
    const snapshots = this.snapshots.get(snapshot.instanceId) || [];
    snapshots.push(JSON.parse(JSON.stringify(snapshot)));
    this.snapshots.set(snapshot.instanceId, snapshots);
  }

  async getSnapshot(instanceId: string, timestamp: Date): Promise<WorkflowSnapshot | null> {
    const snapshots = this.snapshots.get(instanceId) || [];
    const snapshot = snapshots.find(s => 
      s.timestamp.getTime() === timestamp.getTime()
    );
    return snapshot ? JSON.parse(JSON.stringify(snapshot)) : null;
  }

  async listSnapshots(instanceId: string): Promise<WorkflowSnapshot[]> {
    const snapshots = this.snapshots.get(instanceId) || [];
    return snapshots.map(s => JSON.parse(JSON.stringify(s)));
  }

  async deleteSnapshots(instanceId: string, before?: Date): Promise<void> {
    if (before) {
      const snapshots = this.snapshots.get(instanceId) || [];
      const filtered = snapshots.filter(s => s.timestamp >= before);
      this.snapshots.set(instanceId, filtered);
    } else {
      this.snapshots.delete(instanceId);
    }
  }

  async saveEvent(event: WorkflowEvent): Promise<void> {
    const events = this.events.get(event.instanceId) || [];
    events.push(JSON.parse(JSON.stringify(event)));
    this.events.set(event.instanceId, events);
  }

  async getEvents(instanceId: string, after?: Date): Promise<WorkflowEvent[]> {
    const events = this.events.get(instanceId) || [];
    if (after) {
      return events
        .filter(e => e.timestamp >= after)
        .map(e => JSON.parse(JSON.stringify(e)));
    }
    return events.map(e => JSON.parse(JSON.stringify(e)));
  }

  async deleteEvents(instanceId: string, before?: Date): Promise<void> {
    if (before) {
      const events = this.events.get(instanceId) || [];
      const filtered = events.filter(e => e.timestamp >= before);
      this.events.set(instanceId, filtered);
    } else {
      this.events.delete(instanceId);
    }
  }

  async saveHumanTask(task: HumanTask): Promise<void> {
    this.humanTasks.set(task.id, JSON.parse(JSON.stringify(task)));
  }

  async getHumanTask(id: string): Promise<HumanTask | null> {
    const task = this.humanTasks.get(id);
    return task ? JSON.parse(JSON.stringify(task)) : null;
  }

  async listHumanTasks(instanceId?: string): Promise<HumanTask[]> {
    const tasks = Array.from(this.humanTasks.values());
    if (instanceId) {
      return tasks
        .filter(t => t.instanceId === instanceId)
        .map(t => JSON.parse(JSON.stringify(t)));
    }
    return tasks.map(t => JSON.parse(JSON.stringify(t)));
  }

  async updateHumanTask(task: HumanTask): Promise<void> {
    this.humanTasks.set(task.id, JSON.parse(JSON.stringify(task)));
  }

  async deleteHumanTask(id: string): Promise<void> {
    this.humanTasks.delete(id);
  }

  async saveTemplate(template: WorkflowTemplate): Promise<void> {
    this.templates.set(template.id, JSON.parse(JSON.stringify(template)));
  }

  async getTemplate(id: string): Promise<WorkflowTemplate | null> {
    const template = this.templates.get(id);
    return template ? JSON.parse(JSON.stringify(template)) : null;
  }

  async listTemplates(): Promise<WorkflowTemplate[]> {
    return Array.from(this.templates.values()).map(t => 
      JSON.parse(JSON.stringify(t))
    );
  }

  async deleteTemplate(id: string): Promise<void> {
    this.templates.delete(id);
  }
}

export class WorkflowPersistence extends EventEmitter {
  private adapter: PersistenceAdapter;
  private eventBuffer: WorkflowEvent[] = [];
  private bufferFlushInterval: NodeJS.Timeout | null = null;
  private bufferSize = 100;
  private flushInterval = 5000; // 5 seconds

  constructor(adapter: PersistenceAdapter) {
    super();
    this.adapter = adapter;
    this.startEventBuffering();
  }

  // Workflow definitions
  async saveWorkflowDefinition(workflow: WorkflowDefinition): Promise<void> {
    await this.adapter.saveWorkflow(workflow);
    this.emit('workflow:saved', workflow);
  }

  async getWorkflowDefinition(id: string): Promise<WorkflowDefinition | null> {
    return this.adapter.getWorkflow(id);
  }

  async listWorkflowDefinitions(): Promise<WorkflowDefinition[]> {
    return this.adapter.listWorkflows();
  }

  async deleteWorkflowDefinition(id: string): Promise<void> {
    await this.adapter.deleteWorkflow(id);
    this.emit('workflow:deleted', id);
  }

  // Workflow instances
  async saveInstance(instance: WorkflowInstance): Promise<void> {
    await this.adapter.saveInstance(instance);
    await this.recordEvent({
      id: `event-${Date.now()}`,
      instanceId: instance.id,
      type: 'instance.created',
      payload: { status: instance.status },
      timestamp: new Date()
    });
    this.emit('instance:saved', instance);
  }

  async getInstance(id: string): Promise<WorkflowInstance | null> {
    return this.adapter.getInstance(id);
  }

  async listInstances(workflowId?: string): Promise<WorkflowInstance[]> {
    return this.adapter.listInstances(workflowId);
  }

  async updateInstance(instance: WorkflowInstance): Promise<void> {
    await this.adapter.updateInstance(instance);
    await this.recordEvent({
      id: `event-${Date.now()}`,
      instanceId: instance.id,
      type: 'instance.updated',
      payload: { 
        status: instance.status,
        currentNode: instance.currentNodeId 
      },
      timestamp: new Date(),
      nodeId: instance.currentNodeId
    });
    this.emit('instance:updated', instance);
  }

  async deleteInstance(id: string): Promise<void> {
    await this.adapter.deleteInstance(id);
    this.emit('instance:deleted', id);
  }

  // Snapshots for recovery
  async saveSnapshot(snapshot: WorkflowSnapshot): Promise<void> {
    await this.adapter.saveSnapshot(snapshot);
    this.emit('snapshot:saved', snapshot);
  }

  async getSnapshot(instanceId: string, timestamp: Date): Promise<WorkflowSnapshot | null> {
    return this.adapter.getSnapshot(instanceId, timestamp);
  }

  async getLatestSnapshot(instanceId: string): Promise<WorkflowSnapshot | null> {
    const snapshots = await this.adapter.listSnapshots(instanceId);
    if (snapshots.length === 0) return null;
    
    return snapshots.reduce((latest, current) => 
      current.timestamp > latest.timestamp ? current : latest
    );
  }

  async listSnapshots(instanceId: string): Promise<WorkflowSnapshot[]> {
    return this.adapter.listSnapshots(instanceId);
  }

  async cleanupSnapshots(instanceId: string, keepLast: number = 10): Promise<void> {
    const snapshots = await this.adapter.listSnapshots(instanceId);
    if (snapshots.length <= keepLast) return;

    // Sort by timestamp descending
    snapshots.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
    
    // Delete old snapshots
    const cutoffDate = snapshots[keepLast - 1].timestamp;
    await this.adapter.deleteSnapshots(instanceId, cutoffDate);
    
    this.emit('snapshots:cleaned', { instanceId, kept: keepLast });
  }

  // Event sourcing
  async recordEvent(event: WorkflowEvent): Promise<void> {
    this.eventBuffer.push(event);
    
    if (this.eventBuffer.length >= this.bufferSize) {
      await this.flushEventBuffer();
    }
  }

  async getEvents(instanceId: string, after?: Date): Promise<WorkflowEvent[]> {
    // Flush buffer first to ensure all events are persisted
    await this.flushEventBuffer();
    return this.adapter.getEvents(instanceId, after);
  }

  async replayEvents(instanceId: string, from?: Date): Promise<WorkflowInstance | null> {
    const instance = await this.getInstance(instanceId);
    if (!instance) return null;

    const events = await this.getEvents(instanceId, from);
    
    // Reset instance to snapshot state if available
    if (from) {
      const snapshots = await this.listSnapshots(instanceId);
      const relevantSnapshot = snapshots
        .filter(s => s.timestamp <= from)
        .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())[0];
      
      if (relevantSnapshot) {
        Object.assign(instance, relevantSnapshot.state);
      }
    }

    // Replay events
    for (const event of events) {
      this.applyEvent(instance, event);
    }

    return instance;
  }

  // Human tasks
  async saveHumanTask(task: HumanTask): Promise<void> {
    await this.adapter.saveHumanTask(task);
    await this.recordEvent({
      id: `event-${Date.now()}`,
      instanceId: task.instanceId,
      type: 'humanTask.created',
      payload: { taskId: task.id, nodeId: task.nodeId },
      timestamp: new Date(),
      nodeId: task.nodeId
    });
    this.emit('humanTask:saved', task);
  }

  async getHumanTask(id: string): Promise<HumanTask | null> {
    return this.adapter.getHumanTask(id);
  }

  async listHumanTasks(instanceId?: string): Promise<HumanTask[]> {
    return this.adapter.listHumanTasks(instanceId);
  }

  async updateHumanTask(task: HumanTask): Promise<void> {
    await this.adapter.updateHumanTask(task);
    await this.recordEvent({
      id: `event-${Date.now()}`,
      instanceId: task.instanceId,
      type: 'humanTask.updated',
      payload: { 
        taskId: task.id, 
        status: task.status,
        response: task.response 
      },
      timestamp: new Date(),
      nodeId: task.nodeId
    });
    this.emit('humanTask:updated', task);
  }

  // Templates
  async saveTemplate(template: WorkflowTemplate): Promise<void> {
    await this.adapter.saveTemplate(template);
    this.emit('template:saved', template);
  }

  async getTemplate(id: string): Promise<WorkflowTemplate | null> {
    return this.adapter.getTemplate(id);
  }

  async listTemplates(): Promise<WorkflowTemplate[]> {
    return this.adapter.listTemplates();
  }

  async deleteTemplate(id: string): Promise<void> {
    await this.adapter.deleteTemplate(id);
    this.emit('template:deleted', id);
  }

  // Recovery
  async recoverInstance(instanceId: string): Promise<WorkflowInstance | null> {
    // Try to get instance
    let instance = await this.getInstance(instanceId);
    if (!instance) {
      // Try to recover from latest snapshot
      const snapshot = await this.getLatestSnapshot(instanceId);
      if (snapshot) {
        instance = snapshot.state;
        await this.saveInstance(instance);
      }
    }

    if (instance) {
      // Replay events from last known state
      const events = await this.getEvents(instanceId, instance.startedAt);
      for (const event of events) {
        this.applyEvent(instance, event);
      }
      await this.updateInstance(instance);
    }

    return instance;
  }

  // Utility methods
  private startEventBuffering() {
    this.bufferFlushInterval = setInterval(() => {
      this.flushEventBuffer().catch(err => {
        this.emit('error', err);
      });
    }, this.flushInterval);
  }

  private async flushEventBuffer() {
    if (this.eventBuffer.length === 0) return;

    const events = [...this.eventBuffer];
    this.eventBuffer = [];

    try {
      await Promise.all(events.map(event => this.adapter.saveEvent(event)));
      this.emit('events:flushed', { count: events.length });
    } catch (error) {
      // Re-add events to buffer on failure
      this.eventBuffer.unshift(...events);
      throw error;
    }
  }

  private applyEvent(instance: WorkflowInstance, event: WorkflowEvent) {
    switch (event.type) {
      case 'instance.updated':
        if (event.payload.status) {
          instance.status = event.payload.status;
        }
        if (event.payload.currentNode) {
          instance.currentNodeId = event.payload.currentNode;
        }
        break;
      
      case 'humanTask.created':
        instance.humanTasks = instance.humanTasks || [];
        // Task details would be loaded separately
        break;
      
      case 'node.executed':
        instance.context.nodeOutputs[event.nodeId!] = event.payload.outputs;
        break;
      
      // Add more event handlers as needed
    }
  }

  async shutdown() {
    if (this.bufferFlushInterval) {
      clearInterval(this.bufferFlushInterval);
    }
    await this.flushEventBuffer();
    this.removeAllListeners();
  }
}