// Core workflow engine with Mastra compatibility and XState integration

import { EventEmitter } from 'events';
import { createMachine, interpret, State, Interpreter } from 'xstate';
import { v4 as uuidv4 } from 'uuid';
import {
  WorkflowDefinition,
  WorkflowInstance,
  WorkflowContext,
  WorkflowStatus,
  WorkflowNode,
  WorkflowEdge,
  WorkflowError,
  HumanTask,
  XStateWorkflowConfig
} from '../types';
import { WorkflowValidator } from '../validation/workflow-validator';
import { WorkflowPersistence } from '../persistence/workflow-persistence';
import { WorkflowExecutor } from './workflow-executor';
import { WorkflowConverter } from './workflow-converter';

export interface WorkflowEngineOptions {
  persistence: WorkflowPersistence;
  validator?: WorkflowValidator;
  executor?: WorkflowExecutor;
  enableSnapshots?: boolean;
  snapshotInterval?: number;
  maxConcurrentWorkflows?: number;
}

export class WorkflowEngine extends EventEmitter {
  private instances: Map<string, WorkflowInstance> = new Map();
  private interpreters: Map<string, Interpreter<any, any, any>> = new Map();
  private persistence: WorkflowPersistence;
  private validator: WorkflowValidator;
  private executor: WorkflowExecutor;
  private converter: WorkflowConverter;
  private options: WorkflowEngineOptions;

  constructor(options: WorkflowEngineOptions) {
    super();
    this.options = options;
    this.persistence = options.persistence;
    this.validator = options.validator || new WorkflowValidator();
    this.executor = options.executor || new WorkflowExecutor();
    this.converter = new WorkflowConverter();
  }

  async startWorkflow(
    definition: WorkflowDefinition,
    inputs: Record<string, any> = {},
    parentInstanceId?: string
  ): Promise<string> {
    // Validate workflow definition
    const validation = await this.validator.validate(definition);
    if (!validation.valid) {
      throw new Error(`Invalid workflow: ${validation.errors.join(', ')}`);
    }

    // Create workflow instance
    const instanceId = uuidv4();
    const instance: WorkflowInstance = {
      id: instanceId,
      workflowId: definition.id,
      version: definition.version,
      status: 'pending',
      context: {
        inputs,
        variables: this.initializeVariables(definition),
        outputs: {},
        nodeOutputs: {},
        metadata: {
          workflowName: definition.name,
          startedBy: inputs._startedBy || 'system'
        }
      },
      startedAt: new Date(),
      parentInstanceId
    };

    // Convert to XState machine
    const xstateConfig = this.converter.toXState(definition);
    const machine = createMachine({
      id: instanceId,
      initial: 'start',
      context: instance.context,
      ...xstateConfig.machine.config
    });

    // Create interpreter with guards, actions, and services
    const interpreter = interpret(machine)
      .onTransition((state) => this.handleStateTransition(instanceId, state))
      .onDone(() => this.handleWorkflowComplete(instanceId))
      .onStop(() => this.handleWorkflowStop(instanceId));

    // Store instance and interpreter
    this.instances.set(instanceId, instance);
    this.interpreters.set(instanceId, interpreter);

    // Persist initial state
    await this.persistence.saveInstance(instance);

    // Start execution
    interpreter.start();
    instance.status = 'running';
    
    this.emit('workflow:started', { instanceId, workflowId: definition.id });

    // Enable snapshots if configured
    if (this.options.enableSnapshots) {
      this.scheduleSnapshots(instanceId);
    }

    return instanceId;
  }

  async pauseWorkflow(instanceId: string): Promise<void> {
    const instance = this.instances.get(instanceId);
    const interpreter = this.interpreters.get(instanceId);

    if (!instance || !interpreter) {
      throw new Error(`Workflow instance ${instanceId} not found`);
    }

    if (instance.status !== 'running') {
      throw new Error(`Cannot pause workflow in status ${instance.status}`);
    }

    // Save current state
    const state = interpreter.getSnapshot();
    await this.persistence.saveSnapshot({
      instanceId,
      timestamp: new Date(),
      state: instance,
      checksum: this.calculateChecksum(state)
    });

    // Stop interpreter
    interpreter.stop();
    instance.status = 'paused';
    
    await this.persistence.updateInstance(instance);
    this.emit('workflow:paused', { instanceId });
  }

  async resumeWorkflow(instanceId: string): Promise<void> {
    const instance = await this.persistence.getInstance(instanceId);
    
    if (!instance) {
      throw new Error(`Workflow instance ${instanceId} not found`);
    }

    if (instance.status !== 'paused') {
      throw new Error(`Cannot resume workflow in status ${instance.status}`);
    }

    // Load workflow definition
    const definition = await this.persistence.getWorkflowDefinition(instance.workflowId);
    if (!definition) {
      throw new Error(`Workflow definition ${instance.workflowId} not found`);
    }

    // Restore from snapshot
    const snapshot = await this.persistence.getLatestSnapshot(instanceId);
    if (!snapshot) {
      throw new Error(`No snapshot found for instance ${instanceId}`);
    }

    // Recreate XState machine and restore state
    const xstateConfig = this.converter.toXState(definition);
    const machine = createMachine({
      id: instanceId,
      ...xstateConfig.machine.config
    });

    const interpreter = interpret(machine)
      .onTransition((state) => this.handleStateTransition(instanceId, state))
      .onDone(() => this.handleWorkflowComplete(instanceId))
      .onStop(() => this.handleWorkflowStop(instanceId));

    // Restore interpreter state
    interpreter.start(snapshot.state as any);
    
    this.instances.set(instanceId, instance);
    this.interpreters.set(instanceId, interpreter);
    
    instance.status = 'running';
    await this.persistence.updateInstance(instance);
    
    this.emit('workflow:resumed', { instanceId });
  }

  async cancelWorkflow(instanceId: string, reason?: string): Promise<void> {
    const instance = this.instances.get(instanceId);
    const interpreter = this.interpreters.get(instanceId);

    if (!instance) {
      throw new Error(`Workflow instance ${instanceId} not found`);
    }

    if (interpreter) {
      interpreter.stop();
    }

    instance.status = 'cancelled';
    instance.completedAt = new Date();
    if (reason) {
      instance.error = {
        nodeId: instance.currentNodeId || 'unknown',
        message: reason,
        timestamp: new Date()
      };
    }

    await this.persistence.updateInstance(instance);
    this.cleanup(instanceId);
    
    this.emit('workflow:cancelled', { instanceId, reason });
  }

  async getWorkflowStatus(instanceId: string): Promise<WorkflowInstance | null> {
    const instance = this.instances.get(instanceId);
    if (instance) {
      return instance;
    }
    return this.persistence.getInstance(instanceId);
  }

  async completeHumanTask(
    instanceId: string,
    taskId: string,
    response: Record<string, any>
  ): Promise<void> {
    const instance = this.instances.get(instanceId);
    const interpreter = this.interpreters.get(instanceId);

    if (!instance || !interpreter) {
      throw new Error(`Workflow instance ${instanceId} not found`);
    }

    const task = instance.humanTasks?.find(t => t.id === taskId);
    if (!task) {
      throw new Error(`Human task ${taskId} not found`);
    }

    if (task.status === 'completed') {
      throw new Error(`Human task ${taskId} already completed`);
    }

    // Update task
    task.status = 'completed';
    task.completedAt = new Date();
    task.response = response;

    // Send event to state machine
    interpreter.send({
      type: 'HUMAN_TASK_COMPLETE',
      taskId,
      response
    });

    await this.persistence.updateInstance(instance);
    this.emit('humanTask:completed', { instanceId, taskId, response });
  }

  private async handleStateTransition(instanceId: string, state: State<any, any>) {
    const instance = this.instances.get(instanceId);
    if (!instance) return;

    // Update current node
    instance.currentNodeId = state.value as string;
    instance.context = state.context;

    // Handle human tasks
    if (state.meta?.humanTask) {
      const humanTask = await this.createHumanTask(
        instanceId,
        instance.currentNodeId,
        state.meta.humanTask
      );
      instance.humanTasks = instance.humanTasks || [];
      instance.humanTasks.push(humanTask);
      instance.status = 'waiting';
    }

    await this.persistence.updateInstance(instance);
    this.emit('workflow:transition', { instanceId, state: state.value });
  }

  private async handleWorkflowComplete(instanceId: string) {
    const instance = this.instances.get(instanceId);
    if (!instance) return;

    instance.status = 'completed';
    instance.completedAt = new Date();

    await this.persistence.updateInstance(instance);
    this.cleanup(instanceId);
    
    this.emit('workflow:completed', { 
      instanceId, 
      outputs: instance.context.outputs 
    });
  }

  private async handleWorkflowStop(instanceId: string) {
    const instance = this.instances.get(instanceId);
    if (!instance) return;

    if (instance.status === 'running') {
      instance.status = 'failed';
      instance.completedAt = new Date();
      await this.persistence.updateInstance(instance);
    }

    this.cleanup(instanceId);
  }

  private initializeVariables(definition: WorkflowDefinition): Record<string, any> {
    const variables: Record<string, any> = {};
    
    if (definition.variables) {
      for (const variable of definition.variables) {
        variables[variable.name] = variable.defaultValue;
      }
    }

    return variables;
  }

  private async createHumanTask(
    instanceId: string,
    nodeId: string,
    config: any
  ): Promise<HumanTask> {
    const task: HumanTask = {
      id: uuidv4(),
      nodeId,
      instanceId,
      title: config.title || 'Manual Task',
      description: config.description,
      assignee: config.assignee,
      inputs: config.inputs || {},
      form: config.form,
      status: 'pending',
      createdAt: new Date()
    };

    await this.persistence.saveHumanTask(task);
    this.emit('humanTask:created', { instanceId, task });

    return task;
  }

  private scheduleSnapshots(instanceId: string) {
    const interval = this.options.snapshotInterval || 60000; // Default 1 minute
    
    const snapshotTimer = setInterval(async () => {
      const instance = this.instances.get(instanceId);
      const interpreter = this.interpreters.get(instanceId);
      
      if (!instance || !interpreter || instance.status !== 'running') {
        clearInterval(snapshotTimer);
        return;
      }

      const state = interpreter.getSnapshot();
      await this.persistence.saveSnapshot({
        instanceId,
        timestamp: new Date(),
        state: instance,
        checksum: this.calculateChecksum(state)
      });
    }, interval);
  }

  private calculateChecksum(state: any): string {
    // Simple checksum implementation - in production use crypto
    return JSON.stringify(state).length.toString();
  }

  private cleanup(instanceId: string) {
    this.instances.delete(instanceId);
    this.interpreters.delete(instanceId);
  }

  async shutdown() {
    // Stop all running workflows
    for (const [instanceId, interpreter] of this.interpreters) {
      interpreter.stop();
      await this.pauseWorkflow(instanceId);
    }
    
    this.removeAllListeners();
  }
}