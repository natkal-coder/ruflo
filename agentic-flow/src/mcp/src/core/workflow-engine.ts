/**
 * Workflow Engine - Workflow creation and execution
 */

import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';
import {
  Workflow,
  WorkflowStep,
  WorkflowStatus,
  WorkflowExecution,
  StepType,
  TriggerType,
  WorkflowTrigger
} from '../types';
import { AgentManager } from './agent-manager';
import { logger } from '../utils/logger';

export class WorkflowEngine extends EventEmitter {
  private workflows: Map<string, Workflow> = new Map();
  private executions: Map<string, WorkflowExecution> = new Map();
  private scheduledTriggers: Map<string, NodeJS.Timeout> = new Map();

  constructor(private agentManager: AgentManager) {
    super();
    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    this.on('workflow:step:complete', this.handleStepComplete.bind(this));
    this.on('workflow:step:error', this.handleStepError.bind(this));
  }

  /**
   * Create a new workflow
   */
  async createWorkflow(
    name: string,
    description: string,
    steps: Omit<WorkflowStep, 'id'>[],
    triggers: WorkflowTrigger[] = []
  ): Promise<Workflow> {
    const workflow: Workflow = {
      id: uuidv4(),
      name,
      description,
      steps: steps.map(step => ({
        ...step,
        id: uuidv4()
      })),
      triggers,
      status: WorkflowStatus.DRAFT,
      createdAt: new Date(),
      executionHistory: []
    };

    // Validate workflow
    this.validateWorkflow(workflow);

    // Save workflow
    this.workflows.set(workflow.id, workflow);

    // Setup triggers
    if (triggers.length > 0) {
      await this.setupTriggers(workflow);
    }

    logger.info(`Workflow created: ${workflow.name} (${workflow.id})`);
    this.emit('workflow:created', workflow);

    return workflow;
  }

  /**
   * Execute a workflow
   */
  async executeWorkflow(
    workflowId: string,
    params: Record<string, any> = {},
    async: boolean = true
  ): Promise<WorkflowExecution> {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${workflowId} not found`);
    }

    const execution: WorkflowExecution = {
      id: uuidv4(),
      workflowId,
      startedAt: new Date(),
      status: WorkflowStatus.ACTIVE,
      results: {}
    };

    this.executions.set(execution.id, execution);
    workflow.executionHistory.push(execution);

    logger.info(`Workflow execution started: ${workflow.name} (${execution.id})`);
    this.emit('workflow:execution:started', execution);

    if (async) {
      // Execute asynchronously
      this.runWorkflowAsync(workflow, execution, params);
      return execution;
    } else {
      // Execute synchronously
      await this.runWorkflow(workflow, execution, params);
      return execution;
    }
  }

  /**
   * Run workflow asynchronously
   */
  private async runWorkflowAsync(
    workflow: Workflow,
    execution: WorkflowExecution,
    params: Record<string, any>
  ): Promise<void> {
    try {
      await this.runWorkflow(workflow, execution, params);
    } catch (error) {
      logger.error(`Workflow execution failed: ${error}`);
      execution.status = WorkflowStatus.FAILED;
      execution.errors = [error as Error];
      this.emit('workflow:execution:failed', { execution, error });
    }
  }

  /**
   * Run workflow
   */
  private async runWorkflow(
    workflow: Workflow,
    execution: WorkflowExecution,
    params: Record<string, any>
  ): Promise<void> {
    const context: WorkflowContext = {
      workflow,
      execution,
      params,
      results: {},
      completedSteps: new Set()
    };

    try {
      // Execute steps
      for (const step of workflow.steps) {
        if (this.canExecuteStep(step, context)) {
          await this.executeStep(step, context);
        }
      }

      // Update execution
      execution.completedAt = new Date();
      execution.status = WorkflowStatus.COMPLETED;
      execution.results = context.results;

      logger.info(`Workflow execution completed: ${workflow.name} (${execution.id})`);
      this.emit('workflow:execution:completed', execution);
    } catch (error) {
      execution.status = WorkflowStatus.FAILED;
      execution.errors = [error as Error];
      throw error;
    }
  }

  /**
   * Execute a workflow step
   */
  private async executeStep(step: WorkflowStep, context: WorkflowContext): Promise<void> {
    logger.debug(`Executing step: ${step.name} (${step.id})`);

    try {
      let result: any;

      switch (step.type) {
        case StepType.AGENT_ACTION:
          result = await this.executeAgentAction(step, context);
          break;
        case StepType.PARALLEL:
          result = await this.executeParallelSteps(step, context);
          break;
        case StepType.SEQUENTIAL:
          result = await this.executeSequentialSteps(step, context);
          break;
        case StepType.CONDITIONAL:
          result = await this.executeConditionalStep(step, context);
          break;
        case StepType.LOOP:
          result = await this.executeLoopStep(step, context);
          break;
        case StepType.WEBHOOK:
          result = await this.executeWebhookStep(step, context);
          break;
        default:
          throw new Error(`Unknown step type: ${step.type}`);
      }

      context.results[step.id] = result;
      context.completedSteps.add(step.id);
      this.emit('workflow:step:complete', { step, result, context });
    } catch (error) {
      this.emit('workflow:step:error', { step, error, context });
      throw error;
    }
  }

  /**
   * Execute agent action step
   */
  private async executeAgentAction(step: WorkflowStep, context: WorkflowContext): Promise<any> {
    const { agentType, capability, action, params } = step.config;

    // Find suitable agent
    const agents = this.agentManager.getAgentsByCapability(capability);
    if (agents.length === 0) {
      throw new Error(`No agents found with capability: ${capability}`);
    }

    // Select agent (could be more sophisticated)
    const agent = agents[0];

    // Send action message to agent
    await this.agentManager.sendMessage({
      id: uuidv4(),
      from: 'workflow-engine',
      to: agent.id,
      type: MessageType.COMMAND,
      content: { action, params },
      timestamp: new Date(),
      priority: Priority.HIGH,
      requiresResponse: true,
      responseTimeout: step.timeout
    });

    // Wait for response (simplified - in real implementation would use proper async handling)
    return { agentId: agent.id, action, status: 'completed' };
  }

  /**
   * Execute parallel steps
   */
  private async executeParallelSteps(step: WorkflowStep, context: WorkflowContext): Promise<any[]> {
    const { steps } = step.config;
    const promises = steps.map((subStep: WorkflowStep) => 
      this.executeStep(subStep, context)
    );

    return Promise.all(promises);
  }

  /**
   * Execute sequential steps
   */
  private async executeSequentialSteps(step: WorkflowStep, context: WorkflowContext): Promise<any[]> {
    const { steps } = step.config;
    const results = [];

    for (const subStep of steps) {
      const result = await this.executeStep(subStep, context);
      results.push(result);
    }

    return results;
  }

  /**
   * Execute conditional step
   */
  private async executeConditionalStep(step: WorkflowStep, context: WorkflowContext): Promise<any> {
    const { condition, ifTrue, ifFalse } = step.config;

    // Evaluate condition
    const conditionResult = this.evaluateCondition(condition, context);

    if (conditionResult) {
      return this.executeStep(ifTrue, context);
    } else if (ifFalse) {
      return this.executeStep(ifFalse, context);
    }

    return null;
  }

  /**
   * Execute loop step
   */
  private async executeLoopStep(step: WorkflowStep, context: WorkflowContext): Promise<any[]> {
    const { items, loopStep } = step.config;
    const results = [];

    for (const item of items) {
      const loopContext = { ...context, loopItem: item };
      const result = await this.executeStep(loopStep, loopContext);
      results.push(result);
    }

    return results;
  }

  /**
   * Execute webhook step
   */
  private async executeWebhookStep(step: WorkflowStep, context: WorkflowContext): Promise<any> {
    const { url, method, headers, body } = step.config;

    // Simulate webhook call
    logger.debug(`Webhook call: ${method} ${url}`);
    return { status: 200, body: { success: true } };
  }

  /**
   * Check if step can be executed
   */
  private canExecuteStep(step: WorkflowStep, context: WorkflowContext): boolean {
    if (!step.dependencies || step.dependencies.length === 0) {
      return true;
    }

    return step.dependencies.every(depId => context.completedSteps.has(depId));
  }

  /**
   * Evaluate condition
   */
  private evaluateCondition(condition: any, context: WorkflowContext): boolean {
    // Simple condition evaluation - could be more sophisticated
    if (typeof condition === 'function') {
      return condition(context);
    }

    return Boolean(condition);
  }

  /**
   * Validate workflow
   */
  private validateWorkflow(workflow: Workflow): void {
    // Check for circular dependencies
    const visited = new Set<string>();
    const recursionStack = new Set<string>();

    for (const step of workflow.steps) {
      if (!visited.has(step.id)) {
        if (this.hasCycle(step, workflow.steps, visited, recursionStack)) {
          throw new Error('Workflow contains circular dependencies');
        }
      }
    }
  }

  /**
   * Check for cycles in workflow
   */
  private hasCycle(
    step: WorkflowStep,
    allSteps: WorkflowStep[],
    visited: Set<string>,
    recursionStack: Set<string>
  ): boolean {
    visited.add(step.id);
    recursionStack.add(step.id);

    if (step.dependencies) {
      for (const depId of step.dependencies) {
        const depStep = allSteps.find(s => s.id === depId);
        if (!depStep) continue;

        if (!visited.has(depId)) {
          if (this.hasCycle(depStep, allSteps, visited, recursionStack)) {
            return true;
          }
        } else if (recursionStack.has(depId)) {
          return true;
        }
      }
    }

    recursionStack.delete(step.id);
    return false;
  }

  /**
   * Setup workflow triggers
   */
  private async setupTriggers(workflow: Workflow): Promise<void> {
    for (const trigger of workflow.triggers) {
      switch (trigger.type) {
        case TriggerType.SCHEDULE:
          this.setupScheduleTrigger(workflow, trigger);
          break;
        case TriggerType.EVENT:
          this.setupEventTrigger(workflow, trigger);
          break;
        case TriggerType.WEBHOOK:
          this.setupWebhookTrigger(workflow, trigger);
          break;
      }
    }
  }

  /**
   * Setup schedule trigger
   */
  private setupScheduleTrigger(workflow: Workflow, trigger: WorkflowTrigger): void {
    const { interval } = trigger.config;
    const timer = setInterval(() => {
      this.executeWorkflow(workflow.id);
    }, interval);

    this.scheduledTriggers.set(`${workflow.id}-schedule`, timer);
  }

  /**
   * Setup event trigger
   */
  private setupEventTrigger(workflow: Workflow, trigger: WorkflowTrigger): void {
    const { event } = trigger.config;
    this.on(event, (data) => {
      this.executeWorkflow(workflow.id, data);
    });
  }

  /**
   * Setup webhook trigger
   */
  private setupWebhookTrigger(workflow: Workflow, trigger: WorkflowTrigger): void {
    // Webhook setup would be implemented here
    logger.debug(`Webhook trigger setup for workflow ${workflow.id}`);
  }

  /**
   * Handle step completion
   */
  private handleStepComplete({ step, result, context }: any): void {
    logger.debug(`Step completed: ${step.name} (${step.id})`);
  }

  /**
   * Handle step error
   */
  private handleStepError({ step, error, context }: any): void {
    logger.error(`Step failed: ${step.name} (${step.id}) - ${error}`);
  }

  /**
   * Get workflow by ID
   */
  getWorkflow(workflowId: string): Workflow | undefined {
    return this.workflows.get(workflowId);
  }

  /**
   * Get all workflows
   */
  getAllWorkflows(): Workflow[] {
    return Array.from(this.workflows.values());
  }

  /**
   * Get execution by ID
   */
  getExecution(executionId: string): WorkflowExecution | undefined {
    return this.executions.get(executionId);
  }

  /**
   * Update workflow status
   */
  updateWorkflowStatus(workflowId: string, status: WorkflowStatus): void {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${workflowId} not found`);
    }

    workflow.status = status;
    this.emit('workflow:status:updated', { workflowId, status });
  }

  /**
   * Delete workflow
   */
  deleteWorkflow(workflowId: string): void {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${workflowId} not found`);
    }

    // Clean up triggers
    const timer = this.scheduledTriggers.get(`${workflowId}-schedule`);
    if (timer) {
      clearInterval(timer);
      this.scheduledTriggers.delete(`${workflowId}-schedule`);
    }

    this.workflows.delete(workflowId);
    this.emit('workflow:deleted', workflowId);
  }
}

interface WorkflowContext {
  workflow: Workflow;
  execution: WorkflowExecution;
  params: Record<string, any>;
  results: Record<string, any>;
  completedSteps: Set<string>;
  loopItem?: any;
}

import { MessageType, Priority } from '../types';