import { EventEmitter } from 'events';
import { createMachine, interpret, State } from 'xstate';
import { v4 as uuidv4 } from 'uuid';

export interface WorkflowStep {
  id: string;
  type: 'agent-task' | 'parallel' | 'condition' | 'loop' | 'http' | 'script';
  name: string;
  config: any;
  next?: string[];
  onSuccess?: string;
  onFailure?: string;
}

export interface WorkflowDefinition {
  id: string;
  name: string;
  description: string;
  version: string;
  steps: WorkflowStep[];
  variables: Record<string, any>;
  triggers: WorkflowTrigger[];
}

export interface WorkflowTrigger {
  type: 'manual' | 'scheduled' | 'event' | 'webhook';
  config: any;
}

export interface WorkflowExecution {
  id: string;
  workflowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startTime: Date;
  endTime?: Date;
  currentStep?: string;
  variables: Record<string, any>;
  results: Record<string, any>;
  logs: WorkflowLog[];
}

export interface WorkflowLog {
  timestamp: Date;
  level: 'info' | 'warn' | 'error';
  message: string;
  stepId?: string;
  data?: any;
}

export class WorkflowEngine extends EventEmitter {
  private workflows: Map<string, WorkflowDefinition> = new Map();
  private executions: Map<string, WorkflowExecution> = new Map();
  private machines: Map<string, any> = new Map();

  constructor() {
    super();
  }

  async createWorkflow(definition: WorkflowDefinition): Promise<void> {
    // Validate workflow definition
    this.validateWorkflow(definition);
    
    // Create XState machine
    const machine = this.createStateMachine(definition);
    
    // Store workflow and machine
    this.workflows.set(definition.id, definition);
    this.machines.set(definition.id, machine);
    
    this.emit('workflow:created', { workflowId: definition.id });
  }

  async executeWorkflow(workflowId: string, variables: Record<string, any> = {}): Promise<string> {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${workflowId} not found`);
    }

    const executionId = uuidv4();
    const execution: WorkflowExecution = {
      id: executionId,
      workflowId,
      status: 'pending',
      startTime: new Date(),
      variables: { ...workflow.variables, ...variables },
      results: {},
      logs: []
    };

    this.executions.set(executionId, execution);
    
    // Start execution
    this.startExecution(execution);
    
    return executionId;
  }

  private async startExecution(execution: WorkflowExecution): Promise<void> {
    const workflow = this.workflows.get(execution.workflowId)!;
    const machine = this.machines.get(execution.workflowId)!;
    
    execution.status = 'running';
    this.logExecution(execution, 'info', `Starting workflow execution`);
    
    try {
      const service = interpret(machine).onTransition((state) => {
        this.handleStateTransition(execution, state);
      });
      
      service.start();
      
      // Execute first step
      const firstStep = workflow.steps[0];
      if (firstStep) {
        await this.executeStep(execution, firstStep);
      }
      
    } catch (error) {
      execution.status = 'failed';
      execution.endTime = new Date();
      this.logExecution(execution, 'error', `Workflow failed: ${error.message}`);
      this.emit('workflow:failed', { executionId: execution.id, error });
    }
  }

  private async executeStep(execution: WorkflowExecution, step: WorkflowStep): Promise<void> {
    execution.currentStep = step.id;
    this.logExecution(execution, 'info', `Executing step: ${step.name}`, step.id);
    
    try {
      let result: any;
      
      switch (step.type) {
        case 'agent-task':
          result = await this.executeAgentTask(execution, step);
          break;
        case 'parallel':
          result = await this.executeParallel(execution, step);
          break;
        case 'condition':
          result = await this.executeCondition(execution, step);
          break;
        case 'loop':
          result = await this.executeLoop(execution, step);
          break;
        case 'http':
          result = await this.executeHttpRequest(execution, step);
          break;
        case 'script':
          result = await this.executeScript(execution, step);
          break;
        default:
          throw new Error(`Unknown step type: ${step.type}`);
      }
      
      execution.results[step.id] = result;
      this.logExecution(execution, 'info', `Step completed: ${step.name}`, step.id);
      
      // Execute next steps
      await this.executeNextSteps(execution, step, result);
      
    } catch (error) {
      this.logExecution(execution, 'error', `Step failed: ${error.message}`, step.id);
      
      if (step.onFailure) {
        await this.executeNextStep(execution, step.onFailure);
      } else {
        throw error;
      }
    }
  }

  private async executeAgentTask(execution: WorkflowExecution, step: WorkflowStep): Promise<any> {
    const { agentType, goal, provider } = step.config;
    
    // This would integrate with the agent system
    // For now, simulate agent execution
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          agentType,
          goal,
          result: `Agent task completed: ${goal}`,
          timestamp: new Date()
        });
      }, 1000);
    });
  }

  private async executeParallel(execution: WorkflowExecution, step: WorkflowStep): Promise<any> {
    const { steps: parallelSteps } = step.config;
    const workflow = this.workflows.get(execution.workflowId)!;
    
    const promises = parallelSteps.map((stepId: string) => {
      const parallelStep = workflow.steps.find(s => s.id === stepId);
      if (!parallelStep) {
        throw new Error(`Step ${stepId} not found for parallel execution`);
      }
      return this.executeStep(execution, parallelStep);
    });
    
    return Promise.all(promises);
  }

  private async executeCondition(execution: WorkflowExecution, step: WorkflowStep): Promise<any> {
    const { condition, trueStep, falseStep } = step.config;
    
    // Evaluate condition against execution variables and results
    const conditionResult = this.evaluateCondition(condition, execution);
    
    const nextStepId = conditionResult ? trueStep : falseStep;
    if (nextStepId) {
      await this.executeNextStep(execution, nextStepId);
    }
    
    return { condition, result: conditionResult, nextStep: nextStepId };
  }

  private async executeLoop(execution: WorkflowExecution, step: WorkflowStep): Promise<any> {
    const { condition, loopStep, maxIterations = 10 } = step.config;
    const results = [];
    let iterations = 0;
    
    while (this.evaluateCondition(condition, execution) && iterations < maxIterations) {
      const result = await this.executeNextStep(execution, loopStep);
      results.push(result);
      iterations++;
    }
    
    return { iterations, results };
  }

  private async executeHttpRequest(execution: WorkflowExecution, step: WorkflowStep): Promise<any> {
    const { method, url, headers, body } = step.config;
    
    // This would make actual HTTP requests
    // For now, simulate HTTP request
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          status: 200,
          data: { message: `HTTP ${method} to ${url} completed` },
          timestamp: new Date()
        });
      }, 500);
    });
  }

  private async executeScript(execution: WorkflowExecution, step: WorkflowStep): Promise<any> {
    const { script, language = 'javascript' } = step.config;
    
    // This would execute scripts in a sandboxed environment
    // For now, simulate script execution
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          language,
          script: script.substring(0, 100) + '...',
          result: 'Script executed successfully',
          timestamp: new Date()
        });
      }, 300);
    });
  }

  private async executeNextSteps(execution: WorkflowExecution, step: WorkflowStep, result: any): Promise<void> {
    if (step.next) {
      for (const nextStepId of step.next) {
        await this.executeNextStep(execution, nextStepId);
      }
    } else if (step.onSuccess) {
      await this.executeNextStep(execution, step.onSuccess);
    } else {
      // No more steps, complete workflow
      execution.status = 'completed';
      execution.endTime = new Date();
      this.logExecution(execution, 'info', 'Workflow completed successfully');
      this.emit('workflow:completed', { executionId: execution.id });
    }
  }

  private async executeNextStep(execution: WorkflowExecution, stepId: string): Promise<any> {
    const workflow = this.workflows.get(execution.workflowId)!;
    const nextStep = workflow.steps.find(s => s.id === stepId);
    
    if (!nextStep) {
      throw new Error(`Next step ${stepId} not found`);
    }
    
    return this.executeStep(execution, nextStep);
  }

  private evaluateCondition(condition: string, execution: WorkflowExecution): boolean {
    // Simple condition evaluation
    // In a real implementation, this would use a proper expression evaluator
    const context = {
      variables: execution.variables,
      results: execution.results
    };
    
    try {
      // This is a simplified evaluation - use a proper expression parser in production
      return new Function('context', `with(context) { return ${condition}; }`)(context);
    } catch (error) {
      this.logExecution(execution, 'warn', `Condition evaluation failed: ${error.message}`);
      return false;
    }
  }

  private createStateMachine(workflow: WorkflowDefinition): any {
    const states: any = {};
    
    workflow.steps.forEach(step => {
      states[step.id] = {
        on: {
          COMPLETE: step.next ? step.next[0] : 'completed',
          FAIL: step.onFailure || 'failed'
        }
      };
    });
    
    states.completed = { type: 'final' };
    states.failed = { type: 'final' };
    
    return createMachine({
      id: workflow.id,
      initial: workflow.steps[0]?.id || 'completed',
      states
    });
  }

  private handleStateTransition(execution: WorkflowExecution, state: State<any>): void {
    this.logExecution(execution, 'info', `State transition: ${state.value}`);
    this.emit('workflow:state-change', { 
      executionId: execution.id, 
      state: state.value 
    });
  }

  private validateWorkflow(workflow: WorkflowDefinition): void {
    if (!workflow.id || !workflow.name || !workflow.steps.length) {
      throw new Error('Invalid workflow definition');
    }
    
    // Validate step references
    const stepIds = new Set(workflow.steps.map(s => s.id));
    workflow.steps.forEach(step => {
      if (step.next) {
        step.next.forEach(nextId => {
          if (!stepIds.has(nextId)) {
            throw new Error(`Invalid step reference: ${nextId}`);
          }
        });
      }
    });
  }

  private logExecution(execution: WorkflowExecution, level: 'info' | 'warn' | 'error', message: string, stepId?: string): void {
    const log: WorkflowLog = {
      timestamp: new Date(),
      level,
      message,
      stepId
    };
    
    execution.logs.push(log);
    this.emit('workflow:log', { executionId: execution.id, log });
  }

  // Public API methods
  getWorkflow(id: string): WorkflowDefinition | undefined {
    return this.workflows.get(id);
  }

  getExecution(id: string): WorkflowExecution | undefined {
    return this.executions.get(id);
  }

  listWorkflows(): WorkflowDefinition[] {
    return Array.from(this.workflows.values());
  }

  listExecutions(workflowId?: string): WorkflowExecution[] {
    const executions = Array.from(this.executions.values());
    return workflowId ? executions.filter(e => e.workflowId === workflowId) : executions;
  }

  async cancelExecution(executionId: string): Promise<void> {
    const execution = this.executions.get(executionId);
    if (!execution) {
      throw new Error(`Execution ${executionId} not found`);
    }
    
    execution.status = 'cancelled';
    execution.endTime = new Date();
    this.logExecution(execution, 'info', 'Execution cancelled');
    this.emit('workflow:cancelled', { executionId });
  }
}