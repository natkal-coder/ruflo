import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { AgentManager } from './agent-manager';
import { logger } from '../cli/utils/logger';

export interface WorkflowStep {
  id: string;
  name: string;
  type: 'agent-task' | 'parallel' | 'conditional' | 'loop' | 'wait' | 'http' | 'script';
  agentId?: string;
  task?: string;
  duration?: number;
  url?: string;
  method?: string;
  condition?: string;
  steps?: WorkflowStep[];
  items?: any[];
  script?: string;
}

export interface Workflow {
  id: string;
  name: string;
  description?: string;
  trigger: {
    type: 'manual' | 'schedule' | 'event' | 'webhook';
    schedule?: string;
    event?: string;
  };
  steps: WorkflowStep[];
  status: 'active' | 'inactive';
  createdAt: string;
  runs: number;
  lastRunAt?: string;
}

export interface WorkflowRun {
  id: string;
  workflowId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: string;
  completedAt?: string;
  duration?: number;
  stepsExecuted: number;
  outputs?: any;
  error?: string;
}

export class WorkflowEngine extends EventEmitter {
  private workflows: Map<string, Workflow> = new Map();
  private activeWorkflows: Set<string> = new Set();
  private runs: Map<string, WorkflowRun> = new Map();
  private agentManager: AgentManager;

  constructor() {
    super();
    this.agentManager = new AgentManager();
  }

  async registerWorkflow(workflow: Workflow): Promise<void> {
    this.workflows.set(workflow.id, workflow);
    
    if (workflow.status === 'active') {
      this.activeWorkflows.add(workflow.id);
      await this.setupTriggers(workflow);
    }
    
    this.emit('workflow:registered', workflow);
    logger.info('Workflow registered', { workflowId: workflow.id, name: workflow.name });
  }

  async unregisterWorkflow(workflowId: string): Promise<void> {
    const workflow = this.workflows.get(workflowId);
    
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    this.workflows.delete(workflowId);
    this.activeWorkflows.delete(workflowId);
    
    this.emit('workflow:unregistered', workflow);
    logger.info('Workflow unregistered', { workflowId, name: workflow.name });
  }

  async runWorkflow(workflow: Workflow, params: any = {}): Promise<any> {
    const run: WorkflowRun = {
      id: uuidv4(),
      workflowId: workflow.id,
      status: 'running',
      startedAt: new Date().toISOString(),
      stepsExecuted: 0,
    };

    this.runs.set(run.id, run);
    this.emit('workflow:started', { workflow, run });
    
    logger.info('Workflow started', { workflowId: workflow.id, runId: run.id });

    try {
      const context = { params, outputs: {} };
      
      for (const step of workflow.steps) {
        await this.executeStep(step, context, run);
        run.stepsExecuted++;
      }

      run.status = 'completed';
      run.completedAt = new Date().toISOString();
      run.duration = Date.now() - new Date(run.startedAt).getTime();
      run.outputs = context.outputs;
      
      this.emit('workflow:completed', { workflow, run });
      logger.info('Workflow completed', { 
        workflowId: workflow.id, 
        runId: run.id, 
        duration: run.duration 
      });

      return {
        success: true,
        runId: run.id,
        duration: run.duration,
        stepsExecuted: run.stepsExecuted,
        outputs: run.outputs,
      };
    } catch (error) {
      run.status = 'failed';
      run.completedAt = new Date().toISOString();
      run.duration = Date.now() - new Date(run.startedAt).getTime();
      run.error = error.message;
      
      this.emit('workflow:failed', { workflow, run, error });
      logger.error('Workflow failed', { 
        workflowId: workflow.id, 
        runId: run.id, 
        error: error.message 
      });

      throw error;
    }
  }

  private async executeStep(
    step: WorkflowStep, 
    context: any, 
    run: WorkflowRun
  ): Promise<any> {
    this.emit('step:started', { step, run });
    logger.info('Executing step', { stepId: step.id, name: step.name, type: step.type });

    try {
      let result: any;

      switch (step.type) {
        case 'agent-task':
          result = await this.executeAgentTask(step, context);
          break;
        
        case 'parallel':
          result = await this.executeParallelSteps(step, context, run);
          break;
        
        case 'conditional':
          result = await this.executeConditionalStep(step, context, run);
          break;
        
        case 'loop':
          result = await this.executeLoopStep(step, context, run);
          break;
        
        case 'wait':
          result = await this.executeWaitStep(step);
          break;
        
        case 'http':
          result = await this.executeHttpStep(step, context);
          break;
        
        case 'script':
          result = await this.executeScriptStep(step, context);
          break;
        
        default:
          throw new Error(`Unknown step type: ${step.type}`);
      }

      context.outputs[step.id] = result;
      this.emit('step:completed', { step, run, result });
      
      return result;
    } catch (error) {
      this.emit('step:failed', { step, run, error });
      throw error;
    }
  }

  private async executeAgentTask(step: WorkflowStep, context: any): Promise<any> {
    if (!step.agentId || !step.task) {
      throw new Error('Agent task step requires agentId and task');
    }

    // Simulate agent task execution
    return {
      success: true,
      agentId: step.agentId,
      task: step.task,
      result: `Task "${step.task}" completed by agent ${step.agentId}`,
    };
  }

  private async executeParallelSteps(
    step: WorkflowStep, 
    context: any, 
    run: WorkflowRun
  ): Promise<any> {
    if (!step.steps || step.steps.length === 0) {
      throw new Error('Parallel step requires child steps');
    }

    const promises = step.steps.map(childStep => 
      this.executeStep(childStep, context, run)
    );

    const results = await Promise.all(promises);
    return { results };
  }

  private async executeConditionalStep(
    step: WorkflowStep, 
    context: any, 
    run: WorkflowRun
  ): Promise<any> {
    if (!step.condition) {
      throw new Error('Conditional step requires a condition');
    }

    // Simple condition evaluation (in real implementation, use a safe evaluator)
    const conditionMet = this.evaluateCondition(step.condition, context);

    if (conditionMet && step.steps && step.steps.length > 0) {
      const results = [];
      for (const childStep of step.steps) {
        results.push(await this.executeStep(childStep, context, run));
      }
      return { conditionMet: true, results };
    }

    return { conditionMet: false };
  }

  private async executeLoopStep(
    step: WorkflowStep, 
    context: any, 
    run: WorkflowRun
  ): Promise<any> {
    if (!step.items || !step.steps) {
      throw new Error('Loop step requires items and child steps');
    }

    const results = [];
    for (const item of step.items) {
      const loopContext = { ...context, loopItem: item };
      for (const childStep of step.steps) {
        results.push(await this.executeStep(childStep, loopContext, run));
      }
    }

    return { results };
  }

  private async executeWaitStep(step: WorkflowStep): Promise<any> {
    const duration = step.duration || 5;
    await new Promise(resolve => setTimeout(resolve, duration * 1000));
    return { waited: duration };
  }

  private async executeHttpStep(step: WorkflowStep, context: any): Promise<any> {
    if (!step.url) {
      throw new Error('HTTP step requires a URL');
    }

    try {
      const response = await axios({
        method: step.method || 'GET',
        url: step.url,
        data: context.params,
      });

      return {
        status: response.status,
        data: response.data,
      };
    } catch (error) {
      throw new Error(`HTTP request failed: ${error.message}`);
    }
  }

  private async executeScriptStep(step: WorkflowStep, context: any): Promise<any> {
    if (!step.script) {
      throw new Error('Script step requires a script');
    }

    // In a real implementation, use a sandboxed script executor
    return {
      success: true,
      script: step.script,
      message: 'Script execution simulated',
    };
  }

  private evaluateCondition(condition: string, context: any): boolean {
    // Simple condition evaluation - in production, use a safe expression evaluator
    // This is just for demonstration
    if (condition.includes('params.')) {
      const paramName = condition.split('params.')[1].split(' ')[0];
      return context.params[paramName] !== undefined;
    }
    
    return false;
  }

  private async setupTriggers(workflow: Workflow): Promise<void> {
    switch (workflow.trigger.type) {
      case 'schedule':
        // In a real implementation, set up cron job
        logger.info('Schedule trigger setup', { 
          workflowId: workflow.id, 
          schedule: workflow.trigger.schedule 
        });
        break;
      
      case 'event':
        // In a real implementation, set up event listener
        logger.info('Event trigger setup', { 
          workflowId: workflow.id, 
          event: workflow.trigger.event 
        });
        break;
      
      case 'webhook':
        // In a real implementation, register webhook endpoint
        logger.info('Webhook trigger setup', { workflowId: workflow.id });
        break;
    }
  }

  getWorkflow(workflowId: string): Workflow | undefined {
    return this.workflows.get(workflowId);
  }

  getAllWorkflows(): Workflow[] {
    return Array.from(this.workflows.values());
  }

  getActiveWorkflows(): Workflow[] {
    return Array.from(this.activeWorkflows)
      .map(id => this.workflows.get(id))
      .filter((workflow): workflow is Workflow => workflow !== undefined);
  }

  getWorkflowRun(runId: string): WorkflowRun | undefined {
    return this.runs.get(runId);
  }
}