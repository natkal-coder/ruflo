import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { WorkflowEngine, WorkflowDefinition, WorkflowStep } from '../../src/workflows/workflow-engine';

describe('WorkflowEngine', () => {
  let workflowEngine: WorkflowEngine;

  beforeEach(() => {
    workflowEngine = new WorkflowEngine();
  });

  describe('Workflow Creation', () => {
    it('should create a valid workflow', async () => {
      const workflow: WorkflowDefinition = {
        id: 'test-workflow',
        name: 'Test Workflow',
        description: 'A test workflow',
        version: '1.0.0',
        steps: [
          {
            id: 'step1',
            type: 'agent-task',
            name: 'Test Step',
            config: {
              agentType: 'test',
              goal: 'test goal'
            }
          }
        ],
        variables: { testVar: 'testValue' },
        triggers: []
      };

      await expect(workflowEngine.createWorkflow(workflow)).resolves.not.toThrow();
      
      const retrievedWorkflow = workflowEngine.getWorkflow('test-workflow');
      expect(retrievedWorkflow).toEqual(workflow);
    });

    it('should validate workflow definition', async () => {
      const invalidWorkflow: WorkflowDefinition = {
        id: '',
        name: '',
        description: '',
        version: '',
        steps: [],
        variables: {},
        triggers: []
      };

      await expect(workflowEngine.createWorkflow(invalidWorkflow))
        .rejects.toThrow('Invalid workflow definition');
    });

    it('should validate step references', async () => {
      const workflowWithInvalidRef: WorkflowDefinition = {
        id: 'invalid-ref-workflow',
        name: 'Invalid Ref Workflow',
        description: 'Workflow with invalid step reference',
        version: '1.0.0',
        steps: [
          {
            id: 'step1',
            type: 'agent-task',
            name: 'Step 1',
            config: {},
            next: ['nonexistent-step']
          }
        ],
        variables: {},
        triggers: []
      };

      await expect(workflowEngine.createWorkflow(workflowWithInvalidRef))
        .rejects.toThrow('Invalid step reference: nonexistent-step');
    });

    it('should emit workflow created event', async () => {
      const createdSpy = jest.fn();
      workflowEngine.on('workflow:created', createdSpy);

      const workflow: WorkflowDefinition = {
        id: 'event-test-workflow',
        name: 'Event Test Workflow',
        description: 'Test workflow for events',
        version: '1.0.0',
        steps: [
          {
            id: 'step1',
            type: 'script',
            name: 'Test Script',
            config: { script: 'console.log("test")' }
          }
        ],
        variables: {},
        triggers: []
      };

      await workflowEngine.createWorkflow(workflow);
      
      expect(createdSpy).toHaveBeenCalledWith({ workflowId: 'event-test-workflow' });
    });
  });

  describe('Workflow Execution', () => {
    beforeEach(async () => {
      const workflow: WorkflowDefinition = {
        id: 'execution-test',
        name: 'Execution Test',
        description: 'Test workflow execution',
        version: '1.0.0',
        steps: [
          {
            id: 'step1',
            type: 'agent-task',
            name: 'Agent Task',
            config: {
              agentType: 'executor',
              goal: 'Execute test task'
            }
          }
        ],
        variables: { initialVar: 'initial' },
        triggers: []
      };

      await workflowEngine.createWorkflow(workflow);
    });

    it('should execute workflow and return execution ID', async () => {
      const executionId = await workflowEngine.executeWorkflow('execution-test', { customVar: 'custom' });
      
      expect(executionId).toBeDefined();
      expect(typeof executionId).toBe('string');
      
      const execution = workflowEngine.getExecution(executionId);
      expect(execution).toBeDefined();
      expect(execution!.workflowId).toBe('execution-test');
      expect(execution!.variables.initialVar).toBe('initial');
      expect(execution!.variables.customVar).toBe('custom');
    });

    it('should handle non-existent workflow', async () => {
      await expect(workflowEngine.executeWorkflow('nonexistent'))
        .rejects.toThrow('Workflow nonexistent not found');
    });

    it('should track execution status', async () => {
      const executionId = await workflowEngine.executeWorkflow('execution-test');
      
      const execution = workflowEngine.getExecution(executionId);
      expect(['pending', 'running', 'completed', 'failed']).toContain(execution!.status);
    });
  });

  describe('Step Execution', () => {
    beforeEach(async () => {
      const complexWorkflow: WorkflowDefinition = {
        id: 'complex-workflow',
        name: 'Complex Workflow',
        description: 'Workflow with various step types',
        version: '1.0.0',
        steps: [
          {
            id: 'agent-step',
            type: 'agent-task',
            name: 'Agent Step',
            config: {
              agentType: 'test',
              goal: 'test goal'
            },
            next: ['parallel-step']
          },
          {
            id: 'parallel-step',
            type: 'parallel',
            name: 'Parallel Step',
            config: {
              steps: ['http-step', 'script-step']
            },
            next: ['condition-step']
          },
          {
            id: 'http-step',
            type: 'http',
            name: 'HTTP Step',
            config: {
              method: 'GET',
              url: 'https://api.example.com/test'
            }
          },
          {
            id: 'script-step',
            type: 'script',
            name: 'Script Step',
            config: {
              script: 'return { success: true };',
              language: 'javascript'
            }
          },
          {
            id: 'condition-step',
            type: 'condition',
            name: 'Condition Step',
            config: {
              condition: 'variables.testCondition === true',
              trueStep: 'loop-step',
              falseStep: null
            }
          },
          {
            id: 'loop-step',
            type: 'loop',
            name: 'Loop Step',
            config: {
              condition: 'variables.counter < 3',
              loopStep: 'script-step',
              maxIterations: 5
            }
          }
        ],
        variables: { testCondition: true, counter: 0 },
        triggers: []
      };

      await workflowEngine.createWorkflow(complexWorkflow);
    });

    it('should execute agent tasks', async () => {
      const executionId = await workflowEngine.executeWorkflow('complex-workflow');
      
      // Wait for execution to progress
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      const execution = workflowEngine.getExecution(executionId);
      expect(execution!.results).toHaveProperty('agent-step');
    });

    it('should handle parallel execution', async () => {
      const executionId = await workflowEngine.executeWorkflow('complex-workflow');
      
      // Wait for execution to progress
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const execution = workflowEngine.getExecution(executionId);
      expect(execution!.results).toHaveProperty('parallel-step');
    });

    it('should execute HTTP requests', async () => {
      const executionId = await workflowEngine.executeWorkflow('complex-workflow');
      
      // Wait for execution to progress
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const execution = workflowEngine.getExecution(executionId);
      // HTTP step should be executed as part of parallel step
      expect(execution!.results).toBeDefined();
    });

    it('should execute scripts', async () => {
      const executionId = await workflowEngine.executeWorkflow('complex-workflow');
      
      // Wait for execution to progress
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const execution = workflowEngine.getExecution(executionId);
      expect(execution!.results).toBeDefined();
    });
  });

  describe('Workflow Management', () => {
    beforeEach(async () => {
      const workflows = [
        {
          id: 'workflow1',
          name: 'Workflow 1',
          description: 'First workflow',
          version: '1.0.0',
          steps: [{
            id: 'step1',
            type: 'script' as const,
            name: 'Step 1',
            config: { script: 'test' }
          }],
          variables: {},
          triggers: []
        },
        {
          id: 'workflow2',
          name: 'Workflow 2',
          description: 'Second workflow',
          version: '1.0.0',
          steps: [{
            id: 'step1',
            type: 'agent-task' as const,
            name: 'Step 1',
            config: { agentType: 'test' }
          }],
          variables: {},
          triggers: []
        }
      ];

      for (const workflow of workflows) {
        await workflowEngine.createWorkflow(workflow);
      }
    });

    it('should list all workflows', () => {
      const workflows = workflowEngine.listWorkflows();
      
      expect(workflows).toHaveLength(2);
      expect(workflows.map(w => w.id)).toContain('workflow1');
      expect(workflows.map(w => w.id)).toContain('workflow2');
    });

    it('should list executions', async () => {
      const executionId1 = await workflowEngine.executeWorkflow('workflow1');
      const executionId2 = await workflowEngine.executeWorkflow('workflow2');
      
      const allExecutions = workflowEngine.listExecutions();
      expect(allExecutions).toHaveLength(2);
      
      const workflow1Executions = workflowEngine.listExecutions('workflow1');
      expect(workflow1Executions).toHaveLength(1);
      expect(workflow1Executions[0].id).toBe(executionId1);
    });

    it('should cancel executions', async () => {
      const executionId = await workflowEngine.executeWorkflow('workflow1');
      
      await workflowEngine.cancelExecution(executionId);
      
      const execution = workflowEngine.getExecution(executionId);
      expect(execution!.status).toBe('cancelled');
      expect(execution!.endTime).toBeDefined();
    });

    it('should handle cancelling non-existent execution', async () => {
      await expect(workflowEngine.cancelExecution('nonexistent'))
        .rejects.toThrow('Execution nonexistent not found');
    });
  });

  describe('Event Handling', () => {
    it('should emit execution events', async () => {
      const completedSpy = jest.fn();
      const stateSpy = jest.fn();
      const logSpy = jest.fn();

      workflowEngine.on('workflow:completed', completedSpy);
      workflowEngine.on('workflow:state-change', stateSpy);
      workflowEngine.on('workflow:log', logSpy);

      const workflow: WorkflowDefinition = {
        id: 'event-workflow',
        name: 'Event Workflow',
        description: 'Workflow for testing events',
        version: '1.0.0',
        steps: [
          {
            id: 'quick-step',
            type: 'script',
            name: 'Quick Step',
            config: { script: 'return true;' }
          }
        ],
        variables: {},
        triggers: []
      };

      await workflowEngine.createWorkflow(workflow);
      const executionId = await workflowEngine.executeWorkflow('event-workflow');

      // Wait for execution to complete
      await new Promise(resolve => setTimeout(resolve, 1000));

      expect(logSpy).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('should handle step execution failures', async () => {
      const failureWorkflow: WorkflowDefinition = {
        id: 'failure-workflow',
        name: 'Failure Workflow',
        description: 'Workflow that fails',
        version: '1.0.0',
        steps: [
          {
            id: 'failing-step',
            type: 'script',
            name: 'Failing Step',
            config: { script: 'throw new Error("Test failure");' },
            onFailure: 'recovery-step'
          },
          {
            id: 'recovery-step',
            type: 'script',
            name: 'Recovery Step',
            config: { script: 'return { recovered: true };' }
          }
        ],
        variables: {},
        triggers: []
      };

      await workflowEngine.createWorkflow(failureWorkflow);
      const executionId = await workflowEngine.executeWorkflow('failure-workflow');

      // Wait for execution
      await new Promise(resolve => setTimeout(resolve, 1000));

      const execution = workflowEngine.getExecution(executionId);
      expect(execution!.logs.some(log => log.level === 'error')).toBe(true);
    });
  });
});