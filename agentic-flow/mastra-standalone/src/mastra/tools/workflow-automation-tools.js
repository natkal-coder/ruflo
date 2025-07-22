import { createTool } from '@mastra/core';
import { z } from 'zod';

// In-memory storage for workflows, pipelines, and automation rules
const workflowStore = new Map();
const pipelineStore = new Map();
const automationRules = new Map();
const eventTriggers = new Map();
const workflowTemplates = new Map();
const executionHistory = new Map();
const scheduledJobs = new Map();

// Helper functions for workflow execution
const executeWorkflowStep = async (step, context) => {
  const { type, action, params } = step;
  const startTime = Date.now();
  
  try {
    let result;
    switch (type) {
      case 'script':
        result = await eval(`(async () => { ${action} })()`);
        break;
      case 'condition':
        result = await eval(`(${action})`);
        break;
      case 'parallel':
        result = await Promise.all(
          step.tasks.map(task => executeWorkflowStep(task, context))
        );
        break;
      case 'sequential':
        result = [];
        for (const task of step.tasks) {
          result.push(await executeWorkflowStep(task, context));
        }
        break;
      default:
        result = { type, action, params };
    }
    
    return {
      stepId: step.id,
      status: 'completed',
      result,
      duration: Date.now() - startTime
    };
  } catch (error) {
    return {
      stepId: step.id,
      status: 'failed',
      error: error.message,
      duration: Date.now() - startTime
    };
  }
};

const validateWorkflowDAG = (steps) => {
  const graph = new Map();
  steps.forEach(step => {
    graph.set(step.id, step.dependencies || []);
  });
  
  const visited = new Set();
  const visiting = new Set();
  
  const hasCycle = (node) => {
    if (visiting.has(node)) return true;
    if (visited.has(node)) return false;
    
    visiting.add(node);
    const deps = graph.get(node) || [];
    for (const dep of deps) {
      if (hasCycle(dep)) return true;
    }
    visiting.delete(node);
    visited.add(node);
    return false;
  };
  
  for (const node of graph.keys()) {
    if (hasCycle(node)) {
      throw new Error('Workflow contains circular dependencies');
    }
  }
  
  return true;
};

// Tool: Create custom workflows
export const workflowCreate = createTool({
  name: 'workflowCreate',
  description: 'Create custom workflows with steps and dependencies',
  inputSchema: z.object({
    name: z.string().describe('Workflow name'),
    description: z.string().optional().describe('Workflow description'),
    steps: z.array(z.object({
      id: z.string().describe('Step identifier'),
      name: z.string().describe('Step name'),
      type: z.enum(['script', 'condition', 'parallel', 'sequential']).describe('Step type'),
      action: z.string().optional().describe('Action to execute'),
      params: z.record(z.any()).optional().describe('Step parameters'),
      dependencies: z.array(z.string()).optional().describe('Step dependencies'),
      tasks: z.array(z.any()).optional().describe('Sub-tasks for parallel/sequential steps')
    })).describe('Workflow steps'),
    triggers: z.array(z.object({
      type: z.enum(['manual', 'schedule', 'event', 'webhook']).describe('Trigger type'),
      config: z.record(z.any()).describe('Trigger configuration')
    })).optional().describe('Workflow triggers'),
    config: z.object({
      timeout: z.number().optional().describe('Workflow timeout in milliseconds'),
      retries: z.number().optional().describe('Number of retries on failure'),
      notifications: z.boolean().optional().describe('Enable notifications')
    }).optional().describe('Workflow configuration')
  }),
  execute: async ({ name, description, steps, triggers = [], config = {} }) => {
    try {
      // Validate workflow DAG
      validateWorkflowDAG(steps);
      
      const workflowId = `wf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const workflow = {
        id: workflowId,
        name,
        description,
        steps,
        triggers,
        config: {
          timeout: config.timeout || 3600000, // 1 hour default
          retries: config.retries || 0,
          notifications: config.notifications || false
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        version: 1,
        status: 'active'
      };
      
      workflowStore.set(workflowId, workflow);
      
      // Setup triggers if specified
      if (triggers.length > 0) {
        triggers.forEach(trigger => {
          if (trigger.type === 'schedule') {
            // Setup scheduled execution
            const jobId = `job_${workflowId}_${Date.now()}`;
            scheduledJobs.set(jobId, {
              workflowId,
              schedule: trigger.config.cron,
              nextRun: trigger.config.nextRun
            });
          } else if (trigger.type === 'event') {
            // Register event trigger
            const eventName = trigger.config.eventName;
            if (!eventTriggers.has(eventName)) {
              eventTriggers.set(eventName, []);
            }
            eventTriggers.get(eventName).push(workflowId);
          }
        });
      }
      
      return {
        success: true,
        workflowId,
        workflow,
        message: `Workflow '${name}' created successfully`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Execute workflows with parameters
export const workflowExecute = createTool({
  name: 'workflowExecute',
  description: 'Execute workflows with parameters and track execution',
  inputSchema: z.object({
    workflowId: z.string().describe('Workflow ID to execute'),
    params: z.record(z.any()).optional().describe('Execution parameters'),
    mode: z.enum(['sync', 'async']).optional().describe('Execution mode'),
    context: z.record(z.any()).optional().describe('Execution context')
  }),
  execute: async ({ workflowId, params = {}, mode = 'sync', context = {} }) => {
    try {
      const workflow = workflowStore.get(workflowId);
      if (!workflow) {
        throw new Error(`Workflow ${workflowId} not found`);
      }
      
      const executionId = `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const execution = {
        id: executionId,
        workflowId,
        params,
        context,
        startTime: new Date().toISOString(),
        status: 'running',
        steps: []
      };
      
      executionHistory.set(executionId, execution);
      
      // Execute workflow based on mode
      const executeWorkflow = async () => {
        const results = [];
        const stepResults = new Map();
        
        // Execute steps based on dependencies
        const executeStep = async (step) => {
          // Check if dependencies are completed
          if (step.dependencies) {
            for (const dep of step.dependencies) {
              const depResult = stepResults.get(dep);
              if (!depResult || depResult.status !== 'completed') {
                throw new Error(`Dependency ${dep} not satisfied`);
              }
            }
          }
          
          const result = await executeWorkflowStep(step, { params, context, results: stepResults });
          stepResults.set(step.id, result);
          results.push(result);
          return result;
        };
        
        // Execute steps in dependency order
        const executed = new Set();
        while (executed.size < workflow.steps.length) {
          const readySteps = workflow.steps.filter(step => {
            if (executed.has(step.id)) return false;
            if (!step.dependencies) return true;
            return step.dependencies.every(dep => executed.has(dep));
          });
          
          if (readySteps.length === 0) {
            throw new Error('No executable steps found - possible circular dependency');
          }
          
          // Execute ready steps in parallel
          await Promise.all(readySteps.map(async step => {
            await executeStep(step);
            executed.add(step.id);
          }));
        }
        
        execution.steps = results;
        execution.endTime = new Date().toISOString();
        execution.status = results.every(r => r.status === 'completed') ? 'completed' : 'failed';
        execution.duration = Date.now() - Date.parse(execution.startTime);
        
        return execution;
      };
      
      if (mode === 'async') {
        executeWorkflow().catch(error => {
          execution.status = 'failed';
          execution.error = error.message;
          execution.endTime = new Date().toISOString();
        });
        
        return {
          success: true,
          executionId,
          status: 'started',
          message: 'Workflow execution started asynchronously'
        };
      } else {
        const result = await executeWorkflow();
        return {
          success: true,
          executionId,
          execution: result,
          summary: {
            totalSteps: result.steps.length,
            completedSteps: result.steps.filter(s => s.status === 'completed').length,
            failedSteps: result.steps.filter(s => s.status === 'failed').length,
            duration: result.duration
          }
        };
      }
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Schedule workflow execution
export const workflowSchedule = createTool({
  name: 'workflowSchedule',
  description: 'Schedule workflow execution with cron expressions or specific times',
  inputSchema: z.object({
    workflowId: z.string().describe('Workflow ID to schedule'),
    schedule: z.object({
      type: z.enum(['cron', 'once', 'interval']).describe('Schedule type'),
      expression: z.string().optional().describe('Cron expression for cron type'),
      at: z.string().optional().describe('ISO date for once type'),
      interval: z.number().optional().describe('Interval in milliseconds'),
      timezone: z.string().optional().describe('Timezone for scheduling')
    }).describe('Schedule configuration'),
    params: z.record(z.any()).optional().describe('Default parameters for execution'),
    enabled: z.boolean().optional().describe('Enable/disable schedule')
  }),
  execute: async ({ workflowId, schedule, params = {}, enabled = true }) => {
    try {
      const workflow = workflowStore.get(workflowId);
      if (!workflow) {
        throw new Error(`Workflow ${workflowId} not found`);
      }
      
      const scheduleId = `sched_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const scheduledJob = {
        id: scheduleId,
        workflowId,
        schedule,
        params,
        enabled,
        createdAt: new Date().toISOString(),
        lastRun: null,
        nextRun: null,
        runCount: 0
      };
      
      // Calculate next run time based on schedule type
      if (schedule.type === 'once' && schedule.at) {
        scheduledJob.nextRun = schedule.at;
      } else if (schedule.type === 'interval' && schedule.interval) {
        scheduledJob.nextRun = new Date(Date.now() + schedule.interval).toISOString();
      } else if (schedule.type === 'cron' && schedule.expression) {
        // Simple cron parser (would use a library in production)
        scheduledJob.nextRun = new Date(Date.now() + 60000).toISOString(); // Next minute for demo
      }
      
      scheduledJobs.set(scheduleId, scheduledJob);
      
      return {
        success: true,
        scheduleId,
        schedule: scheduledJob,
        message: `Workflow scheduled successfully`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Create CI/CD pipelines
export const pipelineCreate = createTool({
  name: 'pipelineCreate',
  description: 'Create CI/CD pipelines with stages and jobs',
  inputSchema: z.object({
    name: z.string().describe('Pipeline name'),
    config: z.object({
      trigger: z.object({
        branches: z.array(z.string()).optional().describe('Trigger branches'),
        events: z.array(z.string()).optional().describe('Trigger events'),
        paths: z.array(z.string()).optional().describe('Trigger paths')
      }).optional().describe('Pipeline triggers'),
      stages: z.array(z.object({
        name: z.string().describe('Stage name'),
        jobs: z.array(z.object({
          name: z.string().describe('Job name'),
          image: z.string().optional().describe('Docker image'),
          commands: z.array(z.string()).describe('Commands to execute'),
          environment: z.record(z.string()).optional().describe('Environment variables'),
          artifacts: z.array(z.string()).optional().describe('Artifacts to save'),
          cache: z.array(z.string()).optional().describe('Cache paths')
        })).describe('Stage jobs'),
        condition: z.string().optional().describe('Stage condition'),
        parallel: z.boolean().optional().describe('Run jobs in parallel')
      })).describe('Pipeline stages'),
      environment: z.record(z.string()).optional().describe('Global environment'),
      timeout: z.number().optional().describe('Pipeline timeout in minutes')
    }).describe('Pipeline configuration')
  }),
  execute: async ({ name, config }) => {
    try {
      const pipelineId = `pipe_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const pipeline = {
        id: pipelineId,
        name,
        config: {
          ...config,
          timeout: config.timeout || 60, // 60 minutes default
          environment: config.environment || {}
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: 'active',
        runs: []
      };
      
      pipelineStore.set(pipelineId, pipeline);
      
      // Convert pipeline to workflow for execution
      const workflowSteps = [];
      config.stages.forEach((stage, stageIndex) => {
        if (stage.parallel) {
          // Create parallel execution step
          workflowSteps.push({
            id: `stage_${stageIndex}`,
            name: stage.name,
            type: 'parallel',
            tasks: stage.jobs.map((job, jobIndex) => ({
              id: `job_${stageIndex}_${jobIndex}`,
              name: job.name,
              type: 'script',
              action: job.commands.join('; '),
              params: { environment: job.environment, artifacts: job.artifacts }
            })),
            dependencies: stageIndex > 0 ? [`stage_${stageIndex - 1}`] : []
          });
        } else {
          // Create sequential execution steps
          stage.jobs.forEach((job, jobIndex) => {
            workflowSteps.push({
              id: `job_${stageIndex}_${jobIndex}`,
              name: `${stage.name} - ${job.name}`,
              type: 'script',
              action: job.commands.join('; '),
              params: { environment: job.environment, artifacts: job.artifacts },
              dependencies: stageIndex > 0 || jobIndex > 0 
                ? [`job_${stageIndex}_${jobIndex - 1}`] 
                : []
            });
          });
        }
      });
      
      // Create associated workflow
      const workflow = await workflowCreate.execute({
        name: `Pipeline: ${name}`,
        description: `CI/CD pipeline workflow for ${name}`,
        steps: workflowSteps,
        triggers: config.trigger ? [{
          type: 'event',
          config: { eventName: 'pipeline_trigger', ...config.trigger }
        }] : []
      });
      
      pipeline.workflowId = workflow.workflowId;
      
      return {
        success: true,
        pipelineId,
        pipeline,
        workflowId: workflow.workflowId,
        message: `Pipeline '${name}' created successfully`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Setup automation rules
export const automationSetup = createTool({
  name: 'automationSetup',
  description: 'Setup automation rules with conditions and actions',
  inputSchema: z.object({
    rules: z.array(z.object({
      name: z.string().describe('Rule name'),
      description: z.string().optional().describe('Rule description'),
      trigger: z.object({
        type: z.enum(['event', 'condition', 'schedule']).describe('Trigger type'),
        config: z.record(z.any()).describe('Trigger configuration')
      }).describe('Rule trigger'),
      conditions: z.array(z.object({
        field: z.string().describe('Field to check'),
        operator: z.enum(['equals', 'contains', 'greater', 'less', 'regex']).describe('Comparison operator'),
        value: z.any().describe('Value to compare')
      })).optional().describe('Rule conditions'),
      actions: z.array(z.object({
        type: z.enum(['workflow', 'notification', 'webhook', 'script']).describe('Action type'),
        config: z.record(z.any()).describe('Action configuration')
      })).describe('Actions to execute'),
      enabled: z.boolean().optional().describe('Enable/disable rule')
    })).describe('Automation rules')
  }),
  execute: async ({ rules }) => {
    try {
      const results = [];
      
      for (const rule of rules) {
        const ruleId = `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const automationRule = {
          id: ruleId,
          ...rule,
          enabled: rule.enabled !== false,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          executionCount: 0,
          lastExecution: null
        };
        
        automationRules.set(ruleId, automationRule);
        
        // Register event listeners if needed
        if (rule.trigger.type === 'event') {
          const eventName = rule.trigger.config.eventName;
          if (!eventTriggers.has(eventName)) {
            eventTriggers.set(eventName, []);
          }
          eventTriggers.get(eventName).push({ type: 'rule', id: ruleId });
        }
        
        results.push({
          ruleId,
          name: rule.name,
          status: 'created'
        });
      }
      
      return {
        success: true,
        rules: results,
        summary: {
          total: rules.length,
          enabled: rules.filter(r => r.enabled !== false).length,
          disabled: rules.filter(r => r.enabled === false).length
        },
        message: `${rules.length} automation rules created successfully`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Configure event triggers
export const triggerSetup = createTool({
  name: 'triggerSetup',
  description: 'Configure event triggers for workflows and automations',
  inputSchema: z.object({
    events: z.array(z.object({
      name: z.string().describe('Event name'),
      source: z.string().optional().describe('Event source'),
      filter: z.record(z.any()).optional().describe('Event filter criteria')
    })).describe('Events to listen for'),
    actions: z.array(z.object({
      type: z.enum(['workflow', 'automation', 'webhook', 'function']).describe('Action type'),
      target: z.string().describe('Target ID or URL'),
      params: z.record(z.any()).optional().describe('Action parameters'),
      transform: z.string().optional().describe('Data transformation script')
    })).describe('Actions to trigger'),
    config: z.object({
      enabled: z.boolean().optional().describe('Enable/disable trigger'),
      retries: z.number().optional().describe('Number of retries on failure'),
      timeout: z.number().optional().describe('Timeout in milliseconds'),
      rateLimit: z.object({
        requests: z.number().describe('Number of requests'),
        window: z.number().describe('Time window in seconds')
      }).optional().describe('Rate limiting configuration')
    }).optional().describe('Trigger configuration')
  }),
  execute: async ({ events, actions, config = {} }) => {
    try {
      const triggerId = `trig_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const trigger = {
        id: triggerId,
        events,
        actions,
        config: {
          enabled: config.enabled !== false,
          retries: config.retries || 3,
          timeout: config.timeout || 30000,
          rateLimit: config.rateLimit
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        stats: {
          triggered: 0,
          succeeded: 0,
          failed: 0,
          lastTriggered: null
        }
      };
      
      // Register event mappings
      events.forEach(event => {
        if (!eventTriggers.has(event.name)) {
          eventTriggers.set(event.name, []);
        }
        eventTriggers.get(event.name).push({ 
          type: 'trigger', 
          id: triggerId,
          filter: event.filter 
        });
      });
      
      return {
        success: true,
        triggerId,
        trigger,
        registeredEvents: events.map(e => e.name),
        message: `Trigger configured for ${events.length} events with ${actions.length} actions`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Process items in batches
export const batchProcess = createTool({
  name: 'batchProcess',
  description: 'Process multiple items in configurable batches',
  inputSchema: z.object({
    items: z.array(z.any()).describe('Items to process'),
    operation: z.string().describe('Operation to perform on each item'),
    batchSize: z.number().optional().describe('Number of items per batch'),
    parallel: z.boolean().optional().describe('Process batches in parallel'),
    transform: z.string().optional().describe('Transform function for items'),
    onError: z.enum(['stop', 'continue', 'retry']).optional().describe('Error handling strategy')
  }),
  execute: async ({ items, operation, batchSize = 10, parallel = true, transform, onError = 'continue' }) => {
    try {
      const batches = [];
      for (let i = 0; i < items.length; i += batchSize) {
        batches.push(items.slice(i, i + batchSize));
      }
      
      const results = {
        total: items.length,
        processed: 0,
        succeeded: 0,
        failed: 0,
        batches: batches.length,
        items: [],
        errors: []
      };
      
      const processBatch = async (batch, batchIndex) => {
        const batchResults = [];
        
        for (let i = 0; i < batch.length; i++) {
          const item = batch[i];
          const itemIndex = batchIndex * batchSize + i;
          
          try {
            // Apply transform if provided
            const processItem = transform 
              ? await eval(`(${transform})(${JSON.stringify(item)})`)
              : item;
            
            // Execute operation
            const result = await eval(`(async () => { 
              const item = ${JSON.stringify(processItem)};
              ${operation}
            })()`);
            
            batchResults.push({
              index: itemIndex,
              status: 'success',
              input: item,
              output: result
            });
            results.succeeded++;
          } catch (error) {
            const errorResult = {
              index: itemIndex,
              status: 'error',
              input: item,
              error: error.message
            };
            
            batchResults.push(errorResult);
            results.errors.push(errorResult);
            results.failed++;
            
            if (onError === 'stop') {
              throw new Error(`Batch processing stopped at item ${itemIndex}: ${error.message}`);
            } else if (onError === 'retry') {
              // Simple retry logic
              try {
                const retryResult = await eval(`(async () => { 
                  const item = ${JSON.stringify(item)};
                  ${operation}
                })()`);
                batchResults[batchResults.length - 1] = {
                  index: itemIndex,
                  status: 'success',
                  input: item,
                  output: retryResult,
                  retried: true
                };
                results.succeeded++;
                results.failed--;
              } catch (retryError) {
                // Keep original error
              }
            }
          }
          
          results.processed++;
        }
        
        return batchResults;
      };
      
      if (parallel) {
        const batchPromises = batches.map((batch, index) => processBatch(batch, index));
        const batchResults = await Promise.allSettled(batchPromises);
        
        batchResults.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            results.items.push(...result.value);
          } else {
            results.errors.push({
              batch: index,
              error: result.reason.message
            });
          }
        });
      } else {
        for (let i = 0; i < batches.length; i++) {
          const batchResults = await processBatch(batches[i], i);
          results.items.push(...batchResults);
        }
      }
      
      return {
        success: true,
        results,
        summary: {
          totalItems: results.total,
          processedItems: results.processed,
          successRate: results.total > 0 ? (results.succeeded / results.total * 100).toFixed(2) + '%' : '0%',
          failureRate: results.total > 0 ? (results.failed / results.total * 100).toFixed(2) + '%' : '0%',
          batchCount: batches.length,
          processingMode: parallel ? 'parallel' : 'sequential'
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Execute tasks in parallel
export const parallelExecute = createTool({
  name: 'parallelExecute',
  description: 'Execute multiple tasks in parallel with concurrency control',
  inputSchema: z.object({
    tasks: z.array(z.object({
      id: z.string().describe('Task identifier'),
      name: z.string().describe('Task name'),
      action: z.string().describe('Task action to execute'),
      params: z.record(z.any()).optional().describe('Task parameters'),
      timeout: z.number().optional().describe('Task timeout in milliseconds')
    })).describe('Tasks to execute'),
    concurrency: z.number().optional().describe('Maximum concurrent executions'),
    stopOnError: z.boolean().optional().describe('Stop all tasks if one fails'),
    timeout: z.number().optional().describe('Overall timeout in milliseconds')
  }),
  execute: async ({ tasks, concurrency = 5, stopOnError = false, timeout = 300000 }) => {
    try {
      const startTime = Date.now();
      const results = {
        total: tasks.length,
        completed: 0,
        failed: 0,
        tasks: []
      };
      
      // Create task queue
      const taskQueue = [...tasks];
      const executing = new Map();
      const completed = [];
      
      const executeTask = async (task) => {
        const taskStart = Date.now();
        const taskTimeout = task.timeout || timeout;
        
        try {
          // Create timeout promise
          const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error('Task timeout')), taskTimeout);
          });
          
          // Execute task action
          const taskPromise = eval(`(async () => {
            const params = ${JSON.stringify(task.params || {})};
            ${task.action}
          })()`);
          
          const result = await Promise.race([taskPromise, timeoutPromise]);
          
          return {
            id: task.id,
            name: task.name,
            status: 'completed',
            result,
            duration: Date.now() - taskStart
          };
        } catch (error) {
          return {
            id: task.id,
            name: task.name,
            status: 'failed',
            error: error.message,
            duration: Date.now() - taskStart
          };
        }
      };
      
      const processQueue = async () => {
        while (taskQueue.length > 0 || executing.size > 0) {
          // Check overall timeout
          if (Date.now() - startTime > timeout) {
            throw new Error('Overall execution timeout exceeded');
          }
          
          // Start new tasks if under concurrency limit
          while (taskQueue.length > 0 && executing.size < concurrency) {
            const task = taskQueue.shift();
            const taskPromise = executeTask(task);
            executing.set(task.id, taskPromise);
            
            taskPromise.then(result => {
              executing.delete(task.id);
              completed.push(result);
              
              if (result.status === 'completed') {
                results.completed++;
              } else {
                results.failed++;
                if (stopOnError) {
                  throw new Error(`Task ${task.id} failed: ${result.error}`);
                }
              }
            }).catch(error => {
              if (stopOnError) {
                throw error;
              }
            });
          }
          
          // Wait for at least one task to complete
          if (executing.size > 0) {
            await Promise.race(Array.from(executing.values()));
          }
        }
      };
      
      await processQueue();
      results.tasks = completed;
      
      return {
        success: true,
        results,
        summary: {
          totalTasks: results.total,
          completedTasks: results.completed,
          failedTasks: results.failed,
          successRate: results.total > 0 ? (results.completed / results.total * 100).toFixed(2) + '%' : '0%',
          totalDuration: Date.now() - startTime,
          concurrencyUsed: concurrency
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Manage workflow templates
export const workflowTemplate = createTool({
  name: 'workflowTemplate',
  description: 'Manage reusable workflow templates',
  inputSchema: z.object({
    action: z.enum(['create', 'list', 'get', 'update', 'delete', 'instantiate']).describe('Action to perform'),
    templateId: z.string().optional().describe('Template ID for get/update/delete/instantiate'),
    template: z.object({
      name: z.string().describe('Template name'),
      description: z.string().optional().describe('Template description'),
      category: z.string().optional().describe('Template category'),
      parameters: z.array(z.object({
        name: z.string().describe('Parameter name'),
        type: z.string().describe('Parameter type'),
        required: z.boolean().optional().describe('Is parameter required'),
        default: z.any().optional().describe('Default value'),
        description: z.string().optional().describe('Parameter description')
      })).optional().describe('Template parameters'),
      workflow: z.object({
        steps: z.array(z.any()).describe('Workflow steps'),
        config: z.record(z.any()).optional().describe('Workflow configuration')
      }).describe('Workflow definition')
    }).optional().describe('Template data for create/update'),
    params: z.record(z.any()).optional().describe('Parameters for instantiation'),
    filters: z.object({
      category: z.string().optional().describe('Filter by category'),
      search: z.string().optional().describe('Search in name/description')
    }).optional().describe('Filters for list action')
  }),
  execute: async ({ action, templateId, template, params, filters }) => {
    try {
      switch (action) {
        case 'create': {
          if (!template) {
            throw new Error('Template data required for create action');
          }
          
          const id = `tmpl_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          const newTemplate = {
            id,
            ...template,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            version: 1,
            usageCount: 0
          };
          
          workflowTemplates.set(id, newTemplate);
          
          return {
            success: true,
            templateId: id,
            template: newTemplate,
            message: `Template '${template.name}' created successfully`
          };
        }
        
        case 'list': {
          let templates = Array.from(workflowTemplates.values());
          
          // Apply filters
          if (filters) {
            if (filters.category) {
              templates = templates.filter(t => t.category === filters.category);
            }
            if (filters.search) {
              const searchLower = filters.search.toLowerCase();
              templates = templates.filter(t => 
                t.name.toLowerCase().includes(searchLower) ||
                (t.description && t.description.toLowerCase().includes(searchLower))
              );
            }
          }
          
          return {
            success: true,
            templates: templates.map(t => ({
              id: t.id,
              name: t.name,
              description: t.description,
              category: t.category,
              parameters: t.parameters,
              usageCount: t.usageCount,
              createdAt: t.createdAt
            })),
            count: templates.length
          };
        }
        
        case 'get': {
          if (!templateId) {
            throw new Error('Template ID required for get action');
          }
          
          const template = workflowTemplates.get(templateId);
          if (!template) {
            throw new Error(`Template ${templateId} not found`);
          }
          
          return {
            success: true,
            template
          };
        }
        
        case 'update': {
          if (!templateId || !template) {
            throw new Error('Template ID and data required for update action');
          }
          
          const existing = workflowTemplates.get(templateId);
          if (!existing) {
            throw new Error(`Template ${templateId} not found`);
          }
          
          const updated = {
            ...existing,
            ...template,
            id: templateId,
            updatedAt: new Date().toISOString(),
            version: existing.version + 1
          };
          
          workflowTemplates.set(templateId, updated);
          
          return {
            success: true,
            template: updated,
            message: `Template '${updated.name}' updated successfully`
          };
        }
        
        case 'delete': {
          if (!templateId) {
            throw new Error('Template ID required for delete action');
          }
          
          const template = workflowTemplates.get(templateId);
          if (!template) {
            throw new Error(`Template ${templateId} not found`);
          }
          
          workflowTemplates.delete(templateId);
          
          return {
            success: true,
            message: `Template '${template.name}' deleted successfully`
          };
        }
        
        case 'instantiate': {
          if (!templateId) {
            throw new Error('Template ID required for instantiate action');
          }
          
          const template = workflowTemplates.get(templateId);
          if (!template) {
            throw new Error(`Template ${templateId} not found`);
          }
          
          // Validate required parameters
          if (template.parameters) {
            const missingParams = template.parameters
              .filter(p => p.required && !params?.[p.name] && !p.default)
              .map(p => p.name);
            
            if (missingParams.length > 0) {
              throw new Error(`Missing required parameters: ${missingParams.join(', ')}`);
            }
          }
          
          // Merge parameters with defaults
          const mergedParams = {};
          if (template.parameters) {
            template.parameters.forEach(p => {
              mergedParams[p.name] = params?.[p.name] ?? p.default;
            });
          }
          
          // Replace parameter placeholders in workflow
          let workflowStr = JSON.stringify(template.workflow);
          Object.entries(mergedParams).forEach(([key, value]) => {
            workflowStr = workflowStr.replace(
              new RegExp(`{{${key}}}`, 'g'),
              JSON.stringify(value).slice(1, -1)
            );
          });
          
          const instantiatedWorkflow = JSON.parse(workflowStr);
          
          // Create workflow from template
          const result = await workflowCreate.execute({
            name: `${template.name} - ${new Date().toISOString()}`,
            description: `Instantiated from template: ${template.name}`,
            ...instantiatedWorkflow
          });
          
          // Update usage count
          template.usageCount++;
          workflowTemplates.set(templateId, template);
          
          return {
            success: true,
            workflowId: result.workflowId,
            templateId,
            parameters: mergedParams,
            message: `Workflow created from template '${template.name}'`
          };
        }
        
        default:
          throw new Error(`Unknown action: ${action}`);
      }
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Tool: Export workflow definitions
export const workflowExport = createTool({
  name: 'workflowExport',
  description: 'Export workflow definitions in various formats',
  inputSchema: z.object({
    workflowId: z.string().describe('Workflow ID to export'),
    format: z.enum(['json', 'yaml', 'mermaid', 'graphviz']).optional().describe('Export format'),
    includeExecutions: z.boolean().optional().describe('Include execution history'),
    includeMetrics: z.boolean().optional().describe('Include performance metrics')
  }),
  execute: async ({ workflowId, format = 'json', includeExecutions = false, includeMetrics = false }) => {
    try {
      const workflow = workflowStore.get(workflowId);
      if (!workflow) {
        throw new Error(`Workflow ${workflowId} not found`);
      }
      
      const exportData = {
        workflow: { ...workflow },
        metadata: {
          exportedAt: new Date().toISOString(),
          format,
          version: '1.0'
        }
      };
      
      // Add execution history if requested
      if (includeExecutions) {
        const executions = Array.from(executionHistory.values())
          .filter(e => e.workflowId === workflowId)
          .sort((a, b) => new Date(b.startTime) - new Date(a.startTime))
          .slice(0, 10); // Last 10 executions
        
        exportData.executions = executions;
      }
      
      // Add metrics if requested
      if (includeMetrics) {
        const executions = Array.from(executionHistory.values())
          .filter(e => e.workflowId === workflowId);
        
        const metrics = {
          totalExecutions: executions.length,
          successfulExecutions: executions.filter(e => e.status === 'completed').length,
          failedExecutions: executions.filter(e => e.status === 'failed').length,
          averageDuration: executions.length > 0
            ? executions.reduce((sum, e) => sum + (e.duration || 0), 0) / executions.length
            : 0,
          lastExecution: executions.length > 0
            ? executions.sort((a, b) => new Date(b.startTime) - new Date(a.startTime))[0].startTime
            : null
        };
        
        exportData.metrics = metrics;
      }
      
      let output;
      switch (format) {
        case 'json':
          output = JSON.stringify(exportData, null, 2);
          break;
          
        case 'yaml':
          // Simple YAML converter (would use a library in production)
          output = `# Workflow Export\n`;
          output += `workflow:\n`;
          output += `  id: ${workflow.id}\n`;
          output += `  name: ${workflow.name}\n`;
          output += `  description: ${workflow.description || 'N/A'}\n`;
          output += `  steps:\n`;
          workflow.steps.forEach(step => {
            output += `    - id: ${step.id}\n`;
            output += `      name: ${step.name}\n`;
            output += `      type: ${step.type}\n`;
            if (step.dependencies) {
              output += `      dependencies: [${step.dependencies.join(', ')}]\n`;
            }
          });
          break;
          
        case 'mermaid':
          output = `graph TD\n`;
          workflow.steps.forEach(step => {
            output += `    ${step.id}["${step.name}"]\n`;
            if (step.dependencies) {
              step.dependencies.forEach(dep => {
                output += `    ${dep} --> ${step.id}\n`;
              });
            }
          });
          break;
          
        case 'graphviz':
          output = `digraph workflow {\n`;
          output += `    rankdir=TB;\n`;
          output += `    node [shape=box];\n`;
          workflow.steps.forEach(step => {
            output += `    "${step.id}" [label="${step.name}"];\n`;
            if (step.dependencies) {
              step.dependencies.forEach(dep => {
                output += `    "${dep}" -> "${step.id}";\n`;
              });
            }
          });
          output += `}\n`;
          break;
      }
      
      return {
        success: true,
        format,
        output,
        workflow: {
          id: workflow.id,
          name: workflow.name,
          stepCount: workflow.steps.length
        },
        exportSize: output.length,
        message: `Workflow exported successfully in ${format} format`
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
});

// Export all tools
// export const workflowAutomationTools = [
//   workflowCreate,
//   workflowExecute,
//   workflowSchedule,
//   pipelineCreate,
//   automationSetup,
//   triggerSetup,
//   batchProcess,
//   parallelExecute,
//   workflowTemplate,
//   workflowExport
// ];
// Export as object for consistency
export const workflowAutomationTools = {
  workflowCreate,
  workflowExecute,
  workflowSchedule,
  pipelineCreate,
  automationSetup,
  triggerSetup,
  batchProcess,
  parallelExecute,
  workflowTemplate,
  workflowExport
};
