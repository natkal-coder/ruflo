import { createTool } from '@mastra/core';
import { z } from 'zod';

const workflowStore = /* @__PURE__ */ new Map();
const pipelineStore = /* @__PURE__ */ new Map();
const automationRules = /* @__PURE__ */ new Map();
const eventTriggers = /* @__PURE__ */ new Map();
const workflowTemplates = /* @__PURE__ */ new Map();
const executionHistory = /* @__PURE__ */ new Map();
const scheduledJobs = /* @__PURE__ */ new Map();
const executeWorkflowStep = async (step, context) => {
  const { type, action, params } = step;
  const startTime = Date.now();
  try {
    let result;
    switch (type) {
      case "script":
        result = await eval(`(async () => { ${action} })()`);
        break;
      case "condition":
        result = await eval(`(${action})`);
        break;
      case "parallel":
        result = await Promise.all(
          step.tasks.map((task2) => executeWorkflowStep(task2))
        );
        break;
      case "sequential":
        result = [];
        for (const task2 of step.tasks) {
          result.push(await executeWorkflowStep(task2));
        }
        break;
      default:
        result = { type, action, params };
    }
    return {
      stepId: step.id,
      status: "completed",
      result,
      duration: Date.now() - startTime
    };
  } catch (error2) {
    return {
      stepId: step.id,
      status: "failed",
      error: error2.message,
      duration: Date.now() - startTime
    };
  }
};
const validateWorkflowDAG = (steps) => {
  const graph = /* @__PURE__ */ new Map();
  steps.forEach((step2) => {
    graph.set(step2.id, step2.dependencies || []);
  });
  const visited = /* @__PURE__ */ new Set();
  const visiting = /* @__PURE__ */ new Set();
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
      throw new Error("Workflow contains circular dependencies");
    }
  }
  return true;
};
const workflowCreate = createTool({
  name: "workflowCreate",
  description: "Create custom workflows with steps and dependencies",
  inputSchema: z.object({
    name: z.string().describe("Workflow name"),
    description: z.string().optional().describe("Workflow description"),
    steps: z.array(z.object({
      id: z.string().describe("Step identifier"),
      name: z.string().describe("Step name"),
      type: z.enum(["script", "condition", "parallel", "sequential"]).describe("Step type"),
      action: z.string().optional().describe("Action to execute"),
      params: z.record(z.any()).optional().describe("Step parameters"),
      dependencies: z.array(z.string()).optional().describe("Step dependencies"),
      tasks: z.array(z.any()).optional().describe("Sub-tasks for parallel/sequential steps")
    })).describe("Workflow steps"),
    triggers: z.array(z.object({
      type: z.enum(["manual", "schedule", "event", "webhook"]).describe("Trigger type"),
      config: z.record(z.any()).describe("Trigger configuration")
    })).optional().describe("Workflow triggers"),
    config: z.object({
      timeout: z.number().optional().describe("Workflow timeout in milliseconds"),
      retries: z.number().optional().describe("Number of retries on failure"),
      notifications: z.boolean().optional().describe("Enable notifications")
    }).optional().describe("Workflow configuration")
  }),
  execute: async ({ name, description, steps, triggers = [], config = {} }) => {
    try {
      validateWorkflowDAG(steps);
      const workflowId = `wf_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const workflow = {
        id: workflowId,
        name,
        description,
        steps,
        triggers,
        config: {
          timeout: config.timeout || 36e5,
          // 1 hour default
          retries: config.retries || 0,
          notifications: config.notifications || false
        },
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        version: 1,
        status: "active"
      };
      workflowStore.set(workflowId, workflow);
      if (triggers.length > 0) {
        triggers.forEach((trigger) => {
          if (trigger.type === "schedule") {
            const jobId = `job_${workflowId}_${Date.now()}`;
            scheduledJobs.set(jobId, {
              workflowId,
              schedule: trigger.config.cron,
              nextRun: trigger.config.nextRun
            });
          } else if (trigger.type === "event") {
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
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const workflowExecute = createTool({
  name: "workflowExecute",
  description: "Execute workflows with parameters and track execution",
  inputSchema: z.object({
    workflowId: z.string().describe("Workflow ID to execute"),
    params: z.record(z.any()).optional().describe("Execution parameters"),
    mode: z.enum(["sync", "async"]).optional().describe("Execution mode"),
    context: z.record(z.any()).optional().describe("Execution context")
  }),
  execute: async ({ workflowId, params: params2 = {}, mode = "sync", context: context2 = {} }) => {
    try {
      const workflow = workflowStore.get(workflowId);
      if (!workflow) {
        throw new Error(`Workflow ${workflowId} not found`);
      }
      const executionId = `exec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const execution = {
        id: executionId,
        workflowId,
        params: params2,
        context: context2,
        startTime: (/* @__PURE__ */ new Date()).toISOString(),
        status: "running",
        steps: []
      };
      executionHistory.set(executionId, execution);
      const executeWorkflow = async () => {
        const results2 = [];
        const stepResults = /* @__PURE__ */ new Map();
        const executeStep = async (step2) => {
          if (step2.dependencies) {
            for (const dep of step2.dependencies) {
              const depResult = stepResults.get(dep);
              if (!depResult || depResult.status !== "completed") {
                throw new Error(`Dependency ${dep} not satisfied`);
              }
            }
          }
          const result2 = await executeWorkflowStep(step2);
          stepResults.set(step2.id, result2);
          results2.push(result2);
          return result2;
        };
        const executed = /* @__PURE__ */ new Set();
        while (executed.size < workflow.steps.length) {
          const readySteps = workflow.steps.filter((step2) => {
            if (executed.has(step2.id)) return false;
            if (!step2.dependencies) return true;
            return step2.dependencies.every((dep) => executed.has(dep));
          });
          if (readySteps.length === 0) {
            throw new Error("No executable steps found - possible circular dependency");
          }
          await Promise.all(readySteps.map(async (step2) => {
            await executeStep(step2);
            executed.add(step2.id);
          }));
        }
        execution.steps = results2;
        execution.endTime = (/* @__PURE__ */ new Date()).toISOString();
        execution.status = results2.every((r) => r.status === "completed") ? "completed" : "failed";
        execution.duration = Date.now() - Date.parse(execution.startTime);
        return execution;
      };
      if (mode === "async") {
        executeWorkflow().catch((error2) => {
          execution.status = "failed";
          execution.error = error2.message;
          execution.endTime = (/* @__PURE__ */ new Date()).toISOString();
        });
        return {
          success: true,
          executionId,
          status: "started",
          message: "Workflow execution started asynchronously"
        };
      } else {
        const result2 = await executeWorkflow();
        return {
          success: true,
          executionId,
          execution: result2,
          summary: {
            totalSteps: result2.steps.length,
            completedSteps: result2.steps.filter((s) => s.status === "completed").length,
            failedSteps: result2.steps.filter((s) => s.status === "failed").length,
            duration: result2.duration
          }
        };
      }
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const workflowSchedule = createTool({
  name: "workflowSchedule",
  description: "Schedule workflow execution with cron expressions or specific times",
  inputSchema: z.object({
    workflowId: z.string().describe("Workflow ID to schedule"),
    schedule: z.object({
      type: z.enum(["cron", "once", "interval"]).describe("Schedule type"),
      expression: z.string().optional().describe("Cron expression for cron type"),
      at: z.string().optional().describe("ISO date for once type"),
      interval: z.number().optional().describe("Interval in milliseconds"),
      timezone: z.string().optional().describe("Timezone for scheduling")
    }).describe("Schedule configuration"),
    params: z.record(z.any()).optional().describe("Default parameters for execution"),
    enabled: z.boolean().optional().describe("Enable/disable schedule")
  }),
  execute: async ({ workflowId, schedule, params: params2 = {}, enabled = true }) => {
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
        params: params2,
        enabled,
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        lastRun: null,
        nextRun: null,
        runCount: 0
      };
      if (schedule.type === "once" && schedule.at) {
        scheduledJob.nextRun = schedule.at;
      } else if (schedule.type === "interval" && schedule.interval) {
        scheduledJob.nextRun = new Date(Date.now() + schedule.interval).toISOString();
      } else if (schedule.type === "cron" && schedule.expression) {
        scheduledJob.nextRun = new Date(Date.now() + 6e4).toISOString();
      }
      scheduledJobs.set(scheduleId, scheduledJob);
      return {
        success: true,
        scheduleId,
        schedule: scheduledJob,
        message: `Workflow scheduled successfully`
      };
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const pipelineCreate = createTool({
  name: "pipelineCreate",
  description: "Create CI/CD pipelines with stages and jobs",
  inputSchema: z.object({
    name: z.string().describe("Pipeline name"),
    config: z.object({
      trigger: z.object({
        branches: z.array(z.string()).optional().describe("Trigger branches"),
        events: z.array(z.string()).optional().describe("Trigger events"),
        paths: z.array(z.string()).optional().describe("Trigger paths")
      }).optional().describe("Pipeline triggers"),
      stages: z.array(z.object({
        name: z.string().describe("Stage name"),
        jobs: z.array(z.object({
          name: z.string().describe("Job name"),
          image: z.string().optional().describe("Docker image"),
          commands: z.array(z.string()).describe("Commands to execute"),
          environment: z.record(z.string()).optional().describe("Environment variables"),
          artifacts: z.array(z.string()).optional().describe("Artifacts to save"),
          cache: z.array(z.string()).optional().describe("Cache paths")
        })).describe("Stage jobs"),
        condition: z.string().optional().describe("Stage condition"),
        parallel: z.boolean().optional().describe("Run jobs in parallel")
      })).describe("Pipeline stages"),
      environment: z.record(z.string()).optional().describe("Global environment"),
      timeout: z.number().optional().describe("Pipeline timeout in minutes")
    }).describe("Pipeline configuration")
  }),
  execute: async ({ name, config }) => {
    try {
      const pipelineId = `pipe_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      const pipeline = {
        id: pipelineId,
        name,
        config: {
          ...config,
          timeout: config.timeout || 60,
          // 60 minutes default
          environment: config.environment || {}
        },
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        status: "active",
        runs: []
      };
      pipelineStore.set(pipelineId, pipeline);
      const workflowSteps = [];
      config.stages.forEach((stage, stageIndex) => {
        if (stage.parallel) {
          workflowSteps.push({
            id: `stage_${stageIndex}`,
            name: stage.name,
            type: "parallel",
            tasks: stage.jobs.map((job, jobIndex) => ({
              id: `job_${stageIndex}_${jobIndex}`,
              name: job.name,
              type: "script",
              action: job.commands.join("; "),
              params: { environment: job.environment, artifacts: job.artifacts }
            })),
            dependencies: stageIndex > 0 ? [`stage_${stageIndex - 1}`] : []
          });
        } else {
          stage.jobs.forEach((job, jobIndex) => {
            workflowSteps.push({
              id: `job_${stageIndex}_${jobIndex}`,
              name: `${stage.name} - ${job.name}`,
              type: "script",
              action: job.commands.join("; "),
              params: { environment: job.environment, artifacts: job.artifacts },
              dependencies: stageIndex > 0 || jobIndex > 0 ? [`job_${stageIndex}_${jobIndex - 1}`] : []
            });
          });
        }
      });
      const workflow = await workflowCreate.execute({
        name: `Pipeline: ${name}`,
        description: `CI/CD pipeline workflow for ${name}`,
        steps: workflowSteps,
        triggers: config.trigger ? [{
          type: "event",
          config: { eventName: "pipeline_trigger", ...config.trigger }
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
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const automationSetup = createTool({
  name: "automationSetup",
  description: "Setup automation rules with conditions and actions",
  inputSchema: z.object({
    rules: z.array(z.object({
      name: z.string().describe("Rule name"),
      description: z.string().optional().describe("Rule description"),
      trigger: z.object({
        type: z.enum(["event", "condition", "schedule"]).describe("Trigger type"),
        config: z.record(z.any()).describe("Trigger configuration")
      }).describe("Rule trigger"),
      conditions: z.array(z.object({
        field: z.string().describe("Field to check"),
        operator: z.enum(["equals", "contains", "greater", "less", "regex"]).describe("Comparison operator"),
        value: z.any().describe("Value to compare")
      })).optional().describe("Rule conditions"),
      actions: z.array(z.object({
        type: z.enum(["workflow", "notification", "webhook", "script"]).describe("Action type"),
        config: z.record(z.any()).describe("Action configuration")
      })).describe("Actions to execute"),
      enabled: z.boolean().optional().describe("Enable/disable rule")
    })).describe("Automation rules")
  }),
  execute: async ({ rules }) => {
    try {
      const results2 = [];
      for (const rule of rules) {
        const ruleId = `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const automationRule = {
          id: ruleId,
          ...rule,
          enabled: rule.enabled !== false,
          createdAt: (/* @__PURE__ */ new Date()).toISOString(),
          updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
          executionCount: 0,
          lastExecution: null
        };
        automationRules.set(ruleId, automationRule);
        if (rule.trigger.type === "event") {
          const eventName = rule.trigger.config.eventName;
          if (!eventTriggers.has(eventName)) {
            eventTriggers.set(eventName, []);
          }
          eventTriggers.get(eventName).push({ type: "rule", id: ruleId });
        }
        results2.push({
          ruleId,
          name: rule.name,
          status: "created"
        });
      }
      return {
        success: true,
        rules: results2,
        summary: {
          total: rules.length,
          enabled: rules.filter((r) => r.enabled !== false).length,
          disabled: rules.filter((r) => r.enabled === false).length
        },
        message: `${rules.length} automation rules created successfully`
      };
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const triggerSetup = createTool({
  name: "triggerSetup",
  description: "Configure event triggers for workflows and automations",
  inputSchema: z.object({
    events: z.array(z.object({
      name: z.string().describe("Event name"),
      source: z.string().optional().describe("Event source"),
      filter: z.record(z.any()).optional().describe("Event filter criteria")
    })).describe("Events to listen for"),
    actions: z.array(z.object({
      type: z.enum(["workflow", "automation", "webhook", "function"]).describe("Action type"),
      target: z.string().describe("Target ID or URL"),
      params: z.record(z.any()).optional().describe("Action parameters"),
      transform: z.string().optional().describe("Data transformation script")
    })).describe("Actions to trigger"),
    config: z.object({
      enabled: z.boolean().optional().describe("Enable/disable trigger"),
      retries: z.number().optional().describe("Number of retries on failure"),
      timeout: z.number().optional().describe("Timeout in milliseconds"),
      rateLimit: z.object({
        requests: z.number().describe("Number of requests"),
        window: z.number().describe("Time window in seconds")
      }).optional().describe("Rate limiting configuration")
    }).optional().describe("Trigger configuration")
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
          timeout: config.timeout || 3e4,
          rateLimit: config.rateLimit
        },
        createdAt: (/* @__PURE__ */ new Date()).toISOString(),
        updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
        stats: {
          triggered: 0,
          succeeded: 0,
          failed: 0,
          lastTriggered: null
        }
      };
      events.forEach((event) => {
        if (!eventTriggers.has(event.name)) {
          eventTriggers.set(event.name, []);
        }
        eventTriggers.get(event.name).push({
          type: "trigger",
          id: triggerId,
          filter: event.filter
        });
      });
      return {
        success: true,
        triggerId,
        trigger,
        registeredEvents: events.map((e) => e.name),
        message: `Trigger configured for ${events.length} events with ${actions.length} actions`
      };
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const batchProcess = createTool({
  name: "batchProcess",
  description: "Process multiple items in configurable batches",
  inputSchema: z.object({
    items: z.array(z.any()).describe("Items to process"),
    operation: z.string().describe("Operation to perform on each item"),
    batchSize: z.number().optional().describe("Number of items per batch"),
    parallel: z.boolean().optional().describe("Process batches in parallel"),
    transform: z.string().optional().describe("Transform function for items"),
    onError: z.enum(["stop", "continue", "retry"]).optional().describe("Error handling strategy")
  }),
  execute: async ({ items, operation, batchSize = 10, parallel = true, transform, onError = "continue" }) => {
    try {
      const batches = [];
      for (let i2 = 0; i2 < items.length; i2 += batchSize) {
        batches.push(items.slice(i2, i2 + batchSize));
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
            const processItem = transform ? await eval(`(${transform})(${JSON.stringify(item)})`) : item;
            const result = await eval(`(async () => { 
              const item = ${JSON.stringify(processItem)};
              ${operation}
            })()`);
            batchResults.push({
              index: itemIndex,
              status: "success",
              input: item,
              output: result
            });
            results.succeeded++;
          } catch (error) {
            const errorResult = {
              index: itemIndex,
              status: "error",
              input: item,
              error: error.message
            };
            batchResults.push(errorResult);
            results.errors.push(errorResult);
            results.failed++;
            if (onError === "stop") {
              throw new Error(`Batch processing stopped at item ${itemIndex}: ${error.message}`);
            } else if (onError === "retry") {
              try {
                const retryResult = await eval(`(async () => { 
                  const item = ${JSON.stringify(item)};
                  ${operation}
                })()`);
                batchResults[batchResults.length - 1] = {
                  index: itemIndex,
                  status: "success",
                  input: item,
                  output: retryResult,
                  retried: true
                };
                results.succeeded++;
                results.failed--;
              } catch (retryError) {
              }
            }
          }
          results.processed++;
        }
        return batchResults;
      };
      if (parallel) {
        const batchPromises = batches.map((batch2, index) => processBatch(batch2, index));
        const batchResults2 = await Promise.allSettled(batchPromises);
        batchResults2.forEach((result2, index) => {
          if (result2.status === "fulfilled") {
            results.items.push(...result2.value);
          } else {
            results.errors.push({
              batch: index,
              error: result2.reason.message
            });
          }
        });
      } else {
        for (let i2 = 0; i2 < batches.length; i2++) {
          const batchResults2 = await processBatch(batches[i2], i2);
          results.items.push(...batchResults2);
        }
      }
      return {
        success: true,
        results,
        summary: {
          totalItems: results.total,
          processedItems: results.processed,
          successRate: results.total > 0 ? (results.succeeded / results.total * 100).toFixed(2) + "%" : "0%",
          failureRate: results.total > 0 ? (results.failed / results.total * 100).toFixed(2) + "%" : "0%",
          batchCount: batches.length,
          processingMode: parallel ? "parallel" : "sequential"
        }
      };
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const parallelExecute = createTool({
  name: "parallelExecute",
  description: "Execute multiple tasks in parallel with concurrency control",
  inputSchema: z.object({
    tasks: z.array(z.object({
      id: z.string().describe("Task identifier"),
      name: z.string().describe("Task name"),
      action: z.string().describe("Task action to execute"),
      params: z.record(z.any()).optional().describe("Task parameters"),
      timeout: z.number().optional().describe("Task timeout in milliseconds")
    })).describe("Tasks to execute"),
    concurrency: z.number().optional().describe("Maximum concurrent executions"),
    stopOnError: z.boolean().optional().describe("Stop all tasks if one fails"),
    timeout: z.number().optional().describe("Overall timeout in milliseconds")
  }),
  execute: async ({ tasks, concurrency = 5, stopOnError = false, timeout = 3e5 }) => {
    try {
      const startTime = Date.now();
      const results = {
        total: tasks.length,
        completed: 0,
        failed: 0,
        tasks: []
      };
      const taskQueue = [...tasks];
      const executing = /* @__PURE__ */ new Map();
      const completed = [];
      const executeTask = async (task) => {
        const taskStart = Date.now();
        const taskTimeout = task.timeout || timeout;
        try {
          const timeoutPromise = new Promise((_, reject) => {
            setTimeout(() => reject(new Error("Task timeout")), taskTimeout);
          });
          const taskPromise = eval(`(async () => {
            const params = ${JSON.stringify(task.params || {})};
            ${task.action}
          })()`);
          const result = await Promise.race([taskPromise, timeoutPromise]);
          return {
            id: task.id,
            name: task.name,
            status: "completed",
            result,
            duration: Date.now() - taskStart
          };
        } catch (error2) {
          return {
            id: task.id,
            name: task.name,
            status: "failed",
            error: error2.message,
            duration: Date.now() - taskStart
          };
        }
      };
      const processQueue = async () => {
        while (taskQueue.length > 0 || executing.size > 0) {
          if (Date.now() - startTime > timeout) {
            throw new Error("Overall execution timeout exceeded");
          }
          while (taskQueue.length > 0 && executing.size < concurrency) {
            const task2 = taskQueue.shift();
            const taskPromise2 = executeTask(task2);
            executing.set(task2.id, taskPromise2);
            taskPromise2.then((result2) => {
              executing.delete(task2.id);
              completed.push(result2);
              if (result2.status === "completed") {
                results.completed++;
              } else {
                results.failed++;
                if (stopOnError) {
                  throw new Error(`Task ${task2.id} failed: ${result2.error}`);
                }
              }
            }).catch((error2) => {
              if (stopOnError) {
                throw error2;
              }
            });
          }
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
          successRate: results.total > 0 ? (results.completed / results.total * 100).toFixed(2) + "%" : "0%",
          totalDuration: Date.now() - startTime,
          concurrencyUsed: concurrency
        }
      };
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const workflowTemplate = createTool({
  name: "workflowTemplate",
  description: "Manage reusable workflow templates",
  inputSchema: z.object({
    action: z.enum(["create", "list", "get", "update", "delete", "instantiate"]).describe("Action to perform"),
    templateId: z.string().optional().describe("Template ID for get/update/delete/instantiate"),
    template: z.object({
      name: z.string().describe("Template name"),
      description: z.string().optional().describe("Template description"),
      category: z.string().optional().describe("Template category"),
      parameters: z.array(z.object({
        name: z.string().describe("Parameter name"),
        type: z.string().describe("Parameter type"),
        required: z.boolean().optional().describe("Is parameter required"),
        default: z.any().optional().describe("Default value"),
        description: z.string().optional().describe("Parameter description")
      })).optional().describe("Template parameters"),
      workflow: z.object({
        steps: z.array(z.any()).describe("Workflow steps"),
        config: z.record(z.any()).optional().describe("Workflow configuration")
      }).describe("Workflow definition")
    }).optional().describe("Template data for create/update"),
    params: z.record(z.any()).optional().describe("Parameters for instantiation"),
    filters: z.object({
      category: z.string().optional().describe("Filter by category"),
      search: z.string().optional().describe("Search in name/description")
    }).optional().describe("Filters for list action")
  }),
  execute: async ({ action: action2, templateId, template, params: params2, filters }) => {
    try {
      switch (action2) {
        case "create": {
          if (!template) {
            throw new Error("Template data required for create action");
          }
          const id = `tmpl_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          const newTemplate = {
            id,
            ...template,
            createdAt: (/* @__PURE__ */ new Date()).toISOString(),
            updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
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
        case "list": {
          let templates = Array.from(workflowTemplates.values());
          if (filters) {
            if (filters.category) {
              templates = templates.filter((t) => t.category === filters.category);
            }
            if (filters.search) {
              const searchLower = filters.search.toLowerCase();
              templates = templates.filter(
                (t) => t.name.toLowerCase().includes(searchLower) || t.description && t.description.toLowerCase().includes(searchLower)
              );
            }
          }
          return {
            success: true,
            templates: templates.map((t) => ({
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
        case "get": {
          if (!templateId) {
            throw new Error("Template ID required for get action");
          }
          const template2 = workflowTemplates.get(templateId);
          if (!template2) {
            throw new Error(`Template ${templateId} not found`);
          }
          return {
            success: true,
            template: template2
          };
        }
        case "update": {
          if (!templateId || !template) {
            throw new Error("Template ID and data required for update action");
          }
          const existing = workflowTemplates.get(templateId);
          if (!existing) {
            throw new Error(`Template ${templateId} not found`);
          }
          const updated = {
            ...existing,
            ...template,
            id: templateId,
            updatedAt: (/* @__PURE__ */ new Date()).toISOString(),
            version: existing.version + 1
          };
          workflowTemplates.set(templateId, updated);
          return {
            success: true,
            template: updated,
            message: `Template '${updated.name}' updated successfully`
          };
        }
        case "delete": {
          if (!templateId) {
            throw new Error("Template ID required for delete action");
          }
          const template2 = workflowTemplates.get(templateId);
          if (!template2) {
            throw new Error(`Template ${templateId} not found`);
          }
          workflowTemplates.delete(templateId);
          return {
            success: true,
            message: `Template '${template2.name}' deleted successfully`
          };
        }
        case "instantiate": {
          if (!templateId) {
            throw new Error("Template ID required for instantiate action");
          }
          const template2 = workflowTemplates.get(templateId);
          if (!template2) {
            throw new Error(`Template ${templateId} not found`);
          }
          if (template2.parameters) {
            const missingParams = template2.parameters.filter((p) => p.required && !params2?.[p.name] && !p.default).map((p) => p.name);
            if (missingParams.length > 0) {
              throw new Error(`Missing required parameters: ${missingParams.join(", ")}`);
            }
          }
          const mergedParams = {};
          if (template2.parameters) {
            template2.parameters.forEach((p) => {
              mergedParams[p.name] = params2?.[p.name] ?? p.default;
            });
          }
          let workflowStr = JSON.stringify(template2.workflow);
          Object.entries(mergedParams).forEach(([key, value]) => {
            workflowStr = workflowStr.replace(
              new RegExp(`{{${key}}}`, "g"),
              JSON.stringify(value).slice(1, -1)
            );
          });
          const instantiatedWorkflow = JSON.parse(workflowStr);
          const result2 = await workflowCreate.execute({
            name: `${template2.name} - ${(/* @__PURE__ */ new Date()).toISOString()}`,
            description: `Instantiated from template: ${template2.name}`,
            ...instantiatedWorkflow
          });
          template2.usageCount++;
          workflowTemplates.set(templateId, template2);
          return {
            success: true,
            workflowId: result2.workflowId,
            templateId,
            parameters: mergedParams,
            message: `Workflow created from template '${template2.name}'`
          };
        }
        default:
          throw new Error(`Unknown action: ${action2}`);
      }
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const workflowExport = createTool({
  name: "workflowExport",
  description: "Export workflow definitions in various formats",
  inputSchema: z.object({
    workflowId: z.string().describe("Workflow ID to export"),
    format: z.enum(["json", "yaml", "mermaid", "graphviz"]).optional().describe("Export format"),
    includeExecutions: z.boolean().optional().describe("Include execution history"),
    includeMetrics: z.boolean().optional().describe("Include performance metrics")
  }),
  execute: async ({ workflowId, format = "json", includeExecutions = false, includeMetrics = false }) => {
    try {
      const workflow = workflowStore.get(workflowId);
      if (!workflow) {
        throw new Error(`Workflow ${workflowId} not found`);
      }
      const exportData = {
        workflow: { ...workflow },
        metadata: {
          exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
          format,
          version: "1.0"
        }
      };
      if (includeExecutions) {
        const executions = Array.from(executionHistory.values()).filter((e) => e.workflowId === workflowId).sort((a, b) => new Date(b.startTime) - new Date(a.startTime)).slice(0, 10);
        exportData.executions = executions;
      }
      if (includeMetrics) {
        const executions = Array.from(executionHistory.values()).filter((e) => e.workflowId === workflowId);
        const metrics = {
          totalExecutions: executions.length,
          successfulExecutions: executions.filter((e) => e.status === "completed").length,
          failedExecutions: executions.filter((e) => e.status === "failed").length,
          averageDuration: executions.length > 0 ? executions.reduce((sum, e) => sum + (e.duration || 0), 0) / executions.length : 0,
          lastExecution: executions.length > 0 ? executions.sort((a, b) => new Date(b.startTime) - new Date(a.startTime))[0].startTime : null
        };
        exportData.metrics = metrics;
      }
      let output;
      switch (format) {
        case "json":
          output = JSON.stringify(exportData, null, 2);
          break;
        case "yaml":
          output = `# Workflow Export
`;
          output += `workflow:
`;
          output += `  id: ${workflow.id}
`;
          output += `  name: ${workflow.name}
`;
          output += `  description: ${workflow.description || "N/A"}
`;
          output += `  steps:
`;
          workflow.steps.forEach((step2) => {
            output += `    - id: ${step2.id}
`;
            output += `      name: ${step2.name}
`;
            output += `      type: ${step2.type}
`;
            if (step2.dependencies) {
              output += `      dependencies: [${step2.dependencies.join(", ")}]
`;
            }
          });
          break;
        case "mermaid":
          output = `graph TD
`;
          workflow.steps.forEach((step2) => {
            output += `    ${step2.id}["${step2.name}"]
`;
            if (step2.dependencies) {
              step2.dependencies.forEach((dep) => {
                output += `    ${dep} --> ${step2.id}
`;
              });
            }
          });
          break;
        case "graphviz":
          output = `digraph workflow {
`;
          output += `    rankdir=TB;
`;
          output += `    node [shape=box];
`;
          workflow.steps.forEach((step2) => {
            output += `    "${step2.id}" [label="${step2.name}"];
`;
            if (step2.dependencies) {
              step2.dependencies.forEach((dep) => {
                output += `    "${dep}" -> "${step2.id}";
`;
              });
            }
          });
          output += `}
`;
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
    } catch (error2) {
      return {
        success: false,
        error: error2.message
      };
    }
  }
});
const workflowAutomationTools = {
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

export { automationSetup, batchProcess, parallelExecute, pipelineCreate, triggerSetup, workflowAutomationTools, workflowCreate, workflowExecute, workflowExport, workflowSchedule, workflowTemplate };
//# sourceMappingURL=4d62bb0d-a2e6-4e54-a14a-651a91a732fc.mjs.map
