import require$$0 from 'lodash';
import require$$1, { v4 } from 'uuid';
import { EventEmitter } from 'events';
import fetch from 'node-fetch';
import * as vm from 'vm';
import { C as CoordinatorAgent, E as ExecutorAgent } from './index-DFloWDD9.js';
import '@mastra/core';
import 'eventemitter3';
import 'winston';
import 'natural';
import 'compromise';
import 'xstate';
import 'sqlite3';
import 'path';
import 'fs-extra';

class BaseStepExecutor extends EventEmitter {
  measureExecution(fn) {
    const startTime = Date.now();
    return fn().then((result) => ({
      result,
      duration: Date.now() - startTime
    }));
  }
}
class AgentTaskExecutor extends BaseStepExecutor {
  coordinatorAgent;
  executorAgent;
  activeAgents = /* @__PURE__ */ new Map();
  constructor() {
    super();
    this.coordinatorAgent = new CoordinatorAgent("workflow-coordinator");
    this.executorAgent = new ExecutorAgent("workflow-executor");
  }
  async execute(context) {
    const { step, execution } = context;
    const { agentType, goal, provider, capabilities, timeout = 3e4 } = step.config;
    try {
      const { result, duration } = await this.measureExecution(async () => {
        context.logger("info", `Spawning ${agentType} agent for goal: ${goal}`, step.id);
        const agentGoal = {
          id: v4(),
          type: agentType,
          description: goal,
          priority: "high",
          context: {
            workflowId: execution.workflowId,
            executionId: execution.id,
            stepId: step.id,
            variables: context.variables
          }
        };
        const agentId = await this.spawnAgent(agentType, capabilities);
        const taskResult = await this.executeAgentTask(agentId, agentGoal, timeout);
        await this.cleanupAgent(agentId);
        return {
          agentType,
          agentId,
          goal,
          result: taskResult,
          timestamp: /* @__PURE__ */ new Date(),
          provider
        };
      });
      context.logger("info", `Agent task completed successfully`, step.id);
      return { success: true, result, duration };
    } catch (error) {
      context.logger("error", `Agent task failed: ${error.message}`, step.id);
      return { success: false, error, duration: 0 };
    }
  }
  async spawnAgent(type, capabilities = []) {
    const agentId = v4();
    let agent;
    switch (type) {
      case "coordinator":
        agent = new CoordinatorAgent(`agent-${agentId}`);
        break;
      case "executor":
        agent = new ExecutorAgent(`agent-${agentId}`);
        break;
      default:
        agent = new ExecutorAgent(`agent-${agentId}`);
    }
    this.activeAgents.set(agentId, agent);
    this.emit("agent:spawned", { agentId, type, capabilities });
    return agentId;
  }
  async executeAgentTask(agentId, goal, timeout) {
    const agent = this.activeAgents.get(agentId);
    if (!agent) {
      throw new Error(`Agent ${agentId} not found`);
    }
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error("Agent task timeout")), timeout);
    });
    const executePromise = agent.addGoal(goal).then(() => {
      return new Promise((resolve) => {
        const checkCompletion = setInterval(() => {
          const goalStatus = agent.getGoalStatus?.(goal.id);
          if (goalStatus === "completed") {
            clearInterval(checkCompletion);
            resolve(agent.getGoalResult?.(goal.id) || { completed: true });
          } else if (goalStatus === "failed") {
            clearInterval(checkCompletion);
            throw new Error("Agent goal failed");
          }
        }, 1e3);
      });
    });
    return Promise.race([executePromise, timeoutPromise]);
  }
  async cleanupAgent(agentId) {
    const agent = this.activeAgents.get(agentId);
    if (agent) {
      if (agent.shutdown) {
        await agent.shutdown();
      }
      this.activeAgents.delete(agentId);
      this.emit("agent:cleanup", { agentId });
    }
  }
}
class ParallelExecutor extends BaseStepExecutor {
  async execute(context) {
    const { step, execution } = context;
    const { steps: parallelStepIds, maxConcurrency = 5 } = step.config;
    try {
      const { result, duration } = await this.measureExecution(async () => {
        context.logger("info", `Executing ${parallelStepIds.length} steps in parallel`, step.id);
        const workflow = await this.getWorkflowDefinition(execution.workflowId);
        const parallelSteps = parallelStepIds.map((stepId) => {
          const foundStep = workflow.steps.find((s) => s.id === stepId);
          if (!foundStep) {
            throw new Error(`Parallel step ${stepId} not found`);
          }
          return foundStep;
        });
        const results = await this.executeStepsWithConcurrency(
          parallelSteps,
          context,
          maxConcurrency
        );
        return {
          parallelResults: results,
          totalSteps: parallelSteps.length,
          successfulSteps: results.filter((r) => r.success).length,
          timestamp: /* @__PURE__ */ new Date()
        };
      });
      context.logger("info", `Parallel execution completed`, step.id);
      return { success: true, result, duration };
    } catch (error) {
      context.logger("error", `Parallel execution failed: ${error.message}`, step.id);
      return { success: false, error, duration: 0 };
    }
  }
  async executeStepsWithConcurrency(steps, context, maxConcurrency) {
    const results = [];
    const executing = /* @__PURE__ */ new Set();
    for (const step of steps) {
      if (executing.size >= maxConcurrency) {
        const completed = await Promise.race(executing);
        executing.delete(completed);
        results.push(await completed);
      }
      const stepPromise = this.executeStep(step, context);
      executing.add(stepPromise);
    }
    const remainingResults = await Promise.all(executing);
    results.push(...remainingResults);
    return results;
  }
  async executeStep(step, context) {
    const executor = StepExecutorFactory.getExecutor(step.type);
    return executor.execute({
      ...context,
      step
    });
  }
  async getWorkflowDefinition(workflowId) {
    return {
      id: workflowId,
      steps: []
    };
  }
}
class ConditionExecutor extends BaseStepExecutor {
  async execute(context) {
    const { step } = context;
    const { condition, trueStep, falseStep } = step.config;
    try {
      const { result, duration } = await this.measureExecution(async () => {
        context.logger("info", `Evaluating condition: ${condition}`, step.id);
        const evaluationContext = {
          variables: context.variables,
          results: context.results,
          Math,
          Date,
          JSON
        };
        const conditionResult = this.evaluateCondition(condition, evaluationContext);
        const nextStep = conditionResult ? trueStep : falseStep;
        context.logger("info", `Condition evaluated to: ${conditionResult}`, step.id);
        return {
          condition,
          result: conditionResult,
          nextStep,
          evaluationContext: Object.keys(evaluationContext),
          timestamp: /* @__PURE__ */ new Date()
        };
      });
      return { success: true, result, duration };
    } catch (error) {
      context.logger("error", `Condition evaluation failed: ${error.message}`, step.id);
      return { success: false, error, duration: 0 };
    }
  }
  evaluateCondition(condition, context) {
    try {
      const sandbox = vm.createContext(context);
      const script = new vm.Script(`(${condition})`);
      const result = script.runInContext(sandbox, { timeout: 5e3 });
      return Boolean(result);
    } catch (error) {
      throw new Error(`Condition evaluation error: ${error.message}`);
    }
  }
}
class LoopExecutor extends BaseStepExecutor {
  async execute(context) {
    const { step } = context;
    const { condition, loopStep, maxIterations = 100, breakCondition } = step.config;
    try {
      const { result, duration } = await this.measureExecution(async () => {
        context.logger("info", `Starting loop execution`, step.id);
        const results = [];
        let iterations = 0;
        while (iterations < maxIterations) {
          if (condition && !this.evaluateCondition(condition, context)) {
            break;
          }
          context.logger("info", `Loop iteration ${iterations + 1}`, step.id);
          const iterationResult = await this.executeLoopStep(loopStep, context, iterations);
          results.push(iterationResult);
          context.results[`${step.id}_iteration_${iterations}`] = iterationResult;
          iterations++;
          if (breakCondition && this.evaluateCondition(breakCondition, context)) {
            context.logger("info", `Loop break condition met`, step.id);
            break;
          }
        }
        context.logger("info", `Loop completed after ${iterations} iterations`, step.id);
        return {
          iterations,
          results,
          completedNormally: iterations < maxIterations,
          timestamp: /* @__PURE__ */ new Date()
        };
      });
      return { success: true, result, duration };
    } catch (error) {
      context.logger("error", `Loop execution failed: ${error.message}`, step.id);
      return { success: false, error, duration: 0 };
    }
  }
  evaluateCondition(condition, context) {
    new ConditionExecutor();
    try {
      const evalContext = {
        variables: context.variables,
        results: context.results
      };
      const sandbox = vm.createContext(evalContext);
      const script = new vm.Script(`(${condition})`);
      return Boolean(script.runInContext(sandbox, { timeout: 1e3 }));
    } catch {
      return false;
    }
  }
  async executeLoopStep(stepId, context, iteration) {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          stepId,
          iteration,
          result: `Loop iteration ${iteration} completed`,
          timestamp: /* @__PURE__ */ new Date()
        });
      }, 100);
    });
  }
}
class HttpExecutor extends BaseStepExecutor {
  async execute(context) {
    const { step } = context;
    const {
      method = "GET",
      url,
      headers = {},
      body,
      timeout = 3e4,
      retries = 3,
      retryDelay = 1e3
    } = step.config;
    try {
      const { result, duration } = await this.measureExecution(async () => {
        context.logger("info", `Making ${method} request to ${url}`, step.id);
        const resolvedUrl = this.resolveTemplate(url, context);
        const resolvedBody = body ? this.resolveTemplate(JSON.stringify(body), context) : void 0;
        const resolvedHeaders = this.resolveHeaders(headers, context);
        let lastError = null;
        for (let attempt = 0; attempt < retries; attempt++) {
          try {
            const response = await this.makeHttpRequest({
              method,
              url: resolvedUrl,
              headers: resolvedHeaders,
              body: resolvedBody,
              timeout
            });
            context.logger("info", `HTTP request successful (${response.status})`, step.id);
            return {
              status: response.status,
              statusText: response.statusText,
              headers: Object.fromEntries(response.headers.entries()),
              data: await response.json().catch(() => response.text()),
              url: resolvedUrl,
              method,
              attempt: attempt + 1,
              timestamp: /* @__PURE__ */ new Date()
            };
          } catch (error) {
            lastError = error;
            context.logger("warn", `HTTP request attempt ${attempt + 1} failed: ${error.message}`, step.id);
            if (attempt < retries - 1) {
              await new Promise((resolve) => setTimeout(resolve, retryDelay));
            }
          }
        }
        throw lastError || new Error("HTTP request failed after all retries");
      });
      return { success: true, result, duration };
    } catch (error) {
      context.logger("error", `HTTP request failed: ${error.message}`, step.id);
      return { success: false, error, duration: 0 };
    }
  }
  async makeHttpRequest(options) {
    const { method, url, headers, body, timeout } = options;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...headers
        },
        body: body ? body : void 0,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      throw error;
    }
  }
  resolveTemplate(template, context) {
    return template.replace(/\{\{(.+?)\}\}/g, (match, path) => {
      const value = this.resolvePath(path.trim(), context);
      return value !== void 0 ? String(value) : match;
    });
  }
  resolveHeaders(headers, context) {
    const resolved = {};
    for (const [key, value] of Object.entries(headers)) {
      resolved[key] = this.resolveTemplate(value, context);
    }
    return resolved;
  }
  resolvePath(path, context) {
    const segments = path.split(".");
    let current = {
      variables: context.variables,
      results: context.results
    };
    for (const segment of segments) {
      if (current && typeof current === "object") {
        current = current[segment];
      } else {
        return void 0;
      }
    }
    return current;
  }
}
class ScriptExecutor extends BaseStepExecutor {
  async execute(context) {
    const { step } = context;
    const { script, language = "javascript", timeout = 1e4, allowedModules = [] } = step.config;
    try {
      const { result, duration } = await this.measureExecution(async () => {
        context.logger("info", `Executing ${language} script`, step.id);
        if (language !== "javascript") {
          throw new Error(`Unsupported script language: ${language}`);
        }
        const sandbox = this.createSecureSandbox(context, allowedModules);
        const scriptResult = await this.executeScriptInSandbox(script, sandbox, timeout);
        context.logger("info", `Script execution completed`, step.id);
        return {
          language,
          result: scriptResult,
          allowedModules,
          timestamp: /* @__PURE__ */ new Date()
        };
      });
      return { success: true, result, duration };
    } catch (error) {
      context.logger("error", `Script execution failed: ${error.message}`, step.id);
      return { success: false, error, duration: 0 };
    }
  }
  createSecureSandbox(context, allowedModules) {
    const sandbox = {
      // Safe globals
      console: {
        log: (...args) => context.logger("info", args.join(" "), context.step.id),
        warn: (...args) => context.logger("warn", args.join(" "), context.step.id),
        error: (...args) => context.logger("error", args.join(" "), context.step.id)
      },
      Math,
      Date,
      JSON,
      Object,
      Array,
      String,
      Number,
      Boolean,
      // Workflow context
      variables: { ...context.variables },
      results: { ...context.results },
      // Allowed modules (restricted)
      require: (moduleName) => {
        if (!allowedModules.includes(moduleName)) {
          throw new Error(`Module '${moduleName}' is not allowed`);
        }
        switch (moduleName) {
          case "lodash":
            return require$$0;
          case "uuid":
            return require$$1;
          default:
            throw new Error(`Module '${moduleName}' is not available`);
        }
      },
      // Utility functions
      setTimeout: (fn, delay) => {
        if (delay > 5e3) throw new Error("Timeout too long");
        return setTimeout(fn, delay);
      }
    };
    return vm.createContext(sandbox);
  }
  async executeScriptInSandbox(script, sandbox, timeout) {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        reject(new Error("Script execution timeout"));
      }, timeout);
      try {
        const vmScript = new vm.Script(`
          (async function() {
            ${script}
          })()
        `);
        const result = vmScript.runInContext(sandbox, {
          timeout,
          breakOnSigint: true
        });
        if (result && typeof result.then === "function") {
          result.then((asyncResult) => {
            clearTimeout(timeoutId);
            resolve(asyncResult);
          }).catch((error) => {
            clearTimeout(timeoutId);
            reject(error);
          });
        } else {
          clearTimeout(timeoutId);
          resolve(result);
        }
      } catch (error) {
        clearTimeout(timeoutId);
        reject(error);
      }
    });
  }
}
class StepExecutorFactory {
  static executors = /* @__PURE__ */ new Map();
  static initialize() {
    this.executors.set("agent-task", new AgentTaskExecutor());
    this.executors.set("parallel", new ParallelExecutor());
    this.executors.set("condition", new ConditionExecutor());
    this.executors.set("loop", new LoopExecutor());
    this.executors.set("http", new HttpExecutor());
    this.executors.set("script", new ScriptExecutor());
  }
  static getExecutor(stepType) {
    const executor = this.executors.get(stepType);
    if (!executor) {
      throw new Error(`No executor found for step type: ${stepType}`);
    }
    return executor;
  }
  static registerExecutor(stepType, executor) {
    this.executors.set(stepType, executor);
  }
}
StepExecutorFactory.initialize();

export { AgentTaskExecutor, BaseStepExecutor, ConditionExecutor, HttpExecutor, LoopExecutor, ParallelExecutor, ScriptExecutor, StepExecutorFactory };
