// Workflow executor for running node logic

import { EventEmitter } from 'events';
import { WorkflowNode, WorkflowContext, NodeType, MastraConfig } from '../types';
import { Mastra } from '@mastra/core';
import { Agent } from '@mastra/core';

export interface ExecutionResult {
  success: boolean;
  outputs?: Record<string, any>;
  error?: Error;
  duration: number;
}

export class WorkflowExecutor extends EventEmitter {
  private mastra?: Mastra;
  private nodeExecutors: Map<NodeType, NodeExecutor>;

  constructor(mastra?: Mastra) {
    super();
    this.mastra = mastra;
    this.nodeExecutors = this.initializeExecutors();
  }

  async executeNode(
    node: WorkflowNode,
    context: WorkflowContext,
    config?: MastraConfig
  ): Promise<ExecutionResult> {
    const startTime = Date.now();

    try {
      this.emit('node:start', { nodeId: node.id, type: node.type });

      const executor = this.nodeExecutors.get(node.type);
      if (!executor) {
        throw new Error(`No executor found for node type: ${node.type}`);
      }

      // Prepare inputs
      const inputs = this.resolveInputs(node, context);

      // Execute node with Mastra integration if configured
      let outputs: Record<string, any>;
      
      if (config && this.mastra) {
        outputs = await this.executeWithMastra(node, inputs, config);
      } else {
        outputs = await executor.execute(node, inputs, context);
      }

      // Store outputs in context
      context.nodeOutputs[node.id] = outputs;

      const duration = Date.now() - startTime;
      this.emit('node:complete', { 
        nodeId: node.id, 
        duration,
        outputs 
      });

      return { success: true, outputs, duration };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.emit('node:error', { 
        nodeId: node.id, 
        error,
        duration 
      });

      return { 
        success: false, 
        error: error as Error,
        duration 
      };
    }
  }

  private async executeWithMastra(
    node: WorkflowNode,
    inputs: Record<string, any>,
    config: MastraConfig
  ): Promise<Record<string, any>> {
    if (!this.mastra) {
      throw new Error('Mastra not initialized');
    }

    // Get or create agent
    const agent = config.agent ? 
      await this.mastra.getAgent(config.agent) :
      await this.createDefaultAgent(config);

    // Execute with agent
    const result = await agent.generate({
      messages: [{
        role: 'user',
        content: this.buildPrompt(node, inputs)
      }],
      tools: config.tools,
      model: config.model,
      stream: config.streaming
    });

    return {
      result: result.text,
      metadata: {
        model: config.model,
        usage: result.usage
      }
    };
  }

  private async createDefaultAgent(config: MastraConfig): Promise<Agent> {
    return new Agent({
      name: 'workflow-agent',
      instructions: 'Execute workflow tasks as directed',
      model: config.model || 'gpt-4',
      tools: config.tools || []
    });
  }

  private buildPrompt(node: WorkflowNode, inputs: Record<string, any>): string {
    return `
Execute the following task:
Node: ${node.label}
Type: ${node.type}
Inputs: ${JSON.stringify(inputs, null, 2)}
${node.data.prompt ? `Instructions: ${node.data.prompt}` : ''}
    `.trim();
  }

  private resolveInputs(
    node: WorkflowNode,
    context: WorkflowContext
  ): Record<string, any> {
    const inputs: Record<string, any> = {};

    if (node.inputs) {
      for (const input of node.inputs) {
        const value = this.resolveValue(
          input.defaultValue || node.data[input.name],
          context
        );
        inputs[input.name] = value;
      }
    }

    // Add node-specific data
    Object.assign(inputs, node.data);

    return inputs;
  }

  private resolveValue(value: any, context: WorkflowContext): any {
    if (typeof value === 'string' && value.startsWith('$.')) {
      // JSONPath resolution
      return this.resolveJsonPath(value, context);
    }
    
    if (typeof value === 'string' && value.includes('{{')) {
      // Template resolution
      return this.resolveTemplate(value, context);
    }

    return value;
  }

  private resolveJsonPath(path: string, context: WorkflowContext): any {
    const segments = path.substring(2).split('.');
    let current: any = context;

    for (const segment of segments) {
      if (current && typeof current === 'object') {
        current = current[segment];
      } else {
        return undefined;
      }
    }

    return current;
  }

  private resolveTemplate(template: string, context: WorkflowContext): string {
    return template.replace(/\{\{(.+?)\}\}/g, (match, path) => {
      const value = this.resolveJsonPath(`$.${path.trim()}`, context);
      return value !== undefined ? String(value) : match;
    });
  }

  private initializeExecutors(): Map<NodeType, NodeExecutor> {
    const executors = new Map<NodeType, NodeExecutor>();

    // Start node
    executors.set('start', {
      execute: async (node, inputs) => inputs
    });

    // End node
    executors.set('end', {
      execute: async (node, inputs, context) => {
        context.outputs = inputs;
        return inputs;
      }
    });

    // Task node
    executors.set('task', {
      execute: async (node, inputs) => {
        // Custom task execution logic
        if (node.data.handler) {
          const handler = new Function('inputs', 'context', node.data.handler);
          return await handler(inputs, {});
        }
        return inputs;
      }
    });

    // Transform node
    executors.set('transform', {
      execute: async (node, inputs) => {
        if (node.data.transform) {
          const transform = new Function('inputs', node.data.transform);
          return transform(inputs);
        }
        return inputs;
      }
    });

    // Timer node
    executors.set('timer', {
      execute: async (node, inputs) => {
        const delay = node.data.delay || 1000;
        await new Promise(resolve => setTimeout(resolve, delay));
        return inputs;
      }
    });

    // Event node
    executors.set('event', {
      execute: async (node, inputs) => {
        // Emit event
        this.emit('workflow:event', {
          type: node.data.eventType,
          payload: inputs
        });
        return inputs;
      }
    });

    // Decision node
    executors.set('decision', {
      execute: async (node, inputs) => {
        // Decision logic handled by workflow engine
        return inputs;
      }
    });

    // Parallel node
    executors.set('parallel', {
      execute: async (node, inputs) => {
        // Parallel execution handled by workflow engine
        return inputs;
      }
    });

    // Loop node
    executors.set('loop', {
      execute: async (node, inputs) => {
        // Loop logic handled by workflow engine
        return inputs;
      }
    });

    // Aggregate node
    executors.set('aggregate', {
      execute: async (node, inputs) => {
        if (Array.isArray(inputs)) {
          const aggregation = node.data.aggregation || 'merge';
          
          switch (aggregation) {
            case 'merge':
              return Object.assign({}, ...inputs);
            case 'concat':
              return inputs;
            case 'sum':
              return inputs.reduce((sum, item) => sum + (item.value || 0), 0);
            case 'average':
              const sum = inputs.reduce((sum, item) => sum + (item.value || 0), 0);
              return sum / inputs.length;
            default:
              return inputs;
          }
        }
        return inputs;
      }
    });

    // Custom node
    executors.set('custom', {
      execute: async (node, inputs) => {
        if (node.data.customHandler) {
          const handler = new Function('inputs', 'node', node.data.customHandler);
          return await handler(inputs, node);
        }
        return inputs;
      }
    });

    // Human task node (returns inputs, actual handling by engine)
    executors.set('humanTask', {
      execute: async (node, inputs) => inputs
    });

    // Subworkflow node (handled by engine)
    executors.set('subworkflow', {
      execute: async (node, inputs) => inputs
    });

    return executors;
  }
}

interface NodeExecutor {
  execute(
    node: WorkflowNode,
    inputs: Record<string, any>,
    context: WorkflowContext
  ): Promise<Record<string, any>>;
}