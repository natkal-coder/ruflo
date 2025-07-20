// Converts workflow definitions to XState machines

import { 
  createMachine, 
  StateNodeConfig, 
  MachineConfig,
  assign,
  send,
  sendParent
} from 'xstate';
import {
  WorkflowDefinition,
  WorkflowNode,
  WorkflowEdge,
  XStateWorkflowConfig,
  NodeType,
  WorkflowCondition
} from '../types';

export class WorkflowConverter {
  convert(definition: WorkflowDefinition): XStateWorkflowConfig {
    const states = this.buildStates(definition);
    const guards = this.buildGuards(definition);
    const actions = this.buildActions(definition);
    const services = this.buildServices(definition);

    const machine = createMachine({
      id: definition.id,
      initial: this.findStartNode(definition.nodes)?.id || 'start',
      context: {
        inputs: {},
        variables: {},
        outputs: {},
        nodeOutputs: {},
        metadata: {}
      },
      states
    });

    return {
      machine,
      guards,
      actions,
      services
    };
  }

  toXState(definition: WorkflowDefinition): XStateWorkflowConfig {
    return this.convert(definition);
  }

  private buildStates(definition: WorkflowDefinition): Record<string, StateNodeConfig<any, any, any>> {
    const states: Record<string, StateNodeConfig<any, any, any>> = {};
    
    for (const node of definition.nodes) {
      states[node.id] = this.convertNode(node, definition);
    }

    return states;
  }

  private convertNode(
    node: WorkflowNode, 
    definition: WorkflowDefinition
  ): StateNodeConfig<any, any, any> {
    const outgoingEdges = definition.edges.filter(e => e.source === node.id);
    
    switch (node.type) {
      case 'start':
        return this.createStartState(node, outgoingEdges);
      
      case 'end':
        return this.createEndState(node);
      
      case 'task':
        return this.createTaskState(node, outgoingEdges);
      
      case 'decision':
        return this.createDecisionState(node, outgoingEdges);
      
      case 'parallel':
        return this.createParallelState(node, outgoingEdges, definition);
      
      case 'loop':
        return this.createLoopState(node, outgoingEdges, definition);
      
      case 'humanTask':
        return this.createHumanTaskState(node, outgoingEdges);
      
      case 'timer':
        return this.createTimerState(node, outgoingEdges);
      
      case 'event':
        return this.createEventState(node, outgoingEdges);
      
      case 'subworkflow':
        return this.createSubworkflowState(node, outgoingEdges);
      
      case 'transform':
        return this.createTransformState(node, outgoingEdges);
      
      case 'aggregate':
        return this.createAggregateState(node, outgoingEdges);
      
      case 'custom':
        return this.createCustomState(node, outgoingEdges);
      
      default:
        return this.createDefaultState(node, outgoingEdges);
    }
  }

  private createStartState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      entry: 'initializeWorkflow',
      always: this.createTransitions(edges)
    };
  }

  private createEndState(node: WorkflowNode): StateNodeConfig<any, any, any> {
    return {
      type: 'final',
      entry: 'finalizeWorkflow'
    };
  }

  private createTaskState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      invoke: {
        id: `task-${node.id}`,
        src: `executeTask-${node.id}`,
        onDone: {
          target: edges[0]?.target,
          actions: assign({
            nodeOutputs: (context: any, event: any) => ({
              ...context.nodeOutputs,
              [node.id]: event.data
            })
          })
        },
        onError: {
          target: '#error',
          actions: 'logError'
        }
      },
      meta: {
        node
      }
    };
  }

  private createDecisionState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    const transitions: any = {};

    for (const edge of edges) {
      if (edge.condition) {
        transitions[edge.id] = {
          target: edge.target,
          cond: `condition-${edge.id}`
        };
      }
    }

    // Default transition if no conditions match
    const defaultEdge = edges.find(e => !e.condition);
    if (defaultEdge) {
      transitions.DEFAULT = {
        target: defaultEdge.target
      };
    }

    return {
      type: 'atomic',
      on: transitions,
      always: Object.values(transitions)
    };
  }

  private createParallelState(
    node: WorkflowNode,
    edges: WorkflowEdge[],
    definition: WorkflowDefinition
  ): StateNodeConfig<any, any, any> {
    const parallelStates: Record<string, StateNodeConfig<any, any, any>> = {};
    
    // Find all branches from this parallel node
    const branches = edges.filter(e => e.source === node.id);
    
    for (let i = 0; i < branches.length; i++) {
      const branch = branches[i];
      const branchStates = this.buildBranchStates(branch.target, definition);
      parallelStates[`branch${i}`] = {
        initial: branch.target,
        states: branchStates
      };
    }

    return {
      type: 'parallel',
      states: parallelStates,
      onDone: {
        target: this.findJoinNode(node, definition),
        actions: 'mergeParallelOutputs'
      }
    };
  }

  private createLoopState(
    node: WorkflowNode,
    edges: WorkflowEdge[],
    definition: WorkflowDefinition
  ): StateNodeConfig<any, any, any> {
    const loopBody = edges.find(e => e.label !== 'exit')?.target;
    const exitTarget = edges.find(e => e.label === 'exit')?.target;

    return {
      type: 'compound',
      initial: 'check',
      states: {
        check: {
          always: [
            {
              target: 'body',
              cond: `loopCondition-${node.id}`
            },
            {
              target: '#' + exitTarget
            }
          ]
        },
        body: {
          initial: loopBody,
          states: this.buildBranchStates(loopBody!, definition),
          onDone: {
            target: 'check',
            actions: 'updateLoopCounter'
          }
        }
      }
    };
  }

  private createHumanTaskState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      entry: 'createHumanTask',
      on: {
        HUMAN_TASK_COMPLETE: {
          target: edges[0]?.target,
          actions: assign({
            nodeOutputs: (context: any, event: any) => ({
              ...context.nodeOutputs,
              [node.id]: event.response
            })
          })
        }
      },
      meta: {
        humanTask: {
          title: node.data.title,
          description: node.data.description,
          assignee: node.data.assignee,
          form: node.data.form
        }
      }
    };
  }

  private createTimerState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      after: {
        [node.data.delay || 1000]: {
          target: edges[0]?.target
        }
      }
    };
  }

  private createEventState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      on: {
        [node.data.eventType]: {
          target: edges[0]?.target,
          actions: assign({
            nodeOutputs: (context: any, event: any) => ({
              ...context.nodeOutputs,
              [node.id]: event.payload
            })
          })
        }
      }
    };
  }

  private createSubworkflowState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      invoke: {
        id: `subworkflow-${node.id}`,
        src: `executeSubworkflow-${node.id}`,
        data: {
          workflowId: node.data.workflowId,
          inputs: (context: any) => context.nodeOutputs[node.data.inputNode] || {}
        },
        onDone: {
          target: edges[0]?.target,
          actions: assign({
            nodeOutputs: (context: any, event: any) => ({
              ...context.nodeOutputs,
              [node.id]: event.data
            })
          })
        },
        onError: {
          target: '#error',
          actions: 'logError'
        }
      }
    };
  }

  private createTransformState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      entry: [
        assign({
          nodeOutputs: (context: any) => {
            const transform = new Function('inputs', 'context', node.data.transform);
            const inputs = context.nodeOutputs[node.data.inputNode] || {};
            return {
              ...context.nodeOutputs,
              [node.id]: transform(inputs, context)
            };
          }
        })
      ],
      always: {
        target: edges[0]?.target
      }
    };
  }

  private createAggregateState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      entry: 'aggregateOutputs',
      always: {
        target: edges[0]?.target
      },
      meta: {
        aggregation: node.data.aggregation || 'merge'
      }
    };
  }

  private createCustomState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      invoke: {
        id: `custom-${node.id}`,
        src: `executeCustom-${node.id}`,
        onDone: {
          target: edges[0]?.target,
          actions: assign({
            nodeOutputs: (context: any, event: any) => ({
              ...context.nodeOutputs,
              [node.id]: event.data
            })
          })
        },
        onError: {
          target: '#error',
          actions: 'logError'
        }
      },
      meta: {
        node
      }
    };
  }

  private createDefaultState(
    node: WorkflowNode,
    edges: WorkflowEdge[]
  ): StateNodeConfig<any, any, any> {
    return {
      type: 'atomic',
      always: {
        target: edges[0]?.target
      }
    };
  }

  private createTransitions(edges: WorkflowEdge[]): any[] {
    return edges.map(edge => ({
      target: edge.target,
      cond: edge.condition ? `condition-${edge.id}` : undefined
    }));
  }

  private buildBranchStates(
    startNodeId: string,
    definition: WorkflowDefinition
  ): Record<string, StateNodeConfig<any, any, any>> {
    const states: Record<string, StateNodeConfig<any, any, any>> = {};
    const visited = new Set<string>();
    const queue = [startNodeId];

    while (queue.length > 0) {
      const nodeId = queue.shift()!;
      if (visited.has(nodeId)) continue;
      
      visited.add(nodeId);
      const node = definition.nodes.find(n => n.id === nodeId);
      
      if (node) {
        states[nodeId] = this.convertNode(node, definition);
        
        const outgoingEdges = definition.edges.filter(e => e.source === nodeId);
        for (const edge of outgoingEdges) {
          if (!visited.has(edge.target)) {
            queue.push(edge.target);
          }
        }
      }
    }

    return states;
  }

  private buildGuards(definition: WorkflowDefinition): Record<string, Function> {
    const guards: Record<string, Function> = {};

    // Build condition guards for edges
    for (const edge of definition.edges) {
      if (edge.condition) {
        guards[`condition-${edge.id}`] = this.createConditionGuard(edge.condition);
      }
    }

    // Build loop condition guards
    for (const node of definition.nodes) {
      if (node.type === 'loop') {
        guards[`loopCondition-${node.id}`] = this.createLoopGuard(node);
      }
    }

    return guards;
  }

  private createConditionGuard(condition: WorkflowCondition): Function {
    return (context: any, event: any) => {
      switch (condition.type) {
        case 'expression':
          return new Function('context', 'event', `return ${condition.expression}`)(context, event);
        
        case 'comparison':
          const left = this.resolveValue(condition.left, context);
          const right = this.resolveValue(condition.right, context);
          return this.compare(left, condition.operator!, right);
        
        case 'function':
          return new Function('context', 'event', condition.function!)(context, event);
        
        default:
          return true;
      }
    };
  }

  private createLoopGuard(node: WorkflowNode): Function {
    return (context: any) => {
      const maxIterations = node.data.maxIterations || 100;
      const counter = context.loopCounters?.[node.id] || 0;
      
      if (node.data.condition) {
        return new Function('context', 'counter', node.data.condition)(context, counter);
      }
      
      return counter < maxIterations;
    };
  }

  private compare(left: any, operator: string, right: any): boolean {
    switch (operator) {
      case '==': return left == right;
      case '!=': return left != right;
      case '>': return left > right;
      case '<': return left < right;
      case '>=': return left >= right;
      case '<=': return left <= right;
      case 'contains': return String(left).includes(String(right));
      case 'startsWith': return String(left).startsWith(String(right));
      case 'endsWith': return String(left).endsWith(String(right));
      case 'matches': return new RegExp(right).test(String(left));
      default: return false;
    }
  }

  private resolveValue(value: any, context: any): any {
    if (typeof value === 'string' && value.startsWith('$.')) {
      const path = value.substring(2).split('.');
      let current = context;
      
      for (const segment of path) {
        current = current?.[segment];
      }
      
      return current;
    }
    
    return value;
  }

  private buildActions(definition: WorkflowDefinition): Record<string, Function> {
    return {
      initializeWorkflow: assign({
        metadata: () => ({
          startTime: new Date(),
          workflowId: definition.id,
          workflowName: definition.name
        })
      }),

      finalizeWorkflow: assign({
        metadata: (context: any) => ({
          ...context.metadata,
          endTime: new Date(),
          duration: Date.now() - context.metadata.startTime.getTime()
        })
      }),

      logError: (context: any, event: any) => {
        console.error('Workflow error:', event.data);
      },

      updateLoopCounter: assign({
        loopCounters: (context: any, event: any, { state }: any) => {
          const nodeId = state.value;
          return {
            ...context.loopCounters,
            [nodeId]: (context.loopCounters?.[nodeId] || 0) + 1
          };
        }
      }),

      mergeParallelOutputs: assign({
        nodeOutputs: (context: any, event: any) => {
          const merged: any = {};
          
          for (const branchData of event.data) {
            Object.assign(merged, branchData);
          }
          
          return {
            ...context.nodeOutputs,
            ...merged
          };
        }
      }),

      aggregateOutputs: assign({
        nodeOutputs: (context: any, event: any, { state }: any) => {
          const node = state.meta?.node;
          if (!node) return context.nodeOutputs;

          const inputNodes = node.data.inputNodes || [];
          const inputs = inputNodes.map((nodeId: string) => context.nodeOutputs[nodeId]);
          
          const aggregation = state.meta?.aggregation || 'merge';
          let result: any;

          switch (aggregation) {
            case 'merge':
              result = Object.assign({}, ...inputs);
              break;
            case 'concat':
              result = inputs.flat();
              break;
            case 'sum':
              result = inputs.reduce((sum: number, val: any) => sum + (val || 0), 0);
              break;
            case 'average':
              const sum = inputs.reduce((sum: number, val: any) => sum + (val || 0), 0);
              result = sum / inputs.length;
              break;
            default:
              result = inputs;
          }

          return {
            ...context.nodeOutputs,
            [node.id]: result
          };
        }
      }),

      createHumanTask: (context: any, event: any, { state }: any) => {
        // Human task creation handled by the engine
        console.log('Creating human task:', state.meta?.humanTask);
      }
    };
  }

  private buildServices(definition: WorkflowDefinition): Record<string, Function> {
    const services: Record<string, Function> = {};

    for (const node of definition.nodes) {
      if (node.type === 'task' || node.type === 'custom') {
        services[`executeTask-${node.id}`] = async (context: any) => {
          // Task execution handled by WorkflowExecutor
          return { success: true };
        };
      }

      if (node.type === 'subworkflow') {
        services[`executeSubworkflow-${node.id}`] = async (context: any, event: any) => {
          // Subworkflow execution handled by engine
          return { success: true };
        };
      }
    }

    return services;
  }

  private findStartNode(nodes: WorkflowNode[]): WorkflowNode | undefined {
    return nodes.find(n => n.type === 'start');
  }

  private findJoinNode(parallelNode: WorkflowNode, definition: WorkflowDefinition): string {
    // Find the node where parallel branches converge
    const parallelEdges = definition.edges.filter(e => e.source === parallelNode.id);
    const branchTargets = parallelEdges.map(e => e.target);
    
    // Follow each branch to find common target
    // This is a simplified version - in production, use graph algorithms
    for (const edge of definition.edges) {
      if (branchTargets.includes(edge.source)) {
        return edge.target;
      }
    }
    
    return 'end';
  }
}