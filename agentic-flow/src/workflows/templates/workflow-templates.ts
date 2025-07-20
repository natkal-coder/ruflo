// Pre-built workflow templates for common patterns

import { WorkflowTemplate, WorkflowDefinition } from '../types';

export const workflowTemplates: WorkflowTemplate[] = [
  {
    id: 'sequential-tasks',
    name: 'Sequential Task Processing',
    description: 'Execute a series of tasks one after another',
    category: 'basic',
    parameters: [
      {
        name: 'tasks',
        type: 'array',
        description: 'List of tasks to execute sequentially',
        required: true
      }
    ],
    definition: {
      id: 'sequential-template',
      name: 'Sequential Tasks',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 100 },
          data: {}
        },
        {
          id: 'task-1',
          type: 'task',
          label: 'Task 1',
          position: { x: 300, y: 100 },
          data: {
            handler: 'return inputs;'
          }
        },
        {
          id: 'task-2',
          type: 'task',
          label: 'Task 2',
          position: { x: 500, y: 100 },
          data: {
            handler: 'return inputs;'
          }
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 700, y: 100 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'task-1' },
        { id: 'e2', source: 'task-1', target: 'task-2' },
        { id: 'e3', source: 'task-2', target: 'end' }
      ]
    },
    preview: `
    Start → Task 1 → Task 2 → End
    `
  },

  {
    id: 'parallel-processing',
    name: 'Parallel Task Processing',
    description: 'Execute multiple tasks in parallel and aggregate results',
    category: 'basic',
    parameters: [
      {
        name: 'branches',
        type: 'number',
        description: 'Number of parallel branches',
        defaultValue: 3,
        required: true
      },
      {
        name: 'aggregation',
        type: 'string',
        description: 'How to aggregate results (merge, concat, sum, average)',
        defaultValue: 'merge'
      }
    ],
    definition: {
      id: 'parallel-template',
      name: 'Parallel Processing',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 200 },
          data: {}
        },
        {
          id: 'split',
          type: 'parallel',
          label: 'Split',
          position: { x: 300, y: 200 },
          data: {}
        },
        {
          id: 'branch1',
          type: 'task',
          label: 'Branch 1',
          position: { x: 500, y: 100 },
          data: {}
        },
        {
          id: 'branch2',
          type: 'task',
          label: 'Branch 2',
          position: { x: 500, y: 200 },
          data: {}
        },
        {
          id: 'branch3',
          type: 'task',
          label: 'Branch 3',
          position: { x: 500, y: 300 },
          data: {}
        },
        {
          id: 'aggregate',
          type: 'aggregate',
          label: 'Aggregate',
          position: { x: 700, y: 200 },
          data: {
            aggregation: 'merge',
            inputNodes: ['branch1', 'branch2', 'branch3']
          }
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 900, y: 200 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'split' },
        { id: 'e2', source: 'split', target: 'branch1' },
        { id: 'e3', source: 'split', target: 'branch2' },
        { id: 'e4', source: 'split', target: 'branch3' },
        { id: 'e5', source: 'branch1', target: 'aggregate' },
        { id: 'e6', source: 'branch2', target: 'aggregate' },
        { id: 'e7', source: 'branch3', target: 'aggregate' },
        { id: 'e8', source: 'aggregate', target: 'end' }
      ]
    },
    preview: `
           ┌→ Branch 1 →┐
    Start →├→ Branch 2 →├→ Aggregate → End
           └→ Branch 3 →┘
    `
  },

  {
    id: 'conditional-flow',
    name: 'Conditional Workflow',
    description: 'Execute different paths based on conditions',
    category: 'control-flow',
    parameters: [
      {
        name: 'condition',
        type: 'string',
        description: 'Condition expression',
        required: true
      },
      {
        name: 'truePath',
        type: 'object',
        description: 'Configuration for true path',
        required: true
      },
      {
        name: 'falsePath',
        type: 'object',
        description: 'Configuration for false path',
        required: true
      }
    ],
    definition: {
      id: 'conditional-template',
      name: 'Conditional Flow',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 200 },
          data: {}
        },
        {
          id: 'decision',
          type: 'decision',
          label: 'Check Condition',
          position: { x: 300, y: 200 },
          data: {}
        },
        {
          id: 'true-path',
          type: 'task',
          label: 'True Path',
          position: { x: 500, y: 100 },
          data: {}
        },
        {
          id: 'false-path',
          type: 'task',
          label: 'False Path',
          position: { x: 500, y: 300 },
          data: {}
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 700, y: 200 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'decision' },
        { 
          id: 'e2', 
          source: 'decision', 
          target: 'true-path',
          condition: {
            type: 'expression',
            expression: 'context.inputs.value > 0'
          }
        },
        { 
          id: 'e3', 
          source: 'decision', 
          target: 'false-path',
          condition: {
            type: 'expression',
            expression: 'context.inputs.value <= 0'
          }
        },
        { id: 'e4', source: 'true-path', target: 'end' },
        { id: 'e5', source: 'false-path', target: 'end' }
      ]
    },
    preview: `
               ┌→ True Path →┐
    Start → Decision         → End
               └→ False Path →┘
    `
  },

  {
    id: 'retry-pattern',
    name: 'Retry Pattern',
    description: 'Retry failed tasks with exponential backoff',
    category: 'error-handling',
    parameters: [
      {
        name: 'maxAttempts',
        type: 'number',
        description: 'Maximum retry attempts',
        defaultValue: 3,
        required: true
      },
      {
        name: 'backoffDelay',
        type: 'number',
        description: 'Initial backoff delay in ms',
        defaultValue: 1000,
        required: true
      }
    ],
    definition: {
      id: 'retry-template',
      name: 'Retry Pattern',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 100 },
          data: {}
        },
        {
          id: 'task-with-retry',
          type: 'task',
          label: 'Task with Retry',
          position: { x: 300, y: 100 },
          data: {},
          config: {
            retryPolicy: {
              maxAttempts: 3,
              backoff: 'exponential',
              delay: 1000,
              maxDelay: 10000
            }
          }
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 500, y: 100 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'task-with-retry' },
        { id: 'e2', source: 'task-with-retry', target: 'end' }
      ]
    }
  },

  {
    id: 'human-approval',
    name: 'Human Approval Workflow',
    description: 'Workflow with human approval steps',
    category: 'human-in-loop',
    parameters: [
      {
        name: 'approvers',
        type: 'array',
        description: 'List of approvers',
        required: true
      },
      {
        name: 'approvalForm',
        type: 'object',
        description: 'Form configuration for approval',
        required: true
      }
    ],
    definition: {
      id: 'approval-template',
      name: 'Human Approval',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 200 },
          data: {}
        },
        {
          id: 'prepare',
          type: 'task',
          label: 'Prepare Request',
          position: { x: 300, y: 200 },
          data: {}
        },
        {
          id: 'approval',
          type: 'humanTask',
          label: 'Request Approval',
          position: { x: 500, y: 200 },
          data: {
            title: 'Approval Required',
            description: 'Please review and approve this request',
            form: {
              fields: [
                {
                  name: 'approved',
                  type: 'boolean',
                  label: 'Approve?',
                  required: true
                },
                {
                  name: 'comments',
                  type: 'text',
                  label: 'Comments'
                }
              ]
            }
          }
        },
        {
          id: 'check-approval',
          type: 'decision',
          label: 'Check Approval',
          position: { x: 700, y: 200 },
          data: {}
        },
        {
          id: 'approved',
          type: 'task',
          label: 'Process Approved',
          position: { x: 900, y: 100 },
          data: {}
        },
        {
          id: 'rejected',
          type: 'task',
          label: 'Handle Rejection',
          position: { x: 900, y: 300 },
          data: {}
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 1100, y: 200 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'prepare' },
        { id: 'e2', source: 'prepare', target: 'approval' },
        { id: 'e3', source: 'approval', target: 'check-approval' },
        {
          id: 'e4',
          source: 'check-approval',
          target: 'approved',
          condition: {
            type: 'expression',
            expression: 'context.nodeOutputs.approval.approved === true'
          }
        },
        {
          id: 'e5',
          source: 'check-approval',
          target: 'rejected',
          condition: {
            type: 'expression',
            expression: 'context.nodeOutputs.approval.approved === false'
          }
        },
        { id: 'e6', source: 'approved', target: 'end' },
        { id: 'e7', source: 'rejected', target: 'end' }
      ]
    }
  },

  {
    id: 'event-driven',
    name: 'Event-Driven Workflow',
    description: 'Workflow triggered and controlled by events',
    category: 'event-based',
    parameters: [
      {
        name: 'triggerEvent',
        type: 'string',
        description: 'Event type that triggers the workflow',
        required: true
      },
      {
        name: 'eventHandlers',
        type: 'array',
        description: 'List of event handlers',
        required: true
      }
    ],
    definition: {
      id: 'event-template',
      name: 'Event-Driven',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'event',
          label: 'Wait for Event',
          position: { x: 100, y: 100 },
          data: {
            eventType: 'workflow.trigger'
          }
        },
        {
          id: 'process',
          type: 'task',
          label: 'Process Event',
          position: { x: 300, y: 100 },
          data: {}
        },
        {
          id: 'emit',
          type: 'event',
          label: 'Emit Result',
          position: { x: 500, y: 100 },
          data: {
            eventType: 'workflow.result'
          }
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 700, y: 100 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'process' },
        { id: 'e2', source: 'process', target: 'emit' },
        { id: 'e3', source: 'emit', target: 'end' }
      ]
    }
  },

  {
    id: 'loop-pattern',
    name: 'Loop Pattern',
    description: 'Process items in a loop with conditions',
    category: 'control-flow',
    parameters: [
      {
        name: 'items',
        type: 'array',
        description: 'Items to process',
        required: true
      },
      {
        name: 'maxIterations',
        type: 'number',
        description: 'Maximum loop iterations',
        defaultValue: 100
      }
    ],
    definition: {
      id: 'loop-template',
      name: 'Loop Pattern',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 100 },
          data: {}
        },
        {
          id: 'loop',
          type: 'loop',
          label: 'Process Items',
          position: { x: 300, y: 100 },
          data: {
            condition: 'counter < context.inputs.items.length',
            maxIterations: 100
          }
        },
        {
          id: 'process-item',
          type: 'task',
          label: 'Process Item',
          position: { x: 500, y: 100 },
          data: {
            handler: `
              const item = context.inputs.items[context.loopCounters.loop];
              return { processed: item };
            `
          }
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 700, y: 100 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'loop' },
        { id: 'e2', source: 'loop', target: 'process-item' },
        { id: 'e3', source: 'process-item', target: 'loop' },
        { id: 'e4', source: 'loop', target: 'end', label: 'exit' }
      ]
    }
  },

  {
    id: 'map-reduce',
    name: 'Map-Reduce Pattern',
    description: 'Map operation over items and reduce results',
    category: 'data-processing',
    parameters: [
      {
        name: 'items',
        type: 'array',
        description: 'Items to map over',
        required: true
      },
      {
        name: 'mapFunction',
        type: 'string',
        description: 'Map function code',
        required: true
      },
      {
        name: 'reduceFunction',
        type: 'string',
        description: 'Reduce function code',
        required: true
      }
    ],
    definition: {
      id: 'map-reduce-template',
      name: 'Map-Reduce',
      version: '1.0.0',
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 200 },
          data: {}
        },
        {
          id: 'split-items',
          type: 'transform',
          label: 'Split Items',
          position: { x: 300, y: 200 },
          data: {
            transform: 'return inputs.items.map((item, i) => ({ id: i, item }));'
          }
        },
        {
          id: 'map',
          type: 'parallel',
          label: 'Map',
          position: { x: 500, y: 200 },
          data: {}
        },
        {
          id: 'reduce',
          type: 'aggregate',
          label: 'Reduce',
          position: { x: 700, y: 200 },
          data: {
            aggregation: 'custom',
            customAggregation: 'return inputs.reduce((acc, val) => acc + val, 0);'
          }
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 900, y: 200 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'split-items' },
        { id: 'e2', source: 'split-items', target: 'map' },
        { id: 'e3', source: 'map', target: 'reduce' },
        { id: 'e4', source: 'reduce', target: 'end' }
      ]
    }
  },

  {
    id: 'scheduled-workflow',
    name: 'Scheduled Workflow',
    description: 'Workflow with timer-based execution',
    category: 'scheduling',
    parameters: [
      {
        name: 'schedule',
        type: 'string',
        description: 'Cron expression or interval',
        required: true
      },
      {
        name: 'timezone',
        type: 'string',
        description: 'Timezone for schedule',
        defaultValue: 'UTC'
      }
    ],
    definition: {
      id: 'scheduled-template',
      name: 'Scheduled Workflow',
      version: '1.0.0',
      triggers: [
        {
          id: 'schedule-trigger',
          type: 'schedule',
          config: {
            cron: '0 0 * * *',
            timezone: 'UTC'
          }
        }
      ],
      nodes: [
        {
          id: 'start',
          type: 'start',
          label: 'Start',
          position: { x: 100, y: 100 },
          data: {}
        },
        {
          id: 'scheduled-task',
          type: 'task',
          label: 'Scheduled Task',
          position: { x: 300, y: 100 },
          data: {}
        },
        {
          id: 'end',
          type: 'end',
          label: 'End',
          position: { x: 500, y: 100 },
          data: {}
        }
      ],
      edges: [
        { id: 'e1', source: 'start', target: 'scheduled-task' },
        { id: 'e2', source: 'scheduled-task', target: 'end' }
      ]
    }
  }
];

export function getTemplateById(id: string): WorkflowTemplate | undefined {
  return workflowTemplates.find(t => t.id === id);
}

export function getTemplatesByCategory(category: string): WorkflowTemplate[] {
  return workflowTemplates.filter(t => t.category === category);
}

export function applyTemplate(
  template: WorkflowTemplate,
  parameters: Record<string, any>
): WorkflowDefinition {
  // Deep clone the template definition
  const definition = JSON.parse(JSON.stringify(template.definition)) as WorkflowDefinition;
  
  // Apply parameters
  if (template.id === 'sequential-tasks' && parameters.tasks) {
    // Generate nodes for each task
    definition.nodes = [
      definition.nodes[0], // start node
      ...parameters.tasks.map((task: any, index: number) => ({
        id: `task-${index + 1}`,
        type: 'task' as const,
        label: task.name || `Task ${index + 1}`,
        position: { x: 300 + index * 200, y: 100 },
        data: task
      })),
      definition.nodes[definition.nodes.length - 1] // end node
    ];

    // Generate edges
    definition.edges = [];
    for (let i = 0; i < definition.nodes.length - 1; i++) {
      definition.edges.push({
        id: `e${i + 1}`,
        source: definition.nodes[i].id,
        target: definition.nodes[i + 1].id
      });
    }
  }

  // Apply other template-specific parameter logic...

  return definition as WorkflowDefinition;
}