/**
 * Workflow-related MCP tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { WorkflowEngine } from '../core/workflow-engine';
import {
  WorkflowCreateSchema,
  WorkflowExecuteSchema,
  ToolResponse,
  StepType,
  TriggerType,
  WorkflowStatus
} from '../types';
import { logger } from '../utils/logger';

export class WorkflowTools {
  constructor(private workflowEngine: WorkflowEngine) {}

  /**
   * Get all workflow-related tools
   */
  getTools(): Tool[] {
    return [
      this.getWorkflowCreateTool(),
      this.getWorkflowExecuteTool(),
      this.getWorkflowListTool(),
      this.getWorkflowStatusTool(),
      this.getWorkflowDeleteTool(),
      this.getWorkflowExecutionTool(),
      this.getWorkflowTemplateTool()
    ];
  }

  /**
   * Workflow create tool
   */
  private getWorkflowCreateTool(): Tool {
    return {
      name: 'workflow_create',
      description: 'Create a new workflow with defined steps and triggers',
      inputSchema: {
        type: 'object',
        properties: {
          name: {
            type: 'string',
            description: 'Name of the workflow'
          },
          description: {
            type: 'string',
            description: 'Description of what the workflow does'
          },
          steps: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                name: {
                  type: 'string',
                  description: 'Name of the step'
                },
                type: {
                  type: 'string',
                  enum: Object.values(StepType),
                  description: 'Type of step'
                },
                config: {
                  type: 'object',
                  description: 'Step configuration'
                },
                dependencies: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'IDs of steps this step depends on'
                },
                timeout: {
                  type: 'number',
                  description: 'Timeout in milliseconds'
                }
              },
              required: ['name', 'type', 'config']
            },
            description: 'Array of workflow steps'
          },
          triggers: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                type: {
                  type: 'string',
                  enum: Object.values(TriggerType),
                  description: 'Type of trigger'
                },
                config: {
                  type: 'object',
                  description: 'Trigger configuration'
                }
              },
              required: ['type', 'config']
            },
            description: 'Array of workflow triggers'
          }
        },
        required: ['name', 'description', 'steps']
      }
    };
  }

  /**
   * Workflow execute tool
   */
  private getWorkflowExecuteTool(): Tool {
    return {
      name: 'workflow_execute',
      description: 'Execute a workflow with optional parameters',
      inputSchema: {
        type: 'object',
        properties: {
          workflowId: {
            type: 'string',
            description: 'ID of the workflow to execute'
          },
          params: {
            type: 'object',
            description: 'Parameters to pass to the workflow'
          },
          async: {
            type: 'boolean',
            description: 'Whether to execute asynchronously',
            default: true
          }
        },
        required: ['workflowId']
      }
    };
  }

  /**
   * Workflow list tool
   */
  private getWorkflowListTool(): Tool {
    return {
      name: 'workflow_list',
      description: 'List all workflows or filter by status',
      inputSchema: {
        type: 'object',
        properties: {
          status: {
            type: 'string',
            enum: Object.values(WorkflowStatus),
            description: 'Filter workflows by status'
          }
        }
      }
    };
  }

  /**
   * Workflow status tool
   */
  private getWorkflowStatusTool(): Tool {
    return {
      name: 'workflow_status',
      description: 'Get detailed status of a workflow',
      inputSchema: {
        type: 'object',
        properties: {
          workflowId: {
            type: 'string',
            description: 'ID of the workflow'
          }
        },
        required: ['workflowId']
      }
    };
  }

  /**
   * Workflow delete tool
   */
  private getWorkflowDeleteTool(): Tool {
    return {
      name: 'workflow_delete',
      description: 'Delete a workflow and its execution history',
      inputSchema: {
        type: 'object',
        properties: {
          workflowId: {
            type: 'string',
            description: 'ID of the workflow to delete'
          }
        },
        required: ['workflowId']
      }
    };
  }

  /**
   * Workflow execution tool
   */
  private getWorkflowExecutionTool(): Tool {
    return {
      name: 'workflow_execution',
      description: 'Get details of a workflow execution',
      inputSchema: {
        type: 'object',
        properties: {
          executionId: {
            type: 'string',
            description: 'ID of the workflow execution'
          }
        },
        required: ['executionId']
      }
    };
  }

  /**
   * Workflow template tool
   */
  private getWorkflowTemplateTool(): Tool {
    return {
      name: 'workflow_template',
      description: 'Create workflow from predefined templates',
      inputSchema: {
        type: 'object',
        properties: {
          template: {
            type: 'string',
            enum: [
              'data_pipeline',
              'ci_cd',
              'testing_suite',
              'deployment',
              'monitoring',
              'ml_training'
            ],
            description: 'Template type to create'
          },
          name: {
            type: 'string',
            description: 'Name for the new workflow'
          },
          config: {
            type: 'object',
            description: 'Template-specific configuration'
          }
        },
        required: ['template', 'name']
      }
    };
  }

  /**
   * Handle tool calls
   */
  async handleToolCall(name: string, args: any): Promise<ToolResponse> {
    try {
      switch (name) {
        case 'workflow_create':
          return await this.handleWorkflowCreate(args);
        case 'workflow_execute':
          return await this.handleWorkflowExecute(args);
        case 'workflow_list':
          return await this.handleWorkflowList(args);
        case 'workflow_status':
          return await this.handleWorkflowStatus(args);
        case 'workflow_delete':
          return await this.handleWorkflowDelete(args);
        case 'workflow_execution':
          return await this.handleWorkflowExecution(args);
        case 'workflow_template':
          return await this.handleWorkflowTemplate(args);
        default:
          throw new Error(`Unknown workflow tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Workflow tool error: ${name} - ${error}`);
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Handle workflow creation
   */
  private async handleWorkflowCreate(args: any): Promise<ToolResponse> {
    const validated = WorkflowCreateSchema.parse(args);

    const workflow = await this.workflowEngine.createWorkflow(
      validated.name,
      validated.description,
      validated.steps.map(step => ({ ...step, dependencies: step.dependencies || [] })),
      validated.triggers
    );

    return {
      success: true,
      data: {
        workflow: {
          id: workflow.id,
          name: workflow.name,
          description: workflow.description,
          status: workflow.status,
          stepCount: workflow.steps.length,
          triggerCount: workflow.triggers.length,
          createdAt: workflow.createdAt
        }
      },
      metadata: {
        operation: 'workflow_create',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle workflow execution
   */
  private async handleWorkflowExecute(args: any): Promise<ToolResponse> {
    const validated = WorkflowExecuteSchema.parse(args);

    const execution = await this.workflowEngine.executeWorkflow(
      validated.workflowId,
      validated.params,
      validated.async
    );

    return {
      success: true,
      data: {
        execution: {
          id: execution.id,
          workflowId: execution.workflowId,
          status: execution.status,
          startedAt: execution.startedAt,
          completedAt: execution.completedAt
        }
      },
      metadata: {
        operation: 'workflow_execute',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle workflow listing
   */
  private async handleWorkflowList(args: any): Promise<ToolResponse> {
    let workflows = this.workflowEngine.getAllWorkflows();

    // Apply status filter
    if (args.status) {
      workflows = workflows.filter(workflow => workflow.status === args.status);
    }

    const workflowSummaries = workflows.map(workflow => ({
      id: workflow.id,
      name: workflow.name,
      description: workflow.description,
      status: workflow.status,
      stepCount: workflow.steps.length,
      triggerCount: workflow.triggers.length,
      executionCount: workflow.executionHistory.length,
      createdAt: workflow.createdAt
    }));

    return {
      success: true,
      data: {
        workflows: workflowSummaries,
        count: workflowSummaries.length
      },
      metadata: {
        operation: 'workflow_list',
        timestamp: new Date().toISOString(),
        filters: { status: args.status }
      }
    };
  }

  /**
   * Handle workflow status
   */
  private async handleWorkflowStatus(args: any): Promise<ToolResponse> {
    const workflow = this.workflowEngine.getWorkflow(args.workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${args.workflowId} not found`);
    }

    const recentExecutions = workflow.executionHistory
      .slice(-5)
      .map(exec => ({
        id: exec.id,
        status: exec.status,
        startedAt: exec.startedAt,
        completedAt: exec.completedAt,
        duration: exec.completedAt ? exec.completedAt.getTime() - exec.startedAt.getTime() : null
      }));

    return {
      success: true,
      data: {
        workflow: {
          id: workflow.id,
          name: workflow.name,
          description: workflow.description,
          status: workflow.status,
          steps: workflow.steps.map(step => ({
            id: step.id,
            name: step.name,
            type: step.type,
            dependencies: step.dependencies || []
          })),
          triggers: workflow.triggers,
          totalExecutions: workflow.executionHistory.length,
          recentExecutions,
          createdAt: workflow.createdAt
        }
      },
      metadata: {
        operation: 'workflow_status',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle workflow deletion
   */
  private async handleWorkflowDelete(args: any): Promise<ToolResponse> {
    const workflow = this.workflowEngine.getWorkflow(args.workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${args.workflowId} not found`);
    }

    this.workflowEngine.deleteWorkflow(args.workflowId);

    return {
      success: true,
      data: {
        deletedWorkflow: {
          id: workflow.id,
          name: workflow.name
        }
      },
      metadata: {
        operation: 'workflow_delete',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle workflow execution status
   */
  private async handleWorkflowExecution(args: any): Promise<ToolResponse> {
    const execution = this.workflowEngine.getExecution(args.executionId);
    if (!execution) {
      throw new Error(`Workflow execution ${args.executionId} not found`);
    }

    return {
      success: true,
      data: {
        execution: {
          id: execution.id,
          workflowId: execution.workflowId,
          status: execution.status,
          startedAt: execution.startedAt,
          completedAt: execution.completedAt,
          duration: execution.completedAt ? 
            execution.completedAt.getTime() - execution.startedAt.getTime() : null,
          results: execution.results,
          errors: execution.errors?.map(err => err.message)
        }
      },
      metadata: {
        operation: 'workflow_execution',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle workflow template creation
   */
  private async handleWorkflowTemplate(args: any): Promise<ToolResponse> {
    const template = this.getWorkflowTemplate(args.template);
    const customizedTemplate = this.customizeTemplate(template, args.config || {});

    const workflow = await this.workflowEngine.createWorkflow(
      args.name,
      customizedTemplate.description,
      customizedTemplate.steps,
      customizedTemplate.triggers
    );

    return {
      success: true,
      data: {
        workflow: {
          id: workflow.id,
          name: workflow.name,
          description: workflow.description,
          template: args.template,
          stepCount: workflow.steps.length,
          createdAt: workflow.createdAt
        }
      },
      metadata: {
        operation: 'workflow_template',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Get predefined workflow templates
   */
  private getWorkflowTemplate(templateType: string): any {
    const templates: Record<string, any> = {
      data_pipeline: {
        description: 'Data processing pipeline with ETL operations',
        steps: [
          {
            name: 'Extract Data',
            type: StepType.AGENT_ACTION,
            config: { capability: 'data-extraction', action: 'extract' }
          },
          {
            name: 'Transform Data',
            type: StepType.AGENT_ACTION,
            config: { capability: 'data-transformation', action: 'transform' },
            dependencies: ['extract-data']
          },
          {
            name: 'Load Data',
            type: StepType.AGENT_ACTION,
            config: { capability: 'data-loading', action: 'load' },
            dependencies: ['transform-data']
          },
          {
            name: 'Validate Results',
            type: StepType.AGENT_ACTION,
            config: { capability: 'data-validation', action: 'validate' },
            dependencies: ['load-data']
          }
        ],
        triggers: [
          {
            type: TriggerType.SCHEDULE,
            config: { interval: 3600000 } // Hourly
          }
        ]
      },
      ci_cd: {
        description: 'Continuous Integration and Deployment pipeline',
        steps: [
          {
            name: 'Code Checkout',
            type: StepType.AGENT_ACTION,
            config: { capability: 'version-control', action: 'checkout' }
          },
          {
            name: 'Build',
            type: StepType.AGENT_ACTION,
            config: { capability: 'build-system', action: 'build' },
            dependencies: ['code-checkout']
          },
          {
            name: 'Test',
            type: StepType.PARALLEL,
            config: {
              steps: [
                {
                  name: 'Unit Tests',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'testing', action: 'unit-test' }
                },
                {
                  name: 'Integration Tests',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'testing', action: 'integration-test' }
                }
              ]
            },
            dependencies: ['build']
          },
          {
            name: 'Deploy',
            type: StepType.AGENT_ACTION,
            config: { capability: 'deployment', action: 'deploy' },
            dependencies: ['test']
          }
        ],
        triggers: [
          {
            type: TriggerType.WEBHOOK,
            config: { event: 'push', branch: 'main' }
          }
        ]
      },
      testing_suite: {
        description: 'Comprehensive testing workflow',
        steps: [
          {
            name: 'Setup Test Environment',
            type: StepType.AGENT_ACTION,
            config: { capability: 'environment-setup', action: 'setup' }
          },
          {
            name: 'Run Tests',
            type: StepType.PARALLEL,
            config: {
              steps: [
                {
                  name: 'Unit Tests',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'testing', action: 'unit' }
                },
                {
                  name: 'Integration Tests',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'testing', action: 'integration' }
                },
                {
                  name: 'E2E Tests',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'testing', action: 'e2e' }
                }
              ]
            },
            dependencies: ['setup-test-environment']
          },
          {
            name: 'Generate Report',
            type: StepType.AGENT_ACTION,
            config: { capability: 'reporting', action: 'test-report' },
            dependencies: ['run-tests']
          },
          {
            name: 'Cleanup',
            type: StepType.AGENT_ACTION,
            config: { capability: 'cleanup', action: 'teardown' },
            dependencies: ['generate-report']
          }
        ],
        triggers: []
      },
      deployment: {
        description: 'Application deployment workflow',
        steps: [
          {
            name: 'Pre-deployment Checks',
            type: StepType.AGENT_ACTION,
            config: { capability: 'validation', action: 'pre-deploy-check' }
          },
          {
            name: 'Deploy to Staging',
            type: StepType.AGENT_ACTION,
            config: { capability: 'deployment', action: 'deploy-staging' },
            dependencies: ['pre-deployment-checks']
          },
          {
            name: 'Staging Tests',
            type: StepType.AGENT_ACTION,
            config: { capability: 'testing', action: 'staging-test' },
            dependencies: ['deploy-to-staging']
          },
          {
            name: 'Deploy to Production',
            type: StepType.AGENT_ACTION,
            config: { capability: 'deployment', action: 'deploy-production' },
            dependencies: ['staging-tests']
          },
          {
            name: 'Post-deployment Monitoring',
            type: StepType.AGENT_ACTION,
            config: { capability: 'monitoring', action: 'post-deploy-monitor' },
            dependencies: ['deploy-to-production']
          }
        ],
        triggers: []
      },
      monitoring: {
        description: 'System monitoring and alerting workflow',
        steps: [
          {
            name: 'Collect Metrics',
            type: StepType.PARALLEL,
            config: {
              steps: [
                {
                  name: 'System Metrics',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'monitoring', action: 'system-metrics' }
                },
                {
                  name: 'Application Metrics',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'monitoring', action: 'app-metrics' }
                },
                {
                  name: 'Business Metrics',
                  type: StepType.AGENT_ACTION,
                  config: { capability: 'monitoring', action: 'business-metrics' }
                }
              ]
            }
          },
          {
            name: 'Analyze Metrics',
            type: StepType.AGENT_ACTION,
            config: { capability: 'analytics', action: 'analyze' },
            dependencies: ['collect-metrics']
          },
          {
            name: 'Check Thresholds',
            type: StepType.CONDITIONAL,
            config: {
              condition: 'metrics.anomaly_detected',
              ifTrue: {
                name: 'Send Alert',
                type: StepType.AGENT_ACTION,
                config: { capability: 'alerting', action: 'send-alert' }
              }
            },
            dependencies: ['analyze-metrics']
          }
        ],
        triggers: [
          {
            type: TriggerType.SCHEDULE,
            config: { interval: 300000 } // Every 5 minutes
          }
        ]
      },
      ml_training: {
        description: 'Machine learning model training pipeline',
        steps: [
          {
            name: 'Data Preparation',
            type: StepType.AGENT_ACTION,
            config: { capability: 'data-prep', action: 'prepare' }
          },
          {
            name: 'Feature Engineering',
            type: StepType.AGENT_ACTION,
            config: { capability: 'feature-engineering', action: 'engineer' },
            dependencies: ['data-preparation']
          },
          {
            name: 'Model Training',
            type: StepType.AGENT_ACTION,
            config: { capability: 'ml-training', action: 'train' },
            dependencies: ['feature-engineering']
          },
          {
            name: 'Model Evaluation',
            type: StepType.AGENT_ACTION,
            config: { capability: 'ml-evaluation', action: 'evaluate' },
            dependencies: ['model-training']
          },
          {
            name: 'Model Deployment',
            type: StepType.CONDITIONAL,
            config: {
              condition: 'evaluation.performance > threshold',
              ifTrue: {
                name: 'Deploy Model',
                type: StepType.AGENT_ACTION,
                config: { capability: 'ml-deployment', action: 'deploy' }
              }
            },
            dependencies: ['model-evaluation']
          }
        ],
        triggers: []
      }
    };

    const template = templates[templateType];
    if (!template) {
      throw new Error(`Unknown workflow template: ${templateType}`);
    }

    return template;
  }

  /**
   * Customize template with user configuration
   */
  private customizeTemplate(template: any, config: Record<string, any>): any {
    // Deep clone template
    const customized = JSON.parse(JSON.stringify(template));

    // Apply customizations
    if (config.description) {
      customized.description = config.description;
    }

    if (config.schedule && customized.triggers) {
      const scheduleTrigger = customized.triggers.find((t: any) => t.type === TriggerType.SCHEDULE);
      if (scheduleTrigger) {
        scheduleTrigger.config.interval = config.schedule;
      }
    }

    if (config.steps) {
      // Merge custom step configurations
      for (const [stepName, stepConfig] of Object.entries(config.steps)) {
        const step = customized.steps.find((s: any) => s.name.toLowerCase().replace(/\s+/g, '-') === stepName);
        if (step) {
          step.config = { ...step.config, ...(stepConfig as Record<string, any>) };
        }
      }
    }

    return customized;
  }
}