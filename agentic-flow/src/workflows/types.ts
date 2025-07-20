// Workflow system types with Mastra compatibility and XState integration

import { StateMachine, StateNode, EventObject } from 'xstate';
import { z } from 'zod';

// Core workflow types
export interface WorkflowNode {
  id: string;
  type: NodeType;
  label: string;
  position: { x: number; y: number };
  data: Record<string, any>;
  inputs?: WorkflowPort[];
  outputs?: WorkflowPort[];
  config?: NodeConfig;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  sourcePort?: string;
  target: string;
  targetPort?: string;
  label?: string;
  condition?: WorkflowCondition;
}

export interface WorkflowPort {
  id: string;
  name: string;
  type: DataType;
  required?: boolean;
  defaultValue?: any;
}

export interface WorkflowCondition {
  type: 'expression' | 'function' | 'comparison';
  expression?: string;
  function?: string;
  left?: any;
  operator?: ComparisonOperator;
  right?: any;
}

export type NodeType = 
  | 'start'
  | 'end'
  | 'task'
  | 'decision'
  | 'parallel'
  | 'loop'
  | 'subworkflow'
  | 'humanTask'
  | 'timer'
  | 'event'
  | 'transform'
  | 'aggregate'
  | 'custom';

export type DataType = 
  | 'string'
  | 'number'
  | 'boolean'
  | 'object'
  | 'array'
  | 'date'
  | 'any';

export type ComparisonOperator = 
  | '=='
  | '!='
  | '>'
  | '<'
  | '>='
  | '<='
  | 'contains'
  | 'startsWith'
  | 'endsWith'
  | 'matches';

export interface NodeConfig {
  retryPolicy?: RetryPolicy;
  timeout?: number;
  concurrency?: number;
  errorHandler?: string;
  cache?: CacheConfig;
}

export interface RetryPolicy {
  maxAttempts: number;
  backoff: 'linear' | 'exponential' | 'fixed';
  delay: number;
  maxDelay?: number;
}

export interface CacheConfig {
  enabled: boolean;
  ttl?: number;
  key?: string;
}

// Workflow definition
export interface WorkflowDefinition {
  id: string;
  name: string;
  description?: string;
  version: string;
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
  variables?: WorkflowVariable[];
  triggers?: WorkflowTrigger[];
  metadata?: WorkflowMetadata;
  mastraConfig?: MastraConfig;
}

export interface WorkflowVariable {
  name: string;
  type: DataType;
  defaultValue?: any;
  required?: boolean;
  description?: string;
}

export interface WorkflowTrigger {
  id: string;
  type: 'schedule' | 'event' | 'webhook' | 'manual';
  config: Record<string, any>;
}

export interface WorkflowMetadata {
  author?: string;
  created: Date;
  updated: Date;
  tags?: string[];
  category?: string;
  permissions?: WorkflowPermissions;
}

export interface WorkflowPermissions {
  execute: string[];
  modify: string[];
  view: string[];
}

// Mastra compatibility types
export interface MastraConfig {
  agent?: string;
  tools?: string[];
  memory?: boolean;
  streaming?: boolean;
  model?: string;
}

// Execution types
export interface WorkflowInstance {
  id: string;
  workflowId: string;
  version: string;
  status: WorkflowStatus;
  context: WorkflowContext;
  currentNodeId?: string;
  startedAt: Date;
  completedAt?: Date;
  error?: WorkflowError;
  parentInstanceId?: string;
  humanTasks?: HumanTask[];
}

export type WorkflowStatus = 
  | 'pending'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'waiting';

export interface WorkflowContext {
  inputs: Record<string, any>;
  variables: Record<string, any>;
  outputs: Record<string, any>;
  nodeOutputs: Record<string, any>;
  metadata: Record<string, any>;
}

export interface WorkflowError {
  nodeId: string;
  message: string;
  code?: string;
  stack?: string;
  timestamp: Date;
}

// Human-in-the-loop types
export interface HumanTask {
  id: string;
  nodeId: string;
  instanceId: string;
  title: string;
  description?: string;
  assignee?: string;
  inputs: Record<string, any>;
  form?: HumanTaskForm;
  status: HumanTaskStatus;
  createdAt: Date;
  completedAt?: Date;
  response?: Record<string, any>;
}

export type HumanTaskStatus = 
  | 'pending'
  | 'assigned'
  | 'in_progress'
  | 'completed'
  | 'cancelled';

export interface HumanTaskForm {
  fields: FormField[];
  validation?: Record<string, any>;
}

export interface FormField {
  name: string;
  type: 'text' | 'number' | 'boolean' | 'select' | 'multiselect' | 'date' | 'file';
  label: string;
  required?: boolean;
  options?: Array<{ value: any; label: string }>;
  validation?: any;
}

// Persistence types
export interface WorkflowSnapshot {
  instanceId: string;
  timestamp: Date;
  state: WorkflowInstance;
  checksum: string;
}

export interface WorkflowEvent {
  id: string;
  instanceId: string;
  type: string;
  payload: any;
  timestamp: Date;
  nodeId?: string;
}

// Template types
export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  definition: Partial<WorkflowDefinition>;
  parameters: TemplateParameter[];
  preview?: string;
}

export interface TemplateParameter {
  name: string;
  type: DataType;
  description: string;
  defaultValue?: any;
  required?: boolean;
}

// XState integration types
export interface XStateWorkflowConfig {
  machine: StateMachine<any, any, EventObject>;
  guards?: Record<string, (context: any, event: any) => boolean>;
  actions?: Record<string, (context: any, event: any) => void>;
  services?: Record<string, (context: any, event: any) => Promise<any>>;
}

// Validation schemas
export const WorkflowNodeSchema = z.object({
  id: z.string(),
  type: z.enum(['start', 'end', 'task', 'decision', 'parallel', 'loop', 'subworkflow', 'humanTask', 'timer', 'event', 'transform', 'aggregate', 'custom']),
  label: z.string(),
  position: z.object({ x: z.number(), y: z.number() }),
  data: z.record(z.any()),
  inputs: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.enum(['string', 'number', 'boolean', 'object', 'array', 'date', 'any']),
    required: z.boolean().optional(),
    defaultValue: z.any().optional()
  })).optional(),
  outputs: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.enum(['string', 'number', 'boolean', 'object', 'array', 'date', 'any']),
    required: z.boolean().optional(),
    defaultValue: z.any().optional()
  })).optional()
});

export const WorkflowDefinitionSchema = z.object({
  id: z.string(),
  name: z.string(),
  description: z.string().optional(),
  version: z.string(),
  nodes: z.array(WorkflowNodeSchema),
  edges: z.array(z.object({
    id: z.string(),
    source: z.string(),
    target: z.string(),
    condition: z.any().optional()
  }))
});

// Export types
export type WorkflowExport = {
  format: 'json' | 'yaml' | 'xstate';
  version: string;
  workflow: WorkflowDefinition;
  templates?: WorkflowTemplate[];
  metadata?: Record<string, any>;
};