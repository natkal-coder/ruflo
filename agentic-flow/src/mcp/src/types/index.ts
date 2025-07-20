/**
 * Type definitions for the Agentic Flow MCP Server
 */

import { z } from 'zod';

// Agent Types
export interface Agent {
  id: string;
  name: string;
  type: AgentType;
  capabilities: string[];
  status: AgentStatus;
  memory: Map<string, any>;
  connections: string[];
  createdAt: Date;
  lastActive: Date;
}

export enum AgentType {
  COORDINATOR = 'coordinator',
  EXECUTOR = 'executor',
  ANALYZER = 'analyzer',
  LEARNER = 'learner',
  MONITOR = 'monitor',
  SPECIALIST = 'specialist'
}

export enum AgentStatus {
  IDLE = 'idle',
  ACTIVE = 'active',
  BUSY = 'busy',
  SUSPENDED = 'suspended',
  TERMINATED = 'terminated'
}

// Workflow Types
export interface Workflow {
  id: string;
  name: string;
  description: string;
  steps: WorkflowStep[];
  triggers: WorkflowTrigger[];
  status: WorkflowStatus;
  createdAt: Date;
  executionHistory: WorkflowExecution[];
}

export interface WorkflowStep {
  id: string;
  name: string;
  type: StepType;
  config: Record<string, any>;
  dependencies: string[];
  timeout?: number;
  retryPolicy?: RetryPolicy;
}

export enum StepType {
  AGENT_ACTION = 'agent_action',
  PARALLEL = 'parallel',
  SEQUENTIAL = 'sequential',
  CONDITIONAL = 'conditional',
  LOOP = 'loop',
  WEBHOOK = 'webhook'
}

export interface WorkflowTrigger {
  type: TriggerType;
  config: Record<string, any>;
}

export enum TriggerType {
  MANUAL = 'manual',
  SCHEDULE = 'schedule',
  EVENT = 'event',
  WEBHOOK = 'webhook'
}

export enum WorkflowStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  PAUSED = 'paused',
  COMPLETED = 'completed',
  FAILED = 'failed'
}

export interface WorkflowExecution {
  id: string;
  workflowId: string;
  startedAt: Date;
  completedAt?: Date;
  status: WorkflowStatus;
  results: Record<string, any>;
  errors?: Error[];
}

export interface RetryPolicy {
  maxAttempts: number;
  backoffMultiplier: number;
  initialDelay: number;
}

// Goal Types
export interface Goal {
  id: string;
  description: string;
  type: GoalType;
  priority: Priority;
  constraints: Constraint[];
  subgoals: Goal[];
  dependencies: string[];
  metrics: Metric[];
  status: GoalStatus;
}

export enum GoalType {
  TASK = 'task',
  OBJECTIVE = 'objective',
  MILESTONE = 'milestone',
  OUTCOME = 'outcome'
}

export enum Priority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface Constraint {
  type: ConstraintType;
  value: any;
  description: string;
}

export enum ConstraintType {
  TIME = 'time',
  RESOURCE = 'resource',
  DEPENDENCY = 'dependency',
  QUALITY = 'quality'
}

export interface Metric {
  name: string;
  type: MetricType;
  target: number;
  current: number;
  unit: string;
}

export enum MetricType {
  PERFORMANCE = 'performance',
  QUALITY = 'quality',
  COMPLETION = 'completion',
  EFFICIENCY = 'efficiency'
}

export enum GoalStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed',
  BLOCKED = 'blocked'
}

// Learning Types
export interface LearningModel {
  id: string;
  name: string;
  type: ModelType;
  architecture: ModelArchitecture;
  parameters: ModelParameters;
  trainingData: TrainingData;
  performance: ModelPerformance;
  version: string;
  createdAt: Date;
  lastTrained: Date;
}

export enum ModelType {
  CLASSIFICATION = 'classification',
  REGRESSION = 'regression',
  CLUSTERING = 'clustering',
  REINFORCEMENT = 'reinforcement',
  GENERATIVE = 'generative'
}

export interface ModelArchitecture {
  layers: Layer[];
  optimizer: string;
  lossFunction: string;
  metrics: string[];
}

export interface Layer {
  type: string;
  units?: number;
  activation?: string;
  config: Record<string, any>;
}

export interface ModelParameters {
  epochs: number;
  batchSize: number;
  learningRate: number;
  validationSplit: number;
  earlyStopping?: EarlyStopping;
}

export interface EarlyStopping {
  monitor: string;
  patience: number;
  minDelta: number;
  mode: 'min' | 'max';
}

export interface TrainingData {
  datasetId: string;
  features: string[];
  labels: string[];
  size: number;
  splits: DataSplits;
}

export interface DataSplits {
  train: number;
  validation: number;
  test: number;
}

export interface ModelPerformance {
  accuracy?: number;
  loss?: number;
  precision?: number;
  recall?: number;
  f1Score?: number;
  customMetrics: Record<string, number>;
}

// Communication Types
export interface Message {
  id: string;
  from: string;
  to: string | string[];
  type: MessageType;
  content: any;
  timestamp: Date;
  priority: Priority;
  requiresResponse: boolean;
  responseTimeout?: number;
}

export enum MessageType {
  COMMAND = 'command',
  QUERY = 'query',
  RESPONSE = 'response',
  EVENT = 'event',
  BROADCAST = 'broadcast',
  ERROR = 'error'
}

// Coordination Types
export interface CoordinationTask {
  id: string;
  name: string;
  agents: string[];
  strategy: CoordinationStrategy;
  synchronization: SynchronizationType;
  timeout: number;
  status: TaskStatus;
  results: Map<string, any>;
}

export enum CoordinationStrategy {
  ROUND_ROBIN = 'round_robin',
  LOAD_BALANCED = 'load_balanced',
  PRIORITY_BASED = 'priority_based',
  CONSENSUS = 'consensus',
  HIERARCHICAL = 'hierarchical'
}

export enum SynchronizationType {
  SYNC = 'sync',
  ASYNC = 'async',
  BARRIER = 'barrier',
  PIPELINE = 'pipeline'
}

export enum TaskStatus {
  QUEUED = 'queued',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

// Tool Parameter Schemas
export const AgentSpawnSchema = z.object({
  name: z.string(),
  type: z.nativeEnum(AgentType),
  capabilities: z.array(z.string()).optional(),
  config: z.record(z.any()).optional()
});

export const AgentCoordinateSchema = z.object({
  agents: z.array(z.string()),
  task: z.string(),
  strategy: z.nativeEnum(CoordinationStrategy).optional(),
  timeout: z.number().optional()
});

export const AgentCommunicateSchema = z.object({
  from: z.string(),
  to: z.union([z.string(), z.array(z.string())]),
  type: z.nativeEnum(MessageType),
  content: z.any(),
  priority: z.nativeEnum(Priority).optional(),
  requiresResponse: z.boolean().optional()
});

export const WorkflowCreateSchema = z.object({
  name: z.string(),
  description: z.string(),
  steps: z.array(z.object({
    name: z.string(),
    type: z.nativeEnum(StepType),
    config: z.record(z.any()),
    dependencies: z.array(z.string()).optional()
  })),
  triggers: z.array(z.object({
    type: z.nativeEnum(TriggerType),
    config: z.record(z.any())
  })).optional()
});

export const WorkflowExecuteSchema = z.object({
  workflowId: z.string(),
  params: z.record(z.any()).optional(),
  async: z.boolean().optional()
});

export const GoalParseSchema = z.object({
  description: z.string(),
  context: z.record(z.any()).optional()
});

export const GoalDecomposeSchema = z.object({
  goalId: z.string(),
  maxDepth: z.number().optional(),
  strategy: z.enum(['hierarchical', 'functional', 'temporal']).optional()
});

export const LearningTrainSchema = z.object({
  modelId: z.string().optional(),
  type: z.nativeEnum(ModelType),
  data: z.object({
    features: z.array(z.array(z.number())),
    labels: z.array(z.any())
  }),
  parameters: z.object({
    epochs: z.number().optional(),
    batchSize: z.number().optional(),
    learningRate: z.number().optional()
  }).optional()
});

export const LearningPredictSchema = z.object({
  modelId: z.string(),
  input: z.union([z.array(z.number()), z.array(z.array(z.number()))])
});

// Response Types
export interface ToolResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  metadata?: Record<string, any>;
}