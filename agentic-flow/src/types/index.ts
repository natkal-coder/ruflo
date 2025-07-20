/**
 * Core type definitions for the Agentic Flow framework
 */

// Agent-related types
export interface AgentId {
  id: string;
  namespace?: string;
}

export interface AgentCapability {
  name: string;
  description: string;
  inputSchema?: Record<string, any>;
  outputSchema?: Record<string, any>;
}

export interface AgentProfile {
  id: AgentId;
  name: string;
  type: AgentType;
  capabilities: AgentCapability[];
  goals: Goal[];
  state: AgentState;
  metadata: AgentMetadata;
}

export enum AgentType {
  COORDINATOR = 'coordinator',
  EXECUTOR = 'executor',
  ANALYZER = 'analyzer',
  MONITOR = 'monitor',
  SPECIALIST = 'specialist'
}

export enum AgentState {
  IDLE = 'idle',
  THINKING = 'thinking',
  EXECUTING = 'executing',
  COMMUNICATING = 'communicating',
  COORDINATING = 'coordinating',
  ERROR = 'error',
  TERMINATED = 'terminated'
}

export interface AgentMetadata {
  createdAt: Date;
  updatedAt: Date;
  version: string;
  tags: string[];
  performance: PerformanceMetrics;
}

// Goal-related types
export interface Goal {
  id: string;
  description: string;
  type: GoalType;
  priority: GoalPriority;
  status: GoalStatus;
  dependencies: string[];
  constraints: Constraint[];
  deadline?: Date;
  subGoals?: Goal[];
  metadata?: Record<string, any>;
}

export enum GoalType {
  ACHIEVE = 'achieve',
  MAINTAIN = 'maintain',
  QUERY = 'query',
  PERFORM = 'perform',
  PREVENT = 'prevent'
}

export enum GoalPriority {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low'
}

export enum GoalStatus {
  PENDING = 'pending',
  ACTIVE = 'active',
  COMPLETED = 'completed',
  FAILED = 'failed',
  SUSPENDED = 'suspended'
}

export interface Constraint {
  type: string;
  value: any;
  description?: string;
}

// Communication types
export interface Message {
  id: string;
  from: AgentId;
  to: AgentId | AgentId[];
  type: MessageType;
  content: MessageContent;
  timestamp: Date;
  replyTo?: string;
  priority: MessagePriority;
  ttl?: number;
}

export enum MessageType {
  REQUEST = 'request',
  RESPONSE = 'response',
  INFORM = 'inform',
  QUERY = 'query',
  COMMAND = 'command',
  BROADCAST = 'broadcast',
  NEGOTIATE = 'negotiate',
  ACKNOWLEDGE = 'acknowledge'
}

export enum MessagePriority {
  URGENT = 'urgent',
  HIGH = 'high',
  NORMAL = 'normal',
  LOW = 'low'
}

export interface MessageContent {
  topic: string;
  body: any;
  performative?: string;
  language?: string;
  encoding?: string;
  ontology?: string;
}

// Coordination types
export interface Team {
  id: string;
  name: string;
  leader: AgentId;
  members: AgentId[];
  goals: Goal[];
  formation: TeamFormation;
  status: TeamStatus;
  createdAt: Date;
}

export enum TeamFormation {
  HIERARCHICAL = 'hierarchical',
  FLAT = 'flat',
  MATRIX = 'matrix',
  DYNAMIC = 'dynamic'
}

export enum TeamStatus {
  FORMING = 'forming',
  ACTIVE = 'active',
  EXECUTING = 'executing',
  DISBANDED = 'disbanded'
}

export interface CoordinationStrategy {
  type: string;
  parameters: Record<string, any>;
  evaluate: (context: CoordinationContext) => number;
}

export interface CoordinationContext {
  team: Team;
  currentGoals: Goal[];
  agentStates: Map<string, AgentState>;
  environment: Record<string, any>;
}

// Performance and monitoring types
export interface PerformanceMetrics {
  tasksCompleted: number;
  successRate: number;
  averageResponseTime: number;
  resourceUtilization: number;
  communicationEfficiency: number;
}

// Event types
export interface AgentEvent {
  type: string;
  agentId: AgentId;
  timestamp: Date;
  data: any;
}

// Task execution types
export interface Task {
  id: string;
  goalId: string;
  assignedTo: AgentId;
  description: string;
  status: TaskStatus;
  result?: any;
  error?: Error;
  startedAt?: Date;
  completedAt?: Date;
}

export enum TaskStatus {
  PENDING = 'pending',
  ASSIGNED = 'assigned',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled'
}

// Natural Language Processing types
export interface NLPIntent {
  intent: string;
  confidence: number;
  entities: NLPEntity[];
  context?: Record<string, any>;
}

export interface NLPEntity {
  type: string;
  value: string;
  confidence: number;
  position: [number, number];
}

// Configuration types
export interface AgentConfig {
  namespace?: string;
  maxConcurrentTasks?: number;
  communicationTimeout?: number;
  retryAttempts?: number;
  memoryLimit?: number;
  learningRate?: number;
}

// Lifecycle hooks
export interface AgentLifecycleHooks {
  onInit?: () => Promise<void>;
  onStart?: () => Promise<void>;
  onStop?: () => Promise<void>;
  onError?: (error: Error) => Promise<void>;
  onMessage?: (message: Message) => Promise<void>;
  onGoalReceived?: (goal: Goal) => Promise<void>;
  onTaskCompleted?: (task: Task) => Promise<void>;
}