/**
 * Autonomous Operations Type Definitions
 * Core types for self-governing agent systems
 */

export interface Goal {
  id: string;
  description: string;
  priority: number;
  constraints: Constraint[];
  successCriteria: SuccessCriterion[];
  deadline?: Date;
  parentGoalId?: string;
  subGoals?: Goal[];
}

export interface Constraint {
  type: 'resource' | 'time' | 'dependency' | 'capability' | 'policy';
  description: string;
  value: any;
  isSoft?: boolean; // Can be violated with penalty
}

export interface SuccessCriterion {
  metric: string;
  operator: 'eq' | 'gt' | 'lt' | 'gte' | 'lte' | 'contains' | 'custom';
  targetValue: any;
  weight?: number;
}

export interface AgentCapability {
  id: string;
  name: string;
  type: CapabilityType;
  proficiencyLevel: number; // 0-1
  resourceRequirements: ResourceRequirement[];
  performanceMetrics: PerformanceMetric[];
  learningRate: number;
}

export enum CapabilityType {
  ANALYSIS = 'analysis',
  SYNTHESIS = 'synthesis',
  EXECUTION = 'execution',
  COORDINATION = 'coordination',
  LEARNING = 'learning',
  PLANNING = 'planning',
  OPTIMIZATION = 'optimization',
  COMMUNICATION = 'communication'
}

export interface ResourceRequirement {
  resourceType: string;
  quantity: number;
  isExclusive?: boolean;
}

export interface PerformanceMetric {
  name: string;
  value: number;
  timestamp: Date;
  confidence: number;
}

export interface AutonomousAgent {
  id: string;
  name: string;
  type: AgentType;
  capabilities: AgentCapability[];
  goals: Goal[];
  beliefs: Belief[];
  plans: Plan[];
  experiences: Experience[];
  state: AgentState;
  autonomyLevel: number; // 0-1
  socialConnections: SocialConnection[];
}

export enum AgentType {
  SPECIALIST = 'specialist',
  COORDINATOR = 'coordinator',
  LEARNER = 'learner',
  EXPLORER = 'explorer',
  OPTIMIZER = 'optimizer',
  NEGOTIATOR = 'negotiator',
  MONITOR = 'monitor',
  EXECUTOR = 'executor'
}

export interface Belief {
  id: string;
  subject: string;
  predicate: string;
  object: any;
  confidence: number;
  source: string;
  timestamp: Date;
  evidence: Evidence[];
}

export interface Evidence {
  type: 'observation' | 'communication' | 'inference' | 'experience';
  data: any;
  reliability: number;
}

export interface Plan {
  id: string;
  goalId: string;
  steps: PlanStep[];
  expectedUtility: number;
  estimatedDuration: number;
  resourceRequirements: ResourceRequirement[];
  contingencies: Contingency[];
  status: PlanStatus;
}

export interface PlanStep {
  id: string;
  action: Action;
  preconditions: Condition[];
  effects: Effect[];
  estimatedDuration: number;
  dependencies: string[]; // Other step IDs
}

export interface Action {
  type: string;
  parameters: Record<string, any>;
  executor?: string; // Agent ID
}

export interface Condition {
  type: 'belief' | 'resource' | 'capability' | 'state';
  expression: string;
  parameters: Record<string, any>;
}

export interface Effect {
  type: 'add' | 'remove' | 'modify';
  target: string;
  value: any;
  probability: number;
}

export interface Contingency {
  trigger: Condition;
  alternativePlan: Plan | string; // Plan or Plan ID
}

export enum PlanStatus {
  DRAFT = 'draft',
  READY = 'ready',
  EXECUTING = 'executing',
  SUSPENDED = 'suspended',
  COMPLETED = 'completed',
  FAILED = 'failed',
  ABANDONED = 'abandoned'
}

export interface Experience {
  id: string;
  type: ExperienceType;
  context: Context;
  actions: Action[];
  outcome: Outcome;
  lessons: Lesson[];
  timestamp: Date;
}

export enum ExperienceType {
  SUCCESS = 'success',
  FAILURE = 'failure',
  PARTIAL = 'partial',
  UNEXPECTED = 'unexpected',
  LEARNING = 'learning'
}

export interface Context {
  goals: Goal[];
  beliefs: Belief[];
  resources: Resource[];
  constraints: Constraint[];
  environment: Record<string, any>;
}

export interface Outcome {
  success: boolean;
  goalAchievement: number; // 0-1
  resourcesConsumed: Resource[];
  sideEffects: Effect[];
  surprises: Surprise[];
}

export interface Surprise {
  description: string;
  impact: 'positive' | 'negative' | 'neutral';
  severity: number;
  adaptationRequired: boolean;
}

export interface Lesson {
  pattern: string;
  confidence: number;
  applicability: Condition[];
  recommendation: string;
}

export interface Resource {
  id: string;
  type: string;
  quantity: number;
  availability: 'available' | 'reserved' | 'in-use' | 'depleted';
  owner?: string;
  sharable: boolean;
}

export interface AgentState {
  activity: ActivityState;
  resources: Resource[];
  activeGoals: string[];
  activePlans: string[];
  mood: Mood;
  energy: number; // 0-1
  focus: number; // 0-1
}

export enum ActivityState {
  IDLE = 'idle',
  PLANNING = 'planning',
  EXECUTING = 'executing',
  LEARNING = 'learning',
  COMMUNICATING = 'communicating',
  REFLECTING = 'reflecting',
  RECOVERING = 'recovering'
}

export interface Mood {
  valence: number; // -1 to 1 (negative to positive)
  arousal: number; // 0 to 1 (calm to excited)
  dominance: number; // 0 to 1 (submissive to dominant)
}

export interface SocialConnection {
  agentId: string;
  relationshipType: RelationshipType;
  trust: number; // 0-1
  reciprocity: number; // -1 to 1
  interactionHistory: Interaction[];
}

export enum RelationshipType {
  PEER = 'peer',
  SUPERIOR = 'superior',
  SUBORDINATE = 'subordinate',
  COLLABORATOR = 'collaborator',
  COMPETITOR = 'competitor',
  MENTOR = 'mentor',
  STUDENT = 'student'
}

export interface Interaction {
  type: 'cooperation' | 'negotiation' | 'conflict' | 'teaching' | 'learning';
  outcome: 'positive' | 'negative' | 'neutral';
  timestamp: Date;
  impact: number;
}

export interface Team {
  id: string;
  name: string;
  purpose: string;
  members: TeamMember[];
  goals: Goal[];
  formation: TeamFormation;
  performance: TeamPerformance;
  dynamics: TeamDynamics;
}

export interface TeamMember {
  agentId: string;
  role: string;
  responsibilities: string[];
  authority: number; // 0-1
  commitment: number; // 0-1
}

export interface TeamFormation {
  strategy: FormationStrategy;
  initiator: string;
  formationTime: Date;
  stability: number; // 0-1
}

export enum FormationStrategy {
  GOAL_DRIVEN = 'goal-driven',
  CAPABILITY_BASED = 'capability-based',
  SOCIAL_AFFINITY = 'social-affinity',
  RANDOM = 'random',
  HIERARCHICAL = 'hierarchical',
  EMERGENT = 'emergent'
}

export interface TeamPerformance {
  efficiency: number;
  effectiveness: number;
  synergy: number;
  adaptability: number;
}

export interface TeamDynamics {
  cohesion: number;
  communication: number;
  conflictLevel: number;
  leadership: LeadershipStyle;
}

export enum LeadershipStyle {
  AUTOCRATIC = 'autocratic',
  DEMOCRATIC = 'democratic',
  LAISSEZ_FAIRE = 'laissez-faire',
  TRANSFORMATIONAL = 'transformational',
  SERVANT = 'servant',
  DISTRIBUTED = 'distributed'
}

export interface DecisionContext {
  agent: AutonomousAgent;
  options: DecisionOption[];
  constraints: Constraint[];
  timeLimit?: number;
  stakeholders: string[];
}

export interface DecisionOption {
  id: string;
  description: string;
  expectedUtility: number;
  risks: Risk[];
  requirements: Condition[];
  confidence: number;
}

export interface Risk {
  description: string;
  probability: number;
  impact: number;
  mitigation?: string;
}

export interface LearningObjective {
  id: string;
  skill: string;
  targetProficiency: number;
  currentProficiency: number;
  learningPlan: LearningPlan;
  progress: LearningProgress;
}

export interface LearningPlan {
  steps: LearningStep[];
  resources: LearningResource[];
  estimatedDuration: number;
  adaptiveStrategy: boolean;
}

export interface LearningStep {
  type: 'study' | 'practice' | 'experiment' | 'reflect' | 'teach';
  content: string;
  duration: number;
  prerequisites: string[];
}

export interface LearningResource {
  type: 'example' | 'documentation' | 'mentor' | 'experience' | 'feedback';
  source: string;
  relevance: number;
}

export interface LearningProgress {
  completedSteps: string[];
  proficiencyGain: number;
  timeSpent: number;
  insights: string[];
}

export interface CapabilityDiscovery {
  method: DiscoveryMethod;
  discoveredCapabilities: AgentCapability[];
  verificationStatus: VerificationStatus;
  confidence: number;
}

export enum DiscoveryMethod {
  SELF_ASSESSMENT = 'self-assessment',
  PEER_OBSERVATION = 'peer-observation',
  EXPERIMENTATION = 'experimentation',
  DOCUMENTATION = 'documentation',
  INFERENCE = 'inference'
}

export enum VerificationStatus {
  UNVERIFIED = 'unverified',
  PARTIALLY_VERIFIED = 'partially-verified',
  VERIFIED = 'verified',
  CERTIFIED = 'certified'
}

export interface NegotiationContext {
  participants: string[];
  subject: string;
  stakes: any;
  protocol: NegotiationProtocol;
  deadline?: Date;
}

export enum NegotiationProtocol {
  BARGAINING = 'bargaining',
  AUCTION = 'auction',
  VOTING = 'voting',
  CONSENSUS = 'consensus',
  ARBITRATION = 'arbitration'
}

export interface Proposal {
  id: string;
  proposer: string;
  content: any;
  justification: string;
  acceptanceThreshold: number;
  votes: Vote[];
}

export interface Vote {
  voter: string;
  value: number; // -1 to 1
  reason?: string;
  timestamp: Date;
}