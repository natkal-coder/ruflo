/**
 * Goal-Driven Autonomous Agent
 * Implements goal-oriented behavior with planning and execution
 */

import { EventEmitter } from 'events';
import {
  AutonomousAgent,
  Goal,
  Plan,
  PlanStep,
  Belief,
  AgentState,
  ActivityState,
  AgentCapability,
  Experience,
  ExperienceType,
  Context,
  Outcome,
  Lesson,
  AgentType,
  Mood,
  Resource,
  Constraint,
  SuccessCriterion,
  Action,
  Effect,
  Condition,
  PlanStatus
} from '../types';

export class GoalDrivenAgent extends EventEmitter implements AutonomousAgent {
  id: string;
  name: string;
  type: AgentType;
  capabilities: AgentCapability[] = [];
  goals: Goal[] = [];
  beliefs: Belief[] = [];
  plans: Plan[] = [];
  experiences: Experience[] = [];
  state: AgentState;
  autonomyLevel: number;
  socialConnections: any[] = [];

  private goalPriorities: Map<string, number> = new Map();
  private planGenerator: PlanGenerator;
  private beliefRevision: BeliefRevisionEngine;
  private executionEngine: ExecutionEngine;

  constructor(config: AgentConfig) {
    super();
    this.id = config.id;
    this.name = config.name;
    this.type = config.type || AgentType.SPECIALIST;
    this.autonomyLevel = config.autonomyLevel || 0.8;
    
    this.state = {
      activity: ActivityState.IDLE,
      resources: [],
      activeGoals: [],
      activePlans: [],
      mood: { valence: 0, arousal: 0.5, dominance: 0.5 },
      energy: 1,
      focus: 1
    };

    this.planGenerator = new PlanGenerator(this);
    this.beliefRevision = new BeliefRevisionEngine(this);
    this.executionEngine = new ExecutionEngine(this);

    this.initializeCapabilities(config.capabilities || []);
  }

  /**
   * Add a new goal to the agent's goal set
   */
  async addGoal(goal: Goal): Promise<void> {
    // Check if goal is compatible with existing goals
    const conflicts = this.detectGoalConflicts(goal);
    if (conflicts.length > 0) {
      await this.resolveGoalConflicts(goal, conflicts);
    }

    // Add goal and calculate priority
    this.goals.push(goal);
    this.goalPriorities.set(goal.id, this.calculateGoalPriority(goal));
    
    // Generate plans for new goal
    await this.generatePlansForGoal(goal);
    
    this.emit('goal-added', { agent: this.id, goal });
  }

  /**
   * Detect conflicts between goals
   */
  private detectGoalConflicts(newGoal: Goal): Goal[] {
    const conflicts: Goal[] = [];
    
    for (const existingGoal of this.goals) {
      // Check resource conflicts
      const resourceConflict = this.hasResourceConflict(newGoal, existingGoal);
      
      // Check logical conflicts
      const logicalConflict = this.hasLogicalConflict(newGoal, existingGoal);
      
      // Check temporal conflicts
      const temporalConflict = this.hasTemporalConflict(newGoal, existingGoal);
      
      if (resourceConflict || logicalConflict || temporalConflict) {
        conflicts.push(existingGoal);
      }
    }
    
    return conflicts;
  }

  /**
   * Check for resource conflicts between goals
   */
  private hasResourceConflict(goal1: Goal, goal2: Goal): boolean {
    const resources1 = this.estimateGoalResources(goal1);
    const resources2 = this.estimateGoalResources(goal2);
    
    for (const [type, amount1] of resources1) {
      const amount2 = resources2.get(type) || 0;
      const available = this.getAvailableResource(type);
      
      if (amount1 + amount2 > available) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Check for logical conflicts between goals
   */
  private hasLogicalConflict(goal1: Goal, goal2: Goal): boolean {
    // Check if success criteria are mutually exclusive
    for (const criterion1 of goal1.successCriteria) {
      for (const criterion2 of goal2.successCriteria) {
        if (this.areCriteriaMutuallyExclusive(criterion1, criterion2)) {
          return true;
        }
      }
    }
    
    return false;
  }

  /**
   * Check for temporal conflicts between goals
   */
  private hasTemporalConflict(goal1: Goal, goal2: Goal): boolean {
    if (!goal1.deadline || !goal2.deadline) {
      return false;
    }
    
    const duration1 = this.estimateGoalDuration(goal1);
    const duration2 = this.estimateGoalDuration(goal2);
    
    // Check if goals require overlapping execution time
    const overlap = this.calculateTemporalOverlap(
      new Date(),
      goal1.deadline,
      duration1,
      new Date(),
      goal2.deadline,
      duration2
    );
    
    return overlap > 0.5; // More than 50% overlap
  }

  /**
   * Resolve conflicts between goals
   */
  private async resolveGoalConflicts(newGoal: Goal, conflicts: Goal[]): Promise<void> {
    // Try different resolution strategies
    const strategies = [
      this.tryGoalMerging.bind(this),
      this.tryGoalSequencing.bind(this),
      this.tryResourceSharing.bind(this),
      this.tryGoalPrioritization.bind(this)
    ];
    
    for (const strategy of strategies) {
      const resolved = await strategy(newGoal, conflicts);
      if (resolved) {
        return;
      }
    }
    
    // If no resolution found, prioritize based on utility
    await this.prioritizeByUtility(newGoal, conflicts);
  }

  /**
   * Calculate priority for a goal
   */
  private calculateGoalPriority(goal: Goal): number {
    let priority = goal.priority;
    
    // Adjust for urgency
    if (goal.deadline) {
      const urgency = this.calculateUrgency(goal.deadline);
      priority *= (1 + urgency);
    }
    
    // Adjust for dependencies
    const dependencyFactor = this.calculateDependencyFactor(goal);
    priority *= dependencyFactor;
    
    // Adjust for capability match
    const capabilityMatch = this.calculateCapabilityMatch(goal);
    priority *= capabilityMatch;
    
    return Math.min(priority, 10); // Cap at 10
  }

  /**
   * Generate plans to achieve a goal
   */
  private async generatePlansForGoal(goal: Goal): Promise<void> {
    const plans = await this.planGenerator.generatePlans(goal);
    
    // Evaluate and rank plans
    const rankedPlans = plans
      .map(plan => ({
        plan,
        score: this.evaluatePlan(plan)
      }))
      .sort((a, b) => b.score - a.score);
    
    // Add top plans to agent's plan set
    const topPlans = rankedPlans.slice(0, 3).map(rp => rp.plan);
    this.plans.push(...topPlans);
    
    // Start execution of best plan if appropriate
    if (topPlans.length > 0 && this.shouldStartExecution(goal)) {
      await this.startPlanExecution(topPlans[0]);
    }
  }

  /**
   * Evaluate a plan's expected utility
   */
  private evaluatePlan(plan: Plan): number {
    let score = plan.expectedUtility;
    
    // Adjust for resource efficiency
    const resourceEfficiency = this.calculateResourceEfficiency(plan);
    score *= resourceEfficiency;
    
    // Adjust for risk
    const riskFactor = this.calculatePlanRisk(plan);
    score *= (1 - riskFactor);
    
    // Adjust for past experience
    const experienceFactor = this.getExperienceFactor(plan);
    score *= experienceFactor;
    
    return score;
  }

  /**
   * Start executing a plan
   */
  private async startPlanExecution(plan: Plan): Promise<void> {
    plan.status = PlanStatus.EXECUTING;
    this.state.activePlans.push(plan.id);
    this.state.activity = ActivityState.EXECUTING;
    
    this.emit('plan-execution-started', { agent: this.id, plan });
    
    // Execute plan steps
    await this.executionEngine.executePlan(plan);
  }

  /**
   * Update beliefs based on new information
   */
  async updateBelief(belief: Belief): Promise<void> {
    const revised = await this.beliefRevision.revise(belief);
    
    if (revised) {
      // Check if belief changes affect current goals/plans
      await this.reassessGoalsAndPlans();
    }
    
    this.emit('belief-updated', { agent: this.id, belief });
  }

  /**
   * Learn from an experience
   */
  async learnFromExperience(experience: Experience): Promise<void> {
    this.experiences.push(experience);
    
    // Extract lessons
    const lessons = await this.extractLessons(experience);
    experience.lessons = lessons;
    
    // Update capabilities based on experience
    await this.updateCapabilities(experience);
    
    // Adjust future planning based on lessons
    await this.adjustPlanningStrategies(lessons);
    
    this.emit('experience-learned', { agent: this.id, experience, lessons });
  }

  /**
   * Extract lessons from an experience
   */
  private async extractLessons(experience: Experience): Promise<Lesson[]> {
    const lessons: Lesson[] = [];
    
    // Analyze what worked
    if (experience.type === ExperienceType.SUCCESS) {
      const successPatterns = this.identifySuccessPatterns(experience);
      lessons.push(...successPatterns);
    }
    
    // Analyze what didn't work
    if (experience.type === ExperienceType.FAILURE) {
      const failurePatterns = this.identifyFailurePatterns(experience);
      lessons.push(...failurePatterns);
    }
    
    // Analyze surprises
    if (experience.outcome.surprises.length > 0) {
      const surpriseLessons = this.analyzeSurprises(experience);
      lessons.push(...surpriseLessons);
    }
    
    return lessons;
  }

  /**
   * Update agent's mood based on recent experiences
   */
  private updateMood(experience: Experience): void {
    const outcome = experience.outcome;
    
    // Update valence based on success
    const successImpact = outcome.success ? 0.1 : -0.1;
    this.state.mood.valence = Math.max(-1, Math.min(1, 
      this.state.mood.valence + successImpact
    ));
    
    // Update arousal based on surprises
    const surpriseImpact = outcome.surprises.length * 0.05;
    this.state.mood.arousal = Math.max(0, Math.min(1,
      this.state.mood.arousal + surpriseImpact
    ));
    
    // Update dominance based on goal achievement
    const achievementImpact = outcome.goalAchievement * 0.1;
    this.state.mood.dominance = Math.max(0, Math.min(1,
      this.state.mood.dominance + achievementImpact
    ));
  }

  /**
   * Make autonomous decisions
   */
  async makeDecision(context: DecisionContext): Promise<DecisionOption> {
    // Use appropriate decision strategy based on context
    const strategy = this.selectDecisionStrategy(context);
    
    // Apply strategy to evaluate options
    const evaluation = await strategy.evaluate(context);
    
    // Select best option considering risk tolerance
    const selected = this.selectOption(evaluation, this.getRiskTolerance());
    
    this.emit('decision-made', { agent: this.id, context, selected });
    
    return selected;
  }

  /**
   * Adapt behavior based on feedback
   */
  async adaptBehavior(feedback: Feedback): Promise<void> {
    // Update relevant beliefs
    await this.updateBeliefsFromFeedback(feedback);
    
    // Adjust capabilities
    await this.adjustCapabilities(feedback);
    
    // Modify planning strategies
    await this.modifyPlanningStrategies(feedback);
    
    // Update social connections if applicable
    if (feedback.source) {
      await this.updateSocialConnection(feedback.source, feedback);
    }
    
    this.emit('behavior-adapted', { agent: this.id, feedback });
  }

  /**
   * Reflect on recent activities
   */
  async reflect(): Promise<Reflection> {
    this.state.activity = ActivityState.REFLECTING;
    
    const reflection: Reflection = {
      period: this.getReflectionPeriod(),
      achievements: this.summarizeAchievements(),
      failures: this.summarizeFailures(),
      learnings: this.summarizeLearnings(),
      recommendations: this.generateRecommendations()
    };
    
    // Update self-model based on reflection
    await this.updateSelfModel(reflection);
    
    this.state.activity = ActivityState.IDLE;
    
    return reflection;
  }

  // Helper methods
  
  private initializeCapabilities(capabilities: AgentCapability[]): void {
    this.capabilities = capabilities;
    // Initialize capability learning curves
    for (const capability of capabilities) {
      this.initializeCapabilityLearning(capability);
    }
  }

  private estimateGoalResources(goal: Goal): Map<string, number> {
    const resources = new Map<string, number>();
    
    // Estimate based on goal constraints and success criteria
    for (const constraint of goal.constraints) {
      if (constraint.type === 'resource') {
        const existing = resources.get(constraint.description) || 0;
        resources.set(constraint.description, existing + Number(constraint.value));
      }
    }
    
    return resources;
  }

  private getAvailableResource(type: string): number {
    const resource = this.state.resources.find(r => r.type === type);
    return resource ? resource.quantity : 0;
  }

  private areCriteriaMutuallyExclusive(c1: SuccessCriterion, c2: SuccessCriterion): boolean {
    // Check if criteria target the same metric with incompatible conditions
    if (c1.metric !== c2.metric) return false;
    
    // Check for logical incompatibility
    const incompatible = [
      ['gt', 'lt'],
      ['gt', 'lte'],
      ['gte', 'lt'],
      ['eq', 'gt'],
      ['eq', 'lt']
    ];
    
    for (const [op1, op2] of incompatible) {
      if ((c1.operator === op1 && c2.operator === op2) ||
          (c1.operator === op2 && c2.operator === op1)) {
        return true;
      }
    }
    
    return false;
  }

  private estimateGoalDuration(goal: Goal): number {
    // Estimate based on complexity and required resources
    let baseDuration = 1000; // Base duration in time units
    
    // Adjust for constraints
    baseDuration *= (1 + goal.constraints.length * 0.1);
    
    // Adjust for success criteria
    baseDuration *= (1 + goal.successCriteria.length * 0.15);
    
    // Adjust based on past experience
    const similarGoals = this.findSimilarCompletedGoals(goal);
    if (similarGoals.length > 0) {
      const avgDuration = similarGoals.reduce((sum, g) => sum + g.actualDuration, 0) / similarGoals.length;
      baseDuration = (baseDuration + avgDuration) / 2;
    }
    
    return baseDuration;
  }

  private calculateTemporalOverlap(
    start1: Date, end1: Date, duration1: number,
    start2: Date, end2: Date, duration2: number
  ): number {
    const execStart1 = new Date(end1.getTime() - duration1);
    const execStart2 = new Date(end2.getTime() - duration2);
    
    const overlapStart = Math.max(execStart1.getTime(), execStart2.getTime());
    const overlapEnd = Math.min(end1.getTime(), end2.getTime());
    
    if (overlapStart >= overlapEnd) return 0;
    
    const overlap = overlapEnd - overlapStart;
    const minDuration = Math.min(duration1, duration2);
    
    return overlap / minDuration;
  }

  private calculateUrgency(deadline: Date): number {
    const now = new Date();
    const timeRemaining = deadline.getTime() - now.getTime();
    const dayInMs = 24 * 60 * 60 * 1000;
    
    if (timeRemaining < dayInMs) return 2.0;
    if (timeRemaining < 7 * dayInMs) return 1.5;
    if (timeRemaining < 30 * dayInMs) return 1.2;
    
    return 1.0;
  }

  private calculateDependencyFactor(goal: Goal): number {
    // Check how many other goals depend on this one
    let dependentGoals = 0;
    
    for (const otherGoal of this.goals) {
      if (otherGoal.parentGoalId === goal.id) {
        dependentGoals++;
      }
    }
    
    return 1 + (dependentGoals * 0.2);
  }

  private calculateCapabilityMatch(goal: Goal): number {
    // Calculate how well agent's capabilities match goal requirements
    const requiredCapabilities = this.identifyRequiredCapabilities(goal);
    let totalMatch = 0;
    
    for (const required of requiredCapabilities) {
      const agentCapability = this.capabilities.find(c => c.type === required.type);
      if (agentCapability) {
        totalMatch += agentCapability.proficiencyLevel * required.importance;
      }
    }
    
    return Math.max(0.1, totalMatch / requiredCapabilities.length);
  }

  private identifyRequiredCapabilities(goal: Goal): any[] {
    // Analyze goal to determine required capabilities
    const required = [];
    
    // Based on goal description and constraints
    if (goal.description.includes('analyze') || goal.description.includes('research')) {
      required.push({ type: CapabilityType.ANALYSIS, importance: 1.0 });
    }
    
    if (goal.description.includes('create') || goal.description.includes('build')) {
      required.push({ type: CapabilityType.SYNTHESIS, importance: 1.0 });
    }
    
    if (goal.description.includes('optimize') || goal.description.includes('improve')) {
      required.push({ type: CapabilityType.OPTIMIZATION, importance: 1.0 });
    }
    
    // Always need some planning capability
    required.push({ type: CapabilityType.PLANNING, importance: 0.5 });
    
    return required;
  }

  private shouldStartExecution(goal: Goal): boolean {
    // Check if conditions are right to start execution
    if (this.state.energy < 0.3) return false;
    if (this.state.activePlans.length >= 3) return false;
    if (this.state.mood.valence < -0.5) return false;
    
    return true;
  }
}

// Supporting classes
class PlanGenerator {
  constructor(private agent: GoalDrivenAgent) {}
  
  async generatePlans(goal: Goal): Promise<Plan[]> {
    // Implement plan generation logic
    return [];
  }
}

class BeliefRevisionEngine {
  constructor(private agent: GoalDrivenAgent) {}
  
  async revise(belief: Belief): Promise<boolean> {
    // Implement belief revision logic
    return true;
  }
}

class ExecutionEngine {
  constructor(private agent: GoalDrivenAgent) {}
  
  async executePlan(plan: Plan): Promise<void> {
    // Implement plan execution logic
  }
}

// Interfaces
interface AgentConfig {
  id: string;
  name: string;
  type?: AgentType;
  autonomyLevel?: number;
  capabilities?: AgentCapability[];
}

interface DecisionContext {
  agent: AutonomousAgent;
  options: DecisionOption[];
  constraints: Constraint[];
  timeLimit?: number;
  stakeholders: string[];
}

interface DecisionOption {
  id: string;
  description: string;
  expectedUtility: number;
  risks: Risk[];
  requirements: Condition[];
  confidence: number;
}

interface Risk {
  description: string;
  probability: number;
  impact: number;
  mitigation?: string;
}

interface Feedback {
  type: 'positive' | 'negative' | 'corrective';
  aspect: string;
  details: string;
  source?: string;
  timestamp: Date;
}

interface Reflection {
  period: { start: Date; end: Date };
  achievements: Achievement[];
  failures: Failure[];
  learnings: Learning[];
  recommendations: string[];
}

interface Achievement {
  goalId: string;
  level: number;
  impact: string;
}

interface Failure {
  goalId: string;
  reason: string;
  lessons: string[];
}

interface Learning {
  topic: string;
  insight: string;
  applicability: number;
}