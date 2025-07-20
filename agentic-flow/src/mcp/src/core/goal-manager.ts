/**
 * Goal Manager - Goal parsing and decomposition
 */

import { v4 as uuidv4 } from 'uuid';
import { EventEmitter } from 'events';
import {
  Goal,
  GoalType,
  Priority,
  GoalStatus,
  Constraint,
  ConstraintType,
  Metric,
  MetricType
} from '../types';
import { logger } from '../utils/logger';

export class GoalManager extends EventEmitter {
  private goals: Map<string, Goal> = new Map();
  private goalHierarchy: Map<string, string[]> = new Map(); // parent -> children

  constructor() {
    super();
    this.setupEventHandlers();
  }

  private setupEventHandlers() {
    this.on('goal:progress', this.handleGoalProgress.bind(this));
    this.on('goal:completed', this.handleGoalCompleted.bind(this));
  }

  /**
   * Parse a goal description into a structured goal
   */
  async parseGoal(
    description: string,
    context: Record<string, any> = {}
  ): Promise<Goal> {
    // Extract goal components from description
    const parsedComponents = this.extractGoalComponents(description, context);

    const goal: Goal = {
      id: uuidv4(),
      description,
      type: parsedComponents.type,
      priority: parsedComponents.priority,
      constraints: parsedComponents.constraints,
      subgoals: [],
      dependencies: parsedComponents.dependencies,
      metrics: parsedComponents.metrics,
      status: GoalStatus.PENDING
    };

    this.goals.set(goal.id, goal);
    logger.info(`Goal parsed: ${goal.description} (${goal.id})`);
    this.emit('goal:parsed', goal);

    return goal;
  }

  /**
   * Decompose a goal into subgoals
   */
  async decomposeGoal(
    goalId: string,
    maxDepth: number = 3,
    strategy: 'hierarchical' | 'functional' | 'temporal' = 'hierarchical'
  ): Promise<Goal[]> {
    const goal = this.goals.get(goalId);
    if (!goal) {
      throw new Error(`Goal ${goalId} not found`);
    }

    logger.info(`Decomposing goal: ${goal.description} using ${strategy} strategy`);

    let subgoals: Goal[] = [];

    switch (strategy) {
      case 'hierarchical':
        subgoals = await this.hierarchicalDecomposition(goal, maxDepth);
        break;
      case 'functional':
        subgoals = await this.functionalDecomposition(goal, maxDepth);
        break;
      case 'temporal':
        subgoals = await this.temporalDecomposition(goal, maxDepth);
        break;
    }

    // Update goal with subgoals
    goal.subgoals = subgoals;
    this.goalHierarchy.set(goal.id, subgoals.map(sg => sg.id));

    // Save subgoals
    for (const subgoal of subgoals) {
      this.goals.set(subgoal.id, subgoal);
    }

    logger.info(`Goal decomposed into ${subgoals.length} subgoals`);
    this.emit('goal:decomposed', { goal, subgoals });

    return subgoals;
  }

  /**
   * Extract goal components from description
   */
  private extractGoalComponents(
    description: string,
    context: Record<string, any>
  ): {
    type: GoalType;
    priority: Priority;
    constraints: Constraint[];
    dependencies: string[];
    metrics: Metric[];
  } {
    // Simple keyword-based extraction (could use NLP in production)
    const lowerDesc = description.toLowerCase();

    // Determine type
    let type = GoalType.TASK;
    if (lowerDesc.includes('objective') || lowerDesc.includes('achieve')) {
      type = GoalType.OBJECTIVE;
    } else if (lowerDesc.includes('milestone')) {
      type = GoalType.MILESTONE;
    } else if (lowerDesc.includes('outcome') || lowerDesc.includes('result')) {
      type = GoalType.OUTCOME;
    }

    // Determine priority
    let priority = Priority.MEDIUM;
    if (lowerDesc.includes('urgent') || lowerDesc.includes('critical')) {
      priority = Priority.CRITICAL;
    } else if (lowerDesc.includes('high priority') || lowerDesc.includes('important')) {
      priority = Priority.HIGH;
    } else if (lowerDesc.includes('low priority') || lowerDesc.includes('optional')) {
      priority = Priority.LOW;
    }

    // Extract constraints
    const constraints: Constraint[] = [];
    
    // Time constraints
    const timeMatch = description.match(/within (\d+) (hours?|days?|weeks?)/i);
    if (timeMatch) {
      constraints.push({
        type: ConstraintType.TIME,
        value: { amount: parseInt(timeMatch[1]), unit: timeMatch[2] },
        description: timeMatch[0]
      });
    }

    // Resource constraints
    if (lowerDesc.includes('budget') || lowerDesc.includes('cost')) {
      const budgetMatch = description.match(/\$(\d+)/);
      if (budgetMatch) {
        constraints.push({
          type: ConstraintType.RESOURCE,
          value: { budget: parseInt(budgetMatch[1]) },
          description: `Budget constraint: ${budgetMatch[0]}`
        });
      }
    }

    // Extract dependencies from context
    const dependencies = context.dependencies || [];

    // Define metrics
    const metrics: Metric[] = [];
    
    // Add completion metric
    metrics.push({
      name: 'Completion',
      type: MetricType.COMPLETION,
      target: 100,
      current: 0,
      unit: '%'
    });

    // Add performance metrics if mentioned
    if (lowerDesc.includes('performance') || lowerDesc.includes('speed')) {
      metrics.push({
        name: 'Performance',
        type: MetricType.PERFORMANCE,
        target: 95,
        current: 0,
        unit: '%'
      });
    }

    // Add quality metrics if mentioned
    if (lowerDesc.includes('quality') || lowerDesc.includes('accuracy')) {
      metrics.push({
        name: 'Quality',
        type: MetricType.QUALITY,
        target: 98,
        current: 0,
        unit: '%'
      });
    }

    return { type, priority, constraints, dependencies, metrics };
  }

  /**
   * Hierarchical decomposition strategy
   */
  private async hierarchicalDecomposition(goal: Goal, maxDepth: number): Promise<Goal[]> {
    if (maxDepth <= 0) return [];

    const subgoals: Goal[] = [];
    
    // Decompose based on goal type
    switch (goal.type) {
      case GoalType.OBJECTIVE:
        // Break down into milestones
        const milestones = this.generateMilestones(goal);
        for (const milestone of milestones) {
          const subgoal = await this.parseGoal(milestone, { parent: goal.id });
          subgoal.type = GoalType.MILESTONE;
          subgoals.push(subgoal);

          // Recursively decompose
          if (maxDepth > 1) {
            const subSubgoals = await this.hierarchicalDecomposition(subgoal, maxDepth - 1);
            subgoal.subgoals = subSubgoals;
          }
        }
        break;

      case GoalType.MILESTONE:
        // Break down into tasks
        const tasks = this.generateTasks(goal);
        for (const task of tasks) {
          const subgoal = await this.parseGoal(task, { parent: goal.id });
          subgoal.type = GoalType.TASK;
          subgoals.push(subgoal);
        }
        break;

      case GoalType.TASK:
        // Tasks are atomic in hierarchical decomposition
        break;
    }

    return subgoals;
  }

  /**
   * Functional decomposition strategy
   */
  private async functionalDecomposition(goal: Goal, maxDepth: number): Promise<Goal[]> {
    if (maxDepth <= 0) return [];

    const subgoals: Goal[] = [];
    
    // Identify functional areas
    const functionalAreas = this.identifyFunctionalAreas(goal);

    for (const area of functionalAreas) {
      const subgoal = await this.parseGoal(
        `${area.name}: ${area.description}`,
        { parent: goal.id, functionalArea: area.name }
      );
      subgoals.push(subgoal);

      // Recursively decompose
      if (maxDepth > 1) {
        const subSubgoals = await this.functionalDecomposition(subgoal, maxDepth - 1);
        subgoal.subgoals = subSubgoals;
      }
    }

    return subgoals;
  }

  /**
   * Temporal decomposition strategy
   */
  private async temporalDecomposition(goal: Goal, maxDepth: number): Promise<Goal[]> {
    if (maxDepth <= 0) return [];

    const subgoals: Goal[] = [];
    
    // Identify temporal phases
    const phases = this.identifyTemporalPhases(goal);

    for (const phase of phases) {
      const subgoal = await this.parseGoal(
        `${phase.name}: ${phase.description}`,
        { parent: goal.id, phase: phase.name, order: phase.order }
      );
      
      // Add temporal dependencies
      if (phase.order > 0) {
        const previousPhase = subgoals[phase.order - 1];
        if (previousPhase) {
          subgoal.dependencies.push(previousPhase.id);
        }
      }

      subgoals.push(subgoal);

      // Recursively decompose
      if (maxDepth > 1) {
        const subSubgoals = await this.temporalDecomposition(subgoal, maxDepth - 1);
        subgoal.subgoals = subSubgoals;
      }
    }

    return subgoals;
  }

  /**
   * Generate milestones for a goal
   */
  private generateMilestones(goal: Goal): string[] {
    // Simple milestone generation based on goal description
    const milestones: string[] = [];

    if (goal.description.includes('system') || goal.description.includes('application')) {
      milestones.push('Design system architecture');
      milestones.push('Implement core functionality');
      milestones.push('Add user interface');
      milestones.push('Test and validate system');
      milestones.push('Deploy to production');
    } else if (goal.description.includes('analysis') || goal.description.includes('research')) {
      milestones.push('Gather and prepare data');
      milestones.push('Perform initial analysis');
      milestones.push('Deep dive into findings');
      milestones.push('Generate insights and recommendations');
      milestones.push('Present results');
    } else {
      // Generic milestones
      milestones.push(`Plan ${goal.description}`);
      milestones.push(`Execute ${goal.description}`);
      milestones.push(`Validate ${goal.description}`);
      milestones.push(`Complete ${goal.description}`);
    }

    return milestones;
  }

  /**
   * Generate tasks for a goal
   */
  private generateTasks(goal: Goal): string[] {
    // Simple task generation based on goal description
    const tasks: string[] = [];

    if (goal.description.includes('implement')) {
      tasks.push('Set up development environment');
      tasks.push('Create initial structure');
      tasks.push('Implement main logic');
      tasks.push('Add error handling');
      tasks.push('Write tests');
      tasks.push('Document implementation');
    } else if (goal.description.includes('design')) {
      tasks.push('Research requirements');
      tasks.push('Create initial sketches');
      tasks.push('Develop detailed design');
      tasks.push('Get feedback');
      tasks.push('Refine design');
      tasks.push('Create final deliverables');
    } else {
      // Generic tasks
      tasks.push(`Prepare for ${goal.description}`);
      tasks.push(`Execute ${goal.description}`);
      tasks.push(`Review ${goal.description}`);
      tasks.push(`Finalize ${goal.description}`);
    }

    return tasks;
  }

  /**
   * Identify functional areas for a goal
   */
  private identifyFunctionalAreas(goal: Goal): Array<{ name: string; description: string }> {
    const areas: Array<{ name: string; description: string }> = [];

    // Simple functional area identification
    if (goal.description.includes('system') || goal.description.includes('application')) {
      areas.push({ name: 'Frontend', description: 'User interface and experience' });
      areas.push({ name: 'Backend', description: 'Server logic and data processing' });
      areas.push({ name: 'Database', description: 'Data storage and retrieval' });
      areas.push({ name: 'Integration', description: 'External services and APIs' });
      areas.push({ name: 'Security', description: 'Authentication and authorization' });
    } else {
      // Generic functional areas
      areas.push({ name: 'Planning', description: 'Strategy and preparation' });
      areas.push({ name: 'Execution', description: 'Implementation and action' });
      areas.push({ name: 'Monitoring', description: 'Progress tracking and adjustment' });
      areas.push({ name: 'Delivery', description: 'Completion and handoff' });
    }

    return areas;
  }

  /**
   * Identify temporal phases for a goal
   */
  private identifyTemporalPhases(goal: Goal): Array<{ name: string; description: string; order: number }> {
    const phases: Array<{ name: string; description: string; order: number }> = [];

    // Simple temporal phase identification
    phases.push({ name: 'Initiation', description: 'Project kickoff and setup', order: 0 });
    phases.push({ name: 'Planning', description: 'Detailed planning and resource allocation', order: 1 });
    phases.push({ name: 'Execution', description: 'Active work and implementation', order: 2 });
    phases.push({ name: 'Monitoring', description: 'Progress tracking and adjustments', order: 3 });
    phases.push({ name: 'Closure', description: 'Finalization and handoff', order: 4 });

    return phases;
  }

  /**
   * Update goal status
   */
  updateGoalStatus(goalId: string, status: GoalStatus): void {
    const goal = this.goals.get(goalId);
    if (!goal) {
      throw new Error(`Goal ${goalId} not found`);
    }

    goal.status = status;
    this.emit('goal:status:updated', { goalId, status });

    // Check if parent goals need status update
    this.propagateStatusUpdate(goalId);
  }

  /**
   * Update goal metric
   */
  updateGoalMetric(goalId: string, metricName: string, value: number): void {
    const goal = this.goals.get(goalId);
    if (!goal) {
      throw new Error(`Goal ${goalId} not found`);
    }

    const metric = goal.metrics.find(m => m.name === metricName);
    if (!metric) {
      throw new Error(`Metric ${metricName} not found for goal ${goalId}`);
    }

    metric.current = value;
    this.emit('goal:progress', { goalId, metric });

    // Check if goal is completed
    if (this.isGoalCompleted(goal)) {
      this.updateGoalStatus(goalId, GoalStatus.COMPLETED);
      this.emit('goal:completed', goal);
    }
  }

  /**
   * Check if goal is completed
   */
  private isGoalCompleted(goal: Goal): boolean {
    // Check if all metrics meet their targets
    const metricsComplete = goal.metrics.every(m => m.current >= m.target);

    // Check if all subgoals are completed
    const subgoalsComplete = goal.subgoals.every(sg => sg.status === GoalStatus.COMPLETED);

    return metricsComplete && subgoalsComplete;
  }

  /**
   * Propagate status updates to parent goals
   */
  private propagateStatusUpdate(goalId: string): void {
    // Find parent goals
    for (const [parentId, childIds] of this.goalHierarchy.entries()) {
      if (childIds.includes(goalId)) {
        const parent = this.goals.get(parentId);
        if (parent) {
          // Update parent metrics based on children
          this.updateParentMetrics(parent);
        }
      }
    }
  }

  /**
   * Update parent metrics based on children
   */
  private updateParentMetrics(parent: Goal): void {
    const completionMetric = parent.metrics.find(m => m.type === MetricType.COMPLETION);
    if (!completionMetric) return;

    const children = parent.subgoals;
    if (children.length === 0) return;

    // Calculate completion percentage
    const completedCount = children.filter(c => c.status === GoalStatus.COMPLETED).length;
    const completionPercentage = (completedCount / children.length) * 100;

    this.updateGoalMetric(parent.id, completionMetric.name, completionPercentage);
  }

  /**
   * Handle goal progress
   */
  private handleGoalProgress({ goalId, metric }: { goalId: string; metric: Metric }): void {
    logger.debug(`Goal progress: ${goalId} - ${metric.name}: ${metric.current}/${metric.target}`);
  }

  /**
   * Handle goal completion
   */
  private handleGoalCompleted(goal: Goal): void {
    logger.info(`Goal completed: ${goal.description} (${goal.id})`);
  }

  /**
   * Get goal by ID
   */
  getGoal(goalId: string): Goal | undefined {
    return this.goals.get(goalId);
  }

  /**
   * Get all goals
   */
  getAllGoals(): Goal[] {
    return Array.from(this.goals.values());
  }

  /**
   * Get goals by status
   */
  getGoalsByStatus(status: GoalStatus): Goal[] {
    return this.getAllGoals().filter(goal => goal.status === status);
  }

  /**
   * Get goal hierarchy
   */
  getGoalHierarchy(goalId: string): { goal: Goal; children: Goal[] } | undefined {
    const goal = this.goals.get(goalId);
    if (!goal) return undefined;

    const childIds = this.goalHierarchy.get(goalId) || [];
    const children = childIds.map(id => this.goals.get(id)).filter(Boolean) as Goal[];

    return { goal, children };
  }
}