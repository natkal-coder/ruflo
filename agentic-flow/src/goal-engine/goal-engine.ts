import { EventEmitter } from 'eventemitter3';
import { v4 as uuidv4 } from 'uuid';
import * as natural from 'natural';
import nlp from 'compromise';
import {
  Goal,
  GoalType,
  GoalPriority,
  GoalStatus,
  AgentId,
  Constraint,
  NLPIntent,
  NLPEntity,
  Task,
  TaskStatus
} from '../types';
import { Logger } from '../utils/logger';

/**
 * Goal Engine for natural language processing and goal management
 */
export class GoalEngine extends EventEmitter {
  private readonly agentId: AgentId;
  private readonly logger: Logger;
  private goals: Map<string, Goal>;
  private goalDependencies: Map<string, Set<string>>;
  private tokenizer: natural.WordTokenizer;
  private classifier: natural.BayesClassifier;
  private goalQueue: PriorityQueue<Goal>;

  constructor(agentId: AgentId) {
    super();
    this.agentId = agentId;
    this.logger = new Logger(`GoalEngine:${agentId.id}`);
    this.goals = new Map();
    this.goalDependencies = new Map();
    this.tokenizer = new natural.WordTokenizer();
    this.classifier = new natural.BayesClassifier();
    this.goalQueue = new PriorityQueue<Goal>(this.compareGoals);
    
    this.initializeClassifier();
  }

  /**
   * Initialize the NLP classifier with training data
   */
  private initializeClassifier(): void {
    // Train classifier for goal types
    this.classifier.addDocument('achieve complete finish accomplish', GoalType.ACHIEVE);
    this.classifier.addDocument('maintain keep preserve sustain', GoalType.MAINTAIN);
    this.classifier.addDocument('query find search discover what how why', GoalType.QUERY);
    this.classifier.addDocument('perform execute run do action', GoalType.PERFORM);
    this.classifier.addDocument('prevent avoid stop block prohibit', GoalType.PREVENT);
    
    this.classifier.train();
  }

  /**
   * Parse natural language input into a Goal
   */
  public async parseGoal(input: string, context?: Record<string, any>): Promise<Goal> {
    try {
      this.logger.debug('Parsing goal from input', { input });
      
      // Extract intent and entities
      const intent = await this.extractIntent(input);
      const entities = await this.extractEntities(input);
      
      // Determine goal type
      const goalType = this.classifier.classify(input) as GoalType;
      
      // Extract priority from keywords
      const priority = this.extractPriority(input);
      
      // Extract deadline if present
      const deadline = this.extractDeadline(input);
      
      // Create goal
      const goal: Goal = {
        id: uuidv4(),
        description: input,
        type: goalType,
        priority,
        status: GoalStatus.PENDING,
        dependencies: [],
        constraints: this.extractConstraints(input, entities),
        deadline,
        metadata: {
          nlpIntent: intent,
          entities,
          context,
          createdAt: new Date()
        }
      };
      
      this.logger.info('Parsed goal successfully', { goalId: goal.id, type: goalType });
      return goal;
    } catch (error) {
      this.logger.error('Failed to parse goal', error);
      throw error;
    }
  }

  /**
   * Extract intent from natural language input
   */
  private async extractIntent(input: string): Promise<NLPIntent> {
    const doc = nlp(input);
    
    // Extract verbs as potential intents
    const verbs = doc.verbs().out('array');
    const intent = verbs[0] || 'unknown';
    
    // Calculate confidence based on clarity
    const confidence = this.calculateConfidence(input);
    
    // Extract entities
    const entities: NLPEntity[] = [];
    
    // Extract people
    doc.people().forEach((term: any) => {
      entities.push({
        type: 'person',
        value: term.text(),
        confidence: 0.9,
        position: [term.offset, term.offset + term.length]
      });
    });
    
    // Extract places
    doc.places().forEach((term: any) => {
      entities.push({
        type: 'place',
        value: term.text(),
        confidence: 0.9,
        position: [term.offset, term.offset + term.length]
      });
    });
    
    // Extract dates (using generic term iteration)
    const terms = doc.terms().out('array') as string[];
    terms.forEach((term, index) => {
      if (/\d{1,2}[/-]\d{1,2}[/-]\d{2,4}/.test(term)) {
        entities.push({
          type: 'date',
          value: term,
          confidence: 0.9,
          position: [index * 10, (index + 1) * 10]
        });
      }
    });
    
    return {
      intent,
      confidence,
      entities
    };
  }

  /**
   * Extract entities from input
   */
  private async extractEntities(input: string): Promise<NLPEntity[]> {
    const doc = nlp(input);
    const entities: NLPEntity[] = [];
    
    // Extract nouns as potential entities
    doc.nouns().forEach((noun: any) => {
      entities.push({
        type: 'object',
        value: noun.text(),
        confidence: 0.8,
        position: [noun.offset, noun.offset + noun.length]
      });
    });
    
    // Extract numbers
    const docTerms = doc.terms().out('array') as string[];
    docTerms.forEach((term, index) => {
      if (/^\d+$/.test(term)) {
        entities.push({
          type: 'number',
          value: term,
          confidence: 0.95,
          position: [index * 10, (index + 1) * 10]
        });
      }
    });
    
    return entities;
  }

  /**
   * Extract priority from input
   */
  private extractPriority(input: string): GoalPriority {
    const lowercased = input.toLowerCase();
    
    if (lowercased.includes('urgent') || lowercased.includes('critical') || lowercased.includes('asap')) {
      return GoalPriority.CRITICAL;
    } else if (lowercased.includes('high priority') || lowercased.includes('important')) {
      return GoalPriority.HIGH;
    } else if (lowercased.includes('low priority') || lowercased.includes('when possible')) {
      return GoalPriority.LOW;
    }
    
    return GoalPriority.MEDIUM;
  }

  /**
   * Extract deadline from input
   */
  private extractDeadline(input: string): Date | undefined {
    // Simple regex-based date extraction
    const dateRegex = /\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b/;
    const match = input.match(dateRegex);
    
    if (match) {
      const parsed = new Date(match[0]);
      if (!isNaN(parsed.getTime())) {
        return parsed;
      }
    }
    
    return undefined;
  }

  /**
   * Extract constraints from input and entities
   */
  private extractConstraints(input: string, entities: NLPEntity[]): Constraint[] {
    const constraints: Constraint[] = [];
    
    // Time constraints
    if (input.includes('within') || input.includes('before')) {
      const timeEntity = entities.find(e => e.type === 'date' || e.type === 'number');
      if (timeEntity) {
        constraints.push({
          type: 'time',
          value: timeEntity.value,
          description: 'Time constraint'
        });
      }
    }
    
    // Resource constraints
    if (input.includes('using') || input.includes('with')) {
      const resourceEntities = entities.filter(e => e.type === 'object');
      resourceEntities.forEach(entity => {
        constraints.push({
          type: 'resource',
          value: entity.value,
          description: 'Required resource'
        });
      });
    }
    
    return constraints;
  }

  /**
   * Calculate confidence score for intent extraction
   */
  private calculateConfidence(input: string): number {
    const tokens = this.tokenizer.tokenize(input) || [];
    const sentenceLength = tokens.length;
    
    // Simple heuristic: longer, more specific sentences have higher confidence
    if (sentenceLength < 3) return 0.3;
    if (sentenceLength < 5) return 0.5;
    if (sentenceLength < 10) return 0.7;
    return 0.9;
  }

  /**
   * Add a goal to the engine
   */
  public async addGoal(goal: Goal): Promise<void> {
    try {
      this.logger.info('Adding goal to engine', { goalId: goal.id });
      
      // Store goal
      this.goals.set(goal.id, goal);
      
      // Process dependencies
      if (goal.dependencies.length > 0) {
        this.goalDependencies.set(goal.id, new Set(goal.dependencies));
      }
      
      // Add to priority queue if ready
      if (this.isGoalReady(goal)) {
        this.goalQueue.enqueue(goal);
      }
      
      this.emit('goal:added', goal);
    } catch (error) {
      this.logger.error('Failed to add goal', error);
      throw error;
    }
  }

  /**
   * Update goal status
   */
  public async updateGoalStatus(goalId: string, status: GoalStatus): Promise<void> {
    const goal = this.goals.get(goalId);
    if (!goal) {
      throw new Error(`Goal not found: ${goalId}`);
    }
    
    const previousStatus = goal.status;
    goal.status = status;
    
    this.logger.info('Updated goal status', { goalId, previousStatus, newStatus: status });
    
    // Handle status transitions
    if (status === GoalStatus.COMPLETED || status === GoalStatus.FAILED) {
      // Check dependent goals
      this.checkDependentGoals(goalId);
    }
    
    this.emit('goal:statusChanged', { goal, previousStatus, newStatus: status });
  }

  /**
   * Get next goal to process
   */
  public getNextGoal(): Goal | undefined {
    while (!this.goalQueue.isEmpty()) {
      const goal = this.goalQueue.dequeue();
      if (goal && this.isGoalReady(goal)) {
        return goal;
      }
    }
    return undefined;
  }

  /**
   * Decompose a goal into sub-goals
   */
  public async decomposeGoal(goal: Goal): Promise<Goal[]> {
    try {
      this.logger.debug('Decomposing goal', { goalId: goal.id });
      
      const subGoals: Goal[] = [];
      
      // Analyze goal description for decomposition hints
      const doc = nlp(goal.description);
      const clauses = doc.clauses().out('array');
      
      if (clauses.length > 1) {
        // Create sub-goals from clauses
        for (const clause of clauses) {
          const subGoal = await this.parseGoal(clause, goal.metadata);
          subGoal.dependencies = [goal.id];
          subGoals.push(subGoal);
        }
      } else {
        // Try to identify steps in the goal
        const steps = this.identifySteps(goal.description);
        for (const step of steps) {
          const subGoal = await this.parseGoal(step, goal.metadata);
          subGoal.dependencies = [goal.id];
          subGoals.push(subGoal);
        }
      }
      
      goal.subGoals = subGoals;
      this.logger.info('Decomposed goal into sub-goals', { goalId: goal.id, count: subGoals.length });
      
      return subGoals;
    } catch (error) {
      this.logger.error('Failed to decompose goal', error);
      return [];
    }
  }

  /**
   * Convert a goal to executable tasks
   */
  public async goalToTasks(goal: Goal): Promise<Task[]> {
    try {
      this.logger.debug('Converting goal to tasks', { goalId: goal.id });
      
      const tasks: Task[] = [];
      
      // If goal has sub-goals, convert them first
      if (goal.subGoals && goal.subGoals.length > 0) {
        for (const subGoal of goal.subGoals) {
          const subTasks = await this.goalToTasks(subGoal);
          tasks.push(...subTasks);
        }
      } else {
        // Create a single task for the goal
        const task: Task = {
          id: uuidv4(),
          goalId: goal.id,
          assignedTo: this.agentId,
          description: goal.description,
          status: TaskStatus.PENDING
        };
        tasks.push(task);
      }
      
      this.logger.info('Converted goal to tasks', { goalId: goal.id, taskCount: tasks.length });
      return tasks;
    } catch (error) {
      this.logger.error('Failed to convert goal to tasks', error);
      return [];
    }
  }

  /**
   * Check if a goal is ready to be processed
   */
  private isGoalReady(goal: Goal): boolean {
    if (goal.status !== GoalStatus.PENDING) {
      return false;
    }
    
    // Check dependencies
    for (const depId of goal.dependencies) {
      const depGoal = this.goals.get(depId);
      if (!depGoal || depGoal.status !== GoalStatus.COMPLETED) {
        return false;
      }
    }
    
    return true;
  }

  /**
   * Check and activate dependent goals
   */
  private checkDependentGoals(completedGoalId: string): void {
    for (const [goalId, deps] of this.goalDependencies) {
      if (deps.has(completedGoalId)) {
        const goal = this.goals.get(goalId);
        if (goal && this.isGoalReady(goal)) {
          this.goalQueue.enqueue(goal);
          this.emit('goal:ready', goal);
        }
      }
    }
  }

  /**
   * Identify steps in a goal description
   */
  private identifySteps(description: string): string[] {
    const steps: string[] = [];
    
    // Look for numbered steps
    const numberedSteps = description.match(/\d+\.\s+[^.]+/g);
    if (numberedSteps) {
      return numberedSteps.map(step => step.replace(/^\d+\.\s+/, ''));
    }
    
    // Look for sequence words
    const sequenceWords = ['first', 'then', 'next', 'after', 'finally'];
    const doc = nlp(description);
    const sentences = doc.sentences().out('array');
    
    for (const sentence of sentences) {
      const hasSequence = sequenceWords.some(word => 
        sentence.toLowerCase().includes(word)
      );
      if (hasSequence) {
        steps.push(sentence);
      }
    }
    
    return steps.length > 0 ? steps : [description];
  }

  /**
   * Compare goals for priority queue
   */
  private compareGoals(a: Goal, b: Goal): number {
    // Priority comparison
    const priorityWeight = { 
      [GoalPriority.CRITICAL]: 4,
      [GoalPriority.HIGH]: 3,
      [GoalPriority.MEDIUM]: 2,
      [GoalPriority.LOW]: 1
    };
    
    const priorityDiff = priorityWeight[b.priority] - priorityWeight[a.priority];
    if (priorityDiff !== 0) return priorityDiff;
    
    // Deadline comparison
    if (a.deadline && b.deadline) {
      return a.deadline.getTime() - b.deadline.getTime();
    } else if (a.deadline) {
      return -1;
    } else if (b.deadline) {
      return 1;
    }
    
    return 0;
  }

  /**
   * Get all goals
   */
  public getAllGoals(): Goal[] {
    return Array.from(this.goals.values());
  }

  /**
   * Get goals by status
   */
  public getGoalsByStatus(status: GoalStatus): Goal[] {
    return Array.from(this.goals.values()).filter(goal => goal.status === status);
  }

  /**
   * Clear all goals
   */
  public clearGoals(): void {
    this.goals.clear();
    this.goalDependencies.clear();
    this.goalQueue.clear();
    this.emit('goals:cleared');
  }
}

/**
 * Priority Queue implementation for goal scheduling
 */
class PriorityQueue<T> {
  private items: T[] = [];
  private compare: (a: T, b: T) => number;

  constructor(compareFunction: (a: T, b: T) => number) {
    this.compare = compareFunction;
  }

  enqueue(item: T): void {
    this.items.push(item);
    this.items.sort(this.compare);
  }

  dequeue(): T | undefined {
    return this.items.shift();
  }

  isEmpty(): boolean {
    return this.items.length === 0;
  }

  size(): number {
    return this.items.length;
  }

  clear(): void {
    this.items = [];
  }
}