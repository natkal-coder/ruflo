/**
 * Goal-related MCP tools
 */

import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { GoalManager } from '../core/goal-manager';
import {
  GoalParseSchema,
  GoalDecomposeSchema,
  ToolResponse,
  GoalStatus,
  Priority,
  GoalType
} from '../types';
import { logger } from '../utils/logger';

export class GoalTools {
  constructor(private goalManager: GoalManager) {}

  /**
   * Get all goal-related tools
   */
  getTools(): Tool[] {
    return [
      this.getGoalParseTool(),
      this.getGoalDecomposeTool(),
      this.getGoalListTool(),
      this.getGoalStatusTool(),
      this.getGoalUpdateTool(),
      this.getGoalMetricsTool(),
      this.getGoalHierarchyTool()
    ];
  }

  /**
   * Goal parse tool
   */
  private getGoalParseTool(): Tool {
    return {
      name: 'goal_parse',
      description: 'Parse a natural language goal description into structured components',
      inputSchema: {
        type: 'object',
        properties: {
          description: {
            type: 'string',
            description: 'Natural language description of the goal'
          },
          context: {
            type: 'object',
            description: 'Additional context for goal parsing',
            properties: {
              domain: { type: 'string' },
              priority: { type: 'string', enum: Object.values(Priority) },
              deadline: { type: 'string' },
              resources: { type: 'array', items: { type: 'string' } },
              constraints: { type: 'array', items: { type: 'string' } },
              dependencies: { type: 'array', items: { type: 'string' } }
            }
          }
        },
        required: ['description']
      }
    };
  }

  /**
   * Goal decompose tool
   */
  private getGoalDecomposeTool(): Tool {
    return {
      name: 'goal_decompose',
      description: 'Break down a goal into smaller, manageable subgoals',
      inputSchema: {
        type: 'object',
        properties: {
          goalId: {
            type: 'string',
            description: 'ID of the goal to decompose'
          },
          maxDepth: {
            type: 'number',
            description: 'Maximum depth of decomposition',
            minimum: 1,
            maximum: 5,
            default: 3
          },
          strategy: {
            type: 'string',
            enum: ['hierarchical', 'functional', 'temporal'],
            description: 'Decomposition strategy to use',
            default: 'hierarchical'
          }
        },
        required: ['goalId']
      }
    };
  }

  /**
   * Goal list tool
   */
  private getGoalListTool(): Tool {
    return {
      name: 'goal_list',
      description: 'List all goals or filter by status, type, or priority',
      inputSchema: {
        type: 'object',
        properties: {
          status: {
            type: 'string',
            enum: Object.values(GoalStatus),
            description: 'Filter goals by status'
          },
          type: {
            type: 'string',
            enum: Object.values(GoalType),
            description: 'Filter goals by type'
          },
          priority: {
            type: 'string',
            enum: Object.values(Priority),
            description: 'Filter goals by priority'
          }
        }
      }
    };
  }

  /**
   * Goal status tool
   */
  private getGoalStatusTool(): Tool {
    return {
      name: 'goal_status',
      description: 'Get detailed status and progress information for a goal',
      inputSchema: {
        type: 'object',
        properties: {
          goalId: {
            type: 'string',
            description: 'ID of the goal'
          }
        },
        required: ['goalId']
      }
    };
  }

  /**
   * Goal update tool
   */
  private getGoalUpdateTool(): Tool {
    return {
      name: 'goal_update',
      description: 'Update goal status, metrics, or other properties',
      inputSchema: {
        type: 'object',
        properties: {
          goalId: {
            type: 'string',
            description: 'ID of the goal to update'
          },
          status: {
            type: 'string',
            enum: Object.values(GoalStatus),
            description: 'New status for the goal'
          },
          metrics: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                value: { type: 'number' }
              },
              required: ['name', 'value']
            },
            description: 'Metric updates'
          },
          progress: {
            type: 'number',
            minimum: 0,
            maximum: 100,
            description: 'Overall progress percentage'
          }
        },
        required: ['goalId']
      }
    };
  }

  /**
   * Goal metrics tool
   */
  private getGoalMetricsTool(): Tool {
    return {
      name: 'goal_metrics',
      description: 'Get detailed metrics and performance data for a goal',
      inputSchema: {
        type: 'object',
        properties: {
          goalId: {
            type: 'string',
            description: 'ID of the goal'
          }
        },
        required: ['goalId']
      }
    };
  }

  /**
   * Goal hierarchy tool
   */
  private getGoalHierarchyTool(): Tool {
    return {
      name: 'goal_hierarchy',
      description: 'Get the hierarchical structure of a goal and its subgoals',
      inputSchema: {
        type: 'object',
        properties: {
          goalId: {
            type: 'string',
            description: 'ID of the goal'
          },
          depth: {
            type: 'number',
            description: 'Depth of hierarchy to return',
            minimum: 1,
            default: 3
          }
        },
        required: ['goalId']
      }
    };
  }

  /**
   * Handle tool calls
   */
  async handleToolCall(name: string, args: any): Promise<ToolResponse> {
    try {
      switch (name) {
        case 'goal_parse':
          return await this.handleGoalParse(args);
        case 'goal_decompose':
          return await this.handleGoalDecompose(args);
        case 'goal_list':
          return await this.handleGoalList(args);
        case 'goal_status':
          return await this.handleGoalStatus(args);
        case 'goal_update':
          return await this.handleGoalUpdate(args);
        case 'goal_metrics':
          return await this.handleGoalMetrics(args);
        case 'goal_hierarchy':
          return await this.handleGoalHierarchy(args);
        default:
          throw new Error(`Unknown goal tool: ${name}`);
      }
    } catch (error) {
      logger.error(`Goal tool error: ${name} - ${error}`);
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Handle goal parsing
   */
  private async handleGoalParse(args: any): Promise<ToolResponse> {
    const validated = GoalParseSchema.parse(args);

    const goal = await this.goalManager.parseGoal(
      validated.description,
      validated.context
    );

    return {
      success: true,
      data: {
        goal: {
          id: goal.id,
          description: goal.description,
          type: goal.type,
          priority: goal.priority,
          status: goal.status,
          constraints: goal.constraints,
          metrics: goal.metrics,
          dependencies: goal.dependencies
        }
      },
      metadata: {
        operation: 'goal_parse',
        timestamp: new Date().toISOString(),
        complexity: this.calculateGoalComplexity(goal)
      }
    };
  }

  /**
   * Handle goal decomposition
   */
  private async handleGoalDecompose(args: any): Promise<ToolResponse> {
    const validated = GoalDecomposeSchema.parse(args);

    const subgoals = await this.goalManager.decomposeGoal(
      validated.goalId,
      validated.maxDepth,
      validated.strategy
    );

    const goal = this.goalManager.getGoal(validated.goalId);
    if (!goal) {
      throw new Error(`Goal ${validated.goalId} not found`);
    }

    return {
      success: true,
      data: {
        goal: {
          id: goal.id,
          description: goal.description,
          type: goal.type
        },
        subgoals: subgoals.map(subgoal => ({
          id: subgoal.id,
          description: subgoal.description,
          type: subgoal.type,
          priority: subgoal.priority,
          status: subgoal.status,
          dependencies: subgoal.dependencies
        })),
        decompositionInfo: {
          strategy: validated.strategy,
          depth: validated.maxDepth,
          totalSubgoals: subgoals.length
        }
      },
      metadata: {
        operation: 'goal_decompose',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle goal listing
   */
  private async handleGoalList(args: any): Promise<ToolResponse> {
    let goals = this.goalManager.getAllGoals();

    // Apply filters
    if (args.status) {
      goals = goals.filter(goal => goal.status === args.status);
    }

    if (args.type) {
      goals = goals.filter(goal => goal.type === args.type);
    }

    if (args.priority) {
      goals = goals.filter(goal => goal.priority === args.priority);
    }

    const goalSummaries = goals.map(goal => ({
      id: goal.id,
      description: goal.description,
      type: goal.type,
      priority: goal.priority,
      status: goal.status,
      subgoalCount: goal.subgoals.length,
      progress: this.calculateGoalProgress(goal),
      constraintCount: goal.constraints.length,
      metricCount: goal.metrics.length
    }));

    // Sort by priority and status
    goalSummaries.sort((a, b) => {
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const statusOrder = { in_progress: 0, pending: 1, blocked: 2, completed: 3, failed: 4 };
      
      return priorityOrder[a.priority as keyof typeof priorityOrder] - 
             priorityOrder[b.priority as keyof typeof priorityOrder] ||
             statusOrder[a.status as keyof typeof statusOrder] - 
             statusOrder[b.status as keyof typeof statusOrder];
    });

    return {
      success: true,
      data: {
        goals: goalSummaries,
        count: goalSummaries.length,
        summary: {
          byStatus: this.groupBy(goals, 'status'),
          byType: this.groupBy(goals, 'type'),
          byPriority: this.groupBy(goals, 'priority')
        }
      },
      metadata: {
        operation: 'goal_list',
        timestamp: new Date().toISOString(),
        filters: { status: args.status, type: args.type, priority: args.priority }
      }
    };
  }

  /**
   * Handle goal status
   */
  private async handleGoalStatus(args: any): Promise<ToolResponse> {
    const goal = this.goalManager.getGoal(args.goalId);
    if (!goal) {
      throw new Error(`Goal ${args.goalId} not found`);
    }

    const hierarchy = this.goalManager.getGoalHierarchy(args.goalId);
    const progress = this.calculateGoalProgress(goal);
    const blockers = this.identifyBlockers(goal);
    const nextSteps = this.suggestNextSteps(goal);

    return {
      success: true,
      data: {
        goal: {
          id: goal.id,
          description: goal.description,
          type: goal.type,
          priority: goal.priority,
          status: goal.status,
          constraints: goal.constraints,
          dependencies: goal.dependencies,
          metrics: goal.metrics,
          subgoals: goal.subgoals.map(sg => ({
            id: sg.id,
            description: sg.description,
            status: sg.status,
            progress: this.calculateGoalProgress(sg)
          }))
        },
        analysis: {
          progress,
          blockers,
          nextSteps,
          estimatedCompletion: this.estimateCompletion(goal),
          riskLevel: this.assessRisk(goal)
        }
      },
      metadata: {
        operation: 'goal_status',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle goal updates
   */
  private async handleGoalUpdate(args: any): Promise<ToolResponse> {
    const goal = this.goalManager.getGoal(args.goalId);
    if (!goal) {
      throw new Error(`Goal ${args.goalId} not found`);
    }

    const updates: string[] = [];

    // Update status
    if (args.status && args.status !== goal.status) {
      this.goalManager.updateGoalStatus(args.goalId, args.status);
      updates.push(`Status updated to ${args.status}`);
    }

    // Update metrics
    if (args.metrics) {
      for (const metricUpdate of args.metrics) {
        this.goalManager.updateGoalMetric(args.goalId, metricUpdate.name, metricUpdate.value);
        updates.push(`Metric ${metricUpdate.name} updated to ${metricUpdate.value}`);
      }
    }

    // Update progress (completion metric)
    if (args.progress !== undefined) {
      this.goalManager.updateGoalMetric(args.goalId, 'Completion', args.progress);
      updates.push(`Progress updated to ${args.progress}%`);
    }

    const updatedGoal = this.goalManager.getGoal(args.goalId)!;

    return {
      success: true,
      data: {
        goal: {
          id: updatedGoal.id,
          status: updatedGoal.status,
          metrics: updatedGoal.metrics,
          progress: this.calculateGoalProgress(updatedGoal)
        },
        updates
      },
      metadata: {
        operation: 'goal_update',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle goal metrics
   */
  private async handleGoalMetrics(args: any): Promise<ToolResponse> {
    const goal = this.goalManager.getGoal(args.goalId);
    if (!goal) {
      throw new Error(`Goal ${args.goalId} not found`);
    }

    const metrics = goal.metrics.map(metric => ({
      ...metric,
      progress: (metric.current / metric.target) * 100,
      remaining: metric.target - metric.current
    }));

    const overallProgress = this.calculateGoalProgress(goal);
    const velocity = this.calculateVelocity(goal);
    const trend = this.calculateTrend(goal);

    return {
      success: true,
      data: {
        goal: {
          id: goal.id,
          description: goal.description
        },
        metrics,
        analytics: {
          overallProgress,
          velocity,
          trend,
          performanceScore: this.calculatePerformanceScore(goal),
          healthStatus: this.assessGoalHealth(goal)
        }
      },
      metadata: {
        operation: 'goal_metrics',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Handle goal hierarchy
   */
  private async handleGoalHierarchy(args: any): Promise<ToolResponse> {
    const hierarchy = this.goalManager.getGoalHierarchy(args.goalId);
    if (!hierarchy) {
      throw new Error(`Goal ${args.goalId} not found`);
    }

    const buildHierarchyTree = (goal: any, depth: number, maxDepth: number): any => {
      if (depth >= maxDepth) return null;

      return {
        id: goal.id,
        description: goal.description,
        type: goal.type,
        status: goal.status,
        priority: goal.priority,
        progress: this.calculateGoalProgress(goal),
        children: goal.subgoals
          .map((subgoal: any) => buildHierarchyTree(subgoal, depth + 1, maxDepth))
          .filter(Boolean)
      };
    };

    const tree = buildHierarchyTree(hierarchy.goal, 0, args.depth || 3);

    return {
      success: true,
      data: {
        hierarchy: tree,
        statistics: {
          totalGoals: this.countGoalsInHierarchy(tree),
          maxDepth: this.calculateMaxDepth(tree),
          completionRate: this.calculateHierarchyCompletion(tree)
        }
      },
      metadata: {
        operation: 'goal_hierarchy',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Calculate goal complexity
   */
  private calculateGoalComplexity(goal: any): 'low' | 'medium' | 'high' {
    let complexity = 0;
    
    complexity += goal.constraints.length * 2;
    complexity += goal.dependencies.length * 1.5;
    complexity += goal.metrics.length * 1;
    
    if (goal.type === GoalType.OBJECTIVE) complexity += 3;
    if (goal.priority === Priority.CRITICAL) complexity += 2;

    if (complexity < 5) return 'low';
    if (complexity < 10) return 'medium';
    return 'high';
  }

  /**
   * Calculate goal progress
   */
  private calculateGoalProgress(goal: any): number {
    if (goal.metrics.length === 0) return 0;

    const completionMetric = goal.metrics.find((m: any) => m.type === 'completion');
    if (completionMetric) {
      return (completionMetric.current / completionMetric.target) * 100;
    }

    // Average of all metrics
    const avgProgress = goal.metrics.reduce((sum: number, metric: any) => {
      return sum + (metric.current / metric.target);
    }, 0) / goal.metrics.length;

    return Math.min(avgProgress * 100, 100);
  }

  /**
   * Group array by property
   */
  private groupBy<T>(array: T[], property: keyof T): Record<string, number> {
    return array.reduce((groups, item) => {
      const key = String(item[property]);
      groups[key] = (groups[key] || 0) + 1;
      return groups;
    }, {} as Record<string, number>);
  }

  /**
   * Identify goal blockers
   */
  private identifyBlockers(goal: any): string[] {
    const blockers: string[] = [];

    if (goal.status === GoalStatus.BLOCKED) {
      blockers.push('Goal is explicitly marked as blocked');
    }

    // Check dependencies
    for (const depId of goal.dependencies) {
      const dependency = this.goalManager.getGoal(depId);
      if (dependency && dependency.status !== GoalStatus.COMPLETED) {
        blockers.push(`Waiting for dependency: ${dependency.description}`);
      }
    }

    // Check resource constraints
    const resourceConstraints = goal.constraints.filter((c: any) => c.type === 'resource');
    if (resourceConstraints.length > 0) {
      blockers.push('Resource constraints may be limiting progress');
    }

    return blockers;
  }

  /**
   * Suggest next steps
   */
  private suggestNextSteps(goal: any): string[] {
    const nextSteps: string[] = [];

    if (goal.status === GoalStatus.PENDING) {
      nextSteps.push('Begin goal execution');
      
      if (goal.subgoals.length > 0) {
        const pendingSubgoals = goal.subgoals.filter((sg: any) => sg.status === GoalStatus.PENDING);
        if (pendingSubgoals.length > 0) {
          nextSteps.push(`Start working on subgoal: ${pendingSubgoals[0].description}`);
        }
      }
    }

    if (goal.status === GoalStatus.IN_PROGRESS) {
      const blockedSubgoals = goal.subgoals.filter((sg: any) => sg.status === GoalStatus.BLOCKED);
      if (blockedSubgoals.length > 0) {
        nextSteps.push(`Resolve blockers for: ${blockedSubgoals[0].description}`);
      }

      const inProgressSubgoals = goal.subgoals.filter((sg: any) => sg.status === GoalStatus.IN_PROGRESS);
      if (inProgressSubgoals.length > 0) {
        nextSteps.push(`Continue progress on: ${inProgressSubgoals[0].description}`);
      }
    }

    if (goal.status === GoalStatus.BLOCKED) {
      nextSteps.push('Identify and resolve blocking issues');
      nextSteps.push('Review dependencies and constraints');
    }

    return nextSteps;
  }

  /**
   * Estimate completion time
   */
  private estimateCompletion(goal: any): string {
    const progress = this.calculateGoalProgress(goal);
    
    if (progress === 0) return 'Unable to estimate';
    if (progress >= 100) return 'Completed';

    // Simple linear estimation (could be more sophisticated)
    const velocity = this.calculateVelocity(goal);
    if (velocity <= 0) return 'Unable to estimate';

    const remainingProgress = 100 - progress;
    const estimatedDays = Math.ceil(remainingProgress / velocity);

    if (estimatedDays === 1) return '1 day';
    if (estimatedDays < 7) return `${estimatedDays} days`;
    if (estimatedDays < 30) return `${Math.ceil(estimatedDays / 7)} weeks`;
    return `${Math.ceil(estimatedDays / 30)} months`;
  }

  /**
   * Assess risk level
   */
  private assessRisk(goal: any): 'low' | 'medium' | 'high' {
    let riskScore = 0;

    if (goal.status === GoalStatus.BLOCKED) riskScore += 3;
    if (goal.dependencies.length > 3) riskScore += 2;
    if (goal.constraints.length > 2) riskScore += 1;
    if (goal.priority === Priority.CRITICAL) riskScore += 1;

    const progress = this.calculateGoalProgress(goal);
    if (progress < 20) riskScore += 2;

    if (riskScore < 3) return 'low';
    if (riskScore < 6) return 'medium';
    return 'high';
  }

  /**
   * Calculate velocity (progress per day)
   */
  private calculateVelocity(goal: any): number {
    // Simplified calculation - would need historical data in real implementation
    const progress = this.calculateGoalProgress(goal);
    return Math.max(progress / 7, 1); // Assume 1 week has passed
  }

  /**
   * Calculate trend
   */
  private calculateTrend(goal: any): 'improving' | 'stable' | 'declining' {
    // Simplified - would need historical data
    const velocity = this.calculateVelocity(goal);
    if (velocity > 10) return 'improving';
    if (velocity > 5) return 'stable';
    return 'declining';
  }

  /**
   * Calculate performance score
   */
  private calculatePerformanceScore(goal: any): number {
    const progress = this.calculateGoalProgress(goal);
    const velocity = this.calculateVelocity(goal);
    
    // Weighted score
    return Math.min((progress * 0.7 + velocity * 3 * 0.3), 100);
  }

  /**
   * Assess goal health
   */
  private assessGoalHealth(goal: any): 'healthy' | 'at_risk' | 'critical' {
    const performanceScore = this.calculatePerformanceScore(goal);
    const blockers = this.identifyBlockers(goal);

    if (goal.status === GoalStatus.BLOCKED || blockers.length > 2) return 'critical';
    if (performanceScore < 50 || blockers.length > 0) return 'at_risk';
    return 'healthy';
  }

  /**
   * Count goals in hierarchy
   */
  private countGoalsInHierarchy(tree: any): number {
    if (!tree) return 0;
    return 1 + (tree.children || []).reduce((sum: number, child: any) => 
      sum + this.countGoalsInHierarchy(child), 0);
  }

  /**
   * Calculate max depth of hierarchy
   */
  private calculateMaxDepth(tree: any, currentDepth = 0): number {
    if (!tree || !tree.children || tree.children.length === 0) {
      return currentDepth;
    }
    
    return Math.max(...tree.children.map((child: any) => 
      this.calculateMaxDepth(child, currentDepth + 1)));
  }

  /**
   * Calculate hierarchy completion rate
   */
  private calculateHierarchyCompletion(tree: any): number {
    if (!tree) return 0;

    const totalProgress = tree.progress + (tree.children || []).reduce((sum: number, child: any) => 
      sum + this.calculateHierarchyCompletion(child), 0);
    
    const totalGoals = this.countGoalsInHierarchy(tree);
    return totalGoals > 0 ? totalProgress / totalGoals : 0;
  }
}