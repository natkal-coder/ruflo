import { EventEmitter } from 'eventemitter3';
import { v4 as uuidv4 } from 'uuid';
import {
  Team,
  TeamFormation,
  TeamStatus,
  AgentId,
  Goal,
  AgentProfile,
  AgentCapability,
  CoordinationStrategy,
  CoordinationContext,
  Message,
  MessageType,
  MessagePriority
} from '../types';
import { Logger } from '../utils/logger';
import { MessageBus } from '../communication/message-bus';

/**
 * Team coordinator for managing agent teams and coordination
 */
export class TeamCoordinator extends EventEmitter {
  private readonly logger: Logger;
  private readonly messageBus: MessageBus;
  private teams: Map<string, Team>;
  private agentTeams: Map<string, string>; // agentId -> teamId
  private strategies: Map<string, CoordinationStrategy>;

  constructor() {
    super();
    this.logger = new Logger('TeamCoordinator');
    this.messageBus = MessageBus.getInstance();
    this.teams = new Map();
    this.agentTeams = new Map();
    this.strategies = new Map();
    
    this.initializeStrategies();
  }

  /**
   * Initialize default coordination strategies
   */
  private initializeStrategies(): void {
    // Hierarchical strategy
    this.registerStrategy({
      type: 'hierarchical',
      parameters: { levels: 3 },
      evaluate: (context) => {
        // Evaluate based on team size and goal complexity
        const teamSize = context.team.members.length;
        const goalComplexity = context.currentGoals.reduce((sum, g) => 
          sum + (g.subGoals?.length || 1), 0
        );
        return teamSize > 5 && goalComplexity > 10 ? 0.9 : 0.5;
      }
    });
    
    // Flat strategy
    this.registerStrategy({
      type: 'flat',
      parameters: { maxSize: 10 },
      evaluate: (context) => {
        // Better for small teams with simple goals
        const teamSize = context.team.members.length;
        const goalComplexity = context.currentGoals.reduce((sum, g) => 
          sum + (g.subGoals?.length || 1), 0
        );
        return teamSize <= 5 && goalComplexity <= 5 ? 0.9 : 0.3;
      }
    });
    
    // Matrix strategy
    this.registerStrategy({
      type: 'matrix',
      parameters: { dimensions: 2 },
      evaluate: (context) => {
        // Good for cross-functional teams
        const uniqueCapabilities = new Set<string>();
        context.team.members.forEach(memberId => {
          // In real implementation, would look up agent capabilities
          uniqueCapabilities.add('default');
        });
        return uniqueCapabilities.size > 3 ? 0.8 : 0.4;
      }
    });
    
    // Dynamic strategy
    this.registerStrategy({
      type: 'dynamic',
      parameters: { adaptationRate: 0.1 },
      evaluate: (context) => {
        // Always moderately good, adapts over time
        return 0.7;
      }
    });
  }

  /**
   * Create a new team
   */
  public async createTeam(
    name: string,
    leader: AgentId,
    goals: Goal[],
    formation: TeamFormation = TeamFormation.DYNAMIC
  ): Promise<Team> {
    try {
      this.logger.info('Creating new team', { name, leader: leader.id });
      
      const team: Team = {
        id: uuidv4(),
        name,
        leader,
        members: [leader],
        goals,
        formation,
        status: TeamStatus.FORMING,
        createdAt: new Date()
      };
      
      // Store team
      this.teams.set(team.id, team);
      this.agentTeams.set(this.getAgentKey(leader), team.id);
      
      // Notify leader
      await this.notifyTeamUpdate(team, 'team:created');
      
      this.emit('team:created', team);
      return team;
    } catch (error) {
      this.logger.error('Failed to create team', error);
      throw error;
    }
  }

  /**
   * Add member to team
   */
  public async addMember(teamId: string, agentId: AgentId): Promise<void> {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    
    const agentKey = this.getAgentKey(agentId);
    
    // Check if agent is already in a team
    if (this.agentTeams.has(agentKey)) {
      throw new Error(`Agent already in team: ${agentKey}`);
    }
    
    // Add to team
    team.members.push(agentId);
    this.agentTeams.set(agentKey, teamId);
    
    // Notify team members
    await this.notifyTeamUpdate(team, 'member:added', { newMember: agentId });
    
    this.logger.info('Added member to team', { teamId, agentId: agentKey });
    this.emit('team:memberAdded', { team, member: agentId });
  }

  /**
   * Remove member from team
   */
  public async removeMember(teamId: string, agentId: AgentId): Promise<void> {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    
    const agentKey = this.getAgentKey(agentId);
    
    // Remove from team
    team.members = team.members.filter(m => 
      this.getAgentKey(m) !== agentKey
    );
    this.agentTeams.delete(agentKey);
    
    // Check if team is empty
    if (team.members.length === 0) {
      await this.disbandTeam(teamId);
      return;
    }
    
    // Assign new leader if needed
    if (this.getAgentKey(team.leader) === agentKey) {
      team.leader = team.members[0];
      await this.notifyTeamUpdate(team, 'leader:changed', { newLeader: team.leader });
    }
    
    // Notify remaining members
    await this.notifyTeamUpdate(team, 'member:removed', { removedMember: agentId });
    
    this.logger.info('Removed member from team', { teamId, agentId: agentKey });
    this.emit('team:memberRemoved', { team, member: agentId });
  }

  /**
   * Assign goal to team
   */
  public async assignGoal(teamId: string, goal: Goal): Promise<void> {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    
    // Add goal
    team.goals.push(goal);
    
    // Update team status if needed
    if (team.status === TeamStatus.ACTIVE) {
      team.status = TeamStatus.EXECUTING;
    }
    
    // Notify team members
    await this.notifyTeamUpdate(team, 'goal:assigned', { goal });
    
    // Coordinate goal execution
    await this.coordinateGoalExecution(team, goal);
    
    this.logger.info('Assigned goal to team', { teamId, goalId: goal.id });
    this.emit('team:goalAssigned', { team, goal });
  }

  /**
   * Coordinate goal execution within team
   */
  private async coordinateGoalExecution(team: Team, goal: Goal): Promise<void> {
    try {
      // Select coordination strategy
      const strategy = this.selectStrategy(team, [goal]);
      
      // Create coordination context
      const context: CoordinationContext = {
        team,
        currentGoals: [goal],
        agentStates: new Map(), // Would be populated with actual states
        environment: {}
      };
      
      // Apply strategy
      this.logger.debug('Applying coordination strategy', { 
        teamId: team.id, 
        strategy: strategy.type 
      });
      
      // Decompose goal based on team formation
      const taskAssignments = await this.decomposeAndAssign(team, goal, strategy);
      
      // Send task assignments to team members
      for (const [agentId, tasks] of taskAssignments) {
        await this.messageBus.send({
          id: uuidv4(),
          from: team.leader,
          to: agentId,
          type: MessageType.COMMAND,
          content: {
            topic: 'task:assignment',
            body: { tasks, goal, strategy: strategy.type }
          },
          timestamp: new Date(),
          priority: MessagePriority.HIGH
        });
      }
      
      this.emit('coordination:executed', { team, goal, strategy });
    } catch (error) {
      this.logger.error('Failed to coordinate goal execution', error);
      throw error;
    }
  }

  /**
   * Decompose goal and assign tasks to team members
   */
  private async decomposeAndAssign(
    team: Team,
    goal: Goal,
    strategy: CoordinationStrategy
  ): Promise<Map<AgentId, any[]>> {
    const assignments = new Map<AgentId, any[]>();
    
    // Simple round-robin assignment for now
    // In real implementation, would use capability matching
    const subGoals = goal.subGoals || [goal];
    
    subGoals.forEach((subGoal, index) => {
      const assignedAgent = team.members[index % team.members.length];
      
      if (!assignments.has(assignedAgent)) {
        assignments.set(assignedAgent, []);
      }
      
      assignments.get(assignedAgent)!.push({
        goalId: subGoal.id,
        description: subGoal.description,
        type: subGoal.type,
        priority: subGoal.priority
      });
    });
    
    return assignments;
  }

  /**
   * Select best coordination strategy for current context
   */
  private selectStrategy(team: Team, goals: Goal[]): CoordinationStrategy {
    let bestStrategy: CoordinationStrategy | null = null;
    let bestScore = -1;
    
    const context: CoordinationContext = {
      team,
      currentGoals: goals,
      agentStates: new Map(),
      environment: {}
    };
    
    // Evaluate each strategy
    for (const strategy of this.strategies.values()) {
      const score = strategy.evaluate(context);
      if (score > bestScore) {
        bestScore = score;
        bestStrategy = strategy;
      }
    }
    
    // Default to team's formation strategy
    if (!bestStrategy) {
      bestStrategy = this.strategies.get(team.formation) || 
                   this.strategies.get('dynamic')!;
    }
    
    return bestStrategy;
  }

  /**
   * Update team status
   */
  public async updateTeamStatus(teamId: string, status: TeamStatus): Promise<void> {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    
    const previousStatus = team.status;
    team.status = status;
    
    await this.notifyTeamUpdate(team, 'status:changed', { previousStatus, newStatus: status });
    
    this.logger.info('Updated team status', { teamId, previousStatus, newStatus: status });
    this.emit('team:statusChanged', { team, previousStatus, newStatus: status });
  }

  /**
   * Disband a team
   */
  public async disbandTeam(teamId: string): Promise<void> {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    
    // Update status
    team.status = TeamStatus.DISBANDED;
    
    // Remove all members from team mapping
    team.members.forEach(member => {
      this.agentTeams.delete(this.getAgentKey(member));
    });
    
    // Notify members
    await this.notifyTeamUpdate(team, 'team:disbanded');
    
    // Remove team
    this.teams.delete(teamId);
    
    this.logger.info('Disbanded team', { teamId });
    this.emit('team:disbanded', team);
  }

  /**
   * Notify team members of updates
   */
  private async notifyTeamUpdate(
    team: Team,
    updateType: string,
    data?: any
  ): Promise<void> {
    const message: Message = {
      id: uuidv4(),
      from: team.leader,
      to: team.members,
      type: MessageType.INFORM,
      content: {
        topic: updateType,
        body: {
          teamId: team.id,
          teamName: team.name,
          ...data
        }
      },
      timestamp: new Date(),
      priority: MessagePriority.HIGH
    };
    
    await this.messageBus.send(message);
  }

  /**
   * Register a coordination strategy
   */
  public registerStrategy(strategy: CoordinationStrategy): void {
    this.strategies.set(strategy.type, strategy);
    this.logger.info('Registered coordination strategy', { type: strategy.type });
  }

  /**
   * Get team by ID
   */
  public getTeam(teamId: string): Team | undefined {
    return this.teams.get(teamId);
  }

  /**
   * Get team for agent
   */
  public getAgentTeam(agentId: AgentId): Team | undefined {
    const teamId = this.agentTeams.get(this.getAgentKey(agentId));
    return teamId ? this.teams.get(teamId) : undefined;
  }

  /**
   * Get all teams
   */
  public getAllTeams(): Team[] {
    return Array.from(this.teams.values());
  }

  /**
   * Get teams by status
   */
  public getTeamsByStatus(status: TeamStatus): Team[] {
    return Array.from(this.teams.values()).filter(team => team.status === status);
  }

  /**
   * Find teams capable of handling specific goal types
   */
  public findCapableTeams(requiredCapabilities: string[]): Team[] {
    // In real implementation, would check actual agent capabilities
    // For now, return all active teams
    return this.getTeamsByStatus(TeamStatus.ACTIVE);
  }

  /**
   * Get agent key for consistent identification
   */
  private getAgentKey(agentId: AgentId): string {
    return `${agentId.namespace || 'default'}:${agentId.id}`;
  }

  /**
   * Optimize team formation based on performance
   */
  public async optimizeTeamFormation(teamId: string): Promise<void> {
    const team = this.teams.get(teamId);
    if (!team) {
      throw new Error(`Team not found: ${teamId}`);
    }
    
    // Evaluate current performance
    const currentStrategy = this.strategies.get(team.formation);
    if (!currentStrategy) return;
    
    const context: CoordinationContext = {
      team,
      currentGoals: team.goals,
      agentStates: new Map(),
      environment: {}
    };
    
    const currentScore = currentStrategy.evaluate(context);
    
    // Find better formation
    let bestFormation = team.formation;
    let bestScore = currentScore;
    
    for (const [formation, strategy] of this.strategies) {
      const score = strategy.evaluate(context);
      if (score > bestScore) {
        bestScore = score;
        bestFormation = formation as TeamFormation;
      }
    }
    
    // Update if better formation found
    if (bestFormation !== team.formation) {
      team.formation = bestFormation;
      await this.notifyTeamUpdate(team, 'formation:optimized', { 
        previousFormation: team.formation,
        newFormation: bestFormation,
        improvement: bestScore - currentScore
      });
      
      this.logger.info('Optimized team formation', { 
        teamId, 
        newFormation: bestFormation 
      });
    }
  }
}