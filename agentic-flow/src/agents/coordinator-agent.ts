import { BaseAgent } from '../core/agent.base';
import {
  AgentType,
  AgentCapability,
  Goal,
  Task,
  TaskStatus,
  Message,
  MessageType,
  MessagePriority,
  Team,
  TeamFormation
} from '../types';
import { TeamCoordinator } from '../coordination/team-coordinator';

/**
 * Coordinator agent responsible for team management and high-level coordination
 */
export class CoordinatorAgent extends BaseAgent {
  private teamCoordinator: TeamCoordinator;
  private managedTeams: Set<string>;

  constructor(name: string = 'Coordinator') {
    super(name, AgentType.COORDINATOR, {
      maxConcurrentTasks: 10,
      communicationTimeout: 60000
    });
    
    this.teamCoordinator = new TeamCoordinator();
    this.managedTeams = new Set();
    
    this.setupCoordinatorHandlers();
  }

  /**
   * Define coordinator capabilities
   */
  protected defineCapabilities(): AgentCapability[] {
    return [
      {
        name: 'team-formation',
        description: 'Form teams of agents for complex goals'
      },
      {
        name: 'goal-decomposition',
        description: 'Break down complex goals into manageable sub-goals'
      },
      {
        name: 'task-delegation',
        description: 'Delegate tasks to appropriate agents or teams'
      },
      {
        name: 'progress-monitoring',
        description: 'Monitor and track progress of delegated tasks'
      },
      {
        name: 'conflict-resolution',
        description: 'Resolve conflicts between agents or teams'
      },
      {
        name: 'resource-allocation',
        description: 'Allocate resources optimally across teams'
      }
    ];
  }

  /**
   * Process incoming goals
   */
  protected async processGoal(goal: Goal): Promise<void> {
    try {
      this.logger.info('Processing coordinator goal', { goalId: goal.id });
      
      // Decompose complex goal
      const subGoals = await this.goalEngine.decomposeGoal(goal);
      
      if (subGoals.length > 1) {
        // Complex goal requiring team coordination
        await this.handleComplexGoal(goal, subGoals);
      } else {
        // Simple goal - delegate directly
        await this.delegateSimpleGoal(goal);
      }
      
      // Update goal status
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.ACTIVE);
    } catch (error) {
      this.logger.error('Failed to process goal', error);
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.FAILED);
      throw error;
    }
  }

  /**
   * Handle complex goals requiring team formation
   */
  private async handleComplexGoal(goal: Goal, subGoals: Goal[]): Promise<void> {
    // Determine required capabilities
    const requiredCapabilities = this.analyzeRequiredCapabilities(subGoals);
    
    // Check if existing team can handle it
    let team = this.findSuitableTeam(requiredCapabilities);
    
    if (!team) {
      // Form new team
      team = await this.formTeam(goal, requiredCapabilities);
    }
    
    // Assign goal to team
    await this.teamCoordinator.assignGoal(team.id, goal);
    
    // Track team
    this.managedTeams.add(team.id);
  }

  /**
   * Form a new team for a goal
   */
  private async formTeam(goal: Goal, requiredCapabilities: string[]): Promise<Team> {
    // Request agents with required capabilities
    const availableAgents = await this.requestAvailableAgents(requiredCapabilities);
    
    // Select best formation strategy
    const formation = this.selectFormationStrategy(goal, availableAgents.length);
    
    // Create team with self as leader
    const team = await this.teamCoordinator.createTeam(
      `Team-${goal.id}`,
      this.id,
      [goal],
      formation
    );
    
    // Add selected agents to team
    for (const agentId of availableAgents) {
      await this.teamCoordinator.addMember(team.id, agentId);
    }
    
    // Update team status
    await this.teamCoordinator.updateTeamStatus(team.id, TeamStatus.ACTIVE);
    
    return team;
  }

  /**
   * Execute coordinator-specific tasks
   */
  protected async executeTask(task: Task): Promise<any> {
    try {
      this.logger.debug('Executing coordinator task', { taskId: task.id });
      
      switch (task.description) {
        case 'monitor-progress':
          return await this.monitorProgress(task);
        case 'resolve-conflict':
          return await this.resolveConflict(task);
        case 'optimize-teams':
          return await this.optimizeTeams(task);
        default:
          // Delegate to specialized handler
          return await this.handleSpecializedTask(task);
      }
    } catch (error) {
      this.logger.error('Task execution failed', error);
      task.status = TaskStatus.FAILED;
      task.error = error as Error;
      throw error;
    }
  }

  /**
   * Monitor progress of teams and agents
   */
  private async monitorProgress(_task: Task): Promise<any> {
    const progress = {
      teams: [] as any[],
      overallCompletion: 0
    };
    
    for (const teamId of this.managedTeams) {
      const team = this.teamCoordinator.getTeam(teamId);
      if (team) {
        const teamProgress = await this.getTeamProgress(team);
        progress.teams.push({
          teamId: team.id,
          status: team.status,
          progress: teamProgress
        });
      }
    }
    
    progress.overallCompletion = progress.teams.reduce((sum, t) => 
      sum + t.progress, 0
    ) / progress.teams.length;
    
    return progress;
  }

  /**
   * Get progress for a specific team
   */
  private async getTeamProgress(team: Team): Promise<number> {
    // Query team members for progress
    const progressReports = await Promise.all(
      team.members.map(member => this.queryAgentProgress(member))
    );
    
    return progressReports.reduce((sum, p) => sum + p, 0) / progressReports.length;
  }

  /**
   * Query an agent for progress
   */
  private async queryAgentProgress(agentId: AgentId): Promise<number> {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(0), 5000);
      
      this.once(`progress:${agentId.id}`, (progress: number) => {
        clearTimeout(timeout);
        resolve(progress);
      });
      
      this.sendMessage(
        agentId,
        MessageType.QUERY,
        { topic: 'progress', body: {} },
        MessagePriority.HIGH
      );
    });
  }

  /**
   * Setup coordinator-specific message handlers
   */
  private setupCoordinatorHandlers(): void {
    // Handle team requests
    this.registerMessageHandler(MessageType.REQUEST, async (message) => {
      if (message.content.topic === 'team:join') {
        await this.handleTeamJoinRequest(message);
      }
    });
    
    // Handle progress reports
    this.registerMessageHandler(MessageType.INFORM, async (message) => {
      if (message.content.topic === 'progress:report') {
        this.emit(`progress:${message.from.id}`, message.content.body.progress);
      }
    });
  }

  /**
   * Handle team join requests
   */
  private async handleTeamJoinRequest(message: Message): Promise<void> {
    const { capabilities } = message.content.body;
    
    // Find suitable team
    const teams = this.teamCoordinator.findCapableTeams(capabilities);
    
    if (teams.length > 0) {
      // Add to first suitable team
      await this.teamCoordinator.addMember(teams[0].id, message.from);
      
      // Send confirmation
      await this.sendMessage(
        message.from,
        MessageType.RESPONSE,
        {
          topic: 'team:joined',
          body: { teamId: teams[0].id, role: 'member' }
        }
      );
    } else {
      // No suitable team
      await this.sendMessage(
        message.from,
        MessageType.RESPONSE,
        {
          topic: 'team:unavailable',
          body: { reason: 'No suitable team found' }
        }
      );
    }
  }

  /**
   * Delegate simple goals to individual agents
   */
  private async delegateSimpleGoal(goal: Goal): Promise<void> {
    // Find capable agent
    const agents = await this.requestAvailableAgents([goal.type]);
    
    if (agents.length > 0) {
      // Send goal to first available agent
      await this.sendMessage(
        agents[0],
        MessageType.COMMAND,
        {
          topic: 'goal:execute',
          body: { goal }
        },
        MessagePriority.HIGH
      );
    } else {
      // No capable agent - mark as failed
      await this.goalEngine.updateGoalStatus(goal.id, GoalStatus.FAILED);
    }
  }

  /**
   * Request available agents with specific capabilities
   */
  private async requestAvailableAgents(capabilities: string[]): Promise<AgentId[]> {
    return new Promise((resolve) => {
      const agents: AgentId[] = [];
      const timeout = setTimeout(() => resolve(agents), 10000);
      
      this.once('agents:available', (availableAgents: AgentId[]) => {
        clearTimeout(timeout);
        resolve(availableAgents);
      });
      
      // Broadcast request
      this.messageBus.broadcast(
        this.id,
        MessageType.REQUEST,
        {
          topic: 'agents:needed',
          body: { capabilities, coordinator: this.id }
        },
        MessagePriority.HIGH
      );
    });
  }

  /**
   * Analyze required capabilities from sub-goals
   */
  private analyzeRequiredCapabilities(subGoals: Goal[]): string[] {
    const capabilities = new Set<string>();
    
    subGoals.forEach(goal => {
      // Map goal types to capabilities
      switch (goal.type) {
        case GoalType.ACHIEVE:
          capabilities.add('execution');
          break;
        case GoalType.QUERY:
          capabilities.add('analysis');
          break;
        case GoalType.MAINTAIN:
          capabilities.add('monitoring');
          break;
        default:
          capabilities.add('general');
      }
    });
    
    return Array.from(capabilities);
  }

  /**
   * Select best team formation strategy
   */
  private selectFormationStrategy(_goal: Goal, teamSize: number): TeamFormation {
    if (teamSize <= 3) {
      return TeamFormation.FLAT;
    } else if (teamSize <= 7) {
      return TeamFormation.HIERARCHICAL;
    } else {
      return TeamFormation.MATRIX;
    }
  }

  /**
   * Find suitable existing team
   */
  private findSuitableTeam(requiredCapabilities: string[]): Team | undefined {
    const teams = this.teamCoordinator.findCapableTeams(requiredCapabilities);
    
    // Return first team that's not at capacity
    return teams.find(team => 
      team.status === TeamStatus.ACTIVE && 
      team.members.length < 10
    );
  }

  /**
   * Resolve conflicts between agents or teams
   */
  private async resolveConflict(task: Task): Promise<any> {
    // Placeholder for conflict resolution logic
    this.logger.info('Resolving conflict', { taskId: task.id });
    return { resolved: true };
  }

  /**
   * Optimize team formations
   */
  private async optimizeTeams(_task: Task): Promise<any> {
    const optimizations = [];
    
    for (const teamId of this.managedTeams) {
      await this.teamCoordinator.optimizeTeamFormation(teamId);
      optimizations.push({ teamId, optimized: true });
    }
    
    return { optimizations };
  }

  /**
   * Handle specialized coordinator tasks
   */
  private async handleSpecializedTask(task: Task): Promise<any> {
    this.logger.warn('Unhandled task type', { taskId: task.id, description: task.description });
    return { handled: false };
  }
}

// Re-export necessary types
import { GoalStatus, GoalType, TeamStatus, AgentId } from '../types';