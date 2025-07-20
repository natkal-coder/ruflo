import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { AutonomousAgent, Goal, Experience, Capability, DecisionOption } from '../../src/autonomous/autonomous-agent';

describe('AutonomousAgent', () => {
  let agent: AutonomousAgent;

  beforeEach(() => {
    const capabilities: Capability[] = [
      {
        name: 'research',
        description: 'Research and analysis capability',
        proficiency: 0.8,
        requirements: ['data_access'],
        examples: ['research', 'analyze', 'investigate']
      },
      {
        name: 'programming',
        description: 'Code development capability',
        proficiency: 0.9,
        requirements: ['coding_capability'],
        examples: ['code', 'implement', 'develop']
      }
    ];

    agent = new AutonomousAgent('test-agent', 'Test Agent', 'researcher', capabilities);
  });

  afterEach(() => {
    // Clean up any intervals
    agent.pause();
  });

  describe('Goal Management', () => {
    it('should set and manage goals', async () => {
      const goalId = await agent.setGoal('Research quantum computing applications', 5);
      
      expect(goalId).toBeDefined();
      expect(typeof goalId).toBe('string');
      
      const goals = agent.getGoals();
      expect(goals).toHaveLength(1);
      expect(goals[0].description).toBe('Research quantum computing applications');
      expect(goals[0].priority).toBe(5);
      expect(goals[0].status).toBe('pending');
    });

    it('should decompose complex goals into sub-goals', async () => {
      const goalId = await agent.setGoal('Design and implement a comprehensive microservices architecture', 8);
      
      const goals = agent.getGoals();
      const mainGoal = goals.find(g => g.id === goalId);
      
      expect(mainGoal).toBeDefined();
      expect(mainGoal!.subGoals.length).toBeGreaterThan(0);
    });

    it('should handle goal complexity analysis', async () => {
      // Test simple goal
      const simpleGoalId = await agent.setGoal('Write a hello world program', 1);
      const simpleGoal = agent.getGoals().find(g => g.id === simpleGoalId);
      expect(simpleGoal!.subGoals.length).toBe(0);

      // Test complex goal
      const complexGoalId = await agent.setGoal('Research, analyze, and implement multiple comprehensive solutions', 5);
      const complexGoal = agent.getGoals().find(g => g.id === complexGoalId);
      expect(complexGoal!.subGoals.length).toBeGreaterThan(0);
    });
  });

  describe('Decision Making', () => {
    it('should make decisions based on multiple strategies', async () => {
      const options: DecisionOption[] = [
        {
          id: 'option1',
          action: 'research_approach',
          expectedOutcome: 'Comprehensive understanding',
          risk: 0.1,
          cost: 5,
          probability: 0.9
        },
        {
          id: 'option2',
          action: 'quick_implementation',
          expectedOutcome: 'Fast results',
          risk: 0.6,
          cost: 2,
          probability: 0.7
        }
      ];

      const selectedOption = await agent.makeDecision('Choose research strategy', options);
      
      expect(selectedOption).toBeDefined();
      expect(['option1', 'option2']).toContain(selectedOption);
    });

    it('should emit decision events', async () => {
      const decisionSpy = jest.fn();
      agent.on('decision:made', decisionSpy);

      const options: DecisionOption[] = [
        {
          id: 'test-option',
          action: 'test_action',
          expectedOutcome: 'Test outcome',
          risk: 0.2,
          cost: 1,
          probability: 0.8
        }
      ];

      await agent.makeDecision('Test decision', options);
      
      expect(decisionSpy).toHaveBeenCalled();
      expect(decisionSpy.mock.calls[0][0]).toHaveProperty('agentId', 'test-agent');
      expect(decisionSpy.mock.calls[0][0]).toHaveProperty('decision');
    });
  });

  describe('Learning and Adaptation', () => {
    it('should learn from experiences', async () => {
      const initialExperiences = agent.getExperiences().length;
      
      await agent.learnFromExperience(
        'research_task',
        { topic: 'quantum computing' },
        'success',
        0.9
      );

      const experiences = agent.getExperiences();
      expect(experiences.length).toBe(initialExperiences + 1);
      
      const latestExperience = experiences[experiences.length - 1];
      expect(latestExperience.action).toBe('research_task');
      expect(latestExperience.outcome).toBe('success');
      expect(latestExperience.reward).toBe(0.9);
      expect(latestExperience.lessons.length).toBeGreaterThan(0);
    });

    it('should update capabilities based on experiences', async () => {
      const initialProficiency = agent.getCapabilities().find(c => c.name === 'research')!.proficiency;
      
      // Learn from multiple successful research experiences
      for (let i = 0; i < 5; i++) {
        await agent.learnFromExperience(
          'research_analysis',
          { iteration: i },
          'success',
          0.8
        );
      }

      const updatedProficiency = agent.getCapabilities().find(c => c.name === 'research')!.proficiency;
      expect(updatedProficiency).toBeGreaterThanOrEqual(initialProficiency);
    });

    it('should emit learning events', async () => {
      const learningSpy = jest.fn();
      agent.on('learning:experience', learningSpy);

      await agent.learnFromExperience(
        'test_action',
        { test: true },
        'success',
        0.7
      );

      expect(learningSpy).toHaveBeenCalled();
      expect(learningSpy.mock.calls[0][0]).toHaveProperty('agentId', 'test-agent');
      expect(learningSpy.mock.calls[0][0]).toHaveProperty('experience');
    });
  });

  describe('Team Formation', () => {
    it('should propose team composition for goals', async () => {
      const goal: Goal = {
        id: 'test-goal',
        description: 'Build a web application with research and programming',
        priority: 5,
        status: 'pending',
        subGoals: [],
        requirements: [],
        context: {}
      };

      const teamMembers = await agent.proposeTeam(goal);
      
      expect(Array.isArray(teamMembers)).toBe(true);
      expect(teamMembers).toContain('test-agent'); // Should include itself
    });

    it('should assess capability fit correctly', async () => {
      const researchGoal: Goal = {
        id: 'research-goal',
        description: 'Research advanced AI techniques',
        priority: 3,
        status: 'pending',
        subGoals: [],
        requirements: [],
        context: {}
      };

      const team = await agent.proposeTeam(researchGoal);
      expect(team).toContain('test-agent'); // Should include itself for research tasks
    });
  });

  describe('State Management', () => {
    it('should track and update agent state', () => {
      const initialState = agent.getState();
      
      expect(initialState).toHaveProperty('energy');
      expect(initialState).toHaveProperty('focus');
      expect(initialState).toHaveProperty('mood');
      expect(initialState).toHaveProperty('workload');
      expect(initialState).toHaveProperty('stress');
      
      expect(initialState.energy).toBe(100);
      expect(initialState.mood).toBe('confident');
    });

    it('should update state based on workload', async () => {
      // Add multiple goals to increase workload
      for (let i = 0; i < 5; i++) {
        await agent.setGoal(`Task ${i}`, 1);
      }

      // Wait for state update in autonomous thinking
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const state = agent.getState();
      expect(state.workload).toBeGreaterThan(0);
    });
  });

  describe('Public API', () => {
    it('should provide access to goals', () => {
      const goals = agent.getGoals();
      expect(Array.isArray(goals)).toBe(true);
    });

    it('should provide access to capabilities', () => {
      const capabilities = agent.getCapabilities();
      expect(Array.isArray(capabilities)).toBe(true);
      expect(capabilities.length).toBe(2); // research and programming
      expect(capabilities[0]).toHaveProperty('name');
      expect(capabilities[0]).toHaveProperty('proficiency');
    });

    it('should provide access to experiences', () => {
      const experiences = agent.getExperiences();
      expect(Array.isArray(experiences)).toBe(true);
    });

    it('should support pause and resume', async () => {
      const pauseSpy = jest.fn();
      const resumeSpy = jest.fn();
      
      agent.on('agent:paused', pauseSpy);
      agent.on('agent:resumed', resumeSpy);

      await agent.pause();
      expect(pauseSpy).toHaveBeenCalled();

      await agent.resume();
      expect(resumeSpy).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid goal data gracefully', async () => {
      // This should not throw an error
      const goalId = await agent.setGoal('', 0);
      expect(goalId).toBeDefined();
    });

    it('should handle empty decision options', async () => {
      const selectedOption = await agent.makeDecision('Empty decision', []);
      expect(selectedOption).toBeUndefined();
    });
  });
});