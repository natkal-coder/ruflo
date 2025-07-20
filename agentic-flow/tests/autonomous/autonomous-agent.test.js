"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const globals_1 = require("@jest/globals");
const autonomous_agent_1 = require("../../src/autonomous/autonomous-agent");
(0, globals_1.describe)('AutonomousAgent', () => {
    let agent;
    (0, globals_1.beforeEach)(() => {
        const capabilities = [
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
        agent = new autonomous_agent_1.AutonomousAgent('test-agent', 'Test Agent', 'researcher', capabilities);
    });
    afterEach(() => {
        // Clean up any intervals
        agent.pause();
    });
    (0, globals_1.describe)('Goal Management', () => {
        (0, globals_1.it)('should set and manage goals', async () => {
            const goalId = await agent.setGoal('Research quantum computing applications', 5);
            (0, globals_1.expect)(goalId).toBeDefined();
            (0, globals_1.expect)(typeof goalId).toBe('string');
            const goals = agent.getGoals();
            (0, globals_1.expect)(goals).toHaveLength(1);
            (0, globals_1.expect)(goals[0].description).toBe('Research quantum computing applications');
            (0, globals_1.expect)(goals[0].priority).toBe(5);
            (0, globals_1.expect)(goals[0].status).toBe('pending');
        });
        (0, globals_1.it)('should decompose complex goals into sub-goals', async () => {
            const goalId = await agent.setGoal('Design and implement a comprehensive microservices architecture', 8);
            const goals = agent.getGoals();
            const mainGoal = goals.find(g => g.id === goalId);
            (0, globals_1.expect)(mainGoal).toBeDefined();
            (0, globals_1.expect)(mainGoal.subGoals.length).toBeGreaterThan(0);
        });
        (0, globals_1.it)('should handle goal complexity analysis', async () => {
            // Test simple goal
            const simpleGoalId = await agent.setGoal('Write a hello world program', 1);
            const simpleGoal = agent.getGoals().find(g => g.id === simpleGoalId);
            (0, globals_1.expect)(simpleGoal.subGoals.length).toBe(0);
            // Test complex goal
            const complexGoalId = await agent.setGoal('Research, analyze, and implement multiple comprehensive solutions', 5);
            const complexGoal = agent.getGoals().find(g => g.id === complexGoalId);
            (0, globals_1.expect)(complexGoal.subGoals.length).toBeGreaterThan(0);
        });
    });
    (0, globals_1.describe)('Decision Making', () => {
        (0, globals_1.it)('should make decisions based on multiple strategies', async () => {
            const options = [
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
            (0, globals_1.expect)(selectedOption).toBeDefined();
            (0, globals_1.expect)(['option1', 'option2']).toContain(selectedOption);
        });
        (0, globals_1.it)('should emit decision events', async () => {
            const decisionSpy = globals_1.jest.fn();
            agent.on('decision:made', decisionSpy);
            const options = [
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
            (0, globals_1.expect)(decisionSpy).toHaveBeenCalled();
            (0, globals_1.expect)(decisionSpy.mock.calls[0][0]).toHaveProperty('agentId', 'test-agent');
            (0, globals_1.expect)(decisionSpy.mock.calls[0][0]).toHaveProperty('decision');
        });
    });
    (0, globals_1.describe)('Learning and Adaptation', () => {
        (0, globals_1.it)('should learn from experiences', async () => {
            const initialExperiences = agent.getExperiences().length;
            await agent.learnFromExperience('research_task', { topic: 'quantum computing' }, 'success', 0.9);
            const experiences = agent.getExperiences();
            (0, globals_1.expect)(experiences.length).toBe(initialExperiences + 1);
            const latestExperience = experiences[experiences.length - 1];
            (0, globals_1.expect)(latestExperience.action).toBe('research_task');
            (0, globals_1.expect)(latestExperience.outcome).toBe('success');
            (0, globals_1.expect)(latestExperience.reward).toBe(0.9);
            (0, globals_1.expect)(latestExperience.lessons.length).toBeGreaterThan(0);
        });
        (0, globals_1.it)('should update capabilities based on experiences', async () => {
            const initialProficiency = agent.getCapabilities().find(c => c.name === 'research').proficiency;
            // Learn from multiple successful research experiences
            for (let i = 0; i < 5; i++) {
                await agent.learnFromExperience('research_analysis', { iteration: i }, 'success', 0.8);
            }
            const updatedProficiency = agent.getCapabilities().find(c => c.name === 'research').proficiency;
            (0, globals_1.expect)(updatedProficiency).toBeGreaterThanOrEqual(initialProficiency);
        });
        (0, globals_1.it)('should emit learning events', async () => {
            const learningSpy = globals_1.jest.fn();
            agent.on('learning:experience', learningSpy);
            await agent.learnFromExperience('test_action', { test: true }, 'success', 0.7);
            (0, globals_1.expect)(learningSpy).toHaveBeenCalled();
            (0, globals_1.expect)(learningSpy.mock.calls[0][0]).toHaveProperty('agentId', 'test-agent');
            (0, globals_1.expect)(learningSpy.mock.calls[0][0]).toHaveProperty('experience');
        });
    });
    (0, globals_1.describe)('Team Formation', () => {
        (0, globals_1.it)('should propose team composition for goals', async () => {
            const goal = {
                id: 'test-goal',
                description: 'Build a web application with research and programming',
                priority: 5,
                status: 'pending',
                subGoals: [],
                requirements: [],
                context: {}
            };
            const teamMembers = await agent.proposeTeam(goal);
            (0, globals_1.expect)(Array.isArray(teamMembers)).toBe(true);
            (0, globals_1.expect)(teamMembers).toContain('test-agent'); // Should include itself
        });
        (0, globals_1.it)('should assess capability fit correctly', async () => {
            const researchGoal = {
                id: 'research-goal',
                description: 'Research advanced AI techniques',
                priority: 3,
                status: 'pending',
                subGoals: [],
                requirements: [],
                context: {}
            };
            const team = await agent.proposeTeam(researchGoal);
            (0, globals_1.expect)(team).toContain('test-agent'); // Should include itself for research tasks
        });
    });
    (0, globals_1.describe)('State Management', () => {
        (0, globals_1.it)('should track and update agent state', () => {
            const initialState = agent.getState();
            (0, globals_1.expect)(initialState).toHaveProperty('energy');
            (0, globals_1.expect)(initialState).toHaveProperty('focus');
            (0, globals_1.expect)(initialState).toHaveProperty('mood');
            (0, globals_1.expect)(initialState).toHaveProperty('workload');
            (0, globals_1.expect)(initialState).toHaveProperty('stress');
            (0, globals_1.expect)(initialState.energy).toBe(100);
            (0, globals_1.expect)(initialState.mood).toBe('confident');
        });
        (0, globals_1.it)('should update state based on workload', async () => {
            // Add multiple goals to increase workload
            for (let i = 0; i < 5; i++) {
                await agent.setGoal(`Task ${i}`, 1);
            }
            // Wait for state update in autonomous thinking
            await new Promise(resolve => setTimeout(resolve, 100));
            const state = agent.getState();
            (0, globals_1.expect)(state.workload).toBeGreaterThan(0);
        });
    });
    (0, globals_1.describe)('Public API', () => {
        (0, globals_1.it)('should provide access to goals', () => {
            const goals = agent.getGoals();
            (0, globals_1.expect)(Array.isArray(goals)).toBe(true);
        });
        (0, globals_1.it)('should provide access to capabilities', () => {
            const capabilities = agent.getCapabilities();
            (0, globals_1.expect)(Array.isArray(capabilities)).toBe(true);
            (0, globals_1.expect)(capabilities.length).toBe(2); // research and programming
            (0, globals_1.expect)(capabilities[0]).toHaveProperty('name');
            (0, globals_1.expect)(capabilities[0]).toHaveProperty('proficiency');
        });
        (0, globals_1.it)('should provide access to experiences', () => {
            const experiences = agent.getExperiences();
            (0, globals_1.expect)(Array.isArray(experiences)).toBe(true);
        });
        (0, globals_1.it)('should support pause and resume', async () => {
            const pauseSpy = globals_1.jest.fn();
            const resumeSpy = globals_1.jest.fn();
            agent.on('agent:paused', pauseSpy);
            agent.on('agent:resumed', resumeSpy);
            await agent.pause();
            (0, globals_1.expect)(pauseSpy).toHaveBeenCalled();
            await agent.resume();
            (0, globals_1.expect)(resumeSpy).toHaveBeenCalled();
        });
    });
    (0, globals_1.describe)('Error Handling', () => {
        (0, globals_1.it)('should handle invalid goal data gracefully', async () => {
            // This should not throw an error
            const goalId = await agent.setGoal('', 0);
            (0, globals_1.expect)(goalId).toBeDefined();
        });
        (0, globals_1.it)('should handle empty decision options', async () => {
            const selectedOption = await agent.makeDecision('Empty decision', []);
            (0, globals_1.expect)(selectedOption).toBeUndefined();
        });
    });
});
//# sourceMappingURL=autonomous-agent.test.js.map