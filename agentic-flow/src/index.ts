/**
 * Agentic Flow - Autonomous Agent Framework
 * 
 * A comprehensive framework for building autonomous AI agents with
 * natural language goal processing and inter-agent communication.
 */

// Core exports
export { BaseAgent } from './core/agent.base';

// Agent implementations
export { CoordinatorAgent } from './agents/coordinator-agent';
export { ExecutorAgent } from './agents/executor-agent';

// Goal engine
export { GoalEngine } from './goal-engine/goal-engine';

// Communication system
export { MessageBus } from './communication/message-bus';
export { MessageRouter } from './communication/message-router';
export { MessageQueue } from './communication/message-queue';

// Coordination system
export { TeamCoordinator } from './coordination/team-coordinator';

// Utilities
export { Logger } from './utils/logger';

// Type exports
export * from './types';

// Version
export const VERSION = '1.0.0';

/**
 * Quick start example:
 * 
 * ```typescript
 * import { CoordinatorAgent, ExecutorAgent, GoalEngine } from '@agentic-flow/core';
 * 
 * // Create agents
 * const coordinator = new CoordinatorAgent('MainCoordinator');
 * const executor1 = new ExecutorAgent('Executor1');
 * const executor2 = new ExecutorAgent('Executor2');
 * 
 * // Initialize agents
 * await coordinator.initialize();
 * await executor1.initialize();
 * await executor2.initialize();
 * 
 * // Start agents
 * await coordinator.start();
 * await executor1.start();
 * await executor2.start();
 * 
 * // Parse and assign goal
 * const goalEngine = new GoalEngine(coordinator.getId());
 * const goal = await goalEngine.parseGoal('Analyze sales data and generate monthly report');
 * await coordinator.addGoal(goal);
 * ```
 */

// Import all for default export
import { BaseAgent } from './core/agent.base';
import { CoordinatorAgent } from './agents/coordinator-agent';
import { ExecutorAgent } from './agents/executor-agent';
import { GoalEngine } from './goal-engine/goal-engine';
import { MessageBus } from './communication/message-bus';
import { TeamCoordinator } from './coordination/team-coordinator';

// Default export for convenience
const AgenticFlow = {
  BaseAgent,
  CoordinatorAgent,
  ExecutorAgent,
  GoalEngine,
  MessageBus,
  TeamCoordinator,
  VERSION
};

export default AgenticFlow;