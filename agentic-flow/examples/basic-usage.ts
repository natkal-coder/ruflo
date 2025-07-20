/**
 * Basic usage example of the Agentic Flow framework
 */

import {
  CoordinatorAgent,
  ExecutorAgent,
  GoalEngine,
  MessageBus,
  AgentState,
  GoalPriority
} from '../src';

async function main() {
  console.log('🚀 Agentic Flow - Basic Usage Example\n');

  // Create message bus instance
  const messageBus = MessageBus.getInstance();

  // Create agents
  console.log('Creating agents...');
  const coordinator = new CoordinatorAgent('MainCoordinator');
  const executor1 = new ExecutorAgent('DataProcessor');
  const executor2 = new ExecutorAgent('ReportGenerator');

  // Initialize agents
  console.log('Initializing agents...');
  await coordinator.initialize();
  await executor1.initialize();
  await executor2.initialize();

  // Start agents
  console.log('Starting agents...');
  await coordinator.start();
  await executor1.start();
  await executor2.start();

  // Set up event listeners
  coordinator.on('team:created', (team) => {
    console.log(`\n✅ Team created: ${team.name}`);
  });

  coordinator.on('goal:added', (goal) => {
    console.log(`\n📋 Goal added: ${goal.description}`);
  });

  executor1.on('task:completed', (task) => {
    console.log(`\n✅ Task completed by ${executor1.getProfile().name}: ${task.id}`);
  });

  executor2.on('task:completed', (task) => {
    console.log(`\n✅ Task completed by ${executor2.getProfile().name}: ${task.id}`);
  });

  // Example 1: Simple goal processing
  console.log('\n--- Example 1: Simple Goal Processing ---');
  const goalEngine = new GoalEngine(coordinator.getId());
  const simpleGoal = await goalEngine.parseGoal(
    'Calculate the average of these numbers: 10, 20, 30, 40, 50'
  );
  await coordinator.addGoal(simpleGoal);

  // Wait for processing
  await new Promise(resolve => setTimeout(resolve, 3000));

  // Example 2: Complex goal with team formation
  console.log('\n--- Example 2: Complex Goal with Team Formation ---');
  const complexGoal = await goalEngine.parseGoal(
    'Analyze customer data from last quarter and generate a comprehensive report with recommendations'
  );
  complexGoal.priority = GoalPriority.HIGH;
  await coordinator.addGoal(complexGoal);

  // Wait for processing
  await new Promise(resolve => setTimeout(resolve, 5000));

  // Example 3: Natural language goal with deadline
  console.log('\n--- Example 3: Natural Language Goal with Deadline ---');
  const urgentGoal = await goalEngine.parseGoal(
    'Urgent: Process pending invoices and send payment reminders by end of day'
  );
  await coordinator.addGoal(urgentGoal);

  // Wait for processing
  await new Promise(resolve => setTimeout(resolve, 4000));

  // Check agent states
  console.log('\n--- Agent Status Report ---');
  console.log(`Coordinator state: ${coordinator.getState()}`);
  console.log(`Executor 1 state: ${executor1.getState()}`);
  console.log(`Executor 2 state: ${executor2.getState()}`);

  // Get execution statistics
  const exec1Stats = executor1.getQueueStatus();
  const exec2Stats = executor2.getQueueStatus();
  
  console.log(`\nExecutor 1 stats:`, exec1Stats);
  console.log(`Executor 2 stats:`, exec2Stats);

  // Check message history
  const messageHistory = messageBus.getHistory({
    since: new Date(Date.now() - 60000) // Last minute
  });
  console.log(`\nTotal messages exchanged: ${messageHistory.length}`);

  // Cleanup
  console.log('\n--- Shutting down ---');
  await coordinator.stop();
  await executor1.stop();
  await executor2.stop();

  console.log('\n✅ Example completed successfully!');
}

// Run the example
main().catch(console.error);