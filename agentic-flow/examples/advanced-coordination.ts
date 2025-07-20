/**
 * Advanced coordination example demonstrating team formation and complex workflows
 */

import {
  CoordinatorAgent,
  ExecutorAgent,
  BaseAgent,
  AgentType,
  AgentCapability,
  Goal,
  Task,
  GoalType,
  GoalPriority,
  TeamFormation,
  MessageType,
  MessagePriority
} from '../src';

// Custom analyzer agent
class AnalyzerAgent extends BaseAgent {
  constructor(name: string) {
    super(name, AgentType.ANALYZER, {
      maxConcurrentTasks: 5
    });
  }

  protected defineCapabilities(): AgentCapability[] {
    return [
      {
        name: 'data-analysis',
        description: 'Analyze complex datasets'
      },
      {
        name: 'pattern-recognition',
        description: 'Identify patterns and anomalies'
      },
      {
        name: 'statistical-modeling',
        description: 'Build statistical models'
      }
    ];
  }

  protected async processGoal(goal: Goal): Promise<void> {
    console.log(`🔍 Analyzer processing goal: ${goal.description}`);
    
    // Simulate analysis
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Send analysis results
    await this.sendMessage(
      goal.metadata?.requestor || this.id,
      MessageType.INFORM,
      {
        topic: 'analysis:complete',
        body: {
          goalId: goal.id,
          findings: {
            patterns: ['trend_1', 'anomaly_2'],
            confidence: 0.87,
            recommendations: ['optimize_process_A', 'investigate_anomaly_2']
          }
        }
      }
    );
  }

  protected async executeTask(task: Task): Promise<any> {
    console.log(`🔬 Executing analysis task: ${task.description}`);
    
    // Simulate complex analysis
    await new Promise(resolve => setTimeout(resolve, Math.random() * 3000 + 1000));
    
    return {
      analyzed: true,
      dataPoints: Math.floor(Math.random() * 1000),
      insights: Math.floor(Math.random() * 10)
    };
  }
}

// Custom monitor agent
class MonitorAgent extends BaseAgent {
  private metrics: Map<string, number> = new Map();

  constructor(name: string) {
    super(name, AgentType.MONITOR, {
      maxConcurrentTasks: 10
    });
  }

  protected defineCapabilities(): AgentCapability[] {
    return [
      {
        name: 'real-time-monitoring',
        description: 'Monitor system metrics in real-time'
      },
      {
        name: 'alert-generation',
        description: 'Generate alerts based on thresholds'
      },
      {
        name: 'performance-tracking',
        description: 'Track performance over time'
      }
    ];
  }

  protected async processGoal(goal: Goal): Promise<void> {
    console.log(`📊 Monitor processing goal: ${goal.description}`);
    
    if (goal.type === GoalType.MAINTAIN) {
      // Set up continuous monitoring
      this.startMonitoring(goal);
    }
  }

  protected async executeTask(task: Task): Promise<any> {
    console.log(`📈 Executing monitoring task: ${task.description}`);
    
    // Collect metrics
    const metric = {
      timestamp: new Date(),
      value: Math.random() * 100,
      status: Math.random() > 0.8 ? 'alert' : 'normal'
    };
    
    this.metrics.set(task.id, metric.value);
    
    return metric;
  }

  private startMonitoring(goal: Goal): void {
    const interval = setInterval(async () => {
      const currentValue = Math.random() * 100;
      
      if (currentValue > 80) {
        // Send alert
        await this.sendMessage(
          goal.metadata?.requestor || this.id,
          MessageType.INFORM,
          {
            topic: 'alert:threshold',
            body: {
              goalId: goal.id,
              metric: 'system_load',
              value: currentValue,
              threshold: 80,
              severity: 'high'
            }
          },
          MessagePriority.URGENT
        );
      }
    }, 5000);

    // Clean up after 30 seconds
    setTimeout(() => clearInterval(interval), 30000);
  }
}

async function runAdvancedExample() {
  console.log('🚀 Agentic Flow - Advanced Coordination Example\n');

  // Create a diverse team of agents
  const coordinator = new CoordinatorAgent('MasterCoordinator');
  const executor1 = new ExecutorAgent('Executor-Alpha');
  const executor2 = new ExecutorAgent('Executor-Beta');
  const analyzer1 = new AnalyzerAgent('DataAnalyzer-1');
  const analyzer2 = new AnalyzerAgent('DataAnalyzer-2');
  const monitor = new MonitorAgent('SystemMonitor');

  const agents = [coordinator, executor1, executor2, analyzer1, analyzer2, monitor];

  // Initialize all agents
  console.log('Initializing agent network...');
  await Promise.all(agents.map(agent => agent.initialize()));
  await Promise.all(agents.map(agent => agent.start()));

  // Set up comprehensive event logging
  agents.forEach(agent => {
    agent.on('state:changed', ({ previous, current }) => {
      console.log(`🔄 ${agent.getProfile().name}: ${previous} → ${current}`);
    });

    agent.on('message:sent', (message) => {
      console.log(`📤 ${agent.getProfile().name} sent: ${message.content.topic}`);
    });

    agent.on('team:memberAdded', ({ team, member }) => {
      console.log(`👥 Agent joined team ${team.name}`);
    });
  });

  // Scenario 1: Complex multi-agent workflow
  console.log('\n--- Scenario 1: Multi-Agent Data Processing Pipeline ---');
  
  const pipelineGoal = await coordinator.goalEngine.parseGoal(
    'Process customer transaction data, analyze for fraud patterns, generate risk report, and maintain continuous monitoring'
  );
  pipelineGoal.priority = GoalPriority.CRITICAL;
  
  // Add sub-goals
  pipelineGoal.subGoals = [
    await coordinator.goalEngine.parseGoal('Extract and validate transaction data'),
    await coordinator.goalEngine.parseGoal('Analyze transactions for suspicious patterns'),
    await coordinator.goalEngine.parseGoal('Generate comprehensive risk assessment report'),
    await coordinator.goalEngine.parseGoal('Maintain real-time fraud detection monitoring')
  ];

  await coordinator.addGoal(pipelineGoal);

  // Wait for initial processing
  await new Promise(resolve => setTimeout(resolve, 8000));

  // Scenario 2: Dynamic team reorganization
  console.log('\n--- Scenario 2: Dynamic Team Reorganization ---');
  
  const optimizationGoal = await coordinator.goalEngine.parseGoal(
    'Optimize system performance by analyzing bottlenecks and redistributing workload'
  );
  optimizationGoal.priority = GoalPriority.HIGH;
  
  await coordinator.addGoal(optimizationGoal);

  // Simulate changing conditions
  setTimeout(async () => {
    console.log('\n⚡ Simulating high load condition...');
    
    // Send multiple urgent tasks
    for (let i = 0; i < 5; i++) {
      const urgentGoal = await coordinator.goalEngine.parseGoal(
        `Urgent: Process critical request ${i + 1}`
      );
      urgentGoal.priority = GoalPriority.CRITICAL;
      await coordinator.addGoal(urgentGoal);
    }
  }, 5000);

  // Wait for processing
  await new Promise(resolve => setTimeout(resolve, 15000));

  // Scenario 3: Collaborative problem solving
  console.log('\n--- Scenario 3: Collaborative Problem Solving ---');
  
  const complexProblem = await coordinator.goalEngine.parseGoal(
    'Investigate system anomaly: unusual pattern detected in user behavior requiring multi-disciplinary analysis'
  );
  complexProblem.priority = GoalPriority.HIGH;
  complexProblem.constraints = [
    { type: 'time', value: '1 hour', description: 'Must be resolved within 1 hour' },
    { type: 'resource', value: 'all-analyzers', description: 'Requires all analysis agents' }
  ];

  await coordinator.addGoal(complexProblem);

  // Wait for collaborative processing
  await new Promise(resolve => setTimeout(resolve, 10000));

  // Generate final report
  console.log('\n--- Performance Summary ---');
  
  for (const agent of agents) {
    const profile = agent.getProfile();
    const metrics = profile.metadata.performance;
    
    console.log(`\n${profile.name} (${profile.type}):`);
    console.log(`  Tasks completed: ${metrics.tasksCompleted}`);
    console.log(`  Success rate: ${(metrics.successRate * 100).toFixed(1)}%`);
    console.log(`  Current state: ${profile.state}`);
  }

  // Show team information
  const teams = coordinator['teamCoordinator'].getAllTeams();
  console.log(`\nTotal teams formed: ${teams.length}`);
  teams.forEach(team => {
    console.log(`  ${team.name}: ${team.members.length} members, ${team.status}`);
  });

  // Cleanup
  console.log('\n--- Shutting down agent network ---');
  await Promise.all(agents.map(agent => agent.stop()));

  console.log('\n✅ Advanced coordination example completed!');
}

// Run the example
runAdvancedExample().catch(console.error);