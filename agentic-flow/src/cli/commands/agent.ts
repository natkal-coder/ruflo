import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
const Table = require('cli-table3');
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { loadConfig, saveConfig } from '../utils/config';
import { AgentManager } from '../../lib/agent-manager';

const agentManager = new AgentManager();

export const agentCommand = new Command('agent')
  .description('Manage AI agents')
  .action(() => {
    agentCommand.outputHelp();
  });

// Spawn subcommand
agentCommand
  .command('spawn')
  .description('Create a new AI agent')
  .argument('[type]', 'Type of agent to spawn')
  .option('-n, --name <name>', 'Agent name')
  .option('-c, --capabilities <capabilities>', 'Comma-separated list of capabilities')
  .option('-m, --model <model>', 'AI model to use', 'claude-3')
  .option('-p, --parallel <count>', 'Number of parallel agents to spawn', '1')
  .option('--auto-start', 'Automatically start the agent after spawning')
  .action(async (type, options) => {
    const spinner = ora();

    try {
      const config = await loadConfig();

      // Interactive setup if type not provided
      if (!type) {
        const answers = await inquirer.prompt([
          {
            type: 'list',
            name: 'type',
            message: 'Select agent type:',
            choices: [
              { name: 'Researcher - Information gathering and analysis', value: 'researcher' },
              { name: 'Developer - Code generation and implementation', value: 'developer' },
              { name: 'Analyst - Data analysis and insights', value: 'analyst' },
              { name: 'Coordinator - Task orchestration and management', value: 'coordinator' },
              { name: 'Tester - Quality assurance and testing', value: 'tester' },
              { name: 'Documenter - Documentation and reporting', value: 'documenter' },
              { name: 'Custom - Define your own agent', value: 'custom' },
            ],
          },
        ]);
        type = answers.type;
      }

      // Get agent configuration
      let agentConfig: any = {
        type,
        name: options.name,
        model: options.model,
        capabilities: options.capabilities?.split(',').map((c: string) => c.trim()) || [],
      };

      if (type === 'custom' || !agentConfig.name) {
        const customAnswers = await inquirer.prompt([
          {
            type: 'input',
            name: 'name',
            message: 'Agent name:',
            default: `${type}-${Date.now()}`,
            when: !agentConfig.name,
          },
          {
            type: 'input',
            name: 'description',
            message: 'Agent description:',
          },
          {
            type: 'checkbox',
            name: 'capabilities',
            message: 'Select agent capabilities:',
            choices: [
              'code-generation',
              'code-review',
              'testing',
              'documentation',
              'research',
              'data-analysis',
              'task-planning',
              'communication',
              'monitoring',
              'optimization',
            ],
            when: agentConfig.capabilities.length === 0,
          },
          {
            type: 'list',
            name: 'priority',
            message: 'Agent priority:',
            choices: ['low', 'medium', 'high', 'critical'],
            default: 'medium',
          },
        ]);

        agentConfig = { ...agentConfig, ...customAnswers };
      }

      const parallelCount = parseInt(options.parallel);
      const agents = [];

      spinner.start(`Spawning ${parallelCount} agent(s)...`);

      for (let i = 0; i < parallelCount; i++) {
        const agent = {
          id: uuidv4(),
          ...agentConfig,
          name: parallelCount > 1 ? `${agentConfig.name}-${i + 1}` : agentConfig.name,
          status: options.autoStart ? 'running' : 'idle',
          createdAt: new Date().toISOString(),
          metrics: {
            tasksCompleted: 0,
            successRate: 100,
            avgResponseTime: 0,
          },
        };

        agents.push(agent);
        config.agents[agent.id] = agent;

        if (options.autoStart) {
          await agentManager.startAgent(agent.id);
        }
      }

      await saveConfig(config);
      spinner.succeed(`Successfully spawned ${agents.length} agent(s)`);

      // Display created agents
      console.log();
      agents.forEach(agent => {
        console.log(chalk.green('✓'), chalk.cyan(`Agent: ${agent.name}`));
        console.log(chalk.gray(`  ID: ${agent.id}`));
        console.log(chalk.gray(`  Type: ${agent.type}`));
        console.log(chalk.gray(`  Status: ${agent.status}`));
      });

      logger.info('Agents spawned', { agents });
    } catch (error) {
      spinner.fail('Failed to spawn agent');
      throw error;
    }
  });

// List subcommand
agentCommand
  .command('list')
  .description('List all agents')
  .option('-s, --status <status>', 'Filter by status')
  .option('-t, --type <type>', 'Filter by type')
  .option('-j, --json', 'Output as JSON')
  .action(async (options) => {
    try {
      const config = await loadConfig();
      let agents = Object.values(config.agents || {});

      // Apply filters
      if (options.status) {
        agents = agents.filter((agent: any) => agent.status === options.status);
      }
      if (options.type) {
        agents = agents.filter((agent: any) => agent.type === options.type);
      }

      if (agents.length === 0) {
        console.log(chalk.yellow('No agents found.'));
        return;
      }

      if (options.json) {
        console.log(JSON.stringify(agents, null, 2));
        return;
      }

      // Create table
      const tableData = [
        ['ID', 'Name', 'Type', 'Status', 'Tasks', 'Success Rate', 'Created'],
        ...agents.map((agent: any) => [
          agent.id.substring(0, 8),
          agent.name,
          agent.type,
          agent.status === 'running' ? chalk.green(agent.status) : chalk.gray(agent.status),
          agent.metrics.tasksCompleted.toString(),
          `${agent.metrics.successRate}%`,
          new Date(agent.createdAt).toLocaleString(),
        ]),
      ];

      const table = new Table({
        head: tableData[0],
        style: { head: ['cyan'] }
      });
      table.push(...tableData.slice(1));
      console.log(table.toString());
      console.log(chalk.gray(`Total agents: ${agents.length}`));
    } catch (error) {
      throw error;
    }
  });

// Stop subcommand
agentCommand
  .command('stop')
  .description('Stop an agent')
  .argument('<agent-id>', 'Agent ID or name')
  .option('-f, --force', 'Force stop without graceful shutdown')
  .action(async (agentId, options) => {
    const spinner = ora();

    try {
      const config = await loadConfig();
      
      // Find agent by ID or name
      const agent = Object.values(config.agents || {}).find(
        (a: any) => a.id === agentId || a.name === agentId
      );

      if (!agent) {
        throw new Error(`Agent not found: ${agentId}`);
      }

      if (agent.status !== 'running') {
        console.log(chalk.yellow(`Agent ${agent.name} is not running.`));
        return;
      }

      spinner.start(`Stopping agent ${agent.name}...`);
      
      await agentManager.stopAgent(agent.id, options.force);
      
      agent.status = 'stopped';
      agent.stoppedAt = new Date().toISOString();
      await saveConfig(config);

      spinner.succeed(`Agent ${agent.name} stopped successfully`);
      logger.info('Agent stopped', { agentId: agent.id });
    } catch (error) {
      spinner.fail('Failed to stop agent');
      throw error;
    }
  });

// Start subcommand
agentCommand
  .command('start')
  .description('Start an agent')
  .argument('<agent-id>', 'Agent ID or name')
  .action(async (agentId) => {
    const spinner = ora();

    try {
      const config = await loadConfig();
      
      // Find agent by ID or name
      const agent = Object.values(config.agents || {}).find(
        (a: any) => a.id === agentId || a.name === agentId
      );

      if (!agent) {
        throw new Error(`Agent not found: ${agentId}`);
      }

      if (agent.status === 'running') {
        console.log(chalk.yellow(`Agent ${agent.name} is already running.`));
        return;
      }

      spinner.start(`Starting agent ${agent.name}...`);
      
      await agentManager.startAgent(agent.id);
      
      agent.status = 'running';
      agent.startedAt = new Date().toISOString();
      await saveConfig(config);

      spinner.succeed(`Agent ${agent.name} started successfully`);
      logger.info('Agent started', { agentId: agent.id });
    } catch (error) {
      spinner.fail('Failed to start agent');
      throw error;
    }
  });

// Remove subcommand
agentCommand
  .command('remove')
  .description('Remove an agent')
  .argument('<agent-id>', 'Agent ID or name')
  .option('-f, --force', 'Skip confirmation')
  .action(async (agentId, options) => {
    const spinner = ora();

    try {
      const config = await loadConfig();
      
      // Find agent by ID or name
      const agent = Object.values(config.agents || {}).find(
        (a: any) => a.id === agentId || a.name === agentId
      );

      if (!agent) {
        throw new Error(`Agent not found: ${agentId}`);
      }

      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Are you sure you want to remove agent ${agent.name}?`,
            default: false,
          },
        ]);

        if (!confirm) {
          console.log(chalk.yellow('Removal cancelled.'));
          return;
        }
      }

      spinner.start(`Removing agent ${agent.name}...`);
      
      if (agent.status === 'running') {
        await agentManager.stopAgent(agent.id, true);
      }
      
      delete config.agents[agent.id];
      await saveConfig(config);

      spinner.succeed(`Agent ${agent.name} removed successfully`);
      logger.info('Agent removed', { agentId: agent.id });
    } catch (error) {
      spinner.fail('Failed to remove agent');
      throw error;
    }
  });

// Info subcommand
agentCommand
  .command('info')
  .description('Show detailed information about an agent')
  .argument('<agent-id>', 'Agent ID or name')
  .action(async (agentId) => {
    try {
      const config = await loadConfig();
      
      // Find agent by ID or name
      const agent = Object.values(config.agents || {}).find(
        (a: any) => a.id === agentId || a.name === agentId
      );

      if (!agent) {
        throw new Error(`Agent not found: ${agentId}`);
      }

      console.log();
      console.log(chalk.cyan('Agent Information'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(`${chalk.bold('ID:')} ${agent.id}`);
      console.log(`${chalk.bold('Name:')} ${agent.name}`);
      console.log(`${chalk.bold('Type:')} ${agent.type}`);
      console.log(`${chalk.bold('Status:')} ${agent.status === 'running' ? chalk.green(agent.status) : chalk.gray(agent.status)}`);
      console.log(`${chalk.bold('Model:')} ${agent.model}`);
      console.log(`${chalk.bold('Priority:')} ${agent.priority || 'medium'}`);
      console.log(`${chalk.bold('Created:')} ${new Date(agent.createdAt).toLocaleString()}`);
      
      if (agent.description) {
        console.log(`${chalk.bold('Description:')} ${agent.description}`);
      }
      
      if (agent.capabilities && agent.capabilities.length > 0) {
        console.log(`${chalk.bold('Capabilities:')}`);
        agent.capabilities.forEach((cap: string) => {
          console.log(`  • ${cap}`);
        });
      }
      
      console.log();
      console.log(chalk.cyan('Metrics'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(`${chalk.bold('Tasks Completed:')} ${agent.metrics.tasksCompleted}`);
      console.log(`${chalk.bold('Success Rate:')} ${agent.metrics.successRate}%`);
      console.log(`${chalk.bold('Avg Response Time:')} ${agent.metrics.avgResponseTime}ms`);
      
      if (agent.lastTaskAt) {
        console.log(`${chalk.bold('Last Task:')} ${new Date(agent.lastTaskAt).toLocaleString()}`);
      }
    } catch (error) {
      throw error;
    }
  });