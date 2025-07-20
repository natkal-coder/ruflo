import { Command } from 'commander';
import chalk from 'chalk';
const Table = require('cli-table3');

export const helpCommand = new Command('help')
  .description('Display help information')
  .argument('[command]', 'Command to get help for')
  .action((command) => {
    if (!command) {
      // General help
      displayGeneralHelp();
    } else {
      // Command-specific help
      displayCommandHelp(command);
    }
  });

function displayGeneralHelp() {
  console.log();
  console.log(chalk.cyan.bold('Agentic Flow - AI-Powered Workflow Orchestration'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log();
  console.log(chalk.yellow('Available Commands:'));
  console.log();

  const commands = [
    ['init', 'Initialize a new Agentic Flow project'],
    ['agent', 'Manage AI agents (spawn, list, stop, start, remove)'],
    ['workflow', 'Manage workflows (create, list, run, activate)'],
    ['help', 'Display help information'],
  ];

  commands.forEach(([cmd, desc]) => {
    console.log(`  ${chalk.cyan(cmd.padEnd(12))} ${desc}`);
  });

  console.log();
  console.log(chalk.yellow('Quick Start:'));
  console.log();
  console.log('  1. Initialize a new project:');
  console.log(chalk.gray('     $ agentic-flow init my-project'));
  console.log();
  console.log('  2. Create an agent:');
  console.log(chalk.gray('     $ agentic-flow agent spawn researcher'));
  console.log();
  console.log('  3. Create a workflow:');
  console.log(chalk.gray('     $ agentic-flow workflow create'));
  console.log();
  console.log('  4. Run the workflow:');
  console.log(chalk.gray('     $ agentic-flow workflow run <workflow-id>'));
  console.log();
  console.log(chalk.gray('For detailed command help, use: agentic-flow help <command>'));
  console.log();
  console.log(chalk.gray('Documentation: https://github.com/agentic-flow/agentic-flow'));
}

function displayCommandHelp(command: string) {
  console.log();
  
  switch (command) {
    case 'init':
      displayInitHelp();
      break;
    case 'agent':
      displayAgentHelp();
      break;
    case 'workflow':
      displayWorkflowHelp();
      break;
    default:
      console.log(chalk.red(`Unknown command: ${command}`));
      console.log(chalk.gray('Run "agentic-flow help" to see available commands.'));
  }
}

function displayInitHelp() {
  console.log(chalk.cyan.bold('Init Command'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log();
  console.log(chalk.yellow('Description:'));
  console.log('  Initialize a new Agentic Flow project with customizable options.');
  console.log();
  console.log(chalk.yellow('Usage:'));
  console.log('  agentic-flow init [project-name] [options]');
  console.log();
  console.log(chalk.yellow('Options:'));
  
  const options = [
    ['-t, --template <template>', 'Project template to use', 'default'],
    ['-s, --skip-install', 'Skip dependency installation', false],
    ['-g, --git', 'Initialize git repository', true],
    ['-f, --force', 'Force initialization in non-empty directory', false],
  ];

  const tableData = options.map(([flag, desc, defaultVal]) => [
    chalk.cyan(flag),
    desc,
    chalk.gray(defaultVal.toString()),
  ]);

  const table = new Table({
    head: ['Flag', 'Description', 'Default'],
    style: { head: ['cyan'] }
  });
  table.push(...tableData);
  console.log(table.toString());

  console.log(chalk.yellow('Examples:'));
  console.log();
  console.log('  Basic initialization:');
  console.log(chalk.gray('  $ agentic-flow init my-project'));
  console.log();
  console.log('  With custom template:');
  console.log(chalk.gray('  $ agentic-flow init my-project --template advanced'));
  console.log();
  console.log('  Skip dependency installation:');
  console.log(chalk.gray('  $ agentic-flow init my-project --skip-install'));
}

function displayAgentHelp() {
  console.log(chalk.cyan.bold('Agent Command'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log();
  console.log(chalk.yellow('Description:'));
  console.log('  Manage AI agents for task execution and automation.');
  console.log();
  console.log(chalk.yellow('Subcommands:'));
  console.log();

  const subcommands = [
    ['spawn [type]', 'Create a new AI agent'],
    ['list', 'List all agents'],
    ['start <agent-id>', 'Start an agent'],
    ['stop <agent-id>', 'Stop an agent'],
    ['remove <agent-id>', 'Remove an agent'],
    ['info <agent-id>', 'Show detailed agent information'],
  ];

  subcommands.forEach(([cmd, desc]) => {
    console.log(`  ${chalk.cyan(cmd.padEnd(20))} ${desc}`);
  });

  console.log();
  console.log(chalk.yellow('Agent Types:'));
  console.log();
  
  const agentTypes = [
    ['researcher', 'Information gathering and analysis'],
    ['developer', 'Code generation and implementation'],
    ['analyst', 'Data analysis and insights'],
    ['coordinator', 'Task orchestration and management'],
    ['tester', 'Quality assurance and testing'],
    ['documenter', 'Documentation and reporting'],
    ['custom', 'Define your own agent type'],
  ];

  agentTypes.forEach(([type, desc]) => {
    console.log(`  ${chalk.green(type.padEnd(12))} ${desc}`);
  });

  console.log();
  console.log(chalk.yellow('Examples:'));
  console.log();
  console.log('  Spawn a researcher agent:');
  console.log(chalk.gray('  $ agentic-flow agent spawn researcher --name "Research Bot"'));
  console.log();
  console.log('  Spawn multiple agents:');
  console.log(chalk.gray('  $ agentic-flow agent spawn developer --parallel 3'));
  console.log();
  console.log('  List all running agents:');
  console.log(chalk.gray('  $ agentic-flow agent list --status running'));
  console.log();
  console.log('  Stop an agent:');
  console.log(chalk.gray('  $ agentic-flow agent stop <agent-id>'));
}

function displayWorkflowHelp() {
  console.log(chalk.cyan.bold('Workflow Command'));
  console.log(chalk.gray('─'.repeat(60)));
  console.log();
  console.log(chalk.yellow('Description:'));
  console.log('  Create and manage automated workflows with AI agents.');
  console.log();
  console.log(chalk.yellow('Subcommands:'));
  console.log();

  const subcommands = [
    ['create [name]', 'Create a new workflow'],
    ['list', 'List all workflows'],
    ['run <workflow-id>', 'Run a workflow'],
    ['activate <workflow-id>', 'Activate a workflow'],
    ['deactivate <workflow-id>', 'Deactivate a workflow'],
    ['export <workflow-id>', 'Export workflow definition'],
  ];

  subcommands.forEach(([cmd, desc]) => {
    console.log(`  ${chalk.cyan(cmd.padEnd(25))} ${desc}`);
  });

  console.log();
  console.log(chalk.yellow('Workflow Triggers:'));
  console.log();
  
  const triggers = [
    ['manual', 'Triggered manually by user'],
    ['schedule', 'Run on a schedule (cron expression)'],
    ['event', 'Triggered by system events'],
    ['webhook', 'Triggered by external webhook'],
  ];

  triggers.forEach(([type, desc]) => {
    console.log(`  ${chalk.green(type.padEnd(10))} ${desc}`);
  });

  console.log();
  console.log(chalk.yellow('Step Types:'));
  console.log();
  
  const stepTypes = [
    ['agent-task', 'Assign task to an agent'],
    ['parallel', 'Run multiple tasks in parallel'],
    ['conditional', 'Execute based on conditions'],
    ['loop', 'Iterate over items'],
    ['wait', 'Delay execution'],
    ['http', 'Make HTTP requests'],
    ['script', 'Run custom scripts'],
  ];

  stepTypes.forEach(([type, desc]) => {
    console.log(`  ${chalk.green(type.padEnd(12))} ${desc}`);
  });

  console.log();
  console.log(chalk.yellow('Examples:'));
  console.log();
  console.log('  Create workflow from file:');
  console.log(chalk.gray('  $ agentic-flow workflow create --file workflow.yaml'));
  console.log();
  console.log('  Run workflow with parameters:');
  console.log(chalk.gray('  $ agentic-flow workflow run my-workflow --params \'{"key": "value"}\''));
  console.log();
  console.log('  Export workflow as YAML:');
  console.log(chalk.gray('  $ agentic-flow workflow export my-workflow --format yaml -o workflow.yaml'));
}

// Add more detailed help sections as needed