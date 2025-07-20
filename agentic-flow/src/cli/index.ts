import { Command } from 'commander';
import chalk from 'chalk';
import figlet from 'figlet';
// import updateNotifier from 'update-notifier';
import { initCommand } from './commands/init';
import { agentCommand } from './commands/agent';
import { workflowCommand } from './commands/workflow';
import { helpCommand } from './commands/help';
const { version } = require('../../package.json');
import { errorHandler } from './utils/error-handler';
import { logger } from './utils/logger';

// Check for updates
// const pkg = require('../../package.json');
// updateNotifier({ pkg }).notify();

// Create main program
const program = new Command();

// Display banner
console.log(
  chalk.cyan(
    figlet.textSync('Agentic Flow', {
      font: 'Standard',
      horizontalLayout: 'default',
      verticalLayout: 'default',
    })
  )
);

// Configure program
program
  .name('agentic-flow')
  .description('AI-powered workflow orchestration CLI for autonomous agent management')
  .version(version, '-v, --version', 'Display version number')
  .option('-d, --debug', 'Enable debug mode')
  .option('-q, --quiet', 'Suppress non-error output')
  .option('--no-color', 'Disable colored output')
  .hook('preAction', (thisCommand, actionCommand) => {
    // Set up global options
    const options = thisCommand.opts();
    if (options.debug) {
      process.env.DEBUG = 'true';
      logger.level = 'debug';
    }
    if (options.quiet) {
      process.env.QUIET = 'true';
      logger.level = 'error';
    }
    if (!options.color) {
      chalk.level = 0;
    }
  });

// Add commands
program.addCommand(initCommand);
program.addCommand(agentCommand);
program.addCommand(workflowCommand);
program.addCommand(helpCommand);

// Custom help
program.helpOption('-h, --help', 'Display help for command');
program.addHelpText('after', `
${chalk.gray('Examples:')}
  $ agentic-flow init                    Initialize a new project
  $ agentic-flow agent spawn researcher  Create a new researcher agent
  $ agentic-flow workflow create         Create a new workflow
  $ agentic-flow help agent              Get help for agent commands

${chalk.gray('For more information, visit:')} ${chalk.cyan('https://github.com/agentic-flow/agentic-flow')}
`);

// Error handling
program.exitOverride();

// Parse arguments
async function main() {
  try {
    await program.parseAsync(process.argv);
  } catch (error) {
    errorHandler(error);
    process.exit(1);
  }
}

// Run CLI
main().catch(errorHandler);

export { program };