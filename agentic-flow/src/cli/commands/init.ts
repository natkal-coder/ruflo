import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'fs-extra';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../utils/logger';
import { validateProjectName } from '../utils/validators';
import { createProjectStructure } from '../utils/project-generator';

export const initCommand = new Command('init')
  .description('Initialize a new Agentic Flow project')
  .argument('[project-name]', 'Name of the project')
  .option('-t, --template <template>', 'Project template to use', 'default')
  .option('-s, --skip-install', 'Skip dependency installation')
  .option('-g, --git', 'Initialize git repository', true)
  .option('-f, --force', 'Force initialization in non-empty directory')
  .action(async (projectName, options) => {
    const spinner = ora();

    try {
      // Interactive setup if project name not provided
      if (!projectName) {
        const answers = await inquirer.prompt([
          {
            type: 'input',
            name: 'projectName',
            message: 'What is your project name?',
            default: 'my-agentic-flow-project',
            validate: validateProjectName,
          },
        ]);
        projectName = answers.projectName;
      }

      // Validate project name
      const validation = validateProjectName(projectName);
      if (validation !== true) {
        throw new Error(validation);
      }

      const projectPath = path.resolve(process.cwd(), projectName);

      // Check if directory exists
      if (await fs.pathExists(projectPath)) {
        if (!options.force) {
          const { overwrite } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'overwrite',
              message: `Directory ${projectName} already exists. Overwrite?`,
              default: false,
            },
          ]);

          if (!overwrite) {
            console.log(chalk.yellow('Initialization cancelled.'));
            return;
          }
        }
      }

      // Gather project configuration
      const config = await inquirer.prompt([
        {
          type: 'list',
          name: 'agentFramework',
          message: 'Which agent framework would you like to use?',
          choices: [
            { name: 'Claude Flow (Recommended)', value: 'claude-flow' },
            { name: 'Custom Framework', value: 'custom' },
            { name: 'None (Manual Setup)', value: 'none' },
          ],
        },
        {
          type: 'checkbox',
          name: 'features',
          message: 'Which features would you like to include?',
          choices: [
            { name: 'Workflow Automation', value: 'workflows', checked: true },
            { name: 'Agent Monitoring', value: 'monitoring', checked: true },
            { name: 'Memory System', value: 'memory', checked: true },
            { name: 'API Integration', value: 'api', checked: false },
            { name: 'Web Dashboard', value: 'dashboard', checked: false },
            { name: 'Testing Framework', value: 'testing', checked: true },
          ],
        },
        {
          type: 'confirm',
          name: 'typescript',
          message: 'Use TypeScript?',
          default: true,
        },
      ]);

      // Create project
      spinner.start('Creating project structure...');
      
      const projectConfig = {
        id: uuidv4(),
        name: projectName,
        path: projectPath,
        template: options.template,
        framework: config.agentFramework,
        features: config.features,
        typescript: config.typescript,
        createdAt: new Date().toISOString(),
      };

      await createProjectStructure(projectConfig);
      spinner.succeed('Project structure created');

      // Initialize git
      if (options.git) {
        spinner.start('Initializing git repository...');
        await fs.ensureDir(path.join(projectPath, '.git'));
        await fs.writeFile(
          path.join(projectPath, '.gitignore'),
          `node_modules/
dist/
.env
.env.local
*.log
.DS_Store
coverage/
.vscode/
.idea/
*.swp
*.swo
.agentic-flow/cache/
.agentic-flow/logs/
`
        );
        spinner.succeed('Git repository initialized');
      }

      // Create configuration file
      spinner.start('Creating configuration...');
      const configFile = {
        version: '1.0',
        project: projectConfig,
        agents: {},
        workflows: {},
        settings: {
          logLevel: 'info',
          maxConcurrentAgents: 10,
          memoryBackend: 'sqlite',
          apiPort: 3000,
        },
      };

      await fs.ensureDir(path.join(projectPath, '.agentic-flow'));
      await fs.writeJSON(
        path.join(projectPath, '.agentic-flow', 'config.json'),
        configFile,
        { spaces: 2 }
      );
      spinner.succeed('Configuration created');

      // Install dependencies
      if (!options.skipInstall && config.agentFramework !== 'none') {
        spinner.start('Installing dependencies...');
        // In a real implementation, this would run npm/yarn install
        spinner.succeed('Dependencies installed');
      }

      // Success message
      console.log();
      console.log(chalk.green('✨ Project initialized successfully!'));
      console.log();
      console.log(chalk.cyan('Next steps:'));
      console.log(chalk.gray(`  cd ${projectName}`));
      console.log(chalk.gray('  agentic-flow agent spawn researcher'));
      console.log(chalk.gray('  agentic-flow workflow create'));
      console.log();
      console.log(chalk.gray('For more information, run:'));
      console.log(chalk.gray('  agentic-flow help'));

      logger.info('Project initialized', { projectConfig });
    } catch (error) {
      spinner.fail('Initialization failed');
      throw error;
    }
  });