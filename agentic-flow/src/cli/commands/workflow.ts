import { Command } from 'commander';
import inquirer from 'inquirer';
import chalk from 'chalk';
import ora from 'ora';
const Table = require('cli-table3');
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs-extra';
import path from 'path';
import yaml from 'yaml';
import { logger } from '../utils/logger';
import { loadConfig, saveConfig } from '../utils/config';
import { WorkflowEngine } from '../../lib/workflow-engine';

const workflowEngine = new WorkflowEngine();

export const workflowCommand = new Command('workflow')
  .description('Manage workflows')
  .action(() => {
    workflowCommand.outputHelp();
  });

// Create subcommand
workflowCommand
  .command('create')
  .description('Create a new workflow')
  .argument('[name]', 'Workflow name')
  .option('-f, --file <file>', 'Load workflow from YAML file')
  .option('-t, --template <template>', 'Use workflow template')
  .action(async (name, options) => {
    const spinner = ora();

    try {
      const config = await loadConfig();

      let workflowDef: any;

      if (options.file) {
        // Load from file
        spinner.start('Loading workflow from file...');
        const filePath = path.resolve(process.cwd(), options.file);
        const content = await fs.readFile(filePath, 'utf-8');
        
        if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
          workflowDef = yaml.parse(content);
        } else {
          workflowDef = JSON.parse(content);
        }
        
        spinner.succeed('Workflow loaded from file');
      } else {
        // Interactive creation
        if (!name) {
          const { workflowName } = await inquirer.prompt([
            {
              type: 'input',
              name: 'workflowName',
              message: 'Workflow name:',
              default: `workflow-${Date.now()}`,
            },
          ]);
          name = workflowName;
        }

        const answers = await inquirer.prompt([
          {
            type: 'input',
            name: 'description',
            message: 'Workflow description:',
          },
          {
            type: 'list',
            name: 'trigger',
            message: 'Workflow trigger:',
            choices: [
              { name: 'Manual - Triggered by user', value: 'manual' },
              { name: 'Schedule - Run on schedule', value: 'schedule' },
              { name: 'Event - Triggered by event', value: 'event' },
              { name: 'Webhook - External trigger', value: 'webhook' },
            ],
          },
        ]);

        // Get trigger configuration
        let triggerConfig: any = { type: answers.trigger };
        
        if (answers.trigger === 'schedule') {
          const { schedule } = await inquirer.prompt([
            {
              type: 'input',
              name: 'schedule',
              message: 'Cron expression (e.g., "0 0 * * *" for daily):',
              default: '0 0 * * *',
            },
          ]);
          triggerConfig.schedule = schedule;
        } else if (answers.trigger === 'event') {
          const { eventType } = await inquirer.prompt([
            {
              type: 'input',
              name: 'eventType',
              message: 'Event type to listen for:',
              default: 'task.completed',
            },
          ]);
          triggerConfig.event = eventType;
        }

        // Define workflow steps
        const steps = [];
        let addMoreSteps = true;

        console.log(chalk.cyan('\nDefine workflow steps:'));
        
        while (addMoreSteps) {
          const stepAnswers = await inquirer.prompt([
            {
              type: 'input',
              name: 'name',
              message: 'Step name:',
              default: `step-${steps.length + 1}`,
            },
            {
              type: 'list',
              name: 'type',
              message: 'Step type:',
              choices: [
                { name: 'Agent Task - Assign task to agent', value: 'agent-task' },
                { name: 'Parallel Tasks - Run tasks in parallel', value: 'parallel' },
                { name: 'Conditional - If/else logic', value: 'conditional' },
                { name: 'Loop - Iterate over items', value: 'loop' },
                { name: 'Wait - Delay execution', value: 'wait' },
                { name: 'HTTP Request - Call external API', value: 'http' },
                { name: 'Script - Run custom script', value: 'script' },
              ],
            },
          ]);

          const step: any = {
            id: uuidv4(),
            name: stepAnswers.name,
            type: stepAnswers.type,
          };

          // Configure step based on type
          if (stepAnswers.type === 'agent-task') {
            const agents = Object.values(config.agents || {});
            if (agents.length === 0) {
              console.log(chalk.yellow('No agents available. Please create agents first.'));
            } else {
              const { agentId, task } = await inquirer.prompt([
                {
                  type: 'list',
                  name: 'agentId',
                  message: 'Select agent:',
                  choices: agents.map((a: any) => ({ name: `${a.name} (${a.type})`, value: a.id })),
                },
                {
                  type: 'input',
                  name: 'task',
                  message: 'Task description:',
                },
              ]);
              step.agentId = agentId;
              step.task = task;
            }
          } else if (stepAnswers.type === 'wait') {
            const { duration } = await inquirer.prompt([
              {
                type: 'number',
                name: 'duration',
                message: 'Wait duration (seconds):',
                default: 5,
              },
            ]);
            step.duration = duration;
          } else if (stepAnswers.type === 'http') {
            const httpAnswers = await inquirer.prompt([
              {
                type: 'input',
                name: 'url',
                message: 'URL:',
              },
              {
                type: 'list',
                name: 'method',
                message: 'HTTP method:',
                choices: ['GET', 'POST', 'PUT', 'DELETE'],
                default: 'GET',
              },
            ]);
            step.url = httpAnswers.url;
            step.method = httpAnswers.method;
          }

          steps.push(step);

          const { continueAdding } = await inquirer.prompt([
            {
              type: 'confirm',
              name: 'continueAdding',
              message: 'Add another step?',
              default: false,
            },
          ]);
          addMoreSteps = continueAdding;
        }

        workflowDef = {
          name,
          description: answers.description,
          trigger: triggerConfig,
          steps,
        };
      }

      // Create workflow
      spinner.start('Creating workflow...');
      
      const workflow = {
        id: uuidv4(),
        ...workflowDef,
        status: 'inactive',
        createdAt: new Date().toISOString(),
        runs: 0,
        lastRunAt: null,
      };

      config.workflows = config.workflows || {};
      config.workflows[workflow.id] = workflow;
      await saveConfig(config);

      spinner.succeed('Workflow created successfully');

      console.log();
      console.log(chalk.green('✓'), chalk.cyan(`Workflow: ${workflow.name}`));
      console.log(chalk.gray(`  ID: ${workflow.id}`));
      console.log(chalk.gray(`  Trigger: ${workflow.trigger.type}`));
      console.log(chalk.gray(`  Steps: ${workflow.steps.length}`));

      logger.info('Workflow created', { workflow });
    } catch (error) {
      spinner.fail('Failed to create workflow');
      throw error;
    }
  });

// List subcommand
workflowCommand
  .command('list')
  .description('List all workflows')
  .option('-s, --status <status>', 'Filter by status')
  .option('-j, --json', 'Output as JSON')
  .action(async (options) => {
    try {
      const config = await loadConfig();
      let workflows = Object.values(config.workflows || {});

      // Apply filters
      if (options.status) {
        workflows = workflows.filter((wf: any) => wf.status === options.status);
      }

      if (workflows.length === 0) {
        console.log(chalk.yellow('No workflows found.'));
        return;
      }

      if (options.json) {
        console.log(JSON.stringify(workflows, null, 2));
        return;
      }

      // Create table
      const tableData = [
        ['ID', 'Name', 'Status', 'Trigger', 'Steps', 'Runs', 'Last Run'],
        ...workflows.map((wf: any) => [
          wf.id.substring(0, 8),
          wf.name,
          wf.status === 'active' ? chalk.green(wf.status) : chalk.gray(wf.status),
          wf.trigger.type,
          wf.steps.length.toString(),
          wf.runs.toString(),
          wf.lastRunAt ? new Date(wf.lastRunAt).toLocaleString() : 'Never',
        ]),
      ];

      const table = new Table({
        head: tableData[0],
        style: { head: ['cyan'] }
      });
      table.push(...tableData.slice(1));
      console.log(table.toString());
      console.log(chalk.gray(`Total workflows: ${workflows.length}`));
    } catch (error) {
      throw error;
    }
  });

// Run subcommand
workflowCommand
  .command('run')
  .description('Run a workflow')
  .argument('<workflow-id>', 'Workflow ID or name')
  .option('-p, --params <params>', 'Workflow parameters (JSON string)')
  .option('-w, --watch', 'Watch workflow execution')
  .action(async (workflowId, options) => {
    const spinner = ora();

    try {
      const config = await loadConfig();
      
      // Find workflow by ID or name
      const workflow = Object.values(config.workflows || {}).find(
        (w: any) => w.id === workflowId || w.name === workflowId
      );

      if (!workflow) {
        throw new Error(`Workflow not found: ${workflowId}`);
      }

      let params = {};
      if (options.params) {
        try {
          params = JSON.parse(options.params);
        } catch (e) {
          throw new Error('Invalid JSON parameters');
        }
      }

      spinner.start(`Running workflow: ${workflow.name}`);
      
      const runId = uuidv4();
      const result = await workflowEngine.runWorkflow(workflow, params);
      
      // Update workflow stats
      workflow.runs++;
      workflow.lastRunAt = new Date().toISOString();
      await saveConfig(config);

      spinner.succeed(`Workflow completed successfully`);

      console.log();
      console.log(chalk.cyan('Workflow Run Summary'));
      console.log(chalk.gray('─'.repeat(50)));
      console.log(`${chalk.bold('Run ID:')} ${runId}`);
      console.log(`${chalk.bold('Status:')} ${chalk.green('Success')}`);
      console.log(`${chalk.bold('Duration:')} ${result.duration}ms`);
      console.log(`${chalk.bold('Steps Executed:')} ${result.stepsExecuted}`);

      if (result.outputs) {
        console.log();
        console.log(chalk.cyan('Outputs:'));
        console.log(JSON.stringify(result.outputs, null, 2));
      }

      logger.info('Workflow executed', { workflowId: workflow.id, runId, result });
    } catch (error) {
      spinner.fail('Workflow execution failed');
      throw error;
    }
  });

// Activate subcommand
workflowCommand
  .command('activate')
  .description('Activate a workflow')
  .argument('<workflow-id>', 'Workflow ID or name')
  .action(async (workflowId) => {
    const spinner = ora();

    try {
      const config = await loadConfig();
      
      // Find workflow by ID or name
      const workflow = Object.values(config.workflows || {}).find(
        (w: any) => w.id === workflowId || w.name === workflowId
      );

      if (!workflow) {
        throw new Error(`Workflow not found: ${workflowId}`);
      }

      if (workflow.status === 'active') {
        console.log(chalk.yellow(`Workflow ${workflow.name} is already active.`));
        return;
      }

      spinner.start(`Activating workflow: ${workflow.name}`);
      
      workflow.status = 'active';
      workflow.activatedAt = new Date().toISOString();
      
      // Register with workflow engine
      await workflowEngine.registerWorkflow(workflow);
      
      await saveConfig(config);

      spinner.succeed(`Workflow ${workflow.name} activated successfully`);
      logger.info('Workflow activated', { workflowId: workflow.id });
    } catch (error) {
      spinner.fail('Failed to activate workflow');
      throw error;
    }
  });

// Deactivate subcommand
workflowCommand
  .command('deactivate')
  .description('Deactivate a workflow')
  .argument('<workflow-id>', 'Workflow ID or name')
  .action(async (workflowId) => {
    const spinner = ora();

    try {
      const config = await loadConfig();
      
      // Find workflow by ID or name
      const workflow = Object.values(config.workflows || {}).find(
        (w: any) => w.id === workflowId || w.name === workflowId
      );

      if (!workflow) {
        throw new Error(`Workflow not found: ${workflowId}`);
      }

      if (workflow.status !== 'active') {
        console.log(chalk.yellow(`Workflow ${workflow.name} is not active.`));
        return;
      }

      spinner.start(`Deactivating workflow: ${workflow.name}`);
      
      workflow.status = 'inactive';
      workflow.deactivatedAt = new Date().toISOString();
      
      // Unregister from workflow engine
      await workflowEngine.unregisterWorkflow(workflow.id);
      
      await saveConfig(config);

      spinner.succeed(`Workflow ${workflow.name} deactivated successfully`);
      logger.info('Workflow deactivated', { workflowId: workflow.id });
    } catch (error) {
      spinner.fail('Failed to deactivate workflow');
      throw error;
    }
  });

// Export subcommand
workflowCommand
  .command('export')
  .description('Export a workflow')
  .argument('<workflow-id>', 'Workflow ID or name')
  .option('-o, --output <file>', 'Output file')
  .option('-f, --format <format>', 'Export format (json|yaml)', 'yaml')
  .action(async (workflowId, options) => {
    try {
      const config = await loadConfig();
      
      // Find workflow by ID or name
      const workflow = Object.values(config.workflows || {}).find(
        (w: any) => w.id === workflowId || w.name === workflowId
      );

      if (!workflow) {
        throw new Error(`Workflow not found: ${workflowId}`);
      }

      // Remove runtime properties
      const exportData = {
        name: workflow.name,
        description: workflow.description,
        trigger: workflow.trigger,
        steps: workflow.steps,
      };

      let output: string;
      if (options.format === 'yaml') {
        output = yaml.stringify(exportData);
      } else {
        output = JSON.stringify(exportData, null, 2);
      }

      if (options.output) {
        await fs.writeFile(options.output, output);
        console.log(chalk.green(`Workflow exported to ${options.output}`));
      } else {
        console.log(output);
      }
    } catch (error) {
      throw error;
    }
  });