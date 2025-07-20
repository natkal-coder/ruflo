import chalk from 'chalk';
import { logger } from './logger';

export interface AgenticFlowError extends Error {
  code?: string;
  details?: any;
  suggestions?: string[];
}

export function errorHandler(error: any): void {
  logger.error('Error occurred', { error: error.message, stack: error.stack });

  console.error();
  console.error(chalk.red.bold('Error:'), error.message);

  if (error.code) {
    console.error(chalk.gray(`Error Code: ${error.code}`));
  }

  if (error.details) {
    console.error(chalk.gray('Details:'), error.details);
  }

  // Provide helpful suggestions based on error type
  const suggestions = getSuggestions(error);
  if (suggestions.length > 0) {
    console.error();
    console.error(chalk.yellow('Suggestions:'));
    suggestions.forEach((suggestion) => {
      console.error(chalk.gray(`  • ${suggestion}`));
    });
  }

  if (process.env.DEBUG === 'true' && error.stack) {
    console.error();
    console.error(chalk.gray('Stack trace:'));
    console.error(chalk.gray(error.stack));
  }
}

function getSuggestions(error: any): string[] {
  const suggestions: string[] = error.suggestions || [];

  // Add context-specific suggestions
  if (error.code === 'ENOENT') {
    suggestions.push('Check if the file or directory exists');
    suggestions.push('Verify the path is correct');
  } else if (error.code === 'EACCES') {
    suggestions.push('Check file permissions');
    suggestions.push('Try running with elevated privileges');
  } else if (error.message.includes('not found')) {
    suggestions.push('Make sure you are in the correct directory');
    suggestions.push('Check if the resource exists');
  } else if (error.message.includes('configuration')) {
    suggestions.push('Run "agentic-flow init" to initialize the project');
    suggestions.push('Check if .agentic-flow/config.json exists');
  } else if (error.message.includes('agent')) {
    suggestions.push('List available agents with "agentic-flow agent list"');
    suggestions.push('Create a new agent with "agentic-flow agent spawn"');
  } else if (error.message.includes('workflow')) {
    suggestions.push('List available workflows with "agentic-flow workflow list"');
    suggestions.push('Create a new workflow with "agentic-flow workflow create"');
  }

  return suggestions;
}

export class ValidationError extends Error implements AgenticFlowError {
  code = 'VALIDATION_ERROR';
  
  constructor(message: string, public details?: any) {
    super(message);
    this.name = 'ValidationError';
  }
}

export class ConfigurationError extends Error implements AgenticFlowError {
  code = 'CONFIG_ERROR';
  
  constructor(message: string, public suggestions?: string[]) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

export class AgentError extends Error implements AgenticFlowError {
  code = 'AGENT_ERROR';
  
  constructor(message: string, public agentId?: string) {
    super(message);
    this.name = 'AgentError';
  }
}

export class WorkflowError extends Error implements AgenticFlowError {
  code = 'WORKFLOW_ERROR';
  
  constructor(message: string, public workflowId?: string) {
    super(message);
    this.name = 'WorkflowError';
  }
}