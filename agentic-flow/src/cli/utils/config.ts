import fs from 'fs-extra';
import path from 'path';
import { ConfigurationError } from './error-handler';

export interface AgenticFlowConfig {
  version: string;
  project: {
    id: string;
    name: string;
    path: string;
    template: string;
    framework: string;
    features: string[];
    typescript: boolean;
    createdAt: string;
  };
  agents: Record<string, any>;
  workflows: Record<string, any>;
  settings: {
    logLevel: string;
    maxConcurrentAgents: number;
    memoryBackend: string;
    apiPort: number;
    [key: string]: any;
  };
}

export async function loadConfig(): Promise<AgenticFlowConfig> {
  const configPath = await findConfigPath();
  
  if (!configPath) {
    throw new ConfigurationError(
      'No Agentic Flow configuration found',
      [
        'Run "agentic-flow init" to initialize a project',
        'Make sure you are in an Agentic Flow project directory',
      ]
    );
  }

  try {
    const config = await fs.readJSON(configPath);
    return config;
  } catch (error) {
    throw new ConfigurationError(
      `Failed to load configuration: ${error.message}`,
      ['Check if the configuration file is valid JSON']
    );
  }
}

export async function saveConfig(config: AgenticFlowConfig): Promise<void> {
  const configPath = await findConfigPath();
  
  if (!configPath) {
    throw new ConfigurationError('No configuration file found');
  }

  try {
    await fs.writeJSON(configPath, config, { spaces: 2 });
  } catch (error) {
    throw new ConfigurationError(`Failed to save configuration: ${error.message}`);
  }
}

export async function findConfigPath(): Promise<string | null> {
  let currentDir = process.cwd();
  
  while (true) {
    const configPath = path.join(currentDir, '.agentic-flow', 'config.json');
    
    if (await fs.pathExists(configPath)) {
      return configPath;
    }
    
    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) {
      // Reached root directory
      break;
    }
    
    currentDir = parentDir;
  }
  
  return null;
}

export async function isAgenticFlowProject(): Promise<boolean> {
  const configPath = await findConfigPath();
  return configPath !== null;
}

export async function getProjectRoot(): Promise<string | null> {
  const configPath = await findConfigPath();
  
  if (!configPath) {
    return null;
  }
  
  return path.dirname(path.dirname(configPath));
}