import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import * as fs from 'fs';
import * as path from 'path';

// Mock fs module
jest.mock('fs');
jest.mock('path');

const mockFs = fs as jest.Mocked<typeof fs>;
const mockPath = path as jest.Mocked<typeof path>;

describe('CLI Commands', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    // Setup default mocks
    mockPath.join.mockImplementation((...paths) => paths.join('/'));
    mockPath.resolve.mockImplementation((...paths) => '/' + paths.join('/'));
    mockFs.existsSync.mockReturnValue(false);
    mockFs.mkdirSync.mockImplementation(() => {});
    mockFs.writeFileSync.mockImplementation(() => {});
    mockFs.readFileSync.mockReturnValue('{}');
  });

  describe('init command', () => {
    it('should create project structure', async () => {
      // Import the init command dynamically to avoid module-level fs calls
      const { initProject } = await import('../../src/cli/commands/init');
      
      const projectPath = '/test/project';
      const config = {
        name: 'test-project',
        description: 'Test project',
        providers: ['anthropic'],
        features: ['workflows', 'agents']
      };

      await initProject(projectPath, config);

      // Verify directory creation
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath, { recursive: true });
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath + '/agents', { recursive: true });
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath + '/workflows', { recursive: true });
      expect(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath + '/goals', { recursive: true });

      // Verify file creation
      expect(mockFs.writeFileSync).toHaveBeenCalledWith(
        projectPath + '/package.json',
        expect.stringContaining('"name": "test-project"')
      );
      expect(mockFs.writeFileSync).toHaveBeenCalledWith(
        projectPath + '/agentic-flow.config.json',
        expect.any(String)
      );
    });

    it('should handle existing project directory', async () => {
      const { initProject } = await import('../../src/cli/commands/init');
      
      mockFs.existsSync.mockReturnValue(true);
      
      const projectPath = '/existing/project';
      const config = {
        name: 'existing-project',
        description: 'Existing project',
        providers: ['openai'],
        features: ['agents']
      };

      await expect(initProject(projectPath, config)).rejects.toThrow('already exists');
    });

    it('should create correct configuration files', async () => {
      const { initProject } = await import('../../src/cli/commands/init');
      
      const projectPath = '/config/test';
      const config = {
        name: 'config-test',
        description: 'Configuration test',
        providers: ['anthropic', 'openai'],
        features: ['workflows', 'agents', 'learning']
      };

      await initProject(projectPath, config);

      // Find the agentic-flow.config.json write call
      const configCall = mockFs.writeFileSync.mock.calls.find(call => 
        call[0].toString().includes('agentic-flow.config.json')
      );
      
      expect(configCall).toBeDefined();
      
      const configContent = JSON.parse(configCall![1] as string);
      expect(configContent.providers).toEqual(['anthropic', 'openai']);
      expect(configContent.features).toEqual(['workflows', 'agents', 'learning']);
    });
  });

  describe('agent command', () => {
    it('should create agent configuration', async () => {
      const { createAgent } = await import('../../src/cli/commands/agent');
      
      const agentConfig = {
        name: 'test-agent',
        type: 'researcher',
        capabilities: ['research', 'analysis'],
        description: 'A test research agent'
      };

      const result = await createAgent(agentConfig);

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('name', 'test-agent');
      expect(result).toHaveProperty('type', 'researcher');
      expect(result.capabilities).toEqual(['research', 'analysis']);
    });

    it('should validate agent configuration', async () => {
      const { createAgent } = await import('../../src/cli/commands/agent');
      
      const invalidConfig = {
        name: '',
        type: 'invalid-type',
        capabilities: [],
        description: ''
      };

      await expect(createAgent(invalidConfig)).rejects.toThrow();
    });

    it('should support different agent types', async () => {
      const { createAgent } = await import('../../src/cli/commands/agent');
      
      const agentTypes = ['researcher', 'developer', 'analyst', 'coordinator'];
      
      for (const type of agentTypes) {
        const config = {
          name: `${type}-agent`,
          type,
          capabilities: ['generic'],
          description: `A ${type} agent`
        };

        const result = await createAgent(config);
        expect(result.type).toBe(type);
      }
    });
  });

  describe('workflow command', () => {
    it('should create workflow configuration', async () => {
      const { createWorkflow } = await import('../../src/cli/commands/workflow');
      
      const workflowConfig = {
        name: 'test-workflow',
        description: 'A test workflow',
        steps: [
          {
            name: 'Research Step',
            type: 'agent-task',
            config: {
              agentType: 'researcher',
              goal: 'Research the topic'
            }
          }
        ],
        triggers: []
      };

      const result = await createWorkflow(workflowConfig);

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('name', 'test-workflow');
      expect(result.steps).toHaveLength(1);
      expect(result.steps[0]).toHaveProperty('name', 'Research Step');
    });

    it('should validate workflow steps', async () => {
      const { createWorkflow } = await import('../../src/cli/commands/workflow');
      
      const invalidWorkflow = {
        name: 'invalid-workflow',
        description: 'Invalid workflow',
        steps: [
          {
            name: '',
            type: 'invalid-type',
            config: {}
          }
        ],
        triggers: []
      };

      await expect(createWorkflow(invalidWorkflow)).rejects.toThrow();
    });

    it('should support different step types', async () => {
      const { createWorkflow } = await import('../../src/cli/commands/workflow');
      
      const stepTypes = ['agent-task', 'parallel', 'condition', 'loop', 'http', 'script'];
      
      for (const stepType of stepTypes) {
        const config = {
          name: `${stepType}-workflow`,
          description: `Workflow with ${stepType} step`,
          steps: [
            {
              name: `${stepType} Step`,
              type: stepType,
              config: stepType === 'agent-task' ? { agentType: 'test', goal: 'test' } : {}
            }
          ],
          triggers: []
        };

        const result = await createWorkflow(config);
        expect(result.steps[0].type).toBe(stepType);
      }
    });
  });

  describe('error handling', () => {
    it('should handle file system errors gracefully', async () => {
      const { initProject } = await import('../../src/cli/commands/init');
      
      mockFs.mkdirSync.mockImplementation(() => {
        throw new Error('Permission denied');
      });

      const config = {
        name: 'error-test',
        description: 'Error test project',
        providers: ['anthropic'],
        features: ['agents']
      };

      await expect(initProject('/error/path', config)).rejects.toThrow('Permission denied');
    });

    it('should validate required parameters', async () => {
      const { createAgent } = await import('../../src/cli/commands/agent');
      
      const invalidConfigs = [
        { name: '', type: 'researcher', capabilities: [], description: '' },
        { name: 'test', type: '', capabilities: [], description: 'test' },
        { name: 'test', type: 'researcher', capabilities: [], description: '' }
      ];

      for (const config of invalidConfigs) {
        await expect(createAgent(config)).rejects.toThrow();
      }
    });
  });

  describe('utility functions', () => {
    it('should generate unique IDs', async () => {
      const { generateId } = await import('../../src/cli/utils');
      
      const id1 = generateId();
      const id2 = generateId();
      
      expect(id1).toBeDefined();
      expect(id2).toBeDefined();
      expect(id1).not.toBe(id2);
      expect(typeof id1).toBe('string');
      expect(id1.length).toBeGreaterThan(0);
    });

    it('should validate configuration objects', async () => {
      const { validateConfig } = await import('../../src/cli/utils');
      
      const validConfig = {
        name: 'valid-config',
        type: 'agent',
        required: true
      };

      const invalidConfig = {
        name: '',
        type: 'invalid'
      };

      expect(() => validateConfig(validConfig, ['name', 'type'])).not.toThrow();
      expect(() => validateConfig(invalidConfig, ['name', 'type', 'required'])).toThrow();
    });
  });
});