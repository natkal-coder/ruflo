"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const globals_1 = require("@jest/globals");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
// Mock fs module
globals_1.jest.mock('fs');
globals_1.jest.mock('path');
const mockFs = fs;
const mockPath = path;
(0, globals_1.describe)('CLI Commands', () => {
    (0, globals_1.beforeEach)(() => {
        globals_1.jest.clearAllMocks();
        // Setup default mocks
        mockPath.join.mockImplementation((...paths) => paths.join('/'));
        mockPath.resolve.mockImplementation((...paths) => '/' + paths.join('/'));
        mockFs.existsSync.mockReturnValue(false);
        mockFs.mkdirSync.mockImplementation(() => { });
        mockFs.writeFileSync.mockImplementation(() => { });
        mockFs.readFileSync.mockReturnValue('{}');
    });
    (0, globals_1.describe)('init command', () => {
        (0, globals_1.it)('should create project structure', async () => {
            // Import the init command dynamically to avoid module-level fs calls
            const { initProject } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/init')));
            const projectPath = '/test/project';
            const config = {
                name: 'test-project',
                description: 'Test project',
                providers: ['anthropic'],
                features: ['workflows', 'agents']
            };
            await initProject(projectPath, config);
            // Verify directory creation
            (0, globals_1.expect)(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath, { recursive: true });
            (0, globals_1.expect)(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath + '/agents', { recursive: true });
            (0, globals_1.expect)(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath + '/workflows', { recursive: true });
            (0, globals_1.expect)(mockFs.mkdirSync).toHaveBeenCalledWith(projectPath + '/goals', { recursive: true });
            // Verify file creation
            (0, globals_1.expect)(mockFs.writeFileSync).toHaveBeenCalledWith(projectPath + '/package.json', globals_1.expect.stringContaining('"name": "test-project"'));
            (0, globals_1.expect)(mockFs.writeFileSync).toHaveBeenCalledWith(projectPath + '/agentic-flow.config.json', globals_1.expect.any(String));
        });
        (0, globals_1.it)('should handle existing project directory', async () => {
            const { initProject } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/init')));
            mockFs.existsSync.mockReturnValue(true);
            const projectPath = '/existing/project';
            const config = {
                name: 'existing-project',
                description: 'Existing project',
                providers: ['openai'],
                features: ['agents']
            };
            await (0, globals_1.expect)(initProject(projectPath, config)).rejects.toThrow('already exists');
        });
        (0, globals_1.it)('should create correct configuration files', async () => {
            const { initProject } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/init')));
            const projectPath = '/config/test';
            const config = {
                name: 'config-test',
                description: 'Configuration test',
                providers: ['anthropic', 'openai'],
                features: ['workflows', 'agents', 'learning']
            };
            await initProject(projectPath, config);
            // Find the agentic-flow.config.json write call
            const configCall = mockFs.writeFileSync.mock.calls.find(call => call[0].toString().includes('agentic-flow.config.json'));
            (0, globals_1.expect)(configCall).toBeDefined();
            const configContent = JSON.parse(configCall[1]);
            (0, globals_1.expect)(configContent.providers).toEqual(['anthropic', 'openai']);
            (0, globals_1.expect)(configContent.features).toEqual(['workflows', 'agents', 'learning']);
        });
    });
    (0, globals_1.describe)('agent command', () => {
        (0, globals_1.it)('should create agent configuration', async () => {
            const { createAgent } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/agent')));
            const agentConfig = {
                name: 'test-agent',
                type: 'researcher',
                capabilities: ['research', 'analysis'],
                description: 'A test research agent'
            };
            const result = await createAgent(agentConfig);
            (0, globals_1.expect)(result).toHaveProperty('id');
            (0, globals_1.expect)(result).toHaveProperty('name', 'test-agent');
            (0, globals_1.expect)(result).toHaveProperty('type', 'researcher');
            (0, globals_1.expect)(result.capabilities).toEqual(['research', 'analysis']);
        });
        (0, globals_1.it)('should validate agent configuration', async () => {
            const { createAgent } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/agent')));
            const invalidConfig = {
                name: '',
                type: 'invalid-type',
                capabilities: [],
                description: ''
            };
            await (0, globals_1.expect)(createAgent(invalidConfig)).rejects.toThrow();
        });
        (0, globals_1.it)('should support different agent types', async () => {
            const { createAgent } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/agent')));
            const agentTypes = ['researcher', 'developer', 'analyst', 'coordinator'];
            for (const type of agentTypes) {
                const config = {
                    name: `${type}-agent`,
                    type,
                    capabilities: ['generic'],
                    description: `A ${type} agent`
                };
                const result = await createAgent(config);
                (0, globals_1.expect)(result.type).toBe(type);
            }
        });
    });
    (0, globals_1.describe)('workflow command', () => {
        (0, globals_1.it)('should create workflow configuration', async () => {
            const { createWorkflow } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/workflow')));
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
            (0, globals_1.expect)(result).toHaveProperty('id');
            (0, globals_1.expect)(result).toHaveProperty('name', 'test-workflow');
            (0, globals_1.expect)(result.steps).toHaveLength(1);
            (0, globals_1.expect)(result.steps[0]).toHaveProperty('name', 'Research Step');
        });
        (0, globals_1.it)('should validate workflow steps', async () => {
            const { createWorkflow } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/workflow')));
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
            await (0, globals_1.expect)(createWorkflow(invalidWorkflow)).rejects.toThrow();
        });
        (0, globals_1.it)('should support different step types', async () => {
            const { createWorkflow } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/workflow')));
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
                (0, globals_1.expect)(result.steps[0].type).toBe(stepType);
            }
        });
    });
    (0, globals_1.describe)('error handling', () => {
        (0, globals_1.it)('should handle file system errors gracefully', async () => {
            const { initProject } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/init')));
            mockFs.mkdirSync.mockImplementation(() => {
                throw new Error('Permission denied');
            });
            const config = {
                name: 'error-test',
                description: 'Error test project',
                providers: ['anthropic'],
                features: ['agents']
            };
            await (0, globals_1.expect)(initProject('/error/path', config)).rejects.toThrow('Permission denied');
        });
        (0, globals_1.it)('should validate required parameters', async () => {
            const { createAgent } = await Promise.resolve().then(() => __importStar(require('../../src/cli/commands/agent')));
            const invalidConfigs = [
                { name: '', type: 'researcher', capabilities: [], description: '' },
                { name: 'test', type: '', capabilities: [], description: 'test' },
                { name: 'test', type: 'researcher', capabilities: [], description: '' }
            ];
            for (const config of invalidConfigs) {
                await (0, globals_1.expect)(createAgent(config)).rejects.toThrow();
            }
        });
    });
    (0, globals_1.describe)('utility functions', () => {
        (0, globals_1.it)('should generate unique IDs', async () => {
            const { generateId } = await Promise.resolve().then(() => __importStar(require('../../src/cli/utils')));
            const id1 = generateId();
            const id2 = generateId();
            (0, globals_1.expect)(id1).toBeDefined();
            (0, globals_1.expect)(id2).toBeDefined();
            (0, globals_1.expect)(id1).not.toBe(id2);
            (0, globals_1.expect)(typeof id1).toBe('string');
            (0, globals_1.expect)(id1.length).toBeGreaterThan(0);
        });
        (0, globals_1.it)('should validate configuration objects', async () => {
            const { validateConfig } = await Promise.resolve().then(() => __importStar(require('../../src/cli/utils')));
            const validConfig = {
                name: 'valid-config',
                type: 'agent',
                required: true
            };
            const invalidConfig = {
                name: '',
                type: 'invalid'
            };
            (0, globals_1.expect)(() => validateConfig(validConfig, ['name', 'type'])).not.toThrow();
            (0, globals_1.expect)(() => validateConfig(invalidConfig, ['name', 'type', 'required'])).toThrow();
        });
    });
});
//# sourceMappingURL=commands.test.js.map