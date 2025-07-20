import fs from 'fs-extra';
import path from 'path';
import chalk from 'chalk';

export interface ProjectConfig {
  id: string;
  name: string;
  path: string;
  template: string;
  framework: string;
  features: string[];
  typescript: boolean;
  createdAt: string;
}

export async function createProjectStructure(config: ProjectConfig): Promise<void> {
  const { path: projectPath, typescript, features } = config;

  // Create base directories
  const dirs = [
    '',
    'src',
    'src/agents',
    'src/workflows',
    'src/lib',
    'src/utils',
    '.agentic-flow',
    '.agentic-flow/logs',
    '.agentic-flow/cache',
    '.agentic-flow/data',
  ];

  if (features.includes('testing')) {
    dirs.push('tests', 'tests/unit', 'tests/integration');
  }

  if (features.includes('api')) {
    dirs.push('src/api', 'src/api/routes', 'src/api/middleware');
  }

  if (features.includes('dashboard')) {
    dirs.push('src/dashboard', 'public', 'public/assets');
  }

  for (const dir of dirs) {
    await fs.ensureDir(path.join(projectPath, dir));
  }

  // Create package.json
  const packageJson = {
    name: config.name,
    version: '0.1.0',
    description: 'An Agentic Flow project',
    main: typescript ? 'dist/index.js' : 'src/index.js',
    scripts: {
      start: 'node ' + (typescript ? 'dist/index.js' : 'src/index.js'),
      dev: typescript ? 'ts-node-dev src/index.ts' : 'nodemon src/index.js',
      build: typescript ? 'tsc' : 'echo "No build step required"',
      test: features.includes('testing') ? 'jest' : 'echo "No tests configured"',
      lint: typescript ? 'eslint src --ext .ts' : 'eslint src',
    },
    keywords: ['agentic-flow', 'ai', 'automation'],
    dependencies: {
      'agentic-flow': '^1.0.0',
      dotenv: '^16.3.1',
    },
    devDependencies: {},
  };

  if (typescript) {
    packageJson.devDependencies = {
      ...packageJson.devDependencies,
      '@types/node': '^20.10.5',
      'ts-node': '^10.9.2',
      'ts-node-dev': '^2.0.0',
      typescript: '^5.3.3',
      '@typescript-eslint/eslint-plugin': '^6.15.0',
      '@typescript-eslint/parser': '^6.15.0',
    };
  }

  if (features.includes('testing')) {
    packageJson.devDependencies = {
      ...packageJson.devDependencies,
      jest: '^29.7.0',
      ...(typescript ? { '@types/jest': '^29.5.11', 'ts-jest': '^29.1.1' } : {}),
    };
  }

  if (features.includes('api')) {
    packageJson.dependencies = {
      ...packageJson.dependencies,
      'express': '^4.18.2',
      'cors': '^2.8.5',
      'body-parser': '^1.20.2',
    };
    
    if (typescript) {
      packageJson.devDependencies = {
        ...packageJson.devDependencies,
        '@types/express': '^4.17.21',
        '@types/cors': '^2.8.17',
      };
    }
  }

  await fs.writeJSON(path.join(projectPath, 'package.json'), packageJson, { spaces: 2 });

  // Create TypeScript config if needed
  if (typescript) {
    const tsConfig = {
      compilerOptions: {
        target: 'ES2022',
        module: 'commonjs',
        lib: ['ES2022'],
        outDir: './dist',
        rootDir: './src',
        strict: true,
        esModuleInterop: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true,
        resolveJsonModule: true,
        moduleResolution: 'node',
        allowSyntheticDefaultImports: true,
        declaration: true,
        sourceMap: true,
      },
      include: ['src/**/*'],
      exclude: ['node_modules', 'dist', 'tests'],
    };

    await fs.writeJSON(path.join(projectPath, 'tsconfig.json'), tsConfig, { spaces: 2 });
  }

  // Create main entry file
  const ext = typescript ? 'ts' : 'js';
  const mainContent = typescript
    ? `import { AgenticFlow } from 'agentic-flow';

async function main() {
  console.log('Welcome to ${config.name}!');
  
  // Initialize Agentic Flow
  const flow = new AgenticFlow({
    projectId: '${config.id}',
    config: '.agentic-flow/config.json',
  });

  await flow.initialize();
  
  // Your code here
}

main().catch(console.error);
`
    : `const { AgenticFlow } = require('agentic-flow');

async function main() {
  console.log('Welcome to ${config.name}!');
  
  // Initialize Agentic Flow
  const flow = new AgenticFlow({
    projectId: '${config.id}',
    config: '.agentic-flow/config.json',
  });

  await flow.initialize();
  
  // Your code here
}

main().catch(console.error);
`;

  await fs.writeFile(path.join(projectPath, `src/index.${ext}`), mainContent);

  // Create example agent
  const agentContent = typescript
    ? `import { Agent } from 'agentic-flow';

export class ExampleAgent extends Agent {
  constructor() {
    super({
      name: 'example-agent',
      type: 'custom',
      capabilities: ['example'],
    });
  }

  async execute(task: any): Promise<any> {
    console.log('Executing task:', task);
    // Implement your agent logic here
    return { success: true, result: 'Task completed' };
  }
}
`
    : `const { Agent } = require('agentic-flow');

class ExampleAgent extends Agent {
  constructor() {
    super({
      name: 'example-agent',
      type: 'custom',
      capabilities: ['example'],
    });
  }

  async execute(task) {
    console.log('Executing task:', task);
    // Implement your agent logic here
    return { success: true, result: 'Task completed' };
  }
}

module.exports = { ExampleAgent };
`;

  await fs.writeFile(path.join(projectPath, `src/agents/example-agent.${ext}`), agentContent);

  // Create example workflow
  const workflowContent = `name: example-workflow
description: An example workflow
trigger:
  type: manual
steps:
  - id: step1
    name: Example Step
    type: agent-task
    task: Perform an example task
    # agentId will be set when you create an agent
`;

  await fs.writeFile(path.join(projectPath, 'src/workflows/example-workflow.yaml'), workflowContent);

  // Create README
  const readmeContent = `# ${config.name}

An Agentic Flow project for AI-powered workflow orchestration.

## Getting Started

1. Install dependencies:
   \`\`\`bash
   npm install
   \`\`\`

2. Create your first agent:
   \`\`\`bash
   agentic-flow agent spawn researcher
   \`\`\`

3. Create a workflow:
   \`\`\`bash
   agentic-flow workflow create
   \`\`\`

4. Run the workflow:
   \`\`\`bash
   agentic-flow workflow run <workflow-id>
   \`\`\`

## Project Structure

- \`src/agents/\` - AI agent implementations
- \`src/workflows/\` - Workflow definitions
- \`src/lib/\` - Shared libraries
- \`src/utils/\` - Utility functions
- \`.agentic-flow/\` - Project configuration and data

## Features

${features.map(f => `- ${f.charAt(0).toUpperCase() + f.slice(1)}`).join('\n')}

## Learn More

- [Agentic Flow Documentation](https://github.com/agentic-flow/agentic-flow)
- [API Reference](https://github.com/agentic-flow/agentic-flow/docs/api)
- [Examples](https://github.com/agentic-flow/agentic-flow/examples)
`;

  await fs.writeFile(path.join(projectPath, 'README.md'), readmeContent);

  // Create .env.example
  const envContent = `# Agentic Flow Configuration
NODE_ENV=development
LOG_LEVEL=info

# AI Provider Configuration
# OPENAI_API_KEY=your-api-key
# ANTHROPIC_API_KEY=your-api-key

# API Configuration (if using API feature)
API_PORT=3000

# Database Configuration (if using persistence)
# DATABASE_URL=sqlite://.agentic-flow/data/db.sqlite
`;

  await fs.writeFile(path.join(projectPath, '.env.example'), envContent);

  // Create VS Code settings
  const vscodeDir = path.join(projectPath, '.vscode');
  await fs.ensureDir(vscodeDir);

  const vscodeSettings = {
    'editor.formatOnSave': true,
    'editor.codeActionsOnSave': {
      'source.fixAll.eslint': true,
    },
    'typescript.tsdk': 'node_modules/typescript/lib',
  };

  await fs.writeJSON(path.join(vscodeDir, 'settings.json'), vscodeSettings, { spaces: 2 });
}