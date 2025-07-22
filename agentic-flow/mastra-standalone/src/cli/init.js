#!/usr/bin/env node

// Agentic Flow CLI - Initialize Mastra with Agentic Flow branding and configuration
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// CLI Configuration
const CLI_CONFIG = {
  name: 'agentic-flow-mastra',
  version: '2.0.0',
  description: 'Initialize Mastra with Agentic Flow branding and configuration'
};

// Template files to copy
const TEMPLATE_FILES = [
  'src/mastra/index.js',
  'src/mastra/theme.js', 
  'src/mastra/mcp.js',
  'src/mastra/ui/dashboard.js',
  'src/mastra/workflows/agentic-flow-workflows.js',
  'src/mastra/agents/claude-flow-agent.js',
  'src/mastra/agents/hive-mind-agent.js',
  'src/mastra/agents/ruv-swarm-agent.js',
  'package.json',
  '.env.example'
];

// Package.json template
const PACKAGE_JSON_TEMPLATE = {
  "name": "agentic-flow-mastra-project",
  "version": "1.0.0",
  "description": "Agentic Flow project with Mastra integration",
  "type": "module",
  "main": "src/mastra/index.js",
  "scripts": {
    "dev": "mastra dev",
    "start": "mastra start",
    "build": "mastra build",
    "test": "jest",
    "lint": "eslint src/",
    "agentic:init": "node src/cli/init.js",
    "agentic:dev": "npm run dev",
    "agentic:deploy": "npm run build && npm run start"
  },
  "dependencies": {
    "@mastra/core": "^0.10.15",
    "@anthropic-ai/sdk": "^0.24.3"
  },
  "devDependencies": {
    "eslint": "^8.57.0",
    "jest": "^29.7.0"
  },
  "keywords": [
    "agentic-flow",
    "mastra",
    "ai-agents",
    "workflow-automation", 
    "multi-agent-coordination"
  ],
  "author": "Agentic Flow Team",
  "license": "MIT"
};

// Environment template
const ENV_TEMPLATE = `# Agentic Flow Mastra Configuration

# Mastra Configuration
MASTRA_PORT=4111
MASTRA_BASE_URL=http://localhost:4111
MASTRA_ENV=development

# AI Provider Configuration
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Network Configuration
CLAUDE_FLOW_PORT=3001
HIVE_MIND_PORT=3002  
RUV_SWARM_PORT=3003
AGENTIC_FLOW_PORT=3000

# Feature Flags
ENABLE_REAL_TIME=true
ENABLE_NOTIFICATIONS=true
ENABLE_MONITORING=true
ENABLE_MCP_INTEGRATION=true

# Debug Configuration
DEBUG_MODE=false
LOG_LEVEL=info
`;

// CLI Functions
async function createDirectory(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    console.log(`✅ Created directory: ${dirPath}`);
  } catch (error) {
    if (error.code !== 'EEXIST') {
      throw error;
    }
  }
}

async function copyFile(sourcePath, targetPath) {
  try {
    const sourceFullPath = path.resolve(__dirname, '../../', sourcePath);
    const content = await fs.readFile(sourceFullPath, 'utf-8');
    await fs.writeFile(targetPath, content);
    console.log(`✅ Created file: ${targetPath}`);
  } catch (error) {
    console.warn(`⚠️  Could not copy ${sourcePath}: ${error.message}`);
  }
}

async function createPackageJson(targetDir) {
  const packageJsonPath = path.join(targetDir, 'package.json');
  await fs.writeFile(packageJsonPath, JSON.stringify(PACKAGE_JSON_TEMPLATE, null, 2));
  console.log(`✅ Created package.json`);
}

async function createEnvFile(targetDir) {
  const envPath = path.join(targetDir, '.env.example');
  await fs.writeFile(envPath, ENV_TEMPLATE);
  console.log(`✅ Created .env.example`);
}

async function createReadme(targetDir, projectName) {
  const readmeContent = `# ${projectName}

Agentic Flow project with Mastra integration - Multi-agent coordination and workflow automation.

## 🚀 Quick Start

\`\`\`bash
# Install dependencies
npm install

# Copy environment template
cp .env.example .env

# Edit .env with your API keys
# ANTHROPIC_API_KEY=your_key_here

# Start development server
npm run dev
\`\`\`

## 🤖 Features

- **Multi-Agent Coordination**: Claude Flow, Hive Mind, and RUV Swarm networks
- **Visual Workflows**: Design and execute complex workflows
- **Real-time Dashboard**: Monitor system health and performance
- **MCP Integration**: Model Context Protocol servers
- **Custom Branding**: Agentic Flow themed interface

## 🛠️ Available Scripts

- \`npm run dev\` - Start development server with hot reload
- \`npm run start\` - Start production server
- \`npm run build\` - Build for production
- \`npm run test\` - Run test suite
- \`npm run lint\` - Run linter

## 🌐 Networks

### Claude Flow (🧠)
Advanced AI reasoning and multi-agent coordination
- Port: 3001
- Capabilities: Complex reasoning, task decomposition, quality assurance

### Hive Mind (🐝) 
Collective intelligence and distributed reasoning
- Port: 3002
- Capabilities: Collective analysis, consensus building, swarm coordination

### RUV Swarm (🔥)
Distributed agent swarms with dynamic scaling
- Port: 3003
- Capabilities: Swarm deployment, dynamic scaling, fault tolerance

## 📊 Dashboard

Access the Mastra dashboard at: http://localhost:4111

- System overview and health monitoring
- Agent directory and status
- Active workflows and execution
- Tools and integrations
- Performance metrics and analytics

## 🔗 API Endpoints

- \`/api/agents\` - Agent management
- \`/api/workflows\` - Workflow execution
- \`/api/tools\` - Tool integration
- \`/api/system\` - System monitoring

## 📖 Documentation

For more information, visit:
- [Agentic Flow Documentation](https://github.com/ruvnet/claude-code-flow)
- [Mastra Documentation](https://mastra.ai/docs)

## 🤝 Support

For issues and support:
- GitHub Issues: [Submit an issue](https://github.com/ruvnet/claude-code-flow/issues)
- Community: [Join discussions](https://github.com/ruvnet/claude-code-flow/discussions)
`;

  const readmePath = path.join(targetDir, 'README.md');
  await fs.writeFile(readmePath, readmeContent);
  console.log(`✅ Created README.md`);
}

// Main initialization function
async function initAgenticFlowMastra(projectName = 'agentic-flow-mastra', targetDir = null) {
  const projectDir = targetDir || path.resolve(process.cwd(), projectName);
  
  console.log(`\n🤖 Initializing Agentic Flow Mastra Project`);
  console.log(`📁 Project Directory: ${projectDir}\n`);

  try {
    // Create project structure
    await createDirectory(projectDir);
    await createDirectory(path.join(projectDir, 'src'));
    await createDirectory(path.join(projectDir, 'src/mastra'));
    await createDirectory(path.join(projectDir, 'src/mastra/agents'));
    await createDirectory(path.join(projectDir, 'src/mastra/workflows'));
    await createDirectory(path.join(projectDir, 'src/mastra/ui'));
    await createDirectory(path.join(projectDir, 'src/cli'));

    // Copy template files
    for (const filePath of TEMPLATE_FILES) {
      const targetPath = path.join(projectDir, filePath);
      await copyFile(filePath, targetPath);
    }

    // Create configuration files
    await createPackageJson(projectDir);
    await createEnvFile(projectDir);
    await createReadme(projectDir, projectName);

    // Success message
    console.log(`\n✨ Agentic Flow Mastra project created successfully!`);
    console.log(`\n📋 Next Steps:`);
    console.log(`   1. cd ${projectName}`);
    console.log(`   2. npm install`);
    console.log(`   3. cp .env.example .env`);
    console.log(`   4. Edit .env with your API keys`);
    console.log(`   5. npm run dev`);
    console.log(`\n🌐 Dashboard: http://localhost:4111`);
    console.log(`🤖 Networks: Claude Flow, Hive Mind, RUV Swarm`);
    console.log(`📊 Features: Multi-agent coordination, workflows, monitoring\n`);

  } catch (error) {
    console.error(`❌ Error initializing project: ${error.message}`);
    process.exit(1);
  }
}

// CLI handling
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const projectName = args[0] || 'agentic-flow-mastra';
  const targetDir = args[1] || null;

  initAgenticFlowMastra(projectName, targetDir);
}

export default initAgenticFlowMastra;