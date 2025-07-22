// Test script to verify tools are loaded correctly
import { mastra } from './src/mastra/index.js';

console.log('\n🔍 Testing Agentic Flow Mastra Integration\n');

// List all agents
console.log('📋 Loaded Agents:');
const agents = mastra.getAgents();
Object.entries(agents).forEach(([key, agent]) => {
  console.log(`   • ${key}: ${agent.description || agent.name}`);
});

// Check Mastra structure
console.log('\n🔍 Mastra Instance Structure:');
console.log('   Keys:', Object.keys(mastra));
console.log('   Has tools?', 'tools' in mastra);
console.log('   Constructor:', mastra.constructor.name);

// Try to find tools
let tools = {};
if (mastra.tools) {
  tools = mastra.tools;
  console.log('\n🛠️  Found tools on mastra.tools');
} else if (mastra._config && mastra._config.tools) {
  tools = mastra._config.tools;
  console.log('\n🛠️  Found tools on mastra._config.tools');
} else {
  // Tools might be in the constructor parameters
  console.log('\n⚠️  Tools not found in expected locations');
  console.log('   Checking mastra internals...');
  for (const key of Object.keys(mastra)) {
    if (key.includes('tool') || key.includes('Tool')) {
      console.log(`   Found tool-related key: ${key}`);
    }
  }
}

// List all tools if found
if (Object.keys(tools).length > 0) {
  console.log('\n🛠️  Loaded Tools:');
  Object.entries(tools).forEach(([key, tool]) => {
    console.log(`   • ${key}: ${tool.description || tool.name || key}`);
  });
} else {
  console.log('\n❌ No tools found in Mastra instance');
}

// Try workflows
let workflows = {};
if (mastra.workflows) {
  workflows = mastra.workflows;
} else if (mastra._config && mastra._config.workflows) {
  workflows = mastra._config.workflows;
}

if (Object.keys(workflows).length > 0) {
  console.log('\n🔄 Loaded Workflows:');
  Object.entries(workflows).forEach(([key, workflow]) => {
    console.log(`   • ${key}: ${workflow.description || workflow.name || key}`);
  });
}

console.log('\n✨ Integration test complete!\n');
process.exit(0);