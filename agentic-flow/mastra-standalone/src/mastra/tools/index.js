// Comprehensive Tool Collection for Claude Flow and Agentic Flow
// Export all tool categories for easy integration

// Import all tool collections
import { swarmOrchestrationTools } from './swarm-orchestration-tools.js';
import { learningMemoryTools } from './learning-memory-tools.js';
import { performanceMonitoringTools } from './performance-monitoring-tools.js';
import { aiMlTools } from './ai-ml-tools.js';
import { workflowAutomationTools } from './workflow-automation-tools.js';

// Combine all tools into a single collection
export const allTools = {
  // Swarm Orchestration Tools (10 tools)
  ...swarmOrchestrationTools,
  
  // Learning & Memory Tools (10 tools)
  ...learningMemoryTools,
  
  // Performance Monitoring Tools (10 tools)
  ...performanceMonitoringTools,
  
  // AI/ML Integration Tools (10 tools)
  ...aiMlTools,
  
  // Workflow Automation Tools (10 tools)
  ...workflowAutomationTools
};

// Export tool categories
export {
  swarmOrchestrationTools,
  learningMemoryTools,
  performanceMonitoringTools,
  aiMlTools,
  workflowAutomationTools
};

// Tool statistics
export const toolStatistics = {
  totalTools: Object.keys(allTools).length,
  categories: {
    swarmOrchestration: Object.keys(swarmOrchestrationTools).length,
    learningMemory: Object.keys(learningMemoryTools).length,
    performanceMonitoring: Object.keys(performanceMonitoringTools).length,
    aiMl: Object.keys(aiMlTools).length,
    workflowAutomation: Object.keys(workflowAutomationTools).length
  },
  toolList: Object.keys(allTools).sort()
};

// Tool documentation
export const toolDocumentation = {
  swarmOrchestration: {
    description: 'Tools for managing and orchestrating agent swarms',
    tools: [
      'swarmInit - Initialize new swarms with various topologies',
      'agentSpawn - Spawn specialized agents dynamically',
      'taskOrchestrate - Orchestrate complex tasks across agents',
      'swarmStatus - Monitor comprehensive swarm status',
      'swarmScale - Dynamically scale swarms up or down',
      'swarmDestroy - Gracefully shutdown swarms',
      'topologyOptimize - Optimize swarm topology for performance',
      'loadBalance - Distribute tasks efficiently across agents',
      'coordinationSync - Synchronize agent coordination',
      'agentMetrics - Get detailed agent performance metrics'
    ]
  },
  learningMemory: {
    description: 'Tools for persistent memory and learning capabilities',
    tools: [
      'memoryStore - Store persistent memories with TTL',
      'memoryRetrieve - Retrieve memories with pattern matching',
      'memorySearch - Advanced memory search with filters',
      'learningCapture - Capture and store learning experiences',
      'patternRecognize - Recognize patterns in data',
      'knowledgeGraph - Build and query knowledge graphs',
      'memoryBackup - Backup memory stores',
      'memoryRestore - Restore memory from backups',
      'contextSave - Save execution context',
      'contextRestore - Restore execution context'
    ]
  },
  performanceMonitoring: {
    description: 'Tools for monitoring and optimizing system performance',
    tools: [
      'performanceReport - Generate detailed performance reports',
      'bottleneckAnalyze - Identify performance bottlenecks',
      'metricsCollect - Collect comprehensive system metrics',
      'trendAnalysis - Analyze performance trends',
      'healthCheck - Monitor system health',
      'errorAnalysis - Analyze error patterns',
      'usageStats - Track usage statistics',
      'costAnalysis - Analyze resource costs',
      'qualityAssess - Assess output quality',
      'benchmarkRun - Run performance benchmarks'
    ]
  },
  aiMl: {
    description: 'Tools for AI/ML model training and inference',
    tools: [
      'neuralTrain - Train neural networks with WASM SIMD',
      'neuralPredict - Make predictions with trained models',
      'modelLoad - Load pre-trained models',
      'modelSave - Save trained models',
      'inferenceRun - Run neural inference',
      'ensembleCreate - Create model ensembles',
      'transferLearn - Transfer learning capabilities',
      'neuralExplain - AI explainability',
      'cognitiveAnalyze - Cognitive behavior analysis',
      'adaptiveLearning - Implement adaptive learning'
    ]
  },
  workflowAutomation: {
    description: 'Tools for workflow creation and automation',
    tools: [
      'workflowCreate - Create custom workflows',
      'workflowExecute - Execute workflows with parameters',
      'workflowSchedule - Schedule workflow execution',
      'pipelineCreate - Create CI/CD pipelines',
      'automationSetup - Setup automation rules',
      'triggerSetup - Configure event triggers',
      'batchProcess - Process items in batches',
      'parallelExecute - Execute tasks in parallel',
      'workflowTemplate - Manage workflow templates',
      'workflowExport - Export workflow definitions'
    ]
  }
};

// Helper function to get tool by ID
export const getToolById = (toolId) => allTools[toolId];

// Helper function to get tools by category
export const getToolsByCategory = (category) => {
  switch (category) {
    case 'swarmOrchestration':
      return swarmOrchestrationTools;
    case 'learningMemory':
      return learningMemoryTools;
    case 'performanceMonitoring':
      return performanceMonitoringTools;
    case 'aiMl':
      return aiMlTools;
    case 'workflowAutomation':
      return workflowAutomationTools;
    default:
      return {};
  }
};

// Helper function to search tools
export const searchTools = (query) => {
  const lowerQuery = query.toLowerCase();
  return Object.entries(allTools)
    .filter(([id, tool]) => 
      id.toLowerCase().includes(lowerQuery) ||
      tool.description.toLowerCase().includes(lowerQuery)
    )
    .reduce((acc, [id, tool]) => ({ ...acc, [id]: tool }), {});
};

console.log('🔧 Claude Flow & Agentic Flow Tool Collection Loaded');
console.log(`📊 Total Tools: ${toolStatistics.totalTools}`);
console.log('📦 Categories:', Object.entries(toolStatistics.categories).map(([cat, count]) => `${cat}: ${count}`).join(', '));

export default allTools;