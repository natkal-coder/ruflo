import { swarmOrchestrationTools } from './9235dd39-94bf-4dac-86f4-555de59cea09.mjs';
import { learningMemoryTools } from './f114edec-324f-48b7-bada-bc4569de1892.mjs';
import { performanceMonitoringTools } from './a845f4b7-2a37-4314-8a76-e62ce702512a.mjs';
import { aiMlTools } from './a7d70a93-614f-4772-9dc1-2129b0b0b4aa.mjs';
import { workflowAutomationTools } from './4d62bb0d-a2e6-4e54-a14a-651a91a732fc.mjs';
import '@mastra/core';
import 'zod';

const allTools = {
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
const toolStatistics = {
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
const toolDocumentation = {
  swarmOrchestration: {
    description: "Tools for managing and orchestrating agent swarms",
    tools: [
      "swarmInit - Initialize new swarms with various topologies",
      "agentSpawn - Spawn specialized agents dynamically",
      "taskOrchestrate - Orchestrate complex tasks across agents",
      "swarmStatus - Monitor comprehensive swarm status",
      "swarmScale - Dynamically scale swarms up or down",
      "swarmDestroy - Gracefully shutdown swarms",
      "topologyOptimize - Optimize swarm topology for performance",
      "loadBalance - Distribute tasks efficiently across agents",
      "coordinationSync - Synchronize agent coordination",
      "agentMetrics - Get detailed agent performance metrics"
    ]
  },
  learningMemory: {
    description: "Tools for persistent memory and learning capabilities",
    tools: [
      "memoryStore - Store persistent memories with TTL",
      "memoryRetrieve - Retrieve memories with pattern matching",
      "memorySearch - Advanced memory search with filters",
      "learningCapture - Capture and store learning experiences",
      "patternRecognize - Recognize patterns in data",
      "knowledgeGraph - Build and query knowledge graphs",
      "memoryBackup - Backup memory stores",
      "memoryRestore - Restore memory from backups",
      "contextSave - Save execution context",
      "contextRestore - Restore execution context"
    ]
  },
  performanceMonitoring: {
    description: "Tools for monitoring and optimizing system performance",
    tools: [
      "performanceReport - Generate detailed performance reports",
      "bottleneckAnalyze - Identify performance bottlenecks",
      "metricsCollect - Collect comprehensive system metrics",
      "trendAnalysis - Analyze performance trends",
      "healthCheck - Monitor system health",
      "errorAnalysis - Analyze error patterns",
      "usageStats - Track usage statistics",
      "costAnalysis - Analyze resource costs",
      "qualityAssess - Assess output quality",
      "benchmarkRun - Run performance benchmarks"
    ]
  },
  aiMl: {
    description: "Tools for AI/ML model training and inference",
    tools: [
      "neuralTrain - Train neural networks with WASM SIMD",
      "neuralPredict - Make predictions with trained models",
      "modelLoad - Load pre-trained models",
      "modelSave - Save trained models",
      "inferenceRun - Run neural inference",
      "ensembleCreate - Create model ensembles",
      "transferLearn - Transfer learning capabilities",
      "neuralExplain - AI explainability",
      "cognitiveAnalyze - Cognitive behavior analysis",
      "adaptiveLearning - Implement adaptive learning"
    ]
  },
  workflowAutomation: {
    description: "Tools for workflow creation and automation",
    tools: [
      "workflowCreate - Create custom workflows",
      "workflowExecute - Execute workflows with parameters",
      "workflowSchedule - Schedule workflow execution",
      "pipelineCreate - Create CI/CD pipelines",
      "automationSetup - Setup automation rules",
      "triggerSetup - Configure event triggers",
      "batchProcess - Process items in batches",
      "parallelExecute - Execute tasks in parallel",
      "workflowTemplate - Manage workflow templates",
      "workflowExport - Export workflow definitions"
    ]
  }
};
const getToolById = (toolId) => allTools[toolId];
const getToolsByCategory = (category) => {
  switch (category) {
    case "swarmOrchestration":
      return swarmOrchestrationTools;
    case "learningMemory":
      return learningMemoryTools;
    case "performanceMonitoring":
      return performanceMonitoringTools;
    case "aiMl":
      return aiMlTools;
    case "workflowAutomation":
      return workflowAutomationTools;
    default:
      return {};
  }
};
const searchTools = (query) => {
  const lowerQuery = query.toLowerCase();
  return Object.entries(allTools).filter(
    ([id, tool]) => id.toLowerCase().includes(lowerQuery) || tool.description.toLowerCase().includes(lowerQuery)
  ).reduce((acc, [id, tool]) => ({ ...acc, [id]: tool }), {});
};
console.log("\u{1F527} Claude Flow & Agentic Flow Tool Collection Loaded");
console.log(`\u{1F4CA} Total Tools: ${toolStatistics.totalTools}`);
console.log("\u{1F4E6} Categories:", Object.entries(toolStatistics.categories).map(([cat, count]) => `${cat}: ${count}`).join(", "));

export { aiMlTools, allTools, allTools as default, getToolById, getToolsByCategory, learningMemoryTools, performanceMonitoringTools, searchTools, swarmOrchestrationTools, toolDocumentation, toolStatistics, workflowAutomationTools };
//# sourceMappingURL=ff46de8d-e2a5-4276-bfad-bfb45bbf9829.mjs.map
