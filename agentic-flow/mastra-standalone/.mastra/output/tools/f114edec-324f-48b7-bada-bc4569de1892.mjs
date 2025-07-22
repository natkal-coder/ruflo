import { createTool } from '@mastra/core';
import { z } from 'zod';

const memoryStore = /* @__PURE__ */ new Map();
const knowledgeGraphStore = /* @__PURE__ */ new Map();
const backupStore = /* @__PURE__ */ new Map();
const contextStore = /* @__PURE__ */ new Map();
const learningStore = /* @__PURE__ */ new Map();
const generateId = () => `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
const isExpired = (expiresAt) => {
  return expiresAt && new Date(expiresAt) < /* @__PURE__ */ new Date();
};
const cleanExpiredMemories = (namespace) => {
  const memories = memoryStore.get(namespace) || /* @__PURE__ */ new Map();
  for (const [key, value] of memories.entries()) {
    if (isExpired(value.expiresAt)) {
      memories.delete(key);
    }
  }
};
const memoryStoreTool = createTool({
  id: "memory-store",
  name: "Memory Store",
  description: "Store persistent memory with TTL and namespacing",
  version: "1.0.0",
  inputSchema: z.object({
    namespace: z.string().default("default"),
    key: z.string(),
    value: z.any(),
    ttl: z.number().optional().describe("Time to live in seconds"),
    tags: z.array(z.string()).optional(),
    metadata: z.record(z.any()).optional()
  }),
  execute: async ({ namespace, key, value, ttl, tags, metadata }) => {
    if (!memoryStore.has(namespace)) {
      memoryStore.set(namespace, /* @__PURE__ */ new Map());
    }
    const memories = memoryStore.get(namespace);
    const expiresAt = ttl ? new Date(Date.now() + ttl * 1e3).toISOString() : null;
    const memory = {
      key,
      value,
      namespace,
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      expiresAt,
      tags: tags || [],
      metadata: metadata || {},
      accessCount: 0,
      lastAccessed: (/* @__PURE__ */ new Date()).toISOString()
    };
    memories.set(key, memory);
    return {
      success: true,
      memory: {
        key,
        namespace,
        expiresAt,
        tags: memory.tags
      }
    };
  }
});
const memoryRetrieveTool = createTool({
  id: "memory-retrieve",
  name: "Memory Retrieve",
  description: "Retrieve memories with pattern matching",
  version: "1.0.0",
  inputSchema: z.object({
    namespace: z.string().default("default"),
    key: z.string().optional(),
    pattern: z.string().optional(),
    includeExpired: z.boolean().default(false)
  }),
  execute: async ({ namespace, key, pattern, includeExpired }) => {
    if (!memoryStore.has(namespace)) {
      return { success: false, error: "Namespace not found" };
    }
    const memories = memoryStore.get(namespace);
    cleanExpiredMemories(namespace);
    if (key) {
      const memory = memories.get(key);
      if (!memory) {
        return { success: false, error: "Memory not found" };
      }
      if (!includeExpired && isExpired(memory.expiresAt)) {
        return { success: false, error: "Memory expired" };
      }
      memory.accessCount++;
      memory.lastAccessed = (/* @__PURE__ */ new Date()).toISOString();
      return { success: true, memory };
    }
    const results = [];
    const regex = pattern ? new RegExp(pattern, "i") : null;
    for (const [k, memory] of memories.entries()) {
      if (!includeExpired && isExpired(memory.expiresAt)) continue;
      if (!regex || regex.test(k) || regex.test(JSON.stringify(memory.value))) {
        memory.accessCount++;
        memory.lastAccessed = (/* @__PURE__ */ new Date()).toISOString();
        results.push(memory);
      }
    }
    return { success: true, memories: results };
  }
});
const memorySearchTool = createTool({
  id: "memory-search",
  name: "Memory Search",
  description: "Advanced memory search with filters",
  version: "1.0.0",
  inputSchema: z.object({
    namespace: z.string().optional(),
    query: z.string(),
    filters: z.object({
      tags: z.array(z.string()).optional(),
      createdAfter: z.string().optional(),
      createdBefore: z.string().optional(),
      minAccessCount: z.number().optional()
    }).optional(),
    limit: z.number().default(10)
  }),
  execute: async ({ namespace, query, filters = {}, limit }) => {
    const results = [];
    const namespaces = namespace ? [namespace] : Array.from(memoryStore.keys());
    const queryRegex = new RegExp(query, "i");
    for (const ns of namespaces) {
      const memories = memoryStore.get(ns) || /* @__PURE__ */ new Map();
      cleanExpiredMemories(ns);
      for (const [key, memory] of memories.entries()) {
        const matchesQuery = queryRegex.test(key) || queryRegex.test(JSON.stringify(memory.value)) || queryRegex.test(JSON.stringify(memory.tags));
        if (!matchesQuery) continue;
        if (filters.tags && filters.tags.length > 0) {
          const hasAllTags = filters.tags.every((tag) => memory.tags.includes(tag));
          if (!hasAllTags) continue;
        }
        if (filters.createdAfter && new Date(memory.createdAt) < new Date(filters.createdAfter)) {
          continue;
        }
        if (filters.createdBefore && new Date(memory.createdAt) > new Date(filters.createdBefore)) {
          continue;
        }
        if (filters.minAccessCount && memory.accessCount < filters.minAccessCount) {
          continue;
        }
        results.push({
          ...memory,
          relevanceScore: calculateRelevance(memory, query)
        });
      }
    }
    results.sort((a, b) => b.relevanceScore - a.relevanceScore);
    return {
      success: true,
      results: results.slice(0, limit),
      totalFound: results.length
    };
  }
});
const learningCaptureTool = createTool({
  id: "learning-capture",
  name: "Learning Capture",
  description: "Capture learning experiences",
  version: "1.0.0",
  inputSchema: z.object({
    type: z.enum(["pattern", "insight", "correction", "optimization", "failure"]),
    context: z.string(),
    input: z.any(),
    output: z.any(),
    outcome: z.enum(["success", "failure", "partial"]),
    confidence: z.number().min(0).max(1),
    tags: z.array(z.string()).optional(),
    relatedMemories: z.array(z.string()).optional()
  }),
  execute: async ({ type, context, input, output, outcome, confidence, tags, relatedMemories }) => {
    const learningId = generateId();
    const learning = {
      id: learningId,
      type,
      context,
      input,
      output,
      outcome,
      confidence,
      tags: tags || [],
      relatedMemories: relatedMemories || [],
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      reinforcements: 0,
      applications: 0
    };
    learningStore.set(learningId, learning);
    await memoryStoreTool.execute({
      namespace: "learning",
      key: `learning_${learningId}`,
      value: learning,
      tags: ["learning", type, outcome, ...tags || []]
    });
    if (relatedMemories && relatedMemories.length > 0) {
      for (const memoryKey of relatedMemories) {
        const memory = await memoryRetrieveTool.execute({
          namespace: "default",
          key: memoryKey
        });
        if (memory.success && memory.memory) {
          memory.memory.metadata.relatedLearnings = memory.memory.metadata.relatedLearnings || [];
          memory.memory.metadata.relatedLearnings.push(learningId);
        }
      }
    }
    return {
      success: true,
      learning: {
        id: learningId,
        type,
        outcome,
        confidence
      }
    };
  }
});
const patternRecognizeTool = createTool({
  id: "pattern-recognize",
  name: "Pattern Recognize",
  description: "Recognize patterns in data",
  version: "1.0.0",
  inputSchema: z.object({
    data: z.array(z.any()),
    patternTypes: z.array(z.enum(["sequence", "frequency", "correlation", "anomaly"])).optional(),
    threshold: z.number().min(0).max(1).default(0.7)
  }),
  execute: async ({ data, patternTypes = ["sequence", "frequency"], threshold }) => {
    const patterns = [];
    if (patternTypes.includes("frequency")) {
      const frequencyMap = /* @__PURE__ */ new Map();
      data.forEach((item) => {
        const key = JSON.stringify(item);
        frequencyMap.set(key, (frequencyMap.get(key) || 0) + 1);
      });
      for (const [item, count] of frequencyMap.entries()) {
        const frequency = count / data.length;
        if (frequency >= threshold) {
          patterns.push({
            type: "frequency",
            pattern: JSON.parse(item),
            confidence: frequency,
            occurrences: count
          });
        }
      }
    }
    if (patternTypes.includes("sequence") && data.length >= 2) {
      const sequences = /* @__PURE__ */ new Map();
      for (let i = 0; i < data.length - 1; i++) {
        for (let length = 2; length <= Math.min(5, data.length - i); length++) {
          const seq = data.slice(i, i + length);
          const key = JSON.stringify(seq);
          sequences.set(key, (sequences.get(key) || 0) + 1);
        }
      }
      for (const [seq, count] of sequences.entries()) {
        if (count >= 2) {
          const confidence = count / (data.length - JSON.parse(seq).length + 1);
          if (confidence >= threshold) {
            patterns.push({
              type: "sequence",
              pattern: JSON.parse(seq),
              confidence,
              occurrences: count
            });
          }
        }
      }
    }
    if (patternTypes.includes("anomaly")) {
      const frequencies = /* @__PURE__ */ new Map();
      data.forEach((item) => {
        const key = JSON.stringify(item);
        frequencies.set(key, (frequencies.get(key) || 0) + 1);
      });
      const avgFrequency = data.length / frequencies.size;
      for (const [item, count] of frequencies.entries()) {
        const deviation = Math.abs(count - avgFrequency) / avgFrequency;
        if (deviation > 1 - threshold) {
          patterns.push({
            type: "anomaly",
            pattern: JSON.parse(item),
            confidence: deviation,
            occurrences: count,
            expectedOccurrences: avgFrequency
          });
        }
      }
    }
    for (const pattern of patterns) {
      await learningCaptureTool.execute({
        type: "pattern",
        context: "pattern_recognition",
        input: data,
        output: pattern,
        outcome: "success",
        confidence: pattern.confidence,
        tags: ["pattern", pattern.type]
      });
    }
    return {
      success: true,
      patterns: patterns.sort((a, b) => b.confidence - a.confidence),
      totalPatternsFound: patterns.length
    };
  }
});
const knowledgeGraphTool = createTool({
  id: "knowledge-graph",
  name: "Knowledge Graph",
  description: "Build and query knowledge graphs",
  version: "1.0.0",
  inputSchema: z.object({
    action: z.enum(["add_node", "add_edge", "query", "traverse", "delete_node"]),
    nodeId: z.string().optional(),
    nodeData: z.any().optional(),
    sourceId: z.string().optional(),
    targetId: z.string().optional(),
    edgeType: z.string().optional(),
    edgeData: z.any().optional(),
    query: z.object({
      type: z.enum(["node", "edge", "path", "neighbors"]).optional(),
      filters: z.record(z.any()).optional(),
      depth: z.number().optional()
    }).optional()
  }),
  execute: async ({ action, nodeId, nodeData, sourceId, targetId, edgeType, edgeData, query }) => {
    if (!knowledgeGraphStore.has("nodes")) {
      knowledgeGraphStore.set("nodes", /* @__PURE__ */ new Map());
      knowledgeGraphStore.set("edges", /* @__PURE__ */ new Map());
    }
    const nodes = knowledgeGraphStore.get("nodes");
    const edges = knowledgeGraphStore.get("edges");
    switch (action) {
      case "add_node": {
        if (!nodeId) return { success: false, error: "Node ID required" };
        const node = {
          id: nodeId,
          data: nodeData || {},
          createdAt: (/* @__PURE__ */ new Date()).toISOString(),
          edges: { incoming: [], outgoing: [] }
        };
        nodes.set(nodeId, node);
        return { success: true, node };
      }
      case "add_edge": {
        if (!sourceId || !targetId || !edgeType) {
          return { success: false, error: "Source ID, target ID, and edge type required" };
        }
        const edgeId = `${sourceId}-${edgeType}-${targetId}`;
        const edge = {
          id: edgeId,
          source: sourceId,
          target: targetId,
          type: edgeType,
          data: edgeData || {},
          createdAt: (/* @__PURE__ */ new Date()).toISOString()
        };
        edges.set(edgeId, edge);
        const sourceNode = nodes.get(sourceId);
        const targetNode = nodes.get(targetId);
        if (sourceNode) {
          sourceNode.edges.outgoing.push(edgeId);
        }
        if (targetNode) {
          targetNode.edges.incoming.push(edgeId);
        }
        return { success: true, edge };
      }
      case "query": {
        if (!query) return { success: false, error: "Query parameters required" };
        const results = [];
        if (query.type === "node" || !query.type) {
          for (const [id, node] of nodes.entries()) {
            if (matchesFilters(node.data, query.filters)) {
              results.push({ type: "node", ...node });
            }
          }
        }
        if (query.type === "edge" || !query.type) {
          for (const [id, edge] of edges.entries()) {
            if (matchesFilters(edge.data, query.filters)) {
              results.push({ type: "edge", ...edge });
            }
          }
        }
        if (query.type === "neighbors" && nodeId) {
          const node = nodes.get(nodeId);
          if (node) {
            const neighbors = /* @__PURE__ */ new Set();
            node.edges.outgoing.forEach((edgeId) => {
              const edge = edges.get(edgeId);
              if (edge) neighbors.add(edge.target);
            });
            node.edges.incoming.forEach((edgeId) => {
              const edge = edges.get(edgeId);
              if (edge) neighbors.add(edge.source);
            });
            neighbors.forEach((neighborId) => {
              const neighborNode = nodes.get(neighborId);
              if (neighborNode) {
                results.push({ type: "node", ...neighborNode });
              }
            });
          }
        }
        return { success: true, results };
      }
      case "traverse": {
        let traverse = function(currentId, depth) {
          if (depth > maxDepth || visited.has(currentId)) return;
          visited.add(currentId);
          const node = nodes.get(currentId);
          if (!node) return;
          path.push({ type: "node", ...node });
          node.edges.outgoing.forEach((edgeId) => {
            const edge = edges.get(edgeId);
            if (edge && (!query.filters || matchesFilters(edge.data, query.filters))) {
              path.push({ type: "edge", ...edge });
              traverse(edge.target, depth + 1);
            }
          });
        };
        if (!nodeId || !query) return { success: false, error: "Node ID and query required" };
        const visited = /* @__PURE__ */ new Set();
        const path = [];
        const maxDepth = query.depth || 3;
        traverse(nodeId, 0);
        return { success: true, path };
      }
      case "delete_node": {
        if (!nodeId) return { success: false, error: "Node ID required" };
        const node = nodes.get(nodeId);
        if (!node) return { success: false, error: "Node not found" };
        [...node.edges.incoming, ...node.edges.outgoing].forEach((edgeId) => {
          edges.delete(edgeId);
        });
        nodes.delete(nodeId);
        return { success: true, deleted: nodeId };
      }
      default:
        return { success: false, error: "Invalid action" };
    }
  }
});
const memoryBackupTool = createTool({
  id: "memory-backup",
  name: "Memory Backup",
  description: "Backup memory stores",
  version: "1.0.0",
  inputSchema: z.object({
    namespaces: z.array(z.string()).optional(),
    includeKnowledgeGraph: z.boolean().default(true),
    includeLearning: z.boolean().default(true),
    backupId: z.string().optional()
  }),
  execute: async ({ namespaces, includeKnowledgeGraph, includeLearning, backupId }) => {
    const backup = {
      id: backupId || generateId(),
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      memories: {},
      knowledgeGraph: null,
      learning: null,
      metadata: {
        totalMemories: 0,
        totalNodes: 0,
        totalEdges: 0,
        totalLearnings: 0
      }
    };
    const namespacesToBackup = namespaces || Array.from(memoryStore.keys());
    for (const namespace of namespacesToBackup) {
      const memories = memoryStore.get(namespace);
      if (memories) {
        backup.memories[namespace] = Array.from(memories.entries());
        backup.metadata.totalMemories += memories.size;
      }
    }
    if (includeKnowledgeGraph && knowledgeGraphStore.has("nodes")) {
      backup.knowledgeGraph = {
        nodes: Array.from(knowledgeGraphStore.get("nodes").entries()),
        edges: Array.from(knowledgeGraphStore.get("edges").entries())
      };
      backup.metadata.totalNodes = backup.knowledgeGraph.nodes.length;
      backup.metadata.totalEdges = backup.knowledgeGraph.edges.length;
    }
    if (includeLearning) {
      backup.learning = Array.from(learningStore.entries());
      backup.metadata.totalLearnings = backup.learning.length;
    }
    backupStore.set(backup.id, backup);
    return {
      success: true,
      backup: {
        id: backup.id,
        timestamp: backup.timestamp,
        metadata: backup.metadata
      }
    };
  }
});
const memoryRestoreTool = createTool({
  id: "memory-restore",
  name: "Memory Restore",
  description: "Restore from backups",
  version: "1.0.0",
  inputSchema: z.object({
    backupId: z.string(),
    namespaces: z.array(z.string()).optional(),
    restoreKnowledgeGraph: z.boolean().default(true),
    restoreLearning: z.boolean().default(true),
    merge: z.boolean().default(false)
  }),
  execute: async ({ backupId, namespaces, restoreKnowledgeGraph, restoreLearning, merge }) => {
    const backup = backupStore.get(backupId);
    if (!backup) {
      return { success: false, error: "Backup not found" };
    }
    const restored = {
      memories: 0,
      nodes: 0,
      edges: 0,
      learnings: 0
    };
    const namespacesToRestore = namespaces || Object.keys(backup.memories);
    for (const namespace of namespacesToRestore) {
      if (backup.memories[namespace]) {
        if (!merge) {
          memoryStore.set(namespace, /* @__PURE__ */ new Map());
        }
        const memories = memoryStore.get(namespace) || /* @__PURE__ */ new Map();
        for (const [key, value] of backup.memories[namespace]) {
          memories.set(key, value);
          restored.memories++;
        }
        memoryStore.set(namespace, memories);
      }
    }
    if (restoreKnowledgeGraph && backup.knowledgeGraph) {
      if (!merge) {
        knowledgeGraphStore.set("nodes", /* @__PURE__ */ new Map());
        knowledgeGraphStore.set("edges", /* @__PURE__ */ new Map());
      }
      const nodes = knowledgeGraphStore.get("nodes") || /* @__PURE__ */ new Map();
      const edges = knowledgeGraphStore.get("edges") || /* @__PURE__ */ new Map();
      for (const [id, node] of backup.knowledgeGraph.nodes) {
        nodes.set(id, node);
        restored.nodes++;
      }
      for (const [id, edge] of backup.knowledgeGraph.edges) {
        edges.set(id, edge);
        restored.edges++;
      }
      knowledgeGraphStore.set("nodes", nodes);
      knowledgeGraphStore.set("edges", edges);
    }
    if (restoreLearning && backup.learning) {
      if (!merge) {
        learningStore.clear();
      }
      for (const [id, learning] of backup.learning) {
        learningStore.set(id, learning);
        restored.learnings++;
      }
    }
    return {
      success: true,
      restored,
      backup: {
        id: backup.id,
        timestamp: backup.timestamp
      }
    };
  }
});
const contextSaveTool = createTool({
  id: "context-save",
  name: "Context Save",
  description: "Save execution context",
  version: "1.0.0",
  inputSchema: z.object({
    contextId: z.string().optional(),
    state: z.any(),
    activeMemories: z.array(z.string()).optional(),
    activePatterns: z.array(z.string()).optional(),
    metadata: z.record(z.any()).optional()
  }),
  execute: async ({ contextId, state, activeMemories, activePatterns, metadata }) => {
    const id = contextId || generateId();
    const context = {
      id,
      state,
      activeMemories: activeMemories || [],
      activePatterns: activePatterns || [],
      metadata: metadata || {},
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      checkpoints: []
    };
    if (activeMemories && activeMemories.length > 0) {
      context.memorySnapshots = {};
      for (const memoryKey of activeMemories) {
        const parts = memoryKey.split(":");
        const namespace = parts.length > 1 ? parts[0] : "default";
        const key = parts.length > 1 ? parts[1] : memoryKey;
        const result = await memoryRetrieveTool.execute({ namespace, key });
        if (result.success && result.memory) {
          context.memorySnapshots[memoryKey] = result.memory;
        }
      }
    }
    contextStore.set(id, context);
    await memoryStoreTool.execute({
      namespace: "contexts",
      key: `context_${id}`,
      value: context,
      tags: ["context", "snapshot"]
    });
    return {
      success: true,
      context: {
        id,
        timestamp: context.timestamp,
        activeMemories: context.activeMemories.length,
        stateSize: JSON.stringify(state).length
      }
    };
  }
});
const contextRestoreTool = createTool({
  id: "context-restore",
  name: "Context Restore",
  description: "Restore execution context",
  version: "1.0.0",
  inputSchema: z.object({
    contextId: z.string(),
    restoreMemories: z.boolean().default(true),
    checkpoint: z.number().optional()
  }),
  execute: async ({ contextId, restoreMemories, checkpoint }) => {
    let context = contextStore.get(contextId);
    if (!context) {
      const result = await memoryRetrieveTool.execute({
        namespace: "contexts",
        key: `context_${contextId}`
      });
      if (result.success && result.memory) {
        context = result.memory.value;
        contextStore.set(contextId, context);
      }
    }
    if (!context) {
      return { success: false, error: "Context not found" };
    }
    let targetState = context.state;
    if (checkpoint !== void 0 && context.checkpoints[checkpoint]) {
      targetState = context.checkpoints[checkpoint].state;
    }
    const restored = {
      state: targetState,
      activeMemories: context.activeMemories,
      activePatterns: context.activePatterns,
      metadata: context.metadata,
      timestamp: context.timestamp
    };
    if (restoreMemories && context.memorySnapshots) {
      restored.memories = {};
      for (const [key, snapshot] of Object.entries(context.memorySnapshots)) {
        restored.memories[key] = snapshot;
      }
    }
    return {
      success: true,
      context: restored,
      checkpointsAvailable: context.checkpoints.length
    };
  }
});
function calculateRelevance(memory, query) {
  let score = 0;
  const queryLower = query.toLowerCase();
  if (memory.key.toLowerCase().includes(queryLower)) {
    score += 5;
  }
  const valueStr = JSON.stringify(memory.value).toLowerCase();
  if (valueStr.includes(queryLower)) {
    score += 3;
  }
  memory.tags.forEach((tag) => {
    if (tag.toLowerCase().includes(queryLower)) {
      score += 2;
    }
  });
  const hoursSinceAccess = (Date.now() - new Date(memory.lastAccessed).getTime()) / (1e3 * 60 * 60);
  if (hoursSinceAccess < 24) {
    score += 2;
  } else if (hoursSinceAccess < 168) {
    score += 1;
  }
  if (memory.accessCount > 10) {
    score += 1;
  }
  return score;
}
function matchesFilters(data, filters) {
  if (!filters) return true;
  for (const [key, value] of Object.entries(filters)) {
    if (data[key] !== value) {
      return false;
    }
  }
  return true;
}
const learningMemoryTools = {
  memoryStoreTool,
  memoryRetrieveTool,
  memorySearchTool,
  learningCaptureTool,
  patternRecognizeTool,
  knowledgeGraphTool,
  memoryBackupTool,
  memoryRestoreTool,
  contextSaveTool,
  contextRestoreTool
};

export { contextRestoreTool, contextSaveTool, knowledgeGraphTool, learningCaptureTool, learningMemoryTools, memoryBackupTool, memoryRestoreTool, memoryRetrieveTool, memorySearchTool, memoryStoreTool, patternRecognizeTool };
//# sourceMappingURL=f114edec-324f-48b7-bada-bc4569de1892.mjs.map
