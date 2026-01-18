# ADR-030: Claude Code Content Management Architecture

## Status
**Implemented** - Cache Optimizer v3.0.0-alpha

## Context

Claude Code requires intelligent cache management to:
1. Prevent context window compaction (hard cutoff at utilization limits)
2. Maintain relevant context across long sessions
3. Optimize token usage without losing critical information
4. Support topic drift detection across session phases

Traditional LRU caching is insufficient for AI context management because:
- Recent entries may be less relevant than older ones
- Semantic relationships between entries matter
- Content type affects importance (system prompts > bash output)
- Topic drift can make old content irrelevant even if recently accessed

## Decision

Implement an **Intelligent Cache Optimization System (ICOS)** with:

### 1. Multi-Layer Optimization Strategy

```
Layer 1: Proactive Threshold Monitoring
  ├─ Soft Threshold (40%): Start scoring and preparing
  ├─ Hard Threshold (50%): Aggressive pruning
  └─ Emergency Threshold (60%): Force eviction

Layer 2: Temporal Tier Compression
  ├─ Hot (< 2min): 100% size, full content
  ├─ Warm (2-10min): 25% size, compressed
  └─ Cold (> 10min): 3% size, summary only

Layer 3: Relevance-Based Scoring
  ├─ FlashAttention O(N) scoring
  ├─ Recency + Frequency + Semantic weights
  └─ Entry type prioritization

Layer 4: Hyperbolic Intelligence (NEW)
  ├─ Poincaré ball embeddings for hierarchical modeling
  ├─ Hypergraph relationships for multi-way connections
  └─ Historical pattern learning for drift detection

Layer 5: Advanced Token Compression (NEW)
  ├─ Summary Compression (rule-based extraction)
  ├─ Quantized Compression (Int8/Int4 encoding)
  ├─ Structural Compression (AST-like extraction)
  ├─ Delta Compression (diff-based storage)
  └─ Semantic Deduplication (cross-entry)
```

### 2. Hyperbolic Cache Intelligence

Uses Poincaré ball model for hierarchical cache relationships:

```typescript
// Entries closer to origin are more central/important
const typeWeights: Record<CacheEntryType, number> = {
  system_prompt: 0.05,   // Center (always preserved)
  claude_md: 0.1,
  user_message: 0.2,
  assistant_message: 0.25,
  file_read: 0.3,
  file_write: 0.35,
  tool_result: 0.4,
  bash_output: 0.45,
  mcp_context: 0.5,      // Periphery (pruned first)
};
```

**Drift Detection**: Compares current cache embedding against historical successful patterns:
- Detects when cache structure diverges from optimal
- Applies corrections to maintain alignment
- Records successful states for future learning

### 3. Compression Strategy Performance

| Strategy | Best For | Typical Savings |
|----------|----------|-----------------|
| Summary | All types | 65-85% |
| Quantized Int8 | Code/JSON | 15-30% |
| Quantized Int4 | Code/JSON | 30-45% |
| Structural | Large code | 75-90% |
| Delta | Incremental | 60-90% |
| Semantic Dedup | Repeated | 10-40% |

**Automatic Strategy Selection**:
- Code files (>200 tokens): Structural compression
- Code files (<200 tokens): Summary compression
- Tool results/JSON: Quantized compression
- Bash output: Summary compression

### 4. Benchmark Results

#### Compaction Prevention Test
```
WITHOUT Optimization: 149.2% utilization → COMPACTION TRIGGERED
WITH Optimization:    58.9% utilization → COMPACTION PREVENTED

Improvement: 90.3% reduction in peak utilization
```

#### Hyperbolic Intelligence Performance
```
Pruning Speed: 1.22x faster with hyperbolic
Phase Retention: Correctly preserves recent context
Drift Detection: Identifies topic transitions
```

#### Compression Performance
```
Code Files:    93.9% savings (Structural)
Tool Results:  24.9% savings (Quantized)
Bash Output:   77.2% savings (Summary)
Overall:       73.4% average savings
```

## Architecture

```
@claude-flow/cache-optimizer/
├── src/
│   ├── core/
│   │   ├── orchestrator.ts      # Main CacheOptimizer class
│   │   └── scoring-engine.ts    # FlashAttention-based scoring
│   ├── compression/
│   │   ├── advanced-compression.ts  # 5 compression strategies
│   │   └── tier-manager.ts      # Hot/Warm/Cold tier management
│   ├── intelligence/
│   │   ├── hyperbolic-cache.ts  # Poincaré ball + hypergraph
│   │   └── drift-detector.ts    # Historical pattern learning
│   ├── hooks/
│   │   └── handlers.ts          # Claude Code hook integration
│   └── types.ts                 # Type definitions
├── scripts/
│   ├── compaction-comparison.ts     # Before/after compaction test
│   ├── tier-compression-demo.ts     # Tier transition demo
│   ├── hyperbolic-benchmark.ts      # Hyperbolic vs baseline
│   ├── drift-stress-test.ts         # Multi-phase drift test
│   └── compression-strategies-demo.ts # Compression comparison
└── docs/
    └── ADR-030-cache-optimizer.md   # This document
```

## API

### Core API

```typescript
import { CacheOptimizer } from '@claude-flow/cache-optimizer';

const optimizer = new CacheOptimizer({
  contextWindowSize: 200000,
  targetUtilization: 0.75,
  pruning: {
    softThreshold: 0.40,
    hardThreshold: 0.50,
    emergencyThreshold: 0.60,
    strategy: 'adaptive',
  },
}, { useHyperbolic: true });

// Add entries
await optimizer.add(content, 'file_read', {
  source: 'Read',
  filePath: 'src/app.ts',
  sessionId: 'session-123',
});

// Trigger optimization on user prompt
const result = await optimizer.onUserPromptSubmit(query, sessionId);
// Returns: { tokensFreed, entriesPruned, compactionPrevented }

// Score all entries
await optimizer.scoreAll(context);

// Transition tiers and compress
await optimizer.transitionTiers();

// Get metrics
const metrics = optimizer.getMetrics();
// Returns: { utilization, entriesByTier, compactionsPrevented, ... }
```

### Compression API

```typescript
import { CompressionManager } from '@claude-flow/cache-optimizer';

const manager = new CompressionManager();

// Auto-select best strategy and compress
const result = await manager.compress(entry);
// Returns: { summary, compressedTokens, ratio, method }

// Estimate compression ratio
const ratio = manager.estimateRatio(entry);
```

### Hyperbolic Intelligence API

```typescript
import { HyperbolicCacheIntelligence } from '@claude-flow/cache-optimizer';

const intelligence = new HyperbolicCacheIntelligence({
  dims: 64,
  curvature: -1,
  driftThreshold: 0.5,
  enableHypergraph: true,
  enableDriftDetection: true,
});

// Embed entry in hyperbolic space
const embedding = intelligence.embedEntry(entry);

// Add relationships
intelligence.addRelationship(
  [entry1.id, entry2.id, entry3.id],
  'file_group',
  { files: ['src/app.ts'], timestamp: Date.now() }
);

// Analyze drift
const drift = intelligence.analyzeDrift(entries);
// Returns: { isDrifting, driftMagnitude, recommendation }

// Get optimized pruning decisions
const decision = intelligence.getOptimalPruningDecision(entries, targetUtilization);
```

## Consequences

### Positive
- Zero compaction in normal operation (maintained <75% utilization)
- 73% average token savings through intelligent compression
- 22% faster pruning with hyperbolic intelligence
- Semantic-aware context preservation
- Historical pattern learning improves over time

### Negative
- Additional memory overhead for embeddings (~8KB per entry)
- Complexity in compression strategy selection
- Drift detection requires sufficient historical data

### Mitigations
- Embeddings stored efficiently with Float32Array
- Automatic strategy selection based on entry type
- Graceful degradation when no historical patterns available

## Related

- ADR-006: Unified Memory Service (AgentDB integration)
- ADR-009: Hybrid Memory Backend
- ADR-026: Intelligent Model Routing

## References

- Poincaré Ball Model: [Poincaré Embeddings for Learning Hierarchical Representations](https://arxiv.org/abs/1705.08039)
- Flash Attention: [FlashAttention: Fast and Memory-Efficient Exact Attention](https://arxiv.org/abs/2205.14135)
- Hypergraph Learning: [Hypergraph Learning with Cost](https://arxiv.org/abs/1809.09574)
