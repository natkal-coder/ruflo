/**
 * Healthcare Clinical Plugin - Bridge Tests
 *
 * Tests for HealthcareHNSWBridge and HealthcareGNNBridge initialization, lifecycle, and methods
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { HealthcareHNSWBridge } from '../src/bridges/hnsw-bridge.js';
import { HealthcareGNNBridge } from '../src/bridges/gnn-bridge.js';

// Mock WASM modules
vi.mock('../src/bridges/hnsw-wasm.js', () => ({
  initWasm: vi.fn().mockResolvedValue(undefined),
  wasmAvailable: vi.fn().mockReturnValue(false),
}));

vi.mock('../src/bridges/gnn-wasm.js', () => ({
  initWasm: vi.fn().mockResolvedValue(undefined),
  wasmAvailable: vi.fn().mockReturnValue(false),
}));

describe('HealthcareHNSWBridge', () => {
  let bridge: HealthcareHNSWBridge;

  beforeEach(() => {
    vi.clearAllMocks();
    bridge = new HealthcareHNSWBridge();
  });

  afterEach(async () => {
    try {
      bridge.destroy();
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Initialization', () => {
    it('should create bridge instance', () => {
      expect(bridge).toBeInstanceOf(HealthcareHNSWBridge);
    });

    it('should initialize successfully', async () => {
      await bridge.initialize();
      expect(bridge.initialized).toBe(true);
    });

    it('should initialize with custom config', async () => {
      await bridge.initialize({
        dimensions: 256,
        maxElements: 50000,
        efConstruction: 200,
        M: 16,
      });
      expect(bridge.initialized).toBe(true);
    });

    it('should handle HIPAA-compliant config', async () => {
      await bridge.initialize({
        dimensions: 128,
      });
      expect(bridge.initialized).toBe(true);
    });

    it('should handle double initialization gracefully', async () => {
      await bridge.initialize();
      await bridge.initialize(); // Should not throw
      expect(bridge.initialized).toBe(true);
    });
  });

  describe('Lifecycle', () => {
    it('should destroy successfully', async () => {
      await bridge.initialize();
      bridge.destroy();
      expect(bridge.initialized).toBe(false);
    });

    it('should handle destroy when not initialized', () => {
      expect(() => bridge.destroy()).not.toThrow();
    });

    it('should reinitialize after destroy', async () => {
      await bridge.initialize();
      bridge.destroy();
      await bridge.initialize();
      expect(bridge.initialized).toBe(true);
    });
  });

  describe('Vector Operations', () => {
    beforeEach(async () => {
      await bridge.initialize({ dimensions: 768 });
    });

    it('should add vector', async () => {
      await bridge.addVector('patient-1', new Float32Array(768).fill(0.5));
      const count = await bridge.count();
      expect(count).toBe(1);
    });

    it('should add patient with features', async () => {
      await bridge.addPatient('P12345', {
        diagnoses: ['E11.9', 'I10'],
        medications: ['metformin', 'lisinopril'],
      });
      const count = await bridge.count();
      expect(count).toBe(1);
    });

    it('should search for similar vectors', async () => {
      // Add some vectors
      await bridge.addVector('p1', new Float32Array(768).fill(0.1));
      await bridge.addVector('p2', new Float32Array(768).fill(0.2));
      await bridge.addVector('p3', new Float32Array(768).fill(0.9));

      const query = new Float32Array(768).fill(0.15);
      const results = await bridge.search(query, 2);

      expect(Array.isArray(results)).toBe(true);
      expect(results.length).toBeLessThanOrEqual(2);
    });

    it('should search by patient features', async () => {
      await bridge.addPatient('P001', {
        diagnoses: ['E11.9'],
        medications: ['metformin'],
      });
      await bridge.addPatient('P002', {
        diagnoses: ['E11.9', 'E66'],
        medications: ['metformin', 'ozempic'],
      });

      const results = await bridge.searchByFeatures({
        diagnoses: ['E11.9'],
      }, 5);

      expect(Array.isArray(results)).toBe(true);
    });

    it('should delete vector', async () => {
      await bridge.addVector('to-delete', new Float32Array(768).fill(0.5));
      const countBefore = await bridge.count();

      await bridge.delete('to-delete');
      const countAfter = await bridge.count();

      expect(countAfter).toBeLessThan(countBefore);
    });

    it('should return count', async () => {
      await bridge.addVector('v1', new Float32Array(768).fill(0.1));
      await bridge.addVector('v2', new Float32Array(768).fill(0.2));

      const count = await bridge.count();
      expect(count).toBeGreaterThanOrEqual(2);
    });
  });

  describe('Error Handling', () => {
    it('should throw when operations called before init', async () => {
      await expect(
        bridge.addVector('test', new Float32Array(768))
      ).rejects.toThrow('HNSW bridge not initialized');
    });
  });

  describe('JavaScript Fallback', () => {
    it('should work without WASM', async () => {
      const fallbackBridge = new HealthcareHNSWBridge({ dimensions: 768 });
      await fallbackBridge.initialize();

      await fallbackBridge.addVector('test', new Float32Array(768).fill(0.5));
      const results = await fallbackBridge.search(new Float32Array(768).fill(0.5), 1);

      expect(results.length).toBeGreaterThan(0);
      fallbackBridge.destroy();
    });
  });
});

describe('HealthcareGNNBridge', () => {
  let bridge: HealthcareGNNBridge;

  beforeEach(() => {
    vi.clearAllMocks();
    bridge = new HealthcareGNNBridge();
  });

  afterEach(() => {
    try {
      bridge.destroy();
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('Initialization', () => {
    it('should create bridge instance', () => {
      expect(bridge).toBeInstanceOf(HealthcareGNNBridge);
    });

    it('should initialize successfully', async () => {
      await bridge.initialize();
      expect(bridge.initialized).toBe(true);
    });

    it('should initialize with custom config', async () => {
      await bridge.initialize({
        hiddenDimensions: 128,
        numLayers: 4,
        aggregationType: 'mean',
      });
      expect(bridge.initialized).toBe(true);
    });

    it('should handle double initialization gracefully', async () => {
      await bridge.initialize();
      await bridge.initialize();
      expect(bridge.initialized).toBe(true);
    });
  });

  describe('Lifecycle', () => {
    it('should destroy successfully', async () => {
      await bridge.initialize();
      bridge.destroy();
      expect(bridge.initialized).toBe(false);
    });

    it('should handle destroy when not initialized', () => {
      expect(() => bridge.destroy()).not.toThrow();
    });
  });

  describe('Graph Operations', () => {
    beforeEach(async () => {
      await bridge.initialize();
    });

    it('should load drug interaction graph', async () => {
      const graph = {
        nodes: [
          { id: 'drug-1', type: 'drug', properties: { name: 'Aspirin' } },
          { id: 'drug-2', type: 'drug', properties: { name: 'Warfarin' } },
        ],
        edges: [
          { source: 'drug-1', target: 'drug-2', type: 'interacts', properties: { severity: 'high' } },
        ],
      };

      const result = await bridge.loadGraph(graph);
      expect(result.success).toBe(true);
      expect(result.nodeCount).toBe(2);
      expect(result.edgeCount).toBe(1);
    });

    it('should analyze drug interactions', async () => {
      await bridge.loadGraph({
        nodes: [
          { id: 'aspirin', type: 'drug', properties: { name: 'Aspirin', class: 'NSAID' } },
          { id: 'warfarin', type: 'drug', properties: { name: 'Warfarin', class: 'anticoagulant' } },
          { id: 'ibuprofen', type: 'drug', properties: { name: 'Ibuprofen', class: 'NSAID' } },
        ],
        edges: [
          { source: 'aspirin', target: 'warfarin', type: 'interacts', properties: { severity: 'major', mechanism: 'bleeding risk' } },
          { source: 'ibuprofen', target: 'warfarin', type: 'interacts', properties: { severity: 'major', mechanism: 'bleeding risk' } },
        ],
      });

      const interactions = await bridge.analyzeInteractions(['aspirin', 'warfarin']);

      expect(interactions).toHaveProperty('interactions');
      expect(interactions.interactions.length).toBeGreaterThan(0);
      expect(interactions.interactions[0]).toHaveProperty('severity');
    });

    it('should check drug interactions', async () => {
      await bridge.loadGraph({
        nodes: [
          { id: 'metformin', type: 'drug', properties: { name: 'Metformin' } },
          { id: 'lisinopril', type: 'drug', properties: { name: 'Lisinopril' } },
        ],
        edges: [
          { source: 'metformin', target: 'lisinopril', type: 'interacts', properties: { severity: 'moderate' } },
        ],
      });

      const result = await bridge.checkDrugInteractions(['metformin', 'lisinopril']);

      expect(result).toHaveProperty('hasInteractions');
      expect(result).toHaveProperty('details');
    });

    it('should predict clinical pathway', async () => {
      await bridge.loadGraph({
        nodes: [
          { id: 'diagnosis', type: 'condition', properties: { name: 'Type 2 Diabetes' } },
          { id: 'step1', type: 'treatment', properties: { name: 'Lifestyle Changes' } },
          { id: 'step2', type: 'treatment', properties: { name: 'Metformin' } },
          { id: 'step3', type: 'treatment', properties: { name: 'Add Insulin' } },
        ],
        edges: [
          { source: 'diagnosis', target: 'step1', type: 'first_line' },
          { source: 'step1', target: 'step2', type: 'if_inadequate' },
          { source: 'step2', target: 'step3', type: 'if_inadequate' },
        ],
      });

      const pathway = await bridge.predictPathway({
        condition: 'Type 2 Diabetes',
        patientFactors: { age: 55, a1c: 8.5 },
      });

      expect(pathway).toHaveProperty('steps');
      expect(Array.isArray(pathway.steps)).toBe(true);
    });

    it('should get clinical pathway', async () => {
      await bridge.loadGraph({
        nodes: [
          { id: 'chest-pain', type: 'symptom' },
          { id: 'ecg', type: 'test' },
          { id: 'troponin', type: 'test' },
        ],
        edges: [
          { source: 'chest-pain', target: 'ecg', type: 'requires' },
          { source: 'chest-pain', target: 'troponin', type: 'requires' },
        ],
      });

      const pathway = await bridge.getClinicalPathway('chest-pain');

      expect(pathway).toHaveProperty('pathway');
      expect(pathway).toHaveProperty('recommendations');
    });
  });

  describe('Error Handling', () => {
    it('should throw when operations called before init', async () => {
      await expect(
        bridge.loadGraph({ nodes: [], edges: [] })
      ).rejects.toThrow();
    });

    it('should handle invalid graph structure', async () => {
      await bridge.initialize();

      await expect(
        bridge.loadGraph({
          nodes: null as any,
          edges: undefined as any,
        })
      ).rejects.toThrow();
    });

    it('should handle empty drug list', async () => {
      await bridge.initialize();

      const result = await bridge.checkDrugInteractions([]);
      expect(result.hasInteractions).toBe(false);
    });
  });

  describe('Clinical Pathway Analysis', () => {
    beforeEach(async () => {
      await bridge.initialize();
      await bridge.loadGraph({
        nodes: [
          { id: 'sepsis', type: 'condition' },
          { id: 'cultures', type: 'test' },
          { id: 'antibiotics', type: 'treatment' },
          { id: 'fluids', type: 'treatment' },
          { id: 'monitoring', type: 'monitoring' },
        ],
        edges: [
          { source: 'sepsis', target: 'cultures', type: 'requires', properties: { timing: 'immediate' } },
          { source: 'sepsis', target: 'antibiotics', type: 'requires', properties: { timing: 'within 1 hour' } },
          { source: 'sepsis', target: 'fluids', type: 'requires', properties: { timing: 'immediate' } },
          { source: 'antibiotics', target: 'monitoring', type: 'followed_by' },
        ],
      });
    });

    it('should compute node embeddings', async () => {
      const embeddings = await bridge.computeNodeEmbeddings();

      expect(embeddings).toBeDefined();
      expect(Object.keys(embeddings).length).toBeGreaterThan(0);
    });

    it('should find similar patterns', async () => {
      const patterns = await bridge.findSimilarPatterns('sepsis');

      expect(Array.isArray(patterns)).toBe(true);
    });
  });

  describe('JavaScript Fallback', () => {
    it('should work without WASM', async () => {
      const fallbackBridge = new HealthcareGNNBridge();
      await fallbackBridge.initialize();

      await fallbackBridge.loadGraph({
        nodes: [{ id: 'test', type: 'drug' }],
        edges: [],
      });

      const result = await fallbackBridge.checkDrugInteractions(['test']);
      expect(result).toBeDefined();

      await fallbackBridge.destroy();
    });
  });

  describe('Memory Management', () => {
    it('should release resources on destroy', async () => {
      await bridge.initialize();

      // Load substantial graph
      const nodes = Array(100).fill(null).map((_, i) => ({
        id: `node-${i}`,
        type: 'drug',
        properties: { name: `Drug ${i}` },
      }));

      const edges = Array(200).fill(null).map((_, i) => ({
        source: `node-${i % 100}`,
        target: `node-${(i + 1) % 100}`,
        type: 'interacts',
      }));

      await bridge.loadGraph({ nodes, edges });
      await bridge.destroy();

      expect(bridge.isInitialized()).toBe(false);
    });

    it('should handle multiple init/destroy cycles', async () => {
      for (let i = 0; i < 3; i++) {
        await bridge.initialize();
        await bridge.loadGraph({
          nodes: [{ id: 'test', type: 'drug' }],
          edges: [],
        });
        await bridge.destroy();
      }
      expect(bridge.isInitialized()).toBe(false);
    });
  });
});
