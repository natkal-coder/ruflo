// Visual workflow designer backend for node/edge management

import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import {
  WorkflowDefinition,
  WorkflowNode,
  WorkflowEdge,
  NodeType,
  WorkflowPort,
  DataType
} from '../types';
import { WorkflowValidator } from '../validation/workflow-validator';

export interface DesignerState {
  workflow: WorkflowDefinition;
  selectedNodeId?: string;
  selectedEdgeId?: string;
  clipboard?: {
    nodes: WorkflowNode[];
    edges: WorkflowEdge[];
  };
  history: WorkflowDefinition[];
  historyIndex: number;
  isDirty: boolean;
}

export interface NodeTemplate {
  type: NodeType;
  label: string;
  defaultData?: Record<string, any>;
  defaultInputs?: WorkflowPort[];
  defaultOutputs?: WorkflowPort[];
  icon?: string;
  category?: string;
}

export class WorkflowDesignerBackend extends EventEmitter {
  private state: DesignerState;
  private validator: WorkflowValidator;
  private nodeTemplates: Map<NodeType, NodeTemplate>;
  private maxHistorySize = 50;

  constructor(workflow?: WorkflowDefinition) {
    super();
    this.validator = new WorkflowValidator();
    this.nodeTemplates = this.initializeNodeTemplates();
    
    this.state = {
      workflow: workflow || this.createEmptyWorkflow(),
      history: [],
      historyIndex: -1,
      isDirty: false
    };

    this.saveToHistory();
  }

  // Node management
  addNode(type: NodeType, position: { x: number; y: number }): WorkflowNode {
    const template = this.nodeTemplates.get(type);
    if (!template) {
      throw new Error(`Unknown node type: ${type}`);
    }

    const node: WorkflowNode = {
      id: `node-${uuidv4()}`,
      type,
      label: template.label,
      position,
      data: { ...template.defaultData },
      inputs: template.defaultInputs ? [...template.defaultInputs] : undefined,
      outputs: template.defaultOutputs ? [...template.defaultOutputs] : undefined
    };

    this.state.workflow.nodes.push(node);
    this.saveToHistory();
    this.emit('node:added', node);
    
    return node;
  }

  updateNode(nodeId: string, updates: Partial<WorkflowNode>): void {
    const nodeIndex = this.state.workflow.nodes.findIndex(n => n.id === nodeId);
    if (nodeIndex === -1) {
      throw new Error(`Node ${nodeId} not found`);
    }

    const node = this.state.workflow.nodes[nodeIndex];
    Object.assign(node, updates);
    
    this.saveToHistory();
    this.emit('node:updated', node);
  }

  deleteNode(nodeId: string): void {
    // Remove node
    const nodeIndex = this.state.workflow.nodes.findIndex(n => n.id === nodeId);
    if (nodeIndex === -1) {
      throw new Error(`Node ${nodeId} not found`);
    }

    this.state.workflow.nodes.splice(nodeIndex, 1);

    // Remove connected edges
    this.state.workflow.edges = this.state.workflow.edges.filter(
      edge => edge.source !== nodeId && edge.target !== nodeId
    );

    this.saveToHistory();
    this.emit('node:deleted', nodeId);
  }

  moveNode(nodeId: string, position: { x: number; y: number }): void {
    const node = this.state.workflow.nodes.find(n => n.id === nodeId);
    if (!node) {
      throw new Error(`Node ${nodeId} not found`);
    }

    node.position = position;
    this.emit('node:moved', { nodeId, position });
  }

  // Edge management
  addEdge(
    sourceId: string,
    targetId: string,
    sourcePort?: string,
    targetPort?: string
  ): WorkflowEdge {
    // Validate connection
    const validation = this.validateConnection(sourceId, targetId, sourcePort, targetPort);
    if (!validation.valid) {
      throw new Error(`Invalid connection: ${validation.reason}`);
    }

    const edge: WorkflowEdge = {
      id: `edge-${uuidv4()}`,
      source: sourceId,
      target: targetId,
      sourcePort,
      targetPort
    };

    this.state.workflow.edges.push(edge);
    this.saveToHistory();
    this.emit('edge:added', edge);

    return edge;
  }

  updateEdge(edgeId: string, updates: Partial<WorkflowEdge>): void {
    const edgeIndex = this.state.workflow.edges.findIndex(e => e.id === edgeId);
    if (edgeIndex === -1) {
      throw new Error(`Edge ${edgeId} not found`);
    }

    const edge = this.state.workflow.edges[edgeIndex];
    Object.assign(edge, updates);
    
    this.saveToHistory();
    this.emit('edge:updated', edge);
  }

  deleteEdge(edgeId: string): void {
    const edgeIndex = this.state.workflow.edges.findIndex(e => e.id === edgeId);
    if (edgeIndex === -1) {
      throw new Error(`Edge ${edgeId} not found`);
    }

    this.state.workflow.edges.splice(edgeIndex, 1);
    this.saveToHistory();
    this.emit('edge:deleted', edgeId);
  }

  // Port management
  addPort(nodeId: string, port: WorkflowPort, isInput: boolean): void {
    const node = this.state.workflow.nodes.find(n => n.id === nodeId);
    if (!node) {
      throw new Error(`Node ${nodeId} not found`);
    }

    if (isInput) {
      node.inputs = node.inputs || [];
      node.inputs.push(port);
    } else {
      node.outputs = node.outputs || [];
      node.outputs.push(port);
    }

    this.saveToHistory();
    this.emit('port:added', { nodeId, port, isInput });
  }

  removePort(nodeId: string, portId: string, isInput: boolean): void {
    const node = this.state.workflow.nodes.find(n => n.id === nodeId);
    if (!node) {
      throw new Error(`Node ${nodeId} not found`);
    }

    const ports = isInput ? node.inputs : node.outputs;
    if (!ports) return;

    const portIndex = ports.findIndex(p => p.id === portId);
    if (portIndex !== -1) {
      ports.splice(portIndex, 1);
      
      // Remove connected edges
      this.state.workflow.edges = this.state.workflow.edges.filter(edge => {
        if (isInput) {
          return !(edge.target === nodeId && edge.targetPort === portId);
        } else {
          return !(edge.source === nodeId && edge.sourcePort === portId);
        }
      });

      this.saveToHistory();
      this.emit('port:removed', { nodeId, portId, isInput });
    }
  }

  // Selection
  selectNode(nodeId: string): void {
    this.state.selectedNodeId = nodeId;
    this.state.selectedEdgeId = undefined;
    this.emit('selection:changed', { type: 'node', id: nodeId });
  }

  selectEdge(edgeId: string): void {
    this.state.selectedEdgeId = edgeId;
    this.state.selectedNodeId = undefined;
    this.emit('selection:changed', { type: 'edge', id: edgeId });
  }

  clearSelection(): void {
    this.state.selectedNodeId = undefined;
    this.state.selectedEdgeId = undefined;
    this.emit('selection:cleared');
  }

  // Clipboard operations
  copy(): void {
    const nodesToCopy: WorkflowNode[] = [];
    const edgesToCopy: WorkflowEdge[] = [];

    if (this.state.selectedNodeId) {
      const node = this.state.workflow.nodes.find(n => n.id === this.state.selectedNodeId);
      if (node) {
        nodesToCopy.push(JSON.parse(JSON.stringify(node)));
      }
    }

    // Copy edges between copied nodes
    for (const edge of this.state.workflow.edges) {
      if (nodesToCopy.find(n => n.id === edge.source) && 
          nodesToCopy.find(n => n.id === edge.target)) {
        edgesToCopy.push(JSON.parse(JSON.stringify(edge)));
      }
    }

    this.state.clipboard = { nodes: nodesToCopy, edges: edgesToCopy };
    this.emit('clipboard:copy', this.state.clipboard);
  }

  paste(offset: { x: number; y: number } = { x: 50, y: 50 }): void {
    if (!this.state.clipboard || this.state.clipboard.nodes.length === 0) {
      return;
    }

    const idMap = new Map<string, string>();
    const pastedNodes: WorkflowNode[] = [];

    // Paste nodes with new IDs
    for (const node of this.state.clipboard.nodes) {
      const newId = `node-${uuidv4()}`;
      idMap.set(node.id, newId);

      const newNode: WorkflowNode = {
        ...node,
        id: newId,
        position: {
          x: node.position.x + offset.x,
          y: node.position.y + offset.y
        }
      };

      this.state.workflow.nodes.push(newNode);
      pastedNodes.push(newNode);
    }

    // Paste edges with updated IDs
    for (const edge of this.state.clipboard.edges) {
      const newSource = idMap.get(edge.source);
      const newTarget = idMap.get(edge.target);

      if (newSource && newTarget) {
        const newEdge: WorkflowEdge = {
          ...edge,
          id: `edge-${uuidv4()}`,
          source: newSource,
          target: newTarget
        };

        this.state.workflow.edges.push(newEdge);
      }
    }

    this.saveToHistory();
    this.emit('clipboard:paste', pastedNodes);
  }

  // History management
  undo(): void {
    if (this.canUndo()) {
      this.state.historyIndex--;
      this.state.workflow = JSON.parse(
        JSON.stringify(this.state.history[this.state.historyIndex])
      );
      this.emit('history:undo');
    }
  }

  redo(): void {
    if (this.canRedo()) {
      this.state.historyIndex++;
      this.state.workflow = JSON.parse(
        JSON.stringify(this.state.history[this.state.historyIndex])
      );
      this.emit('history:redo');
    }
  }

  canUndo(): boolean {
    return this.state.historyIndex > 0;
  }

  canRedo(): boolean {
    return this.state.historyIndex < this.state.history.length - 1;
  }

  // Validation
  async validate(): Promise<{ valid: boolean; errors: string[] }> {
    return this.validator.validate(this.state.workflow);
  }

  validateConnection(
    sourceId: string,
    targetId: string,
    sourcePort?: string,
    targetPort?: string
  ): { valid: boolean; reason?: string } {
    // Check nodes exist
    const sourceNode = this.state.workflow.nodes.find(n => n.id === sourceId);
    const targetNode = this.state.workflow.nodes.find(n => n.id === targetId);

    if (!sourceNode || !targetNode) {
      return { valid: false, reason: 'Node not found' };
    }

    // Prevent self-connections
    if (sourceId === targetId) {
      return { valid: false, reason: 'Cannot connect node to itself' };
    }

    // Check for duplicate connections
    const existingEdge = this.state.workflow.edges.find(
      e => e.source === sourceId && e.target === targetId &&
           e.sourcePort === sourcePort && e.targetPort === targetPort
    );

    if (existingEdge) {
      return { valid: false, reason: 'Connection already exists' };
    }

    // Validate port types if specified
    if (sourcePort && targetPort) {
      const sourcePortDef = sourceNode.outputs?.find(p => p.id === sourcePort);
      const targetPortDef = targetNode.inputs?.find(p => p.id === targetPort);

      if (!sourcePortDef || !targetPortDef) {
        return { valid: false, reason: 'Port not found' };
      }

      if (!this.areTypesCompatible(sourcePortDef.type, targetPortDef.type)) {
        return { valid: false, reason: 'Incompatible port types' };
      }
    }

    // Check for cycles (simplified)
    if (this.wouldCreateCycle(sourceId, targetId)) {
      return { valid: false, reason: 'Connection would create a cycle' };
    }

    return { valid: true };
  }

  // Auto-layout
  autoLayout(): void {
    // Simple hierarchical layout
    const layers = this.topologicalSort();
    const nodeSpacing = { x: 200, y: 100 };
    const startPosition = { x: 100, y: 100 };

    layers.forEach((layer, layerIndex) => {
      layer.forEach((nodeId, nodeIndex) => {
        const node = this.state.workflow.nodes.find(n => n.id === nodeId);
        if (node) {
          node.position = {
            x: startPosition.x + layerIndex * nodeSpacing.x,
            y: startPosition.y + nodeIndex * nodeSpacing.y
          };
        }
      });
    });

    this.saveToHistory();
    this.emit('layout:auto');
  }

  // Export/Import
  getWorkflow(): WorkflowDefinition {
    return JSON.parse(JSON.stringify(this.state.workflow));
  }

  setWorkflow(workflow: WorkflowDefinition): void {
    this.state.workflow = JSON.parse(JSON.stringify(workflow));
    this.state.history = [];
    this.state.historyIndex = -1;
    this.saveToHistory();
    this.emit('workflow:loaded', workflow);
  }

  // Utility methods
  private createEmptyWorkflow(): WorkflowDefinition {
    return {
      id: `workflow-${uuidv4()}`,
      name: 'New Workflow',
      version: '1.0.0',
      nodes: [],
      edges: []
    };
  }

  private saveToHistory(): void {
    // Remove any redo history
    if (this.state.historyIndex < this.state.history.length - 1) {
      this.state.history = this.state.history.slice(0, this.state.historyIndex + 1);
    }

    // Add current state
    this.state.history.push(JSON.parse(JSON.stringify(this.state.workflow)));
    this.state.historyIndex++;

    // Limit history size
    if (this.state.history.length > this.maxHistorySize) {
      this.state.history.shift();
      this.state.historyIndex--;
    }

    this.state.isDirty = true;
  }

  private areTypesCompatible(sourceType: DataType, targetType: DataType): boolean {
    if (sourceType === targetType || targetType === 'any') {
      return true;
    }

    // Add more type compatibility rules as needed
    return false;
  }

  private wouldCreateCycle(sourceId: string, targetId: string): boolean {
    // Simple DFS to check for cycles
    const visited = new Set<string>();
    const stack = [targetId];

    while (stack.length > 0) {
      const current = stack.pop()!;
      if (current === sourceId) {
        return true;
      }

      if (!visited.has(current)) {
        visited.add(current);
        const outgoing = this.state.workflow.edges
          .filter(e => e.source === current)
          .map(e => e.target);
        stack.push(...outgoing);
      }
    }

    return false;
  }

  private topologicalSort(): string[][] {
    const layers: string[][] = [];
    const visited = new Set<string>();
    const inDegree = new Map<string, number>();

    // Calculate in-degrees
    for (const node of this.state.workflow.nodes) {
      inDegree.set(node.id, 0);
    }

    for (const edge of this.state.workflow.edges) {
      inDegree.set(edge.target, (inDegree.get(edge.target) || 0) + 1);
    }

    // Process nodes layer by layer
    while (visited.size < this.state.workflow.nodes.length) {
      const layer: string[] = [];

      for (const node of this.state.workflow.nodes) {
        if (!visited.has(node.id) && inDegree.get(node.id) === 0) {
          layer.push(node.id);
        }
      }

      if (layer.length === 0) {
        // Handle cycles by adding remaining nodes
        for (const node of this.state.workflow.nodes) {
          if (!visited.has(node.id)) {
            layer.push(node.id);
            break;
          }
        }
      }

      for (const nodeId of layer) {
        visited.add(nodeId);
        
        // Reduce in-degree of targets
        for (const edge of this.state.workflow.edges) {
          if (edge.source === nodeId) {
            inDegree.set(edge.target, (inDegree.get(edge.target) || 1) - 1);
          }
        }
      }

      layers.push(layer);
    }

    return layers;
  }

  private initializeNodeTemplates(): Map<NodeType, NodeTemplate> {
    const templates = new Map<NodeType, NodeTemplate>();

    templates.set('start', {
      type: 'start',
      label: 'Start',
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      icon: '▶️',
      category: 'control'
    });

    templates.set('end', {
      type: 'end',
      label: 'End',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      icon: '⏹️',
      category: 'control'
    });

    templates.set('task', {
      type: 'task',
      label: 'Task',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        handler: '// Task logic here\nreturn inputs;'
      },
      icon: '📋',
      category: 'basic'
    });

    templates.set('decision', {
      type: 'decision',
      label: 'Decision',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [
        {
          id: 'true',
          name: 'true',
          type: 'any'
        },
        {
          id: 'false',
          name: 'false',
          type: 'any'
        }
      ],
      icon: '🔀',
      category: 'control'
    });

    templates.set('parallel', {
      type: 'parallel',
      label: 'Parallel',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [
        {
          id: 'out1',
          name: 'branch1',
          type: 'any'
        },
        {
          id: 'out2',
          name: 'branch2',
          type: 'any'
        }
      ],
      icon: '🔱',
      category: 'control'
    });

    templates.set('loop', {
      type: 'loop',
      label: 'Loop',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        condition: 'return counter < 10;',
        maxIterations: 100
      },
      icon: '🔄',
      category: 'control'
    });

    templates.set('humanTask', {
      type: 'humanTask',
      label: 'Human Task',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        title: 'Review and Approve',
        description: 'Please review the request and provide approval'
      },
      icon: '👤',
      category: 'human'
    });

    templates.set('timer', {
      type: 'timer',
      label: 'Timer',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        delay: 1000
      },
      icon: '⏱️',
      category: 'timing'
    });

    templates.set('event', {
      type: 'event',
      label: 'Event',
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        eventType: 'custom.event'
      },
      icon: '📡',
      category: 'events'
    });

    templates.set('transform', {
      type: 'transform',
      label: 'Transform',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        transform: '// Transform data\nreturn { ...inputs, transformed: true };'
      },
      icon: '🔧',
      category: 'data'
    });

    templates.set('aggregate', {
      type: 'aggregate',
      label: 'Aggregate',
      defaultInputs: [
        {
          id: 'in1',
          name: 'input1',
          type: 'any'
        },
        {
          id: 'in2',
          name: 'input2',
          type: 'any'
        }
      ],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        aggregation: 'merge'
      },
      icon: '🔗',
      category: 'data'
    });

    templates.set('subworkflow', {
      type: 'subworkflow',
      label: 'Subworkflow',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        workflowId: ''
      },
      icon: '📦',
      category: 'advanced'
    });

    templates.set('custom', {
      type: 'custom',
      label: 'Custom',
      defaultInputs: [{
        id: 'in',
        name: 'input',
        type: 'any'
      }],
      defaultOutputs: [{
        id: 'out',
        name: 'output',
        type: 'any'
      }],
      defaultData: {
        customHandler: '// Custom logic\nreturn inputs;'
      },
      icon: '⚙️',
      category: 'advanced'
    });

    return templates;
  }

  getNodeTemplates(): NodeTemplate[] {
    return Array.from(this.nodeTemplates.values());
  }

  getNodeTemplate(type: NodeType): NodeTemplate | undefined {
    return this.nodeTemplates.get(type);
  }
}