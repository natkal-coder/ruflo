/**
 * Swarm Coordinator - Inter-swarm communication and coordination system
 */

import { EventEmitter } from 'events';
import chalk from 'chalk';

export class SwarmCoordinator extends EventEmitter {
  constructor() {
    super();
    this.swarms = new Map();
    this.communicationChannels = new Map();
    this.globalState = {
      insights: [],
      sharedMemory: new Map(),
      consensusProtocols: new Map(),
      coordinationLocks: new Map()
    };
    this.messageQueue = [];
    this.isActive = false;
  }

  /**
   * Register a swarm with the coordinator
   */
  async registerSwarm(swarm) {
    this.swarms.set(swarm.id, {
      swarm,
      lastHeartbeat: Date.now(),
      communicationStats: {
        messagesSent: 0,
        messagesReceived: 0,
        lastCommunication: null
      }
    });

    // Create communication channels with existing swarms
    for (const [existingId, _] of this.swarms) {
      if (existingId !== swarm.id) {
        this.createCommunicationChannel(swarm.id, existingId);
      }
    }

    this.emit('swarmRegistered', swarm);
    console.log(chalk.cyan(`📡 Swarm ${swarm.id} registered with coordinator`));
  }

  /**
   * Create bidirectional communication channel
   */
  createCommunicationChannel(swarm1Id, swarm2Id) {
    const channelId = this.getChannelId(swarm1Id, swarm2Id);
    
    if (!this.communicationChannels.has(channelId)) {
      this.communicationChannels.set(channelId, {
        id: channelId,
        participants: [swarm1Id, swarm2Id],
        established: Date.now(),
        messages: [],
        bandwidth: 1000, // messages per second
        latency: 10, // ms
        reliability: 0.99
      });
    }
  }

  /**
   * Get channel ID for two swarms
   */
  getChannelId(swarm1Id, swarm2Id) {
    return [swarm1Id, swarm2Id].sort().join('-');
  }

  /**
   * Start coordination protocols
   */
  async startCoordination(swarmMap) {
    this.isActive = true;
    console.log(chalk.bold.cyan('🎯 Starting Swarm Coordination Protocols...'));

    // Initialize consensus mechanisms
    await this.initializeConsensus();

    // Start heartbeat monitoring
    this.startHeartbeatMonitoring();

    // Start message processing
    this.startMessageProcessing();

    // Initialize shared memory sync
    this.initializeSharedMemorySync();

    // Start coordination cycles
    this.startCoordinationCycles();
  }

  /**
   * Initialize consensus mechanisms
   */
  async initializeConsensus() {
    const consensusTypes = ['task-allocation', 'resource-sharing', 'priority-decisions'];
    
    for (const type of consensusTypes) {
      this.globalState.consensusProtocols.set(type, {
        type,
        participants: new Set(),
        proposals: [],
        decisions: [],
        algorithm: 'byzantine-fault-tolerant'
      });
    }
  }

  /**
   * Start heartbeat monitoring
   */
  startHeartbeatMonitoring() {
    setInterval(() => {
      if (!this.isActive) return;

      const now = Date.now();
      for (const [swarmId, data] of this.swarms) {
        const timeSinceLastHeartbeat = now - data.lastHeartbeat;
        
        if (timeSinceLastHeartbeat > 5000) {
          console.log(chalk.yellow(`⚠️  Swarm ${swarmId} heartbeat delayed`));
          this.handleSwarmTimeout(swarmId);
        }
      }
    }, 1000);
  }

  /**
   * Start message processing
   */
  startMessageProcessing() {
    setInterval(() => {
      if (!this.isActive || this.messageQueue.length === 0) return;

      const batch = this.messageQueue.splice(0, 10); // Process up to 10 messages
      
      for (const message of batch) {
        this.processMessage(message);
      }
    }, 50);
  }

  /**
   * Process individual message
   */
  async processMessage(message) {
    const { from, to, type, payload, priority } = message;
    
    // Record communication
    if (this.swarms.has(from)) {
      this.swarms.get(from).communicationStats.messagesSent++;
      this.swarms.get(from).communicationStats.lastCommunication = Date.now();
    }
    
    if (this.swarms.has(to)) {
      this.swarms.get(to).communicationStats.messagesReceived++;
    }

    // Handle different message types
    switch (type) {
      case 'consensus-proposal':
        await this.handleConsensusProposal(from, payload);
        break;
      case 'resource-request':
        await this.handleResourceRequest(from, to, payload);
        break;
      case 'insight-share':
        await this.handleInsightShare(from, payload);
        break;
      case 'coordination-update':
        await this.handleCoordinationUpdate(from, payload);
        break;
      case 'emergency':
        await this.handleEmergencyMessage(from, payload);
        break;
      default:
        // Store in channel history
        const channelId = this.getChannelId(from, to);
        if (this.communicationChannels.has(channelId)) {
          this.communicationChannels.get(channelId).messages.push(message);
        }
    }

    this.emit('messageProcessed', message);
  }

  /**
   * Initialize shared memory synchronization
   */
  initializeSharedMemorySync() {
    // Create memory segments
    const memorySegments = [
      'global-insights',
      'resource-pool',
      'task-registry',
      'performance-metrics',
      'error-logs'
    ];

    for (const segment of memorySegments) {
      this.globalState.sharedMemory.set(segment, {
        data: new Map(),
        lastSync: Date.now(),
        version: 1,
        subscribers: new Set()
      });
    }
  }

  /**
   * Start coordination cycles
   */
  startCoordinationCycles() {
    // Major coordination cycle every 10 seconds
    setInterval(() => {
      if (!this.isActive) return;
      this.executeMajorCoordinationCycle();
    }, 10000);

    // Minor coordination cycle every 2 seconds
    setInterval(() => {
      if (!this.isActive) return;
      this.executeMinorCoordinationCycle();
    }, 2000);
  }

  /**
   * Execute major coordination cycle
   */
  async executeMajorCoordinationCycle() {
    console.log(chalk.bold.blue('\n🔄 Major Coordination Cycle'));

    // Global resource rebalancing
    await this.rebalanceGlobalResources();

    // Cross-swarm task optimization
    await this.optimizeCrossSwarmTasks();

    // Consensus decisions
    await this.processConsensusDecisions();

    // Performance synchronization
    await this.synchronizePerformanceMetrics();
  }

  /**
   * Execute minor coordination cycle
   */
  async executeMinorCoordinationCycle() {
    // Quick health checks
    this.performHealthChecks();

    // Process urgent messages
    this.processUrgentMessages();

    // Update shared memory
    this.updateSharedMemory();
  }

  /**
   * Exchange data between swarms
   */
  async exchangeData(swarm1Id, swarm2Id, data) {
    const message = {
      id: `msg-${Date.now()}-${Math.random()}`,
      from: swarm1Id,
      to: swarm2Id,
      type: 'data-exchange',
      payload: data,
      timestamp: Date.now(),
      priority: 'normal'
    };

    this.messageQueue.push(message);
    
    // Bidirectional acknowledgment
    const ackMessage = {
      ...message,
      from: swarm2Id,
      to: swarm1Id,
      type: 'ack'
    };
    
    this.messageQueue.push(ackMessage);
  }

  /**
   * Handle consensus proposal
   */
  async handleConsensusProposal(swarmId, proposal) {
    const { type, decision, justification } = proposal;
    const protocol = this.globalState.consensusProtocols.get(type);
    
    if (protocol) {
      protocol.proposals.push({
        swarmId,
        decision,
        justification,
        timestamp: Date.now(),
        votes: new Map()
      });

      // Request votes from other swarms
      for (const [otherId, _] of this.swarms) {
        if (otherId !== swarmId) {
          this.requestVote(otherId, type, proposal);
        }
      }
    }
  }

  /**
   * Request vote from swarm
   */
  requestVote(swarmId, consensusType, proposal) {
    const message = {
      from: 'coordinator',
      to: swarmId,
      type: 'vote-request',
      payload: { consensusType, proposal },
      priority: 'high'
    };
    
    this.messageQueue.push(message);
  }

  /**
   * Handle resource request
   */
  async handleResourceRequest(from, to, request) {
    const { resourceType, amount, urgency } = request;
    
    // Check if target swarm can provide resources
    const targetSwarm = this.swarms.get(to);
    if (targetSwarm && targetSwarm.swarm.metrics.efficiency > 50) {
      // Approve resource transfer
      const transfer = {
        from: to,
        to: from,
        type: 'resource-transfer',
        payload: { resourceType, amount: amount * 0.8 }, // Transfer 80% of requested
        priority: urgency
      };
      
      this.messageQueue.push(transfer);
      console.log(chalk.green(`✅ Resource transfer approved: ${resourceType} from ${to} to ${from}`));
    }
  }

  /**
   * Handle insight sharing
   */
  async handleInsightShare(from, insight) {
    this.globalState.insights.push({
      source: from,
      insight,
      timestamp: Date.now(),
      propagated: false
    });

    // Propagate to relevant swarms
    const relevantSwarms = this.findRelevantSwarms(insight);
    for (const swarmId of relevantSwarms) {
      if (swarmId !== from) {
        this.propagateInsight(swarmId, insight);
      }
    }
  }

  /**
   * Find swarms relevant to an insight
   */
  findRelevantSwarms(insight) {
    const relevant = [];
    
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      // Check if swarm capabilities match insight type
      const hasRelevantAgents = Array.from(swarm.agents.values()).some(agent =>
        agent.capabilities.some(cap => insight.tags?.includes(cap))
      );
      
      if (hasRelevantAgents) {
        relevant.push(swarmId);
      }
    }
    
    return relevant;
  }

  /**
   * Propagate insight to swarm
   */
  propagateInsight(swarmId, insight) {
    const message = {
      from: 'coordinator',
      to: swarmId,
      type: 'insight-propagation',
      payload: insight,
      priority: 'normal'
    };
    
    this.messageQueue.push(message);
  }

  /**
   * Handle coordination update
   */
  async handleCoordinationUpdate(from, update) {
    // Update coordination state
    const segment = this.globalState.sharedMemory.get(update.segment);
    if (segment) {
      segment.data.set(update.key, update.value);
      segment.version++;
      segment.lastSync = Date.now();
      
      // Notify subscribers
      for (const subscriberId of segment.subscribers) {
        if (subscriberId !== from) {
          this.notifyMemoryUpdate(subscriberId, update.segment, update.key);
        }
      }
    }
  }

  /**
   * Handle emergency message
   */
  async handleEmergencyMessage(from, emergency) {
    console.log(chalk.red(`🚨 EMERGENCY from ${from}: ${emergency.message}`));
    
    // Immediate broadcast to all swarms
    for (const [swarmId, _] of this.swarms) {
      if (swarmId !== from) {
        const alert = {
          from: 'coordinator',
          to: swarmId,
          type: 'emergency-broadcast',
          payload: emergency,
          priority: 'critical'
        };
        
        // Skip queue for emergencies
        await this.processMessage(alert);
      }
    }
    
    // Trigger emergency protocols
    await this.activateEmergencyProtocols(from, emergency);
  }

  /**
   * Activate emergency protocols
   */
  async activateEmergencyProtocols(sourceSwarm, emergency) {
    // Pause non-critical operations
    this.globalState.coordinationLocks.set('emergency', {
      active: true,
      source: sourceSwarm,
      timestamp: Date.now()
    });

    // Reallocate resources to handle emergency
    await this.emergencyResourceReallocation(sourceSwarm, emergency);

    // After 5 seconds, resume normal operations
    setTimeout(() => {
      this.globalState.coordinationLocks.delete('emergency');
      console.log(chalk.green('✅ Emergency protocols deactivated'));
    }, 5000);
  }

  /**
   * Emergency resource reallocation
   */
  async emergencyResourceReallocation(targetSwarm, emergency) {
    // Find swarms with available resources
    const availableSwarms = Array.from(this.swarms.entries())
      .filter(([id, data]) => id !== targetSwarm && data.swarm.metrics.efficiency > 70)
      .sort((a, b) => b[1].swarm.metrics.efficiency - a[1].swarm.metrics.efficiency);

    // Allocate resources from top performers
    for (const [swarmId, _] of availableSwarms.slice(0, 2)) {
      const assistance = {
        from: swarmId,
        to: targetSwarm,
        type: 'emergency-assistance',
        payload: { 
          agents: 2, 
          priority: 'critical',
          duration: 5000 
        },
        priority: 'critical'
      };
      
      this.messageQueue.push(assistance);
    }
  }

  /**
   * Handle swarm timeout
   */
  handleSwarmTimeout(swarmId) {
    const swarmData = this.swarms.get(swarmId);
    if (!swarmData) return;

    // Mark as potentially failed
    swarmData.swarm.status = 'unresponsive';
    
    // Redistribute critical tasks
    this.redistributeSwarmTasks(swarmData.swarm);
    
    // Alert other swarms
    for (const [otherId, _] of this.swarms) {
      if (otherId !== swarmId) {
        const alert = {
          from: 'coordinator',
          to: otherId,
          type: 'swarm-timeout',
          payload: { timeoutSwarm: swarmId },
          priority: 'high'
        };
        
        this.messageQueue.push(alert);
      }
    }
  }

  /**
   * Redistribute tasks from failed swarm
   */
  redistributeSwarmTasks(failedSwarm) {
    const criticalTasks = failedSwarm.tasks.filter(task => task.priority === 'high');
    
    if (criticalTasks.length > 0) {
      // Find healthy swarms
      const healthySwarms = Array.from(this.swarms.values())
        .filter(data => data.swarm.status === 'active' && data.swarm.metrics.efficiency > 60)
        .map(data => data.swarm);
      
      // Distribute tasks round-robin
      criticalTasks.forEach((task, index) => {
        const targetSwarm = healthySwarms[index % healthySwarms.length];
        if (targetSwarm) {
          targetSwarm.tasks.push(task);
          console.log(chalk.yellow(`📋 Redistributed task to ${targetSwarm.id}`));
        }
      });
    }
  }

  /**
   * Rebalance global resources
   */
  async rebalanceGlobalResources() {
    const resourceMetrics = new Map();
    
    // Collect resource usage from all swarms
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      resourceMetrics.set(swarmId, {
        efficiency: swarm.metrics.efficiency,
        load: swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted,
        health: swarm.metrics.health,
        agentUtilization: this.calculateAgentUtilization(swarm)
      });
    }

    // Identify imbalances
    const avgEfficiency = Array.from(resourceMetrics.values())
      .reduce((sum, m) => sum + m.efficiency, 0) / resourceMetrics.size;
    
    // Rebalance if needed
    for (const [swarmId, metrics] of resourceMetrics) {
      if (metrics.efficiency < avgEfficiency * 0.7) {
        // This swarm needs help
        await this.requestResourceAssistance(swarmId, metrics);
      } else if (metrics.efficiency > avgEfficiency * 1.3) {
        // This swarm can help others
        await this.offerResourceAssistance(swarmId, metrics);
      }
    }
  }

  /**
   * Calculate agent utilization
   */
  calculateAgentUtilization(swarm) {
    const agents = Array.from(swarm.agents.values());
    const activeAgents = agents.filter(a => a.status === 'working').length;
    return (activeAgents / agents.length) * 100;
  }

  /**
   * Optimize cross-swarm tasks
   */
  async optimizeCrossSwarmTasks() {
    // Identify tasks that could benefit from cross-swarm collaboration
    const collaborationOpportunities = [];
    
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      
      // Find complex tasks
      const complexTasks = swarm.tasks.filter(task => 
        task.complexity === 'high' || task.requiresCollaboration
      );
      
      for (const task of complexTasks) {
        const bestPartner = this.findBestCollaborationPartner(swarm, task);
        if (bestPartner) {
          collaborationOpportunities.push({
            task,
            primarySwarm: swarmId,
            partnerSwarm: bestPartner.id,
            estimatedImprovement: 30 // percentage
          });
        }
      }
    }

    // Execute collaborations
    for (const collab of collaborationOpportunities) {
      await this.establishCollaboration(collab);
    }
  }

  /**
   * Find best collaboration partner
   */
  findBestCollaborationPartner(swarm, task) {
    let bestPartner = null;
    let bestScore = 0;
    
    for (const [otherId, data] of this.swarms) {
      if (otherId === swarm.id) continue;
      
      const otherSwarm = data.swarm;
      const score = this.calculateCollaborationScore(task, otherSwarm);
      
      if (score > bestScore) {
        bestScore = score;
        bestPartner = otherSwarm;
      }
    }
    
    return bestScore > 0.7 ? bestPartner : null;
  }

  /**
   * Calculate collaboration score
   */
  calculateCollaborationScore(task, swarm) {
    // Check agent capabilities match
    const requiredCapabilities = task.requiredCapabilities || [];
    const swarmCapabilities = new Set();
    
    for (const agent of swarm.agents.values()) {
      agent.capabilities.forEach(cap => swarmCapabilities.add(cap));
    }
    
    const matchingCapabilities = requiredCapabilities.filter(cap => 
      swarmCapabilities.has(cap)
    ).length;
    
    const capabilityScore = matchingCapabilities / Math.max(1, requiredCapabilities.length);
    const efficiencyScore = swarm.metrics.efficiency / 100;
    const availabilityScore = (100 - this.calculateAgentUtilization(swarm)) / 100;
    
    return (capabilityScore * 0.5) + (efficiencyScore * 0.3) + (availabilityScore * 0.2);
  }

  /**
   * Establish collaboration
   */
  async establishCollaboration(collab) {
    const message = {
      from: collab.primarySwarm,
      to: collab.partnerSwarm,
      type: 'collaboration-request',
      payload: {
        task: collab.task,
        estimatedDuration: 5000,
        sharedReward: true
      },
      priority: 'high'
    };
    
    this.messageQueue.push(message);
    
    console.log(chalk.magenta(
      `🤝 Collaboration established: ${collab.primarySwarm} ↔ ${collab.partnerSwarm}`
    ));
  }

  /**
   * Process consensus decisions
   */
  async processConsensusDecisions() {
    for (const [type, protocol] of this.globalState.consensusProtocols) {
      const pendingProposals = protocol.proposals.filter(p => !p.decided);
      
      for (const proposal of pendingProposals) {
        const voteCount = proposal.votes.size;
        const totalSwarms = this.swarms.size;
        
        if (voteCount >= Math.ceil(totalSwarms * 0.66)) {
          // Consensus reached
          const decision = this.tallyVotes(proposal);
          protocol.decisions.push({
            proposal,
            decision,
            timestamp: Date.now(),
            consensus: true
          });
          
          proposal.decided = true;
          
          // Broadcast decision
          await this.broadcastConsensusDecision(type, decision);
        }
      }
    }
  }

  /**
   * Tally votes for proposal
   */
  tallyVotes(proposal) {
    const votes = Array.from(proposal.votes.values());
    const yesVotes = votes.filter(v => v === 'yes').length;
    const noVotes = votes.filter(v => v === 'no').length;
    
    return {
      approved: yesVotes > noVotes,
      yesVotes,
      noVotes,
      participation: (votes.length / this.swarms.size) * 100
    };
  }

  /**
   * Broadcast consensus decision
   */
  async broadcastConsensusDecision(type, decision) {
    for (const [swarmId, _] of this.swarms) {
      const message = {
        from: 'coordinator',
        to: swarmId,
        type: 'consensus-decision',
        payload: { type, decision },
        priority: 'high'
      };
      
      this.messageQueue.push(message);
    }
    
    console.log(chalk.green(`✅ Consensus reached on ${type}: ${decision.approved ? 'APPROVED' : 'REJECTED'}`));
  }

  /**
   * Synchronize performance metrics
   */
  async synchronizePerformanceMetrics() {
    const globalMetrics = {
      timestamp: Date.now(),
      swarmMetrics: new Map(),
      aggregates: {
        totalTasks: 0,
        completedTasks: 0,
        avgEfficiency: 0,
        totalAgents: 0,
        activeAgents: 0
      }
    };

    // Collect metrics from all swarms
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      globalMetrics.swarmMetrics.set(swarmId, swarm.metrics);
      
      globalMetrics.aggregates.totalTasks += swarm.metrics.tasksAssigned;
      globalMetrics.aggregates.completedTasks += swarm.metrics.tasksCompleted;
      globalMetrics.aggregates.totalAgents += swarm.agents.size;
      globalMetrics.aggregates.activeAgents += Array.from(swarm.agents.values())
        .filter(a => a.status === 'working').length;
    }

    globalMetrics.aggregates.avgEfficiency = 
      Array.from(globalMetrics.swarmMetrics.values())
        .reduce((sum, m) => sum + m.efficiency, 0) / globalMetrics.swarmMetrics.size;

    // Store in shared memory
    const metricsSegment = this.globalState.sharedMemory.get('performance-metrics');
    metricsSegment.data.set('global', globalMetrics);
    
    // Notify all swarms
    for (const [swarmId, _] of this.swarms) {
      this.notifyMemoryUpdate(swarmId, 'performance-metrics', 'global');
    }
  }

  /**
   * Notify memory update
   */
  notifyMemoryUpdate(swarmId, segment, key) {
    const message = {
      from: 'coordinator',
      to: swarmId,
      type: 'memory-update',
      payload: { segment, key },
      priority: 'normal'
    };
    
    this.messageQueue.push(message);
  }

  /**
   * Perform health checks
   */
  performHealthChecks() {
    const now = Date.now();
    
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      
      // Check agent health
      let unhealthyAgents = 0;
      for (const agent of swarm.agents.values()) {
        if (agent.performance < 50 || 
            (agent.status === 'working' && now - agent.lastActivity > 10000)) {
          unhealthyAgents++;
        }
      }
      
      // Update swarm health
      swarm.metrics.health = Math.max(0, 100 - (unhealthyAgents / swarm.agents.size) * 100);
      
      // Update heartbeat
      data.lastHeartbeat = now;
    }
  }

  /**
   * Process urgent messages
   */
  processUrgentMessages() {
    const urgentMessages = this.messageQueue.filter(m => 
      m.priority === 'critical' || m.priority === 'high'
    );
    
    if (urgentMessages.length > 0) {
      // Remove from main queue
      this.messageQueue = this.messageQueue.filter(m => 
        m.priority !== 'critical' && m.priority !== 'high'
      );
      
      // Process immediately
      for (const message of urgentMessages) {
        this.processMessage(message);
      }
    }
  }

  /**
   * Update shared memory
   */
  updateSharedMemory() {
    // Increment versions for changed segments
    for (const [segmentName, segment] of this.globalState.sharedMemory) {
      if (Date.now() - segment.lastSync > 1000) {
        segment.version++;
        segment.lastSync = Date.now();
      }
    }
  }

  /**
   * Request resource assistance
   */
  async requestResourceAssistance(swarmId, metrics) {
    const request = {
      from: swarmId,
      to: 'broadcast',
      type: 'assistance-request',
      payload: {
        currentMetrics: metrics,
        assistanceType: 'load-balancing',
        urgency: metrics.efficiency < 50 ? 'high' : 'medium'
      },
      priority: 'high'
    };
    
    // Broadcast to all healthy swarms
    for (const [otherId, _] of this.swarms) {
      if (otherId !== swarmId) {
        this.messageQueue.push({ ...request, to: otherId });
      }
    }
  }

  /**
   * Offer resource assistance
   */
  async offerResourceAssistance(swarmId, metrics) {
    const offer = {
      from: swarmId,
      to: 'coordinator',
      type: 'assistance-offer',
      payload: {
        availableCapacity: 100 - metrics.agentUtilization,
        capabilities: this.getSwarmCapabilities(swarmId),
        duration: 10000 // 10 seconds
      },
      priority: 'normal'
    };
    
    this.messageQueue.push(offer);
  }

  /**
   * Get swarm capabilities
   */
  getSwarmCapabilities(swarmId) {
    const swarmData = this.swarms.get(swarmId);
    if (!swarmData) return [];
    
    const capabilities = new Set();
    for (const agent of swarmData.swarm.agents.values()) {
      agent.capabilities.forEach(cap => capabilities.add(cap));
    }
    
    return Array.from(capabilities);
  }

  /**
   * Collect global insights
   */
  async collectGlobalInsights(swarmMap) {
    const insights = {
      timestamp: Date.now(),
      swarmInsights: [],
      patterns: [],
      recommendations: []
    };

    // Collect from each swarm
    for (const swarm of swarmMap.values()) {
      const swarmInsight = {
        swarmId: swarm.id,
        efficiency: swarm.metrics.efficiency,
        tasksCompleted: swarm.metrics.tasksCompleted,
        agentPerformance: this.analyzeAgentPerformance(swarm),
        bottlenecks: this.identifyBottlenecks(swarm)
      };
      
      insights.swarmInsights.push(swarmInsight);
    }

    // Identify patterns
    insights.patterns = this.identifyGlobalPatterns(insights.swarmInsights);
    
    // Generate recommendations
    insights.recommendations = this.generateRecommendations(insights);

    return insights;
  }

  /**
   * Analyze agent performance
   */
  analyzeAgentPerformance(swarm) {
    const agentStats = [];
    
    for (const agent of swarm.agents.values()) {
      agentStats.push({
        agentId: agent.id,
        type: agent.type,
        tasksCompleted: agent.tasksCompleted,
        performance: agent.performance,
        utilization: agent.status === 'working' ? 100 : 0
      });
    }
    
    return {
      topPerformers: agentStats.sort((a, b) => b.tasksCompleted - a.tasksCompleted).slice(0, 3),
      avgPerformance: agentStats.reduce((sum, a) => sum + a.performance, 0) / agentStats.length
    };
  }

  /**
   * Identify bottlenecks
   */
  identifyBottlenecks(swarm) {
    const bottlenecks = [];
    
    // Check task backlog
    const backlog = swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted;
    if (backlog > swarm.agents.size * 2) {
      bottlenecks.push({
        type: 'task-backlog',
        severity: 'high',
        value: backlog
      });
    }

    // Check agent utilization
    const utilization = this.calculateAgentUtilization(swarm);
    if (utilization > 90) {
      bottlenecks.push({
        type: 'over-utilization',
        severity: 'medium',
        value: utilization
      });
    }

    return bottlenecks;
  }

  /**
   * Identify global patterns
   */
  identifyGlobalPatterns(swarmInsights) {
    const patterns = [];
    
    // Performance correlation
    const efficiencies = swarmInsights.map(s => s.efficiency);
    const avgEfficiency = efficiencies.reduce((a, b) => a + b, 0) / efficiencies.length;
    
    if (Math.max(...efficiencies) - Math.min(...efficiencies) > 30) {
      patterns.push({
        type: 'efficiency-imbalance',
        description: 'Significant efficiency variance across swarms',
        recommendation: 'Consider load balancing'
      });
    }

    // Bottleneck patterns
    const commonBottlenecks = new Map();
    swarmInsights.forEach(insight => {
      insight.bottlenecks.forEach(bottleneck => {
        const count = commonBottlenecks.get(bottleneck.type) || 0;
        commonBottlenecks.set(bottleneck.type, count + 1);
      });
    });

    for (const [type, count] of commonBottlenecks) {
      if (count > swarmInsights.length / 2) {
        patterns.push({
          type: 'common-bottleneck',
          description: `${type} affecting ${count} swarms`,
          recommendation: 'Address systematically'
        });
      }
    }

    return patterns;
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(insights) {
    const recommendations = [];
    
    // Based on patterns
    insights.patterns.forEach(pattern => {
      recommendations.push({
        priority: 'high',
        action: pattern.recommendation,
        rationale: pattern.description
      });
    });

    // Based on performance
    const lowPerformers = insights.swarmInsights.filter(s => s.efficiency < 60);
    if (lowPerformers.length > 0) {
      recommendations.push({
        priority: 'medium',
        action: 'Scale up low-performing swarms',
        rationale: `${lowPerformers.length} swarms operating below 60% efficiency`
      });
    }

    return recommendations;
  }

  /**
   * Emergency shutdown
   */
  async emergencyShutdown(swarmMap) {
    console.log(chalk.red('🚨 Initiating emergency shutdown...'));
    
    this.isActive = false;
    
    // Save state
    const emergencyState = {
      timestamp: Date.now(),
      swarms: Array.from(swarmMap.entries()),
      sharedMemory: Array.from(this.globalState.sharedMemory.entries()),
      pendingMessages: this.messageQueue
    };

    // Notify all swarms
    for (const [swarmId, _] of this.swarms) {
      const message = {
        from: 'coordinator',
        to: swarmId,
        type: 'shutdown',
        payload: { reason: 'emergency' },
        priority: 'critical'
      };
      
      await this.processMessage(message);
    }

    return emergencyState;
  }
}