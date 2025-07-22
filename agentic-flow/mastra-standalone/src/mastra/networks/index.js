// Agent Networks Export
import claudeFlowNetwork from './claude-flow-network.js';
import hiveMindNetwork from './hive-mind-network.js';
import ruvSwarmNetwork from './ruv-swarm-network.js';
import multiNetworkOrchestrator from './multi-network-orchestrator.js';

// Export all networks
export const agentNetworks = {
  'claude-flow': claudeFlowNetwork,
  'hive-mind': hiveMindNetwork,
  'ruv-swarm': ruvSwarmNetwork,
  'multi-network': multiNetworkOrchestrator
};

// Export individual networks
export {
  claudeFlowNetwork,
  hiveMindNetwork,
  ruvSwarmNetwork,
  multiNetworkOrchestrator
};

// Network management functions
export const networkManagement = {
  // Initialize all networks
  initializeAll: async () => {
    console.log('🌐 Initializing all agent networks...');
    const results = {};
    
    for (const [name, network] of Object.entries(agentNetworks)) {
      try {
        results[name] = {
          status: 'initialized',
          name: network.name,
          agents: network.agents.length,
          tools: network.tools.length
        };
        console.log(`✅ ${name} network initialized`);
      } catch (error) {
        results[name] = {
          status: 'failed',
          error: error.message
        };
        console.error(`❌ Failed to initialize ${name}:`, error);
      }
    }
    
    return results;
  },
  
  // Get all network statuses
  getAllStatuses: async () => {
    const statuses = {};
    
    for (const [name, network] of Object.entries(agentNetworks)) {
      statuses[name] = {
        name: network.name,
        description: network.description,
        agents: network.agents.length,
        tools: network.tools.length,
        topology: network.config.networkTopology,
        status: 'active'
      };
    }
    
    return statuses;
  },
  
  // Find optimal network for task
  findOptimalNetwork: (requirements) => {
    if (requirements.needsScale || requirements.priority === 'critical') {
      return agentNetworks['ruv-swarm'];
    } else if (requirements.needsConsensus || requirements.collaborative) {
      return agentNetworks['hive-mind'];
    } else if (requirements.needsReasoning || requirements.complex) {
      return agentNetworks['claude-flow'];
    } else if (requirements.crossNetwork || requirements.orchestration) {
      return agentNetworks['multi-network'];
    }
    
    // Default to Claude Flow for general tasks
    return agentNetworks['claude-flow'];
  },
  
  // Get network metrics
  getNetworkMetrics: (networkName) => {
    const network = agentNetworks[networkName];
    if (!network) return null;
    
    return {
      name: network.name,
      metrics: network.metrics,
      capabilities: network.capabilities,
      performance: {
        agentCount: network.agents.length,
        toolCount: network.tools.length,
        workflowCount: network.workflows.length
      }
    };
  }
};

export default agentNetworks;