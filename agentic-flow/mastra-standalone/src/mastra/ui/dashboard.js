// Agentic Flow Custom Dashboard for Mastra UI
import { agenticFlowTheme, brandConfig } from '../theme.js';
import { getNetworkStatus } from '../mcp.js';
import { claudeFlowAgent } from '../agents/claude-flow-agent.js';
import { hiveMindAgent } from '../agents/hive-mind-agent.js';
import { ruvSwarmAgent } from '../agents/ruv-swarm-agent.js';

// Dashboard Configuration
export const dashboardConfig = {
  title: brandConfig.name,
  subtitle: brandConfig.tagline,
  theme: agenticFlowTheme,
  
  // Layout Configuration
  layout: {
    grid: 'auto-fit',
    minWidth: '350px',
    gap: '1.5rem',
    padding: '2rem',
  },
  
  // Widget Configurations
  widgets: [
    // System Overview Widget
    {
      id: 'system-overview',
      title: '🤖 System Overview',
      type: 'metrics',
      size: 'large',
      data: async () => {
        const status = await getNetworkStatus();
        return {
          totalAgents: status.overall.totalAgents,
          totalTasks: status.overall.totalTasks,
          systemEfficiency: `${(status.overall.systemEfficiency * 100).toFixed(1)}%`,
          uptime: status.overall.status === 'healthy' ? 'Online' : 'Offline'
        };
      },
      style: {
        background: agenticFlowTheme.components.agentCard.background,
        border: agenticFlowTheme.components.agentCard.border,
      }
    },
    
    // Network Status Widget
    {
      id: 'network-status',
      title: '🌐 Network Status',
      type: 'status-grid',
      size: 'medium',
      data: async () => {
        const status = await getNetworkStatus();
        return Object.entries(status.networks).map(([name, data]) => ({
          name: name.replace('-', ' ').toUpperCase(),
          status: data.status,
          agents: data.agents || data.nodes || data.swarms || 0,
          performance: `${(data.performance * 100).toFixed(0)}%`,
          color: brandConfig.integrations[name.replace('-', '')]?.color || agenticFlowTheme.colors.primary
        }));
      },
      style: {
        background: agenticFlowTheme.components.workflowCard.background,
        border: agenticFlowTheme.components.workflowCard.border,
      }
    },
    
    // Agent Directory Widget
    {
      id: 'agent-directory',
      title: '👥 Agent Directory',
      type: 'agent-cards',
      size: 'large',
      data: () => [
        {
          id: 'claude-flow-coordinator',
          name: 'Claude Flow',
          description: 'Advanced AI reasoning and coordination',
          icon: '🧠',
          color: '#FF6B35',
          status: 'active',
          capabilities: claudeFlowAgent.metadata.capabilities,
          category: claudeFlowAgent.metadata.category
        },
        {
          id: 'hive-mind-collective',
          name: 'Hive Mind',
          description: 'Collective intelligence system',
          icon: '🐝',
          color: '#FFD23F',
          status: 'active',
          capabilities: hiveMindAgent.metadata.capabilities,
          category: hiveMindAgent.metadata.category
        },
        {
          id: 'ruv-swarm-coordinator',
          name: 'RUV Swarm',
          description: 'Distributed agent swarms',
          icon: '🔥',
          color: '#EE4266',
          status: 'active',
          capabilities: ruvSwarmAgent.metadata.capabilities,
          category: ruvSwarmAgent.metadata.category
        }
      ],
      style: {
        background: agenticFlowTheme.components.agentCard.background,
        border: agenticFlowTheme.components.agentCard.border,
      }
    },
    
    // Workflow Status Widget
    {
      id: 'workflow-status',
      title: '🔄 Active Workflows',
      type: 'workflow-list',
      size: 'medium',
      data: () => [
        {
          id: 'software-development',
          name: 'Software Development',
          description: 'Complete SDLC workflow',
          status: 'available',
          steps: 4,
          agents: ['coordinator', 'researcher', 'architect', 'executor'],
          icon: '💻'
        },
        {
          id: 'problem-solving',
          name: 'Problem Solving',
          description: 'Structured problem resolution',
          status: 'available',
          steps: 4,
          agents: ['coordinator', 'researcher', 'architect', 'executor'],
          icon: '🧩'
        }
      ],
      style: {
        background: agenticFlowTheme.components.workflowCard.background,
        border: agenticFlowTheme.components.workflowCard.border,
      }
    },
    
    // Tools and Integrations Widget
    {
      id: 'tools-integrations',
      title: '🛠️ Tools & Integrations',
      type: 'tool-grid',
      size: 'medium',
      data: () => [
        {
          name: 'Create Team',
          description: 'Form agent teams for specific goals',
          icon: '👥',
          category: 'team-management',
          status: 'active'
        },
        {
          name: 'Execute Workflow',
          description: 'Run predefined workflows',
          icon: '🔄',
          category: 'workflow-execution',
          status: 'active'
        },
        {
          name: 'Monitor System',
          description: 'Health and performance monitoring',
          icon: '📊',
          category: 'system-monitoring',
          status: 'active'
        },
        {
          name: 'MCP Integration',
          description: 'Model Context Protocol servers',
          icon: '🔗',
          category: 'integrations',
          status: 'active'
        }
      ],
      style: {
        background: agenticFlowTheme.components.toolCard.background,
        border: agenticFlowTheme.components.toolCard.border,
      }
    },
    
    // Performance Metrics Widget
    {
      id: 'performance-metrics',
      title: '📈 Performance Metrics',
      type: 'metrics-chart',
      size: 'large',
      data: async () => {
        const status = await getNetworkStatus();
        return {
          systemEfficiency: status.overall.systemEfficiency,
          networkPerformance: Object.values(status.networks).map(n => n.performance),
          averageUptime: Object.values(status.networks).reduce((acc, n) => 
            acc + parseFloat(n.uptime.replace('%', '')), 0) / Object.keys(status.networks).length,
          totalThroughput: status.overall.totalTasks,
          resourceUtilization: 0.78
        };
      },
      style: {
        background: 'linear-gradient(135deg, #1E293B 0%, #334155 100%)',
        border: `1px solid ${agenticFlowTheme.colors.primary}`,
      }
    }
  ],
  
  // Navigation Configuration
  navigation: brandConfig.navigation,
  
  // Quick Actions
  quickActions: [
    {
      id: 'create-team',
      label: 'Create Team',
      icon: '👥',
      color: agenticFlowTheme.colors.agents.coordinator,
      action: 'openModal',
      modal: 'createTeam'
    },
    {
      id: 'run-workflow',
      label: 'Run Workflow', 
      icon: '🔄',
      color: agenticFlowTheme.colors.agents.executor,
      action: 'openModal',
      modal: 'runWorkflow'
    },
    {
      id: 'monitor-health',
      label: 'System Health',
      icon: '🏥',
      color: agenticFlowTheme.colors.agents.monitor,
      action: 'navigate',
      path: '/monitor'
    },
    {
      id: 'view-agents',
      label: 'View Agents',
      icon: '🤖',
      color: agenticFlowTheme.colors.primary,
      action: 'navigate', 
      path: '/agents'
    }
  ],
  
  // Real-time Updates Configuration
  realtime: {
    enabled: true,
    interval: 30000, // 30 seconds
    endpoints: [
      '/api/system/status',
      '/api/agents/status',
      '/api/workflows/active'
    ]
  },
  
  // Notification Configuration
  notifications: {
    enabled: true,
    position: 'top-right',
    duration: 5000,
    types: {
      success: { color: agenticFlowTheme.colors.accent },
      warning: { color: agenticFlowTheme.colors.warning },
      error: { color: agenticFlowTheme.colors.error },
      info: { color: agenticFlowTheme.colors.primary }
    }
  },
  
  // Accessibility Configuration
  accessibility: {
    highContrast: false,
    reducedMotion: false,
    screenReader: true,
    keyboardNavigation: true
  }
};

// Dashboard Event Handlers
export const dashboardHandlers = {
  // Handle widget interactions
  onWidgetClick: (widgetId, data) => {
    console.log(`Widget clicked: ${widgetId}`, data);
    
    switch (widgetId) {
      case 'agent-directory':
        return { action: 'navigate', path: '/agents' };
      case 'workflow-status':
        return { action: 'navigate', path: '/workflows' };
      case 'tools-integrations':
        return { action: 'navigate', path: '/tools' };
      default:
        return { action: 'none' };
    }
  },
  
  // Handle quick action clicks
  onQuickAction: (actionId) => {
    console.log(`Quick action triggered: ${actionId}`);
    
    const action = dashboardConfig.quickActions.find(a => a.id === actionId);
    return action ? { 
      action: action.action, 
      target: action.modal || action.path 
    } : { action: 'none' };
  },
  
  // Handle real-time updates
  onRealtimeUpdate: (endpoint, data) => {
    console.log(`Real-time update from ${endpoint}:`, data);
    return { action: 'updateWidget', data };
  },
  
  // Handle notification events
  onNotification: (type, message, data) => {
    console.log(`Notification [${type}]: ${message}`, data);
    return { 
      type, 
      message, 
      timestamp: new Date().toISOString(),
      data 
    };
  }
};

export default { dashboardConfig, dashboardHandlers };