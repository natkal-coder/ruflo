// Agentic Flow Custom Theme for Mastra UI
export const agenticFlowTheme = {
  // Brand Colors
  colors: {
    primary: '#2563EB',      // Agentic Flow Blue
    secondary: '#7C3AED',    // Agentic Flow Purple  
    accent: '#10B981',       // Success Green
    warning: '#F59E0B',      // Warning Amber
    error: '#EF4444',        // Error Red
    
    // Background Colors
    background: '#0F172A',   // Dark Navy
    surface: '#1E293B',      // Dark Gray
    card: '#334155',         // Medium Gray
    
    // Text Colors
    text: {
      primary: '#F8FAFC',    // White
      secondary: '#CBD5E1',  // Light Gray
      muted: '#94A3B8',      // Medium Gray
    },
    
    // Agent Type Colors
    agents: {
      coordinator: '#3B82F6', // Blue
      executor: '#10B981',    // Green  
      researcher: '#F59E0B',  // Amber
      architect: '#8B5CF6',   // Purple
      analyst: '#EF4444',     // Red
      coder: '#06B6D4',       // Cyan
      tester: '#84CC16',      // Lime
      reviewer: '#F97316',    // Orange
      monitor: '#6366F1',     // Indigo
      optimizer: '#EC4899',   // Pink
    }
  },
  
  // Typography
  typography: {
    fontFamily: {
      sans: ['Inter', 'system-ui', 'sans-serif'],
      mono: ['Fira Code', 'Monaco', 'monospace'],
    },
    fontSize: {
      xs: '0.75rem',
      sm: '0.875rem', 
      base: '1rem',
      lg: '1.125rem',
      xl: '1.25rem',
      '2xl': '1.5rem',
      '3xl': '1.875rem',
      '4xl': '2.25rem',
    },
    fontWeight: {
      normal: '400',
      medium: '500',
      semibold: '600',
      bold: '700',
    }
  },
  
  // Spacing
  spacing: {
    xs: '0.5rem',
    sm: '0.75rem',
    md: '1rem',
    lg: '1.5rem',
    xl: '2rem',
    '2xl': '3rem',
  },
  
  // Border Radius
  borderRadius: {
    sm: '0.375rem',
    md: '0.5rem',
    lg: '0.75rem',
    xl: '1rem',
  },
  
  // Shadows
  shadows: {
    sm: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
    md: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
    lg: '0 10px 15px -3px rgb(0 0 0 / 0.1)',
    xl: '0 20px 25px -5px rgb(0 0 0 / 0.1)',
  },
  
  // Component Styles
  components: {
    // Agent Cards
    agentCard: {
      background: 'linear-gradient(135deg, #1E293B 0%, #334155 100%)',
      border: '1px solid #475569',
      borderRadius: '0.75rem',
      padding: '1.5rem',
      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
    },
    
    // Workflow Cards
    workflowCard: {
      background: 'linear-gradient(135deg, #312E81 0%, #5B21B6 100%)',
      border: '1px solid #6366F1',
      borderRadius: '0.75rem',
      padding: '1.5rem',
      boxShadow: '0 10px 15px -3px rgb(0 0 0 / 0.1)',
    },
    
    // Tool Cards
    toolCard: {
      background: 'linear-gradient(135deg, #065F46 0%, #047857 100%)',
      border: '1px solid #10B981',
      borderRadius: '0.75rem',
      padding: '1rem',
      boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
    },
    
    // Status Indicators
    status: {
      active: '#10B981',
      inactive: '#6B7280',
      running: '#3B82F6',
      completed: '#10B981',
      failed: '#EF4444',
      pending: '#F59E0B',
    }
  },
  
  // Animation
  animation: {
    duration: {
      fast: '150ms',
      normal: '300ms',
      slow: '500ms',
    },
    easing: {
      default: 'cubic-bezier(0.4, 0, 0.2, 1)',
      in: 'cubic-bezier(0.4, 0, 1, 1)',
      out: 'cubic-bezier(0, 0, 0.2, 1)',
    }
  }
};

// Brand Configuration
export const brandConfig = {
  name: 'Agentic Flow',
  tagline: 'AI Orchestration Platform',
  description: 'Multi-agent coordination and workflow automation',
  version: '2.0.0',
  
  // Logo Configuration
  logo: {
    text: '🤖 Agentic Flow',
    icon: '🤖',
    colors: {
      primary: '#2563EB',
      secondary: '#7C3AED',
    }
  },
  
  // Navigation
  navigation: {
    primary: [
      { name: 'Dashboard', path: '/', icon: '📊' },
      { name: 'Agents', path: '/agents', icon: '🤖' },
      { name: 'Workflows', path: '/workflows', icon: '🔄' },
      { name: 'Tools', path: '/tools', icon: '🛠️' },
      { name: 'Teams', path: '/teams', icon: '👥' },
      { name: 'Monitor', path: '/monitor', icon: '📈' },
    ],
    secondary: [
      { name: 'Settings', path: '/settings', icon: '⚙️' },
      { name: 'Documentation', path: '/docs', icon: '📖' },
      { name: 'API', path: '/api', icon: '🔗' },
    ]
  },
  
  // Feature Highlights
  features: [
    {
      title: 'Multi-Agent Coordination',
      description: 'Coordinate multiple AI agents for complex tasks',
      icon: '🤖',
      color: '#3B82F6'
    },
    {
      title: 'Visual Workflows',
      description: 'Design and execute workflows visually',
      icon: '🔄', 
      color: '#8B5CF6'
    },
    {
      title: 'Real-time Monitoring',
      description: 'Monitor system health and performance',
      icon: '📊',
      color: '#10B981'
    },
    {
      title: 'Team Management',
      description: 'Form and manage agent teams dynamically',
      icon: '👥',
      color: '#F59E0B'
    }
  ],
  
  // Integration Points
  integrations: {
    claudeFlow: {
      name: 'Claude Flow',
      description: 'Advanced Claude agent coordination',
      icon: '🧠',
      color: '#FF6B35'
    },
    hiveMind: {
      name: 'Hive Mind',
      description: 'Collective intelligence system', 
      icon: '🐝',
      color: '#FFD23F'
    },
    ruvSwarm: {
      name: 'RUV Swarm',
      description: 'Distributed agent swarms',
      icon: '🔥',
      color: '#EE4266'
    }
  }
};

export default { agenticFlowTheme, brandConfig };