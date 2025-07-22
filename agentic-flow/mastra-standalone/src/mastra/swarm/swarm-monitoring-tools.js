/**
 * Swarm Monitoring Tools
 * Real-time monitoring and analytics tools for concurrent swarm operations
 */

import { createTool } from '@mastra/core';
import { z } from 'zod';
import { SwarmMonitor } from './swarm-monitor.js';
import { ConcurrentSwarmDemo } from './concurrent-swarm-demo.js';

// Global monitor instance
let globalMonitor = null;
let activeSwarmDemo = null;

// Initialize swarm monitor
export const initializeSwarmMonitor = createTool({
  id: 'initialize-swarm-monitor',
  name: 'Initialize Swarm Monitor',
  description: 'Initialize real-time monitoring system for concurrent swarms',
  inputSchema: z.object({
    enableDashboard: z.boolean().default(true),
    alertThresholds: z.object({
      efficiency: z.number().default(70),
      taskBacklog: z.number().default(10),
      errorRate: z.number().default(5)
    }).optional()
  }),
  execute: async ({ context }) => {
    const { enableDashboard, alertThresholds } = context;
    
    // Create monitor instance
    globalMonitor = new SwarmMonitor();
    
    // Apply custom thresholds if provided
    if (alertThresholds) {
      globalMonitor.thresholds.efficiency.warning = alertThresholds.efficiency;
      globalMonitor.thresholds.taskBacklog.warning = alertThresholds.taskBacklog;
      globalMonitor.thresholds.errorRate.warning = alertThresholds.errorRate;
    }
    
    // Initialize monitor
    await globalMonitor.initialize();
    
    return {
      success: true,
      monitorId: `monitor_${Date.now()}`,
      dashboardEnabled: enableDashboard,
      thresholds: globalMonitor.thresholds,
      message: 'Swarm monitor initialized successfully'
    };
  }
});

// Launch concurrent swarm demo
export const launchConcurrentSwarmDemo = createTool({
  id: 'launch-concurrent-swarm-demo',
  name: 'Launch Concurrent Swarm Demo',
  description: 'Launch a demonstration of multiple concurrent swarms with different missions',
  inputSchema: z.object({
    autoMonitor: z.boolean().default(true)
  }),
  execute: async ({ context }) => {
    const { autoMonitor } = context;
    
    // Create new swarm demo instance
    activeSwarmDemo = new ConcurrentSwarmDemo();
    
    // Use the demo's monitor if auto-monitoring is enabled
    if (autoMonitor && !globalMonitor) {
      globalMonitor = activeSwarmDemo.monitor;
    }
    
    // Launch the demo
    console.log('🚀 Launching concurrent swarm demonstration...');
    
    // Run in background
    activeSwarmDemo.launch().catch(error => {
      console.error('Swarm demo error:', error);
    });
    
    // Wait a moment for initialization
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    return {
      success: true,
      demoId: `demo_${Date.now()}`,
      activeSwarms: activeSwarmDemo.swarms.size,
      totalAgents: activeSwarmDemo.metrics.totalAgents,
      message: 'Concurrent swarm demonstration launched successfully'
    };
  }
});

// Get swarm performance metrics
export const getSwarmPerformanceMetrics = createTool({
  id: 'get-swarm-performance-metrics',
  name: 'Get Swarm Performance Metrics',
  description: 'Retrieve real-time performance metrics for all active swarms',
  inputSchema: z.object({
    includeHistory: z.boolean().default(false),
    swarmId: z.string().optional()
  }),
  execute: async ({ context }) => {
    const { includeHistory, swarmId } = context;
    
    if (!globalMonitor || !activeSwarmDemo) {
      return {
        success: false,
        error: 'No active swarm monitoring session',
        metrics: null
      };
    }
    
    // Collect current metrics
    globalMonitor.collectMetrics(activeSwarmDemo.swarms, activeSwarmDemo.metrics);
    
    const performanceMetrics = globalMonitor.metrics.get('swarm-performance');
    const currentMetrics = {};
    
    // Filter by swarmId if provided
    if (swarmId) {
      const swarmMetrics = performanceMetrics.current.get(swarmId);
      if (swarmMetrics) {
        currentMetrics[swarmId] = swarmMetrics;
      }
    } else {
      // Get all swarm metrics
      for (const [id, metrics] of performanceMetrics.current) {
        currentMetrics[id] = metrics;
      }
    }
    
    const response = {
      success: true,
      timestamp: Date.now(),
      currentMetrics,
      aggregates: performanceMetrics.aggregates,
      globalMetrics: activeSwarmDemo.metrics
    };
    
    if (includeHistory) {
      response.history = globalMonitor.performanceHistory.slice(-10);
    }
    
    return response;
  }
});

// Analyze swarm patterns
export const analyzeSwarmPatterns = createTool({
  id: 'analyze-swarm-patterns',
  name: 'Analyze Swarm Patterns',
  description: 'Analyze behavioral patterns and performance trends across swarms',
  inputSchema: z.object({
    analysisType: z.enum(['efficiency', 'collaboration', 'bottlenecks', 'comprehensive']).default('comprehensive'),
    timeframe: z.number().default(60000) // Default to last minute
  }),
  execute: async ({ context }) => {
    const { analysisType, timeframe } = context;
    
    if (!globalMonitor || !activeSwarmDemo) {
      return {
        success: false,
        error: 'No active swarm monitoring session',
        analysis: null
      };
    }
    
    // Get recent history within timeframe
    const currentTime = Date.now();
    const recentHistory = globalMonitor.performanceHistory.filter(
      snapshot => (currentTime - snapshot.timestamp) <= timeframe
    );
    
    const analysis = {
      analysisType,
      timeframe,
      dataPoints: recentHistory.length,
      patterns: []
    };
    
    // Analyze based on type
    switch (analysisType) {
      case 'efficiency':
        analysis.patterns = analyzeEfficiencyPatterns(recentHistory);
        break;
      case 'collaboration':
        analysis.patterns = analyzeCollaborationPatterns(activeSwarmDemo.swarms);
        break;
      case 'bottlenecks':
        analysis.patterns = analyzeBottlenecks(recentHistory, activeSwarmDemo.swarms);
        break;
      case 'comprehensive':
        analysis.patterns = [
          ...analyzeEfficiencyPatterns(recentHistory),
          ...analyzeCollaborationPatterns(activeSwarmDemo.swarms),
          ...analyzeBottlenecks(recentHistory, activeSwarmDemo.swarms)
        ];
        break;
    }
    
    // Add recommendations
    analysis.recommendations = generatePatternRecommendations(analysis.patterns);
    
    return {
      success: true,
      analysis,
      trends: globalMonitor.analyzeTrends()
    };
  }
});

// Get swarm alerts
export const getSwarmAlerts = createTool({
  id: 'get-swarm-alerts',
  name: 'Get Swarm Alerts',
  description: 'Retrieve active alerts and warnings from swarm monitoring',
  inputSchema: z.object({
    severity: z.enum(['all', 'warning', 'critical']).default('all'),
    limit: z.number().default(10)
  }),
  execute: async ({ context }) => {
    const { severity, limit } = context;
    
    if (!globalMonitor) {
      return {
        success: false,
        error: 'No active swarm monitoring session',
        alerts: []
      };
    }
    
    let alerts = globalMonitor.alerts;
    
    // Filter by severity
    if (severity !== 'all') {
      alerts = alerts.filter(alert => alert.severity === severity);
    }
    
    // Sort by timestamp (most recent first)
    alerts.sort((a, b) => b.timestamp - a.timestamp);
    
    // Apply limit
    alerts = alerts.slice(0, limit);
    
    return {
      success: true,
      totalAlerts: globalMonitor.alerts.length,
      filteredCount: alerts.length,
      alerts,
      alertSummary: {
        critical: globalMonitor.alerts.filter(a => a.severity === 'critical').length,
        warning: globalMonitor.alerts.filter(a => a.severity === 'warning').length
      }
    };
  }
});

// Generate swarm performance report
export const generateSwarmPerformanceReport = createTool({
  id: 'generate-swarm-performance-report',
  name: 'Generate Swarm Performance Report',
  description: 'Generate comprehensive performance report for concurrent swarms',
  inputSchema: z.object({
    format: z.enum(['summary', 'detailed', 'executive']).default('summary'),
    includeRecommendations: z.boolean().default(true)
  }),
  execute: async ({ context }) => {
    const { format, includeRecommendations } = context;
    
    if (!globalMonitor || !activeSwarmDemo) {
      return {
        success: false,
        error: 'No active swarm monitoring session',
        report: null
      };
    }
    
    // Collect final insights
    const insights = await activeSwarmDemo.coordinator.collectGlobalInsights(activeSwarmDemo.swarms);
    
    // Generate report
    const fullReport = globalMonitor.generateFinalReport(
      activeSwarmDemo.swarms,
      activeSwarmDemo.metrics,
      insights
    );
    
    let report = {};
    
    switch (format) {
      case 'summary':
        report = {
          summary: fullReport.summary,
          overallEfficiency: calculateOverallEfficiency(fullReport.swarmPerformance),
          keyMetrics: {
            tasksCompleted: fullReport.summary.totalTasksCompleted,
            swarmSyncs: fullReport.summary.swarmSynchronizations,
            errorsRecovered: fullReport.summary.errorsRecovered
          }
        };
        break;
        
      case 'detailed':
        report = fullReport;
        break;
        
      case 'executive':
        report = {
          executiveSummary: generateExecutiveSummary(fullReport),
          criticalAlerts: fullReport.alerts.filter(a => a.severity === 'critical').length,
          performance: {
            overall: calculateOverallEfficiency(fullReport.swarmPerformance),
            bySwarm: fullReport.swarmPerformance.map(s => ({
              name: s.name,
              efficiency: s.efficiency
            }))
          }
        };
        break;
    }
    
    if (includeRecommendations) {
      report.recommendations = fullReport.recommendations;
    }
    
    return {
      success: true,
      format,
      generatedAt: new Date().toISOString(),
      report
    };
  }
});

// Helper functions
function analyzeEfficiencyPatterns(history) {
  const patterns = [];
  
  if (history.length < 2) return patterns;
  
  // Check for declining efficiency
  const efficiencies = history.map(h => {
    const swarmEffs = Array.from(h.swarms.values()).map(s => s.efficiency);
    return swarmEffs.reduce((a, b) => a + b, 0) / swarmEffs.length;
  });
  
  const trend = calculateTrend(efficiencies);
  if (trend < -0.1) {
    patterns.push({
      type: 'declining_efficiency',
      severity: 'warning',
      description: 'Overall swarm efficiency is declining',
      value: `${(trend * 100).toFixed(2)}% per minute`
    });
  }
  
  return patterns;
}

function analyzeCollaborationPatterns(swarms) {
  const patterns = [];
  
  // Analyze message exchange patterns
  let totalMessages = 0;
  swarms.forEach(swarm => {
    totalMessages += swarm.metrics.tasksCompleted * 2; // Estimated messages per task
  });
  
  if (totalMessages > 1000) {
    patterns.push({
      type: 'high_communication',
      severity: 'info',
      description: 'High inter-swarm communication detected',
      value: `${totalMessages} messages exchanged`
    });
  }
  
  return patterns;
}

function analyzeBottlenecks(history, swarms) {
  const patterns = [];
  
  // Check for task backlog
  swarms.forEach(swarm => {
    const backlog = swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted;
    if (backlog > 10) {
      patterns.push({
        type: 'task_backlog',
        severity: 'warning',
        description: `High task backlog in ${swarm.mission.name}`,
        value: `${backlog} pending tasks`
      });
    }
  });
  
  return patterns;
}

function generatePatternRecommendations(patterns) {
  const recommendations = [];
  
  patterns.forEach(pattern => {
    switch (pattern.type) {
      case 'declining_efficiency':
        recommendations.push('Consider scaling agent resources or optimizing task distribution');
        break;
      case 'task_backlog':
        recommendations.push('Increase agent capacity or redistribute tasks to less loaded swarms');
        break;
      case 'high_communication':
        recommendations.push('Optimize communication protocols to reduce message overhead');
        break;
    }
  });
  
  return [...new Set(recommendations)]; // Remove duplicates
}

function calculateTrend(values) {
  if (values.length < 2) return 0;
  
  const n = values.length;
  const sumX = (n * (n - 1)) / 2;
  const sumY = values.reduce((a, b) => a + b, 0);
  const sumXY = values.reduce((sum, y, x) => sum + x * y, 0);
  const sumX2 = (n * (n - 1) * (2 * n - 1)) / 6;
  
  return (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
}

function calculateOverallEfficiency(swarmPerformance) {
  if (!swarmPerformance || swarmPerformance.length === 0) return 0;
  
  const totalEfficiency = swarmPerformance.reduce((sum, s) => sum + s.efficiency, 0);
  return (totalEfficiency / swarmPerformance.length).toFixed(2);
}

function generateExecutiveSummary(report) {
  return `Concurrent swarm operations completed with ${report.swarmPerformance.length} active swarms. ` +
         `Total of ${report.summary.totalAgents} agents completed ${report.summary.totalTasksCompleted} tasks. ` +
         `System recovered from ${report.summary.errorsRecovered} errors with ${report.alerts.length} alerts generated.`;
}

// Export swarm monitoring tools
export const swarmMonitoringTools = {
  initializeSwarmMonitor,
  launchConcurrentSwarmDemo,
  getSwarmPerformanceMetrics,
  analyzeSwarmPatterns,
  getSwarmAlerts,
  generateSwarmPerformanceReport
};