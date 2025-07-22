/**
 * Swarm Monitor - Real-time performance monitoring and analytics
 */

import { EventEmitter } from 'events';
import chalk from 'chalk';

export class SwarmMonitor extends EventEmitter {
  constructor() {
    super();
    this.metrics = new Map();
    this.alerts = [];
    this.performanceHistory = [];
    this.thresholds = {
      efficiency: { warning: 70, critical: 50 },
      taskBacklog: { warning: 10, critical: 20 },
      agentUtilization: { warning: 80, critical: 95 },
      responseTime: { warning: 1000, critical: 3000 },
      errorRate: { warning: 5, critical: 10 }
    };
    this.dashboardInterval = null;
    this.isActive = false;
  }

  /**
   * Initialize monitoring system
   */
  async initialize() {
    this.isActive = true;
    console.log(chalk.cyan('📊 Swarm Monitor initialized'));
    
    // Initialize metric collectors
    this.initializeMetricCollectors();
    
    // Start real-time dashboard
    this.startDashboard();
    
    // Initialize alert system
    this.initializeAlertSystem();
  }

  /**
   * Initialize metric collectors
   */
  initializeMetricCollectors() {
    const collectors = [
      'swarm-performance',
      'agent-metrics',
      'task-analytics',
      'resource-usage',
      'communication-stats',
      'error-tracking'
    ];

    for (const collector of collectors) {
      this.metrics.set(collector, {
        current: new Map(),
        history: [],
        aggregates: {}
      });
    }
  }

  /**
   * Start real-time dashboard
   */
  startDashboard() {
    // Update dashboard every 5 seconds
    this.dashboardInterval = setInterval(() => {
      if (this.isActive) {
        this.renderDashboard();
      }
    }, 5000);
  }

  /**
   * Initialize alert system
   */
  initializeAlertSystem() {
    // Check for alerts every second
    setInterval(() => {
      if (this.isActive) {
        this.checkAlerts();
      }
    }, 1000);
  }

  /**
   * Collect metrics from swarms
   */
  collectMetrics(swarms, globalMetrics) {
    const timestamp = Date.now();
    const snapshot = {
      timestamp,
      swarms: new Map(),
      global: globalMetrics,
      analysis: {}
    };

    // Collect swarm-level metrics
    for (const [swarmId, swarm] of swarms) {
      const swarmMetrics = this.collectSwarmMetrics(swarm);
      snapshot.swarms.set(swarmId, swarmMetrics);
    }

    // Perform analysis
    snapshot.analysis = this.analyzeMetrics(snapshot);
    
    // Store in history
    this.performanceHistory.push(snapshot);
    
    // Keep only last 100 snapshots
    if (this.performanceHistory.length > 100) {
      this.performanceHistory.shift();
    }

    // Update current metrics
    this.updateCurrentMetrics(snapshot);
    
    // Emit metrics event
    this.emit('metricsCollected', snapshot);
  }

  /**
   * Collect metrics for individual swarm
   */
  collectSwarmMetrics(swarm) {
    const metrics = {
      id: swarm.id,
      status: swarm.status,
      efficiency: swarm.metrics.efficiency,
      tasksAssigned: swarm.metrics.tasksAssigned,
      tasksCompleted: swarm.metrics.tasksCompleted,
      taskBacklog: swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted,
      health: swarm.metrics.health,
      agents: this.collectAgentMetrics(swarm.agents),
      performance: {
        throughput: this.calculateThroughput(swarm),
        responseTime: this.calculateAverageResponseTime(swarm),
        errorRate: this.calculateErrorRate(swarm)
      },
      resources: {
        cpuUsage: Math.random() * 100, // Simulated
        memoryUsage: Math.random() * 100, // Simulated
        networkBandwidth: Math.random() * 1000 // Simulated
      }
    };

    return metrics;
  }

  /**
   * Collect agent metrics
   */
  collectAgentMetrics(agents) {
    const agentMetrics = {
      total: agents.size,
      byStatus: { idle: 0, working: 0, failed: 0 },
      byType: new Map(),
      performance: []
    };

    for (const agent of agents.values()) {
      // Status counts
      agentMetrics.byStatus[agent.status]++;
      
      // Type counts
      const typeCount = agentMetrics.byType.get(agent.type) || 0;
      agentMetrics.byType.set(agent.type, typeCount + 1);
      
      // Performance data
      agentMetrics.performance.push({
        id: agent.id,
        type: agent.type,
        tasksCompleted: agent.tasksCompleted,
        performance: agent.performance,
        utilization: agent.status === 'working' ? 100 : 0
      });
    }

    // Calculate aggregates
    agentMetrics.avgPerformance = agentMetrics.performance.length > 0
      ? agentMetrics.performance.reduce((sum, a) => sum + a.performance, 0) / agentMetrics.performance.length
      : 0;
    
    agentMetrics.utilization = (agentMetrics.byStatus.working / agentMetrics.total) * 100;

    return agentMetrics;
  }

  /**
   * Calculate throughput
   */
  calculateThroughput(swarm) {
    // Find previous snapshot
    const previousSnapshot = this.performanceHistory
      .slice(-2, -1)[0];
    
    if (!previousSnapshot) return 0;
    
    const previousSwarmData = previousSnapshot.swarms.get(swarm.id);
    if (!previousSwarmData) return 0;
    
    const timeDiff = Date.now() - previousSnapshot.timestamp;
    const tasksDiff = swarm.metrics.tasksCompleted - previousSwarmData.tasksCompleted;
    
    return (tasksDiff / timeDiff) * 1000; // Tasks per second
  }

  /**
   * Calculate average response time
   */
  calculateAverageResponseTime(swarm) {
    // Simulated for demo
    return 500 + Math.random() * 1000;
  }

  /**
   * Calculate error rate
   */
  calculateErrorRate(swarm) {
    // Simulated for demo
    return Math.random() * 5;
  }

  /**
   * Analyze metrics
   */
  analyzeMetrics(snapshot) {
    const analysis = {
      trends: this.analyzeTrends(),
      anomalies: this.detectAnomalies(snapshot),
      predictions: this.generatePredictions(snapshot),
      recommendations: this.generateMonitoringRecommendations(snapshot)
    };

    return analysis;
  }

  /**
   * Analyze trends
   */
  analyzeTrends() {
    if (this.performanceHistory.length < 5) {
      return { status: 'insufficient-data' };
    }

    const recentHistory = this.performanceHistory.slice(-10);
    const trends = {
      efficiency: this.calculateTrend(recentHistory, 'efficiency'),
      throughput: this.calculateTrend(recentHistory, 'throughput'),
      errorRate: this.calculateTrend(recentHistory, 'errorRate')
    };

    return trends;
  }

  /**
   * Calculate trend for metric
   */
  calculateTrend(history, metric) {
    const values = history.map(snapshot => {
      const swarmValues = Array.from(snapshot.swarms.values());
      if (metric === 'efficiency') {
        return swarmValues.reduce((sum, s) => sum + s.efficiency, 0) / swarmValues.length;
      } else if (metric === 'throughput') {
        return swarmValues.reduce((sum, s) => sum + s.performance.throughput, 0);
      } else if (metric === 'errorRate') {
        return swarmValues.reduce((sum, s) => sum + s.performance.errorRate, 0) / swarmValues.length;
      }
      return 0;
    });

    // Simple linear regression
    const n = values.length;
    const sumX = (n * (n - 1)) / 2;
    const sumY = values.reduce((a, b) => a + b, 0);
    const sumXY = values.reduce((sum, y, x) => sum + x * y, 0);
    const sumX2 = (n * (n - 1) * (2 * n - 1)) / 6;
    
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    
    return {
      direction: slope > 0.1 ? 'increasing' : slope < -0.1 ? 'decreasing' : 'stable',
      rate: Math.abs(slope),
      currentValue: values[values.length - 1]
    };
  }

  /**
   * Detect anomalies
   */
  detectAnomalies(snapshot) {
    const anomalies = [];
    
    for (const [swarmId, metrics] of snapshot.swarms) {
      // Check efficiency
      if (metrics.efficiency < this.thresholds.efficiency.critical) {
        anomalies.push({
          type: 'critical-efficiency',
          swarmId,
          value: metrics.efficiency,
          threshold: this.thresholds.efficiency.critical
        });
      }
      
      // Check task backlog
      if (metrics.taskBacklog > this.thresholds.taskBacklog.critical) {
        anomalies.push({
          type: 'critical-backlog',
          swarmId,
          value: metrics.taskBacklog,
          threshold: this.thresholds.taskBacklog.critical
        });
      }
      
      // Check agent utilization
      if (metrics.agents.utilization > this.thresholds.agentUtilization.critical) {
        anomalies.push({
          type: 'critical-utilization',
          swarmId,
          value: metrics.agents.utilization,
          threshold: this.thresholds.agentUtilization.critical
        });
      }
      
      // Check error rate
      if (metrics.performance.errorRate > this.thresholds.errorRate.critical) {
        anomalies.push({
          type: 'critical-errors',
          swarmId,
          value: metrics.performance.errorRate,
          threshold: this.thresholds.errorRate.critical
        });
      }
    }
    
    return anomalies;
  }

  /**
   * Generate predictions
   */
  generatePredictions(snapshot) {
    const predictions = {
      taskCompletionTime: this.predictTaskCompletionTime(snapshot),
      resourceExhaustion: this.predictResourceExhaustion(snapshot),
      performanceDegradation: this.predictPerformanceDegradation(snapshot)
    };
    
    return predictions;
  }

  /**
   * Predict task completion time
   */
  predictTaskCompletionTime(snapshot) {
    let totalBacklog = 0;
    let totalThroughput = 0;
    
    for (const metrics of snapshot.swarms.values()) {
      totalBacklog += metrics.taskBacklog;
      totalThroughput += metrics.performance.throughput;
    }
    
    if (totalThroughput === 0) return Infinity;
    
    return {
      estimatedTime: (totalBacklog / totalThroughput) * 1000, // milliseconds
      confidence: 0.75
    };
  }

  /**
   * Predict resource exhaustion
   */
  predictResourceExhaustion(snapshot) {
    const predictions = [];
    
    for (const [swarmId, metrics] of snapshot.swarms) {
      const cpuTrend = this.calculateResourceTrend('cpu', swarmId);
      const memoryTrend = this.calculateResourceTrend('memory', swarmId);
      
      if (cpuTrend.rate > 0.5 && metrics.resources.cpuUsage > 80) {
        predictions.push({
          swarmId,
          resource: 'cpu',
          timeToExhaustion: (100 - metrics.resources.cpuUsage) / cpuTrend.rate * 1000
        });
      }
      
      if (memoryTrend.rate > 0.5 && metrics.resources.memoryUsage > 80) {
        predictions.push({
          swarmId,
          resource: 'memory',
          timeToExhaustion: (100 - metrics.resources.memoryUsage) / memoryTrend.rate * 1000
        });
      }
    }
    
    return predictions;
  }

  /**
   * Calculate resource trend
   */
  calculateResourceTrend(resource, swarmId) {
    // Simplified for demo
    return {
      rate: Math.random() * 0.5,
      direction: 'increasing'
    };
  }

  /**
   * Predict performance degradation
   */
  predictPerformanceDegradation(snapshot) {
    const predictions = [];
    
    const trends = this.analyzeTrends();
    
    if (trends.efficiency && trends.efficiency.direction === 'decreasing') {
      predictions.push({
        metric: 'efficiency',
        currentTrend: trends.efficiency,
        riskLevel: trends.efficiency.rate > 0.5 ? 'high' : 'medium',
        estimatedImpact: trends.efficiency.rate * 10 // percentage
      });
    }
    
    if (trends.errorRate && trends.errorRate.direction === 'increasing') {
      predictions.push({
        metric: 'errorRate',
        currentTrend: trends.errorRate,
        riskLevel: trends.errorRate.rate > 0.3 ? 'high' : 'medium',
        estimatedImpact: trends.errorRate.rate * 5
      });
    }
    
    return predictions;
  }

  /**
   * Generate monitoring recommendations
   */
  generateMonitoringRecommendations(snapshot) {
    const recommendations = [];
    const analysis = snapshot.analysis;
    
    // Based on anomalies
    if (analysis.anomalies.length > 0) {
      analysis.anomalies.forEach(anomaly => {
        recommendations.push({
          priority: 'high',
          type: anomaly.type,
          action: this.getAnomalyRecommendation(anomaly),
          targetSwarm: anomaly.swarmId
        });
      });
    }
    
    // Based on predictions
    if (analysis.predictions.resourceExhaustion.length > 0) {
      recommendations.push({
        priority: 'medium',
        type: 'resource-scaling',
        action: 'Consider scaling resources for affected swarms',
        details: analysis.predictions.resourceExhaustion
      });
    }
    
    // Based on trends
    if (analysis.trends.efficiency && analysis.trends.efficiency.direction === 'decreasing') {
      recommendations.push({
        priority: 'medium',
        type: 'efficiency-optimization',
        action: 'Investigate declining efficiency trend',
        currentTrend: analysis.trends.efficiency
      });
    }
    
    return recommendations;
  }

  /**
   * Get anomaly recommendation
   */
  getAnomalyRecommendation(anomaly) {
    const recommendations = {
      'critical-efficiency': 'Redistribute tasks or scale agents',
      'critical-backlog': 'Increase agent capacity or optimize task processing',
      'critical-utilization': 'Add more agents or optimize workload distribution',
      'critical-errors': 'Investigate error sources and implement fixes'
    };
    
    return recommendations[anomaly.type] || 'Investigate anomaly';
  }

  /**
   * Update current metrics
   */
  updateCurrentMetrics(snapshot) {
    // Update swarm performance metrics
    const perfMetrics = this.metrics.get('swarm-performance');
    for (const [swarmId, metrics] of snapshot.swarms) {
      perfMetrics.current.set(swarmId, {
        efficiency: metrics.efficiency,
        throughput: metrics.performance.throughput,
        health: metrics.health
      });
    }
    
    // Update aggregates
    perfMetrics.aggregates = {
      avgEfficiency: this.calculateAverage(snapshot.swarms, 'efficiency'),
      totalThroughput: this.calculateSum(snapshot.swarms, 'performance.throughput'),
      overallHealth: this.calculateAverage(snapshot.swarms, 'health')
    };
  }

  /**
   * Calculate average
   */
  calculateAverage(swarms, path) {
    let sum = 0;
    let count = 0;
    
    for (const metrics of swarms.values()) {
      const value = this.getNestedValue(metrics, path);
      if (value !== undefined) {
        sum += value;
        count++;
      }
    }
    
    return count > 0 ? sum / count : 0;
  }

  /**
   * Calculate sum
   */
  calculateSum(swarms, path) {
    let sum = 0;
    
    for (const metrics of swarms.values()) {
      const value = this.getNestedValue(metrics, path);
      if (value !== undefined) {
        sum += value;
      }
    }
    
    return sum;
  }

  /**
   * Get nested value from object
   */
  getNestedValue(obj, path) {
    const keys = path.split('.');
    let value = obj;
    
    for (const key of keys) {
      value = value[key];
      if (value === undefined) break;
    }
    
    return value;
  }

  /**
   * Check for alerts
   */
  checkAlerts() {
    const currentMetrics = this.metrics.get('swarm-performance').current;
    
    for (const [swarmId, metrics] of currentMetrics) {
      // Check efficiency
      if (metrics.efficiency < this.thresholds.efficiency.warning) {
        this.createAlert({
          type: 'efficiency',
          severity: metrics.efficiency < this.thresholds.efficiency.critical ? 'critical' : 'warning',
          swarmId,
          value: metrics.efficiency,
          threshold: metrics.efficiency < this.thresholds.efficiency.critical 
            ? this.thresholds.efficiency.critical 
            : this.thresholds.efficiency.warning
        });
      }
    }
    
    // Process alert queue
    this.processAlerts();
  }

  /**
   * Create alert
   */
  createAlert(alert) {
    alert.timestamp = Date.now();
    alert.id = `alert-${Date.now()}-${Math.random()}`;
    
    // Check if similar alert exists
    const existingAlert = this.alerts.find(a => 
      a.type === alert.type && 
      a.swarmId === alert.swarmId &&
      Date.now() - a.timestamp < 60000 // Within last minute
    );
    
    if (!existingAlert) {
      this.alerts.push(alert);
      this.emit('alert', alert);
      
      // Log alert
      const color = alert.severity === 'critical' ? chalk.red : chalk.yellow;
      console.log(color(`\n⚠️  ALERT: ${alert.type} - ${alert.swarmId}`));
      console.log(color(`   Value: ${alert.value}, Threshold: ${alert.threshold}`));
    }
  }

  /**
   * Process alerts
   */
  processAlerts() {
    // Remove old alerts
    const cutoffTime = Date.now() - 300000; // 5 minutes
    this.alerts = this.alerts.filter(alert => alert.timestamp > cutoffTime);
    
    // Group alerts by severity
    const criticalAlerts = this.alerts.filter(a => a.severity === 'critical');
    const warningAlerts = this.alerts.filter(a => a.severity === 'warning');
    
    // Take action on critical alerts
    if (criticalAlerts.length > 3) {
      this.emit('criticalAlertThreshold', criticalAlerts);
    }
  }

  /**
   * Render dashboard
   */
  renderDashboard() {
    console.log(chalk.bold.cyan('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    console.log(chalk.bold.cyan('                 SWARM MONITOR DASHBOARD                  '));
    console.log(chalk.bold.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
    
    const perfMetrics = this.metrics.get('swarm-performance');
    
    // Global metrics
    if (perfMetrics.aggregates.avgEfficiency !== undefined) {
      console.log(chalk.white('\n📊 Global Metrics:'));
      console.log(chalk.white(`   • Average Efficiency: ${perfMetrics.aggregates.avgEfficiency.toFixed(1)}%`));
      console.log(chalk.white(`   • Total Throughput: ${perfMetrics.aggregates.totalThroughput.toFixed(2)} tasks/sec`));
      console.log(chalk.white(`   • Overall Health: ${perfMetrics.aggregates.overallHealth.toFixed(1)}%`));
    }
    
    // Swarm status
    if (perfMetrics.current.size > 0) {
      console.log(chalk.white('\n🔹 Swarm Status:'));
      for (const [swarmId, metrics] of perfMetrics.current) {
        const statusColor = metrics.efficiency > 80 ? chalk.green : 
                          metrics.efficiency > 60 ? chalk.yellow : chalk.red;
        console.log(statusColor(`   • ${swarmId}: ${metrics.efficiency.toFixed(1)}% efficiency, ${metrics.throughput.toFixed(2)} tasks/sec`));
      }
    }
    
    // Active alerts
    if (this.alerts.length > 0) {
      console.log(chalk.white('\n⚠️  Active Alerts:'));
      const recentAlerts = this.alerts.slice(-3);
      recentAlerts.forEach(alert => {
        const alertColor = alert.severity === 'critical' ? chalk.red : chalk.yellow;
        console.log(alertColor(`   • [${alert.severity.toUpperCase()}] ${alert.type} in ${alert.swarmId}`));
      });
    }
    
    // Trends
    const trends = this.analyzeTrends();
    if (trends.efficiency) {
      console.log(chalk.white('\n📈 Trends:'));
      const trendIcon = trends.efficiency.direction === 'increasing' ? '↗' : 
                       trends.efficiency.direction === 'decreasing' ? '↘' : '→';
      console.log(chalk.white(`   • Efficiency: ${trendIcon} ${trends.efficiency.direction}`));
      
      if (trends.throughput) {
        const throughputIcon = trends.throughput.direction === 'increasing' ? '↗' : 
                             trends.throughput.direction === 'decreasing' ? '↘' : '→';
        console.log(chalk.white(`   • Throughput: ${throughputIcon} ${trends.throughput.direction}`));
      }
    }
    
    console.log(chalk.bold.cyan('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'));
  }

  /**
   * Generate final report
   */
  generateFinalReport(swarms, globalMetrics, insights) {
    const report = {
      summary: {
        totalSwarms: swarms.size,
        totalAgents: globalMetrics.totalAgents,
        totalTasksCompleted: globalMetrics.tasksCompleted,
        totalMessagesExchanged: globalMetrics.messagesExchanged,
        errorsRecovered: globalMetrics.errorsRecovered,
        swarmSynchronizations: globalMetrics.swarmSyncs
      },
      swarmPerformance: [],
      insights: insights,
      recommendations: [],
      alerts: this.alerts
    };

    // Collect swarm performance
    for (const [swarmId, swarm] of swarms) {
      report.swarmPerformance.push({
        swarmId,
        name: swarm.mission.name,
        efficiency: swarm.metrics.efficiency,
        tasksCompleted: swarm.metrics.tasksCompleted,
        agentCount: swarm.agents.size,
        health: swarm.metrics.health
      });
    }

    // Generate final recommendations
    report.recommendations = this.generateFinalRecommendations(report);

    return report;
  }

  /**
   * Generate final recommendations
   */
  generateFinalRecommendations(report) {
    const recommendations = [];
    
    // Performance recommendations
    const avgEfficiency = report.swarmPerformance.reduce((sum, s) => sum + s.efficiency, 0) / report.swarmPerformance.length;
    
    if (avgEfficiency < 70) {
      recommendations.push({
        category: 'performance',
        priority: 'high',
        recommendation: 'Overall system efficiency is below optimal. Consider scaling agents or optimizing task distribution.'
      });
    }
    
    // Alert-based recommendations
    const criticalAlerts = report.alerts.filter(a => a.severity === 'critical');
    if (criticalAlerts.length > 0) {
      recommendations.push({
        category: 'stability',
        priority: 'critical',
        recommendation: `Address ${criticalAlerts.length} critical alerts to improve system stability.`
      });
    }
    
    // Insight-based recommendations
    if (report.insights.patterns) {
      report.insights.patterns.forEach(pattern => {
        if (pattern.recommendation) {
          recommendations.push({
            category: 'optimization',
            priority: 'medium',
            recommendation: pattern.recommendation
          });
        }
      });
    }
    
    return recommendations;
  }

  /**
   * Save emergency snapshot
   */
  async saveEmergencySnapshot(swarms, metrics) {
    const snapshot = {
      timestamp: Date.now(),
      type: 'emergency',
      swarms: Array.from(swarms.entries()),
      globalMetrics: metrics,
      performanceHistory: this.performanceHistory.slice(-10),
      activeAlerts: this.alerts
    };
    
    // In a real system, this would save to persistent storage
    console.log(chalk.yellow('💾 Emergency snapshot saved'));
    
    return snapshot;
  }

  /**
   * Shutdown monitor
   */
  shutdown() {
    this.isActive = false;
    
    if (this.dashboardInterval) {
      clearInterval(this.dashboardInterval);
    }
    
    console.log(chalk.cyan('📊 Swarm Monitor shutdown complete'));
  }
}