#!/usr/bin/env node

const express = require('express');
const promClient = require('prom-client');
const winston = require('winston');

// Create Express app for metrics endpoint
const app = express();
const PORT = process.env.MONITORING_PORT || 9090;

// Configure Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'agentic-flow-monitoring' },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ filename: 'logs/monitoring.log' })
  ]
});

// Create a Registry to register the metrics
const register = new promClient.Registry();

// Add default metrics
promClient.collectDefaultMetrics({
  register,
  prefix: 'agentic_flow_',
});

// Custom metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'agentic_flow_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
});

const httpRequestsTotal = new promClient.Counter({
  name: 'agentic_flow_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

const activeConnections = new promClient.Gauge({
  name: 'agentic_flow_active_connections',
  help: 'Number of active connections'
});

const workflowExecutions = new promClient.Counter({
  name: 'agentic_flow_workflow_executions_total',
  help: 'Total number of workflow executions',
  labelNames: ['workflow_type', 'status']
});

const workflowDuration = new promClient.Histogram({
  name: 'agentic_flow_workflow_duration_seconds',
  help: 'Duration of workflow executions in seconds',
  labelNames: ['workflow_type'],
  buckets: [1, 5, 10, 30, 60, 300, 600, 1800, 3600]
});

const memoryUsage = new promClient.Gauge({
  name: 'agentic_flow_memory_usage_bytes',
  help: 'Memory usage in bytes',
  labelNames: ['type']
});

const queueSize = new promClient.Gauge({
  name: 'agentic_flow_queue_size',
  help: 'Number of items in queue',
  labelNames: ['queue_name']
});

const errorRate = new promClient.Counter({
  name: 'agentic_flow_errors_total',
  help: 'Total number of errors',
  labelNames: ['type', 'severity']
});

// Register custom metrics
register.registerMetric(httpRequestDuration);
register.registerMetric(httpRequestsTotal);
register.registerMetric(activeConnections);
register.registerMetric(workflowExecutions);
register.registerMetric(workflowDuration);
register.registerMetric(memoryUsage);
register.registerMetric(queueSize);
register.registerMetric(errorRate);

// Middleware to track HTTP metrics
const trackHttpMetrics = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const route = req.route ? req.route.path : req.path;
    
    httpRequestDuration
      .labels(req.method, route, res.statusCode)
      .observe(duration);
    
    httpRequestsTotal
      .labels(req.method, route, res.statusCode)
      .inc();
  });
  
  next();
};

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    pid: process.pid
  });
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (ex) {
    res.status(500).end(ex);
  }
});

// Update system metrics periodically
const updateSystemMetrics = () => {
  const memUsage = process.memoryUsage();
  
  memoryUsage.labels('rss').set(memUsage.rss);
  memoryUsage.labels('heapTotal').set(memUsage.heapTotal);
  memoryUsage.labels('heapUsed').set(memUsage.heapUsed);
  memoryUsage.labels('external').set(memUsage.external);
  
  // Simulate queue metrics (replace with actual queue monitoring)
  queueSize.labels('main').set(Math.floor(Math.random() * 100));
  queueSize.labels('priority').set(Math.floor(Math.random() * 50));
  
  logger.debug('System metrics updated', {
    memory: memUsage,
    uptime: process.uptime()
  });
};

// Error handling
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  errorRate.labels('uncaught_exception', 'critical').inc();
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  errorRate.labels('unhandled_rejection', 'high').inc();
});

// Graceful shutdown
const gracefulShutdown = (signal) => {
  logger.info(`Received ${signal}. Shutting down gracefully...`);
  
  server.close(() => {
    logger.info('HTTP server closed.');
    process.exit(0);
  });
  
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start monitoring server
const server = app.listen(PORT, () => {
  logger.info(`Monitoring server started on port ${PORT}`);
  logger.info(`Metrics available at http://localhost:${PORT}/metrics`);
  logger.info(`Health check available at http://localhost:${PORT}/health`);
});

// Update metrics every 30 seconds
setInterval(updateSystemMetrics, 30000);

// Initial metrics update
updateSystemMetrics();

// Export for testing
module.exports = {
  app,
  register,
  logger,
  metrics: {
    httpRequestDuration,
    httpRequestsTotal,
    activeConnections,
    workflowExecutions,
    workflowDuration,
    memoryUsage,
    queueSize,
    errorRate
  }
};