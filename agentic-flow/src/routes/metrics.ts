import { Router } from 'express';
import promClient from 'prom-client';
import { config } from '../config';

export const metricsRouter = Router();

// Create a Registry to register the metrics
const register = new promClient.Registry();

// Add default metrics
promClient.collectDefaultMetrics({
  register,
  prefix: 'agentic_flow_',
});

// Custom metrics
const httpRequestsTotal = new promClient.Counter({
  name: 'agentic_flow_http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
});

const httpRequestDuration = new promClient.Histogram({
  name: 'agentic_flow_http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10],
});

// Register custom metrics
register.registerMetric(httpRequestsTotal);
register.registerMetric(httpRequestDuration);

// Metrics endpoint
metricsRouter.get('/', async (req, res) => {
  if (!config.monitoring.enabled) {
    return res.status(404).json({ error: 'Metrics disabled' });
  }

  try {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (error) {
    res.status(500).end(error);
  }
});

export { register, httpRequestsTotal, httpRequestDuration };