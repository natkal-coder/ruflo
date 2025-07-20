import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

export const config = {
  env: process.env.NODE_ENV || 'development',
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.HOST || '0.0.0.0',
  
  // API configuration
  api: {
    version: process.env.API_VERSION || 'v1',
    prefix: process.env.API_PREFIX || '/api',
  },
  
  // Database configuration
  database: {
    url: process.env.DATABASE_URL || 'postgresql://localhost:5432/agentic_flow',
  },
  
  // Redis configuration
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
  
  // Security
  security: {
    jwtSecret: process.env.JWT_SECRET || 'default-secret',
    jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
    encryptionKey: process.env.ENCRYPTION_KEY || 'default-encryption-key',
  },
  
  // CORS
  cors: {
    origin: process.env.CORS_ORIGIN?.split(',') || ['http://localhost:3000'],
    credentials: process.env.CORS_CREDENTIALS === 'true',
  },
  
  // Monitoring
  monitoring: {
    enabled: process.env.ENABLE_METRICS === 'true',
    prometheusPort: parseInt(process.env.PROMETHEUS_PORT || '9090', 10),
    tracingEnabled: process.env.ENABLE_TRACING === 'true',
  },
  
  // Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    format: process.env.LOG_FORMAT || 'json',
  },
  
  // MCP
  mcp: {
    serverUrl: process.env.MCP_SERVER_URL || 'http://localhost:8080',
    apiKey: process.env.MCP_API_KEY || '',
    timeout: parseInt(process.env.MCP_TIMEOUT || '30000', 10),
  },
  
  // Queue
  queue: {
    concurrency: parseInt(process.env.QUEUE_CONCURRENCY || '5', 10),
    defaultAttempts: parseInt(process.env.QUEUE_DEFAULT_ATTEMPTS || '3', 10),
  },
};