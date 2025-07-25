#!/usr/bin/env node

/**
 * Real Agentic Flow Backend Server
 * Integrates with actual HiveMind and Mastra systems
 */

import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { HiveMindIntegration } from './hive-integration.js';
import { MastraIntegration } from './mastra-integration.js';
import { setupRoutes } from './routes.js';
import { setupWebSocket } from './websocket.js';
import { TerminalHandler } from './terminal-handler.js';
import { initializeMCPHandler } from './mcp-handler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3001;
const UI_PORT = process.env.UI_PORT || 5173;

class AgenticFlowServer {
  private app: express.Application;
  private server: any;
  private io: Server;
  private hive: HiveMindIntegration;
  private mastra: MastraIntegration;
  private terminalHandler: TerminalHandler | null = null;

  constructor() {
    this.app = express();
    this.server = createServer(this.app);
    this.io = new Server(this.server, {
      cors: {
        origin: [`http://localhost:${UI_PORT}`, 'http://localhost:3000'],
        methods: ['GET', 'POST'],
        credentials: true
      }
    });

    // Initialize integrations
    this.hive = new HiveMindIntegration({
      databasePath: path.join(__dirname, '../../data/hive-mind.db'),
      memoryPath: path.join(__dirname, '../../memory'),
      io: this.io
    });

    this.mastra = new MastraIntegration({
      port: 4111,
      io: this.io
    });

    this.setupMiddleware();
    this.setupRoutes();
    this.setupWebSocket();
  }

  private setupMiddleware(): void {
    // CORS configuration
    this.app.use(cors({
      origin: [`http://localhost:${UI_PORT}`, 'http://localhost:3000'],
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization']
    }));

    // Parse JSON bodies
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

    // Logging middleware
    this.app.use((req, res, next) => {
      console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
      next();
    });

    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        integrations: {
          hive: this.hive.isConnected(),
          mastra: this.mastra.isConnected()
        }
      });
    });
  }

  private setupRoutes(): void {
    setupRoutes(this.app, this.hive, this.mastra);
  }

  private setupWebSocket(): void {
    const wsHandler = setupWebSocket(this.io, this.hive, this.mastra);
    this.terminalHandler = wsHandler.terminalHandler;
    console.log('💻 Terminal handler stored for cleanup');
  }

  public async start(): Promise<void> {
    try {
      console.log('🚀 Starting Agentic Flow Backend Server...');

      // Initialize integrations
      console.log('📡 Initializing HiveMind integration...');
      await this.hive.initialize();

      console.log('🤖 Initializing Mastra integration...');
      await this.mastra.initialize();

      console.log('🔧 Initializing MCP handler...');
      await initializeMCPHandler();

      // Start server with error handling
      this.server.listen(PORT, () => {
        console.log(`\n✅ Agentic Flow Backend Server started successfully!\n`);
        console.log(`📊 API Server: http://localhost:${PORT}`);
        console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
        console.log(`🎯 UI Server: http://localhost:${UI_PORT}`);
        console.log(`\n🔗 Integrations:`);
        console.log(`   🧠 HiveMind: ${this.hive.isConnected() ? '✅ Connected' : '❌ Disconnected'}`);
        console.log(`   🤖 Mastra: ${this.mastra.isConnected() ? '✅ Connected' : '❌ Disconnected'}`);
        console.log(`\n📋 Health Check: http://localhost:${PORT}/health`);
        console.log(`📚 API Docs: http://localhost:${PORT}/api/docs`);
      });

      // Handle port already in use error
      this.server.on('error', (error: NodeJS.ErrnoException) => {
        if (error.code === 'EADDRINUSE') {
          console.log(`\n✅ Agentic Flow Backend Server is already running on port ${PORT}\n`);
          console.log(`📊 API Server: http://localhost:${PORT}`);
          console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
          console.log(`🎯 UI Server: http://localhost:${UI_PORT}`);
          console.log('\n💡 The server is already running in another terminal.');
          console.log('   To restart, first stop the existing server with Ctrl+C.\n');
          process.exit(0);
        } else {
          throw error;
        }
      });

      // Handle graceful shutdown
      process.on('SIGTERM', () => this.shutdown());
      process.on('SIGINT', () => this.shutdown());

    } catch (error) {
      console.error('❌ Failed to start server:', error);
      process.exit(1);
    }
  }

  private async shutdown(): Promise<void> {
    console.log('\n🛑 Shutting down Agentic Flow Backend Server...');

    try {
      // Close WebSocket connections
      this.io.close();

      // Cleanup terminal handler
      if (this.terminalHandler) {
        await this.terminalHandler.cleanup();
        console.log('💻 Terminal handler cleanup complete');
      }

      // Cleanup integrations
      await this.hive.cleanup();
      await this.mastra.cleanup();

      // Close server
      this.server.close(() => {
        console.log('✅ Server shutdown complete');
        process.exit(0);
      });
    } catch (error) {
      console.error('❌ Error during shutdown:', error);
      process.exit(1);
    }
  }
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new AgenticFlowServer();
  server.start().catch(console.error);
}

export default AgenticFlowServer;