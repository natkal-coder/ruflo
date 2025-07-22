// MCP Server Definitions for Mastra
// Based on https://mastra.ai/en/docs/tools-mcp/mcp-overview

import { MCPClient } from '@mastra/mcp';

// Claude Flow MCP Server
export const claudeFlowMcpServer = {
  command: 'npx',
  args: ['claude-flow', 'mcp', 'start'],
  env: {
    CLAUDE_FLOW_MODE: 'mcp',
    CLAUDE_FLOW_PORT: '5001'
  }
};

// Agentic Flow MCP Server
export const agenticFlowMcpServer = {
  command: 'node',
  args: ['../../src/mcp/dist/index.js'],
  env: {
    AGENTIC_FLOW_MODE: 'mcp',
    AGENTIC_FLOW_PORT: '5002'
  }
};

// Mastra Docs MCP Server (example of a working MCP server)
export const mastraDocsMcpServer = {
  command: 'npx',
  args: ['-y', '@mastra/mcp-docs-server']
};

// Create MCP client instance
export const createMcpClient = () => {
  return new MCPClient({
    servers: {
      'claude-flow': claudeFlowMcpServer.server,
      'agentic-flow': agenticFlowMcpServer.server,
      'mastra-docs': mastraDocsMcpServer.server
    }
  });
};

// Export server configurations
export const mcpServers = {
  'claude-flow': claudeFlowMcpServer,
  'agentic-flow': agenticFlowMcpServer,
  'mastra-docs': mastraDocsMcpServer
};

export default mcpServers;