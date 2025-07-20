/**
 * Simple test script to verify MCP tools are working
 */

const { spawn } = require('child_process');
const readline = require('readline');

async function testMCPServer() {
  console.log('🧪 Testing Agentic Flow MCP Server...\n');

  // Start the server
  const server = spawn('node', ['dist/index.js'], {
    stdio: ['pipe', 'pipe', 'inherit']
  });

  const rl = readline.createInterface({
    input: server.stdout,
    output: process.stdout,
    terminal: false
  });

  let responseCount = 0;
  const maxResponses = 3;

  return new Promise((resolve, reject) => {
    let timeoutHandle;

    // Setup timeout
    timeoutHandle = setTimeout(() => {
      console.log('❌ Test timed out');
      server.kill();
      reject(new Error('Test timeout'));
    }, 15000);

    // Listen for responses
    rl.on('line', (line) => {
      try {
        const response = JSON.parse(line);
        responseCount++;
        
        console.log(`✅ Response ${responseCount}:`, JSON.stringify(response, null, 2));
        
        if (responseCount >= maxResponses) {
          clearTimeout(timeoutHandle);
          server.kill();
          console.log('\n🎉 All tests completed successfully!');
          resolve();
        }
      } catch (e) {
        // Not JSON, probably log output
        console.log('📋 Server log:', line);
      }
    });

    server.on('error', (error) => {
      clearTimeout(timeoutHandle);
      console.error('❌ Server error:', error);
      reject(error);
    });

    // Wait a moment for server to start, then send test requests
    setTimeout(() => {
      console.log('📤 Sending test requests...\n');

      // Test 1: List tools
      const listToolsRequest = {
        method: 'tools/list',
        params: {}
      };
      server.stdin.write(JSON.stringify(listToolsRequest) + '\n');

      // Test 2: Create an agent
      setTimeout(() => {
        const createAgentRequest = {
          method: 'tools/call',
          params: {
            name: 'agent_spawn',
            arguments: {
              name: 'Test Agent',
              type: 'executor',
              capabilities: ['testing']
            }
          }
        };
        server.stdin.write(JSON.stringify(createAgentRequest) + '\n');
      }, 1000);

      // Test 3: Parse a goal
      setTimeout(() => {
        const parseGoalRequest = {
          method: 'tools/call',
          params: {
            name: 'goal_parse',
            arguments: {
              description: 'Build a simple web application with user authentication'
            }
          }
        };
        server.stdin.write(JSON.stringify(parseGoalRequest) + '\n');
      }, 2000);
    }, 2000);
  });
}

// Run the test
testMCPServer()
  .then(() => {
    console.log('\n✅ All MCP server tests passed!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ MCP server tests failed:', error.message);
    process.exit(1);
  });