# How to Add Tools and Networks to Mastra

## Adding New Tools

### 1. Add Tool to index.js

Add your new tool in the `tools` section of `/src/mastra/index.js`:

```javascript
// In the tools section of the Mastra configuration
tools: {
    // ... existing tools ...
    
    // Add your new tool
    myNewTool: new Tool({
        name: 'myNewTool',
        description: 'Description of what this tool does',
        inputSchema: {
            type: 'object',
            properties: {
                param1: { 
                    type: 'string', 
                    description: 'First parameter' 
                },
                param2: { 
                    type: 'number', 
                    minimum: 1,
                    maximum: 100,
                    default: 10,
                    description: 'Second parameter' 
                }
            },
            required: ['param1']  // Required parameters
        },
        execute: async (input) => {
            const { param1, param2 = 10 } = input;
            
            // Your tool logic here
            console.log(`🔧 Executing tool with ${param1} and ${param2}`);
            
            return {
                success: true,
                result: `Tool executed successfully`,
                data: {
                    // Return any data
                }
            };
        }
    }),
}
```

### 2. Update Custom UI

Add the tool to `custom-ui.html` in the tools section:

```html
<div class="tool-card card" onclick="executeMyNewTool()">
    <h3>🔧 My New Tool</h3>
    <p>Description of what this tool does</p>
    <div class="capabilities">
        <span class="capability">Feature1</span>
        <span class="capability">Feature2</span>
    </div>
    <br>
    <button class="execute-btn">Execute Tool</button>
</div>
```

Add the JavaScript function:

```javascript
function executeMyNewTool() {
    const param1 = prompt('Enter parameter 1:');
    if (param1) {
        alert(`🔧 Executing tool with: ${param1}`);
        // You could make an API call here if you create custom endpoints
    }
}
```

## Adding New Networks

### 1. Create Network Agent

Create a new agent file in `/src/mastra/agents/`:

```javascript
// File: /src/mastra/agents/my-network-agent.js
import { Agent } from '@mastra/core';

export const myNetworkAgent = new Agent({
    name: 'my-network-coordinator',
    description: '🌟 My Network - Description of your network',
    model: {
        provider: 'anthropic',
        name: 'claude-3-sonnet-20240229',
    },
    instructions: `You are a My Network Coordinator that specializes in:

🌟 **Core Capabilities:**
- Capability 1
- Capability 2
- Capability 3

🎯 **Primary Functions:**
1. Function 1
2. Function 2
3. Function 3

Always follow the network's principles...`,
    
    tools: [],
    
    config: {
        maxTokens: 3072,
        temperature: 0.7,
        topP: 0.9,
    },
    
    metadata: {
        category: 'network-coordination',
        priority: 'high',
        capabilities: ['capability1', 'capability2'],
        visualConfig: {
            icon: '🌟',
            color: '#00D9FF',
            cardStyle: 'my-network',
        }
    }
});

export default myNetworkAgent;
```

### 2. Import and Add to index.js

```javascript
// At the top of index.js
import { myNetworkAgent } from './agents/my-network-agent.js';

// In the agents section
agents: {
    // ... existing agents ...
    'my-network-coordinator': myNetworkAgent,
}
```

### 3. Create Network-Specific Tool

```javascript
// In the tools section
myNetworkTool: new Tool({
    name: 'myNetworkTool',
    description: 'Tool for My Network operations',
    inputSchema: {
        type: 'object',
        properties: {
            operation: { 
                type: 'string',
                enum: ['analyze', 'process', 'optimize'],
                description: 'Operation to perform' 
            },
            data: { 
                type: 'string', 
                description: 'Data to process' 
            }
        },
        required: ['operation', 'data']
    },
    execute: async (input) => {
        const { operation, data } = input;
        
        console.log(`🌟 My Network: ${operation} operation started`);
        
        return {
            success: true,
            networkId: `my-network-${Date.now()}`,
            message: `My Network ${operation} completed successfully`
        };
    }
}),
```

### 4. Create Network Workflow

```javascript
// In /src/mastra/workflows/my-network-workflow.js
import { Workflow } from '@mastra/core';

export const myNetworkWorkflow = new Workflow({
    name: 'my-network-workflow',
    description: 'Workflow for My Network operations',
    steps: [
        {
            id: 'init',
            type: 'agent',
            agent: 'my-network-coordinator',
            prompt: 'Initialize network for: {{task}}',
        },
        {
            id: 'process',
            type: 'agent',
            agent: 'my-network-coordinator',
            prompt: 'Process data: {{outputs.init.response}}',
        },
        {
            id: 'complete',
            type: 'agent',
            agent: 'my-network-coordinator',
            prompt: 'Finalize results: {{outputs.process.response}}',
        }
    ],
});
```

## Example: Adding a "Quantum Network"

Here's a complete example of adding a new network:

```javascript
// 1. Create agent: /src/mastra/agents/quantum-network-agent.js
import { Agent } from '@mastra/core';

export const quantumNetworkAgent = new Agent({
    name: 'quantum-network-orchestrator',
    description: '⚛️ Quantum Network - Quantum-inspired parallel processing',
    model: {
        provider: 'anthropic',
        name: 'claude-3-opus-20240229',
    },
    instructions: `You are a Quantum Network Orchestrator...`,
    tools: [],
    config: {
        maxTokens: 4096,
        temperature: 0.5,
    },
    metadata: {
        category: 'quantum-processing',
        capabilities: ['superposition', 'entanglement', 'parallel-compute'],
        visualConfig: {
            icon: '⚛️',
            color: '#9333EA',
        }
    }
});

// 2. Add tool in index.js
quantumNetworkProcess: new Tool({
    name: 'quantumNetworkProcess',
    description: 'Process data using quantum-inspired algorithms',
    inputSchema: {
        type: 'object',
        properties: {
            algorithm: { 
                type: 'string',
                enum: ['superposition', 'entanglement', 'collapse'],
                description: 'Quantum algorithm to use' 
            },
            qubits: { 
                type: 'number',
                minimum: 1,
                maximum: 128,
                default: 8,
                description: 'Number of quantum bits' 
            },
            data: { 
                type: 'string', 
                description: 'Data to process' 
            }
        },
        required: ['algorithm', 'data']
    },
    execute: async (input) => {
        const { algorithm, qubits = 8, data } = input;
        
        console.log(`⚛️ Quantum Network: Processing with ${algorithm} using ${qubits} qubits`);
        
        return {
            success: true,
            quantumId: `quantum-${Date.now()}`,
            message: `Quantum ${algorithm} completed with ${qubits} qubits`,
            result: {
                algorithm,
                qubits,
                probability: Math.random(),
                state: 'collapsed'
            }
        };
    }
}),
```

## After Adding Tools/Networks

1. **Restart Mastra**: Kill the current process and run `npx mastra dev` again
2. **Update Custom UI**: Add the new tools/agents to custom-ui.html
3. **Test**: Use the API or custom UI to verify everything works

## Tips

- Use descriptive names for tools and agents
- Include emojis for visual distinction
- Add comprehensive input validation
- Document all parameters clearly
- Test thoroughly before deployment
- Consider error handling in execute functions

Remember: Tools won't appear in Mastra's playground UI, but they'll work via API and your custom UI!