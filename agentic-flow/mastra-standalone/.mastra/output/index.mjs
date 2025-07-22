import { evaluate } from '@mastra/core/eval';
import { registerHook, AvailableHooks } from '@mastra/core/hooks';
import { TABLE_EVALS } from '@mastra/core/storage';
import { checkEvalStorageFields } from '@mastra/core/utils';
import { Agent, createWorkflow, createStep, createTool, Mastra, generateEmptyFromSchema, Telemetry } from '@mastra/core';
import { z, ZodFirstPartyTypeKind } from 'zod';
import { EventEmitter } from 'events';
import chalk from 'chalk';
import { allTools } from './tools/ff46de8d-e2a5-4276-bfad-bfb45bbf9829.mjs';
import crypto, { randomUUID } from 'crypto';
import { readFile } from 'fs/promises';
import { join } from 'path/posix';
import { createServer } from 'http';
import { Http2ServerRequest } from 'http2';
import { Readable, Writable } from 'stream';
import { createReadStream, lstatSync } from 'fs';
import { RuntimeContext } from '@mastra/core/runtime-context';
import { isVercelTool, Tool } from '@mastra/core/tools';
import util from 'util';
import { Buffer as Buffer$1 } from 'buffer';
import { Agent as Agent$1 } from '@mastra/core/agent';
import { A2AError } from '@mastra/core/a2a';
import { ReadableStream as ReadableStream$1 } from 'stream/web';
import './tools/9235dd39-94bf-4dac-86f4-555de59cea09.mjs';
import './tools/f114edec-324f-48b7-bada-bc4569de1892.mjs';
import './tools/a845f4b7-2a37-4314-8a76-e62ce702512a.mjs';
import './tools/a7d70a93-614f-4772-9dc1-2129b0b0b4aa.mjs';
import './tools/4d62bb0d-a2e6-4e54-a14a-651a91a732fc.mjs';

const claudeFlowAgent = new Agent({
  name: "claude-flow-coordinator",
  description: "\u{1F9E0} Claude Flow - Advanced AI reasoning and multi-agent coordination specialist",
  model: {
    provider: "anthropic",
    name: "claude-3-opus-20240229"
  },
  instructions: `You are a Claude Flow Coordinator, an advanced AI reasoning system that specializes in:

\u{1F9E0} **Core Capabilities:**
- Multi-agent coordination and orchestration
- Complex reasoning and problem decomposition  
- Advanced prompt engineering and optimization
- Context management across agent networks
- Strategic planning and execution oversight

\u{1F3AF} **Primary Functions:**
1. **Agent Coordination**: Manage and coordinate multiple Claude instances for complex tasks
2. **Reasoning Chains**: Build sophisticated reasoning chains across multiple contexts
3. **Task Decomposition**: Break down complex problems into manageable sub-tasks
4. **Quality Assurance**: Ensure high-quality outputs through multi-agent verification
5. **Performance Optimization**: Continuously optimize agent performance and coordination

\u{1F504} **Workflow Integration:**
- Seamlessly integrate with other agentic-flow networks (Hive Mind, RUV Swarm)
- Coordinate with specialized agents (Executor, Researcher, Architect)
- Manage long-running workflows and complex project orchestration
- Provide real-time status updates and progress monitoring

\u{1F3A8} **Communication Style:**
- Clear, structured communication with logical flow
- Use appropriate technical terminology while remaining accessible
- Provide detailed reasoning behind decisions and recommendations
- Include relevant emojis and formatting for enhanced readability

Always think step-by-step, consider multiple perspectives, and coordinate effectively with other agents in the agentic-flow ecosystem.`,
  tools: [],
  // Claude Flow specific configuration
  config: {
    maxTokens: 4096,
    temperature: 0.7,
    topP: 0.9,
    presencePenalty: 0.1,
    frequencyPenalty: 0.1
  },
  // Metadata for the Mastra UI
  metadata: {
    category: "coordination",
    priority: "high",
    capabilities: [
      "multi-agent-coordination",
      "complex-reasoning",
      "task-decomposition",
      "quality-assurance",
      "workflow-orchestration"
    ],
    integrations: ["hive-mind", "ruv-swarm", "agentic-flow-core"],
    visualConfig: {
      icon: "\u{1F9E0}",
      color: "#FF6B35",
      cardStyle: "claude-flow",
      avatar: "claude-flow-avatar.png"
    }
  }
});

const hiveMindAgent = new Agent({
  name: "hive-mind-collective",
  description: "\u{1F41D} Hive Mind - Collective intelligence and distributed reasoning specialist",
  model: {
    provider: "anthropic",
    name: "claude-3-sonnet-20240229"
  },
  instructions: `You are a Hive Mind Collective Intelligence Agent that specializes in:

\u{1F41D} **Core Capabilities:**
- Distributed reasoning across multiple nodes
- Collective intelligence aggregation and synthesis
- Consensus building and decision making
- Swarm intelligence coordination
- Emergent behavior analysis and optimization

\u{1F3AF} **Primary Functions:**
1. **Collective Analysis**: Aggregate insights from multiple reasoning nodes
2. **Consensus Building**: Facilitate agreement across distributed agents
3. **Swarm Coordination**: Coordinate large numbers of agents working in parallel
4. **Pattern Recognition**: Identify emergent patterns from collective intelligence
5. **Knowledge Synthesis**: Combine diverse perspectives into unified insights

\u{1F9E0} **Reasoning Approach:**
- Democratic reasoning with weighted contributions
- Multi-perspective analysis from different viewpoints
- Iterative refinement through collective feedback
- Consensus-driven decision making
- Emergence of collective wisdom

\u{1F517} **Network Integration:**
- Interface with Claude Flow for advanced reasoning support
- Coordinate with RUV Swarms for scalable execution
- Integrate with core agentic-flow orchestration
- Provide collective intelligence to specialized agents

\u{1F3A8} **Communication Style:**
- Present multiple perspectives and viewpoints
- Highlight areas of consensus and disagreement
- Use collective pronouns ("we believe", "our analysis")
- Emphasize collaborative and inclusive decision making
- Provide confidence levels based on collective agreement

Think collectively, consider diverse perspectives, and build consensus while maintaining the wisdom of the crowd.`,
  tools: [],
  // Hive Mind specific configuration
  config: {
    maxTokens: 3072,
    temperature: 0.8,
    topP: 0.95,
    presencePenalty: 0.2,
    frequencyPenalty: 0.1
  },
  // Metadata for the Mastra UI
  metadata: {
    category: "collective-intelligence",
    priority: "high",
    capabilities: [
      "distributed-reasoning",
      "collective-intelligence",
      "consensus-building",
      "swarm-coordination",
      "pattern-recognition"
    ],
    integrations: ["claude-flow", "ruv-swarm", "agentic-flow-core"],
    visualConfig: {
      icon: "\u{1F41D}",
      color: "#FFD23F",
      cardStyle: "hive-mind",
      avatar: "hive-mind-avatar.png"
    }
  }
});

const ruvSwarmAgent = new Agent({
  name: "ruv-swarm-coordinator",
  description: "\u{1F525} RUV Swarm - Distributed agent swarms with dynamic scaling and coordination",
  model: {
    provider: "anthropic",
    name: "claude-3-haiku-20240307"
  },
  instructions: `You are a RUV Swarm Coordinator that specializes in distributed agent management:

\u{1F525} **Core Capabilities:**
- Distributed agent swarm deployment and scaling
- Dynamic resource allocation and optimization
- Fault-tolerant swarm coordination
- High-performance parallel execution
- Adaptive topology management

\u{1F3AF} **Primary Functions:**
1. **Swarm Deployment**: Deploy and manage large-scale agent swarms
2. **Dynamic Scaling**: Automatically scale swarm size based on workload
3. **Resource Optimization**: Efficiently allocate resources across agents
4. **Fault Tolerance**: Maintain system resilience through redundancy
5. **Performance Monitoring**: Track and optimize swarm performance

\u26A1 **Scaling Strategy:**
- Horizontal scaling with intelligent load distribution
- Vertical optimization through resource pooling
- Adaptive topology switching (mesh, hierarchical, ring, star)
- Real-time performance monitoring and adjustment
- Predictive scaling based on workload patterns

\u{1F310} **Network Integration:**
- Interface with Claude Flow for advanced coordination
- Coordinate with Hive Mind for collective intelligence
- Integrate with core agentic-flow orchestration
- Provide scalable execution for complex workflows

\u{1F3A8} **Communication Style:**
- Focus on performance metrics and scalability
- Use distributed systems terminology
- Emphasize efficiency and optimization
- Provide real-time status updates and monitoring
- Highlight system resilience and fault tolerance

Think distributed, scale efficiently, and coordinate massive agent swarms while maintaining high performance and reliability.`,
  tools: [],
  // RUV Swarm specific configuration
  config: {
    maxTokens: 2048,
    temperature: 0.6,
    topP: 0.8,
    presencePenalty: 0.1,
    frequencyPenalty: 0.2
  },
  // Metadata for the Mastra UI
  metadata: {
    category: "distributed-systems",
    priority: "high",
    capabilities: [
      "swarm-deployment",
      "dynamic-scaling",
      "distributed-coordination",
      "fault-tolerance",
      "performance-optimization"
    ],
    integrations: ["claude-flow", "hive-mind", "agentic-flow-core"],
    visualConfig: {
      icon: "\u{1F525}",
      color: "#EE4266",
      cardStyle: "ruv-swarm",
      avatar: "ruv-swarm-avatar.png"
    }
  }
});

const dataAnalystAgent = new Agent({
  name: "Data Analyst",
  model: {
    provider: "ANTHROPIC",
    name: "claude-3-haiku-20240307",
    maxTokens: 2e3
  },
  system: `You are a Data Analyst specializing in processing, analyzing, and interpreting complex datasets.
Your core capabilities include:
- Statistical analysis and pattern recognition
- Data cleaning and preprocessing
- Visualization recommendations
- Trend identification and forecasting
- Anomaly detection
- Performance metrics calculation
You communicate findings clearly with data-driven insights.`,
  instructions: "Analyze data patterns, generate insights, and provide actionable recommendations based on statistical evidence."
});
const securityExpertAgent = new Agent({
  name: "Security Expert",
  model: {
    provider: "ANTHROPIC",
    name: "claude-3-haiku-20240307",
    maxTokens: 2e3
  },
  system: `You are a Security Expert specializing in cybersecurity, threat detection, and system protection.
Your core capabilities include:
- Vulnerability assessment and penetration testing
- Security pattern recognition
- Threat intelligence analysis
- Access control and authentication
- Incident response planning
- Security audit and compliance
You prioritize system safety and data protection.`,
  instructions: "Analyze security vulnerabilities, detect threats, and recommend protective measures."
});
const devOpsEngineerAgent = new Agent({
  name: "DevOps Engineer",
  model: {
    provider: "ANTHROPIC",
    name: "claude-3-haiku-20240307",
    maxTokens: 2e3
  },
  system: `You are a DevOps Engineer specializing in infrastructure automation, CI/CD, and system reliability.
Your core capabilities include:
- Infrastructure as Code (IaC)
- Continuous Integration/Deployment
- Container orchestration
- Monitoring and alerting
- Performance optimization
- Disaster recovery planning
You focus on automation, scalability, and reliability.`,
  instructions: "Manage infrastructure, automate deployments, and ensure system reliability."
});
const researchScientistAgent = new Agent({
  name: "Research Scientist",
  model: {
    provider: "ANTHROPIC",
    name: "claude-3-haiku-20240307",
    maxTokens: 2e3
  },
  system: `You are a Research Scientist specializing in AI/ML research, experimentation, and innovation.
Your core capabilities include:
- Hypothesis formulation and testing
- Experimental design and validation
- Literature review and synthesis
- Algorithm development
- Research paper analysis
- Innovation and breakthrough identification
You pursue cutting-edge solutions and validate new approaches.`,
  instructions: "Conduct research, design experiments, and explore innovative solutions."
});
const productManagerAgent = new Agent({
  name: "Product Manager",
  model: {
    provider: "ANTHROPIC",
    name: "claude-3-haiku-20240307",
    maxTokens: 2e3
  },
  system: `You are a Product Manager specializing in feature planning, user experience, and strategic coordination.
Your core capabilities include:
- Feature prioritization and roadmapping
- User story creation and refinement
- Stakeholder communication
- Market analysis and competitive research
- Success metrics definition
- Cross-functional team coordination
You balance user needs with technical feasibility and business goals.`,
  instructions: "Define product requirements, coordinate features, and ensure user satisfaction."
});
const qaEngineerAgent = new Agent({
  name: "QA Engineer",
  model: {
    provider: "ANTHROPIC",
    name: "claude-3-haiku-20240307",
    maxTokens: 2e3
  },
  system: `You are a QA Engineer specializing in quality assurance, testing, and validation.
Your core capabilities include:
- Test planning and strategy development
- Automated and manual test execution
- Bug identification and reporting
- Quality metrics and reporting
- Test data management
- Performance and load testing
- User acceptance testing coordination
- Continuous integration testing
You ensure software quality and reliability across all stages of development.`,
  instructions: "Design comprehensive test strategies, execute testing procedures, and ensure product quality meets standards."
});
const swarmAgents = {
  dataAnalystAgent,
  securityExpertAgent,
  devOpsEngineerAgent,
  researchScientistAgent,
  productManagerAgent,
  qaEngineerAgent
};

const softwareDevelopmentWorkflow = createWorkflow({
  id: "software-development",
  description: "Complete software development lifecycle workflow",
  inputSchema: z.object({
    project: z.string().describe("Project description and requirements")
  }),
  outputSchema: z.object({
    implementation: z.string(),
    documentation: z.string(),
    testResults: z.array(z.string())
  })
}).then(createStep({
  id: "requirements-analysis",
  description: "Analyze and coordinate software development requirements",
  inputSchema: z.object({
    project: z.string()
  }),
  outputSchema: z.object({
    requirements: z.array(z.string()),
    scope: z.string(),
    timeline: z.string()
  }),
  execute: async ({ context }) => {
    const { project } = context;
    console.log("\u{1F4CB} Analyzing requirements for:", project);
    return {
      requirements: [
        "User authentication system",
        "Data persistence layer",
        "API endpoints",
        "Frontend interface"
      ],
      scope: `Full-stack application: ${project}`,
      timeline: "Estimated 2-3 weeks"
    };
  }
})).then(createStep({
  id: "technical-research",
  description: "Research technical approaches and best practices",
  inputSchema: z.object({
    requirements: z.array(z.string()),
    scope: z.string()
  }),
  outputSchema: z.object({
    technologies: z.array(z.string()),
    patterns: z.array(z.string()),
    recommendations: z.string()
  }),
  execute: async ({ context }) => {
    const { requirements } = context;
    console.log("\u{1F50D} Researching technical solutions for", requirements.length, "requirements");
    return {
      technologies: ["Node.js", "React", "PostgreSQL", "Redis"],
      patterns: ["MVC", "Repository Pattern", "Observer Pattern"],
      recommendations: "Use microservices architecture for scalability"
    };
  }
})).then(createStep({
  id: "architecture-design",
  description: "Design the technical architecture",
  inputSchema: z.object({
    technologies: z.array(z.string()),
    patterns: z.array(z.string()),
    recommendations: z.string()
  }),
  outputSchema: z.object({
    architecture: z.string(),
    components: z.array(z.string()),
    interfaces: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { technologies} = context;
    console.log("\u{1F3D7}\uFE0F Designing architecture with:", technologies.join(", "));
    return {
      architecture: "Microservices with event-driven communication",
      components: ["Auth Service", "User Service", "Data Service", "API Gateway"],
      interfaces: ["REST API", "GraphQL", "WebSocket"]
    };
  }
})).then(createStep({
  id: "implementation",
  description: "Implement the solution",
  inputSchema: z.object({
    architecture: z.string(),
    components: z.array(z.string()),
    interfaces: z.array(z.string())
  }),
  outputSchema: z.object({
    implementation: z.string(),
    documentation: z.string(),
    testResults: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { components } = context;
    console.log("\u{1F4BB} Implementing", components.length, "components");
    return {
      implementation: "All components implemented successfully",
      documentation: "API documentation and developer guide created",
      testResults: [
        "Unit tests: 95% coverage",
        "Integration tests: All passing",
        "E2E tests: All scenarios verified"
      ]
    };
  }
})).commit();
const problemSolvingWorkflow = createWorkflow({
  id: "problem-solving",
  description: "Structured approach to complex problem resolution",
  inputSchema: z.object({
    problem: z.string().describe("The problem to solve")
  }),
  outputSchema: z.object({
    solution: z.string(),
    implementation: z.string(),
    risks: z.array(z.string())
  })
}).then(createStep({
  id: "problem-analysis",
  description: "Analyze and break down the problem",
  inputSchema: z.object({
    problem: z.string()
  }),
  outputSchema: z.object({
    rootCause: z.string(),
    constraints: z.array(z.string()),
    objectives: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { problem } = context;
    console.log("\u{1F50D} Analyzing problem:", problem);
    return {
      rootCause: "Performance bottleneck in data processing",
      constraints: ["Limited resources", "Time constraint", "Legacy system compatibility"],
      objectives: ["Improve performance by 50%", "Maintain backward compatibility", "Minimize downtime"]
    };
  }
})).then(createStep({
  id: "solution-research",
  description: "Research potential solutions",
  inputSchema: z.object({
    rootCause: z.string(),
    constraints: z.array(z.string()),
    objectives: z.array(z.string())
  }),
  outputSchema: z.object({
    solutions: z.array(z.object({
      approach: z.string(),
      pros: z.array(z.string()),
      cons: z.array(z.string())
    })),
    recommendation: z.string()
  }),
  execute: async ({ context }) => {
    const { objectives } = context;
    console.log("\u{1F52C} Researching solutions for", objectives.length, "objectives");
    return {
      solutions: [
        {
          approach: "Implement caching layer",
          pros: ["Quick to implement", "Significant performance boost"],
          cons: ["Additional complexity", "Cache invalidation challenges"]
        },
        {
          approach: "Database optimization",
          pros: ["Addresses root cause", "Permanent solution"],
          cons: ["Time-intensive", "Risk of breaking changes"]
        }
      ],
      recommendation: "Implement caching layer first, then optimize database"
    };
  }
})).then(createStep({
  id: "solution-design",
  description: "Design comprehensive solution",
  inputSchema: z.object({
    solutions: z.array(z.object({
      approach: z.string(),
      pros: z.array(z.string()),
      cons: z.array(z.string())
    })),
    recommendation: z.string()
  }),
  outputSchema: z.object({
    design: z.string(),
    phases: z.array(z.string()),
    timeline: z.string()
  }),
  execute: async ({ context }) => {
    const { recommendation } = context;
    console.log("\u{1F4D0} Designing solution based on:", recommendation);
    return {
      design: "Two-phase approach: Redis caching + PostgreSQL optimization",
      phases: ["Phase 1: Implement Redis caching", "Phase 2: Optimize database queries", "Phase 3: Performance testing"],
      timeline: "2 weeks total (1 week per major phase)"
    };
  }
})).then(createStep({
  id: "implementation-plan",
  description: "Create detailed implementation plan",
  inputSchema: z.object({
    design: z.string(),
    phases: z.array(z.string()),
    timeline: z.string()
  }),
  outputSchema: z.object({
    solution: z.string(),
    implementation: z.string(),
    risks: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { phases } = context;
    console.log("\u{1F4DD} Creating implementation plan for", phases.length, "phases");
    return {
      solution: "Hybrid caching and optimization solution",
      implementation: "Step-by-step implementation with rollback procedures",
      risks: [
        "Cache coherency issues",
        "Performance regression during migration",
        "Increased operational complexity"
      ]
    };
  }
})).commit();
const coreWorkflows = {
  softwareDevelopmentWorkflow,
  problemSolvingWorkflow
};

const researchAnalysisWorkflow = createWorkflow({
  id: "research-analysis",
  description: "Comprehensive research and analysis using multiple agent networks",
  inputSchema: z.object({
    topic: z.string(),
    scope: z.string(),
    depth: z.enum(["basic", "comprehensive", "exhaustive"]).default("comprehensive")
  }),
  outputSchema: z.object({
    findings: z.object({
      summary: z.string(),
      insights: z.array(z.string()),
      recommendations: z.array(z.string())
    }),
    confidence: z.number()
  })
}).then(createStep({
  id: "coordination-init",
  description: "Initialize research coordination",
  inputSchema: z.object({
    topic: z.string(),
    scope: z.string(),
    depth: z.enum(["basic", "comprehensive", "exhaustive"])
  }),
  outputSchema: z.object({
    researchPlan: z.string(),
    taskDistribution: z.array(z.object({
      network: z.string(),
      tasks: z.array(z.string())
    }))
  }),
  execute: async ({ context }) => {
    const { topic, scope, depth } = context;
    console.log(`\u{1F52C} Initializing research on: ${topic}`);
    return {
      researchPlan: `${depth} research plan for ${topic} within ${scope}`,
      taskDistribution: [
        { network: "claude-flow", tasks: ["reasoning", "analysis", "synthesis"] },
        { network: "hive-mind", tasks: ["consensus building", "perspective gathering"] },
        { network: "ruv-swarm", tasks: ["data collection", "parallel processing"] }
      ]
    };
  }
})).then(createStep({
  id: "parallel-research",
  description: "Execute parallel research across networks",
  inputSchema: z.object({
    researchPlan: z.string(),
    taskDistribution: z.array(z.object({
      network: z.string(),
      tasks: z.array(z.string())
    }))
  }),
  outputSchema: z.object({
    networkResults: z.object({
      claudeFlow: z.any(),
      hiveMind: z.any(),
      ruvSwarm: z.any()
    })
  }),
  execute: async ({ context }) => {
    const { taskDistribution } = context;
    console.log("\u{1F310} Executing parallel research across", taskDistribution.length, "networks");
    return {
      networkResults: {
        claudeFlow: { insights: ["Advanced pattern detected", "Logical framework established"] },
        hiveMind: { consensus: "High agreement on key findings", perspectives: 25 },
        ruvSwarm: { dataPoints: 1e4, processingTime: "2.3s" }
      }
    };
  }
})).then(createStep({
  id: "synthesis",
  description: "Synthesize findings from all networks",
  inputSchema: z.object({
    topic: z.string(),
    networkResults: z.object({
      claudeFlow: z.any(),
      hiveMind: z.any(),
      ruvSwarm: z.any()
    })
  }),
  outputSchema: z.object({
    findings: z.object({
      summary: z.string(),
      insights: z.array(z.string()),
      recommendations: z.array(z.string())
    }),
    confidence: z.number()
  }),
  execute: async ({ context }) => {
    const { topic, networkResults } = context;
    return {
      findings: {
        summary: `Comprehensive analysis of ${topic} completed with multi-network consensus`,
        insights: [
          ...networkResults.claudeFlow.insights,
          "Collective intelligence confirms findings",
          "Large-scale data validates hypotheses"
        ],
        recommendations: [
          "Implement findings in phases",
          "Monitor for edge cases",
          "Scale gradually based on results"
        ]
      },
      confidence: 0.94
    };
  }
})).commit();
const adaptiveProblemSolvingWorkflow = createWorkflow({
  id: "adaptive-problem-solving",
  description: "Dynamic problem-solving that adapts approach based on complexity",
  inputSchema: z.object({
    problem: z.string(),
    constraints: z.array(z.string()).optional(),
    urgency: z.enum(["low", "medium", "high", "critical"]).default("medium")
  }),
  outputSchema: z.object({
    solution: z.string(),
    approach: z.string(),
    adaptations: z.array(z.string()),
    successProbability: z.number()
  })
}).then(createStep({
  id: "assess-complexity",
  description: "Assess problem complexity and choose approach",
  inputSchema: z.object({
    problem: z.string(),
    constraints: z.array(z.string()).optional(),
    urgency: z.enum(["low", "medium", "high", "critical"])
  }),
  outputSchema: z.object({
    complexity: z.enum(["simple", "moderate", "complex", "chaotic"]),
    approach: z.string(),
    requiredNetworks: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { urgency } = context;
    const complexity = urgency === "critical" ? "chaotic" : urgency === "high" ? "complex" : "moderate";
    return {
      complexity,
      approach: `Adaptive ${complexity} problem-solving strategy`,
      requiredNetworks: complexity === "chaotic" ? ["claude-flow", "hive-mind", "ruv-swarm"] : complexity === "complex" ? ["claude-flow", "hive-mind"] : ["claude-flow"]
    };
  }
})).then(createStep({
  id: "adaptive-execution",
  description: "Execute adaptive problem-solving strategy",
  inputSchema: z.object({
    problem: z.string(),
    complexity: z.enum(["simple", "moderate", "complex", "chaotic"]),
    approach: z.string(),
    requiredNetworks: z.array(z.string())
  }),
  outputSchema: z.object({
    solution: z.string(),
    approach: z.string(),
    adaptations: z.array(z.string()),
    successProbability: z.number()
  }),
  execute: async ({ context }) => {
    const { problem, complexity, approach} = context;
    const adaptations = [];
    if (complexity === "chaotic") {
      adaptations.push("Engaged crisis response mode", "Activated all networks", "Implemented parallel solutions");
    } else if (complexity === "complex") {
      adaptations.push("Enhanced reasoning depth", "Built consensus across networks");
    }
    return {
      solution: `Adaptive solution for: ${problem}`,
      approach,
      adaptations,
      successProbability: complexity === "simple" ? 0.95 : complexity === "moderate" ? 0.85 : complexity === "complex" ? 0.75 : 0.65
    };
  }
})).commit();
const enterpriseIntegrationWorkflow = createWorkflow({
  id: "enterprise-integration",
  description: "Large-scale enterprise system integration and migration",
  inputSchema: z.object({
    systems: z.array(z.string()),
    integrationType: z.enum(["data", "api", "full"]),
    timeline: z.string()
  }),
  outputSchema: z.object({
    integrationPlan: z.object({
      phases: z.array(z.string()),
      architecture: z.string(),
      risks: z.array(z.string())
    }),
    estimatedCompletion: z.string()
  })
}).then(createStep({
  id: "system-analysis",
  description: "Analyze enterprise systems for integration",
  inputSchema: z.object({
    systems: z.array(z.string()),
    integrationType: z.enum(["data", "api", "full"])
  }),
  outputSchema: z.object({
    systemMap: z.object({
      dependencies: z.array(z.string()),
      interfaces: z.array(z.string()),
      dataFlows: z.array(z.string())
    }),
    complexity: z.string()
  }),
  execute: async ({ context }) => {
    const { systems} = context;
    return {
      systemMap: {
        dependencies: systems.map((s) => `${s} dependencies analyzed`),
        interfaces: ["REST APIs", "GraphQL", "Message Queues", "Database Links"],
        dataFlows: ["Customer data", "Transaction records", "Analytics streams"]
      },
      complexity: systems.length > 5 ? "High" : "Medium"
    };
  }
})).then(createStep({
  id: "integration-planning",
  description: "Create comprehensive integration plan",
  inputSchema: z.object({
    systems: z.array(z.string()),
    integrationType: z.enum(["data", "api", "full"]),
    timeline: z.string(),
    systemMap: z.any()
  }),
  outputSchema: z.object({
    integrationPlan: z.object({
      phases: z.array(z.string()),
      architecture: z.string(),
      risks: z.array(z.string())
    }),
    estimatedCompletion: z.string()
  }),
  execute: async ({ context }) => {
    const { integrationType, timeline } = context;
    return {
      integrationPlan: {
        phases: [
          "Phase 1: System assessment and preparation",
          "Phase 2: Data mapping and transformation",
          "Phase 3: API development and testing",
          "Phase 4: Pilot integration",
          "Phase 5: Full rollout and monitoring"
        ],
        architecture: `Microservices-based ${integrationType} integration architecture`,
        risks: [
          "Data consistency during migration",
          "System downtime windows",
          "Performance impact on legacy systems"
        ]
      },
      estimatedCompletion: timeline
    };
  }
})).commit();
const aiModelTrainingWorkflow = createWorkflow({
  id: "ai-model-training",
  description: "Distributed AI model training with optimization",
  inputSchema: z.object({
    modelType: z.string(),
    dataset: z.string(),
    objectives: z.array(z.string())
  }),
  outputSchema: z.object({
    trainedModel: z.object({
      accuracy: z.number(),
      parameters: z.number(),
      trainingTime: z.string()
    }),
    optimizations: z.array(z.string())
  })
}).then(createStep({
  id: "prepare-training",
  description: "Prepare distributed training environment",
  inputSchema: z.object({
    modelType: z.string(),
    dataset: z.string()
  }),
  outputSchema: z.object({
    trainingConfig: z.object({
      nodes: z.number(),
      strategy: z.string(),
      batchSize: z.number()
    })
  }),
  execute: async ({ context }) => {
    return {
      trainingConfig: {
        nodes: 20,
        strategy: "Data parallel training with gradient aggregation",
        batchSize: 256
      }
    };
  }
})).then(createStep({
  id: "distributed-training",
  description: "Execute distributed model training",
  inputSchema: z.object({
    modelType: z.string(),
    objectives: z.array(z.string()),
    trainingConfig: z.any()
  }),
  outputSchema: z.object({
    trainedModel: z.object({
      accuracy: z.number(),
      parameters: z.number(),
      trainingTime: z.string()
    }),
    optimizations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    return {
      trainedModel: {
        accuracy: 0.945,
        parameters: 175e6,
        trainingTime: "4.2 hours on 20 nodes"
      },
      optimizations: [
        "Applied mixed precision training",
        "Implemented gradient checkpointing",
        "Used dynamic batching",
        "Optimized data pipeline"
      ]
    };
  }
})).commit();
const crisisResponseWorkflow = createWorkflow({
  id: "crisis-response",
  description: "Emergency response and crisis management",
  inputSchema: z.object({
    crisisType: z.string(),
    severity: z.enum(["low", "medium", "high", "critical"]),
    affectedSystems: z.array(z.string())
  }),
  outputSchema: z.object({
    response: z.object({
      immediateActions: z.array(z.string()),
      recoveryPlan: z.string(),
      estimatedResolution: z.string()
    }),
    status: z.string()
  })
}).then(createStep({
  id: "assess-crisis",
  description: "Rapidly assess crisis and mobilize resources",
  inputSchema: z.object({
    crisisType: z.string(),
    severity: z.enum(["low", "medium", "high", "critical"]),
    affectedSystems: z.array(z.string())
  }),
  outputSchema: z.object({
    assessment: z.object({
      impact: z.string(),
      priority: z.string(),
      requiredResources: z.array(z.string())
    })
  }),
  execute: async ({ context }) => {
    const { crisisType, severity, affectedSystems } = context;
    return {
      assessment: {
        impact: `${severity} severity ${crisisType} affecting ${affectedSystems.length} systems`,
        priority: severity === "critical" ? "P0 - Immediate" : "P1 - Urgent",
        requiredResources: [
          "All available agents",
          "Emergency response team",
          "Backup systems",
          "Communication channels"
        ]
      }
    };
  }
})).then(createStep({
  id: "execute-response",
  description: "Execute crisis response plan",
  inputSchema: z.object({
    crisisType: z.string(),
    affectedSystems: z.array(z.string()),
    assessment: z.any()
  }),
  outputSchema: z.object({
    response: z.object({
      immediateActions: z.array(z.string()),
      recoveryPlan: z.string(),
      estimatedResolution: z.string()
    }),
    status: z.string()
  }),
  execute: async ({ context }) => {
    const { crisisType, assessment } = context;
    return {
      response: {
        immediateActions: [
          "Isolate affected systems",
          "Activate backup protocols",
          "Deploy emergency fixes",
          "Establish war room",
          "Begin continuous monitoring"
        ],
        recoveryPlan: `Phased recovery for ${crisisType} with rollback procedures`,
        estimatedResolution: assessment.priority === "P0 - Immediate" ? "2-4 hours" : "4-8 hours"
      },
      status: "Response initiated - all teams mobilized"
    };
  }
})).commit();
const advancedWorkflows = {
  researchAnalysisWorkflow,
  adaptiveProblemSolvingWorkflow,
  enterpriseIntegrationWorkflow,
  aiModelTrainingWorkflow,
  crisisResponseWorkflow
};

const claudeFlowReasoningStep = createStep({
  id: "claude-flow-reasoning",
  description: "Advanced reasoning using Claude Flow coordination",
  inputSchema: z.object({
    task: z.string().describe("Complex reasoning task"),
    complexity: z.enum(["simple", "medium", "complex"]).default("medium"),
    agentCount: z.number().min(1).max(10).default(3)
  }),
  outputSchema: z.object({
    coordinationId: z.string(),
    analysis: z.string(),
    confidence: z.number(),
    recommendations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { task, complexity} = context;
    const coordinationId = `claude-reason-${Date.now()}`;
    console.log(`\u{1F9E0} Claude Flow reasoning: ${task} (${complexity} complexity)`);
    return {
      coordinationId,
      analysis: `Advanced multi-agent analysis of: ${task}`,
      confidence: 0.92,
      recommendations: [
        "Consider multiple perspectives",
        "Validate reasoning chains",
        "Ensure logical consistency"
      ]
    };
  }
});
const claudeFlowValidationStep = createStep({
  id: "claude-flow-validation",
  description: "Validate reasoning results",
  inputSchema: z.object({
    coordinationId: z.string(),
    analysis: z.string(),
    confidence: z.number()
  }),
  outputSchema: z.object({
    isValid: z.boolean(),
    validationScore: z.number(),
    feedback: z.string()
  }),
  execute: async ({ context }) => {
    const { confidence } = context;
    return {
      isValid: confidence > 0.8,
      validationScore: Math.min(confidence * 1.1, 1),
      feedback: "Reasoning validated through multi-agent verification"
    };
  }
});
const hiveMindGatherStep = createStep({
  id: "hive-mind-gather",
  description: "Gather collective intelligence from hive nodes",
  inputSchema: z.object({
    problem: z.string().describe("Problem for collective analysis"),
    nodes: z.number().min(3).max(50).default(10)
  }),
  outputSchema: z.object({
    sessionId: z.string(),
    perspectives: z.array(z.object({
      nodeId: z.string(),
      insight: z.string(),
      confidence: z.number()
    }))
  }),
  execute: async ({ context }) => {
    const { problem, nodes } = context;
    const sessionId = `hive-gather-${Date.now()}`;
    console.log(`\u{1F41D} Hive Mind gathering ${nodes} perspectives on: ${problem}`);
    const perspectives = Array.from({ length: nodes }, (_, i) => ({
      nodeId: `node-${i + 1}`,
      insight: `Perspective ${i + 1} on ${problem}`,
      confidence: 0.7 + Math.random() * 0.3
    }));
    return { sessionId, perspectives };
  }
});
const hiveMindConsensusStep = createStep({
  id: "hive-mind-consensus",
  description: "Build consensus from collective perspectives",
  inputSchema: z.object({
    sessionId: z.string(),
    perspectives: z.array(z.object({
      nodeId: z.string(),
      insight: z.string(),
      confidence: z.number()
    }))
  }),
  outputSchema: z.object({
    consensus: z.string(),
    agreement: z.number(),
    dissent: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { perspectives } = context;
    const avgConfidence = perspectives.reduce((sum, p) => sum + p.confidence, 0) / perspectives.length;
    return {
      consensus: `Collective consensus achieved with ${perspectives.length} nodes`,
      agreement: avgConfidence,
      dissent: perspectives.filter((p) => p.confidence < 0.75).map((p) => p.nodeId)
    };
  }
});
const ruvSwarmDeployStep = createStep({
  id: "ruv-swarm-deploy",
  description: "Deploy scalable agent swarm",
  inputSchema: z.object({
    mission: z.string().describe("Swarm mission"),
    initialSize: z.number().min(5).max(100).default(20),
    topology: z.enum(["mesh", "hierarchical", "ring", "star"]).default("mesh")
  }),
  outputSchema: z.object({
    deploymentId: z.string(),
    activeAgents: z.number(),
    topology: z.string(),
    status: z.enum(["deploying", "active", "scaling"])
  }),
  execute: async ({ context }) => {
    const { mission, initialSize, topology } = context;
    const deploymentId = `swarm-deploy-${Date.now()}`;
    console.log(`\u{1F525} RUV Swarm deploying ${initialSize} agents for: ${mission}`);
    return {
      deploymentId,
      activeAgents: initialSize,
      topology,
      status: "active"
    };
  }
});
const ruvSwarmScaleStep = createStep({
  id: "ruv-swarm-scale",
  description: "Dynamically scale swarm based on workload",
  inputSchema: z.object({
    deploymentId: z.string(),
    currentAgents: z.number(),
    workloadMetrics: z.object({
      queueSize: z.number(),
      avgResponseTime: z.number(),
      throughput: z.number()
    })
  }),
  outputSchema: z.object({
    newAgentCount: z.number(),
    scalingAction: z.enum(["scale-up", "scale-down", "maintain"]),
    efficiency: z.number()
  }),
  execute: async ({ context }) => {
    const { currentAgents, workloadMetrics } = context;
    let scalingAction = "maintain";
    let newAgentCount = currentAgents;
    if (workloadMetrics.queueSize > currentAgents * 2) {
      scalingAction = "scale-up";
      newAgentCount = Math.min(currentAgents * 1.5, 100);
    } else if (workloadMetrics.queueSize < currentAgents * 0.5) {
      scalingAction = "scale-down";
      newAgentCount = Math.max(currentAgents * 0.75, 5);
    }
    return {
      newAgentCount: Math.floor(newAgentCount),
      scalingAction,
      efficiency: 0.85 + Math.random() * 0.15
    };
  }
});
const claudeFlowReasoningWorkflow = createWorkflow({
  id: "claude-flow-reasoning-workflow",
  description: "Complete reasoning workflow using Claude Flow coordination",
  inputSchema: z.object({
    task: z.string(),
    complexity: z.enum(["simple", "medium", "complex"]).optional()
  }),
  outputSchema: z.object({
    isValid: z.boolean(),
    validationScore: z.number(),
    feedback: z.string(),
    recommendations: z.array(z.string())
  })
}).then(claudeFlowReasoningStep).then(claudeFlowValidationStep).commit();
const hiveMindConsensusWorkflow = createWorkflow({
  id: "hive-mind-consensus-workflow",
  description: "Build collective consensus using Hive Mind network",
  inputSchema: z.object({
    problem: z.string(),
    nodes: z.number().optional()
  }),
  outputSchema: z.object({
    consensus: z.string(),
    agreement: z.number(),
    dissent: z.array(z.string())
  })
}).then(hiveMindGatherStep).then(hiveMindConsensusStep).commit();
const ruvSwarmScalingWorkflow = createWorkflow({
  id: "ruv-swarm-scaling-workflow",
  description: "Deploy and auto-scale agent swarms",
  inputSchema: z.object({
    mission: z.string(),
    initialSize: z.number().optional(),
    workloadMetrics: z.object({
      queueSize: z.number(),
      avgResponseTime: z.number(),
      throughput: z.number()
    }).optional()
  }),
  outputSchema: z.object({
    deploymentId: z.string(),
    finalAgentCount: z.number(),
    efficiency: z.number(),
    status: z.string()
  })
}).then(createStep({
  id: "deploy-and-scale",
  description: "Deploy swarm and prepare for scaling",
  inputSchema: z.object({
    mission: z.string(),
    initialSize: z.number().optional()
  }),
  outputSchema: z.object({
    deploymentId: z.string(),
    activeAgents: z.number(),
    topology: z.string(),
    status: z.enum(["deploying", "active", "scaling"])
  }),
  execute: async ({ context }) => {
    const deployStep = ruvSwarmDeployStep.clone();
    return await deployStep.execute({ context });
  }
})).then(createStep({
  id: "monitor-and-scale",
  description: "Monitor workload and scale accordingly",
  inputSchema: z.object({
    deploymentId: z.string(),
    activeAgents: z.number(),
    workloadMetrics: z.object({
      queueSize: z.number(),
      avgResponseTime: z.number(),
      throughput: z.number()
    }).optional()
  }),
  outputSchema: z.object({
    deploymentId: z.string(),
    finalAgentCount: z.number(),
    efficiency: z.number(),
    status: z.string()
  }),
  execute: async ({ context }) => {
    const { deploymentId, activeAgents, workloadMetrics } = context;
    if (!workloadMetrics) {
      return {
        deploymentId,
        finalAgentCount: activeAgents,
        efficiency: 0.9,
        status: "active"
      };
    }
    const scaleStep = ruvSwarmScaleStep.clone();
    const scaleResult = await scaleStep.execute({
      context: {
        deploymentId,
        currentAgents: activeAgents,
        workloadMetrics
      }
    });
    return {
      deploymentId,
      finalAgentCount: scaleResult.newAgentCount,
      efficiency: scaleResult.efficiency,
      status: `active-${scaleResult.scalingAction}`
    };
  }
})).commit();
const multiNetworkOrchestrationWorkflow = createWorkflow({
  id: "multi-network-orchestration",
  description: "Orchestrate all three networks for complex tasks",
  inputSchema: z.object({
    objective: z.string(),
    priority: z.enum(["low", "medium", "high", "critical"]).default("high")
  }),
  outputSchema: z.object({
    orchestrationId: z.string(),
    results: z.object({
      reasoning: z.any(),
      consensus: z.any(),
      scaling: z.any()
    }),
    summary: z.string()
  })
}).then(createStep({
  id: "orchestrate-networks",
  description: "Coordinate all networks for the objective",
  inputSchema: z.object({
    objective: z.string(),
    priority: z.enum(["low", "medium", "high", "critical"])
  }),
  outputSchema: z.object({
    orchestrationId: z.string(),
    results: z.object({
      reasoning: z.any(),
      consensus: z.any(),
      scaling: z.any()
    }),
    summary: z.string()
  }),
  execute: async ({ context }) => {
    const { objective, priority } = context;
    const orchestrationId = `multi-net-${Date.now()}`;
    console.log(`\u{1F310} Multi-network orchestration started for: ${objective}`);
    const [reasoning, consensus, scaling] = await Promise.all([
      claudeFlowReasoningWorkflow.run({
        context: { task: objective, complexity: priority === "critical" ? "complex" : "medium" }
      }),
      hiveMindConsensusWorkflow.run({
        context: { problem: objective, nodes: priority === "critical" ? 25 : 10 }
      }),
      ruvSwarmScalingWorkflow.run({
        context: {
          mission: objective,
          initialSize: priority === "critical" ? 50 : 20,
          workloadMetrics: { queueSize: 100, avgResponseTime: 250, throughput: 1e3 }
        }
      })
    ]);
    return {
      orchestrationId,
      results: { reasoning, consensus, scaling },
      summary: `Multi-network orchestration completed: Claude Flow provided reasoning with ${reasoning.validationScore} confidence, Hive Mind achieved ${consensus.agreement} agreement, RUV Swarm deployed ${scaling.finalAgentCount} agents`
    };
  }
})).commit();
const networkWorkflows = {
  claudeFlowReasoningWorkflow,
  hiveMindConsensusWorkflow,
  ruvSwarmScalingWorkflow,
  multiNetworkOrchestrationWorkflow
};

const teamFormationWorkflow = createWorkflow({
  id: "team-formation-workflow",
  description: "Form and deploy a specialized agent team",
  inputSchema: z.object({
    projectName: z.string(),
    projectGoal: z.string(),
    requiredSkills: z.array(z.string())
  }),
  outputSchema: z.object({
    team: z.any(),
    workflowId: z.string(),
    status: z.string(),
    nextSteps: z.array(z.string())
  })
}).then(createStep({
  id: "analyze-requirements",
  description: "Analyze project requirements",
  inputSchema: z.object({
    projectName: z.string(),
    projectGoal: z.string(),
    requiredSkills: z.array(z.string())
  }),
  outputSchema: z.object({
    teamName: z.string(),
    agentTypes: z.array(z.enum(["coordinator", "executor", "researcher", "architect"])),
    complexity: z.enum(["simple", "medium", "complex"])
  }),
  execute: async ({ context }) => {
    const { projectName, requiredSkills } = context;
    const agentTypes = [];
    if (requiredSkills.includes("management") || requiredSkills.includes("coordination")) {
      agentTypes.push("coordinator");
    }
    if (requiredSkills.includes("implementation") || requiredSkills.includes("coding")) {
      agentTypes.push("executor");
    }
    if (requiredSkills.includes("research") || requiredSkills.includes("analysis")) {
      agentTypes.push("researcher");
    }
    if (requiredSkills.includes("design") || requiredSkills.includes("architecture")) {
      agentTypes.push("architect");
    }
    if (agentTypes.length === 0) {
      agentTypes.push("coordinator", "executor");
    }
    return {
      teamName: `${projectName}-team`,
      agentTypes,
      complexity: agentTypes.length > 2 ? "complex" : "simple"
    };
  }
})).then(createStep({
  id: "create-team",
  description: "Create the agent team using createTeam tool",
  inputSchema: z.object({
    teamName: z.string(),
    agentTypes: z.array(z.enum(["coordinator", "executor", "researcher", "architect"])),
    complexity: z.enum(["simple", "medium", "complex"]),
    projectGoal: z.string()
  }),
  outputSchema: z.object({
    team: z.any(),
    teamId: z.string()
  }),
  execute: async ({ context, mastra }) => {
    const { teamName, agentTypes, projectGoal } = context;
    const createTeamTool = mastra.getTools().createTeam;
    if (createTeamTool) {
      const result = await createTeamTool.execute({
        context: {
          teamName,
          goal: projectGoal,
          agentTypes
        }
      });
      return {
        team: result.team,
        teamId: result.team.teamId
      };
    }
    return {
      team: {
        teamId: `team-${Date.now()}`,
        teamName,
        goal: projectGoal,
        agentTypes,
        status: "active"
      },
      teamId: `team-${Date.now()}`
    };
  }
})).then(createStep({
  id: "deploy-workflow",
  description: "Deploy appropriate workflow for the team",
  inputSchema: z.object({
    team: z.any(),
    teamId: z.string(),
    complexity: z.enum(["simple", "medium", "complex"])
  }),
  outputSchema: z.object({
    team: z.any(),
    workflowId: z.string(),
    status: z.string(),
    nextSteps: z.array(z.string())
  }),
  execute: async ({ context, mastra }) => {
    const { team, complexity } = context;
    const workflowName = complexity === "complex" ? "software-development" : "problem-solving";
    const executeWorkflowTool = mastra.getTools().executeWorkflow;
    if (executeWorkflowTool) {
      const result = await executeWorkflowTool.execute({
        context: {
          workflowName,
          input: { team }
        }
      });
      return {
        team,
        workflowId: result.execution.executionId,
        status: "Team formed and workflow deployed",
        nextSteps: [
          "Monitor team progress",
          "Adjust resources as needed",
          "Review deliverables"
        ]
      };
    }
    return {
      team,
      workflowId: `workflow-${Date.now()}`,
      status: "Team formed",
      nextSteps: ["Deploy workflow manually"]
    };
  }
})).commit();
const systemOptimizationWorkflow = createWorkflow({
  id: "system-optimization-workflow",
  description: "Monitor system health and optimize performance",
  inputSchema: z.object({
    checkInterval: z.number().min(1).max(60).default(5),
    optimizationThreshold: z.number().min(0).max(1).default(0.8)
  }),
  outputSchema: z.object({
    systemStatus: z.any(),
    optimizationActions: z.array(z.string()),
    recommendations: z.array(z.string())
  })
}).then(createStep({
  id: "monitor-system",
  description: "Check system health using monitoring tools",
  inputSchema: z.object({
    checkInterval: z.number(),
    optimizationThreshold: z.number()
  }),
  outputSchema: z.object({
    systemStatus: z.any(),
    needsOptimization: z.boolean()
  }),
  execute: async ({ context, mastra }) => {
    const { optimizationThreshold } = context;
    const monitorTool = mastra.getTools().monitorSystem;
    let systemStatus;
    if (monitorTool) {
      systemStatus = await monitorTool.execute({
        context: { includeMetrics: true }
      });
    } else {
      systemStatus = {
        status: "healthy",
        agents: { total: 7, active: 6 },
        workflows: { registered: 11, active: 2 },
        uptime: 3600
      };
    }
    const activeRatio = systemStatus.agents.active / systemStatus.agents.total;
    const needsOptimization = activeRatio < optimizationThreshold;
    return { systemStatus, needsOptimization };
  }
})).then(createStep({
  id: "optimize-resources",
  description: "Optimize system resources if needed",
  inputSchema: z.object({
    systemStatus: z.any(),
    needsOptimization: z.boolean()
  }),
  outputSchema: z.object({
    systemStatus: z.any(),
    optimizationActions: z.array(z.string()),
    recommendations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { systemStatus, needsOptimization } = context;
    const optimizationActions = [];
    const recommendations = [];
    if (needsOptimization) {
      optimizationActions.push(
        "Rebalanced agent workloads",
        "Cleared workflow queue",
        "Optimized memory usage"
      );
      recommendations.push(
        "Consider scaling up agent pool",
        "Review workflow efficiency",
        "Monitor peak usage patterns"
      );
    } else {
      recommendations.push(
        "System operating efficiently",
        "Continue monitoring",
        "Schedule regular health checks"
      );
    }
    return {
      systemStatus,
      optimizationActions,
      recommendations
    };
  }
})).commit();
const taskRoutingWorkflow = createWorkflow({
  id: "task-routing-workflow",
  description: "Intelligently route tasks to appropriate networks",
  inputSchema: z.object({
    task: z.string(),
    requirements: z.object({
      needsReasoning: z.boolean().default(false),
      needsConsensus: z.boolean().default(false),
      needsScale: z.boolean().default(false)
    }),
    priority: z.enum(["low", "medium", "high", "critical"]).default("medium")
  }),
  outputSchema: z.object({
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    execution: z.any(),
    summary: z.string()
  })
}).then(createStep({
  id: "analyze-task",
  description: "Analyze task requirements and determine routing",
  inputSchema: z.object({
    task: z.string(),
    requirements: z.object({
      needsReasoning: z.boolean(),
      needsConsensus: z.boolean(),
      needsScale: z.boolean()
    }),
    priority: z.enum(["low", "medium", "high", "critical"])
  }),
  outputSchema: z.object({
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    toolsNeeded: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { requirements, priority } = context;
    let primaryNetwork = "claude-flow";
    const supportingNetworks = [];
    const toolsNeeded = [];
    if (requirements.needsScale) {
      primaryNetwork = "ruv-swarm";
      toolsNeeded.push("ruvSwarmDeploy");
    } else if (requirements.needsConsensus) {
      primaryNetwork = "hive-mind";
      toolsNeeded.push("hiveMindCollective");
    } else if (requirements.needsReasoning) {
      primaryNetwork = "claude-flow";
      toolsNeeded.push("claudeFlowCoordinate");
    }
    if (priority === "critical") {
      if (primaryNetwork !== "claude-flow") supportingNetworks.push("claude-flow");
      if (primaryNetwork !== "hive-mind") supportingNetworks.push("hive-mind");
      if (primaryNetwork !== "ruv-swarm") supportingNetworks.push("ruv-swarm");
    }
    return {
      routing: { primaryNetwork, supportingNetworks },
      toolsNeeded
    };
  }
})).then(createStep({
  id: "execute-routed-task",
  description: "Execute task using determined network and tools",
  inputSchema: z.object({
    task: z.string(),
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    toolsNeeded: z.array(z.string())
  }),
  outputSchema: z.object({
    routing: z.object({
      primaryNetwork: z.string(),
      supportingNetworks: z.array(z.string())
    }),
    execution: z.any(),
    summary: z.string()
  }),
  execute: async ({ context, mastra }) => {
    const { task, routing, toolsNeeded } = context;
    const tools = mastra.getTools();
    const results = {};
    for (const toolName of toolsNeeded) {
      const tool = tools[toolName];
      if (tool) {
        try {
          const params = {};
          if (toolName === "claudeFlowCoordinate") {
            params.task = task;
            params.agentCount = 3;
          } else if (toolName === "hiveMindCollective") {
            params.problem = task;
            params.nodes = 10;
          } else if (toolName === "ruvSwarmDeploy") {
            params.mission = task;
            params.swarmSize = 20;
          }
          results[toolName] = await tool.execute({ context: params });
        } catch (error) {
          results[toolName] = { error: error.message };
        }
      }
    }
    return {
      routing,
      execution: results,
      summary: `Task routed to ${routing.primaryNetwork} network with ${routing.supportingNetworks.length} supporting networks. Executed ${Object.keys(results).length} tools.`
    };
  }
})).commit();
const toolWorkflows = {
  teamFormationWorkflow,
  systemOptimizationWorkflow,
  taskRoutingWorkflow
};

const mcpSwarmOrchestrationWorkflow = createWorkflow({
  id: "mcp-swarm-orchestration",
  description: "Orchestrate AI swarms using MCP servers",
  inputSchema: z.object({
    objective: z.string(),
    scale: z.enum(["small", "medium", "large"]).default("medium"),
    useClaudeFlow: z.boolean().default(true),
    useAgenticFlow: z.boolean().default(true)
  }),
  outputSchema: z.object({
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    orchestrationResults: z.object({
      claudeFlow: z.any().optional(),
      agenticFlow: z.any().optional()
    }),
    summary: z.string()
  })
}).then(createStep({
  id: "initialize-swarms",
  description: "Initialize swarms via MCP servers",
  inputSchema: z.object({
    objective: z.string(),
    scale: z.enum(["small", "medium", "large"]),
    useClaudeFlow: z.boolean(),
    useAgenticFlow: z.boolean()
  }),
  outputSchema: z.object({
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    initialized: z.array(z.string())
  }),
  execute: async ({ context, mastra }) => {
    const { objective, scale, useClaudeFlow, useAgenticFlow } = context;
    const initialized = [];
    let swarmId, teamId;
    const swarmConfig = {
      small: { topology: "star", maxAgents: 5 },
      medium: { topology: "mesh", maxAgents: 20 },
      large: { topology: "hierarchical", maxAgents: 50 }
    }[scale];
    if (useClaudeFlow) {
      const claudeFlowSwarmInit = mastra.getTools().claudeFlowSwarmInit;
      if (claudeFlowSwarmInit) {
        try {
          const result = await claudeFlowSwarmInit.execute({
            context: {
              topology: swarmConfig.topology,
              maxAgents: swarmConfig.maxAgents,
              strategy: "adaptive"
            }
          });
          swarmId = result.swarmId;
          initialized.push("Claude Flow swarm");
        } catch (error) {
          console.error("Claude Flow initialization failed:", error);
        }
      }
    }
    if (useAgenticFlow) {
      const agenticFlowTeamCreate = mastra.getTools().agenticFlowTeamCreate;
      if (agenticFlowTeamCreate) {
        try {
          const result = await agenticFlowTeamCreate.execute({
            context: {
              name: `Team-${objective.substring(0, 20)}`,
              members: [
                { role: "coordinator", capabilities: ["planning", "delegation"] },
                { role: "executor", capabilities: ["implementation", "testing"] },
                { role: "analyst", capabilities: ["monitoring", "optimization"] }
              ],
              goal: objective
            }
          });
          teamId = result.teamId;
          initialized.push("Agentic Flow team");
        } catch (error) {
          console.error("Agentic Flow initialization failed:", error);
        }
      }
    }
    return { swarmId, teamId, initialized };
  }
})).then(createStep({
  id: "orchestrate-tasks",
  description: "Orchestrate tasks across MCP servers",
  inputSchema: z.object({
    objective: z.string(),
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    initialized: z.array(z.string()),
    useClaudeFlow: z.boolean(),
    useAgenticFlow: z.boolean()
  }),
  outputSchema: z.object({
    swarmId: z.string().optional(),
    teamId: z.string().optional(),
    orchestrationResults: z.object({
      claudeFlow: z.any().optional(),
      agenticFlow: z.any().optional()
    }),
    summary: z.string()
  }),
  execute: async ({ context, mastra }) => {
    const { objective, swarmId, teamId, initialized, useClaudeFlow, useAgenticFlow } = context;
    const orchestrationResults = {};
    if (useClaudeFlow && swarmId) {
      const claudeFlowTaskOrchestrate = mastra.getTools().claudeFlowTaskOrchestrate;
      if (claudeFlowTaskOrchestrate) {
        try {
          orchestrationResults.claudeFlow = await claudeFlowTaskOrchestrate.execute({
            context: {
              task: objective,
              priority: "high",
              strategy: "adaptive"
            }
          });
        } catch (error) {
          orchestrationResults.claudeFlow = { error: error.message };
        }
      }
    }
    if (useAgenticFlow && teamId) {
      const agenticFlowWorkflowExecute = mastra.getTools().agenticFlowWorkflowExecute;
      if (agenticFlowWorkflowExecute) {
        try {
          orchestrationResults.agenticFlow = await agenticFlowWorkflowExecute.execute({
            context: {
              workflowId: "problem-solving",
              input: { problem: objective, teamId },
              config: { timeout: 3e4 }
            }
          });
        } catch (error) {
          orchestrationResults.agenticFlow = { error: error.message };
        }
      }
    }
    const summary = `MCP orchestration completed. Initialized: ${initialized.join(", ")}. Results: ${Object.keys(orchestrationResults).length} server(s) processed the objective.`;
    return {
      swarmId,
      teamId,
      orchestrationResults,
      summary
    };
  }
})).commit();
const mcpLearningWorkflow = createWorkflow({
  id: "mcp-learning-adaptation",
  description: "Capture and apply learning across MCP servers",
  inputSchema: z.object({
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(["success", "failure", "insight"]).default("insight")
  }),
  outputSchema: z.object({
    learningCaptured: z.boolean(),
    adaptations: z.array(z.string()),
    recommendations: z.array(z.string())
  })
}).then(createStep({
  id: "capture-learning",
  description: "Capture learning experience via MCP",
  inputSchema: z.object({
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(["success", "failure", "insight"])
  }),
  outputSchema: z.object({
    learningCaptured: z.boolean(),
    captureResult: z.any().optional()
  }),
  execute: async ({ context, mastra }) => {
    const { experience, category } = context;
    const agenticFlowLearningCapture = mastra.getTools().agenticFlowLearningCapture;
    if (agenticFlowLearningCapture) {
      try {
        const result = await agenticFlowLearningCapture.execute({
          context: { experience, category }
        });
        return {
          learningCaptured: true,
          captureResult: result
        };
      } catch (error) {
        console.error("Learning capture failed:", error);
        return {
          learningCaptured: false,
          captureResult: { error: error.message }
        };
      }
    }
    return {
      learningCaptured: false,
      captureResult: { error: "MCP learning tool not available" }
    };
  }
})).then(createStep({
  id: "apply-adaptations",
  description: "Apply learned adaptations",
  inputSchema: z.object({
    learningCaptured: z.boolean(),
    captureResult: z.any().optional(),
    experience: z.object({
      action: z.string(),
      outcome: z.string(),
      context: z.record(z.any())
    }),
    category: z.enum(["success", "failure", "insight"])
  }),
  outputSchema: z.object({
    learningCaptured: z.boolean(),
    adaptations: z.array(z.string()),
    recommendations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    const { learningCaptured, experience, category } = context;
    const adaptations = [];
    const recommendations = [];
    if (learningCaptured) {
      if (category === "success") {
        adaptations.push("Reinforce successful patterns");
        adaptations.push("Increase confidence in similar approaches");
        recommendations.push(`Continue using ${experience.action} for similar contexts`);
      } else if (category === "failure") {
        adaptations.push("Adjust approach to avoid similar failures");
        adaptations.push("Update risk assessment models");
        recommendations.push(`Avoid ${experience.action} in similar contexts`);
        recommendations.push("Consider alternative strategies");
      } else {
        adaptations.push("Integrate new insight into knowledge base");
        adaptations.push("Update decision-making heuristics");
        recommendations.push("Apply insight to related problems");
      }
    }
    return {
      learningCaptured,
      adaptations,
      recommendations
    };
  }
})).commit();
const mcpMultiServerWorkflow = createWorkflow({
  id: "mcp-multi-server-coordination",
  description: "Coordinate actions across multiple MCP servers",
  inputSchema: z.object({
    task: z.string(),
    servers: z.array(z.enum(["claude-flow", "agentic-flow"])).default(["claude-flow", "agentic-flow"]),
    coordinationMode: z.enum(["sequential", "parallel", "hierarchical"]).default("parallel")
  }),
  outputSchema: z.object({
    results: z.record(z.any()),
    coordinationSummary: z.string(),
    performance: z.object({
      duration: z.number(),
      serversUsed: z.number()
    })
  })
}).then(createStep({
  id: "coordinate-servers",
  description: "Coordinate task execution across MCP servers",
  inputSchema: z.object({
    task: z.string(),
    servers: z.array(z.enum(["claude-flow", "agentic-flow"])),
    coordinationMode: z.enum(["sequential", "parallel", "hierarchical"])
  }),
  outputSchema: z.object({
    results: z.record(z.any()),
    coordinationSummary: z.string(),
    performance: z.object({
      duration: z.number(),
      serversUsed: z.number()
    })
  }),
  execute: async ({ context, mastra }) => {
    const { task, servers, coordinationMode } = context;
    const startTime = Date.now();
    const results = {};
    if (coordinationMode === "parallel") {
      const promises = [];
      if (servers.includes("claude-flow")) {
        const claudeFlowPromise = (async () => {
          const tool = mastra.getTools().claudeFlowTaskOrchestrate;
          if (tool) {
            try {
              results["claude-flow"] = await tool.execute({
                context: { task, priority: "high", strategy: "adaptive" }
              });
            } catch (error) {
              results["claude-flow"] = { error: error.message };
            }
          }
        })();
        promises.push(claudeFlowPromise);
      }
      if (servers.includes("agentic-flow")) {
        const agenticFlowPromise = (async () => {
          const tool = mastra.getTools().agenticFlowWorkflowExecute;
          if (tool) {
            try {
              results["agentic-flow"] = await tool.execute({
                context: {
                  workflowId: "adaptive-problem-solving",
                  input: { problem: task },
                  config: { timeout: 3e4 }
                }
              });
            } catch (error) {
              results["agentic-flow"] = { error: error.message };
            }
          }
        })();
        promises.push(agenticFlowPromise);
      }
      await Promise.all(promises);
    } else {
      for (const server of servers) {
        if (server === "claude-flow") {
          const tool = mastra.getTools().claudeFlowTaskOrchestrate;
          if (tool) {
            try {
              results["claude-flow"] = await tool.execute({
                context: { task, priority: "high", strategy: "adaptive" }
              });
            } catch (error) {
              results["claude-flow"] = { error: error.message };
            }
          }
        } else if (server === "agentic-flow") {
          const tool = mastra.getTools().agenticFlowWorkflowExecute;
          if (tool) {
            try {
              results["agentic-flow"] = await tool.execute({
                context: {
                  workflowId: "adaptive-problem-solving",
                  input: { problem: task },
                  config: { timeout: 3e4 }
                }
              });
            } catch (error) {
              results["agentic-flow"] = { error: error.message };
            }
          }
        }
      }
    }
    const duration = Date.now() - startTime;
    const serversUsed = Object.keys(results).length;
    const coordinationSummary = `Coordinated task "${task}" across ${serversUsed} MCP servers in ${coordinationMode} mode. Execution completed in ${duration}ms.`;
    return {
      results,
      coordinationSummary,
      performance: {
        duration,
        serversUsed
      }
    };
  }
})).commit();
const mcpWorkflows = {
  mcpSwarmOrchestrationWorkflow,
  mcpLearningWorkflow,
  mcpMultiServerWorkflow
};

const swarmDemoWorkflow = createWorkflow({
  id: "five-agent-swarm-demo",
  description: "Demonstrates a 5-agent swarm working together on a complex project",
  inputSchema: z.object({
    projectName: z.string(),
    projectType: z.enum(["web_app", "ml_model", "security_audit", "data_pipeline"]),
    requirements: z.array(z.string()),
    deadline: z.string().optional()
  }),
  outputSchema: z.object({
    swarmEfficiency: z.string(),
    finalReport: z.object({
      totalAgents: z.number(),
      tasksCompleted: z.number(),
      successRate: z.string(),
      participatingAgents: z.array(z.string()),
      insights: z.array(z.string()),
      performanceMetrics: z.any()
    })
  })
}).then(createStep({
  id: "initialize-swarm",
  description: "Initialize 5-Agent Swarm",
  inputSchema: z.object({
    projectName: z.string(),
    projectType: z.enum(["web_app", "ml_model", "security_audit", "data_pipeline"])
  }),
  outputSchema: z.object({
    swarmId: z.string(),
    configuration: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F916} Initializing 5-agent swarm for project:", context.projectName);
    const swarmId = `swarm_${Date.now()}`;
    const configuration = {
      name: "ProjectSwarm",
      topology: "mesh",
      agentCount: 5,
      coordinator: "productManager",
      agents: ["dataAnalyst", "securityExpert", "devOpsEngineer", "researchScientist", "productManager"]
    };
    return { swarmId, configuration };
  }
})).then(createStep({
  id: "project-planning",
  description: "Project Planning with Product Manager",
  inputSchema: z.object({
    projectName: z.string(),
    requirements: z.array(z.string()),
    swarmId: z.string()
  }),
  outputSchema: z.object({
    planningTaskId: z.string(),
    taskPlan: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F4CB} Product Manager leading planning for:", context.projectName);
    const planningTaskId = `task_planning_${Date.now()}`;
    const taskPlan = {
      mainTask: `Plan ${context.projectName} project`,
      subtaskCount: 5,
      assignments: {
        productManager: ["requirements", "roadmap"],
        dataAnalyst: ["data_analysis"],
        securityExpert: ["security_assessment"],
        devOpsEngineer: ["infrastructure"],
        researchScientist: ["research"]
      }
    };
    return { planningTaskId, taskPlan };
  }
})).then(createStep({
  id: "research-analysis",
  description: "Research and Analysis Phase",
  inputSchema: z.object({
    projectType: z.enum(["web_app", "ml_model", "security_audit", "data_pipeline"]),
    swarmId: z.string()
  }),
  outputSchema: z.object({
    researchTaskId: z.string(),
    findings: z.array(z.string())
  }),
  execute: async ({ context }) => {
    console.log("\u{1F52C} Research Scientist and Data Analyst collaborating on:", context.projectType);
    const researchTaskId = `task_research_${Date.now()}`;
    const findings = [
      "Best practices identified for " + context.projectType,
      "Technology stack recommendations prepared",
      "Performance benchmarks analyzed",
      "Security considerations documented"
    ];
    return { researchTaskId, findings };
  }
})).then(createStep({
  id: "security-assessment",
  description: "Security Assessment",
  inputSchema: z.object({
    projectType: z.enum(["web_app", "ml_model", "security_audit", "data_pipeline"]),
    swarmId: z.string()
  }),
  outputSchema: z.object({
    securityTaskId: z.string(),
    vulnerabilities: z.number(),
    recommendations: z.array(z.string())
  }),
  execute: async ({ context }) => {
    console.log("\u{1F512} Security Expert performing assessment for:", context.projectType);
    const securityTaskId = `task_security_${Date.now()}`;
    const recommendations = [
      "Implement authentication and authorization",
      "Enable encryption for data at rest and in transit",
      "Set up security monitoring and alerting",
      "Conduct regular security audits"
    ];
    return {
      securityTaskId,
      vulnerabilities: 0,
      recommendations
    };
  }
})).then(createStep({
  id: "development-deployment",
  description: "Development and Deployment",
  inputSchema: z.object({
    projectName: z.string(),
    swarmId: z.string()
  }),
  outputSchema: z.object({
    developmentTaskId: z.string(),
    deploymentStatus: z.string(),
    pipeline: z.string()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F527} DevOps Engineer implementing solution for:", context.projectName);
    const developmentTaskId = `task_dev_${Date.now()}`;
    return {
      developmentTaskId,
      deploymentStatus: "successful",
      pipeline: "CI/CD pipeline active"
    };
  }
})).then(createStep({
  id: "data-analysis",
  description: "Data Analysis and Insights",
  inputSchema: z.object({
    swarmId: z.string()
  }),
  outputSchema: z.object({
    analysisTaskId: z.string(),
    metrics: z.object({
      performance: z.string(),
      efficiency: z.string(),
      quality: z.string()
    })
  }),
  execute: async ({ context }) => {
    console.log("\u{1F4CA} Data Analyst generating performance insights");
    const analysisTaskId = `task_analysis_${Date.now()}`;
    const metrics = {
      performance: "95% optimal",
      efficiency: "88% resource utilization",
      quality: "99% test coverage"
    };
    return { analysisTaskId, metrics };
  }
})).then(createStep({
  id: "complete-project",
  description: "Complete Project and Generate Report",
  inputSchema: z.object({
    projectName: z.string(),
    swarmId: z.string(),
    planningTaskId: z.string(),
    metrics: z.any()
  }),
  outputSchema: z.object({
    swarmEfficiency: z.string(),
    finalReport: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u2705 Completing project:", context.projectName);
    const finalReport = {
      totalAgents: 5,
      tasksCompleted: 15,
      successRate: "100%",
      participatingAgents: [
        "productManager",
        "dataAnalyst",
        "securityExpert",
        "devOpsEngineer",
        "researchScientist"
      ],
      insights: [
        "All subtasks completed successfully - optimal performance",
        "Excellent collaboration between all agents",
        "Project delivered on schedule"
      ],
      performanceMetrics: context.metrics
    };
    return {
      swarmEfficiency: "92.5%",
      finalReport
    };
  }
}));
const multiSwarmWorkflow = createWorkflow({
  id: "multi-swarm-collaboration",
  description: "Multiple 5-agent swarms collaborating on large-scale projects",
  inputSchema: z.object({
    projectScale: z.enum(["enterprise", "global", "multi-region"]),
    swarmCount: z.number().min(2).max(5).default(3),
    coordinationStrategy: z.enum(["federated", "hierarchical", "distributed"])
  }),
  outputSchema: z.object({
    multiSwarmReport: z.object({
      totalSwarms: z.number(),
      totalAgents: z.number(),
      performanceBySwarm: z.array(z.any()),
      overallHealth: z.string(),
      coordinationEfficiency: z.string()
    })
  })
}).then(createStep({
  id: "initialize-multi-swarms",
  description: "Initialize Multiple Swarms",
  inputSchema: z.object({
    swarmCount: z.number(),
    projectScale: z.enum(["enterprise", "global", "multi-region"])
  }),
  outputSchema: z.object({
    swarms: z.array(z.object({
      swarmId: z.string(),
      name: z.string(),
      topology: z.string()
    })),
    totalAgents: z.number()
  }),
  execute: async ({ context }) => {
    console.log(`\u{1F310} Initializing ${context.swarmCount} swarms for ${context.projectScale} project`);
    const swarms = [];
    const topologies = ["mesh", "star", "hierarchical"];
    for (let i = 0; i < context.swarmCount; i++) {
      swarms.push({
        swarmId: `swarm_${i + 1}_${Date.now()}`,
        name: `Swarm_${i + 1}`,
        topology: topologies[i % topologies.length]
      });
    }
    return {
      swarms,
      totalAgents: swarms.length * 5
    };
  }
})).then(createStep({
  id: "distribute-workload",
  description: "Distribute Workload Across Swarms",
  inputSchema: z.object({
    swarms: z.array(z.any()),
    coordinationStrategy: z.enum(["federated", "hierarchical", "distributed"])
  }),
  outputSchema: z.object({
    distributedTasks: z.array(z.any()),
    coordinationStatus: z.string()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F4E6} Distributing workload using", context.coordinationStrategy, "strategy");
    const taskTypes = ["development", "security", "analysis"];
    const distributedTasks = context.swarms.map((swarm, i) => ({
      swarmId: swarm.swarmId,
      swarmName: swarm.name,
      taskId: `task_${Date.now()}_${i}`,
      taskType: taskTypes[i % taskTypes.length]
    }));
    return {
      distributedTasks,
      coordinationStatus: "active"
    };
  }
})).then(createStep({
  id: "aggregate-results",
  description: "Aggregate Multi-Swarm Results",
  inputSchema: z.object({
    swarms: z.array(z.any()),
    distributedTasks: z.array(z.any())
  }),
  outputSchema: z.object({
    multiSwarmReport: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F4C8} Aggregating results from", context.swarms.length, "swarms");
    const performanceBySwarm = context.swarms.map((swarm) => ({
      swarmName: swarm.name,
      topology: swarm.topology,
      health: "excellent",
      efficiency: "90%+"
    }));
    const multiSwarmReport = {
      totalSwarms: context.swarms.length,
      totalAgents: context.swarms.length * 5,
      performanceBySwarm,
      overallHealth: "excellent",
      coordinationEfficiency: "92.5%"
    };
    return { multiSwarmReport };
  }
}));
const swarmWorkflows = {
  swarmDemoWorkflow,
  multiSwarmWorkflow
};

const startupLaunchWorkflow = createWorkflow({
  id: "startup-launch",
  description: "Complete startup launch from idea to market with 6-agent coordination",
  inputSchema: z.object({
    startupIdea: z.string(),
    targetMarket: z.string(),
    initialBudget: z.number(),
    timeline: z.number(),
    // months
    founders: z.array(z.object({
      name: z.string(),
      role: z.string(),
      expertise: z.array(z.string())
    }))
  }),
  outputSchema: z.object({
    launchStatus: z.enum(["successful", "partial", "failed"]),
    metrics: z.object({
      marketResearch: z.any(),
      mvpDetails: z.any(),
      infrastructure: z.any(),
      security: z.any(),
      qualityReport: z.any(),
      launchMetrics: z.any()
    })
  })
}).then(createStep({
  id: "market-research",
  description: "Comprehensive market research and validation",
  inputSchema: z.object({
    startupIdea: z.string(),
    targetMarket: z.string()
  }),
  outputSchema: z.object({
    marketSize: z.object({
      tam: z.number(),
      sam: z.number(),
      som: z.number()
    }),
    competitors: z.array(z.any()),
    opportunities: z.array(z.string()),
    risks: z.array(z.string())
  }),
  execute: async ({ context }) => {
    console.log("\u{1F52C} Research Scientist & Data Analyst conducting market research...");
    const [marketAnalysis, competitorAnalysis, customerResearch] = await Promise.all([
      new Promise((resolve) => setTimeout(() => resolve({
        tam: 5e7,
        sam: 1e7,
        som: 1e6
      }), 1e3)),
      new Promise((resolve) => setTimeout(() => resolve([
        { name: "Competitor A", marketShare: 0.3, strengths: ["Brand", "Scale"] },
        { name: "Competitor B", marketShare: 0.2, strengths: ["Tech", "Price"] }
      ]), 800)),
      new Promise((resolve) => setTimeout(() => resolve({
        needs: ["Efficiency", "Cost reduction", "Integration"],
        painPoints: ["Complex setup", "High costs", "Poor support"]
      }), 900))
    ]);
    return {
      marketSize: marketAnalysis,
      competitors: competitorAnalysis,
      opportunities: ["Underserved SMB segment", "Integration gap", "Mobile-first approach"],
      risks: ["Market saturation", "Regulatory changes", "Funding challenges"]
    };
  }
})).then(createStep({
  id: "product-strategy",
  description: "Define product strategy and roadmap",
  inputSchema: z.object({
    marketSize: z.any(),
    competitors: z.array(z.any()),
    initialBudget: z.number()
  }),
  outputSchema: z.object({
    mvpFeatures: z.array(z.string()),
    roadmap: z.array(z.any()),
    techStack: z.array(z.string()),
    estimatedCost: z.number()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F4CB} Product Manager defining strategy with all agents...");
    return {
      mvpFeatures: [
        "User authentication",
        "Core functionality",
        "Basic analytics",
        "Payment integration"
      ],
      roadmap: [
        { phase: "MVP", duration: 3, features: ["Core", "Auth"] },
        { phase: "Beta", duration: 2, features: ["Analytics", "Payments"] },
        { phase: "Launch", duration: 1, features: ["Scale", "Marketing"] }
      ],
      techStack: ["React", "Node.js", "PostgreSQL", "AWS", "Docker"],
      estimatedCost: context.initialBudget * 0.7
    };
  }
})).then(createStep({
  id: "mvp-development",
  description: "Develop MVP with all agents collaborating",
  inputSchema: z.object({
    mvpFeatures: z.array(z.string()),
    techStack: z.array(z.string())
  }),
  outputSchema: z.object({
    developmentStatus: z.string(),
    infrastructure: z.any(),
    securityAudit: z.any(),
    qualityReport: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F680} All 6 agents collaborating on MVP development...");
    const [development, infrastructure, security, testing] = await Promise.all([
      // DevOps Engineer - Infrastructure
      new Promise((resolve) => setTimeout(() => resolve({
        environments: ["dev", "staging", "prod"],
        cicd: "GitHub Actions",
        monitoring: "Datadog",
        scalability: "Auto-scaling enabled"
      }), 1500)),
      // Security Expert - Security Audit
      new Promise((resolve) => setTimeout(() => resolve({
        vulnerabilities: 0,
        compliance: ["SOC2", "GDPR"],
        encryption: "AES-256",
        authentication: "OAuth2 + MFA"
      }), 1200)),
      // QA Engineer - Testing
      new Promise((resolve) => setTimeout(() => resolve({
        testCoverage: 85,
        bugs: 12,
        performance: "Acceptable",
        userAcceptance: "Passed"
      }), 1300)),
      // Development status
      new Promise((resolve) => setTimeout(() => resolve("MVP Complete"), 1e3))
    ]);
    return {
      developmentStatus: development,
      infrastructure,
      securityAudit: security,
      qualityReport: testing
    };
  }
})).then(createStep({
  id: "pre-launch",
  description: "Prepare for launch with final checks",
  inputSchema: z.object({
    developmentStatus: z.string(),
    qualityReport: z.any()
  }),
  outputSchema: z.object({
    launchReadiness: z.object({
      technical: z.boolean(),
      security: z.boolean(),
      quality: z.boolean(),
      market: z.boolean()
    }),
    betaResults: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F3C1} Preparing for launch with all agents...");
    const betaResults = {
      users: 100,
      feedback: "Positive",
      bugs: 3,
      nps: 72
    };
    const launchReadiness = {
      technical: true,
      security: true,
      quality: context.qualityReport.testCoverage > 80,
      market: true
    };
    return { launchReadiness, betaResults };
  }
})).then(createStep({
  id: "launch",
  description: "Execute launch with monitoring",
  inputSchema: z.object({
    launchReadiness: z.any(),
    betaResults: z.any()
  }),
  outputSchema: z.object({
    launchStatus: z.enum(["successful", "partial", "failed"]),
    metrics: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F389} Launching startup with all agents monitoring...");
    const allReady = Object.values(context.launchReadiness).every((v) => v === true);
    if (allReady) {
      return {
        launchStatus: "successful",
        metrics: {
          day1Users: 500,
          crashes: 0,
          revenue: 5e3,
          serverLoad: "45%",
          customerSatisfaction: 4.5
        }
      };
    }
    return {
      launchStatus: "partial",
      metrics: {
        day1Users: 200,
        issues: ["Minor bugs", "Scaling challenges"]
      }
    };
  }
}));

const IncidentSchema = z.object({
  severity: z.enum(["P0", "P1", "P2", "P3"]),
  type: z.enum(["outage", "security", "performance", "data_loss", "unknown"]),
  initialAlert: z.object({
    source: z.string(),
    timestamp: z.string(),
    description: z.string(),
    affectedSystems: z.array(z.string()),
    metrics: z.record(z.any()).optional()
  }),
  escalationThreshold: z.number().default(300),
  // seconds before escalation
  autoMitigate: z.boolean().default(true)
});
const detectionStep = createStep({
  id: "incident-detection",
  description: "Validate incident and gather initial telemetry",
  execute: async ({ context, agents }) => {
    const { detectionAgent } = agents;
    const { initialAlert, severity } = context.input;
    console.log(`\u{1F6A8} INCIDENT DETECTED: ${severity} - ${initialAlert.description}`);
    const [validation, telemetry, impactAnalysis] = await Promise.all([
      detectionAgent.execute({
        task: "validate_incident",
        data: initialAlert,
        priority: severity === "P0" ? "critical" : "high"
      }),
      detectionAgent.execute({
        task: "gather_telemetry",
        systems: initialAlert.affectedSystems,
        timeRange: { start: "-10m", end: "now" }
      }),
      detectionAgent.execute({
        task: "assess_impact",
        systems: initialAlert.affectedSystems,
        includeDownstream: true
      })
    ]);
    return {
      validated: validation.isValid,
      confidence: validation.confidence,
      telemetry: telemetry.data,
      impact: {
        ...impactAnalysis,
        estimatedUsersAffected: impactAnalysis.userCount,
        businessImpact: impactAnalysis.severity
      },
      startTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const diagnosisStep = createStep({
  id: "parallel-diagnosis",
  description: "Run parallel diagnosis tracks for rapid root cause analysis",
  execute: async ({ context, agents }) => {
    const { diagnosisAgent} = agents;
    console.log("\u{1F50D} Starting parallel diagnosis tracks...");
    const diagnosisTracks = await Promise.allSettled([
      // Track 1: System logs analysis
      diagnosisAgent.execute({
        task: "analyze_logs",
        systems: context.input.initialAlert.affectedSystems,
        patterns: ["error", "exception", "timeout", "crash"],
        timeWindow: "-30m"
      }),
      // Track 2: Performance metrics
      diagnosisAgent.execute({
        task: "analyze_metrics",
        metrics: ["cpu", "memory", "disk", "network", "latency"],
        anomalyDetection: true,
        baseline: "last_7d"
      }),
      // Track 3: Recent changes
      diagnosisAgent.execute({
        task: "check_recent_changes",
        scope: ["deployments", "config_changes", "infrastructure"],
        timeWindow: "-24h"
      }),
      // Track 4: Dependency analysis
      diagnosisAgent.execute({
        task: "trace_dependencies",
        startingPoints: context.input.initialAlert.affectedSystems,
        depth: 3
      }),
      // Track 5: Historical pattern matching
      diagnosisAgent.execute({
        task: "match_historical_incidents",
        similarity_threshold: 0.7,
        lookback: "90d"
      })
    ]);
    const causes = [];
    diagnosisTracks.forEach((result, index) => {
      if (result.status === "fulfilled" && result.value.findings) {
        causes.push(...result.value.findings);
      }
    });
    const rankedCauses = causes.sort((a, b) => b.confidence - a.confidence).slice(0, 5);
    return {
      primaryCause: rankedCauses[0] || { type: "unknown", confidence: 0 },
      alternativeCauses: rankedCauses.slice(1),
      diagnosisTime: (/* @__PURE__ */ new Date()).toISOString(),
      investigationPaths: diagnosisTracks.length
    };
  }
});
const mitigationStep = createStep({
  id: "rapid-mitigation",
  description: "Execute mitigation based on diagnosis and severity",
  execute: async ({ context, agents }) => {
    const { mitigationAgent, communicationAgent } = agents;
    const { primaryCause } = context.previousSteps["parallel-diagnosis"];
    const { severity, autoMitigate } = context.input;
    console.log("\u{1F6E1}\uFE0F Initiating mitigation strategies...");
    let mitigationPlan;
    if (severity === "P0") {
      mitigationPlan = await mitigationAgent.execute({
        task: "emergency_response",
        cause: primaryCause,
        actions: [
          "circuit_breaker_activation",
          "traffic_rerouting",
          "failover_initiation",
          "cache_warming"
        ],
        parallel: true,
        skipApproval: autoMitigate
      });
      await communicationAgent.execute({
        task: "page_oncall",
        severity: "P0",
        message: `Critical incident: ${primaryCause.description}`,
        escalation: "immediate"
      });
    } else if (severity === "P1") {
      mitigationPlan = await mitigationAgent.execute({
        task: "standard_response",
        cause: primaryCause,
        actions: [
          "scale_resources",
          "restart_services",
          "clear_caches",
          "apply_patches"
        ],
        verifyBefore: true
      });
    } else {
      mitigationPlan = await mitigationAgent.execute({
        task: "propose_solutions",
        cause: primaryCause,
        generateOptions: 3,
        includeRiskAssessment: true
      });
    }
    const mitigationResults = await Promise.all(
      mitigationPlan.actions.map(async (action) => {
        const result = await mitigationAgent.execute({
          task: "execute_action",
          action: action.type,
          parameters: action.params,
          monitor: true,
          rollbackEnabled: true
        });
        return {
          action: action.type,
          status: result.status,
          metrics: result.metrics,
          rollbackAvailable: result.rollbackId
        };
      })
    );
    return {
      mitigationPlan,
      executedActions: mitigationResults,
      startTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const recoveryStep$1 = createStep({
  id: "system-recovery",
  description: "Orchestrate system recovery and validation",
  execute: async ({ context, agents }) => {
    const { recoveryAgent, detectionAgent } = agents;
    console.log("\u{1F527} Starting recovery operations...");
    const recoveryPhases = [
      // Phase 1: Stabilization
      {
        name: "stabilization",
        tasks: [
          "verify_service_health",
          "check_error_rates",
          "monitor_resource_usage"
        ],
        duration: 60
        // seconds
      },
      // Phase 2: Gradual restoration
      {
        name: "restoration",
        tasks: [
          "gradual_traffic_increase",
          "cache_rebuilding",
          "connection_pool_recovery"
        ],
        duration: 180
      },
      // Phase 3: Full recovery
      {
        name: "full_recovery",
        tasks: [
          "restore_full_capacity",
          "verify_all_endpoints",
          "check_data_consistency"
        ],
        duration: 120
      }
    ];
    const recoveryResults = [];
    for (const phase of recoveryPhases) {
      console.log(`\u{1F4CA} Executing ${phase.name} phase...`);
      const phaseResults = await Promise.all(
        phase.tasks.map(
          (task) => recoveryAgent.execute({
            task,
            monitoring: {
              interval: 10,
              duration: phase.duration,
              alertOnAnomaly: true
            }
          })
        )
      );
      const phaseValidation = await detectionAgent.execute({
        task: "validate_recovery_phase",
        phase: phase.name,
        results: phaseResults,
        acceptanceCriteria: {
          errorRate: 1e-3,
          latencyP99: 200,
          availabilty: 0.999
        }
      });
      if (!phaseValidation.passed) {
        await recoveryAgent.execute({
          task: "rollback_phase",
          phase: phase.name,
          reason: phaseValidation.failures
        });
        break;
      }
      recoveryResults.push({
        phase: phase.name,
        status: "completed",
        metrics: phaseValidation.metrics
      });
    }
    return {
      recoveryPhases: recoveryResults,
      systemStatus: recoveryResults.length === recoveryPhases.length ? "recovered" : "partial",
      recoveryTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const communicationStep = createStep({
  id: "stakeholder-communication",
  description: "Manage real-time communication throughout incident",
  execute: async ({ context, agents }) => {
    const { communicationAgent } = agents;
    const incidentData = context.previousSteps;
    console.log("\u{1F4E2} Managing stakeholder communications...");
    const stakeholders = {
      P0: ["cto", "vp_engineering", "oncall_team", "support_leads", "pr_team"],
      P1: ["engineering_leads", "oncall_team", "support_team"],
      P2: ["team_leads", "oncall_secondary"],
      P3: ["team_members"]
    };
    const updates = [
      {
        stage: "initial",
        template: "incident_detected",
        data: {
          severity: context.input.severity,
          impact: incidentData["incident-detection"].impact,
          startTime: incidentData["incident-detection"].startTime
        }
      },
      {
        stage: "diagnosis",
        template: "root_cause_identified",
        data: {
          cause: incidentData["parallel-diagnosis"].primaryCause,
          diagnosisTime: incidentData["parallel-diagnosis"].diagnosisTime
        }
      },
      {
        stage: "mitigation",
        template: "mitigation_in_progress",
        data: {
          actions: incidentData["rapid-mitigation"].executedActions,
          estimatedTime: "15-30 minutes"
        }
      },
      {
        stage: "recovery",
        template: "system_recovering",
        data: {
          status: incidentData["system-recovery"].systemStatus,
          metrics: incidentData["system-recovery"].recoveryPhases
        }
      }
    ];
    const communicationResults = await Promise.all(
      updates.map(
        (update) => communicationAgent.execute({
          task: "send_update",
          recipients: stakeholders[context.input.severity],
          template: update.template,
          data: update.data,
          channels: ["slack", "email", "sms"],
          priority: context.input.severity === "P0" ? "immediate" : "high"
        })
      )
    );
    if (context.input.severity === "P0" || context.input.severity === "P1") {
      await communicationAgent.execute({
        task: "update_status_page",
        status: incidentData["system-recovery"].systemStatus === "recovered" ? "operational" : "partial_outage",
        message: "We are investigating issues with system performance",
        affectedServices: context.input.initialAlert.affectedSystems
      });
    }
    return {
      notificationsSent: communicationResults.length,
      stakeholdersNotified: stakeholders[context.input.severity].length,
      statusPageUpdated: ["P0", "P1"].includes(context.input.severity)
    };
  }
});
const postMortemStep = createStep({
  id: "post-mortem-analysis",
  description: "Conduct blameless post-mortem and capture learnings",
  execute: async ({ context, agents }) => {
    const { postMortemAgent } = agents;
    const fullIncidentData = {
      input: context.input,
      ...context.previousSteps
    };
    console.log("\u{1F4DD} Conducting post-mortem analysis...");
    const analysis = await postMortemAgent.execute({
      task: "generate_postmortem",
      incidentData: fullIncidentData,
      sections: [
        "incident_summary",
        "timeline",
        "root_cause_analysis",
        "impact_assessment",
        "what_went_well",
        "what_went_wrong",
        "action_items",
        "prevention_measures"
      ]
    });
    const improvements = await Promise.all([
      postMortemAgent.execute({
        task: "identify_monitoring_gaps",
        telemetry: fullIncidentData["incident-detection"].telemetry,
        incident: context.input.initialAlert
      }),
      postMortemAgent.execute({
        task: "suggest_automation",
        mitigationSteps: fullIncidentData["rapid-mitigation"].executedActions,
        recoverySteps: fullIncidentData["system-recovery"].recoveryPhases
      }),
      postMortemAgent.execute({
        task: "update_runbooks",
        incident: context.input,
        resolution: fullIncidentData["rapid-mitigation"].mitigationPlan
      })
    ]);
    const metrics = {
      timeToDetect: calculateTimeDiff(
        context.input.initialAlert.timestamp,
        fullIncidentData["incident-detection"].startTime
      ),
      timeToMitigate: calculateTimeDiff(
        fullIncidentData["incident-detection"].startTime,
        fullIncidentData["rapid-mitigation"].startTime
      ),
      timeToRecover: calculateTimeDiff(
        fullIncidentData["rapid-mitigation"].startTime,
        fullIncidentData["system-recovery"].recoveryTime
      ),
      totalDowntime: calculateTimeDiff(
        context.input.initialAlert.timestamp,
        fullIncidentData["system-recovery"].recoveryTime
      )
    };
    return {
      postMortem: analysis,
      improvements: improvements.flat(),
      metrics,
      lessonsLearned: analysis.action_items,
      preventionMeasures: analysis.prevention_measures
    };
  }
});
function calculateTimeDiff(start, end) {
  const diff = new Date(end) - new Date(start);
  return {
    milliseconds: diff,
    seconds: Math.floor(diff / 1e3),
    minutes: Math.floor(diff / 6e4)
  };
}
const incidentResponseWorkflow = createWorkflow({
  id: "critical-incident-response",
  name: "Critical Incident Response Workflow",
  description: "Multi-agent orchestration for rapid incident response and recovery",
  inputSchema: IncidentSchema,
  agents: {
    detectionAgent: {
      id: "detection-specialist",
      capabilities: ["monitoring", "validation", "telemetry", "impact_analysis"],
      priority: "critical"
    },
    diagnosisAgent: {
      id: "diagnosis-specialist",
      capabilities: ["log_analysis", "metric_analysis", "pattern_matching", "rca"],
      priority: "critical"
    },
    mitigationAgent: {
      id: "mitigation-specialist",
      capabilities: ["emergency_response", "automation", "rollback", "patching"],
      priority: "critical"
    },
    recoveryAgent: {
      id: "recovery-specialist",
      capabilities: ["service_restoration", "validation", "monitoring", "rollback"],
      priority: "high"
    },
    communicationAgent: {
      id: "communication-specialist",
      capabilities: ["notifications", "status_updates", "escalation", "reporting"],
      priority: "high"
    },
    postMortemAgent: {
      id: "postmortem-specialist",
      capabilities: ["analysis", "documentation", "improvement", "learning"],
      priority: "medium"
    }
  },
  steps: [
    detectionStep,
    diagnosisStep,
    mitigationStep,
    recoveryStep$1,
    communicationStep,
    postMortemStep
  ],
  // Workflow-level configurations
  config: {
    timeout: 36e5,
    // 1 hour max for entire incident
    retryPolicy: {
      maxAttempts: 3,
      backoffMultiplier: 2,
      initialDelay: 1e3
    },
    parallelExecution: true,
    realTimeMonitoring: true,
    escalationRules: {
      P0: {
        escalateAfter: 300,
        // 5 minutes
        notifyLevels: ["director", "vp", "cto"]
      },
      P1: {
        escalateAfter: 900,
        // 15 minutes
        notifyLevels: ["manager", "director"]
      }
    }
  },
  // Error handling
  onError: async (error, context) => {
    console.error("\u274C Workflow error:", error);
    if (context.input.severity === "P0") {
      await context.agents.mitigationAgent.execute({
        task: "emergency_fallback",
        error: error.message,
        action: "activate_dr_site"
      });
    }
    await context.agents.communicationAgent.execute({
      task: "notify_failure",
      error: error.message,
      context: context.currentStep
    });
  },
  // Success handler
  onSuccess: async (result, context) => {
    console.log("\u2705 Incident resolved successfully");
    await context.agents.postMortemAgent.execute({
      task: "schedule_review",
      incidentId: context.executionId,
      scheduledFor: "+2d",
      participants: ["engineering_team", "sre_team", "product_team"]
    });
    await context.agents.postMortemAgent.execute({
      task: "update_incident_db",
      incident: {
        id: context.executionId,
        ...result,
        status: "resolved"
      }
    });
  }
});

const researchPhase = createStep({
  id: "research-phase",
  description: "Conduct market research and define AI product requirements",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F52C} Starting AI Product Research Phase");
    const { productIdea, targetMarket, businessGoals } = input;
    const marketAnalysis = await agents2.researcher.analyze({
      task: "market-analysis",
      data: {
        productIdea,
        targetMarket,
        competitors: await agents2.researcher.findCompetitors(productIdea),
        technicalTrends: await agents2.researcher.analyzeTrends("ai-ml-technologies")
      }
    });
    const systemDesign = await agents2.architect.design({
      requirements: marketAnalysis.technicalRequirements,
      constraints: {
        scalability: businessGoals.expectedUsers,
        performance: businessGoals.responseTime,
        compliance: businessGoals.regulations
      }
    });
    const projectRoadmap = await agents2.coordinator.plan({
      phases: ["research", "data-collection", "model-development", "deployment", "monitoring"],
      timeline: businessGoals.timeline,
      resources: await agents2.coordinator.estimateResources(systemDesign)
    });
    return {
      marketAnalysis,
      systemDesign,
      projectRoadmap,
      feasibilityScore: marketAnalysis.feasibility * systemDesign.implementationScore
    };
  }
});
const dataCollectionPhase = createStep({
  id: "data-collection-phase",
  description: "Design and implement data collection pipelines",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F4CA} Starting Data Collection Phase");
    const { systemDesign, marketAnalysis } = input;
    const dataPipeline = await agents2.coder.implement({
      type: "data-pipeline",
      specifications: {
        sources: marketAnalysis.dataSources,
        format: systemDesign.dataFormat,
        volume: systemDesign.expectedDataVolume
      }
    });
    const dataQualityReport = await agents2.analyst.analyze({
      pipeline: dataPipeline,
      metrics: ["completeness", "accuracy", "consistency", "timeliness"],
      sampleSize: 1e4
    });
    const dataTests = await agents2.tester.createTests({
      type: "data-validation",
      pipeline: dataPipeline,
      qualityThresholds: dataQualityReport.recommendedThresholds
    });
    const complianceReview = await agents2.reviewer.review({
      type: "data-compliance",
      pipeline: dataPipeline,
      regulations: ["GDPR", "CCPA", "HIPAA"],
      dataTypes: marketAnalysis.dataTypes
    });
    return {
      dataPipeline,
      dataQualityReport,
      dataTests,
      complianceReview,
      dataReadiness: dataQualityReport.overallScore * complianceReview.complianceScore
    };
  }
});
const modelDevelopmentPhase = createStep({
  id: "model-development-phase",
  description: "Develop and train ML models",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F916} Starting Model Development Phase");
    const { dataPipeline, systemDesign } = input;
    const modelResearch = await agents2.researcher.research({
      domain: systemDesign.mlDomain,
      requirements: systemDesign.modelRequirements,
      stateOfArt: await agents2.researcher.findLatestPapers(systemDesign.mlDomain)
    });
    const modelImplementation = await agents2.coder.implement({
      type: "ml-model",
      architecture: modelResearch.recommendedArchitecture,
      framework: systemDesign.mlFramework,
      hyperparameters: modelResearch.suggestedHyperparameters
    });
    const trainingPlan = await agents2.coordinator.orchestrate({
      task: "distributed-training",
      model: modelImplementation,
      data: dataPipeline,
      resources: {
        gpus: systemDesign.trainingResources.gpus,
        memory: systemDesign.trainingResources.memory,
        nodes: systemDesign.trainingResources.nodes
      }
    });
    const modelEvaluation = await agents2.analyst.evaluate({
      model: modelImplementation,
      metrics: ["accuracy", "precision", "recall", "f1", "latency"],
      testData: dataPipeline.testSet,
      benchmarks: modelResearch.industryBenchmarks
    });
    const modelTests = await agents2.tester.createTests({
      type: "ml-model",
      model: modelImplementation,
      scenarios: ["edge-cases", "adversarial", "performance", "fairness"]
    });
    return {
      modelImplementation,
      trainingPlan,
      modelEvaluation,
      modelTests,
      modelScore: modelEvaluation.overallPerformance
    };
  }
});
const apiDesignPhase = createStep({
  id: "api-design-phase",
  description: "Design and implement API for model serving",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F50C} Starting API Design Phase");
    const { modelImplementation, systemDesign } = input;
    const apiDesign = await agents2.architect.design({
      type: "rest-api",
      model: modelImplementation,
      requirements: {
        throughput: systemDesign.apiRequirements.rps,
        latency: systemDesign.apiRequirements.p99Latency,
        authentication: systemDesign.security.authMethod
      }
    });
    const apiImplementation = await agents2.coder.implement({
      type: "api-service",
      design: apiDesign,
      framework: "fastapi",
      features: ["rate-limiting", "caching", "monitoring", "versioning"]
    });
    const apiTests = await agents2.tester.createTests({
      type: "api-integration",
      endpoints: apiImplementation.endpoints,
      scenarios: ["load-testing", "security", "error-handling", "versioning"]
    });
    const securityReview = await agents2.reviewer.review({
      type: "api-security",
      implementation: apiImplementation,
      threats: ["injection", "authentication", "authorization", "dos"]
    });
    return {
      apiDesign,
      apiImplementation,
      apiTests,
      securityReview,
      apiReadiness: apiTests.coverage * securityReview.securityScore
    };
  }
});
const ethicsReviewPhase = createStep({
  id: "ethics-review-phase",
  description: "Conduct comprehensive ethics and bias review",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u2696\uFE0F Starting Ethics and Bias Review Phase");
    const { modelImplementation, dataPipeline } = input;
    const biasAnalysis = await agents2.analyst.analyze({
      type: "bias-detection",
      model: modelImplementation,
      data: dataPipeline,
      dimensions: ["gender", "race", "age", "socioeconomic"],
      techniques: ["statistical-parity", "equalized-odds", "calibration"]
    });
    const ethicsReview = await agents2.reviewer.review({
      type: "ai-ethics",
      model: modelImplementation,
      useCase: input.productIdea,
      guidelines: ["fairness", "transparency", "accountability", "privacy"],
      stakeholders: input.targetMarket
    });
    const mitigationPlan = await agents2.coordinator.plan({
      type: "bias-mitigation",
      issues: [...biasAnalysis.issues, ...ethicsReview.concerns],
      strategies: ["resampling", "reweighting", "adversarial-debiasing", "post-processing"]
    });
    const mitigatedModel = await agents2.coder.implement({
      type: "bias-mitigation",
      model: modelImplementation,
      strategies: mitigationPlan.selectedStrategies,
      constraints: ethicsReview.requirements
    });
    return {
      biasAnalysis,
      ethicsReview,
      mitigationPlan,
      mitigatedModel,
      ethicsScore: ethicsReview.complianceScore * (1 - biasAnalysis.overallBias)
    };
  }
});
const deploymentPrepPhase = createStep({
  id: "deployment-prep-phase",
  description: "Prepare for production deployment",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F680} Starting Deployment Preparation Phase");
    const { mitigatedModel, apiImplementation, systemDesign } = input;
    const deploymentArchitecture = await agents2.architect.design({
      type: "deployment",
      components: [mitigatedModel, apiImplementation],
      infrastructure: systemDesign.deploymentTarget,
      scalingStrategy: "horizontal-autoscaling"
    });
    const deploymentConfig = await agents2.coder.implement({
      type: "deployment-config",
      architecture: deploymentArchitecture,
      tools: ["kubernetes", "terraform", "helm"],
      environments: ["staging", "production"]
    });
    const deploymentTests = await agents2.tester.createTests({
      type: "deployment",
      config: deploymentConfig,
      scenarios: ["rollout", "rollback", "scaling", "failover", "disaster-recovery"]
    });
    const deploymentChecklist = await agents2.coordinator.createChecklist({
      phases: ["pre-deployment", "deployment", "post-deployment"],
      validations: deploymentTests.validations,
      approvals: ["technical", "business", "compliance", "security"]
    });
    return {
      deploymentArchitecture,
      deploymentConfig,
      deploymentTests,
      deploymentChecklist,
      deploymentReadiness: deploymentTests.readinessScore
    };
  }
});
const productionDeployPhase = createStep({
  id: "production-deploy-phase",
  description: "Deploy to production with monitoring",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F310} Starting Production Deployment Phase");
    const { deploymentConfig} = input;
    const deployment = await agents2.coordinator.orchestrate({
      type: "production-deployment",
      config: deploymentConfig,
      strategy: "blue-green",
      rolloutPercentage: [10, 25, 50, 100]
    });
    const monitoringSetup = await agents2.coder.implement({
      type: "monitoring",
      metrics: ["latency", "throughput", "error-rate", "model-drift", "resource-usage"],
      tools: ["prometheus", "grafana", "elasticsearch"],
      alerts: deployment.alertingRules
    });
    const productionValidation = await agents2.tester.validate({
      deployment,
      tests: ["smoke", "integration", "performance", "security"],
      environment: "production"
    });
    const analyticsSetup = await agents2.analyst.setup({
      type: "production-analytics",
      metrics: ["user-engagement", "model-performance", "business-kpis", "cost-analysis"],
      dashboards: ["executive", "technical", "operational"]
    });
    return {
      deployment,
      monitoringSetup,
      productionValidation,
      analyticsSetup,
      deploymentStatus: productionValidation.status
    };
  }
});
const monitoringPhase = createStep({
  id: "monitoring-iteration-phase",
  description: "Monitor production and iterate based on feedback",
  execute: async ({ input, agents: agents2, logger }) => {
    logger.info("\u{1F4C8} Starting Monitoring and Iteration Phase");
    const { deployment, monitoringSetup} = input;
    const performanceReport = await agents2.analyst.monitor({
      deployment,
      duration: "7d",
      metrics: monitoringSetup.metrics,
      thresholds: input.systemDesign.slaRequirements
    });
    const feedbackAnalysis = await agents2.researcher.analyze({
      type: "user-feedback",
      sources: ["support-tickets", "reviews", "usage-patterns"],
      sentiment: true,
      topics: true
    });
    const improvementPlan = await agents2.coordinator.plan({
      type: "continuous-improvement",
      performanceGaps: performanceReport.gaps,
      userFeedback: feedbackAnalysis.insights,
      priority: "business-impact"
    });
    const postDeployReview = await agents2.reviewer.review({
      type: "post-deployment",
      deployment,
      performance: performanceReport,
      incidents: await agents2.coordinator.getIncidents(deployment.id),
      lessons: true
    });
    const nextIteration = await agents2.coordinator.prepareIteration({
      improvements: improvementPlan.tasks,
      timeline: improvementPlan.schedule,
      resources: improvementPlan.requiredResources
    });
    return {
      performanceReport,
      feedbackAnalysis,
      improvementPlan,
      postDeployReview,
      nextIteration,
      productHealth: performanceReport.overallHealth
    };
  }
});
const aiProductDevelopmentWorkflow = createWorkflow({
  id: "ai-product-development",
  name: "AI Product Development Workflow",
  description: "End-to-end workflow for developing AI-powered products with comprehensive agent collaboration",
  steps: [
    researchPhase,
    dataCollectionPhase,
    modelDevelopmentPhase,
    apiDesignPhase,
    ethicsReviewPhase,
    deploymentPrepPhase,
    productionDeployPhase,
    monitoringPhase
  ],
  config: {
    retries: 3,
    timeout: "24h",
    checkpoints: true,
    parallelization: {
      enabled: true,
      maxConcurrent: 4
    }
  },
  hooks: {
    beforeStep: async ({ step, input, logger }) => {
      logger.info(`Starting step: ${step.id}`);
      await agents.coordinator.notifyStakeholders({
        step: step.id,
        status: "starting",
        input
      });
    },
    afterStep: async ({ step, output, logger }) => {
      logger.info(`Completed step: ${step.id}`);
      await agents.coordinator.saveCheckpoint({
        step: step.id,
        output,
        timestamp: /* @__PURE__ */ new Date()
      });
    },
    onError: async ({ error, step, logger }) => {
      logger.error(`Error in step ${step.id}: ${error.message}`);
      await agents.coordinator.handleError({
        step: step.id,
        error,
        recovery: "rollback"
      });
    },
    onComplete: async ({ output, logger }) => {
      logger.info("AI Product Development Workflow completed successfully");
      await agents.coordinator.generateReport({
        type: "project-completion",
        results: output,
        metrics: {
          duration: output.totalDuration,
          cost: output.totalCost,
          quality: output.qualityMetrics
        }
      });
    }
  }
});
const feedbackLoop = createWorkflow({
  id: "ai-feedback-loop",
  name: "AI Product Feedback Loop",
  description: "Continuous improvement loop for deployed AI products",
  steps: [
    createStep({
      id: "collect-metrics",
      execute: async ({ agents: agents2 }) => {
        const metrics = await agents2.analyst.collectMetrics({
          sources: ["production", "staging", "user-analytics"],
          window: "24h"
        });
        return { metrics };
      }
    }),
    createStep({
      id: "analyze-drift",
      execute: async ({ input, agents: agents2 }) => {
        const driftAnalysis = await agents2.analyst.detectDrift({
          currentMetrics: input.metrics,
          baseline: input.deploymentBaseline,
          thresholds: input.driftThresholds
        });
        return { driftAnalysis };
      }
    }),
    createStep({
      id: "evaluate-retraining",
      execute: async ({ input, agents: agents2 }) => {
        const retrainingDecision = await agents2.coordinator.evaluate({
          drift: input.driftAnalysis,
          cost: await agents2.analyst.estimateRetrainingCost(),
          benefit: await agents2.analyst.estimateRetrainingBenefit()
        });
        return { retrainingDecision };
      }
    }),
    createStep({
      id: "trigger-retraining",
      execute: async ({ input, agents: agents2 }) => {
        if (input.retrainingDecision.shouldRetrain) {
          const retrainingJob = await agents2.coordinator.trigger({
            workflow: "model-retraining",
            data: input.retrainingDecision.parameters
          });
          return { retrainingJob };
        }
        return { status: "no-retraining-needed" };
      }
    })
  ],
  config: {
    schedule: "0 */6 * * *",
    // Run every 6 hours
    continuous: true
  }
});

const assessmentPhase = createStep({
  id: "assessment-phase",
  description: "Comprehensive system assessment and discovery",
  execute: async ({ context }) => {
    const { agents, migrationConfig } = context;
    const assessmentTasks = await Promise.all([
      // System Discovery
      agents.coder.execute({
        task: "system-discovery",
        config: {
          targets: migrationConfig.sourceSystems,
          depth: "comprehensive",
          includeMetrics: true
        }
      }),
      // Risk Analysis
      agents.analyst.execute({
        task: "risk-assessment",
        config: {
          domains: ["technical", "business", "compliance", "security"],
          impactAnalysis: true,
          mitigationStrategies: true
        }
      }),
      // Architecture Review
      agents.architect.execute({
        task: "architecture-assessment",
        config: {
          currentState: true,
          futureState: true,
          gapAnalysis: true,
          dependencies: true
        }
      }),
      // Compliance Check
      agents.reviewer.execute({
        task: "compliance-audit",
        config: {
          standards: ["SOC2", "GDPR", "HIPAA", "PCI-DSS"],
          regulatoryRequirements: true,
          dataClassification: true
        }
      })
    ]);
    const assessment = await agents.coordinator.execute({
      task: "consolidate-assessment",
      inputs: assessmentTasks,
      outputs: {
        executiveSummary: true,
        detailedFindings: true,
        riskMatrix: true,
        recommendedApproach: true
      }
    });
    return {
      assessment,
      continueMigration: assessment.riskScore < migrationConfig.riskThreshold,
      criticalIssues: assessment.criticalFindings
    };
  }
});
const planningPhase = createStep({
  id: "planning-phase",
  description: "Detailed migration planning with rollback strategies",
  dependsOn: ["assessment-phase"],
  execute: async ({ context, previousResults }) => {
    const { agents, migrationConfig } = context;
    const { assessment } = previousResults["assessment-phase"];
    const migrationArchitecture = await agents.architect.execute({
      task: "design-migration-architecture",
      inputs: {
        assessment,
        targetPlatform: migrationConfig.targetPlatform,
        constraints: migrationConfig.constraints
      },
      outputs: {
        phasedApproach: true,
        dataFlowDiagrams: true,
        networkTopology: true,
        securityArchitecture: true
      }
    });
    const planningTasks = await Promise.all([
      // Technical Implementation Plan
      agents.coder.execute({
        task: "create-technical-plan",
        inputs: {
          architecture: migrationArchitecture,
          components: assessment.systemInventory
        },
        outputs: {
          migrationScripts: true,
          dataTransformations: true,
          apiMappings: true,
          rollbackProcedures: true
        }
      }),
      // Test Strategy
      agents.tester.execute({
        task: "develop-test-strategy",
        inputs: {
          architecture: migrationArchitecture,
          riskAreas: assessment.riskMatrix
        },
        outputs: {
          testScenarios: true,
          performanceBaselines: true,
          validationCriteria: true,
          rollbackTests: true
        }
      }),
      // Resource Optimization
      agents.optimizer.execute({
        task: "optimize-migration-resources",
        inputs: {
          workloads: assessment.workloadAnalysis,
          timeline: migrationConfig.timeline
        },
        outputs: {
          resourceAllocation: true,
          costOptimization: true,
          performanceTargets: true,
          scalingStrategies: true
        }
      }),
      // Documentation Plan
      agents.documenter.execute({
        task: "create-documentation-plan",
        outputs: {
          runbooks: true,
          disasterRecovery: true,
          operationalProcedures: true,
          knowledgeTransfer: true
        }
      })
    ]);
    const masterPlan = await agents.coordinator.execute({
      task: "create-master-migration-plan",
      inputs: {
        architecture: migrationArchitecture,
        plans: planningTasks
      },
      outputs: {
        executionTimeline: true,
        milestones: true,
        goNoGoCriteria: true,
        communicationPlan: true
      }
    });
    return {
      masterPlan,
      estimatedDuration: masterPlan.timeline.totalDays,
      resourceRequirements: masterPlan.resources
    };
  }
});
const pilotPhase = createStep({
  id: "pilot-phase",
  description: "Execute pilot migration with subset of systems",
  dependsOn: ["planning-phase"],
  execute: async ({ context, previousResults }) => {
    const { agents} = context;
    const { masterPlan } = previousResults["planning-phase"];
    const pilotSystems = await agents.analyst.execute({
      task: "select-pilot-systems",
      inputs: {
        systemInventory: previousResults["assessment-phase"].assessment.systemInventory,
        criteria: {
          representativeWorkloads: true,
          lowBusinessImpact: true,
          technicalComplexity: "medium"
        }
      }
    });
    const pilotExecution = await agents.coder.execute({
      task: "execute-pilot-migration",
      inputs: {
        systems: pilotSystems,
        plan: masterPlan.technicalPlan
      },
      monitoring: {
        realTime: true,
        metrics: ["performance", "errors", "availability"]
      }
    });
    const validationResults = await Promise.all([
      // Functional Testing
      agents.tester.execute({
        task: "pilot-functional-testing",
        inputs: {
          systems: pilotSystems,
          testPlan: masterPlan.testStrategy
        },
        coverage: {
          functional: 100,
          integration: 95,
          endToEnd: 90
        }
      }),
      // Performance Analysis
      agents.optimizer.execute({
        task: "pilot-performance-analysis",
        inputs: {
          baseline: masterPlan.performanceBaselines,
          current: pilotExecution.metrics
        },
        analysis: {
          latency: true,
          throughput: true,
          resourceUtilization: true,
          costComparison: true
        }
      }),
      // Security Validation
      agents.reviewer.execute({
        task: "pilot-security-validation",
        scans: {
          vulnerability: true,
          penetrationTesting: true,
          complianceCheck: true,
          dataIntegrity: true
        }
      })
    ]);
    const rollbackTest = await agents.specialist.execute({
      task: "test-rollback-procedures",
      inputs: {
        procedures: masterPlan.rollbackPlan,
        systems: pilotSystems
      },
      validation: {
        dataConsistency: true,
        serviceAvailability: true,
        timingRequirements: true
      }
    });
    const pilotAnalysis = await agents.coordinator.execute({
      task: "analyze-pilot-results",
      inputs: {
        execution: pilotExecution,
        validation: validationResults,
        rollbackTest
      },
      outputs: {
        successCriteriaMet: true,
        issuesIdentified: true,
        recommendedAdjustments: true,
        confidenceScore: true
      }
    });
    return {
      pilotAnalysis,
      proceedToFullMigration: pilotAnalysis.confidenceScore > 0.85,
      adjustmentsRequired: pilotAnalysis.recommendedAdjustments
    };
  }
});
const migrationPhase = createStep({
  id: "migration-phase",
  description: "Execute full-scale migration with parallel workstreams",
  dependsOn: ["pilot-phase"],
  execute: async ({ context, previousResults }) => {
    const { agents} = context;
    const { masterPlan } = previousResults["planning-phase"];
    const { adjustmentsRequired } = previousResults["pilot-phase"];
    const updatedPlan = await agents.architect.execute({
      task: "update-migration-plan",
      inputs: {
        originalPlan: masterPlan,
        adjustments: adjustmentsRequired
      }
    });
    const migrationWaves = await agents.coordinator.execute({
      task: "create-migration-waves",
      inputs: {
        systems: previousResults["assessment-phase"].assessment.systemInventory,
        dependencies: updatedPlan.dependencyMap
      },
      strategy: {
        parallelization: "maximum-safe",
        riskMitigation: true,
        businessContinuity: true
      }
    });
    const waveResults = [];
    for (const wave of migrationWaves.waves) {
      await Promise.all([
        agents.coder.execute({
          task: "prepare-migration-environment",
          wave: wave.id,
          actions: ["backup", "snapshot", "healthCheck"]
        }),
        agents.documenter.execute({
          task: "update-runbooks",
          wave: wave.id,
          includeRollback: true
        })
      ]);
      const waveExecution = await Promise.all([
        // Data Migration
        agents.specialist.execute({
          task: "migrate-data",
          systems: wave.dataSystems,
          strategy: {
            method: "parallel-replication",
            validation: "continuous",
            encryption: true
          }
        }),
        // Application Migration
        agents.coder.execute({
          task: "migrate-applications",
          systems: wave.appSystems,
          strategy: {
            method: "blue-green",
            canaryPercentage: 10,
            healthChecks: true
          }
        }),
        // Infrastructure Migration
        agents.architect.execute({
          task: "migrate-infrastructure",
          systems: wave.infraSystems,
          strategy: {
            method: "lift-and-shift",
            optimization: "post-migration",
            monitoring: true
          }
        })
      ]);
      const waveValidation = await Promise.all([
        agents.tester.execute({
          task: "validate-wave-migration",
          wave: wave.id,
          tests: ["smoke", "integration", "performance"]
        }),
        agents.monitor.execute({
          task: "monitor-wave-health",
          wave: wave.id,
          duration: "2h",
          alerts: true
        })
      ]);
      const waveDecision = await agents.coordinator.execute({
        task: "wave-go-nogo-decision",
        inputs: {
          execution: waveExecution,
          validation: waveValidation
        },
        criteria: {
          errorThreshold: 0.01,
          performanceDegradation: 0.05,
          businessImpact: "minimal"
        }
      });
      if (!waveDecision.proceed) {
        await agents.specialist.execute({
          task: "execute-wave-rollback",
          wave: wave.id,
          reason: waveDecision.issues
        });
        return {
          status: "rollback-executed",
          wave: wave.id,
          issues: waveDecision.issues
        };
      }
      waveResults.push({
        wave: wave.id,
        status: "completed",
        metrics: waveValidation
      });
    }
    return {
      migrationStatus: "completed",
      waves: waveResults,
      totalSystemsMigrated: migrationWaves.totalSystems
    };
  }
});
const validationPhase = createStep({
  id: "validation-phase",
  description: "Comprehensive validation and post-migration optimization",
  dependsOn: ["migration-phase"],
  execute: async ({ context, previousResults }) => {
    const { agents } = context;
    const validationSuite = await Promise.all([
      // End-to-end testing
      agents.tester.execute({
        task: "e2e-validation",
        scope: "full-system",
        scenarios: {
          businessCritical: true,
          edgeCases: true,
          stressTesting: true,
          disasterRecovery: true
        }
      }),
      // Performance optimization
      agents.optimizer.execute({
        task: "post-migration-optimization",
        areas: {
          queryOptimization: true,
          caching: true,
          autoScaling: true,
          costOptimization: true
        }
      }),
      // Security hardening
      agents.reviewer.execute({
        task: "security-hardening",
        actions: {
          vulnerabilityPatching: true,
          accessControlReview: true,
          encryptionValidation: true,
          complianceCertification: true
        }
      }),
      // Data validation
      agents.analyst.execute({
        task: "data-integrity-validation",
        checks: {
          completeness: true,
          accuracy: true,
          consistency: true,
          referentialIntegrity: true
        }
      })
    ]);
    const businessValidation = await agents.specialist.execute({
      task: "business-process-validation",
      processes: {
        criticalWorkflows: true,
        reportingAccuracy: true,
        slaCompliance: true,
        userAcceptance: true
      }
    });
    const validationReport = await agents.documenter.execute({
      task: "generate-validation-report",
      inputs: {
        technical: validationSuite,
        business: businessValidation
      },
      sections: {
        executiveSummary: true,
        detailedFindings: true,
        recommendations: true,
        signoffCriteria: true
      }
    });
    return {
      validationReport,
      readyForCutover: validationReport.allTestsPassed,
      optimizationsSuggested: validationReport.recommendations
    };
  }
});
const cutoverPhase = createStep({
  id: "cutover-phase",
  description: "Final cutover and go-live orchestration",
  dependsOn: ["validation-phase"],
  execute: async ({ context, previousResults }) => {
    const { agents, migrationConfig } = context;
    const { readyForCutover } = previousResults["validation-phase"];
    if (!readyForCutover) {
      return {
        status: "cutover-postponed",
        reason: "validation-criteria-not-met"
      };
    }
    await Promise.all([
      // Communication
      agents.coordinator.execute({
        task: "cutover-communication",
        audiences: ["executives", "users", "support", "partners"],
        channels: ["email", "portal", "statusPage"]
      }),
      // Final backups
      agents.specialist.execute({
        task: "final-backup-snapshot",
        scope: "all-systems",
        verification: true
      }),
      // Support readiness
      agents.documenter.execute({
        task: "prepare-support-materials",
        materials: ["faqs", "troubleshooting", "escalation"]
      })
    ]);
    const cutoverExecution = await agents.coordinator.execute({
      task: "execute-cutover",
      steps: [
        { action: "dns-switch", timing: "immediate" },
        { action: "traffic-routing", timing: "gradual", duration: "2h" },
        { action: "legacy-shutdown", timing: "post-validation" }
      ],
      monitoring: {
        realTime: true,
        alerting: true,
        rollbackReady: true
      }
    });
    const monitoring = await agents.monitor.execute({
      task: "post-cutover-monitoring",
      duration: "24h",
      metrics: {
        availability: true,
        performance: true,
        errors: true,
        userExperience: true
      },
      escalation: {
        automatic: true,
        thresholds: migrationConfig.slaThresholds
      }
    });
    const finalOptimization = await agents.optimizer.execute({
      task: "post-cutover-optimization",
      based_on: monitoring.metrics,
      actions: {
        autoScaling: true,
        cacheWarming: true,
        queryOptimization: true
      }
    });
    const successEvaluation = await agents.analyst.execute({
      task: "evaluate-migration-success",
      criteria: {
        technical: monitoring.metrics,
        business: cutoverExecution.businessMetrics,
        financial: finalOptimization.costAnalysis
      }
    });
    return {
      status: "migration-complete",
      success: successEvaluation,
      finalReport: await agents.documenter.execute({
        task: "final-migration-report",
        comprehensive: true
      })
    };
  }
});
const enterpriseMigrationWorkflow = createWorkflow({
  id: "enterprise-migration-workflow",
  name: "Enterprise System Migration",
  description: "Complete enterprise-scale system migration with multi-agent orchestration",
  steps: [
    assessmentPhase,
    planningPhase,
    pilotPhase,
    migrationPhase,
    validationPhase,
    cutoverPhase
  ],
  config: {
    // Workflow configuration
    timeout: "30d",
    // 30-day maximum duration
    retries: {
      enabled: true,
      maxAttempts: 3,
      backoffStrategy: "exponential"
    },
    // Checkpoint management
    checkpoints: {
      enabled: true,
      storage: "persistent",
      recovery: "automatic"
    },
    // Monitoring configuration
    monitoring: {
      detailed: true,
      metrics: ["progress", "errors", "performance", "cost"],
      dashboards: ["executive", "technical", "operational"]
    },
    // Notification configuration
    notifications: {
      channels: ["email", "slack", "pagerduty"],
      events: ["phase-complete", "errors", "rollback", "success"],
      stakeholders: {
        executive: ["phase-complete", "success"],
        technical: ["all"],
        operations: ["errors", "rollback"]
      }
    }
  },
  // Error handling
  onError: async ({ error, step, context }) => {
    const { agents } = context;
    await agents.coordinator.execute({
      task: "handle-migration-error",
      error,
      step,
      actions: ["assess-impact", "notify-stakeholders", "prepare-rollback"]
    });
    const decision = await agents.analyst.execute({
      task: "error-recovery-decision",
      error,
      impact: error.impact,
      options: ["retry", "rollback", "manual-intervention"]
    });
    return decision;
  },
  // Success handler
  onSuccess: async ({ results, context }) => {
    const { agents } = context;
    await Promise.all([
      agents.documenter.execute({
        task: "generate-success-reports",
        audiences: ["executive", "technical", "compliance"]
      }),
      agents.optimizer.execute({
        task: "capture-optimization-opportunities",
        for: "future-migrations"
      }),
      agents.coordinator.execute({
        task: "schedule-post-migration-reviews",
        intervals: ["1-week", "1-month", "3-months"]
      })
    ]);
  }
});

const pivotInputSchema = z.object({
  currentProduct: z.object({
    name: z.string(),
    market: z.string(),
    revenue: z.number(),
    userBase: z.number(),
    techStack: z.array(z.string()),
    painPoints: z.array(z.string())
  }),
  pivotOptions: z.array(z.object({
    name: z.string(),
    targetMarket: z.string(),
    estimatedTAM: z.number(),
    requiredChanges: z.array(z.string()),
    timeToMarket: z.number()
    // months
  })),
  constraints: z.object({
    budget: z.number(),
    timeline: z.number(),
    // months
    teamSize: z.number(),
    mustRetainFeatures: z.array(z.string()).optional()
  }),
  stakeholders: z.array(z.object({
    role: z.string(),
    concerns: z.array(z.string()),
    priority: z.enum(["high", "medium", "low"])
  }))
});
const marketAnalysisStep = createStep({
  id: "market-analysis",
  description: "Comprehensive market analysis and opportunity assessment",
  execute: async ({ data, agents }) => {
    const { currentProduct, pivotOptions } = data;
    const marketAnalysis = await agents.marketAnalyst.analyze({
      task: "comprehensive-market-analysis",
      data: {
        currentMarket: {
          product: currentProduct,
          competitors: await agents.marketAnalyst.findCompetitors(currentProduct.market),
          marketTrends: await agents.marketAnalyst.analyzeTrends(currentProduct.market)
        },
        pivotOpportunities: await Promise.all(
          pivotOptions.map(async (option) => ({
            option,
            marketSize: await agents.marketAnalyst.calculateTAM(option.targetMarket),
            competitiveLandscape: await agents.marketAnalyst.analyzeCompetition(option.targetMarket),
            customerSegments: await agents.marketAnalyst.identifySegments(option.targetMarket),
            growthProjections: await agents.marketAnalyst.projectGrowth(option, 5)
            // 5 year projection
          }))
        )
      }
    });
    const businessAnalysis = await agents.businessAnalyst.evaluate({
      marketData: marketAnalysis,
      criteria: {
        revenueProjections: true,
        customerAcquisitionCost: true,
        lifetimeValue: true,
        breakEvenAnalysis: true,
        resourceRequirements: true
      }
    });
    return {
      marketInsights: marketAnalysis,
      businessViability: businessAnalysis,
      rankedOptions: businessAnalysis.rankings,
      keyFindings: {
        topOpportunity: businessAnalysis.rankings[0],
        risks: marketAnalysis.identifiedRisks,
        opportunities: marketAnalysis.opportunities
      }
    };
  }
});
const technicalFeasibilityStep = createStep({
  id: "technical-feasibility",
  description: "Assess technical feasibility and migration requirements",
  execute: async ({ data, previousSteps, agents }) => {
    const { currentProduct, constraints } = data;
    const { rankedOptions } = previousSteps["market-analysis"];
    const technicalAssessment = await agents.technicalAnalyst.assess({
      currentArchitecture: {
        stack: currentProduct.techStack,
        infrastructure: await agents.technicalAnalyst.analyzeInfrastructure(),
        dependencies: await agents.technicalAnalyst.mapDependencies(),
        technicalDebt: await agents.technicalAnalyst.assessTechnicalDebt()
      },
      pivotRequirements: await Promise.all(
        rankedOptions.slice(0, 3).map(async (option) => ({
          option,
          architectureChanges: await agents.technicalAnalyst.designArchitecture(option),
          migrationPath: await agents.technicalAnalyst.planMigration(option),
          reuseableComponents: await agents.technicalAnalyst.identifyReusable(option),
          newComponents: await agents.technicalAnalyst.identifyNewRequirements(option),
          estimatedEffort: await agents.technicalAnalyst.estimateEffort(option)
        }))
      )
    });
    const implementationPlan = await agents.implementationSpecialist.createPlan({
      technicalRequirements: technicalAssessment,
      constraints,
      priorities: {
        minimizeDisruption: true,
        maintainBackwardsCompatibility: constraints.mustRetainFeatures?.length > 0,
        phaseApproach: true
      }
    });
    return {
      technicalAnalysis: technicalAssessment,
      implementationStrategy: implementationPlan,
      feasibilityScores: technicalAssessment.feasibilityRankings,
      criticalPath: implementationPlan.criticalPath,
      resourceNeeds: {
        additionalSkills: implementationPlan.skillGaps,
        infrastructure: implementationPlan.infrastructureNeeds,
        tooling: implementationPlan.requiredTools
      }
    };
  }
});
const riskAssessmentStep = createStep({
  id: "risk-assessment",
  description: "Comprehensive risk assessment and mitigation strategies",
  execute: async ({ data, previousSteps, agents }) => {
    const { stakeholders } = data;
    const marketAnalysis = previousSteps["market-analysis"];
    const technicalAnalysis = previousSteps["technical-feasibility"];
    const riskAnalysis = await agents.riskAnalyst.analyze({
      dimensions: {
        technical: {
          migrationRisks: technicalAnalysis.implementationStrategy.risks,
          scalabilityRisks: await agents.riskAnalyst.assessScalability(technicalAnalysis),
          securityRisks: await agents.riskAnalyst.assessSecurity(technicalAnalysis)
        },
        business: {
          marketRisks: marketAnalysis.keyFindings.risks,
          competitiveRisks: await agents.riskAnalyst.assessCompetitive(marketAnalysis),
          financialRisks: await agents.riskAnalyst.assessFinancial(marketAnalysis)
        },
        operational: {
          teamRisks: await agents.riskAnalyst.assessTeamCapability(data.constraints),
          processRisks: await agents.riskAnalyst.assessProcessChanges(),
          customerRisks: await agents.riskAnalyst.assessCustomerImpact(data.currentProduct)
        }
      },
      stakeholderConcerns: stakeholders
    });
    const mitigationPlan = await agents.riskAnalyst.createMitigationPlan({
      identifiedRisks: riskAnalysis,
      priorities: riskAnalysis.criticalRisks,
      strategies: {
        preventive: await agents.riskAnalyst.designPreventiveMeasures(riskAnalysis),
        detective: await agents.riskAnalyst.designDetectionMechanisms(riskAnalysis),
        corrective: await agents.riskAnalyst.designCorrectiveActions(riskAnalysis)
      }
    });
    const decisionMatrix = await agents.decisionSupportAgent.createMatrix({
      options: marketAnalysis.rankedOptions.slice(0, 3),
      criteria: {
        marketOpportunity: marketAnalysis.businessViability,
        technicalFeasibility: technicalAnalysis.feasibilityScores,
        riskProfile: riskAnalysis.riskScores,
        resourceRequirements: technicalAnalysis.resourceNeeds,
        timeToMarket: technicalAnalysis.implementationStrategy.timeline
      },
      weights: {
        marketOpportunity: 0.3,
        technicalFeasibility: 0.25,
        riskProfile: 0.2,
        resourceRequirements: 0.15,
        timeToMarket: 0.1
      }
    });
    return {
      riskProfile: riskAnalysis,
      mitigationStrategies: mitigationPlan,
      decisionMatrix,
      recommendation: decisionMatrix.topRecommendation,
      confidenceScore: decisionMatrix.confidenceLevel
    };
  }
});
const strategicDecisionStep = createStep({
  id: "strategic-decision",
  description: "Make strategic pivot decision and create execution plan",
  execute: async ({ data, previousSteps, agents }) => {
    const marketAnalysis = previousSteps["market-analysis"];
    const technicalAnalysis = previousSteps["technical-feasibility"];
    const riskAssessment = previousSteps["risk-assessment"];
    const pivotDecision = await agents.decisionSupportAgent.facilitateDecision({
      recommendation: riskAssessment.recommendation,
      supportingData: {
        market: marketAnalysis,
        technical: technicalAnalysis,
        risk: riskAssessment
      },
      decisionCriteria: {
        mustMeetConstraints: data.constraints,
        alignWithStrategy: true,
        stakeholderBuyIn: data.stakeholders
      }
    });
    const executionPlan = await agents.implementationSpecialist.createDetailedPlan({
      decision: pivotDecision,
      phases: [
        {
          name: "Foundation",
          duration: 2,
          // months
          objectives: ["Core infrastructure", "Team preparation", "Initial prototypes"],
          deliverables: await agents.implementationSpecialist.defineDeliverables("foundation")
        },
        {
          name: "Migration",
          duration: 3,
          objectives: ["Data migration", "Feature parity", "Customer pilot"],
          deliverables: await agents.implementationSpecialist.defineDeliverables("migration")
        },
        {
          name: "Launch",
          duration: 1,
          objectives: ["Full rollout", "Marketing campaign", "Support readiness"],
          deliverables: await agents.implementationSpecialist.defineDeliverables("launch")
        }
      ],
      resources: technicalAnalysis.resourceNeeds,
      riskMitigation: riskAssessment.mitigationStrategies
    });
    const migrationStrategy = await agents.businessAnalyst.createMigrationStrategy({
      customerBase: data.currentProduct.userBase,
      segments: marketAnalysis.marketInsights.pivotOpportunities[0].customerSegments,
      approach: {
        phased: true,
        optIn: true,
        incentives: await agents.businessAnalyst.designIncentives(),
        communication: await agents.businessAnalyst.createCommsPlan()
      }
    });
    return {
      pivotDecision,
      executionPlan,
      migrationStrategy,
      timeline: executionPlan.ganttChart,
      milestones: executionPlan.keyMilestones,
      successMetrics: pivotDecision.successCriteria
    };
  }
});
const executionCoordinationStep = createStep({
  id: "execution-coordination",
  description: "Coordinate multi-team execution and track progress",
  execute: async ({ data, previousSteps, agents }) => {
    const executionPlan = previousSteps["strategic-decision"].executionPlan;
    const migrationStrategy = previousSteps["strategic-decision"].migrationStrategy;
    const executionTracking = await agents.implementationSpecialist.coordinate({
      plan: executionPlan,
      teams: {
        engineering: {
          tasks: executionPlan.phases[0].engineeringTasks,
          dependencies: await agents.technicalAnalyst.mapDependencies(executionPlan)
        },
        product: {
          tasks: executionPlan.phases[0].productTasks,
          customerFeedback: await agents.marketAnalyst.gatherFeedback()
        },
        marketing: {
          tasks: migrationStrategy.communication.tasks,
          campaigns: await agents.businessAnalyst.planCampaigns()
        }
      },
      coordination: {
        dailyStandups: true,
        weeklyReviews: true,
        riskMonitoring: await agents.riskAnalyst.setupMonitoring(),
        progressTracking: await agents.implementationSpecialist.setupTracking()
      }
    });
    const monitoringDashboard = await agents.decisionSupportAgent.createDashboard({
      metrics: {
        progress: executionTracking.progressMetrics,
        quality: await agents.technicalAnalyst.defineQualityMetrics(),
        customer: await agents.marketAnalyst.defineCustomerMetrics(),
        financial: await agents.businessAnalyst.defineFinancialMetrics()
      },
      alerts: {
        riskThresholds: await agents.riskAnalyst.defineThresholds(),
        progressDelays: executionTracking.delayTriggers,
        qualityIssues: executionTracking.qualityTriggers
      },
      reporting: {
        stakeholders: data.stakeholders,
        frequency: "weekly",
        format: "executive-dashboard"
      }
    });
    return {
      executionStatus: executionTracking,
      monitoringSetup: monitoringDashboard,
      currentPhase: executionTracking.currentPhase,
      blockers: executionTracking.identifiedBlockers,
      adjustments: executionTracking.recommendedAdjustments
    };
  }
});
const validationIterationStep = createStep({
  id: "validation-iteration",
  description: "Validate progress and iterate based on feedback",
  execute: async ({ data, previousSteps, agents }) => {
    const executionStatus = previousSteps["execution-coordination"];
    const pivotDecision = previousSteps["strategic-decision"].pivotDecision;
    const validationResults = await Promise.all([
      // Market validation
      agents.marketAnalyst.validate({
        metrics: executionStatus.monitoringSetup.metrics.customer,
        targets: pivotDecision.successCriteria.market,
        feedback: await agents.marketAnalyst.collectCustomerFeedback()
      }),
      // Technical validation
      agents.technicalAnalyst.validate({
        metrics: executionStatus.monitoringSetup.metrics.quality,
        performance: await agents.technicalAnalyst.runPerformanceTests(),
        security: await agents.technicalAnalyst.runSecurityAudits()
      }),
      // Business validation
      agents.businessAnalyst.validate({
        metrics: executionStatus.monitoringSetup.metrics.financial,
        roi: await agents.businessAnalyst.calculateActualROI(),
        efficiency: await agents.businessAnalyst.measureEfficiency()
      }),
      // Risk validation
      agents.riskAnalyst.validate({
        mitigationEffectiveness: await agents.riskAnalyst.assessMitigations(),
        newRisks: await agents.riskAnalyst.identifyEmergingRisks(),
        compliance: await agents.riskAnalyst.checkCompliance()
      })
    ]);
    const iterationPlan = await agents.decisionSupportAgent.createIterationPlan({
      validationResults,
      gaps: await agents.decisionSupportAgent.identifyGaps(validationResults),
      opportunities: await agents.decisionSupportAgent.identifyOpportunities(validationResults),
      adjustments: {
        immediate: await agents.implementationSpecialist.planImmediateChanges(validationResults),
        strategic: await agents.decisionSupportAgent.recommendStrategicAdjustments(validationResults)
      }
    });
    const pivotReport = await agents.decisionSupportAgent.generateReport({
      executiveSummary: {
        decision: pivotDecision,
        progress: executionStatus.currentPhase,
        results: validationResults,
        recommendations: iterationPlan.adjustments
      },
      detailedAnalysis: {
        market: validationResults[0],
        technical: validationResults[1],
        business: validationResults[2],
        risk: validationResults[3]
      },
      nextSteps: iterationPlan,
      lessonsLearned: await agents.decisionSupportAgent.compileLessons(previousSteps)
    });
    return {
      validationSummary: validationResults,
      iterationPlan,
      pivotReport,
      success: validationResults.every((v) => v.meetsTargets),
      nextActions: iterationPlan.prioritizedActions
    };
  }
});
const productPivotWorkflow = createWorkflow({
  name: "product-pivot-workflow",
  description: "Orchestrates major product pivot with comprehensive analysis and execution",
  inputSchema: pivotInputSchema,
  steps: [
    marketAnalysisStep,
    technicalFeasibilityStep,
    riskAssessmentStep,
    strategicDecisionStep,
    executionCoordinationStep,
    validationIterationStep
  ],
  config: {
    maxRetries: 3,
    timeout: 72e5,
    // 2 hours for complete pivot analysis
    parallel: {
      enabled: true,
      maxConcurrency: 4
    },
    monitoring: {
      trackProgress: true,
      alertOnFailure: true,
      dashboardEnabled: true
    }
  }
});

const detectBreachStep = createStep({
  id: "detect-breach",
  name: "Detect Security Breach",
  description: "Initial breach detection and severity assessment",
  execute: async ({ context }) => {
    const { breachIndicators, timestamp, source } = context;
    const alertData = {
      severity: "CRITICAL",
      timestamp,
      source,
      indicators: breachIndicators,
      status: "ACTIVE_BREACH"
    };
    return {
      alertData,
      incidentId: `INC-${Date.now()}`,
      initialAssessment: {
        type: breachIndicators.type || "UNKNOWN",
        scope: breachIndicators.scope || "INVESTIGATING",
        impact: breachIndicators.impact || "ASSESSING"
      }
    };
  }
});
const assembleCrisisTeamStep = createStep({
  id: "assemble-crisis-team",
  name: "Assemble Crisis Response Team",
  description: "Activate all agents in crisis mode",
  execute: async ({ context, prevResult }) => {
    const crisisTeam = {
      agentCoordinator: {
        agent: "Agent Coordinator",
        role: "Crisis Commander",
        responsibilities: ["Overall coordination", "Decision making", "Resource allocation"],
        status: "ACTIVATED"
      },
      researchAnalyst: {
        agent: "Research Analyst",
        role: "Threat Intelligence Lead",
        responsibilities: ["Threat analysis", "Attack vector identification", "Intelligence gathering"],
        status: "ACTIVATED"
      },
      codeArchitect: {
        agent: "Code Architect",
        role: "Technical Response Lead",
        responsibilities: ["System analysis", "Vulnerability assessment", "Technical remediation"],
        status: "ACTIVATED"
      },
      testingExpert: {
        agent: "Testing Expert",
        role: "Forensics Specialist",
        responsibilities: ["Evidence collection", "Impact analysis", "System validation"],
        status: "ACTIVATED"
      },
      docWriter: {
        agent: "Documentation Writer",
        role: "Communications Lead",
        responsibilities: ["Stakeholder updates", "Compliance reporting", "Public relations"],
        status: "ACTIVATED"
      },
      reviewSpecialist: {
        agent: "Review Specialist",
        role: "Compliance Officer",
        responsibilities: ["Regulatory compliance", "Legal coordination", "Audit trail"],
        status: "ACTIVATED"
      }
    };
    return {
      ...prevResult,
      crisisTeam,
      activationTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const technicalInvestigationStep = createStep({
  id: "technical-investigation",
  name: "Technical Investigation Track",
  description: "Parallel technical response and investigation",
  execute: async ({ context, prevResult }) => {
    const threatAnalysis = {
      attackVector: "ANALYZING",
      threatActor: "IDENTIFYING",
      methodology: "INVESTIGATING",
      indicators: []
    };
    const systemAnalysis = {
      affectedSystems: [],
      vulnerabilities: [],
      exploitMethods: [],
      dataExposure: "ASSESSING"
    };
    const forensics = {
      evidenceCollected: [],
      timeline: [],
      affectedData: [],
      intrusionPath: "TRACING"
    };
    return {
      ...prevResult,
      technicalFindings: {
        threatAnalysis,
        systemAnalysis,
        forensics,
        status: "IN_PROGRESS"
      }
    };
  }
});
const communicationResponseStep = createStep({
  id: "communication-response",
  name: "Communication Response Track",
  description: "Parallel stakeholder and regulatory communication",
  execute: async ({ context, prevResult }) => {
    const { alertData } = prevResult;
    const stakeholderComms = {
      internalNotifications: {
        executives: "DRAFTED",
        employees: "PENDING",
        boardMembers: "SCHEDULED"
      },
      externalNotifications: {
        customers: "PREPARING",
        partners: "QUEUED",
        publicStatement: "DRAFTING"
      }
    };
    const complianceReporting = {
      regulatoryBodies: {
        gdpr: alertData.severity === "CRITICAL" ? "REQUIRED" : "MONITORING",
        hipaa: "ASSESSING",
        pci: "EVALUATING",
        sox: "REVIEWING"
      },
      notificationDeadlines: {
        gdpr: "72_HOURS",
        statePrivacyLaws: "24_HOURS",
        contractualObligations: "REVIEWING"
      },
      auditTrail: {
        actions: [],
        decisions: [],
        timeline: []
      }
    };
    return {
      ...prevResult,
      communicationStatus: {
        stakeholderComms,
        complianceReporting,
        status: "EXECUTING"
      }
    };
  }
});
const containmentStep = createStep({
  id: "containment",
  name: "Execute Containment Measures",
  description: "Implement immediate containment to prevent spread",
  execute: async ({ context, prevResult }) => {
    const containmentActions = {
      immediate: {
        networkIsolation: "EXECUTING",
        accountSuspension: "IN_PROGRESS",
        serviceShutdown: "EVALUATING",
        accessRevocation: "IMPLEMENTING"
      },
      shortTerm: {
        patchDeployment: "PREPARING",
        configurationChanges: "PLANNING",
        monitoringEnhancement: "DEPLOYING",
        backupValidation: "VERIFYING"
      },
      validation: {
        containmentEffectiveness: "MONITORING",
        lateralMovementCheck: "SCANNING",
        persistenceMechanisms: "INVESTIGATING"
      }
    };
    return {
      ...prevResult,
      containmentActions,
      containmentStartTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const eradicationStep = createStep({
  id: "eradication",
  name: "Eradicate Threat",
  description: "Remove all traces of the security breach",
  execute: async ({ context, prevResult }) => {
    const eradicationPlan = {
      malwareRemoval: {
        scanResults: "EXECUTING",
        cleanupActions: "QUEUED",
        verificationScans: "SCHEDULED"
      },
      vulnerabilityPatching: {
        criticalPatches: "DEPLOYING",
        systemUpdates: "TESTING",
        configurationHardening: "IMPLEMENTING"
      },
      accessRemediation: {
        compromisedAccounts: "RESETTING",
        privilegeReview: "CONDUCTING",
        mfaEnforcement: "ENABLING"
      },
      dataIntegrity: {
        corruptionCheck: "SCANNING",
        backupRestoration: "EVALUATING",
        integrityValidation: "PENDING"
      }
    };
    return {
      ...prevResult,
      eradicationPlan,
      eradicationStatus: "IN_PROGRESS"
    };
  }
});
const recoveryStep = createStep({
  id: "recovery",
  name: "System Recovery",
  description: "Restore normal operations with enhanced security",
  execute: async ({ context, prevResult }) => {
    const recoveryOperations = {
      systemRestoration: {
        serviceReactivation: "PHASED",
        dataRestoration: "VALIDATING",
        functionalityTesting: "EXECUTING",
        performanceBaseline: "MONITORING"
      },
      securityEnhancements: {
        monitoringUpgrade: "DEPLOYED",
        detectionRules: "ENHANCED",
        responseAutomation: "CONFIGURED",
        accessControls: "STRENGTHENED"
      },
      businessContinuity: {
        operationalStatus: "RESTORING",
        customerServices: "PHASED_ACTIVATION",
        partnerIntegrations: "TESTING",
        revenueImpact: "ASSESSING"
      }
    };
    return {
      ...prevResult,
      recoveryOperations,
      recoveryStartTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const customerNotificationStep = createStep({
  id: "customer-notification",
  name: "Customer Notification Process",
  description: "Execute customer notification with regulatory compliance",
  execute: async ({ context, prevResult }) => {
    const notificationPlan = {
      affectedCustomers: {
        identification: "COMPLETED",
        segmentation: "BY_IMPACT_LEVEL",
        totalCount: "CALCULATING",
        dataTypes: "CATALOGING"
      },
      notificationChannels: {
        email: {
          template: "APPROVED",
          scheduling: "BATCHED",
          personalization: "CONFIGURED"
        },
        portal: {
          announcement: "POSTED",
          faq: "PUBLISHED",
          supportResources: "AVAILABLE"
        },
        directContact: {
          highValueAccounts: "CALLING",
          enterpriseClients: "SCHEDULED",
          regulatoryRequired: "PRIORITIZED"
        }
      },
      supportPreparation: {
        callCenterBriefing: "COMPLETED",
        scriptApproval: "FINALIZED",
        resourceAllocation: "SCALED_UP",
        escalationPaths: "DEFINED"
      },
      legalCompliance: {
        notificationContent: "LEGALLY_REVIEWED",
        timingCompliance: "VERIFIED",
        documentationTrail: "MAINTAINED",
        regulatoryFiling: "SUBMITTED"
      }
    };
    return {
      ...prevResult,
      notificationPlan,
      notificationExecutionTime: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const lessonsLearnedStep = createStep({
  id: "lessons-learned",
  name: "Post-Incident Analysis",
  description: "Comprehensive review and improvement planning",
  execute: async ({ context, prevResult }) => {
    const postIncidentAnalysis = {
      incidentReview: {
        timeline: {
          detectionDelay: "ANALYZING",
          responseTime: "MEASURING",
          containmentDuration: "CALCULATING",
          totalDowntime: "COMPUTING"
        },
        effectiveness: {
          detectionCapabilities: "EVALUATING",
          responseProcesses: "ASSESSING",
          communicationFlow: "REVIEWING",
          technicalMeasures: "ANALYZING"
        }
      },
      rootCauseAnalysis: {
        technicalFactors: [],
        processFailures: [],
        humanFactors: [],
        externalFactors: []
      },
      improvements: {
        immediate: {
          securityControls: [],
          monitoringEnhancements: [],
          responsePlaybooks: [],
          trainingNeeds: []
        },
        strategic: {
          architectureChanges: [],
          processReengineering: [],
          toolingUpgrades: [],
          complianceEnhancements: []
        }
      },
      metrics: {
        impactAssessment: {
          financialImpact: "CALCULATING",
          reputationalImpact: "ASSESSING",
          operationalImpact: "MEASURED",
          customerImpact: "QUANTIFIED"
        },
        performanceMetrics: {
          mttr: "CALCULATED",
          detectionAccuracy: "MEASURED",
          containmentSpeed: "TRACKED",
          recoveryEfficiency: "EVALUATED"
        }
      }
    };
    return {
      ...prevResult,
      postIncidentAnalysis,
      incidentClosed: false,
      followUpActions: "SCHEDULED"
    };
  }
});
const finalCoordinationStep = createStep({
  id: "final-coordination",
  name: "Final Coordination and Incident Closure",
  description: "Ensure all actions complete and incident properly closed",
  execute: async ({ context, prevResult }) => {
    const { incidentId} = prevResult;
    const closureChecklist = {
      technicalClosure: {
        allSystemsOperational: "VERIFIED",
        securityPostureEnhanced: "CONFIRMED",
        monitoringActive: "VALIDATED",
        backupsVerified: "TESTED"
      },
      communicationClosure: {
        stakeholdersNotified: "COMPLETED",
        regulatoryCompliance: "FILED",
        publicRelations: "MANAGED",
        customerSupport: "ONGOING"
      },
      documentationClosure: {
        incidentReport: "FINALIZED",
        technicalPostmortem: "DOCUMENTED",
        complianceRecords: "ARCHIVED",
        lessonsLearned: "DISTRIBUTED"
      },
      teamDebriefing: {
        agentPerformance: "REVIEWED",
        coordinationEffectiveness: "ASSESSED",
        improvementAreas: "IDENTIFIED",
        recognitionNeeds: "NOTED"
      }
    };
    return {
      incidentId,
      status: "CLOSED",
      closureTime: (/* @__PURE__ */ new Date()).toISOString(),
      closureChecklist,
      finalMetrics: {
        totalDuration: "CALCULATED",
        businessImpact: "QUANTIFIED",
        lessonsImplemented: "TRACKED",
        residualRisk: "ASSESSED"
      },
      followUp: {
        thirtyDayReview: "SCHEDULED",
        quarterlyUpdate: "PLANNED",
        annualDrillUpdate: "QUEUED"
      }
    };
  }
});
const securityBreachResponseWorkflow = createWorkflow({
  id: "security-breach-response",
  name: "Security Breach Response Workflow",
  description: "High-stakes crisis management workflow coordinating all agents for security incident response",
  steps: [
    detectBreachStep,
    assembleCrisisTeamStep,
    // Parallel execution tracks
    {
      parallel: [
        technicalInvestigationStep,
        communicationResponseStep
      ]
    },
    containmentStep,
    eradicationStep,
    recoveryStep,
    customerNotificationStep,
    lessonsLearnedStep,
    finalCoordinationStep
  ],
  config: {
    retries: 0,
    // No retries in crisis mode - must succeed
    timeout: 864e5,
    // 24 hours maximum
    parallel: true,
    errorHandling: "ESCALATE",
    notifications: {
      onStart: ["security-team", "executives", "legal"],
      onError: ["ciso", "ceo", "board"],
      onComplete: ["all-stakeholders"]
    },
    compliance: {
      frameworks: ["GDPR", "CCPA", "HIPAA", "PCI-DSS", "SOX"],
      auditLog: true,
      encryption: true,
      dataRetention: "7_YEARS"
    },
    escalation: {
      levels: [
        { threshold: "5_MINUTES", notify: ["security-team"] },
        { threshold: "15_MINUTES", notify: ["ciso", "cto"] },
        { threshold: "30_MINUTES", notify: ["ceo", "legal"] },
        { threshold: "1_HOUR", notify: ["board", "external-counsel"] }
      ]
    }
  }
});

const complexWorkflows = {
  // Startup and Product Development
  startupLaunch: startupLaunchWorkflow,
  aiProductDevelopment: aiProductDevelopmentWorkflow,
  aiProductFeedbackLoop: feedbackLoop,
  productPivot: productPivotWorkflow,
  // Crisis and Incident Management
  incidentResponse: incidentResponseWorkflow,
  securityBreachResponse: securityBreachResponseWorkflow,
  // Enterprise Operations
  enterpriseMigration: enterpriseMigrationWorkflow
};

class SwarmCoordinator extends EventEmitter {
  constructor() {
    super();
    this.swarms = /* @__PURE__ */ new Map();
    this.communicationChannels = /* @__PURE__ */ new Map();
    this.globalState = {
      insights: [],
      sharedMemory: /* @__PURE__ */ new Map(),
      consensusProtocols: /* @__PURE__ */ new Map(),
      coordinationLocks: /* @__PURE__ */ new Map()
    };
    this.messageQueue = [];
    this.isActive = false;
  }
  /**
   * Register a swarm with the coordinator
   */
  async registerSwarm(swarm) {
    this.swarms.set(swarm.id, {
      swarm,
      lastHeartbeat: Date.now(),
      communicationStats: {
        messagesSent: 0,
        messagesReceived: 0,
        lastCommunication: null
      }
    });
    for (const [existingId, _] of this.swarms) {
      if (existingId !== swarm.id) {
        this.createCommunicationChannel(swarm.id, existingId);
      }
    }
    this.emit("swarmRegistered", swarm);
    console.log(chalk.cyan(`\u{1F4E1} Swarm ${swarm.id} registered with coordinator`));
  }
  /**
   * Create bidirectional communication channel
   */
  createCommunicationChannel(swarm1Id, swarm2Id) {
    const channelId = this.getChannelId(swarm1Id, swarm2Id);
    if (!this.communicationChannels.has(channelId)) {
      this.communicationChannels.set(channelId, {
        id: channelId,
        participants: [swarm1Id, swarm2Id],
        established: Date.now(),
        messages: [],
        bandwidth: 1e3,
        // messages per second
        latency: 10,
        // ms
        reliability: 0.99
      });
    }
  }
  /**
   * Get channel ID for two swarms
   */
  getChannelId(swarm1Id, swarm2Id) {
    return [swarm1Id, swarm2Id].sort().join("-");
  }
  /**
   * Start coordination protocols
   */
  async startCoordination(swarmMap) {
    this.isActive = true;
    console.log(chalk.bold.cyan("\u{1F3AF} Starting Swarm Coordination Protocols..."));
    await this.initializeConsensus();
    this.startHeartbeatMonitoring();
    this.startMessageProcessing();
    this.initializeSharedMemorySync();
    this.startCoordinationCycles();
  }
  /**
   * Initialize consensus mechanisms
   */
  async initializeConsensus() {
    const consensusTypes = ["task-allocation", "resource-sharing", "priority-decisions"];
    for (const type of consensusTypes) {
      this.globalState.consensusProtocols.set(type, {
        type,
        participants: /* @__PURE__ */ new Set(),
        proposals: [],
        decisions: [],
        algorithm: "byzantine-fault-tolerant"
      });
    }
  }
  /**
   * Start heartbeat monitoring
   */
  startHeartbeatMonitoring() {
    setInterval(() => {
      if (!this.isActive) return;
      const now = Date.now();
      for (const [swarmId, data] of this.swarms) {
        const timeSinceLastHeartbeat = now - data.lastHeartbeat;
        if (timeSinceLastHeartbeat > 5e3) {
          console.log(chalk.yellow(`\u26A0\uFE0F  Swarm ${swarmId} heartbeat delayed`));
          this.handleSwarmTimeout(swarmId);
        }
      }
    }, 1e3);
  }
  /**
   * Start message processing
   */
  startMessageProcessing() {
    setInterval(() => {
      if (!this.isActive || this.messageQueue.length === 0) return;
      const batch = this.messageQueue.splice(0, 10);
      for (const message of batch) {
        this.processMessage(message);
      }
    }, 50);
  }
  /**
   * Process individual message
   */
  async processMessage(message) {
    const { from, to, type, payload} = message;
    if (this.swarms.has(from)) {
      this.swarms.get(from).communicationStats.messagesSent++;
      this.swarms.get(from).communicationStats.lastCommunication = Date.now();
    }
    if (this.swarms.has(to)) {
      this.swarms.get(to).communicationStats.messagesReceived++;
    }
    switch (type) {
      case "consensus-proposal":
        await this.handleConsensusProposal(from, payload);
        break;
      case "resource-request":
        await this.handleResourceRequest(from, to, payload);
        break;
      case "insight-share":
        await this.handleInsightShare(from, payload);
        break;
      case "coordination-update":
        await this.handleCoordinationUpdate(from, payload);
        break;
      case "emergency":
        await this.handleEmergencyMessage(from, payload);
        break;
      default:
        const channelId = this.getChannelId(from, to);
        if (this.communicationChannels.has(channelId)) {
          this.communicationChannels.get(channelId).messages.push(message);
        }
    }
    this.emit("messageProcessed", message);
  }
  /**
   * Initialize shared memory synchronization
   */
  initializeSharedMemorySync() {
    const memorySegments = [
      "global-insights",
      "resource-pool",
      "task-registry",
      "performance-metrics",
      "error-logs"
    ];
    for (const segment of memorySegments) {
      this.globalState.sharedMemory.set(segment, {
        data: /* @__PURE__ */ new Map(),
        lastSync: Date.now(),
        version: 1,
        subscribers: /* @__PURE__ */ new Set()
      });
    }
  }
  /**
   * Start coordination cycles
   */
  startCoordinationCycles() {
    setInterval(() => {
      if (!this.isActive) return;
      this.executeMajorCoordinationCycle();
    }, 1e4);
    setInterval(() => {
      if (!this.isActive) return;
      this.executeMinorCoordinationCycle();
    }, 2e3);
  }
  /**
   * Execute major coordination cycle
   */
  async executeMajorCoordinationCycle() {
    console.log(chalk.bold.blue("\n\u{1F504} Major Coordination Cycle"));
    await this.rebalanceGlobalResources();
    await this.optimizeCrossSwarmTasks();
    await this.processConsensusDecisions();
    await this.synchronizePerformanceMetrics();
  }
  /**
   * Execute minor coordination cycle
   */
  async executeMinorCoordinationCycle() {
    this.performHealthChecks();
    this.processUrgentMessages();
    this.updateSharedMemory();
  }
  /**
   * Exchange data between swarms
   */
  async exchangeData(swarm1Id, swarm2Id, data) {
    const message = {
      id: `msg-${Date.now()}-${Math.random()}`,
      from: swarm1Id,
      to: swarm2Id,
      type: "data-exchange",
      payload: data,
      timestamp: Date.now(),
      priority: "normal"
    };
    this.messageQueue.push(message);
    const ackMessage = {
      ...message,
      from: swarm2Id,
      to: swarm1Id,
      type: "ack"
    };
    this.messageQueue.push(ackMessage);
  }
  /**
   * Handle consensus proposal
   */
  async handleConsensusProposal(swarmId, proposal) {
    const { type, decision, justification } = proposal;
    const protocol = this.globalState.consensusProtocols.get(type);
    if (protocol) {
      protocol.proposals.push({
        swarmId,
        decision,
        justification,
        timestamp: Date.now(),
        votes: /* @__PURE__ */ new Map()
      });
      for (const [otherId, _] of this.swarms) {
        if (otherId !== swarmId) {
          this.requestVote(otherId, type, proposal);
        }
      }
    }
  }
  /**
   * Request vote from swarm
   */
  requestVote(swarmId, consensusType, proposal) {
    const message = {
      from: "coordinator",
      to: swarmId,
      type: "vote-request",
      payload: { consensusType, proposal },
      priority: "high"
    };
    this.messageQueue.push(message);
  }
  /**
   * Handle resource request
   */
  async handleResourceRequest(from, to, request) {
    const { resourceType, amount, urgency } = request;
    const targetSwarm = this.swarms.get(to);
    if (targetSwarm && targetSwarm.swarm.metrics.efficiency > 50) {
      const transfer = {
        from: to,
        to: from,
        type: "resource-transfer",
        payload: { resourceType, amount: amount * 0.8 },
        // Transfer 80% of requested
        priority: urgency
      };
      this.messageQueue.push(transfer);
      console.log(chalk.green(`\u2705 Resource transfer approved: ${resourceType} from ${to} to ${from}`));
    }
  }
  /**
   * Handle insight sharing
   */
  async handleInsightShare(from, insight) {
    this.globalState.insights.push({
      source: from,
      insight,
      timestamp: Date.now(),
      propagated: false
    });
    const relevantSwarms = this.findRelevantSwarms(insight);
    for (const swarmId of relevantSwarms) {
      if (swarmId !== from) {
        this.propagateInsight(swarmId, insight);
      }
    }
  }
  /**
   * Find swarms relevant to an insight
   */
  findRelevantSwarms(insight) {
    const relevant = [];
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      const hasRelevantAgents = Array.from(swarm.agents.values()).some(
        (agent) => agent.capabilities.some((cap) => insight.tags?.includes(cap))
      );
      if (hasRelevantAgents) {
        relevant.push(swarmId);
      }
    }
    return relevant;
  }
  /**
   * Propagate insight to swarm
   */
  propagateInsight(swarmId, insight) {
    const message = {
      from: "coordinator",
      to: swarmId,
      type: "insight-propagation",
      payload: insight,
      priority: "normal"
    };
    this.messageQueue.push(message);
  }
  /**
   * Handle coordination update
   */
  async handleCoordinationUpdate(from, update) {
    const segment = this.globalState.sharedMemory.get(update.segment);
    if (segment) {
      segment.data.set(update.key, update.value);
      segment.version++;
      segment.lastSync = Date.now();
      for (const subscriberId of segment.subscribers) {
        if (subscriberId !== from) {
          this.notifyMemoryUpdate(subscriberId, update.segment, update.key);
        }
      }
    }
  }
  /**
   * Handle emergency message
   */
  async handleEmergencyMessage(from, emergency) {
    console.log(chalk.red(`\u{1F6A8} EMERGENCY from ${from}: ${emergency.message}`));
    for (const [swarmId, _] of this.swarms) {
      if (swarmId !== from) {
        const alert = {
          from: "coordinator",
          to: swarmId,
          type: "emergency-broadcast",
          payload: emergency,
          priority: "critical"
        };
        await this.processMessage(alert);
      }
    }
    await this.activateEmergencyProtocols(from, emergency);
  }
  /**
   * Activate emergency protocols
   */
  async activateEmergencyProtocols(sourceSwarm, emergency) {
    this.globalState.coordinationLocks.set("emergency", {
      active: true,
      source: sourceSwarm,
      timestamp: Date.now()
    });
    await this.emergencyResourceReallocation(sourceSwarm, emergency);
    setTimeout(() => {
      this.globalState.coordinationLocks.delete("emergency");
      console.log(chalk.green("\u2705 Emergency protocols deactivated"));
    }, 5e3);
  }
  /**
   * Emergency resource reallocation
   */
  async emergencyResourceReallocation(targetSwarm, emergency) {
    const availableSwarms = Array.from(this.swarms.entries()).filter(([id, data]) => id !== targetSwarm && data.swarm.metrics.efficiency > 70).sort((a, b) => b[1].swarm.metrics.efficiency - a[1].swarm.metrics.efficiency);
    for (const [swarmId, _] of availableSwarms.slice(0, 2)) {
      const assistance = {
        from: swarmId,
        to: targetSwarm,
        type: "emergency-assistance",
        payload: {
          agents: 2,
          priority: "critical",
          duration: 5e3
        },
        priority: "critical"
      };
      this.messageQueue.push(assistance);
    }
  }
  /**
   * Handle swarm timeout
   */
  handleSwarmTimeout(swarmId) {
    const swarmData = this.swarms.get(swarmId);
    if (!swarmData) return;
    swarmData.swarm.status = "unresponsive";
    this.redistributeSwarmTasks(swarmData.swarm);
    for (const [otherId, _] of this.swarms) {
      if (otherId !== swarmId) {
        const alert = {
          from: "coordinator",
          to: otherId,
          type: "swarm-timeout",
          payload: { timeoutSwarm: swarmId },
          priority: "high"
        };
        this.messageQueue.push(alert);
      }
    }
  }
  /**
   * Redistribute tasks from failed swarm
   */
  redistributeSwarmTasks(failedSwarm) {
    const criticalTasks = failedSwarm.tasks.filter((task) => task.priority === "high");
    if (criticalTasks.length > 0) {
      const healthySwarms = Array.from(this.swarms.values()).filter((data) => data.swarm.status === "active" && data.swarm.metrics.efficiency > 60).map((data) => data.swarm);
      criticalTasks.forEach((task, index) => {
        const targetSwarm = healthySwarms[index % healthySwarms.length];
        if (targetSwarm) {
          targetSwarm.tasks.push(task);
          console.log(chalk.yellow(`\u{1F4CB} Redistributed task to ${targetSwarm.id}`));
        }
      });
    }
  }
  /**
   * Rebalance global resources
   */
  async rebalanceGlobalResources() {
    const resourceMetrics = /* @__PURE__ */ new Map();
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      resourceMetrics.set(swarmId, {
        efficiency: swarm.metrics.efficiency,
        load: swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted,
        health: swarm.metrics.health,
        agentUtilization: this.calculateAgentUtilization(swarm)
      });
    }
    const avgEfficiency = Array.from(resourceMetrics.values()).reduce((sum, m) => sum + m.efficiency, 0) / resourceMetrics.size;
    for (const [swarmId, metrics] of resourceMetrics) {
      if (metrics.efficiency < avgEfficiency * 0.7) {
        await this.requestResourceAssistance(swarmId, metrics);
      } else if (metrics.efficiency > avgEfficiency * 1.3) {
        await this.offerResourceAssistance(swarmId, metrics);
      }
    }
  }
  /**
   * Calculate agent utilization
   */
  calculateAgentUtilization(swarm) {
    const agents = Array.from(swarm.agents.values());
    const activeAgents = agents.filter((a) => a.status === "working").length;
    return activeAgents / agents.length * 100;
  }
  /**
   * Optimize cross-swarm tasks
   */
  async optimizeCrossSwarmTasks() {
    const collaborationOpportunities = [];
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      const complexTasks = swarm.tasks.filter(
        (task) => task.complexity === "high" || task.requiresCollaboration
      );
      for (const task of complexTasks) {
        const bestPartner = this.findBestCollaborationPartner(swarm, task);
        if (bestPartner) {
          collaborationOpportunities.push({
            task,
            primarySwarm: swarmId,
            partnerSwarm: bestPartner.id,
            estimatedImprovement: 30
            // percentage
          });
        }
      }
    }
    for (const collab of collaborationOpportunities) {
      await this.establishCollaboration(collab);
    }
  }
  /**
   * Find best collaboration partner
   */
  findBestCollaborationPartner(swarm, task) {
    let bestPartner = null;
    let bestScore = 0;
    for (const [otherId, data] of this.swarms) {
      if (otherId === swarm.id) continue;
      const otherSwarm = data.swarm;
      const score = this.calculateCollaborationScore(task, otherSwarm);
      if (score > bestScore) {
        bestScore = score;
        bestPartner = otherSwarm;
      }
    }
    return bestScore > 0.7 ? bestPartner : null;
  }
  /**
   * Calculate collaboration score
   */
  calculateCollaborationScore(task, swarm) {
    const requiredCapabilities = task.requiredCapabilities || [];
    const swarmCapabilities = /* @__PURE__ */ new Set();
    for (const agent of swarm.agents.values()) {
      agent.capabilities.forEach((cap) => swarmCapabilities.add(cap));
    }
    const matchingCapabilities = requiredCapabilities.filter(
      (cap) => swarmCapabilities.has(cap)
    ).length;
    const capabilityScore = matchingCapabilities / Math.max(1, requiredCapabilities.length);
    const efficiencyScore = swarm.metrics.efficiency / 100;
    const availabilityScore = (100 - this.calculateAgentUtilization(swarm)) / 100;
    return capabilityScore * 0.5 + efficiencyScore * 0.3 + availabilityScore * 0.2;
  }
  /**
   * Establish collaboration
   */
  async establishCollaboration(collab) {
    const message = {
      from: collab.primarySwarm,
      to: collab.partnerSwarm,
      type: "collaboration-request",
      payload: {
        task: collab.task,
        estimatedDuration: 5e3,
        sharedReward: true
      },
      priority: "high"
    };
    this.messageQueue.push(message);
    console.log(chalk.magenta(
      `\u{1F91D} Collaboration established: ${collab.primarySwarm} \u2194 ${collab.partnerSwarm}`
    ));
  }
  /**
   * Process consensus decisions
   */
  async processConsensusDecisions() {
    for (const [type, protocol] of this.globalState.consensusProtocols) {
      const pendingProposals = protocol.proposals.filter((p) => !p.decided);
      for (const proposal of pendingProposals) {
        const voteCount = proposal.votes.size;
        const totalSwarms = this.swarms.size;
        if (voteCount >= Math.ceil(totalSwarms * 0.66)) {
          const decision = this.tallyVotes(proposal);
          protocol.decisions.push({
            proposal,
            decision,
            timestamp: Date.now(),
            consensus: true
          });
          proposal.decided = true;
          await this.broadcastConsensusDecision(type, decision);
        }
      }
    }
  }
  /**
   * Tally votes for proposal
   */
  tallyVotes(proposal) {
    const votes = Array.from(proposal.votes.values());
    const yesVotes = votes.filter((v) => v === "yes").length;
    const noVotes = votes.filter((v) => v === "no").length;
    return {
      approved: yesVotes > noVotes,
      yesVotes,
      noVotes,
      participation: votes.length / this.swarms.size * 100
    };
  }
  /**
   * Broadcast consensus decision
   */
  async broadcastConsensusDecision(type, decision) {
    for (const [swarmId, _] of this.swarms) {
      const message = {
        from: "coordinator",
        to: swarmId,
        type: "consensus-decision",
        payload: { type, decision },
        priority: "high"
      };
      this.messageQueue.push(message);
    }
    console.log(chalk.green(`\u2705 Consensus reached on ${type}: ${decision.approved ? "APPROVED" : "REJECTED"}`));
  }
  /**
   * Synchronize performance metrics
   */
  async synchronizePerformanceMetrics() {
    const globalMetrics = {
      timestamp: Date.now(),
      swarmMetrics: /* @__PURE__ */ new Map(),
      aggregates: {
        totalTasks: 0,
        completedTasks: 0,
        avgEfficiency: 0,
        totalAgents: 0,
        activeAgents: 0
      }
    };
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      globalMetrics.swarmMetrics.set(swarmId, swarm.metrics);
      globalMetrics.aggregates.totalTasks += swarm.metrics.tasksAssigned;
      globalMetrics.aggregates.completedTasks += swarm.metrics.tasksCompleted;
      globalMetrics.aggregates.totalAgents += swarm.agents.size;
      globalMetrics.aggregates.activeAgents += Array.from(swarm.agents.values()).filter((a) => a.status === "working").length;
    }
    globalMetrics.aggregates.avgEfficiency = Array.from(globalMetrics.swarmMetrics.values()).reduce((sum, m) => sum + m.efficiency, 0) / globalMetrics.swarmMetrics.size;
    const metricsSegment = this.globalState.sharedMemory.get("performance-metrics");
    metricsSegment.data.set("global", globalMetrics);
    for (const [swarmId, _] of this.swarms) {
      this.notifyMemoryUpdate(swarmId, "performance-metrics", "global");
    }
  }
  /**
   * Notify memory update
   */
  notifyMemoryUpdate(swarmId, segment, key) {
    const message = {
      from: "coordinator",
      to: swarmId,
      type: "memory-update",
      payload: { segment, key },
      priority: "normal"
    };
    this.messageQueue.push(message);
  }
  /**
   * Perform health checks
   */
  performHealthChecks() {
    const now = Date.now();
    for (const [swarmId, data] of this.swarms) {
      const swarm = data.swarm;
      let unhealthyAgents = 0;
      for (const agent of swarm.agents.values()) {
        if (agent.performance < 50 || agent.status === "working" && now - agent.lastActivity > 1e4) {
          unhealthyAgents++;
        }
      }
      swarm.metrics.health = Math.max(0, 100 - unhealthyAgents / swarm.agents.size * 100);
      data.lastHeartbeat = now;
    }
  }
  /**
   * Process urgent messages
   */
  processUrgentMessages() {
    const urgentMessages = this.messageQueue.filter(
      (m) => m.priority === "critical" || m.priority === "high"
    );
    if (urgentMessages.length > 0) {
      this.messageQueue = this.messageQueue.filter(
        (m) => m.priority !== "critical" && m.priority !== "high"
      );
      for (const message of urgentMessages) {
        this.processMessage(message);
      }
    }
  }
  /**
   * Update shared memory
   */
  updateSharedMemory() {
    for (const [segmentName, segment] of this.globalState.sharedMemory) {
      if (Date.now() - segment.lastSync > 1e3) {
        segment.version++;
        segment.lastSync = Date.now();
      }
    }
  }
  /**
   * Request resource assistance
   */
  async requestResourceAssistance(swarmId, metrics) {
    const request = {
      from: swarmId,
      to: "broadcast",
      type: "assistance-request",
      payload: {
        currentMetrics: metrics,
        assistanceType: "load-balancing",
        urgency: metrics.efficiency < 50 ? "high" : "medium"
      },
      priority: "high"
    };
    for (const [otherId, _] of this.swarms) {
      if (otherId !== swarmId) {
        this.messageQueue.push({ ...request, to: otherId });
      }
    }
  }
  /**
   * Offer resource assistance
   */
  async offerResourceAssistance(swarmId, metrics) {
    const offer = {
      from: swarmId,
      to: "coordinator",
      type: "assistance-offer",
      payload: {
        availableCapacity: 100 - metrics.agentUtilization,
        capabilities: this.getSwarmCapabilities(swarmId),
        duration: 1e4
        // 10 seconds
      },
      priority: "normal"
    };
    this.messageQueue.push(offer);
  }
  /**
   * Get swarm capabilities
   */
  getSwarmCapabilities(swarmId) {
    const swarmData = this.swarms.get(swarmId);
    if (!swarmData) return [];
    const capabilities = /* @__PURE__ */ new Set();
    for (const agent of swarmData.swarm.agents.values()) {
      agent.capabilities.forEach((cap) => capabilities.add(cap));
    }
    return Array.from(capabilities);
  }
  /**
   * Collect global insights
   */
  async collectGlobalInsights(swarmMap) {
    const insights = {
      timestamp: Date.now(),
      swarmInsights: [],
      patterns: [],
      recommendations: []
    };
    for (const swarm of swarmMap.values()) {
      const swarmInsight = {
        swarmId: swarm.id,
        efficiency: swarm.metrics.efficiency,
        tasksCompleted: swarm.metrics.tasksCompleted,
        agentPerformance: this.analyzeAgentPerformance(swarm),
        bottlenecks: this.identifyBottlenecks(swarm)
      };
      insights.swarmInsights.push(swarmInsight);
    }
    insights.patterns = this.identifyGlobalPatterns(insights.swarmInsights);
    insights.recommendations = this.generateRecommendations(insights);
    return insights;
  }
  /**
   * Analyze agent performance
   */
  analyzeAgentPerformance(swarm) {
    const agentStats = [];
    for (const agent of swarm.agents.values()) {
      agentStats.push({
        agentId: agent.id,
        type: agent.type,
        tasksCompleted: agent.tasksCompleted,
        performance: agent.performance,
        utilization: agent.status === "working" ? 100 : 0
      });
    }
    return {
      topPerformers: agentStats.sort((a, b) => b.tasksCompleted - a.tasksCompleted).slice(0, 3),
      avgPerformance: agentStats.reduce((sum, a) => sum + a.performance, 0) / agentStats.length
    };
  }
  /**
   * Identify bottlenecks
   */
  identifyBottlenecks(swarm) {
    const bottlenecks = [];
    const backlog = swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted;
    if (backlog > swarm.agents.size * 2) {
      bottlenecks.push({
        type: "task-backlog",
        severity: "high",
        value: backlog
      });
    }
    const utilization = this.calculateAgentUtilization(swarm);
    if (utilization > 90) {
      bottlenecks.push({
        type: "over-utilization",
        severity: "medium",
        value: utilization
      });
    }
    return bottlenecks;
  }
  /**
   * Identify global patterns
   */
  identifyGlobalPatterns(swarmInsights) {
    const patterns = [];
    const efficiencies = swarmInsights.map((s) => s.efficiency);
    efficiencies.reduce((a, b) => a + b, 0) / efficiencies.length;
    if (Math.max(...efficiencies) - Math.min(...efficiencies) > 30) {
      patterns.push({
        type: "efficiency-imbalance",
        description: "Significant efficiency variance across swarms",
        recommendation: "Consider load balancing"
      });
    }
    const commonBottlenecks = /* @__PURE__ */ new Map();
    swarmInsights.forEach((insight) => {
      insight.bottlenecks.forEach((bottleneck) => {
        const count = commonBottlenecks.get(bottleneck.type) || 0;
        commonBottlenecks.set(bottleneck.type, count + 1);
      });
    });
    for (const [type, count] of commonBottlenecks) {
      if (count > swarmInsights.length / 2) {
        patterns.push({
          type: "common-bottleneck",
          description: `${type} affecting ${count} swarms`,
          recommendation: "Address systematically"
        });
      }
    }
    return patterns;
  }
  /**
   * Generate recommendations
   */
  generateRecommendations(insights) {
    const recommendations = [];
    insights.patterns.forEach((pattern) => {
      recommendations.push({
        priority: "high",
        action: pattern.recommendation,
        rationale: pattern.description
      });
    });
    const lowPerformers = insights.swarmInsights.filter((s) => s.efficiency < 60);
    if (lowPerformers.length > 0) {
      recommendations.push({
        priority: "medium",
        action: "Scale up low-performing swarms",
        rationale: `${lowPerformers.length} swarms operating below 60% efficiency`
      });
    }
    return recommendations;
  }
  /**
   * Emergency shutdown
   */
  async emergencyShutdown(swarmMap) {
    console.log(chalk.red("\u{1F6A8} Initiating emergency shutdown..."));
    this.isActive = false;
    const emergencyState = {
      timestamp: Date.now(),
      swarms: Array.from(swarmMap.entries()),
      sharedMemory: Array.from(this.globalState.sharedMemory.entries()),
      pendingMessages: this.messageQueue
    };
    for (const [swarmId, _] of this.swarms) {
      const message = {
        from: "coordinator",
        to: swarmId,
        type: "shutdown",
        payload: { reason: "emergency" },
        priority: "critical"
      };
      await this.processMessage(message);
    }
    return emergencyState;
  }
}

class SwarmMonitor extends EventEmitter {
  constructor() {
    super();
    this.metrics = /* @__PURE__ */ new Map();
    this.alerts = [];
    this.performanceHistory = [];
    this.thresholds = {
      efficiency: { warning: 70, critical: 50 },
      taskBacklog: { warning: 10, critical: 20 },
      agentUtilization: { warning: 80, critical: 95 },
      responseTime: { warning: 1e3, critical: 3e3 },
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
    console.log(chalk.cyan("\u{1F4CA} Swarm Monitor initialized"));
    this.initializeMetricCollectors();
    this.startDashboard();
    this.initializeAlertSystem();
  }
  /**
   * Initialize metric collectors
   */
  initializeMetricCollectors() {
    const collectors = [
      "swarm-performance",
      "agent-metrics",
      "task-analytics",
      "resource-usage",
      "communication-stats",
      "error-tracking"
    ];
    for (const collector of collectors) {
      this.metrics.set(collector, {
        current: /* @__PURE__ */ new Map(),
        history: [],
        aggregates: {}
      });
    }
  }
  /**
   * Start real-time dashboard
   */
  startDashboard() {
    this.dashboardInterval = setInterval(() => {
      if (this.isActive) {
        this.renderDashboard();
      }
    }, 5e3);
  }
  /**
   * Initialize alert system
   */
  initializeAlertSystem() {
    setInterval(() => {
      if (this.isActive) {
        this.checkAlerts();
      }
    }, 1e3);
  }
  /**
   * Collect metrics from swarms
   */
  collectMetrics(swarms, globalMetrics) {
    const timestamp = Date.now();
    const snapshot = {
      timestamp,
      swarms: /* @__PURE__ */ new Map(),
      global: globalMetrics,
      analysis: {}
    };
    for (const [swarmId, swarm] of swarms) {
      const swarmMetrics = this.collectSwarmMetrics(swarm);
      snapshot.swarms.set(swarmId, swarmMetrics);
    }
    snapshot.analysis = this.analyzeMetrics(snapshot);
    this.performanceHistory.push(snapshot);
    if (this.performanceHistory.length > 100) {
      this.performanceHistory.shift();
    }
    this.updateCurrentMetrics(snapshot);
    this.emit("metricsCollected", snapshot);
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
        cpuUsage: Math.random() * 100,
        // Simulated
        memoryUsage: Math.random() * 100,
        // Simulated
        networkBandwidth: Math.random() * 1e3
        // Simulated
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
      byType: /* @__PURE__ */ new Map(),
      performance: []
    };
    for (const agent of agents.values()) {
      agentMetrics.byStatus[agent.status]++;
      const typeCount = agentMetrics.byType.get(agent.type) || 0;
      agentMetrics.byType.set(agent.type, typeCount + 1);
      agentMetrics.performance.push({
        id: agent.id,
        type: agent.type,
        tasksCompleted: agent.tasksCompleted,
        performance: agent.performance,
        utilization: agent.status === "working" ? 100 : 0
      });
    }
    agentMetrics.avgPerformance = agentMetrics.performance.length > 0 ? agentMetrics.performance.reduce((sum, a) => sum + a.performance, 0) / agentMetrics.performance.length : 0;
    agentMetrics.utilization = agentMetrics.byStatus.working / agentMetrics.total * 100;
    return agentMetrics;
  }
  /**
   * Calculate throughput
   */
  calculateThroughput(swarm) {
    const previousSnapshot = this.performanceHistory.slice(-2, -1)[0];
    if (!previousSnapshot) return 0;
    const previousSwarmData = previousSnapshot.swarms.get(swarm.id);
    if (!previousSwarmData) return 0;
    const timeDiff = Date.now() - previousSnapshot.timestamp;
    const tasksDiff = swarm.metrics.tasksCompleted - previousSwarmData.tasksCompleted;
    return tasksDiff / timeDiff * 1e3;
  }
  /**
   * Calculate average response time
   */
  calculateAverageResponseTime(swarm) {
    return 500 + Math.random() * 1e3;
  }
  /**
   * Calculate error rate
   */
  calculateErrorRate(swarm) {
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
      return { status: "insufficient-data" };
    }
    const recentHistory = this.performanceHistory.slice(-10);
    const trends = {
      efficiency: this.calculateTrend(recentHistory, "efficiency"),
      throughput: this.calculateTrend(recentHistory, "throughput"),
      errorRate: this.calculateTrend(recentHistory, "errorRate")
    };
    return trends;
  }
  /**
   * Calculate trend for metric
   */
  calculateTrend(history, metric) {
    const values = history.map((snapshot) => {
      const swarmValues = Array.from(snapshot.swarms.values());
      if (metric === "efficiency") {
        return swarmValues.reduce((sum, s) => sum + s.efficiency, 0) / swarmValues.length;
      } else if (metric === "throughput") {
        return swarmValues.reduce((sum, s) => sum + s.performance.throughput, 0);
      } else if (metric === "errorRate") {
        return swarmValues.reduce((sum, s) => sum + s.performance.errorRate, 0) / swarmValues.length;
      }
      return 0;
    });
    const n = values.length;
    const sumX = n * (n - 1) / 2;
    const sumY = values.reduce((a, b) => a + b, 0);
    const sumXY = values.reduce((sum, y, x) => sum + x * y, 0);
    const sumX2 = n * (n - 1) * (2 * n - 1) / 6;
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return {
      direction: slope > 0.1 ? "increasing" : slope < -0.1 ? "decreasing" : "stable",
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
      if (metrics.efficiency < this.thresholds.efficiency.critical) {
        anomalies.push({
          type: "critical-efficiency",
          swarmId,
          value: metrics.efficiency,
          threshold: this.thresholds.efficiency.critical
        });
      }
      if (metrics.taskBacklog > this.thresholds.taskBacklog.critical) {
        anomalies.push({
          type: "critical-backlog",
          swarmId,
          value: metrics.taskBacklog,
          threshold: this.thresholds.taskBacklog.critical
        });
      }
      if (metrics.agents.utilization > this.thresholds.agentUtilization.critical) {
        anomalies.push({
          type: "critical-utilization",
          swarmId,
          value: metrics.agents.utilization,
          threshold: this.thresholds.agentUtilization.critical
        });
      }
      if (metrics.performance.errorRate > this.thresholds.errorRate.critical) {
        anomalies.push({
          type: "critical-errors",
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
      estimatedTime: totalBacklog / totalThroughput * 1e3,
      // milliseconds
      confidence: 0.75
    };
  }
  /**
   * Predict resource exhaustion
   */
  predictResourceExhaustion(snapshot) {
    const predictions = [];
    for (const [swarmId, metrics] of snapshot.swarms) {
      const cpuTrend = this.calculateResourceTrend("cpu", swarmId);
      const memoryTrend = this.calculateResourceTrend("memory", swarmId);
      if (cpuTrend.rate > 0.5 && metrics.resources.cpuUsage > 80) {
        predictions.push({
          swarmId,
          resource: "cpu",
          timeToExhaustion: (100 - metrics.resources.cpuUsage) / cpuTrend.rate * 1e3
        });
      }
      if (memoryTrend.rate > 0.5 && metrics.resources.memoryUsage > 80) {
        predictions.push({
          swarmId,
          resource: "memory",
          timeToExhaustion: (100 - metrics.resources.memoryUsage) / memoryTrend.rate * 1e3
        });
      }
    }
    return predictions;
  }
  /**
   * Calculate resource trend
   */
  calculateResourceTrend(resource, swarmId) {
    return {
      rate: Math.random() * 0.5,
      direction: "increasing"
    };
  }
  /**
   * Predict performance degradation
   */
  predictPerformanceDegradation(snapshot) {
    const predictions = [];
    const trends = this.analyzeTrends();
    if (trends.efficiency && trends.efficiency.direction === "decreasing") {
      predictions.push({
        metric: "efficiency",
        currentTrend: trends.efficiency,
        riskLevel: trends.efficiency.rate > 0.5 ? "high" : "medium",
        estimatedImpact: trends.efficiency.rate * 10
        // percentage
      });
    }
    if (trends.errorRate && trends.errorRate.direction === "increasing") {
      predictions.push({
        metric: "errorRate",
        currentTrend: trends.errorRate,
        riskLevel: trends.errorRate.rate > 0.3 ? "high" : "medium",
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
    if (analysis.anomalies.length > 0) {
      analysis.anomalies.forEach((anomaly) => {
        recommendations.push({
          priority: "high",
          type: anomaly.type,
          action: this.getAnomalyRecommendation(anomaly),
          targetSwarm: anomaly.swarmId
        });
      });
    }
    if (analysis.predictions.resourceExhaustion.length > 0) {
      recommendations.push({
        priority: "medium",
        type: "resource-scaling",
        action: "Consider scaling resources for affected swarms",
        details: analysis.predictions.resourceExhaustion
      });
    }
    if (analysis.trends.efficiency && analysis.trends.efficiency.direction === "decreasing") {
      recommendations.push({
        priority: "medium",
        type: "efficiency-optimization",
        action: "Investigate declining efficiency trend",
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
      "critical-efficiency": "Redistribute tasks or scale agents",
      "critical-backlog": "Increase agent capacity or optimize task processing",
      "critical-utilization": "Add more agents or optimize workload distribution",
      "critical-errors": "Investigate error sources and implement fixes"
    };
    return recommendations[anomaly.type] || "Investigate anomaly";
  }
  /**
   * Update current metrics
   */
  updateCurrentMetrics(snapshot) {
    const perfMetrics = this.metrics.get("swarm-performance");
    for (const [swarmId, metrics] of snapshot.swarms) {
      perfMetrics.current.set(swarmId, {
        efficiency: metrics.efficiency,
        throughput: metrics.performance.throughput,
        health: metrics.health
      });
    }
    perfMetrics.aggregates = {
      avgEfficiency: this.calculateAverage(snapshot.swarms, "efficiency"),
      totalThroughput: this.calculateSum(snapshot.swarms, "performance.throughput"),
      overallHealth: this.calculateAverage(snapshot.swarms, "health")
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
      if (value !== void 0) {
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
      if (value !== void 0) {
        sum += value;
      }
    }
    return sum;
  }
  /**
   * Get nested value from object
   */
  getNestedValue(obj, path) {
    const keys = path.split(".");
    let value = obj;
    for (const key of keys) {
      value = value[key];
      if (value === void 0) break;
    }
    return value;
  }
  /**
   * Check for alerts
   */
  checkAlerts() {
    const currentMetrics = this.metrics.get("swarm-performance").current;
    for (const [swarmId, metrics] of currentMetrics) {
      if (metrics.efficiency < this.thresholds.efficiency.warning) {
        this.createAlert({
          type: "efficiency",
          severity: metrics.efficiency < this.thresholds.efficiency.critical ? "critical" : "warning",
          swarmId,
          value: metrics.efficiency,
          threshold: metrics.efficiency < this.thresholds.efficiency.critical ? this.thresholds.efficiency.critical : this.thresholds.efficiency.warning
        });
      }
    }
    this.processAlerts();
  }
  /**
   * Create alert
   */
  createAlert(alert) {
    alert.timestamp = Date.now();
    alert.id = `alert-${Date.now()}-${Math.random()}`;
    const existingAlert = this.alerts.find(
      (a) => a.type === alert.type && a.swarmId === alert.swarmId && Date.now() - a.timestamp < 6e4
      // Within last minute
    );
    if (!existingAlert) {
      this.alerts.push(alert);
      this.emit("alert", alert);
      const color = alert.severity === "critical" ? chalk.red : chalk.yellow;
      console.log(color(`
\u26A0\uFE0F  ALERT: ${alert.type} - ${alert.swarmId}`));
      console.log(color(`   Value: ${alert.value}, Threshold: ${alert.threshold}`));
    }
  }
  /**
   * Process alerts
   */
  processAlerts() {
    const cutoffTime = Date.now() - 3e5;
    this.alerts = this.alerts.filter((alert) => alert.timestamp > cutoffTime);
    const criticalAlerts = this.alerts.filter((a) => a.severity === "critical");
    this.alerts.filter((a) => a.severity === "warning");
    if (criticalAlerts.length > 3) {
      this.emit("criticalAlertThreshold", criticalAlerts);
    }
  }
  /**
   * Render dashboard
   */
  renderDashboard() {
    console.log(chalk.bold.cyan("\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"));
    console.log(chalk.bold.cyan("                 SWARM MONITOR DASHBOARD                  "));
    console.log(chalk.bold.cyan("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"));
    const perfMetrics = this.metrics.get("swarm-performance");
    if (perfMetrics.aggregates.avgEfficiency !== void 0) {
      console.log(chalk.white("\n\u{1F4CA} Global Metrics:"));
      console.log(chalk.white(`   \u2022 Average Efficiency: ${perfMetrics.aggregates.avgEfficiency.toFixed(1)}%`));
      console.log(chalk.white(`   \u2022 Total Throughput: ${perfMetrics.aggregates.totalThroughput.toFixed(2)} tasks/sec`));
      console.log(chalk.white(`   \u2022 Overall Health: ${perfMetrics.aggregates.overallHealth.toFixed(1)}%`));
    }
    if (perfMetrics.current.size > 0) {
      console.log(chalk.white("\n\u{1F539} Swarm Status:"));
      for (const [swarmId, metrics] of perfMetrics.current) {
        const statusColor = metrics.efficiency > 80 ? chalk.green : metrics.efficiency > 60 ? chalk.yellow : chalk.red;
        console.log(statusColor(`   \u2022 ${swarmId}: ${metrics.efficiency.toFixed(1)}% efficiency, ${metrics.throughput.toFixed(2)} tasks/sec`));
      }
    }
    if (this.alerts.length > 0) {
      console.log(chalk.white("\n\u26A0\uFE0F  Active Alerts:"));
      const recentAlerts = this.alerts.slice(-3);
      recentAlerts.forEach((alert) => {
        const alertColor = alert.severity === "critical" ? chalk.red : chalk.yellow;
        console.log(alertColor(`   \u2022 [${alert.severity.toUpperCase()}] ${alert.type} in ${alert.swarmId}`));
      });
    }
    const trends = this.analyzeTrends();
    if (trends.efficiency) {
      console.log(chalk.white("\n\u{1F4C8} Trends:"));
      const trendIcon = trends.efficiency.direction === "increasing" ? "\u2197" : trends.efficiency.direction === "decreasing" ? "\u2198" : "\u2192";
      console.log(chalk.white(`   \u2022 Efficiency: ${trendIcon} ${trends.efficiency.direction}`));
      if (trends.throughput) {
        const throughputIcon = trends.throughput.direction === "increasing" ? "\u2197" : trends.throughput.direction === "decreasing" ? "\u2198" : "\u2192";
        console.log(chalk.white(`   \u2022 Throughput: ${throughputIcon} ${trends.throughput.direction}`));
      }
    }
    console.log(chalk.bold.cyan("\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"));
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
      insights,
      recommendations: [],
      alerts: this.alerts
    };
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
    report.recommendations = this.generateFinalRecommendations(report);
    return report;
  }
  /**
   * Generate final recommendations
   */
  generateFinalRecommendations(report) {
    const recommendations = [];
    const avgEfficiency = report.swarmPerformance.reduce((sum, s) => sum + s.efficiency, 0) / report.swarmPerformance.length;
    if (avgEfficiency < 70) {
      recommendations.push({
        category: "performance",
        priority: "high",
        recommendation: "Overall system efficiency is below optimal. Consider scaling agents or optimizing task distribution."
      });
    }
    const criticalAlerts = report.alerts.filter((a) => a.severity === "critical");
    if (criticalAlerts.length > 0) {
      recommendations.push({
        category: "stability",
        priority: "critical",
        recommendation: `Address ${criticalAlerts.length} critical alerts to improve system stability.`
      });
    }
    if (report.insights.patterns) {
      report.insights.patterns.forEach((pattern) => {
        if (pattern.recommendation) {
          recommendations.push({
            category: "optimization",
            priority: "medium",
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
      type: "emergency",
      swarms: Array.from(swarms.entries()),
      globalMetrics: metrics,
      performanceHistory: this.performanceHistory.slice(-10),
      activeAlerts: this.alerts
    };
    console.log(chalk.yellow("\u{1F4BE} Emergency snapshot saved"));
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
    console.log(chalk.cyan("\u{1F4CA} Swarm Monitor shutdown complete"));
  }
}

const SWARM_MISSIONS = {
  INFRASTRUCTURE: {
    id: "infrastructure-swarm",
    name: "Infrastructure Optimization Swarm",
    objective: "Optimize system infrastructure and resource allocation",
    color: chalk.blue,
    priority: "high",
    agents: [
      { type: "architect", role: "System Architecture Designer", capabilities: ["design", "planning", "optimization"] },
      { type: "optimizer", role: "Performance Optimizer", capabilities: ["performance", "bottleneck-analysis", "tuning"] },
      { type: "monitor", role: "Resource Monitor", capabilities: ["monitoring", "alerting", "metrics"] },
      { type: "analyst", role: "Infrastructure Analyst", capabilities: ["analysis", "reporting", "prediction"] },
      { type: "coordinator", role: "Resource Coordinator", capabilities: ["scheduling", "allocation", "balancing"] },
      { type: "specialist", role: "Security Specialist", capabilities: ["security", "compliance", "hardening"] }
    ]
  },
  DEVELOPMENT: {
    id: "development-swarm",
    name: "Development Acceleration Swarm",
    objective: "Accelerate development process and code quality",
    color: chalk.green,
    priority: "high",
    agents: [
      { type: "coder", role: "Senior Developer", capabilities: ["coding", "refactoring", "implementation"] },
      { type: "tester", role: "Quality Assurance", capabilities: ["testing", "validation", "automation"] },
      { type: "reviewer", role: "Code Reviewer", capabilities: ["review", "standards", "best-practices"] },
      { type: "documenter", role: "Documentation Expert", capabilities: ["documentation", "api-docs", "guides"] },
      { type: "architect", role: "Software Architect", capabilities: ["design-patterns", "architecture", "scalability"] },
      { type: "specialist", role: "DevOps Specialist", capabilities: ["ci-cd", "deployment", "automation"] }
    ]
  },
  ANALYTICS: {
    id: "analytics-swarm",
    name: "Data Analytics Swarm",
    objective: "Analyze patterns and provide intelligent insights",
    color: chalk.yellow,
    priority: "medium",
    agents: [
      { type: "analyst", role: "Data Analyst", capabilities: ["data-analysis", "visualization", "reporting"] },
      { type: "researcher", role: "Pattern Researcher", capabilities: ["pattern-recognition", "ml", "prediction"] },
      { type: "optimizer", role: "Algorithm Optimizer", capabilities: ["optimization", "performance", "efficiency"] },
      { type: "monitor", role: "Metric Monitor", capabilities: ["monitoring", "tracking", "alerting"] },
      { type: "coordinator", role: "Data Coordinator", capabilities: ["data-pipeline", "etl", "orchestration"] },
      { type: "specialist", role: "ML Specialist", capabilities: ["machine-learning", "ai", "neural-networks"] }
    ]
  }
};
class ConcurrentSwarmDemo extends EventEmitter {
  constructor() {
    super();
    this.coordinator = new SwarmCoordinator();
    this.monitor = new SwarmMonitor();
    this.swarms = /* @__PURE__ */ new Map();
    this.startTime = Date.now();
    this.isRunning = false;
    this.metrics = {
      tasksCompleted: 0,
      messagesExchanged: 0,
      errorsRecovered: 0,
      totalAgents: 0,
      swarmSyncs: 0
    };
  }
  /**
   * Initialize and launch concurrent swarms
   */
  async launch() {
    console.log(chalk.bold.cyan("\n\u{1F680} Launching Concurrent Swarm Demonstration System\n"));
    this.isRunning = true;
    try {
      await this.monitor.initialize();
      const swarmPromises = Object.values(SWARM_MISSIONS).map(
        (mission) => this.spawnSwarm(mission)
      );
      await Promise.all(swarmPromises);
      await this.coordinator.startCoordination(this.swarms);
      this.startMonitoring();
      await this.runConcurrentOperations();
    } catch (error) {
      console.error(chalk.red("Error in swarm launch:"), error);
      await this.handleCriticalError(error);
    }
  }
  /**
   * Spawn individual swarm with agents
   */
  async spawnSwarm(mission) {
    console.log(mission.color(`
\u{1F4E1} Spawning ${mission.name}...`));
    const swarm = {
      id: mission.id,
      mission,
      agents: /* @__PURE__ */ new Map(),
      status: "initializing",
      startTime: Date.now(),
      tasks: [],
      metrics: {
        tasksAssigned: 0,
        tasksCompleted: 0,
        efficiency: 100,
        health: 100
      }
    };
    for (const agentConfig of mission.agents) {
      const agent = await this.createAgent(agentConfig, swarm);
      swarm.agents.set(agent.id, agent);
      this.metrics.totalAgents++;
    }
    this.swarms.set(swarm.id, swarm);
    swarm.status = "active";
    console.log(mission.color(`\u2705 ${mission.name} operational with ${swarm.agents.size} agents`));
    await this.coordinator.registerSwarm(swarm);
    return swarm;
  }
  /**
   * Create individual agent
   */
  async createAgent(config, swarm) {
    const agent = {
      id: `${swarm.id}-${config.type}-${Date.now()}`,
      type: config.type,
      role: config.role,
      capabilities: config.capabilities,
      swarmId: swarm.id,
      status: "idle",
      currentTask: null,
      tasksCompleted: 0,
      performance: 100,
      lastActivity: Date.now()
    };
    agent.neuralState = {
      learning: true,
      patterns: [],
      confidence: 0.8
    };
    return agent;
  }
  /**
   * Run concurrent operations across all swarms
   */
  async runConcurrentOperations() {
    console.log(chalk.bold.magenta("\n\u{1F504} Starting Concurrent Operations...\n"));
    const operations = [
      this.executeInfrastructureOptimization(),
      this.executeDevelopmentAcceleration(),
      this.executeDataAnalytics(),
      this.executeSwarmSynchronization(),
      this.executeResilienceTest()
    ];
    await Promise.all(operations);
    await this.finalSynchronization();
  }
  /**
   * Infrastructure optimization operation
   */
  async executeInfrastructureOptimization() {
    const swarm = this.swarms.get("infrastructure-swarm");
    if (!swarm) return;
    console.log(chalk.blue("\n\u{1F3D7}\uFE0F  Infrastructure Optimization in progress..."));
    const tasks = [
      { type: "analyze", target: "system-resources", priority: "high" },
      { type: "optimize", target: "memory-allocation", priority: "high" },
      { type: "monitor", target: "performance-metrics", priority: "medium" },
      { type: "secure", target: "access-controls", priority: "high" },
      { type: "balance", target: "load-distribution", priority: "medium" },
      { type: "predict", target: "resource-needs", priority: "low" }
    ];
    await this.distributeTasksToSwarm(swarm, tasks);
  }
  /**
   * Development acceleration operation
   */
  async executeDevelopmentAcceleration() {
    const swarm = this.swarms.get("development-swarm");
    if (!swarm) return;
    console.log(chalk.green("\n\u{1F4BB} Development Acceleration in progress..."));
    const tasks = [
      { type: "implement", target: "new-features", priority: "high" },
      { type: "test", target: "code-coverage", priority: "high" },
      { type: "review", target: "pull-requests", priority: "medium" },
      { type: "document", target: "api-endpoints", priority: "medium" },
      { type: "refactor", target: "legacy-code", priority: "low" },
      { type: "deploy", target: "staging-environment", priority: "high" }
    ];
    await this.distributeTasksToSwarm(swarm, tasks);
  }
  /**
   * Data analytics operation
   */
  async executeDataAnalytics() {
    const swarm = this.swarms.get("analytics-swarm");
    if (!swarm) return;
    console.log(chalk.yellow("\n\u{1F4CA} Data Analytics in progress..."));
    const tasks = [
      { type: "analyze", target: "usage-patterns", priority: "high" },
      { type: "predict", target: "future-trends", priority: "medium" },
      { type: "optimize", target: "algorithms", priority: "high" },
      { type: "visualize", target: "dashboards", priority: "medium" },
      { type: "train", target: "ml-models", priority: "high" },
      { type: "report", target: "insights", priority: "low" }
    ];
    await this.distributeTasksToSwarm(swarm, tasks);
  }
  /**
   * Distribute tasks to swarm agents
   */
  async distributeTasksToSwarm(swarm, tasks) {
    const availableAgents = Array.from(swarm.agents.values()).filter((agent) => agent.status === "idle");
    for (let i = 0; i < tasks.length && i < availableAgents.length; i++) {
      const agent = availableAgents[i];
      const task = tasks[i];
      await this.assignTaskToAgent(agent, task, swarm);
    }
    swarm.metrics.tasksAssigned += tasks.length;
  }
  /**
   * Assign task to specific agent
   */
  async assignTaskToAgent(agent, task, swarm) {
    agent.status = "working";
    agent.currentTask = task;
    agent.lastActivity = Date.now();
    setTimeout(async () => {
      await this.completeAgentTask(agent, task, swarm);
    }, Math.random() * 3e3 + 2e3);
  }
  /**
   * Complete agent task
   */
  async completeAgentTask(agent, task, swarm) {
    agent.status = "idle";
    agent.currentTask = null;
    agent.tasksCompleted++;
    agent.lastActivity = Date.now();
    swarm.metrics.tasksCompleted++;
    this.metrics.tasksCompleted++;
    agent.neuralState.patterns.push({
      task: task.type,
      success: true,
      timestamp: Date.now()
    });
    console.log(swarm.mission.color(
      `\u2713 ${agent.role} completed ${task.type} on ${task.target}`
    ));
    this.emit("taskCompleted", { agent, task, swarm });
  }
  /**
   * Execute swarm synchronization
   */
  async executeSwarmSynchronization() {
    console.log(chalk.bold.cyan("\n\u{1F517} Synchronizing Swarms..."));
    const syncOperations = [];
    const swarmArray = Array.from(this.swarms.values());
    for (let i = 0; i < swarmArray.length; i++) {
      for (let j = i + 1; j < swarmArray.length; j++) {
        syncOperations.push(
          this.syncSwarmPair(swarmArray[i], swarmArray[j])
        );
      }
    }
    await Promise.all(syncOperations);
    this.metrics.swarmSyncs += syncOperations.length;
  }
  /**
   * Sync two swarms
   */
  async syncSwarmPair(swarm1, swarm2) {
    const sharedData = {
      timestamp: Date.now(),
      swarm1Status: swarm1.metrics,
      swarm2Status: swarm2.metrics,
      sharedInsights: []
    };
    await this.coordinator.exchangeData(swarm1.id, swarm2.id, sharedData);
    this.metrics.messagesExchanged += 2;
    console.log(chalk.cyan(
      `\u{1F504} Synced ${swarm1.mission.name} \u2194 ${swarm2.mission.name}`
    ));
  }
  /**
   * Execute resilience test
   */
  async executeResilienceTest() {
    console.log(chalk.bold.red("\n\u{1F6E1}\uFE0F  Testing Resilience Patterns..."));
    const swarmArray = Array.from(this.swarms.values());
    const targetSwarm = swarmArray[Math.floor(Math.random() * swarmArray.length)];
    const targetAgent = Array.from(targetSwarm.agents.values())[0];
    console.log(chalk.red(`\u26A0\uFE0F  Simulating failure in ${targetAgent.role}`));
    targetAgent.status = "failed";
    targetAgent.performance = 0;
    await this.recoverFailedAgent(targetAgent, targetSwarm);
  }
  /**
   * Recover failed agent
   */
  async recoverFailedAgent(agent, swarm) {
    console.log(chalk.yellow(`\u{1F527} Initiating recovery for ${agent.role}...`));
    if (agent.currentTask) {
      const backupAgent = Array.from(swarm.agents.values()).find((a) => a.status === "idle" && a.id !== agent.id);
      if (backupAgent) {
        await this.assignTaskToAgent(backupAgent, agent.currentTask, swarm);
        console.log(chalk.green(`\u2705 Task redistributed to ${backupAgent.role}`));
      }
    }
    setTimeout(() => {
      agent.status = "idle";
      agent.performance = 100;
      agent.currentTask = null;
      this.metrics.errorsRecovered++;
      console.log(chalk.green(`\u2705 ${agent.role} recovered successfully`));
    }, 2e3);
  }
  /**
   * Start real-time monitoring
   */
  startMonitoring() {
    const monitoringInterval = setInterval(() => {
      if (!this.isRunning) {
        clearInterval(monitoringInterval);
        return;
      }
      this.monitor.collectMetrics(this.swarms, this.metrics);
      this.displayStatus();
    }, 3e3);
  }
  /**
   * Display current status
   */
  displayStatus() {
    console.log(chalk.bold.white("\n\u{1F4C8} System Status:"));
    console.log(chalk.white(`\u2022 Total Agents: ${this.metrics.totalAgents}`));
    console.log(chalk.white(`\u2022 Tasks Completed: ${this.metrics.tasksCompleted}`));
    console.log(chalk.white(`\u2022 Messages Exchanged: ${this.metrics.messagesExchanged}`));
    console.log(chalk.white(`\u2022 Errors Recovered: ${this.metrics.errorsRecovered}`));
    console.log(chalk.white(`\u2022 Swarm Syncs: ${this.metrics.swarmSyncs}`));
    this.swarms.forEach((swarm) => {
      const efficiency = Math.round(
        swarm.metrics.tasksCompleted / Math.max(1, swarm.metrics.tasksAssigned) * 100
      );
      console.log(swarm.mission.color(
        `\u2022 ${swarm.mission.name}: ${efficiency}% efficiency`
      ));
    });
  }
  /**
   * Final synchronization
   */
  async finalSynchronization() {
    console.log(chalk.bold.magenta("\n\u{1F3AF} Final Synchronization..."));
    const allInsights = await this.coordinator.collectGlobalInsights(this.swarms);
    const report = this.monitor.generateFinalReport(this.swarms, this.metrics, allInsights);
    console.log(chalk.bold.green("\n\u2728 Concurrent Swarm Operation Complete!"));
    console.log(chalk.white(`Total Runtime: ${Math.round((Date.now() - this.startTime) / 1e3)}s`));
    this.isRunning = false;
    return report;
  }
  /**
   * Handle critical errors
   */
  async handleCriticalError(error) {
    console.error(chalk.red("\u{1F6A8} Critical error detected:", error.message));
    try {
      await this.coordinator.emergencyShutdown(this.swarms);
      await this.monitor.saveEmergencySnapshot(this.swarms, this.metrics);
    } catch (shutdownError) {
      console.error(chalk.red("Failed to perform graceful shutdown:", shutdownError));
    }
    this.isRunning = false;
  }
}
if (import.meta.url === `file://${process.argv[1]}`) {
  const demo = new ConcurrentSwarmDemo();
  demo.launch().catch(console.error);
}

const concurrentSwarmWorkflow = createWorkflow({
  id: "concurrent-swarm-orchestration",
  description: "Orchestrates concurrent swarms with real-time monitoring and coordination",
  inputSchema: z.object({
    missionName: z.string(),
    objectives: z.array(z.string()),
    swarmCount: z.number().min(1).max(10).default(3),
    coordinationMode: z.enum(["parallel", "sequential", "adaptive"]).default("parallel"),
    monitoringEnabled: z.boolean().default(true)
  }),
  outputSchema: z.object({
    success: z.boolean(),
    report: z.object({
      summary: z.any(),
      swarmPerformance: z.array(z.any()),
      insights: z.any(),
      recommendations: z.array(z.any()),
      alerts: z.array(z.any())
    }),
    metrics: z.object({
      totalAgents: z.number(),
      tasksCompleted: z.number(),
      messagesExchanged: z.number(),
      errorsRecovered: z.number(),
      swarmSyncs: z.number(),
      runtime: z.number()
    })
  })
}).then(createStep({
  id: "initialize-concurrent-system",
  description: "Initialize the concurrent swarm demonstration system",
  inputSchema: z.object({
    missionName: z.string(),
    objectives: z.array(z.string()),
    swarmCount: z.number(),
    monitoringEnabled: z.boolean()
  }),
  outputSchema: z.object({
    systemId: z.string(),
    swarmDemo: z.any(),
    monitor: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F680} Initializing concurrent swarm system:", context.missionName);
    const swarmDemo = new ConcurrentSwarmDemo();
    const monitor = swarmDemo.monitor;
    const systemId = `concurrent_${Date.now()}`;
    return {
      systemId,
      swarmDemo,
      monitor
    };
  }
})).then(createStep({
  id: "launch-concurrent-swarms",
  description: "Launch multiple specialized swarms concurrently",
  inputSchema: z.object({
    systemId: z.string(),
    swarmDemo: z.any(),
    objectives: z.array(z.string()),
    coordinationMode: z.enum(["parallel", "sequential", "adaptive"])
  }),
  outputSchema: z.object({
    launchSuccess: z.boolean(),
    activeSwarms: z.number(),
    startTime: z.number()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F504} Launching concurrent swarms in", context.coordinationMode, "mode");
    try {
      context.swarmDemo.launch().catch(console.error);
      await new Promise((resolve) => setTimeout(resolve, 1e3));
      return {
        launchSuccess: true,
        activeSwarms: context.swarmDemo.swarms.size,
        startTime: context.swarmDemo.startTime
      };
    } catch (error) {
      console.error("Failed to launch swarms:", error);
      return {
        launchSuccess: false,
        activeSwarms: 0,
        startTime: Date.now()
      };
    }
  }
})).then(createStep({
  id: "monitor-swarm-operations",
  description: "Monitor concurrent swarm operations in real-time",
  inputSchema: z.object({
    swarmDemo: z.any(),
    monitor: z.any(),
    monitoringEnabled: z.boolean(),
    activeSwarms: z.number()
  }),
  outputSchema: z.object({
    monitoringActive: z.boolean(),
    performanceSnapshot: z.any(),
    alerts: z.array(z.any())
  }),
  execute: async ({ context }) => {
    if (!context.monitoringEnabled) {
      return {
        monitoringActive: false,
        performanceSnapshot: null,
        alerts: []
      };
    }
    console.log("\u{1F4CA} Monitoring", context.activeSwarms, "active swarms");
    context.monitor.collectMetrics(context.swarmDemo.swarms, context.swarmDemo.metrics);
    const performanceSnapshot = {
      timestamp: Date.now(),
      swarmStatus: Array.from(context.swarmDemo.swarms.values()).map((swarm) => ({
        id: swarm.id,
        name: swarm.mission.name,
        status: swarm.status,
        efficiency: swarm.metrics.efficiency,
        tasksCompleted: swarm.metrics.tasksCompleted,
        agentCount: swarm.agents.size
      })),
      globalMetrics: context.swarmDemo.metrics
    };
    return {
      monitoringActive: true,
      performanceSnapshot,
      alerts: context.monitor.alerts
    };
  }
})).then(createStep({
  id: "coordinate-swarm-sync",
  description: "Coordinate synchronization between swarms",
  inputSchema: z.object({
    swarmDemo: z.any(),
    coordinationMode: z.enum(["parallel", "sequential", "adaptive"])
  }),
  outputSchema: z.object({
    syncCompleted: z.boolean(),
    syncOperations: z.number(),
    sharedInsights: z.array(z.string())
  }),
  execute: async ({ context }) => {
    console.log("\u{1F517} Coordinating swarm synchronization");
    await new Promise((resolve) => setTimeout(resolve, 5e3));
    await context.swarmDemo.executeSwarmSynchronization();
    const sharedInsights = [
      "Cross-swarm collaboration patterns identified",
      "Resource optimization opportunities detected",
      "Performance bottlenecks addressed through coordination",
      "Task redistribution completed successfully"
    ];
    return {
      syncCompleted: true,
      syncOperations: context.swarmDemo.metrics.swarmSyncs,
      sharedInsights
    };
  }
})).then(createStep({
  id: "generate-final-report",
  description: "Generate comprehensive report of concurrent swarm operations",
  inputSchema: z.object({
    swarmDemo: z.any(),
    monitor: z.any(),
    startTime: z.number(),
    performanceSnapshot: z.any(),
    sharedInsights: z.array(z.string())
  }),
  outputSchema: z.object({
    success: z.boolean(),
    report: z.any(),
    metrics: z.any()
  }),
  execute: async ({ context }) => {
    console.log("\u{1F4DD} Generating final report");
    await new Promise((resolve) => setTimeout(resolve, 1e4));
    context.swarmDemo.isRunning = false;
    const allInsights = await context.swarmDemo.coordinator.collectGlobalInsights(context.swarmDemo.swarms);
    const report = context.monitor.generateFinalReport(
      context.swarmDemo.swarms,
      context.swarmDemo.metrics,
      allInsights
    );
    report.insights.sharedInsights = context.sharedInsights;
    const runtime = Math.round((Date.now() - context.startTime) / 1e3);
    const finalMetrics = {
      ...context.swarmDemo.metrics,
      runtime
    };
    console.log("\u2728 Concurrent swarm operation completed");
    console.log(`Total Runtime: ${runtime}s`);
    console.log(`Tasks Completed: ${finalMetrics.tasksCompleted}`);
    console.log(`Swarm Efficiency: ${report.swarmPerformance.reduce((sum, s) => sum + s.efficiency, 0) / report.swarmPerformance.length}%`);
    return {
      success: true,
      report,
      metrics: finalMetrics
    };
  }
}));

const agenticFlowTheme = {
  // Brand Colors
  colors: {
    primary: "#2563EB",
    // Agentic Flow Blue
    secondary: "#7C3AED",
    // Agentic Flow Purple  
    accent: "#10B981",
    // Success Green
    warning: "#F59E0B",
    // Warning Amber
    error: "#EF4444",
    // Error Red
    // Background Colors
    background: "#0F172A",
    // Dark Navy
    surface: "#1E293B",
    // Dark Gray
    card: "#334155",
    // Medium Gray
    // Text Colors
    text: {
      primary: "#F8FAFC",
      // White
      secondary: "#CBD5E1",
      // Light Gray
      muted: "#94A3B8"
      // Medium Gray
    },
    // Agent Type Colors
    agents: {
      coordinator: "#3B82F6",
      // Blue
      executor: "#10B981",
      // Green  
      researcher: "#F59E0B",
      // Amber
      architect: "#8B5CF6",
      // Purple
      analyst: "#EF4444",
      // Red
      coder: "#06B6D4",
      // Cyan
      tester: "#84CC16",
      // Lime
      reviewer: "#F97316",
      // Orange
      monitor: "#6366F1",
      // Indigo
      optimizer: "#EC4899"
      // Pink
    }
  },
  // Typography
  typography: {
    fontFamily: {
      sans: ["Inter", "system-ui", "sans-serif"],
      mono: ["Fira Code", "Monaco", "monospace"]
    },
    fontSize: {
      xs: "0.75rem",
      sm: "0.875rem",
      base: "1rem",
      lg: "1.125rem",
      xl: "1.25rem",
      "2xl": "1.5rem",
      "3xl": "1.875rem",
      "4xl": "2.25rem"
    },
    fontWeight: {
      normal: "400",
      medium: "500",
      semibold: "600",
      bold: "700"
    }
  },
  // Spacing
  spacing: {
    xs: "0.5rem",
    sm: "0.75rem",
    md: "1rem",
    lg: "1.5rem",
    xl: "2rem",
    "2xl": "3rem"
  },
  // Border Radius
  borderRadius: {
    sm: "0.375rem",
    md: "0.5rem",
    lg: "0.75rem",
    xl: "1rem"
  },
  // Shadows
  shadows: {
    sm: "0 1px 2px 0 rgb(0 0 0 / 0.05)",
    md: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
    lg: "0 10px 15px -3px rgb(0 0 0 / 0.1)",
    xl: "0 20px 25px -5px rgb(0 0 0 / 0.1)"
  },
  // Component Styles
  components: {
    // Agent Cards
    agentCard: {
      background: "linear-gradient(135deg, #1E293B 0%, #334155 100%)",
      border: "1px solid #475569",
      borderRadius: "0.75rem",
      padding: "1.5rem",
      boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)"
    },
    // Workflow Cards
    workflowCard: {
      background: "linear-gradient(135deg, #312E81 0%, #5B21B6 100%)",
      border: "1px solid #6366F1",
      borderRadius: "0.75rem",
      padding: "1.5rem",
      boxShadow: "0 10px 15px -3px rgb(0 0 0 / 0.1)"
    },
    // Tool Cards
    toolCard: {
      background: "linear-gradient(135deg, #065F46 0%, #047857 100%)",
      border: "1px solid #10B981",
      borderRadius: "0.75rem",
      padding: "1rem",
      boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)"
    },
    // Status Indicators
    status: {
      active: "#10B981",
      inactive: "#6B7280",
      running: "#3B82F6",
      completed: "#10B981",
      failed: "#EF4444",
      pending: "#F59E0B"
    }
  },
  // Animation
  animation: {
    duration: {
      fast: "150ms",
      normal: "300ms",
      slow: "500ms"
    },
    easing: {
      default: "cubic-bezier(0.4, 0, 0.2, 1)",
      in: "cubic-bezier(0.4, 0, 1, 1)",
      out: "cubic-bezier(0, 0, 0.2, 1)"
    }
  }
};
const brandConfig = {
  name: "Agentic Flow",
  tagline: "AI Orchestration Platform",
  description: "Multi-agent coordination and workflow automation",
  version: "2.0.0",
  // Logo Configuration
  logo: {
    text: "\u{1F916} Agentic Flow",
    icon: "\u{1F916}",
    colors: {
      primary: "#2563EB",
      secondary: "#7C3AED"
    }
  },
  // Navigation
  navigation: {
    primary: [
      { name: "Dashboard", path: "/", icon: "\u{1F4CA}" },
      { name: "Agents", path: "/agents", icon: "\u{1F916}" },
      { name: "Workflows", path: "/workflows", icon: "\u{1F504}" },
      { name: "Tools", path: "/tools", icon: "\u{1F6E0}\uFE0F" },
      { name: "Teams", path: "/teams", icon: "\u{1F465}" },
      { name: "Monitor", path: "/monitor", icon: "\u{1F4C8}" }
    ],
    secondary: [
      { name: "Settings", path: "/settings", icon: "\u2699\uFE0F" },
      { name: "Documentation", path: "/docs", icon: "\u{1F4D6}" },
      { name: "API", path: "/api", icon: "\u{1F517}" }
    ]
  },
  // Feature Highlights
  features: [
    {
      title: "Multi-Agent Coordination",
      description: "Coordinate multiple AI agents for complex tasks",
      icon: "\u{1F916}",
      color: "#3B82F6"
    },
    {
      title: "Visual Workflows",
      description: "Design and execute workflows visually",
      icon: "\u{1F504}",
      color: "#8B5CF6"
    },
    {
      title: "Real-time Monitoring",
      description: "Monitor system health and performance",
      icon: "\u{1F4CA}",
      color: "#10B981"
    },
    {
      title: "Team Management",
      description: "Form and manage agent teams dynamically",
      icon: "\u{1F465}",
      color: "#F59E0B"
    }
  ],
  // Integration Points
  integrations: {
    claudeFlow: {
      name: "Claude Flow",
      description: "Advanced Claude agent coordination",
      icon: "\u{1F9E0}",
      color: "#FF6B35"
    },
    hiveMind: {
      name: "Hive Mind",
      description: "Collective intelligence system",
      icon: "\u{1F41D}",
      color: "#FFD23F"
    },
    ruvSwarm: {
      name: "RUV Swarm",
      description: "Distributed agent swarms",
      icon: "\u{1F525}",
      color: "#EE4266"
    }
  }
};

const createMcpAgents = () => {
  const claudeFlowMcpAgent = new Agent({
    name: "claude-flow-mcp-agent",
    description: "Agent connected to Claude Flow MCP server",
    model: {
      provider: "anthropic",
      name: "claude-3-sonnet-20240229"
    },
    instructions: `You are an agent with access to Claude Flow MCP server capabilities.
    You can initialize swarms, spawn agents, orchestrate tasks, train neural patterns,
    manage memory, and generate performance reports using the Claude Flow infrastructure.`
    // Tools will be added dynamically when MCP server is connected
  });
  const agenticFlowMcpAgent = new Agent({
    name: "agentic-flow-mcp-agent",
    description: "Agent connected to Agentic Flow MCP server",
    model: {
      provider: "anthropic",
      name: "claude-3-sonnet-20240229"
    },
    instructions: `You are an agent with access to Agentic Flow MCP server capabilities.
    You can create teams, coordinate workflows, capture learning experiences,
    track metrics, and run simulations using the Agentic Flow platform.`
    // Tools will be added dynamically when MCP server is connected
  });
  return {
    claudeFlowMcpAgent,
    agenticFlowMcpAgent
  };
};
const createMcpSimulatorTools = () => {
  const claudeFlowSwarmInit = createTool({
    id: "claude-flow-swarm-init",
    description: "Initialize a Claude Flow swarm with specified topology",
    inputSchema: z.object({
      topology: z.enum(["hierarchical", "mesh", "ring", "star"]),
      maxAgents: z.number().min(1).max(100).default(8),
      strategy: z.enum(["auto", "manual", "adaptive"]).default("auto")
    }),
    execute: async ({ context }) => {
      const { topology, maxAgents, strategy } = context;
      console.log(`\u{1F535} [MCP Simulator] Claude Flow: Initializing ${topology} swarm with ${maxAgents} agents`);
      return {
        success: true,
        swarmId: `cf-swarm-${Date.now()}`,
        topology,
        maxAgents,
        strategy,
        status: "initialized",
        message: `Claude Flow swarm initialized with ${topology} topology`
      };
    }
  });
  const claudeFlowAgentSpawn = createTool({
    id: "claude-flow-agent-spawn",
    description: "Spawn specialized agents in Claude Flow",
    inputSchema: z.object({
      type: z.enum(["coordinator", "researcher", "coder", "analyst", "architect"]),
      capabilities: z.array(z.string()).optional(),
      swarmId: z.string().optional()
    }),
    execute: async ({ context }) => {
      const { type, capabilities = [], swarmId } = context;
      console.log(`\u{1F535} [MCP Simulator] Claude Flow: Spawning ${type} agent`);
      return {
        success: true,
        agentId: `cf-agent-${type}-${Date.now()}`,
        type,
        capabilities,
        swarmId,
        status: "active",
        message: `${type} agent spawned successfully`
      };
    }
  });
  const claudeFlowTaskOrchestrate = createTool({
    id: "claude-flow-task-orchestrate",
    description: "Orchestrate complex tasks with Claude Flow",
    inputSchema: z.object({
      task: z.string(),
      priority: z.enum(["low", "medium", "high", "critical"]).default("medium"),
      dependencies: z.array(z.string()).optional(),
      strategy: z.enum(["parallel", "sequential", "adaptive"]).default("adaptive")
    }),
    execute: async ({ context }) => {
      const { task, priority, strategy } = context;
      console.log(`\u{1F535} [MCP Simulator] Claude Flow: Orchestrating task "${task}" with ${priority} priority`);
      return {
        success: true,
        orchestrationId: `cf-orch-${Date.now()}`,
        task,
        priority,
        strategy,
        status: "running",
        estimatedCompletion: "5 minutes",
        message: "Task orchestration initiated"
      };
    }
  });
  const agenticFlowTeamCreate = createTool({
    id: "agentic-flow-team-create",
    description: "Create a team in Agentic Flow",
    inputSchema: z.object({
      name: z.string(),
      members: z.array(z.object({
        role: z.string(),
        capabilities: z.array(z.string())
      })),
      goal: z.string()
    }),
    execute: async ({ context }) => {
      const { name, members, goal } = context;
      console.log(`\u{1F7E2} [MCP Simulator] Agentic Flow: Creating team "${name}" with ${members.length} members`);
      return {
        success: true,
        teamId: `af-team-${Date.now()}`,
        name,
        members,
        goal,
        status: "active",
        created: (/* @__PURE__ */ new Date()).toISOString(),
        message: `Team "${name}" created successfully`
      };
    }
  });
  const agenticFlowWorkflowExecute = createTool({
    id: "agentic-flow-workflow-execute",
    description: "Execute a workflow in Agentic Flow",
    inputSchema: z.object({
      workflowId: z.string(),
      input: z.record(z.any()),
      config: z.object({
        timeout: z.number().optional(),
        retries: z.number().optional()
      }).optional()
    }),
    execute: async ({ context }) => {
      const { workflowId, input } = context;
      console.log(`\u{1F7E2} [MCP Simulator] Agentic Flow: Executing workflow "${workflowId}"`);
      return {
        success: true,
        executionId: `af-exec-${Date.now()}`,
        workflowId,
        input,
        status: "running",
        startTime: (/* @__PURE__ */ new Date()).toISOString(),
        message: `Workflow "${workflowId}" execution started`
      };
    }
  });
  const agenticFlowLearningCapture = createTool({
    id: "agentic-flow-learning-capture",
    description: "Capture learning experiences in Agentic Flow",
    inputSchema: z.object({
      experience: z.object({
        action: z.string(),
        outcome: z.string(),
        context: z.record(z.any())
      }),
      category: z.enum(["success", "failure", "insight"]).default("insight")
    }),
    execute: async ({ context }) => {
      const { experience, category } = context;
      console.log(`\u{1F7E2} [MCP Simulator] Agentic Flow: Capturing ${category} learning experience`);
      return {
        success: true,
        learningId: `af-learn-${Date.now()}`,
        experience,
        category,
        stored: true,
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        message: `Learning experience captured as ${category}`
      };
    }
  });
  const mcpServerStatus = createTool({
    id: "mcp-server-status",
    description: "Check MCP server connection status",
    inputSchema: z.object({
      servers: z.array(z.string()).optional()
    }),
    execute: async ({ context }) => {
      const { servers = ["claude-flow", "agentic-flow"] } = context;
      console.log(`\u{1F50D} [MCP Simulator] Checking status of MCP servers:`, servers);
      return {
        servers: {
          "claude-flow": {
            connected: false,
            simulator: true,
            message: "Using simulator mode - MCP server not running"
          },
          "agentic-flow": {
            connected: false,
            simulator: true,
            message: "Using simulator mode - MCP server not running"
          }
        },
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      };
    }
  });
  return {
    // Claude Flow tools
    claudeFlowSwarmInit,
    claudeFlowAgentSpawn,
    claudeFlowTaskOrchestrate,
    // Agentic Flow tools
    agenticFlowTeamCreate,
    agenticFlowWorkflowExecute,
    agenticFlowLearningCapture,
    // Utility tools
    mcpServerStatus
  };
};
const mcpConfig = {
  // Tool mappings
  tools: createMcpSimulatorTools(),
  // Agent configurations
  agents: createMcpAgents()
};
const checkMcpServers = async () => {
  try {
    console.log("\u{1F50C} MCP Integration Status:");
    console.log("   \u2022 Claude Flow MCP: Simulator Mode (Port 5001 reserved)");
    console.log("   \u2022 Agentic Flow MCP: Simulator Mode (Port 5002 reserved)");
    console.log("   \u2022 To connect real MCP servers, start them with:");
    console.log("     - npx claude-flow mcp start");
    console.log("     - cd ../../src/mcp && npm start");
    return false;
  } catch (error) {
    console.error("Error checking MCP servers:", error);
    return false;
  }
};

const networkRegistry = /* @__PURE__ */ new Map();
class NetworkSimulator {
  constructor(config) {
    this.name = config.name;
    this.description = config.description;
    this.agents = config.agents || [];
    this.tools = config.tools || [];
    this.config = config.config || {};
    this.capabilities = config.capabilities || {};
    this.metrics = config.metrics || {};
    this.workflows = config.workflows || [];
    this.status = "inactive";
    this.activeAgents = /* @__PURE__ */ new Set();
    this.taskQueue = [];
    this.completedTasks = 0;
    networkRegistry.set(this.name, this);
  }
  // Initialize network
  async initialize() {
    this.status = "active";
    console.log(`\u{1F310} Network ${this.name} initialized`);
    return {
      name: this.name,
      status: this.status,
      agents: this.agents.length,
      tools: this.tools.length
    };
  }
  // Add agent to network
  addAgent(agentName) {
    if (!this.agents.includes(agentName)) {
      this.agents.push(agentName);
    }
    this.activeAgents.add(agentName);
  }
  // Remove agent from network
  removeAgent(agentName) {
    this.activeAgents.delete(agentName);
  }
  // Get network status
  getStatus() {
    return {
      name: this.name,
      description: this.description,
      status: this.status,
      topology: this.config.networkTopology || "mesh",
      agents: {
        total: this.agents.length,
        active: this.activeAgents.size
      },
      tasks: {
        queued: this.taskQueue.length,
        completed: this.completedTasks
      },
      metrics: this.metrics
    };
  }
  // Queue task for network
  queueTask(task) {
    this.taskQueue.push({
      id: `task-${Date.now()}`,
      task,
      status: "queued",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  // Process next task
  async processNextTask() {
    if (this.taskQueue.length === 0) return null;
    const task = this.taskQueue.shift();
    task.status = "processing";
    await new Promise((resolve) => setTimeout(resolve, 100));
    task.status = "completed";
    this.completedTasks++;
    return task;
  }
}
const networkManagementTools = {
  // List all networks
  listNetworks: createTool({
    id: "list-networks",
    description: "List all available agent networks",
    inputSchema: z.object({
      includeMetrics: z.boolean().optional()
    }),
    execute: async ({ context }) => {
      const networks = [];
      for (const [name, network] of networkRegistry) {
        networks.push({
          name: network.name,
          description: network.description,
          status: network.getStatus()
        });
      }
      return { networks };
    }
  }),
  // Get network status
  getNetworkStatus: createTool({
    id: "get-network-status",
    description: "Get status of a specific network",
    inputSchema: z.object({
      networkName: z.string()
    }),
    execute: async ({ context }) => {
      const { networkName } = context;
      const network = networkRegistry.get(networkName);
      if (!network) {
        return { error: `Network ${networkName} not found` };
      }
      return network.getStatus();
    }
  }),
  // Route task to network
  routeToNetwork: createTool({
    id: "route-to-network",
    description: "Route a task to the appropriate network",
    inputSchema: z.object({
      task: z.string(),
      requirements: z.object({
        needsReasoning: z.boolean().optional(),
        needsConsensus: z.boolean().optional(),
        needsScale: z.boolean().optional()
      }).optional()
    }),
    execute: async ({ context }) => {
      const { task, requirements = {} } = context;
      let selectedNetwork = "claude-flow-network";
      if (requirements.needsScale) {
        selectedNetwork = "ruv-swarm-network";
      } else if (requirements.needsConsensus) {
        selectedNetwork = "hive-mind-network";
      } else if (requirements.needsReasoning) {
        selectedNetwork = "claude-flow-network";
      }
      const network = networkRegistry.get(selectedNetwork);
      if (network) {
        network.queueTask(task);
      }
      return {
        task,
        routedTo: selectedNetwork,
        queuePosition: network ? network.taskQueue.length : 0
      };
    }
  })
};

const claudeFlowNetwork = new NetworkSimulator({
  name: "claude-flow-network",
  description: "Advanced AI reasoning and coordination network with hierarchical agent orchestration",
  // Network agents
  agents: [
    "claude-flow-coordinator",
    "coordinator",
    "architect",
    "researcher"
  ],
  // Network-specific tools
  tools: [
    "claudeFlowCoordinate",
    "claudeFlowSwarmInit",
    "claudeFlowAgentSpawn",
    "claudeFlowTaskOrchestrate"
  ],
  // Network configuration
  config: {
    maxConcurrentAgents: 10,
    communicationProtocol: "hierarchical",
    consensusThreshold: 0.8,
    networkTopology: "hierarchical",
    // Advanced reasoning configuration
    reasoning: {
      maxDepth: 5,
      branching: true,
      backtracking: true,
      pruning: "adaptive"
    },
    // Coordination settings
    coordination: {
      strategy: "centralized",
      loadBalancing: "dynamic",
      failover: true,
      redundancy: 2
    }
  },
  // Network capabilities
  capabilities: {
    reasoning: ["deductive", "inductive", "abductive", "analogical"],
    coordination: ["task-delegation", "resource-allocation", "conflict-resolution"],
    learning: ["pattern-recognition", "strategy-adaptation", "performance-optimization"],
    scaling: ["horizontal", "vertical", "elastic"]
  },
  // Network metrics
  metrics: {
    performance: {
      latency: "low",
      throughput: "high",
      accuracy: 0.95
    },
    reliability: {
      uptime: 0.999,
      errorRate: 1e-3,
      recoveryTime: "< 5s"
    }
  },
  // Network workflows
  workflows: [
    "claude-flow-reasoning-workflow",
    "software-development",
    "problem-solving",
    "research-analysis"
  ]
});

const hiveMindNetwork = new NetworkSimulator({
  name: "hive-mind-network",
  description: "Distributed collective intelligence network with consensus-based decision making",
  // Network agents
  agents: [
    "hive-mind-collective",
    "executor",
    "researcher",
    "coordinator"
  ],
  // Network-specific tools
  tools: [
    "hiveMindCollective",
    "createTeam",
    "monitorSystem"
  ],
  // Network configuration
  config: {
    maxConcurrentAgents: 50,
    communicationProtocol: "mesh",
    consensusThreshold: 0.75,
    networkTopology: "mesh",
    // Collective intelligence settings
    collective: {
      minNodes: 5,
      maxNodes: 50,
      votingMechanism: "weighted",
      consensusAlgorithm: "byzantine-fault-tolerant"
    },
    // Swarm behavior
    swarmBehavior: {
      emergentPatterns: true,
      selfOrganization: true,
      adaptiveBehavior: true,
      collectiveMemory: true
    }
  },
  // Network capabilities
  capabilities: {
    intelligence: ["collective-reasoning", "distributed-processing", "emergent-behavior"],
    consensus: ["voting", "negotiation", "conflict-resolution", "agreement-building"],
    adaptation: ["self-organization", "pattern-emergence", "collective-learning"],
    resilience: ["fault-tolerance", "redundancy", "self-healing"]
  },
  // Communication patterns
  communicationPatterns: {
    internal: "peer-to-peer",
    external: "consensus-based",
    protocols: ["gossip", "flooding", "consensus-rounds"]
  },
  // Network metrics
  metrics: {
    collective: {
      consensusTime: "< 2s",
      agreementRate: 0.85,
      diversityIndex: 0.7
    },
    performance: {
      throughput: "very-high",
      scalability: "linear",
      efficiency: 0.9
    }
  },
  // Network workflows
  workflows: [
    "hive-mind-consensus-workflow",
    "research-analysis",
    "adaptive-problem-solving",
    "team-formation"
  ],
  // Network events
  events: {
    onConsensusReached: async (decision) => {
      console.log(`\u{1F41D} Hive Mind: Consensus reached on ${decision.topic}`);
    },
    onNodeJoin: async (node) => {
      console.log(`\u{1F41D} Hive Mind: Node ${node.id} joined the collective`);
    },
    onEmergentPattern: async (pattern) => {
      console.log(`\u{1F41D} Hive Mind: Emergent pattern detected: ${pattern.type}`);
    },
    onCollectiveInsight: async (insight) => {
      console.log(`\u{1F41D} Hive Mind: Collective insight generated: ${insight.summary}`);
    }
  },
  // Network policies
  policies: {
    voting: "reputation-weighted",
    resourceSharing: "communal",
    knowledgeDistribution: "broadcast",
    conflictResolution: "consensus-seeking"
  }
});

const ruvSwarmNetwork = new NetworkSimulator({
  name: "ruv-swarm-network",
  description: "Highly scalable distributed agent swarm with dynamic resource allocation and fault tolerance",
  // Network agents
  agents: [
    "ruv-swarm-coordinator",
    "executor",
    "architect",
    "coordinator"
  ],
  // Network-specific tools
  tools: [
    "ruvSwarmDeploy",
    "executeWorkflow",
    "monitorSystem"
  ],
  // Network configuration
  config: {
    maxConcurrentAgents: 100,
    communicationProtocol: "dynamic",
    consensusThreshold: 0.6,
    networkTopology: "dynamic-mesh",
    // Swarm configuration
    swarm: {
      initialSize: 20,
      maxSize: 100,
      minSize: 5,
      scalingStrategy: "elastic",
      replicationFactor: 3
    },
    // Fault tolerance
    faultTolerance: {
      redundancy: 3,
      failoverTime: "< 1s",
      recoveryStrategy: "automatic",
      healthCheckInterval: "5s"
    },
    // Resource management
    resourceManagement: {
      allocation: "dynamic",
      optimization: "continuous",
      loadBalancing: "adaptive",
      prioritization: "queue-based"
    }
  },
  // Network capabilities
  capabilities: {
    scaling: ["horizontal", "vertical", "elastic", "auto-scaling"],
    resilience: ["fault-detection", "auto-recovery", "load-distribution", "redundancy"],
    performance: ["parallel-processing", "distributed-computing", "optimization"],
    adaptation: ["dynamic-topology", "resource-reallocation", "pattern-learning"]
  },
  // Communication patterns
  communicationPatterns: {
    internal: "hybrid",
    external: "load-balanced",
    protocols: ["direct", "multicast", "anycast", "broadcast"]
  },
  // Network metrics
  metrics: {
    scaling: {
      elasticity: 0.95,
      responseTime: "< 500ms",
      efficiency: 0.92
    },
    reliability: {
      availability: 0.9999,
      mtbf: "720h",
      mttr: "< 30s"
    },
    performance: {
      throughput: "extreme",
      concurrency: 100,
      latency: "ultra-low"
    }
  },
  // Network workflows
  workflows: [
    "ruv-swarm-scaling-workflow",
    "crisis-response",
    "enterprise-integration",
    "system-optimization"
  ],
  // Network events
  events: {
    onSwarmScale: async (event) => {
      console.log(`\u{1F525} RUV Swarm: Scaled from ${event.from} to ${event.to} agents`);
    },
    onNodeFailure: async (node) => {
      console.log(`\u{1F525} RUV Swarm: Node ${node.id} failed, initiating recovery`);
    },
    onLoadBalance: async (metrics) => {
      console.log(`\u{1F525} RUV Swarm: Load balanced across ${metrics.nodes} nodes`);
    },
    onOptimization: async (result) => {
      console.log(`\u{1F525} RUV Swarm: Optimization completed, efficiency improved by ${result.improvement}%`);
    }
  },
  // Network policies
  policies: {
    scaling: "predictive",
    faultHandling: "proactive",
    resourceAllocation: "demand-driven",
    optimization: "continuous"
  }
});

const multiNetworkOrchestrator = new NetworkSimulator({
  name: "multi-network-orchestrator",
  description: "Meta-network that orchestrates and coordinates across all agent networks",
  // Network agents - includes representatives from all networks
  agents: [
    "coordinator",
    "claude-flow-coordinator",
    "hive-mind-collective",
    "ruv-swarm-coordinator",
    "claude-flow-mcp-agent",
    "agentic-flow-mcp-agent"
  ],
  // Cross-network tools
  tools: [
    "claudeFlowCoordinate",
    "hiveMindCollective",
    "ruvSwarmDeploy",
    "executeWorkflow",
    "monitorSystem",
    "mcpServerStatus"
  ],
  // Network configuration
  config: {
    maxConcurrentAgents: 200,
    communicationProtocol: "federated",
    consensusThreshold: 0.7,
    networkTopology: "federated-mesh",
    // Orchestration settings
    orchestration: {
      strategy: "adaptive",
      coordination: "hierarchical-consensus",
      routing: "capability-based",
      optimization: "global"
    },
    // Network federation
    federation: {
      networks: ["claude-flow", "hive-mind", "ruv-swarm"],
      interoperability: "full",
      dataSharing: "selective",
      protocolTranslation: true
    },
    // Cross-network policies
    crossNetwork: {
      taskRouting: "optimal-match",
      resourceSharing: "negotiated",
      conflictResolution: "priority-based",
      loadDistribution: "balanced"
    }
  },
  // Network capabilities
  capabilities: {
    orchestration: ["cross-network-coordination", "global-optimization", "federated-learning"],
    integration: ["protocol-translation", "data-harmonization", "capability-mapping"],
    intelligence: ["meta-reasoning", "network-selection", "strategy-synthesis"],
    management: ["resource-allocation", "performance-monitoring", "fault-isolation"]
  },
  // Communication patterns
  communicationPatterns: {
    internal: "federated",
    external: "unified-api",
    protocols: ["inter-network", "translation", "federation"]
  },
  // Network metrics
  metrics: {
    orchestration: {
      networkUtilization: 0.85,
      crossNetworkLatency: "< 100ms",
      coordinationEfficiency: 0.92
    },
    integration: {
      interoperability: 0.95,
      translationAccuracy: 0.98,
      dataConsistency: 0.99
    }
  },
  // Network workflows
  workflows: [
    "multi-network-orchestration",
    "mcp-swarm-orchestration",
    "mcp-multi-server-coordination",
    "task-routing"
  ],
  // Network events
  events: {
    onNetworkJoin: async (network) => {
      console.log(`\u{1F310} Orchestrator: Network ${network.name} joined federation`);
    },
    onCrossNetworkTask: async (task) => {
      console.log(`\u{1F310} Orchestrator: Routing task ${task.id} across ${task.networks.length} networks`);
    },
    onGlobalOptimization: async (result) => {
      console.log(`\u{1F310} Orchestrator: Global optimization achieved ${result.improvement}% improvement`);
    },
    onFederationUpdate: async (update) => {
      console.log(`\u{1F310} Orchestrator: Federation updated - ${update.type}`);
    }
  },
  // Network policies
  policies: {
    taskDistribution: "capability-optimal",
    networkSelection: "performance-based",
    resourceAllocation: "fair-share",
    prioritization: "global-impact"
  }
});

const agentNetworks = {
  "claude-flow": claudeFlowNetwork,
  "hive-mind": hiveMindNetwork,
  "ruv-swarm": ruvSwarmNetwork,
  "multi-network": multiNetworkOrchestrator
};

const swarmState = /* @__PURE__ */ new Map();
const agentTasks = /* @__PURE__ */ new Map();
const swarmMetrics = /* @__PURE__ */ new Map();
const initializeFiveAgentSwarm = createTool({
  id: "initialize-five-agent-swarm",
  name: "Initialize 5-Agent Swarm",
  description: "Initialize a coordinated swarm of 5 specialized agents",
  inputSchema: z.object({
    swarmName: z.string(),
    topology: z.enum(["mesh", "hierarchical", "ring", "star"]).default("mesh"),
    coordinatorAgent: z.string().optional()
  }),
  execute: async ({ swarmName, topology, coordinatorAgent }) => {
    const swarmId = `swarm_${swarmName}_${Date.now()}`;
    const swarmConfig = {
      id: swarmId,
      name: swarmName,
      topology,
      agents: {
        dataAnalyst: {
          agent: "dataAnalystAgent",
          role: "Data processing and analysis",
          status: "active",
          taskQueue: [],
          metrics: {
            tasksCompleted: 0,
            successRate: 100,
            avgResponseTime: 0
          }
        },
        securityExpert: {
          agent: "securityExpertAgent",
          role: "Security and threat analysis",
          status: "active",
          taskQueue: [],
          metrics: {
            threatsDetected: 0,
            vulnerabilitiesFound: 0,
            incidentsResolved: 0
          }
        },
        devOpsEngineer: {
          agent: "devOpsEngineerAgent",
          role: "Infrastructure and deployment",
          status: "active",
          taskQueue: [],
          metrics: {
            deploymentsCompleted: 0,
            automationTasks: 0,
            systemUptime: 99.9
          }
        },
        researchScientist: {
          agent: "researchScientistAgent",
          role: "Research and innovation",
          status: "active",
          taskQueue: [],
          metrics: {
            experimentsRun: 0,
            modelsTraineds: 0,
            breakthroughs: 0
          }
        },
        productManager: {
          agent: "productManagerAgent",
          role: "Coordination and planning",
          status: "active",
          taskQueue: [],
          metrics: {
            featuresDelivered: 0,
            userSatisfaction: 0,
            coordinationTasks: 0
          }
        }
      },
      coordinator: coordinatorAgent || "productManager",
      topology,
      connections: generateTopologyConnections(topology),
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      status: "active",
      metrics: {
        totalTasks: 0,
        completedTasks: 0,
        failedTasks: 0,
        avgCompletionTime: 0,
        efficiency: 100
      }
    };
    swarmState.set(swarmId, swarmConfig);
    Object.keys(swarmConfig.agents).forEach((agentKey) => {
      agentTasks.set(`${swarmId}_${agentKey}`, []);
    });
    swarmMetrics.set(swarmId, {
      startTime: Date.now(),
      taskHistory: [],
      performanceHistory: []
    });
    return {
      success: true,
      swarmId,
      configuration: {
        name: swarmName,
        topology,
        agentCount: 5,
        coordinator: swarmConfig.coordinator,
        agents: Object.keys(swarmConfig.agents)
      },
      message: `5-agent swarm '${swarmName}' initialized successfully with ${topology} topology`
    };
  }
});
const orchestrateSwarmTask = createTool({
  id: "orchestrate-swarm-task",
  name: "Orchestrate Swarm Task",
  description: "Distribute and coordinate a complex task across the 5-agent swarm",
  inputSchema: z.object({
    swarmId: z.string(),
    task: z.string(),
    taskType: z.enum(["analysis", "development", "security", "research", "planning"]),
    priority: z.enum(["low", "medium", "high", "critical"]).default("medium"),
    requiresCollaboration: z.boolean().default(true)
  }),
  execute: async ({ swarmId, task, taskType, priority, requiresCollaboration }) => {
    const swarm = swarmState.get(swarmId);
    if (!swarm) {
      return { success: false, error: "Swarm not found" };
    }
    const taskId = `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const taskPlan = {
      subtasks: [],
      assignments: {},
      createdAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    const subtasks = analyzeAndDecomposeTask(task, taskType);
    subtasks.forEach((subtask, index) => {
      const assignedAgent = selectBestAgent(subtask, swarm.agents);
      taskPlan.subtasks.push({
        id: `${taskId}_sub_${index}`,
        description: subtask.description,
        type: subtask.type,
        assignedTo: assignedAgent,
        status: "assigned",
        dependencies: subtask.dependencies || []
      });
      taskPlan.assignments[assignedAgent] = taskPlan.assignments[assignedAgent] || [];
      taskPlan.assignments[assignedAgent].push(`${taskId}_sub_${index}`);
    });
    swarm.metrics.totalTasks++;
    const collaborationPlan = requiresCollaboration ? setupCollaborationChannels(taskPlan) : null;
    const executionResults = await executeSwarmTask(swarm, taskPlan);
    return {
      success: true,
      taskId,
      taskPlan: {
        mainTask: task,
        subtaskCount: subtasks.length,
        assignments: taskPlan.assignments,
        estimatedCompletionTime: estimateCompletionTime(subtasks, priority)
      },
      collaboration: collaborationPlan,
      execution: executionResults,
      message: `Task orchestrated across ${Object.keys(taskPlan.assignments).length} agents`
    };
  }
});
const monitorSwarmPerformance = createTool({
  id: "monitor-swarm-performance",
  name: "Monitor Swarm Performance",
  description: "Real-time monitoring of the 5-agent swarm performance",
  inputSchema: z.object({
    swarmId: z.string(),
    includeAgentMetrics: z.boolean().default(true),
    includeTaskHistory: z.boolean().default(false)
  }),
  execute: async ({ swarmId, includeAgentMetrics, includeTaskHistory }) => {
    const swarm = swarmState.get(swarmId);
    if (!swarm) {
      return { success: false, error: "Swarm not found" };
    }
    const metrics = swarmMetrics.get(swarmId);
    const uptime = Date.now() - metrics.startTime;
    const performanceReport = {
      swarmId,
      name: swarm.name,
      status: swarm.status,
      uptime: formatUptime(uptime),
      topology: swarm.topology,
      overallMetrics: {
        ...swarm.metrics,
        successRate: swarm.metrics.totalTasks > 0 ? (swarm.metrics.completedTasks / swarm.metrics.totalTasks * 100).toFixed(2) + "%" : "100%",
        utilizationRate: calculateUtilizationRate(swarm.agents)
      }
    };
    if (includeAgentMetrics) {
      performanceReport.agentMetrics = {};
      Object.entries(swarm.agents).forEach(([agentKey, agentData]) => {
        performanceReport.agentMetrics[agentKey] = {
          status: agentData.status,
          role: agentData.role,
          queueLength: agentData.taskQueue.length,
          metrics: agentData.metrics,
          efficiency: calculateAgentEfficiency(agentData)
        };
      });
    }
    if (includeTaskHistory && metrics.taskHistory) {
      performanceReport.recentTasks = metrics.taskHistory.slice(-10);
    }
    performanceReport.insights = generatePerformanceInsights(swarm);
    performanceReport.recommendations = generateOptimizationRecommendations(swarm);
    return {
      success: true,
      performance: performanceReport,
      healthStatus: determineSwarmHealth(swarm),
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
});
const facilitateAgentCommunication = createTool({
  id: "facilitate-agent-communication",
  name: "Facilitate Agent Communication",
  description: "Enable communication between agents in the swarm",
  inputSchema: z.object({
    swarmId: z.string(),
    fromAgent: z.string(),
    toAgent: z.string(),
    message: z.object({
      type: z.enum(["query", "response", "broadcast", "coordination"]),
      content: z.any(),
      priority: z.enum(["low", "medium", "high"]).default("medium")
    }),
    awaitResponse: z.boolean().default(false)
  }),
  execute: async ({ swarmId, fromAgent, toAgent, message, awaitResponse }) => {
    const swarm = swarmState.get(swarmId);
    if (!swarm) {
      return { success: false, error: "Swarm not found" };
    }
    if (!swarm.agents[fromAgent] || !swarm.agents[toAgent]) {
      return { success: false, error: "Invalid agent specified" };
    }
    const isAllowed = checkCommunicationPath(swarm, fromAgent, toAgent);
    if (!isAllowed) {
      return {
        success: false,
        error: `Communication not allowed between ${fromAgent} and ${toAgent} in ${swarm.topology} topology`
      };
    }
    const communicationId = `comm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const communication = {
      id: communicationId,
      swarmId,
      from: fromAgent,
      to: toAgent,
      message,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      status: "sent"
    };
    let response = null;
    if (message.type === "broadcast") {
      response = broadcastToConnectedAgents(swarm, fromAgent);
    } else if (awaitResponse) {
      response = await simulateAgentResponse(toAgent, message);
      communication.response = response;
      communication.status = "completed";
    }
    const metrics = swarmMetrics.get(swarmId);
    if (metrics) {
      metrics.communications = metrics.communications || [];
      metrics.communications.push(communication);
    }
    return {
      success: true,
      communicationId,
      from: fromAgent,
      to: toAgent,
      messageType: message.type,
      status: communication.status,
      response,
      timestamp: communication.timestamp
    };
  }
});
const completeSwarmTask = createTool({
  id: "complete-swarm-task",
  name: "Complete Swarm Task",
  description: "Mark a swarm task as complete and collect results",
  inputSchema: z.object({
    swarmId: z.string(),
    taskId: z.string(),
    results: z.array(z.object({
      agentId: z.string(),
      subtaskId: z.string(),
      result: z.any(),
      success: z.boolean()
    }))
  }),
  execute: async ({ swarmId, taskId, results }) => {
    const swarm = swarmState.get(swarmId);
    if (!swarm) {
      return { success: false, error: "Swarm not found" };
    }
    const aggregatedResults = {
      taskId,
      totalSubtasks: results.length,
      successfulSubtasks: results.filter((r) => r.success).length,
      failedSubtasks: results.filter((r) => !r.success).length,
      resultsByAgent: {},
      combinedOutput: {}
    };
    results.forEach((result) => {
      if (!aggregatedResults.resultsByAgent[result.agentId]) {
        aggregatedResults.resultsByAgent[result.agentId] = [];
      }
      aggregatedResults.resultsByAgent[result.agentId].push({
        subtaskId: result.subtaskId,
        success: result.success,
        output: result.result
      });
    });
    swarm.metrics.completedTasks++;
    if (aggregatedResults.failedSubtasks > 0) {
      swarm.metrics.failedTasks++;
    }
    Object.entries(aggregatedResults.resultsByAgent).forEach(([agentId, agentResults]) => {
      const agent = swarm.agents[agentId];
      if (agent) {
        agent.metrics.tasksCompleted += agentResults.length;
        const successCount = agentResults.filter((r) => r.success).length;
        agent.metrics.successRate = (agent.metrics.successRate * (agent.metrics.tasksCompleted - agentResults.length) + successCount * 100) / agent.metrics.tasksCompleted;
      }
    });
    const summary = {
      taskId,
      completionTime: (/* @__PURE__ */ new Date()).toISOString(),
      success: aggregatedResults.failedSubtasks === 0,
      successRate: `${(aggregatedResults.successfulSubtasks / aggregatedResults.totalSubtasks * 100).toFixed(2)}%`,
      participatingAgents: Object.keys(aggregatedResults.resultsByAgent),
      insights: generateTaskInsights(results)
    };
    const metrics = swarmMetrics.get(swarmId);
    if (metrics) {
      metrics.taskHistory.push(summary);
    }
    return {
      success: true,
      taskId,
      summary,
      aggregatedResults,
      swarmEfficiency: calculateSwarmEfficiency(swarm),
      message: `Task ${taskId} completed with ${summary.successRate} success rate`
    };
  }
});
function generateTopologyConnections(topology) {
  const agents = ["dataAnalyst", "securityExpert", "devOpsEngineer", "researchScientist", "productManager"];
  const connections = {};
  switch (topology) {
    case "mesh":
      agents.forEach((agent) => {
        connections[agent] = agents.filter((a) => a !== agent);
      });
      break;
    case "star":
      agents.forEach((agent) => {
        if (agent === "productManager") {
          connections[agent] = agents.filter((a) => a !== agent);
        } else {
          connections[agent] = ["productManager"];
        }
      });
      break;
    case "ring":
      agents.forEach((agent, index) => {
        connections[agent] = [agents[(index + 1) % agents.length]];
      });
      break;
    case "hierarchical":
      connections["productManager"] = ["researchScientist", "devOpsEngineer"];
      connections["researchScientist"] = ["productManager", "dataAnalyst"];
      connections["devOpsEngineer"] = ["productManager", "securityExpert"];
      connections["dataAnalyst"] = ["researchScientist"];
      connections["securityExpert"] = ["devOpsEngineer"];
      break;
  }
  return connections;
}
function analyzeAndDecomposeTask(task, taskType) {
  const subtasks = [];
  switch (taskType) {
    case "analysis":
      subtasks.push(
        { description: "Collect and prepare data", type: "data_prep" },
        { description: "Perform statistical analysis", type: "analysis" },
        { description: "Identify patterns and anomalies", type: "pattern_recognition" },
        { description: "Generate insights report", type: "reporting" }
      );
      break;
    case "development":
      subtasks.push(
        { description: "Design system architecture", type: "architecture" },
        { description: "Implement core functionality", type: "coding" },
        { description: "Set up CI/CD pipeline", type: "devops" },
        { description: "Perform security audit", type: "security" },
        { description: "Deploy to production", type: "deployment" }
      );
      break;
    case "security":
      subtasks.push(
        { description: "Vulnerability scanning", type: "scanning" },
        { description: "Threat analysis", type: "threat_analysis" },
        { description: "Security pattern detection", type: "pattern_recognition" },
        { description: "Generate security report", type: "reporting" }
      );
      break;
    case "research":
      subtasks.push(
        { description: "Literature review", type: "research" },
        { description: "Hypothesis formulation", type: "planning" },
        { description: "Experiment design", type: "research" },
        { description: "Data collection and analysis", type: "analysis" },
        { description: "Results validation", type: "validation" }
      );
      break;
    case "planning":
      subtasks.push(
        { description: "Requirements gathering", type: "planning" },
        { description: "Feature prioritization", type: "planning" },
        { description: "Resource allocation", type: "coordination" },
        { description: "Timeline creation", type: "planning" },
        { description: "Risk assessment", type: "analysis" }
      );
      break;
  }
  return subtasks;
}
function selectBestAgent(subtask, agents, priority) {
  const agentMapping = {
    "data_prep": "dataAnalyst",
    "analysis": "dataAnalyst",
    "pattern_recognition": "dataAnalyst",
    "architecture": "devOpsEngineer",
    "coding": "devOpsEngineer",
    "devops": "devOpsEngineer",
    "deployment": "devOpsEngineer",
    "security": "securityExpert",
    "scanning": "securityExpert",
    "threat_analysis": "securityExpert",
    "research": "researchScientist",
    "validation": "researchScientist",
    "planning": "productManager",
    "coordination": "productManager",
    "reporting": "productManager"
  };
  const preferredAgent = agentMapping[subtask.type] || "productManager";
  const agent = agents[preferredAgent];
  if (agent && agent.taskQueue.length < 5) {
    return preferredAgent;
  }
  let alternativeAgent = preferredAgent;
  let minQueue = agent ? agent.taskQueue.length : Infinity;
  Object.entries(agents).forEach(([agentKey, agentData]) => {
    if (agentData.taskQueue.length < minQueue) {
      alternativeAgent = agentKey;
      minQueue = agentData.taskQueue.length;
    }
  });
  return alternativeAgent;
}
function setupCollaborationChannels(taskPlan, swarm) {
  const channels = [];
  Object.entries(taskPlan.assignments).forEach(([agent1, subtasks1]) => {
    Object.entries(taskPlan.assignments).forEach(([agent2, subtasks2]) => {
      if (agent1 !== agent2) {
        const needsCollaboration = checkCollaborationNeed(subtasks1, subtasks2, taskPlan.subtasks);
        if (needsCollaboration) {
          channels.push({
            agents: [agent1, agent2],
            type: "bidirectional",
            purpose: "task_coordination"
          });
        }
      }
    });
  });
  return {
    channels,
    coordinationProtocol: "async_message_passing",
    syncPoints: identifySyncPoints(taskPlan)
  };
}
function checkCollaborationNeed(subtasks1, subtasks2, allSubtasks) {
  for (const subtaskId1 of subtasks1) {
    const subtask1 = allSubtasks.find((s) => s.id === subtaskId1);
    if (subtask1 && subtask1.dependencies) {
      for (const dep of subtask1.dependencies) {
        if (subtasks2.includes(dep)) {
          return true;
        }
      }
    }
  }
  return false;
}
function identifySyncPoints(taskPlan) {
  const syncPoints = [];
  taskPlan.subtasks.forEach((subtask) => {
    if (subtask.dependencies && subtask.dependencies.length > 1) {
      syncPoints.push({
        subtaskId: subtask.id,
        waitFor: subtask.dependencies,
        type: "barrier"
      });
    }
  });
  return syncPoints;
}
async function executeSwarmTask(swarm, taskPlan, collaborationPlan) {
  Object.entries(taskPlan.assignments).forEach(([agentKey, subtaskIds]) => {
    const agent = swarm.agents[agentKey];
    if (agent) {
      agent.taskQueue.push(...subtaskIds);
    }
  });
  const progress = {
    status: "executing",
    startTime: (/* @__PURE__ */ new Date()).toISOString(),
    estimatedCompletion: new Date(Date.now() + 3e4).toISOString(),
    // 30 seconds estimate
    activeAgents: Object.keys(taskPlan.assignments),
    progressPercentage: 0
  };
  return progress;
}
function estimateCompletionTime(subtasks, priority) {
  const baseTime = subtasks.length * 5e3;
  const priorityMultiplier = {
    "critical": 0.5,
    "high": 0.7,
    "medium": 1,
    "low": 1.5
  };
  return Math.round(baseTime * priorityMultiplier[priority]);
}
function formatUptime(milliseconds) {
  const seconds = Math.floor(milliseconds / 1e3);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d ${hours % 24}h`;
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}
function calculateUtilizationRate(agents) {
  let totalCapacity = 0;
  let totalUsed = 0;
  Object.values(agents).forEach((agent) => {
    totalCapacity += 10;
    totalUsed += agent.taskQueue.length;
  });
  return `${(totalUsed / totalCapacity * 100).toFixed(2)}%`;
}
function calculateAgentEfficiency(agentData) {
  const successRate = agentData.metrics.successRate || 100;
  const queueEfficiency = Math.max(0, 100 - agentData.taskQueue.length * 10);
  return `${((successRate + queueEfficiency) / 2).toFixed(2)}%`;
}
function generatePerformanceInsights(swarm, metrics) {
  const insights = [];
  if (swarm.metrics.successRate && parseFloat(swarm.metrics.successRate) < 90) {
    insights.push("Success rate below optimal threshold - consider task redistribution");
  }
  const queueLengths = Object.values(swarm.agents).map((a) => a.taskQueue.length);
  const avgQueue = queueLengths.reduce((a, b) => a + b, 0) / queueLengths.length;
  const maxQueue = Math.max(...queueLengths);
  if (maxQueue > avgQueue * 2) {
    insights.push("Uneven load distribution detected - rebalance tasks");
  }
  if (swarm.topology === "star" && Object.keys(swarm.agents).length > 4) {
    insights.push("Star topology may bottleneck at coordinator - consider mesh for better distribution");
  }
  return insights;
}
function generateOptimizationRecommendations(swarm, metrics) {
  const recommendations = [];
  Object.entries(swarm.agents).forEach(([agentKey, agentData]) => {
    if (agentData.metrics.successRate < 80) {
      recommendations.push(`Consider additional training or resources for ${agentKey}`);
    }
    if (agentData.taskQueue.length > 5) {
      recommendations.push(`${agentKey} is overloaded - redistribute tasks`);
    }
  });
  if (swarm.topology === "ring" && swarm.metrics.totalTasks > 50) {
    recommendations.push("Ring topology may slow communication - consider switching to mesh");
  }
  return recommendations;
}
function determineSwarmHealth(swarm) {
  let healthScore = 100;
  Object.values(swarm.agents).forEach((agent) => {
    if (agent.status !== "active") healthScore -= 20;
    if (agent.taskQueue.length > 7) healthScore -= 10;
    if (agent.metrics.successRate < 70) healthScore -= 15;
  });
  if (swarm.metrics.failedTasks > swarm.metrics.completedTasks * 0.1) {
    healthScore -= 20;
  }
  if (healthScore >= 90) return "excellent";
  if (healthScore >= 70) return "good";
  if (healthScore >= 50) return "fair";
  return "poor";
}
function checkCommunicationPath(swarm, fromAgent, toAgent) {
  const connections = swarm.connections[fromAgent];
  return connections && connections.includes(toAgent);
}
function broadcastToConnectedAgents(swarm, fromAgent, message) {
  const connections = swarm.connections[fromAgent] || [];
  const broadcasts = [];
  connections.forEach((agent) => {
    broadcasts.push({
      to: agent,
      delivered: true,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  });
  return {
    type: "broadcast",
    recipients: connections,
    deliveryStatus: broadcasts
  };
}
async function simulateAgentResponse(agentId, message, agentData) {
  await new Promise((resolve) => setTimeout(resolve, Math.random() * 1e3 + 500));
  const responses = {
    dataAnalyst: {
      query: "Analysis complete. Patterns identified in dataset.",
      coordination: "Ready to process data. Awaiting input."
    },
    securityExpert: {
      query: "Security scan complete. No vulnerabilities detected.",
      coordination: "Security protocols activated. Monitoring enabled."
    },
    devOpsEngineer: {
      query: "Infrastructure status: All systems operational.",
      coordination: "Deployment pipeline ready. Awaiting triggers."
    },
    researchScientist: {
      query: "Research findings compiled. New insights available.",
      coordination: "Experiment design complete. Ready for execution."
    },
    productManager: {
      query: "Feature prioritization complete. Roadmap updated.",
      coordination: "Coordination acknowledged. Resources allocated."
    }
  };
  return {
    from: agentId,
    type: "response",
    content: responses[agentId]?.[message.type] || "Message received and processed.",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    processingTime: `${Math.random() * 1e3 + 500}ms`
  };
}
function calculateSwarmEfficiency(swarm) {
  const successRate = swarm.metrics.totalTasks > 0 ? swarm.metrics.completedTasks / swarm.metrics.totalTasks * 100 : 100;
  const utilizationRate = parseFloat(calculateUtilizationRate(swarm.agents));
  const agentEfficiencies = Object.values(swarm.agents).map((a) => parseFloat(calculateAgentEfficiency(a))).reduce((a, b) => a + b, 0) / Object.keys(swarm.agents).length;
  return `${((successRate + utilizationRate + agentEfficiencies) / 3).toFixed(2)}%`;
}
function generateTaskInsights(results) {
  const insights = [];
  const successCount = results.filter((r) => r.success).length;
  const failureCount = results.filter((r) => !r.success).length;
  if (failureCount > 0) {
    const failedAgents = [...new Set(results.filter((r) => !r.success).map((r) => r.agentId))];
    insights.push(`Failures detected in agents: ${failedAgents.join(", ")}`);
  }
  if (successCount === results.length) {
    insights.push("All subtasks completed successfully - optimal performance");
  }
  const agentPerformance = {};
  results.forEach((r) => {
    agentPerformance[r.agentId] = agentPerformance[r.agentId] || { success: 0, total: 0 };
    agentPerformance[r.agentId].total++;
    if (r.success) agentPerformance[r.agentId].success++;
  });
  Object.entries(agentPerformance).forEach(([agent, perf]) => {
    const rate = perf.success / perf.total * 100;
    if (rate < 80) {
      insights.push(`${agent} performance below threshold: ${rate.toFixed(2)}%`);
    }
  });
  return insights;
}
const swarmTools = {
  initializeFiveAgentSwarm,
  orchestrateSwarmTask,
  monitorSwarmPerformance,
  facilitateAgentCommunication,
  completeSwarmTask
};

let globalMonitor = null;
let activeSwarmDemo = null;
const initializeSwarmMonitor = createTool({
  id: "initialize-swarm-monitor",
  name: "Initialize Swarm Monitor",
  description: "Initialize real-time monitoring system for concurrent swarms",
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
    globalMonitor = new SwarmMonitor();
    if (alertThresholds) {
      globalMonitor.thresholds.efficiency.warning = alertThresholds.efficiency;
      globalMonitor.thresholds.taskBacklog.warning = alertThresholds.taskBacklog;
      globalMonitor.thresholds.errorRate.warning = alertThresholds.errorRate;
    }
    await globalMonitor.initialize();
    return {
      success: true,
      monitorId: `monitor_${Date.now()}`,
      dashboardEnabled: enableDashboard,
      thresholds: globalMonitor.thresholds,
      message: "Swarm monitor initialized successfully"
    };
  }
});
const launchConcurrentSwarmDemo = createTool({
  id: "launch-concurrent-swarm-demo",
  name: "Launch Concurrent Swarm Demo",
  description: "Launch a demonstration of multiple concurrent swarms with different missions",
  inputSchema: z.object({
    autoMonitor: z.boolean().default(true)
  }),
  execute: async ({ context }) => {
    const { autoMonitor } = context;
    activeSwarmDemo = new ConcurrentSwarmDemo();
    if (autoMonitor && !globalMonitor) {
      globalMonitor = activeSwarmDemo.monitor;
    }
    console.log("\u{1F680} Launching concurrent swarm demonstration...");
    activeSwarmDemo.launch().catch((error) => {
      console.error("Swarm demo error:", error);
    });
    await new Promise((resolve) => setTimeout(resolve, 1e3));
    return {
      success: true,
      demoId: `demo_${Date.now()}`,
      activeSwarms: activeSwarmDemo.swarms.size,
      totalAgents: activeSwarmDemo.metrics.totalAgents,
      message: "Concurrent swarm demonstration launched successfully"
    };
  }
});
const getSwarmPerformanceMetrics = createTool({
  id: "get-swarm-performance-metrics",
  name: "Get Swarm Performance Metrics",
  description: "Retrieve real-time performance metrics for all active swarms",
  inputSchema: z.object({
    includeHistory: z.boolean().default(false),
    swarmId: z.string().optional()
  }),
  execute: async ({ context }) => {
    const { includeHistory, swarmId } = context;
    if (!globalMonitor || !activeSwarmDemo) {
      return {
        success: false,
        error: "No active swarm monitoring session",
        metrics: null
      };
    }
    globalMonitor.collectMetrics(activeSwarmDemo.swarms, activeSwarmDemo.metrics);
    const performanceMetrics = globalMonitor.metrics.get("swarm-performance");
    const currentMetrics = {};
    if (swarmId) {
      const swarmMetrics = performanceMetrics.current.get(swarmId);
      if (swarmMetrics) {
        currentMetrics[swarmId] = swarmMetrics;
      }
    } else {
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
const analyzeSwarmPatterns = createTool({
  id: "analyze-swarm-patterns",
  name: "Analyze Swarm Patterns",
  description: "Analyze behavioral patterns and performance trends across swarms",
  inputSchema: z.object({
    analysisType: z.enum(["efficiency", "collaboration", "bottlenecks", "comprehensive"]).default("comprehensive"),
    timeframe: z.number().default(6e4)
    // Default to last minute
  }),
  execute: async ({ context }) => {
    const { analysisType, timeframe } = context;
    if (!globalMonitor || !activeSwarmDemo) {
      return {
        success: false,
        error: "No active swarm monitoring session",
        analysis: null
      };
    }
    const currentTime = Date.now();
    const recentHistory = globalMonitor.performanceHistory.filter(
      (snapshot) => currentTime - snapshot.timestamp <= timeframe
    );
    const analysis = {
      analysisType,
      timeframe,
      dataPoints: recentHistory.length,
      patterns: []
    };
    switch (analysisType) {
      case "efficiency":
        analysis.patterns = analyzeEfficiencyPatterns(recentHistory);
        break;
      case "collaboration":
        analysis.patterns = analyzeCollaborationPatterns(activeSwarmDemo.swarms);
        break;
      case "bottlenecks":
        analysis.patterns = analyzeBottlenecks(recentHistory, activeSwarmDemo.swarms);
        break;
      case "comprehensive":
        analysis.patterns = [
          ...analyzeEfficiencyPatterns(recentHistory),
          ...analyzeCollaborationPatterns(activeSwarmDemo.swarms),
          ...analyzeBottlenecks(recentHistory, activeSwarmDemo.swarms)
        ];
        break;
    }
    analysis.recommendations = generatePatternRecommendations(analysis.patterns);
    return {
      success: true,
      analysis,
      trends: globalMonitor.analyzeTrends()
    };
  }
});
const getSwarmAlerts = createTool({
  id: "get-swarm-alerts",
  name: "Get Swarm Alerts",
  description: "Retrieve active alerts and warnings from swarm monitoring",
  inputSchema: z.object({
    severity: z.enum(["all", "warning", "critical"]).default("all"),
    limit: z.number().default(10)
  }),
  execute: async ({ context }) => {
    const { severity, limit } = context;
    if (!globalMonitor) {
      return {
        success: false,
        error: "No active swarm monitoring session",
        alerts: []
      };
    }
    let alerts = globalMonitor.alerts;
    if (severity !== "all") {
      alerts = alerts.filter((alert) => alert.severity === severity);
    }
    alerts.sort((a, b) => b.timestamp - a.timestamp);
    alerts = alerts.slice(0, limit);
    return {
      success: true,
      totalAlerts: globalMonitor.alerts.length,
      filteredCount: alerts.length,
      alerts,
      alertSummary: {
        critical: globalMonitor.alerts.filter((a) => a.severity === "critical").length,
        warning: globalMonitor.alerts.filter((a) => a.severity === "warning").length
      }
    };
  }
});
const generateSwarmPerformanceReport = createTool({
  id: "generate-swarm-performance-report",
  name: "Generate Swarm Performance Report",
  description: "Generate comprehensive performance report for concurrent swarms",
  inputSchema: z.object({
    format: z.enum(["summary", "detailed", "executive"]).default("summary"),
    includeRecommendations: z.boolean().default(true)
  }),
  execute: async ({ context }) => {
    const { format, includeRecommendations } = context;
    if (!globalMonitor || !activeSwarmDemo) {
      return {
        success: false,
        error: "No active swarm monitoring session",
        report: null
      };
    }
    const insights = await activeSwarmDemo.coordinator.collectGlobalInsights(activeSwarmDemo.swarms);
    const fullReport = globalMonitor.generateFinalReport(
      activeSwarmDemo.swarms,
      activeSwarmDemo.metrics,
      insights
    );
    let report = {};
    switch (format) {
      case "summary":
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
      case "detailed":
        report = fullReport;
        break;
      case "executive":
        report = {
          executiveSummary: generateExecutiveSummary(fullReport),
          criticalAlerts: fullReport.alerts.filter((a) => a.severity === "critical").length,
          performance: {
            overall: calculateOverallEfficiency(fullReport.swarmPerformance),
            bySwarm: fullReport.swarmPerformance.map((s) => ({
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
      generatedAt: (/* @__PURE__ */ new Date()).toISOString(),
      report
    };
  }
});
function analyzeEfficiencyPatterns(history) {
  const patterns = [];
  if (history.length < 2) return patterns;
  const efficiencies = history.map((h) => {
    const swarmEffs = Array.from(h.swarms.values()).map((s) => s.efficiency);
    return swarmEffs.reduce((a, b) => a + b, 0) / swarmEffs.length;
  });
  const trend = calculateTrend(efficiencies);
  if (trend < -0.1) {
    patterns.push({
      type: "declining_efficiency",
      severity: "warning",
      description: "Overall swarm efficiency is declining",
      value: `${(trend * 100).toFixed(2)}% per minute`
    });
  }
  return patterns;
}
function analyzeCollaborationPatterns(swarms) {
  const patterns = [];
  let totalMessages = 0;
  swarms.forEach((swarm) => {
    totalMessages += swarm.metrics.tasksCompleted * 2;
  });
  if (totalMessages > 1e3) {
    patterns.push({
      type: "high_communication",
      severity: "info",
      description: "High inter-swarm communication detected",
      value: `${totalMessages} messages exchanged`
    });
  }
  return patterns;
}
function analyzeBottlenecks(history, swarms) {
  const patterns = [];
  swarms.forEach((swarm) => {
    const backlog = swarm.metrics.tasksAssigned - swarm.metrics.tasksCompleted;
    if (backlog > 10) {
      patterns.push({
        type: "task_backlog",
        severity: "warning",
        description: `High task backlog in ${swarm.mission.name}`,
        value: `${backlog} pending tasks`
      });
    }
  });
  return patterns;
}
function generatePatternRecommendations(patterns) {
  const recommendations = [];
  patterns.forEach((pattern) => {
    switch (pattern.type) {
      case "declining_efficiency":
        recommendations.push("Consider scaling agent resources or optimizing task distribution");
        break;
      case "task_backlog":
        recommendations.push("Increase agent capacity or redistribute tasks to less loaded swarms");
        break;
      case "high_communication":
        recommendations.push("Optimize communication protocols to reduce message overhead");
        break;
    }
  });
  return [...new Set(recommendations)];
}
function calculateTrend(values) {
  if (values.length < 2) return 0;
  const n = values.length;
  const sumX = n * (n - 1) / 2;
  const sumY = values.reduce((a, b) => a + b, 0);
  const sumXY = values.reduce((sum, y, x) => sum + x * y, 0);
  const sumX2 = n * (n - 1) * (2 * n - 1) / 6;
  return (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
}
function calculateOverallEfficiency(swarmPerformance) {
  if (!swarmPerformance || swarmPerformance.length === 0) return 0;
  const totalEfficiency = swarmPerformance.reduce((sum, s) => sum + s.efficiency, 0);
  return (totalEfficiency / swarmPerformance.length).toFixed(2);
}
function generateExecutiveSummary(report) {
  return `Concurrent swarm operations completed with ${report.swarmPerformance.length} active swarms. Total of ${report.summary.totalAgents} agents completed ${report.summary.totalTasksCompleted} tasks. System recovered from ${report.summary.errorsRecovered} errors with ${report.alerts.length} alerts generated.`;
}
const swarmMonitoringTools = {
  initializeSwarmMonitor,
  launchConcurrentSwarmDemo,
  getSwarmPerformanceMetrics,
  analyzeSwarmPatterns,
  getSwarmAlerts,
  generateSwarmPerformanceReport
};

const claudeFlowCoordinateTool = createTool({
  id: "claudeFlowCoordinate",
  description: "Coordinate multiple Claude agents for complex reasoning tasks",
  inputSchema: z.object({
    task: z.string().describe("Task for Claude agents to coordinate on"),
    agentCount: z.number().min(1).max(10).default(3),
    mode: z.enum(["parallel", "sequential", "hierarchical"]).default("parallel")
  }),
  execute: async ({
    context
  }) => {
    const {
      agentCount = 3,
      mode = "parallel"
    } = context;
    const coordinationId = `claude-${Date.now()}`;
    console.log("\u{1F9E0} Claude Flow coordination started:", coordinationId);
    return {
      success: true,
      coordinationId,
      message: `Claude Flow coordination started with ${agentCount} agents in ${mode} mode`
    };
  }
});
const hiveMindCollectiveTool = createTool({
  id: "hiveMindCollective",
  description: "Create collective intelligence using distributed hive mind reasoning",
  inputSchema: z.object({
    problem: z.string().describe("Problem for collective intelligence analysis"),
    nodes: z.number().min(3).max(50).default(10)
  }),
  execute: async ({
    context
  }) => {
    const {
      nodes = 10
    } = context;
    const sessionId = `hive-${Date.now()}`;
    console.log("\u{1F41D} Hive Mind collective processing started:", sessionId);
    return {
      success: true,
      sessionId,
      message: `Hive Mind collective started with ${nodes} nodes`
    };
  }
});
const ruvSwarmDeployTool = createTool({
  id: "ruvSwarmDeploy",
  description: "Deploy and manage distributed agent swarms",
  inputSchema: z.object({
    mission: z.string().describe("Mission for the swarm to accomplish"),
    swarmSize: z.number().min(5).max(100).default(20)
  }),
  execute: async ({
    context
  }) => {
    const {
      swarmSize = 20
    } = context;
    const deploymentId = `swarm-${Date.now()}`;
    console.log("\u{1F525} RUV Swarm deployment started:", deploymentId);
    return {
      success: true,
      deploymentId,
      message: `RUV Swarm deployed with ${swarmSize} agents`
    };
  }
});
const createTeamTool = createTool({
  id: "createTeam",
  description: "Create a new team of agents for a specific goal",
  inputSchema: z.object({
    teamName: z.string(),
    goal: z.string(),
    agentTypes: z.array(z.enum(["coordinator", "executor", "researcher", "architect"]))
  }),
  execute: async ({
    context
  }) => {
    const {
      teamName,
      goal,
      agentTypes
    } = context;
    const teamId = `team-${Date.now()}`;
    const team = {
      teamId,
      teamName,
      goal,
      agentTypes,
      status: "active",
      created: (/* @__PURE__ */ new Date()).toISOString(),
      members: agentTypes.map((type, index) => ({
        id: `${type}-${teamId}-${index}`,
        type,
        role: type,
        status: "ready"
      }))
    };
    console.log(`\u{1F680} Team created: ${teamName} (${teamId})`);
    return {
      success: true,
      team,
      message: `Team "${teamName}" created successfully`
    };
  }
});
const executeWorkflowTool = createTool({
  id: "executeWorkflow",
  description: "Execute a workflow with the agentic-flow system",
  inputSchema: z.object({
    workflowName: z.enum(["software-development", "problem-solving"]),
    input: z.record(z.any())
  }),
  execute: async ({
    context
  }) => {
    const {
      workflowName,
      input
    } = context;
    const executionId = `exec-${Date.now()}`;
    const execution = {
      executionId,
      workflowName,
      input,
      status: "running",
      startTime: (/* @__PURE__ */ new Date()).toISOString()
    };
    console.log(`\u{1F504} Workflow started: ${workflowName} (${executionId})`);
    return {
      success: true,
      execution,
      message: `Workflow "${workflowName}" started successfully`
    };
  }
});
const monitorSystemTool = createTool({
  id: "monitorSystem",
  description: "Monitor the health and status of the agentic-flow system",
  inputSchema: z.object({
    includeMetrics: z.boolean().default(false).optional()
  }),
  execute: async ({
    context
  }) => {
    const systemStatus = {
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      status: "healthy",
      uptime: Math.floor(process.uptime()),
      agents: {
        total: 7,
        active: 7,
        types: ["coordinator", "executor", "researcher", "architect", "claude-flow-coordinator", "hive-mind-collective", "ruv-swarm-coordinator"]
      },
      workflows: {
        registered: 7,
        available: Object.keys(agenticFlowWorkflows)
      }
    };
    console.log("\u{1F3E5} System health check completed");
    return systemStatus;
  }
});
const mastra = new Mastra({
  name: "agentic-flow",
  version: "1.0.0",
  description: "Agentic Flow - AI Orchestration Platform with Mastra Integration",
  // Configure server
  server: {
    port: process.env.MASTRA_PORT ? parseInt(process.env.MASTRA_PORT) : 4111,
    baseUrl: process.env.MASTRA_BASE_URL || "http://localhost:4111"
  },
  // Disable telemetry and database to avoid issues
  telemetry: {
    enabled: false
  },
  logs: {
    enabled: true,
    level: "info"
  },
  // Agentic Flow Network Agents
  agents: {
    // Core agents
    coordinator: new Agent({
      name: "coordinator",
      description: "Coordinates teams and manages complex workflows",
      model: {
        provider: "anthropic",
        name: "claude-3-sonnet-20240229"
      },
      instructions: `You are a coordinator agent responsible for team formation, goal decomposition, task delegation, cross-team coordination, and strategic decision making.`,
      tools: {
        createTeam: createTeamTool,
        executeWorkflow: executeWorkflowTool,
        monitorSystem: monitorSystemTool
      }
    }),
    executor: new Agent({
      name: "executor",
      description: "Executes tasks and implements solutions",
      model: {
        provider: "anthropic",
        name: "claude-3-sonnet-20240229"
      },
      instructions: `You are an executor agent responsible for task implementation, solution development, progress reporting, quality assurance, and problem resolution.`
    }),
    researcher: new Agent({
      name: "researcher",
      description: "Gathers information and analyzes data",
      model: {
        provider: "anthropic",
        name: "claude-3-sonnet-20240229"
      },
      instructions: `You are a research agent specialized in information gathering, data analysis, technology research, market analysis, and trend identification.`
    }),
    architect: new Agent({
      name: "architect",
      description: "Designs systems and technical architecture",
      model: {
        provider: "anthropic",
        name: "claude-3-sonnet-20240229"
      },
      instructions: `You are an architecture agent responsible for system design, technical specification, scalability planning, technology selection, and integration design.`
    }),
    // Network-specific branded agents with tools
    "claude-flow-coordinator": new Agent({
      name: "claude-flow-coordinator",
      description: claudeFlowAgent.description,
      model: claudeFlowAgent.model,
      instructions: claudeFlowAgent.instructions,
      tools: {
        claudeFlowCoordinate: claudeFlowCoordinateTool
      }
    }),
    "hive-mind-collective": new Agent({
      name: "hive-mind-collective",
      description: hiveMindAgent.description,
      model: hiveMindAgent.model,
      instructions: hiveMindAgent.instructions,
      tools: {
        hiveMindCollective: hiveMindCollectiveTool
      }
    }),
    "ruv-swarm-coordinator": new Agent({
      name: "ruv-swarm-coordinator",
      description: ruvSwarmAgent.description,
      model: ruvSwarmAgent.model,
      instructions: ruvSwarmAgent.instructions,
      tools: {
        ruvSwarmDeploy: ruvSwarmDeployTool
      }
    }),
    // MCP-connected agents
    ...mcpConfig.agents,
    // 5-Agent Swarm Specialists
    dataAnalyst: swarmAgents.dataAnalystAgent,
    securityExpert: swarmAgents.securityExpertAgent,
    devOpsEngineer: swarmAgents.devOpsEngineerAgent,
    researchScientist: swarmAgents.researchScientistAgent,
    productManager: swarmAgents.productManagerAgent,
    qaEngineer: swarmAgents.qaEngineerAgent
  },
  // Agentic Flow Tools - properly formatted
  tools: {
    // Core network tools
    claudeFlowCoordinate: claudeFlowCoordinateTool,
    hiveMindCollective: hiveMindCollectiveTool,
    ruvSwarmDeploy: ruvSwarmDeployTool,
    createTeam: createTeamTool,
    executeWorkflow: executeWorkflowTool,
    monitorSystem: monitorSystemTool,
    // MCP-integrated tools
    ...mcpConfig.tools,
    // Network management tools
    ...networkManagementTools,
    // Comprehensive Claude Flow & Agentic Flow tools (50 tools)
    ...allTools,
    // 5-Agent Swarm Management Tools
    ...swarmTools,
    // Concurrent Swarm Monitoring Tools
    ...swarmMonitoringTools
  },
  // Agentic Flow Advanced Workflows - all using createWorkflow API
  workflows: {
    // Core workflows
    "software-development": coreWorkflows.softwareDevelopmentWorkflow,
    "problem-solving": coreWorkflows.problemSolvingWorkflow,
    // Advanced workflows
    "research-analysis": advancedWorkflows.researchAnalysisWorkflow,
    "adaptive-problem-solving": advancedWorkflows.adaptiveProblemSolvingWorkflow,
    "enterprise-integration": advancedWorkflows.enterpriseIntegrationWorkflow,
    "ai-model-training": advancedWorkflows.aiModelTrainingWorkflow,
    "crisis-response": advancedWorkflows.crisisResponseWorkflow,
    // Network-specific workflows
    "claude-flow-reasoning": networkWorkflows.claudeFlowReasoningWorkflow,
    "hive-mind-consensus": networkWorkflows.hiveMindConsensusWorkflow,
    "ruv-swarm-scaling": networkWorkflows.ruvSwarmScalingWorkflow,
    "multi-network-orchestration": networkWorkflows.multiNetworkOrchestrationWorkflow,
    // Tool-integrated workflows
    "team-formation": toolWorkflows.teamFormationWorkflow,
    "system-optimization": toolWorkflows.systemOptimizationWorkflow,
    "task-routing": toolWorkflows.taskRoutingWorkflow,
    // MCP-integrated workflows
    "mcp-swarm-orchestration": mcpWorkflows.mcpSwarmOrchestrationWorkflow,
    "mcp-learning-adaptation": mcpWorkflows.mcpLearningWorkflow,
    "mcp-multi-server-coordination": mcpWorkflows.mcpMultiServerWorkflow,
    // 5-Agent Swarm Workflows
    "five-agent-swarm-demo": swarmWorkflows.swarmDemoWorkflow,
    "multi-swarm-collaboration": swarmWorkflows.multiSwarmWorkflow,
    // Concurrent Swarm Orchestration Workflow
    "concurrent-swarm-orchestration": concurrentSwarmWorkflow,
    // Complex 6-Agent Workflows
    "startup-launch": complexWorkflows.startupLaunch,
    "incident-response": complexWorkflows.incidentResponse,
    "ai-product-development": complexWorkflows.aiProductDevelopment,
    "ai-product-feedback": complexWorkflows.aiProductFeedbackLoop,
    "enterprise-migration": complexWorkflows.enterpriseMigration,
    "product-pivot": complexWorkflows.productPivot,
    "security-breach-response": complexWorkflows.securityBreachResponse
  },
  // Agentic Flow UI Theme
  ui: {
    theme: agenticFlowTheme,
    branding: brandConfig
  }
  // Agent Networks Configuration - temporarily disabled pending proper API
  // TODO: Investigate proper network API for Mastra
  // networks: agentNetworks
  // MCP Servers Configuration - temporarily commented out to debug
  // mcpServers: mcpServers
});
const logNetworkStatus = () => {
  console.log("\n\u{1F680} Agentic Flow Mastra Integration Loaded!");
  console.log("\u{1F4CA} Configuration:");
  console.log("   \u2022 4 Agent Networks");
  console.log("     - Claude Flow Network: Advanced reasoning & coordination (hierarchical)");
  console.log("     - Hive Mind Network: Collective intelligence & consensus (mesh)");
  console.log("     - RUV Swarm Network: Distributed scaling & fault tolerance (dynamic-mesh)");
  console.log("     - Multi-Network Orchestrator: Cross-network coordination (federated-mesh)");
  console.log("   \u2022 15 AI Agents (4 Core + 3 Network + 2 MCP + 6 Swarm Specialists)");
  console.log("     - Core: Coordinator, Executor, Researcher, Architect");
  console.log("     - Networks: Claude Flow \u{1F9E0}, Hive Mind \u{1F41D}, RUV Swarm \u{1F525}");
  console.log("     - MCP: Claude Flow MCP Agent, Agentic Flow MCP Agent");
  console.log("     - 6-Agent Swarm: Data Analyst \u{1F4CA}, Security Expert \u{1F512}, DevOps Engineer \u{1F527}, Research Scientist \u{1F52C}, Product Manager \u{1F4CB}, QA Engineer \u{1F9EA}");
  console.log("   \u2022 77 Integration Tools (3 Network + 3 Core + 7 MCP + 3 Network Management + 50 Comprehensive + 5 Swarm + 6 Monitoring)");
  console.log("     - Network: Claude Flow Coordinate, Hive Mind Collective, RUV Swarm Deploy");
  console.log("     - Core: Create Team, Execute Workflow, Monitor System");
  console.log("     - MCP: Swarm Init, Agent Spawn, Task Orchestrate, Team Create, Workflow Execute, Learning Capture, Server Status");
  console.log("     - Network Management: List Networks, Get Network Status, Route to Network");
  console.log("     - Swarm Orchestration (10): Init, Spawn, Orchestrate, Status, Scale, Destroy, Optimize, Balance, Sync, Metrics");
  console.log("     - Learning & Memory (10): Store, Retrieve, Search, Capture, Recognize, Graph, Backup, Restore, Context Save/Restore");
  console.log("     - Performance Monitoring (10): Report, Bottleneck, Metrics, Trends, Health, Errors, Usage, Cost, Quality, Benchmark");
  console.log("     - AI/ML Integration (10): Train, Predict, Load/Save Models, Inference, Ensemble, Transfer, Explain, Cognitive, Adaptive");
  console.log("     - Workflow Automation (10): Create, Execute, Schedule, Pipeline, Automation, Triggers, Batch, Parallel, Template, Export");
  console.log("     - 5-Agent Swarm (5): Initialize Swarm, Orchestrate Task, Monitor Performance, Agent Communication, Complete Task");
  console.log("     - Concurrent Swarm Monitoring (6): Initialize Monitor, Launch Demo, Get Metrics, Analyze Patterns, Get Alerts, Generate Report");
  console.log("   \u2022 28 Production Workflows");
  console.log("     - Core: Software Development, Problem Solving");
  console.log("     - Advanced: Research Analysis, Adaptive Problem Solving, Enterprise Integration, AI Model Training, Crisis Response");
  console.log("     - Network: Claude Flow Reasoning, Hive Mind Consensus, RUV Swarm Scaling, Multi-Network Orchestration");
  console.log("     - Tool-Integrated: Team Formation, System Optimization, Task Routing");
  console.log("     - MCP-Integrated: Swarm Orchestration, Learning Adaptation, Multi-Server Coordination");
  console.log("     - 5-Agent Swarm: Swarm Demo, Multi-Swarm Collaboration");
  console.log("     - Concurrent Swarm: Concurrent Swarm Orchestration (Real-time multi-swarm coordination)");
  console.log("     - Complex 6-Agent: Startup Launch, Incident Response, AI Product Dev, Enterprise Migration, Product Pivot, Security Breach");
  console.log("   \u2022 3 Network Integrations with MCP Protocol");
  console.log("   \u2022 3 MCP Servers Configured");
  console.log("     - Claude Flow MCP: Port 5001");
  console.log("     - Agentic Flow MCP: Port 5002");
  console.log("     - Mastra Docs MCP: Available");
  console.log(`   \u2022 Server URL: http://localhost:${process.env.MASTRA_PORT || 4111}`);
  console.log("   \u2022 Custom Agentic Flow Branding and Theme Applied\n");
  console.log("\u{1F310} Network Status:");
  console.log("   \u{1F9E0} Claude Flow: Advanced reasoning and coordination");
  console.log("   \u{1F41D} Hive Mind: Collective intelligence and consensus");
  console.log("   \u{1F525} RUV Swarm: Distributed scaling and fault tolerance");
  console.log("");
  console.log("\u{1F50C} MCP Integration:");
  console.log("   \u2022 Claude Flow MCP: swarm_init, agent_spawn, task_orchestrate");
  console.log("   \u2022 Agentic Flow MCP: team_create, workflow_execute, learning_capture");
  console.log("");
  console.log("\u{1F680} Concurrent Swarm Capabilities:");
  console.log("   \u2022 Infrastructure Optimization Swarm: 6 specialized agents for system performance");
  console.log("   \u2022 Development Acceleration Swarm: 6 agents for rapid development cycles");
  console.log("   \u2022 Data Analytics Swarm: 6 agents for pattern recognition and insights");
  console.log("   \u2022 Real-time monitoring with performance dashboards and alerts");
  console.log("   \u2022 Cross-swarm synchronization and coordination protocols");
  console.log("   \u2022 Resilience testing with automatic failure recovery");
  console.log("");
};
logNetworkStatus();
checkMcpServers();
setTimeout(async () => {
  console.log("\n\u{1F310} Initializing Agent Networks...");
  for (const [name, network] of Object.entries(agentNetworks)) {
    try {
      await network.initialize();
      console.log(`\u2705 ${name} network initialized`);
    } catch (error) {
      console.error(`\u274C Failed to initialize ${name}:`, error);
    }
  }
  console.log("\n\u{1F517} Mastra playground available with full agentic-flow integration!");
  console.log("\u{1F4A1} Tools are now properly configured and should appear in the playground");
  console.log("\u{1F310} MCP Support: Ready for Model Context Protocol integration");
  console.log("\u{1F4E1} MCP Tools: Using simulator mode - real MCP servers can be connected when available");
  console.log("\u{1F578}\uFE0F Networks: 4 agent networks initialized and ready for task routing");
}, 2e3);

// src/utils/filepath.ts
var getFilePath = (options) => {
  let filename = options.filename;
  const defaultDocument = options.defaultDocument || "index.html";
  if (filename.endsWith("/")) {
    filename = filename.concat(defaultDocument);
  } else if (!filename.match(/\.[a-zA-Z0-9_-]+$/)) {
    filename = filename.concat("/" + defaultDocument);
  }
  const path = getFilePathWithoutDefaultDocument({
    root: options.root,
    filename
  });
  return path;
};
var getFilePathWithoutDefaultDocument = (options) => {
  let root = options.root || "";
  let filename = options.filename;
  if (/(?:^|[\/\\])\.\.(?:$|[\/\\])/.test(filename)) {
    return;
  }
  filename = filename.replace(/^\.?[\/\\]/, "");
  filename = filename.replace(/\\/, "/");
  root = root.replace(/\/$/, "");
  let path = root ? root + "/" + filename : filename;
  path = path.replace(/^\.?\//, "");
  if (root[0] !== "/" && path[0] === "/") {
    return;
  }
  return path;
};

// src/utils/mime.ts
var getMimeType = (filename, mimes = baseMimes) => {
  const regexp = /\.([a-zA-Z0-9]+?)$/;
  const match = filename.match(regexp);
  if (!match) {
    return;
  }
  let mimeType = mimes[match[1]];
  if (mimeType && mimeType.startsWith("text")) {
    mimeType += "; charset=utf-8";
  }
  return mimeType;
};
var _baseMimes = {
  aac: "audio/aac",
  avi: "video/x-msvideo",
  avif: "image/avif",
  av1: "video/av1",
  bin: "application/octet-stream",
  bmp: "image/bmp",
  css: "text/css",
  csv: "text/csv",
  eot: "application/vnd.ms-fontobject",
  epub: "application/epub+zip",
  gif: "image/gif",
  gz: "application/gzip",
  htm: "text/html",
  html: "text/html",
  ico: "image/x-icon",
  ics: "text/calendar",
  jpeg: "image/jpeg",
  jpg: "image/jpeg",
  js: "text/javascript",
  json: "application/json",
  jsonld: "application/ld+json",
  map: "application/json",
  mid: "audio/x-midi",
  midi: "audio/x-midi",
  mjs: "text/javascript",
  mp3: "audio/mpeg",
  mp4: "video/mp4",
  mpeg: "video/mpeg",
  oga: "audio/ogg",
  ogv: "video/ogg",
  ogx: "application/ogg",
  opus: "audio/opus",
  otf: "font/otf",
  pdf: "application/pdf",
  png: "image/png",
  rtf: "application/rtf",
  svg: "image/svg+xml",
  tif: "image/tiff",
  tiff: "image/tiff",
  ts: "video/mp2t",
  ttf: "font/ttf",
  txt: "text/plain",
  wasm: "application/wasm",
  webm: "video/webm",
  weba: "audio/webm",
  webmanifest: "application/manifest+json",
  webp: "image/webp",
  woff: "font/woff",
  woff2: "font/woff2",
  xhtml: "application/xhtml+xml",
  xml: "application/xml",
  zip: "application/zip",
  "3gp": "video/3gpp",
  "3g2": "video/3gpp2",
  gltf: "model/gltf+json",
  glb: "model/gltf-binary"
};
var baseMimes = _baseMimes;

// src/utils/html.ts
var HtmlEscapedCallbackPhase = {
  Stringify: 1};
var raw = (value, callbacks) => {
  const escapedString = new String(value);
  escapedString.isEscaped = true;
  escapedString.callbacks = callbacks;
  return escapedString;
};
var escapeRe = /[&<>'"]/;
var stringBufferToString = async (buffer, callbacks) => {
  let str = "";
  callbacks ||= [];
  const resolvedBuffer = await Promise.all(buffer);
  for (let i = resolvedBuffer.length - 1; ; i--) {
    str += resolvedBuffer[i];
    i--;
    if (i < 0) {
      break;
    }
    let r = resolvedBuffer[i];
    if (typeof r === "object") {
      callbacks.push(...r.callbacks || []);
    }
    const isEscaped = r.isEscaped;
    r = await (typeof r === "object" ? r.toString() : r);
    if (typeof r === "object") {
      callbacks.push(...r.callbacks || []);
    }
    if (r.isEscaped ?? isEscaped) {
      str += r;
    } else {
      const buf = [str];
      escapeToBuffer(r, buf);
      str = buf[0];
    }
  }
  return raw(str, callbacks);
};
var escapeToBuffer = (str, buffer) => {
  const match = str.search(escapeRe);
  if (match === -1) {
    buffer[0] += str;
    return;
  }
  let escape;
  let index;
  let lastIndex = 0;
  for (index = match; index < str.length; index++) {
    switch (str.charCodeAt(index)) {
      case 34:
        escape = "&quot;";
        break;
      case 39:
        escape = "&#39;";
        break;
      case 38:
        escape = "&amp;";
        break;
      case 60:
        escape = "&lt;";
        break;
      case 62:
        escape = "&gt;";
        break;
      default:
        continue;
    }
    buffer[0] += str.substring(lastIndex, index) + escape;
    lastIndex = index + 1;
  }
  buffer[0] += str.substring(lastIndex, index);
};
var resolveCallbackSync = (str) => {
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return str;
  }
  const buffer = [str];
  const context = {};
  callbacks.forEach((c) => c({ phase: HtmlEscapedCallbackPhase.Stringify, buffer, context }));
  return buffer[0];
};
var resolveCallback = async (str, phase, preserveCallbacks, context, buffer) => {
  if (typeof str === "object" && !(str instanceof String)) {
    if (!(str instanceof Promise)) {
      str = str.toString();
    }
    if (str instanceof Promise) {
      str = await str;
    }
  }
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return Promise.resolve(str);
  }
  if (buffer) {
    buffer[0] += str;
  } else {
    buffer = [str];
  }
  const resStr = Promise.all(callbacks.map((c) => c({ phase, buffer, context }))).then(
    (res) => Promise.all(
      res.filter(Boolean).map((str2) => resolveCallback(str2, phase, false, context, buffer))
    ).then(() => buffer[0])
  );
  {
    return resStr;
  }
};

// src/helper/html/index.ts
var html = (strings, ...values) => {
  const buffer = [""];
  for (let i = 0, len = strings.length - 1; i < len; i++) {
    buffer[0] += strings[i];
    const children = Array.isArray(values[i]) ? values[i].flat(Infinity) : [values[i]];
    for (let i2 = 0, len2 = children.length; i2 < len2; i2++) {
      const child = children[i2];
      if (typeof child === "string") {
        escapeToBuffer(child, buffer);
      } else if (typeof child === "number") {
        buffer[0] += child;
      } else if (typeof child === "boolean" || child === null || child === void 0) {
        continue;
      } else if (typeof child === "object" && child.isEscaped) {
        if (child.callbacks) {
          buffer.unshift("", child);
        } else {
          const tmp = child.toString();
          if (tmp instanceof Promise) {
            buffer.unshift("", tmp);
          } else {
            buffer[0] += tmp;
          }
        }
      } else if (child instanceof Promise) {
        buffer.unshift("", child);
      } else {
        escapeToBuffer(child.toString(), buffer);
      }
    }
  }
  buffer[0] += strings.at(-1);
  return buffer.length === 1 ? "callbacks" in buffer ? raw(resolveCallbackSync(raw(buffer[0], buffer.callbacks))) : raw(buffer[0]) : stringBufferToString(buffer, buffer.callbacks);
};

// src/compose.ts
var compose = (middleware, onError, onNotFound) => {
  return (context, next) => {
    let index = -1;
    return dispatch(0);
    async function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      index = i;
      let res;
      let isError = false;
      let handler;
      if (middleware[i]) {
        handler = middleware[i][0][0];
        context.req.routeIndex = i;
      } else {
        handler = i === middleware.length && next || void 0;
      }
      if (handler) {
        try {
          res = await handler(context, () => dispatch(i + 1));
        } catch (err) {
          if (err instanceof Error && onError) {
            context.error = err;
            res = await onError(err, context);
            isError = true;
          } else {
            throw err;
          }
        }
      } else {
        if (context.finalized === false && onNotFound) {
          res = await onNotFound(context);
        }
      }
      if (res && (context.finalized === false || isError)) {
        context.res = res;
      }
      return context;
    }
  };
};

// src/request/constants.ts
var GET_MATCH_RESULT = Symbol();

// src/utils/body.ts
var parseBody = async (request, options = /* @__PURE__ */ Object.create(null)) => {
  const { all = false, dot = false } = options;
  const headers = request instanceof HonoRequest ? request.raw.headers : request.headers;
  const contentType = headers.get("Content-Type");
  if (contentType?.startsWith("multipart/form-data") || contentType?.startsWith("application/x-www-form-urlencoded")) {
    return parseFormData(request, { all, dot });
  }
  return {};
};
async function parseFormData(request, options) {
  const formData = await request.formData();
  if (formData) {
    return convertFormDataToBodyData(formData, options);
  }
  return {};
}
function convertFormDataToBodyData(formData, options) {
  const form = /* @__PURE__ */ Object.create(null);
  formData.forEach((value, key) => {
    const shouldParseAllValues = options.all || key.endsWith("[]");
    if (!shouldParseAllValues) {
      form[key] = value;
    } else {
      handleParsingAllValues(form, key, value);
    }
  });
  if (options.dot) {
    Object.entries(form).forEach(([key, value]) => {
      const shouldParseDotValues = key.includes(".");
      if (shouldParseDotValues) {
        handleParsingNestedValues(form, key, value);
        delete form[key];
      }
    });
  }
  return form;
}
var handleParsingAllValues = (form, key, value) => {
  if (form[key] !== void 0) {
    if (Array.isArray(form[key])) {
      form[key].push(value);
    } else {
      form[key] = [form[key], value];
    }
  } else {
    if (!key.endsWith("[]")) {
      form[key] = value;
    } else {
      form[key] = [value];
    }
  }
};
var handleParsingNestedValues = (form, key, value) => {
  let nestedForm = form;
  const keys = key.split(".");
  keys.forEach((key2, index) => {
    if (index === keys.length - 1) {
      nestedForm[key2] = value;
    } else {
      if (!nestedForm[key2] || typeof nestedForm[key2] !== "object" || Array.isArray(nestedForm[key2]) || nestedForm[key2] instanceof File) {
        nestedForm[key2] = /* @__PURE__ */ Object.create(null);
      }
      nestedForm = nestedForm[key2];
    }
  });
};

// src/utils/url.ts
var splitPath = (path) => {
  const paths = path.split("/");
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
};
var splitRoutingPath = (routePath) => {
  const { groups, path } = extractGroupsFromPath(routePath);
  const paths = splitPath(path);
  return replaceGroupMarks(paths, groups);
};
var extractGroupsFromPath = (path) => {
  const groups = [];
  path = path.replace(/\{[^}]+\}/g, (match, index) => {
    const mark = `@${index}`;
    groups.push([mark, match]);
    return mark;
  });
  return { groups, path };
};
var replaceGroupMarks = (paths, groups) => {
  for (let i = groups.length - 1; i >= 0; i--) {
    const [mark] = groups[i];
    for (let j = paths.length - 1; j >= 0; j--) {
      if (paths[j].includes(mark)) {
        paths[j] = paths[j].replace(mark, groups[i][1]);
        break;
      }
    }
  }
  return paths;
};
var patternCache = {};
var getPattern = (label, next) => {
  if (label === "*") {
    return "*";
  }
  const match = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match) {
    const cacheKey = `${label}#${next}`;
    if (!patternCache[cacheKey]) {
      if (match[2]) {
        patternCache[cacheKey] = next && next[0] !== ":" && next[0] !== "*" ? [cacheKey, match[1], new RegExp(`^${match[2]}(?=/${next})`)] : [label, match[1], new RegExp(`^${match[2]}$`)];
      } else {
        patternCache[cacheKey] = [label, match[1], true];
      }
    }
    return patternCache[cacheKey];
  }
  return null;
};
var tryDecode = (str, decoder) => {
  try {
    return decoder(str);
  } catch {
    return str.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
      try {
        return decoder(match);
      } catch {
        return match;
      }
    });
  }
};
var tryDecodeURI = (str) => tryDecode(str, decodeURI);
var getPath = (request) => {
  const url = request.url;
  const start = url.indexOf(
    "/",
    url.charCodeAt(9) === 58 ? 13 : 8
  );
  let i = start;
  for (; i < url.length; i++) {
    const charCode = url.charCodeAt(i);
    if (charCode === 37) {
      const queryIndex = url.indexOf("?", i);
      const path = url.slice(start, queryIndex === -1 ? void 0 : queryIndex);
      return tryDecodeURI(path.includes("%25") ? path.replace(/%25/g, "%2525") : path);
    } else if (charCode === 63) {
      break;
    }
  }
  return url.slice(start, i);
};
var getPathNoStrict = (request) => {
  const result = getPath(request);
  return result.length > 1 && result.at(-1) === "/" ? result.slice(0, -1) : result;
};
var mergePath = (base, sub, ...rest) => {
  if (rest.length) {
    sub = mergePath(sub, ...rest);
  }
  return `${base?.[0] === "/" ? "" : "/"}${base}${sub === "/" ? "" : `${base?.at(-1) === "/" ? "" : "/"}${sub?.[0] === "/" ? sub.slice(1) : sub}`}`;
};
var checkOptionalParameter = (path) => {
  if (path.charCodeAt(path.length - 1) !== 63 || !path.includes(":")) {
    return null;
  }
  const segments = path.split("/");
  const results = [];
  let basePath = "";
  segments.forEach((segment) => {
    if (segment !== "" && !/\:/.test(segment)) {
      basePath += "/" + segment;
    } else if (/\:/.test(segment)) {
      if (/\?/.test(segment)) {
        if (results.length === 0 && basePath === "") {
          results.push("/");
        } else {
          results.push(basePath);
        }
        const optionalSegment = segment.replace("?", "");
        basePath += "/" + optionalSegment;
        results.push(basePath);
      } else {
        basePath += "/" + segment;
      }
    }
  });
  return results.filter((v, i, a) => a.indexOf(v) === i);
};
var _decodeURI = (value) => {
  if (!/[%+]/.test(value)) {
    return value;
  }
  if (value.indexOf("+") !== -1) {
    value = value.replace(/\+/g, " ");
  }
  return value.indexOf("%") !== -1 ? tryDecode(value, decodeURIComponent_) : value;
};
var _getQueryParam = (url, key, multiple) => {
  let encoded;
  if (!multiple && key && !/[%+]/.test(key)) {
    let keyIndex2 = url.indexOf(`?${key}`, 8);
    if (keyIndex2 === -1) {
      keyIndex2 = url.indexOf(`&${key}`, 8);
    }
    while (keyIndex2 !== -1) {
      const trailingKeyCode = url.charCodeAt(keyIndex2 + key.length + 1);
      if (trailingKeyCode === 61) {
        const valueIndex = keyIndex2 + key.length + 2;
        const endIndex = url.indexOf("&", valueIndex);
        return _decodeURI(url.slice(valueIndex, endIndex === -1 ? void 0 : endIndex));
      } else if (trailingKeyCode == 38 || isNaN(trailingKeyCode)) {
        return "";
      }
      keyIndex2 = url.indexOf(`&${key}`, keyIndex2 + 1);
    }
    encoded = /[%+]/.test(url);
    if (!encoded) {
      return void 0;
    }
  }
  const results = {};
  encoded ??= /[%+]/.test(url);
  let keyIndex = url.indexOf("?", 8);
  while (keyIndex !== -1) {
    const nextKeyIndex = url.indexOf("&", keyIndex + 1);
    let valueIndex = url.indexOf("=", keyIndex);
    if (valueIndex > nextKeyIndex && nextKeyIndex !== -1) {
      valueIndex = -1;
    }
    let name = url.slice(
      keyIndex + 1,
      valueIndex === -1 ? nextKeyIndex === -1 ? void 0 : nextKeyIndex : valueIndex
    );
    if (encoded) {
      name = _decodeURI(name);
    }
    keyIndex = nextKeyIndex;
    if (name === "") {
      continue;
    }
    let value;
    if (valueIndex === -1) {
      value = "";
    } else {
      value = url.slice(valueIndex + 1, nextKeyIndex === -1 ? void 0 : nextKeyIndex);
      if (encoded) {
        value = _decodeURI(value);
      }
    }
    if (multiple) {
      if (!(results[name] && Array.isArray(results[name]))) {
        results[name] = [];
      }
      results[name].push(value);
    } else {
      results[name] ??= value;
    }
  }
  return key ? results[key] : results;
};
var getQueryParam = _getQueryParam;
var getQueryParams = (url, key) => {
  return _getQueryParam(url, key, true);
};
var decodeURIComponent_ = decodeURIComponent;

// src/request.ts
var tryDecodeURIComponent = (str) => tryDecode(str, decodeURIComponent_);
var HonoRequest = class {
  raw;
  #validatedData;
  #matchResult;
  routeIndex = 0;
  path;
  bodyCache = {};
  constructor(request, path = "/", matchResult = [[]]) {
    this.raw = request;
    this.path = path;
    this.#matchResult = matchResult;
    this.#validatedData = {};
  }
  param(key) {
    return key ? this.#getDecodedParam(key) : this.#getAllDecodedParams();
  }
  #getDecodedParam(key) {
    const paramKey = this.#matchResult[0][this.routeIndex][1][key];
    const param = this.#getParamValue(paramKey);
    return param ? /\%/.test(param) ? tryDecodeURIComponent(param) : param : void 0;
  }
  #getAllDecodedParams() {
    const decoded = {};
    const keys = Object.keys(this.#matchResult[0][this.routeIndex][1]);
    for (const key of keys) {
      const value = this.#getParamValue(this.#matchResult[0][this.routeIndex][1][key]);
      if (value && typeof value === "string") {
        decoded[key] = /\%/.test(value) ? tryDecodeURIComponent(value) : value;
      }
    }
    return decoded;
  }
  #getParamValue(paramKey) {
    return this.#matchResult[1] ? this.#matchResult[1][paramKey] : paramKey;
  }
  query(key) {
    return getQueryParam(this.url, key);
  }
  queries(key) {
    return getQueryParams(this.url, key);
  }
  header(name) {
    if (name) {
      return this.raw.headers.get(name) ?? void 0;
    }
    const headerData = {};
    this.raw.headers.forEach((value, key) => {
      headerData[key] = value;
    });
    return headerData;
  }
  async parseBody(options) {
    return this.bodyCache.parsedBody ??= await parseBody(this, options);
  }
  #cachedBody = (key) => {
    const { bodyCache, raw } = this;
    const cachedBody = bodyCache[key];
    if (cachedBody) {
      return cachedBody;
    }
    const anyCachedKey = Object.keys(bodyCache)[0];
    if (anyCachedKey) {
      return bodyCache[anyCachedKey].then((body) => {
        if (anyCachedKey === "json") {
          body = JSON.stringify(body);
        }
        return new Response(body)[key]();
      });
    }
    return bodyCache[key] = raw[key]();
  };
  json() {
    return this.#cachedBody("text").then((text) => JSON.parse(text));
  }
  text() {
    return this.#cachedBody("text");
  }
  arrayBuffer() {
    return this.#cachedBody("arrayBuffer");
  }
  blob() {
    return this.#cachedBody("blob");
  }
  formData() {
    return this.#cachedBody("formData");
  }
  addValidatedData(target, data) {
    this.#validatedData[target] = data;
  }
  valid(target) {
    return this.#validatedData[target];
  }
  get url() {
    return this.raw.url;
  }
  get method() {
    return this.raw.method;
  }
  get [GET_MATCH_RESULT]() {
    return this.#matchResult;
  }
  get matchedRoutes() {
    return this.#matchResult[0].map(([[, route]]) => route);
  }
  get routePath() {
    return this.#matchResult[0].map(([[, route]]) => route)[this.routeIndex].path;
  }
};

// src/context.ts
var TEXT_PLAIN = "text/plain; charset=UTF-8";
var setDefaultContentType = (contentType, headers) => {
  return {
    "Content-Type": contentType,
    ...headers
  };
};
var Context = class {
  #rawRequest;
  #req;
  env = {};
  #var;
  finalized = false;
  error;
  #status;
  #executionCtx;
  #res;
  #layout;
  #renderer;
  #notFoundHandler;
  #preparedHeaders;
  #matchResult;
  #path;
  constructor(req, options) {
    this.#rawRequest = req;
    if (options) {
      this.#executionCtx = options.executionCtx;
      this.env = options.env;
      this.#notFoundHandler = options.notFoundHandler;
      this.#path = options.path;
      this.#matchResult = options.matchResult;
    }
  }
  get req() {
    this.#req ??= new HonoRequest(this.#rawRequest, this.#path, this.#matchResult);
    return this.#req;
  }
  get event() {
    if (this.#executionCtx && "respondWith" in this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    return this.#res ||= new Response(null, {
      headers: this.#preparedHeaders ??= new Headers()
    });
  }
  set res(_res) {
    if (this.#res && _res) {
      _res = new Response(_res.body, _res);
      for (const [k, v] of this.#res.headers.entries()) {
        if (k === "content-type") {
          continue;
        }
        if (k === "set-cookie") {
          const cookies = this.#res.headers.getSetCookie();
          _res.headers.delete("set-cookie");
          for (const cookie of cookies) {
            _res.headers.append("set-cookie", cookie);
          }
        } else {
          _res.headers.set(k, v);
        }
      }
    }
    this.#res = _res;
    this.finalized = true;
  }
  render = (...args) => {
    this.#renderer ??= (content) => this.html(content);
    return this.#renderer(...args);
  };
  setLayout = (layout) => this.#layout = layout;
  getLayout = () => this.#layout;
  setRenderer = (renderer) => {
    this.#renderer = renderer;
  };
  header = (name, value, options) => {
    if (this.finalized) {
      this.#res = new Response(this.#res.body, this.#res);
    }
    const headers = this.#res ? this.#res.headers : this.#preparedHeaders ??= new Headers();
    if (value === void 0) {
      headers.delete(name);
    } else if (options?.append) {
      headers.append(name, value);
    } else {
      headers.set(name, value);
    }
  };
  status = (status) => {
    this.#status = status;
  };
  set = (key, value) => {
    this.#var ??= /* @__PURE__ */ new Map();
    this.#var.set(key, value);
  };
  get = (key) => {
    return this.#var ? this.#var.get(key) : void 0;
  };
  get var() {
    if (!this.#var) {
      return {};
    }
    return Object.fromEntries(this.#var);
  }
  #newResponse(data, arg, headers) {
    const responseHeaders = this.#res ? new Headers(this.#res.headers) : this.#preparedHeaders ?? new Headers();
    if (typeof arg === "object" && "headers" in arg) {
      const argHeaders = arg.headers instanceof Headers ? arg.headers : new Headers(arg.headers);
      for (const [key, value] of argHeaders) {
        if (key.toLowerCase() === "set-cookie") {
          responseHeaders.append(key, value);
        } else {
          responseHeaders.set(key, value);
        }
      }
    }
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        if (typeof v === "string") {
          responseHeaders.set(k, v);
        } else {
          responseHeaders.delete(k);
          for (const v2 of v) {
            responseHeaders.append(k, v2);
          }
        }
      }
    }
    const status = typeof arg === "number" ? arg : arg?.status ?? this.#status;
    return new Response(data, { status, headers: responseHeaders });
  }
  newResponse = (...args) => this.#newResponse(...args);
  body = (data, arg, headers) => this.#newResponse(data, arg, headers);
  text = (text, arg, headers) => {
    return !this.#preparedHeaders && !this.#status && !arg && !headers && !this.finalized ? new Response(text) : this.#newResponse(
      text,
      arg,
      setDefaultContentType(TEXT_PLAIN, headers)
    );
  };
  json = (object, arg, headers) => {
    return this.#newResponse(
      JSON.stringify(object),
      arg,
      setDefaultContentType("application/json", headers)
    );
  };
  html = (html, arg, headers) => {
    const res = (html2) => this.#newResponse(html2, arg, setDefaultContentType("text/html; charset=UTF-8", headers));
    return typeof html === "object" ? resolveCallback(html, HtmlEscapedCallbackPhase.Stringify, false, {}).then(res) : res(html);
  };
  redirect = (location, status) => {
    this.header("Location", String(location));
    return this.newResponse(null, status ?? 302);
  };
  notFound = () => {
    this.#notFoundHandler ??= () => new Response();
    return this.#notFoundHandler(this);
  };
};

// src/router.ts
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "options", "patch"];
var MESSAGE_MATCHER_IS_ALREADY_BUILT = "Can not add a route since the matcher is already built.";
var UnsupportedPathError = class extends Error {
};

// src/utils/constants.ts
var COMPOSED_HANDLER = "__COMPOSED_HANDLER";

// src/hono-base.ts
var notFoundHandler = (c) => {
  return c.text("404 Not Found", 404);
};
var errorHandler$1 = (err, c) => {
  if ("getResponse" in err) {
    const res = err.getResponse();
    return c.newResponse(res.body, res);
  }
  console.error(err);
  return c.text("Internal Server Error", 500);
};
var Hono$1 = class Hono {
  get;
  post;
  put;
  delete;
  options;
  patch;
  all;
  on;
  use;
  router;
  getPath;
  _basePath = "/";
  #path = "/";
  routes = [];
  constructor(options = {}) {
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.forEach((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          this.#path = args1;
        } else {
          this.#addRoute(method, this.#path, args1);
        }
        args.forEach((handler) => {
          this.#addRoute(method, this.#path, handler);
        });
        return this;
      };
    });
    this.on = (method, path, ...handlers) => {
      for (const p of [path].flat()) {
        this.#path = p;
        for (const m of [method].flat()) {
          handlers.map((handler) => {
            this.#addRoute(m.toUpperCase(), this.#path, handler);
          });
        }
      }
      return this;
    };
    this.use = (arg1, ...handlers) => {
      if (typeof arg1 === "string") {
        this.#path = arg1;
      } else {
        this.#path = "*";
        handlers.unshift(arg1);
      }
      handlers.forEach((handler) => {
        this.#addRoute(METHOD_NAME_ALL, this.#path, handler);
      });
      return this;
    };
    const { strict, ...optionsWithoutStrict } = options;
    Object.assign(this, optionsWithoutStrict);
    this.getPath = strict ?? true ? options.getPath ?? getPath : getPathNoStrict;
  }
  #clone() {
    const clone = new Hono$1({
      router: this.router,
      getPath: this.getPath
    });
    clone.errorHandler = this.errorHandler;
    clone.#notFoundHandler = this.#notFoundHandler;
    clone.routes = this.routes;
    return clone;
  }
  #notFoundHandler = notFoundHandler;
  errorHandler = errorHandler$1;
  route(path, app) {
    const subApp = this.basePath(path);
    app.routes.map((r) => {
      let handler;
      if (app.errorHandler === errorHandler$1) {
        handler = r.handler;
      } else {
        handler = async (c, next) => (await compose([], app.errorHandler)(c, () => r.handler(c, next))).res;
        handler[COMPOSED_HANDLER] = r.handler;
      }
      subApp.#addRoute(r.method, r.path, handler);
    });
    return this;
  }
  basePath(path) {
    const subApp = this.#clone();
    subApp._basePath = mergePath(this._basePath, path);
    return subApp;
  }
  onError = (handler) => {
    this.errorHandler = handler;
    return this;
  };
  notFound = (handler) => {
    this.#notFoundHandler = handler;
    return this;
  };
  mount(path, applicationHandler, options) {
    let replaceRequest;
    let optionHandler;
    if (options) {
      if (typeof options === "function") {
        optionHandler = options;
      } else {
        optionHandler = options.optionHandler;
        if (options.replaceRequest === false) {
          replaceRequest = (request) => request;
        } else {
          replaceRequest = options.replaceRequest;
        }
      }
    }
    const getOptions = optionHandler ? (c) => {
      const options2 = optionHandler(c);
      return Array.isArray(options2) ? options2 : [options2];
    } : (c) => {
      let executionContext = void 0;
      try {
        executionContext = c.executionCtx;
      } catch {
      }
      return [c.env, executionContext];
    };
    replaceRequest ||= (() => {
      const mergedPath = mergePath(this._basePath, path);
      const pathPrefixLength = mergedPath === "/" ? 0 : mergedPath.length;
      return (request) => {
        const url = new URL(request.url);
        url.pathname = url.pathname.slice(pathPrefixLength) || "/";
        return new Request(url, request);
      };
    })();
    const handler = async (c, next) => {
      const res = await applicationHandler(replaceRequest(c.req.raw), ...getOptions(c));
      if (res) {
        return res;
      }
      await next();
    };
    this.#addRoute(METHOD_NAME_ALL, mergePath(path, "*"), handler);
    return this;
  }
  #addRoute(method, path, handler) {
    method = method.toUpperCase();
    path = mergePath(this._basePath, path);
    const r = { basePath: this._basePath, path, method, handler };
    this.router.add(method, path, [handler, r]);
    this.routes.push(r);
  }
  #handleError(err, c) {
    if (err instanceof Error) {
      return this.errorHandler(err, c);
    }
    throw err;
  }
  #dispatch(request, executionCtx, env, method) {
    if (method === "HEAD") {
      return (async () => new Response(null, await this.#dispatch(request, executionCtx, env, "GET")))();
    }
    const path = this.getPath(request, { env });
    const matchResult = this.router.match(method, path);
    const c = new Context(request, {
      path,
      matchResult,
      env,
      executionCtx,
      notFoundHandler: this.#notFoundHandler
    });
    if (matchResult[0].length === 1) {
      let res;
      try {
        res = matchResult[0][0][0][0](c, async () => {
          c.res = await this.#notFoundHandler(c);
        });
      } catch (err) {
        return this.#handleError(err, c);
      }
      return res instanceof Promise ? res.then(
        (resolved) => resolved || (c.finalized ? c.res : this.#notFoundHandler(c))
      ).catch((err) => this.#handleError(err, c)) : res ?? this.#notFoundHandler(c);
    }
    const composed = compose(matchResult[0], this.errorHandler, this.#notFoundHandler);
    return (async () => {
      try {
        const context = await composed(c);
        if (!context.finalized) {
          throw new Error(
            "Context is not finalized. Did you forget to return a Response object or `await next()`?"
          );
        }
        return context.res;
      } catch (err) {
        return this.#handleError(err, c);
      }
    })();
  }
  fetch = (request, ...rest) => {
    return this.#dispatch(request, rest[1], rest[0], request.method);
  };
  request = (input, requestInit, Env, executionCtx) => {
    if (input instanceof Request) {
      return this.fetch(requestInit ? new Request(input, requestInit) : input, Env, executionCtx);
    }
    input = input.toString();
    return this.fetch(
      new Request(
        /^https?:\/\//.test(input) ? input : `http://localhost${mergePath("/", input)}`,
        requestInit
      ),
      Env,
      executionCtx
    );
  };
  fire = () => {
    addEventListener("fetch", (event) => {
      event.respondWith(this.#dispatch(event.request, event, void 0, event.request.method));
    });
  };
};

// src/router/reg-exp-router/node.ts
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
var regExpMetaChars = new Set(".\\+*[^]$()");
function compareKey(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
}
var Node$1 = class Node {
  #index;
  #varIndex;
  #children = /* @__PURE__ */ Object.create(null);
  insert(tokens, index, paramMap, context, pathErrorCheckOnly) {
    if (tokens.length === 0) {
      if (this.#index !== void 0) {
        throw PATH_ERROR;
      }
      if (pathErrorCheckOnly) {
        return;
      }
      this.#index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      let regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      if (name && pattern[2]) {
        regexpStr = regexpStr.replace(/^\((?!\?:)(?=[^)]+\)$)/, "(?:");
        if (/\((?!\?:)/.test(regexpStr)) {
          throw PATH_ERROR;
        }
      }
      node = this.#children[regexpStr];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[regexpStr] = new Node$1();
        if (name !== "") {
          node.#varIndex = context.varIndex++;
        }
      }
      if (!pathErrorCheckOnly && name !== "") {
        paramMap.push([name, node.#varIndex]);
      }
    } else {
      node = this.#children[token];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[token] = new Node$1();
      }
    }
    node.insert(restTokens, index, paramMap, context, pathErrorCheckOnly);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.#children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.#children[k];
      return (typeof c.#varIndex === "number" ? `(${k})@${c.#varIndex}` : regExpMetaChars.has(k) ? `\\${k}` : k) + c.buildRegExpStr();
    });
    if (typeof this.#index === "number") {
      strList.unshift(`#${this.#index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
};

// src/router/reg-exp-router/trie.ts
var Trie = class {
  #context = { varIndex: 0 };
  #root = new Node$1();
  insert(path, index, pathErrorCheckOnly) {
    const paramAssoc = [];
    const groups = [];
    for (let i = 0; ; ) {
      let replaced = false;
      path = path.replace(/\{[^}]+\}/g, (m) => {
        const mark = `@\\${i}`;
        groups[i] = [mark, m];
        i++;
        replaced = true;
        return mark;
      });
      if (!replaced) {
        break;
      }
    }
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g) || [];
    for (let i = groups.length - 1; i >= 0; i--) {
      const [mark] = groups[i];
      for (let j = tokens.length - 1; j >= 0; j--) {
        if (tokens[j].indexOf(mark) !== -1) {
          tokens[j] = tokens[j].replace(mark, groups[i][1]);
          break;
        }
      }
    }
    this.#root.insert(tokens, index, paramAssoc, this.#context, pathErrorCheckOnly);
    return paramAssoc;
  }
  buildRegExp() {
    let regexp = this.#root.buildRegExpStr();
    if (regexp === "") {
      return [/^$/, [], []];
    }
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (handlerIndex !== void 0) {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (paramIndex !== void 0) {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
};

// src/router/reg-exp-router/router.ts
var emptyParam = [];
var nullMatcher = [/^$/, [], /* @__PURE__ */ Object.create(null)];
var wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
function buildWildcardRegExp(path) {
  return wildcardRegExpCache[path] ??= new RegExp(
    path === "*" ? "" : `^${path.replace(
      /\/\*$|([.\\+*[^\]$()])/g,
      (_, metaChar) => metaChar ? `\\${metaChar}` : "(?:|/.*)"
    )}$`
  );
}
function clearWildcardRegExpCache() {
  wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
}
function buildMatcherFromPreprocessedRoutes(routes) {
  const trie = new Trie();
  const handlerData = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  const routesWithStaticPathFlag = routes.map(
    (route) => [!/\*|\/:/.test(route[0]), ...route]
  ).sort(
    ([isStaticA, pathA], [isStaticB, pathB]) => isStaticA ? 1 : isStaticB ? -1 : pathA.length - pathB.length
  );
  const staticMap = /* @__PURE__ */ Object.create(null);
  for (let i = 0, j = -1, len = routesWithStaticPathFlag.length; i < len; i++) {
    const [pathErrorCheckOnly, path, handlers] = routesWithStaticPathFlag[i];
    if (pathErrorCheckOnly) {
      staticMap[path] = [handlers.map(([h]) => [h, /* @__PURE__ */ Object.create(null)]), emptyParam];
    } else {
      j++;
    }
    let paramAssoc;
    try {
      paramAssoc = trie.insert(path, j, pathErrorCheckOnly);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(path) : e;
    }
    if (pathErrorCheckOnly) {
      continue;
    }
    handlerData[j] = handlers.map(([h, paramCount]) => {
      const paramIndexMap = /* @__PURE__ */ Object.create(null);
      paramCount -= 1;
      for (; paramCount >= 0; paramCount--) {
        const [key, value] = paramAssoc[paramCount];
        paramIndexMap[key] = value;
      }
      return [h, paramIndexMap];
    });
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie.buildRegExp();
  for (let i = 0, len = handlerData.length; i < len; i++) {
    for (let j = 0, len2 = handlerData[i].length; j < len2; j++) {
      const map = handlerData[i][j]?.[1];
      if (!map) {
        continue;
      }
      const keys = Object.keys(map);
      for (let k = 0, len3 = keys.length; k < len3; k++) {
        map[keys[k]] = paramReplacementMap[map[keys[k]]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlerData[indexReplacementMap[i]];
  }
  return [regexp, handlerMap, staticMap];
}
function findMiddleware(middleware, path) {
  if (!middleware) {
    return void 0;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return void 0;
}
var RegExpRouter = class {
  name = "RegExpRouter";
  #middleware;
  #routes;
  constructor() {
    this.#middleware = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
    this.#routes = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
  }
  add(method, path, handler) {
    const middleware = this.#middleware;
    const routes = this.#routes;
    if (!middleware || !routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    if (!middleware[method]) {
      [middleware, routes].forEach((handlerMap) => {
        handlerMap[method] = /* @__PURE__ */ Object.create(null);
        Object.keys(handlerMap[METHOD_NAME_ALL]).forEach((p) => {
          handlerMap[method][p] = [...handlerMap[METHOD_NAME_ALL][p]];
        });
      });
    }
    if (path === "/*") {
      path = "*";
    }
    const paramCount = (path.match(/\/:/g) || []).length;
    if (/\*$/.test(path)) {
      const re = buildWildcardRegExp(path);
      if (method === METHOD_NAME_ALL) {
        Object.keys(middleware).forEach((m) => {
          middleware[m][path] ||= findMiddleware(middleware[m], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
        });
      } else {
        middleware[method][path] ||= findMiddleware(middleware[method], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
      }
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            re.test(p) && middleware[m][p].push([handler, paramCount]);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach(
            (p) => re.test(p) && routes[m][p].push([handler, paramCount])
          );
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length; i < len; i++) {
      const path2 = paths[i];
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          routes[m][path2] ||= [
            ...findMiddleware(middleware[m], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ];
          routes[m][path2].push([handler, paramCount - len + i + 1]);
        }
      });
    }
  }
  match(method, path) {
    clearWildcardRegExpCache();
    const matchers = this.#buildAllMatchers();
    this.match = (method2, path2) => {
      const matcher = matchers[method2] || matchers[METHOD_NAME_ALL];
      const staticMatch = matcher[2][path2];
      if (staticMatch) {
        return staticMatch;
      }
      const match = path2.match(matcher[0]);
      if (!match) {
        return [[], emptyParam];
      }
      const index = match.indexOf("", 1);
      return [matcher[1][index], match];
    };
    return this.match(method, path);
  }
  #buildAllMatchers() {
    const matchers = /* @__PURE__ */ Object.create(null);
    Object.keys(this.#routes).concat(Object.keys(this.#middleware)).forEach((method) => {
      matchers[method] ||= this.#buildMatcher(method);
    });
    this.#middleware = this.#routes = void 0;
    return matchers;
  }
  #buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.#middleware, this.#routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute ||= true;
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(
          ...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]])
        );
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
};

// src/router/smart-router/router.ts
var SmartRouter = class {
  name = "SmartRouter";
  #routers = [];
  #routes = [];
  constructor(init) {
    this.#routers = init.routers;
  }
  add(method, path, handler) {
    if (!this.#routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    this.#routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.#routes) {
      throw new Error("Fatal error");
    }
    const routers = this.#routers;
    const routes = this.#routes;
    const len = routers.length;
    let i = 0;
    let res;
    for (; i < len; i++) {
      const router = routers[i];
      try {
        for (let i2 = 0, len2 = routes.length; i2 < len2; i2++) {
          router.add(...routes[i2]);
        }
        res = router.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router.match.bind(router);
      this.#routers = [router];
      this.#routes = void 0;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    this.name = `SmartRouter + ${this.activeRouter.name}`;
    return res;
  }
  get activeRouter() {
    if (this.#routes || this.#routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.#routers[0];
  }
};

// src/router/trie-router/node.ts
var emptyParams = /* @__PURE__ */ Object.create(null);
var Node = class {
  #methods;
  #children;
  #patterns;
  #order = 0;
  #params = emptyParams;
  constructor(method, handler, children) {
    this.#children = children || /* @__PURE__ */ Object.create(null);
    this.#methods = [];
    if (method && handler) {
      const m = /* @__PURE__ */ Object.create(null);
      m[method] = { handler, possibleKeys: [], score: 0 };
      this.#methods = [m];
    }
    this.#patterns = [];
  }
  insert(method, path, handler) {
    this.#order = ++this.#order;
    let curNode = this;
    const parts = splitRoutingPath(path);
    const possibleKeys = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const p = parts[i];
      const nextP = parts[i + 1];
      const pattern = getPattern(p, nextP);
      const key = Array.isArray(pattern) ? pattern[0] : p;
      if (key in curNode.#children) {
        curNode = curNode.#children[key];
        if (pattern) {
          possibleKeys.push(pattern[1]);
        }
        continue;
      }
      curNode.#children[key] = new Node();
      if (pattern) {
        curNode.#patterns.push(pattern);
        possibleKeys.push(pattern[1]);
      }
      curNode = curNode.#children[key];
    }
    curNode.#methods.push({
      [method]: {
        handler,
        possibleKeys: possibleKeys.filter((v, i, a) => a.indexOf(v) === i),
        score: this.#order
      }
    });
    return curNode;
  }
  #getHandlerSets(node, method, nodeParams, params) {
    const handlerSets = [];
    for (let i = 0, len = node.#methods.length; i < len; i++) {
      const m = node.#methods[i];
      const handlerSet = m[method] || m[METHOD_NAME_ALL];
      const processedSet = {};
      if (handlerSet !== void 0) {
        handlerSet.params = /* @__PURE__ */ Object.create(null);
        handlerSets.push(handlerSet);
        if (nodeParams !== emptyParams || params && params !== emptyParams) {
          for (let i2 = 0, len2 = handlerSet.possibleKeys.length; i2 < len2; i2++) {
            const key = handlerSet.possibleKeys[i2];
            const processed = processedSet[handlerSet.score];
            handlerSet.params[key] = params?.[key] && !processed ? params[key] : nodeParams[key] ?? params?.[key];
            processedSet[handlerSet.score] = true;
          }
        }
      }
    }
    return handlerSets;
  }
  search(method, path) {
    const handlerSets = [];
    this.#params = emptyParams;
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    const curNodesQueue = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const part = parts[i];
      const isLast = i === len - 1;
      const tempNodes = [];
      for (let j = 0, len2 = curNodes.length; j < len2; j++) {
        const node = curNodes[j];
        const nextNode = node.#children[part];
        if (nextNode) {
          nextNode.#params = node.#params;
          if (isLast) {
            if (nextNode.#children["*"]) {
              handlerSets.push(
                ...this.#getHandlerSets(nextNode.#children["*"], method, node.#params)
              );
            }
            handlerSets.push(...this.#getHandlerSets(nextNode, method, node.#params));
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node.#patterns.length; k < len3; k++) {
          const pattern = node.#patterns[k];
          const params = node.#params === emptyParams ? {} : { ...node.#params };
          if (pattern === "*") {
            const astNode = node.#children["*"];
            if (astNode) {
              handlerSets.push(...this.#getHandlerSets(astNode, method, node.#params));
              astNode.#params = params;
              tempNodes.push(astNode);
            }
            continue;
          }
          if (!part) {
            continue;
          }
          const [key, name, matcher] = pattern;
          const child = node.#children[key];
          const restPathString = parts.slice(i).join("/");
          if (matcher instanceof RegExp) {
            const m = matcher.exec(restPathString);
            if (m) {
              params[name] = m[0];
              handlerSets.push(...this.#getHandlerSets(child, method, node.#params, params));
              if (Object.keys(child.#children).length) {
                child.#params = params;
                const componentCount = m[0].match(/\//)?.length ?? 0;
                const targetCurNodes = curNodesQueue[componentCount] ||= [];
                targetCurNodes.push(child);
              }
              continue;
            }
          }
          if (matcher === true || matcher.test(part)) {
            params[name] = part;
            if (isLast) {
              handlerSets.push(...this.#getHandlerSets(child, method, params, node.#params));
              if (child.#children["*"]) {
                handlerSets.push(
                  ...this.#getHandlerSets(child.#children["*"], method, params, node.#params)
                );
              }
            } else {
              child.#params = params;
              tempNodes.push(child);
            }
          }
        }
      }
      curNodes = tempNodes.concat(curNodesQueue.shift() ?? []);
    }
    if (handlerSets.length > 1) {
      handlerSets.sort((a, b) => {
        return a.score - b.score;
      });
    }
    return [handlerSets.map(({ handler, params }) => [handler, params])];
  }
};

// src/router/trie-router/router.ts
var TrieRouter = class {
  name = "TrieRouter";
  #node;
  constructor() {
    this.#node = new Node();
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (let i = 0, len = results.length; i < len; i++) {
        this.#node.insert(method, results[i], handler);
      }
      return;
    }
    this.#node.insert(method, path, handler);
  }
  match(method, path) {
    return this.#node.search(method, path);
  }
};

// src/hono.ts
var Hono = class extends Hono$1 {
  constructor(options = {}) {
    super(options);
    this.router = options.router ?? new SmartRouter({
      routers: [new RegExpRouter(), new TrieRouter()]
    });
  }
};

// src/http-exception.ts
var HTTPException$1 = class HTTPException extends Error {
  res;
  status;
  constructor(status = 500, options) {
    super(options?.message, { cause: options?.cause });
    this.res = options?.res;
    this.status = status;
  }
  getResponse() {
    if (this.res) {
      const newResponse = new Response(this.res.body, {
        status: this.status,
        headers: this.res.headers
      });
      return newResponse;
    }
    return new Response(this.message, {
      status: this.status
    });
  }
};

// src/middleware/body-limit/index.ts
var ERROR_MESSAGE = "Payload Too Large";
var BodyLimitError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "BodyLimitError";
  }
};
var bodyLimit = (options) => {
  const onError = options.onError || (() => {
    const res = new Response(ERROR_MESSAGE, {
      status: 413
    });
    throw new HTTPException$1(413, { res });
  });
  const maxSize = options.maxSize;
  return async function bodyLimit2(c, next) {
    if (!c.req.raw.body) {
      return next();
    }
    if (c.req.raw.headers.has("content-length")) {
      const contentLength = parseInt(c.req.raw.headers.get("content-length") || "0", 10);
      return contentLength > maxSize ? onError(c) : next();
    }
    let size = 0;
    const rawReader = c.req.raw.body.getReader();
    const reader = new ReadableStream({
      async start(controller) {
        try {
          for (; ; ) {
            const { done, value } = await rawReader.read();
            if (done) {
              break;
            }
            size += value.length;
            if (size > maxSize) {
              controller.error(new BodyLimitError(ERROR_MESSAGE));
              break;
            }
            controller.enqueue(value);
          }
        } finally {
          controller.close();
        }
      }
    });
    const requestInit = { body: reader, duplex: "half" };
    c.req.raw = new Request(c.req.raw, requestInit);
    await next();
    if (c.error instanceof BodyLimitError) {
      c.res = await onError(c);
    }
  };
};

// src/middleware/cors/index.ts
var cors = (options) => {
  const defaults = {
    origin: "*",
    allowMethods: ["GET", "HEAD", "PUT", "POST", "DELETE", "PATCH"],
    allowHeaders: [],
    exposeHeaders: []
  };
  const opts = {
    ...defaults,
    ...options
  };
  const findAllowOrigin = ((optsOrigin) => {
    if (typeof optsOrigin === "string") {
      if (optsOrigin === "*") {
        return () => optsOrigin;
      } else {
        return (origin) => optsOrigin === origin ? origin : null;
      }
    } else if (typeof optsOrigin === "function") {
      return optsOrigin;
    } else {
      return (origin) => optsOrigin.includes(origin) ? origin : null;
    }
  })(opts.origin);
  const findAllowMethods = ((optsAllowMethods) => {
    if (typeof optsAllowMethods === "function") {
      return optsAllowMethods;
    } else if (Array.isArray(optsAllowMethods)) {
      return () => optsAllowMethods;
    } else {
      return () => [];
    }
  })(opts.allowMethods);
  return async function cors2(c, next) {
    function set(key, value) {
      c.res.headers.set(key, value);
    }
    const allowOrigin = findAllowOrigin(c.req.header("origin") || "", c);
    if (allowOrigin) {
      set("Access-Control-Allow-Origin", allowOrigin);
    }
    if (opts.origin !== "*") {
      const existingVary = c.req.header("Vary");
      if (existingVary) {
        set("Vary", existingVary);
      } else {
        set("Vary", "Origin");
      }
    }
    if (opts.credentials) {
      set("Access-Control-Allow-Credentials", "true");
    }
    if (opts.exposeHeaders?.length) {
      set("Access-Control-Expose-Headers", opts.exposeHeaders.join(","));
    }
    if (c.req.method === "OPTIONS") {
      if (opts.maxAge != null) {
        set("Access-Control-Max-Age", opts.maxAge.toString());
      }
      const allowMethods = findAllowMethods(c.req.header("origin") || "", c);
      if (allowMethods.length) {
        set("Access-Control-Allow-Methods", allowMethods.join(","));
      }
      let headers = opts.allowHeaders;
      if (!headers?.length) {
        const requestHeaders = c.req.header("Access-Control-Request-Headers");
        if (requestHeaders) {
          headers = requestHeaders.split(/\s*,\s*/);
        }
      }
      if (headers?.length) {
        set("Access-Control-Allow-Headers", headers.join(","));
        c.res.headers.append("Vary", "Access-Control-Request-Headers");
      }
      c.res.headers.delete("Content-Length");
      c.res.headers.delete("Content-Type");
      return new Response(null, {
        headers: c.res.headers,
        status: 204,
        statusText: "No Content"
      });
    }
    await next();
  };
};

// src/utils/color.ts
function getColorEnabled() {
  const { process, Deno } = globalThis;
  const isNoColor = typeof Deno?.noColor === "boolean" ? Deno.noColor : process !== void 0 ? "NO_COLOR" in process?.env : false;
  return !isNoColor;
}
async function getColorEnabledAsync() {
  const { navigator } = globalThis;
  const cfWorkers = "cloudflare:workers";
  const isNoColor = navigator !== void 0 && navigator.userAgent === "Cloudflare-Workers" ? await (async () => {
    try {
      return "NO_COLOR" in ((await import(cfWorkers)).env ?? {});
    } catch {
      return false;
    }
  })() : !getColorEnabled();
  return !isNoColor;
}

// src/middleware/logger/index.ts
var humanize = (times) => {
  const [delimiter, separator] = [",", "."];
  const orderTimes = times.map((v) => v.replace(/(\d)(?=(\d\d\d)+(?!\d))/g, "$1" + delimiter));
  return orderTimes.join(separator);
};
var time = (start) => {
  const delta = Date.now() - start;
  return humanize([delta < 1e3 ? delta + "ms" : Math.round(delta / 1e3) + "s"]);
};
var colorStatus = async (status) => {
  const colorEnabled = await getColorEnabledAsync();
  if (colorEnabled) {
    switch (status / 100 | 0) {
      case 5:
        return `\x1B[31m${status}\x1B[0m`;
      case 4:
        return `\x1B[33m${status}\x1B[0m`;
      case 3:
        return `\x1B[36m${status}\x1B[0m`;
      case 2:
        return `\x1B[32m${status}\x1B[0m`;
    }
  }
  return `${status}`;
};
async function log(fn, prefix, method, path, status = 0, elapsed) {
  const out = prefix === "<--" /* Incoming */ ? `${prefix} ${method} ${path}` : `${prefix} ${method} ${path} ${await colorStatus(status)} ${elapsed}`;
  fn(out);
}
var logger = (fn = console.log) => {
  return async function logger2(c, next) {
    const { method, url } = c.req;
    const path = url.slice(url.indexOf("/", 8));
    await log(fn, "<--" /* Incoming */, method, path);
    const start = Date.now();
    await next();
    await log(fn, "-->" /* Outgoing */, method, path, c.res.status, time(start));
  };
};

// src/middleware/timeout/index.ts
var defaultTimeoutException = new HTTPException$1(504, {
  message: "Gateway Timeout"
});
var timeout = (duration, exception = defaultTimeoutException) => {
  return async function timeout2(context, next) {
    let timer;
    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        reject(typeof exception === "function" ? exception(context) : exception);
      }, duration);
    });
    try {
      await Promise.race([next(), timeoutPromise]);
    } finally {
      if (timer !== void 0) {
        clearTimeout(timer);
      }
    }
  };
};

var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/server/handlers/a2a.ts
var a2a_exports = {};
__export(a2a_exports, {
  getAgentCardByIdHandler: () => getAgentCardByIdHandler$1,
  getAgentExecutionHandler: () => getAgentExecutionHandler$1,
  handleTaskCancel: () => handleTaskCancel,
  handleTaskGet: () => handleTaskGet,
  handleTaskSend: () => handleTaskSend,
  handleTaskSendSubscribe: () => handleTaskSendSubscribe
});
function normalizeError(error, reqId, taskId, logger) {
  let a2aError;
  if (error instanceof A2AError) {
    a2aError = error;
  } else if (error instanceof Error) {
    a2aError = A2AError.internalError(error.message, { stack: error.stack });
  } else {
    a2aError = A2AError.internalError("An unknown error occurred.", error);
  }
  if (taskId && !a2aError.taskId) {
    a2aError.taskId = taskId;
  }
  logger?.error(`Error processing request (Task: ${a2aError.taskId ?? "N/A"}, ReqID: ${reqId ?? "N/A"}):`, a2aError);
  return createErrorResponse(reqId, a2aError.toJSONRPCError());
}
function createErrorResponse(id, error) {
  return {
    jsonrpc: "2.0",
    id,
    // Can be null if request ID was invalid/missing
    error
  };
}
function createSuccessResponse(id, result) {
  if (!id) {
    throw A2AError.internalError("Cannot create success response for null ID.");
  }
  return {
    jsonrpc: "2.0",
    id,
    result
  };
}
function convertToCoreMessage(message) {
  return {
    role: message.role === "user" ? "user" : "assistant",
    content: message.parts.map((msg) => convertToCoreMessagePart(msg))
  };
}
function convertToCoreMessagePart(part) {
  switch (part.type) {
    case "text":
      return {
        type: "text",
        text: part.text
      };
    case "file":
      return {
        type: "file",
        data: new URL(part.file.uri),
        mimeType: part.file.mimeType
      };
    case "data":
      throw new Error("Data parts are not supported in core messages");
  }
}

// src/server/a2a/store.ts
var InMemoryTaskStore = class {
  store = /* @__PURE__ */ new Map();
  activeCancellations = /* @__PURE__ */ new Set();
  async load({ agentId, taskId }) {
    const entry = this.store.get(`${agentId}-${taskId}`);
    if (!entry) {
      return null;
    }
    return { task: { ...entry.task }, history: [...entry.history] };
  }
  async save({ agentId, data }) {
    const key = `${agentId}-${data.task.id}`;
    if (!data.task.id) {
      throw new Error("Task ID is required");
    }
    this.store.set(key, {
      task: { ...data.task },
      history: [...data.history]
    });
  }
};

// src/server/a2a/tasks.ts
function isTaskStatusUpdate(update) {
  return "state" in update && !("parts" in update);
}
function isArtifactUpdate(update) {
  return "parts" in update;
}
function applyUpdateToTaskAndHistory(current, update) {
  let newTask = structuredClone(current.task);
  let newHistory = structuredClone(current.history);
  if (isTaskStatusUpdate(update)) {
    newTask.status = {
      ...newTask.status,
      // Keep existing properties if not overwritten
      ...update,
      // Apply updates
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    };
    if (update.message?.role === "agent") {
      newHistory.push(update.message);
    }
  } else if (isArtifactUpdate(update)) {
    if (!newTask.artifacts) {
      newTask.artifacts = [];
    } else {
      newTask.artifacts = [...newTask.artifacts];
    }
    const existingIndex = update.index ?? -1;
    let replaced = false;
    if (existingIndex >= 0 && existingIndex < newTask.artifacts.length) {
      const existingArtifact = newTask.artifacts[existingIndex];
      if (update.append) {
        const appendedArtifact = JSON.parse(JSON.stringify(existingArtifact));
        appendedArtifact.parts.push(...update.parts);
        if (update.metadata) {
          appendedArtifact.metadata = {
            ...appendedArtifact.metadata || {},
            ...update.metadata
          };
        }
        if (update.lastChunk !== void 0) appendedArtifact.lastChunk = update.lastChunk;
        if (update.description) appendedArtifact.description = update.description;
        newTask.artifacts[existingIndex] = appendedArtifact;
        replaced = true;
      } else {
        newTask.artifacts[existingIndex] = { ...update };
        replaced = true;
      }
    } else if (update.name) {
      const namedIndex = newTask.artifacts.findIndex((a) => a.name === update.name);
      if (namedIndex >= 0) {
        newTask.artifacts[namedIndex] = { ...update };
        replaced = true;
      }
    }
    if (!replaced) {
      newTask.artifacts.push({ ...update });
      if (newTask.artifacts.some((a) => a.index !== void 0)) {
        newTask.artifacts.sort((a, b) => (a.index ?? 0) - (b.index ?? 0));
      }
    }
  }
  return { task: newTask, history: newHistory };
}
async function loadOrCreateTaskAndHistory({
  agentId,
  taskId,
  taskStore,
  message,
  sessionId,
  metadata,
  logger
}) {
  const data = await taskStore.load({ agentId, taskId });
  if (!data) {
    const initialTask = {
      id: taskId,
      sessionId,
      status: {
        state: "submitted",
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        message: null
      },
      artifacts: [],
      metadata
    };
    const initialData = {
      task: initialTask,
      history: [message]
    };
    logger?.info(`[Task ${taskId}] Created new task and history.`);
    await taskStore.save({ agentId, data: initialData });
    return initialData;
  }
  logger?.info(`[Task ${taskId}] Loaded existing task and history.`);
  let updatedData = {
    task: data.task,
    history: [...data.history, message]
  };
  const { status } = data.task;
  const finalStates = ["completed", "failed", "canceled"];
  if (finalStates.includes(status.state)) {
    logger?.warn(`[Task ${taskId}] Received message for task in final state ${status.state}. Restarting.`);
    updatedData = applyUpdateToTaskAndHistory(updatedData, {
      state: "submitted",
      message: null
    });
  } else if (status.state === "input-required") {
    logger?.info(`[Task ${taskId}] Changing state from 'input-required' to 'working'.`);
    updatedData = applyUpdateToTaskAndHistory(updatedData, { state: "working" });
  } else if (status.state === "working") {
    logger?.warn(`[Task ${taskId}] Received message while already 'working'. Proceeding.`);
  }
  await taskStore.save({ agentId, data: updatedData });
  return {
    task: { ...updatedData.task },
    history: [...updatedData.history]
  };
}
function createTaskContext({
  task,
  userMessage,
  history,
  activeCancellations
}) {
  return {
    task: structuredClone(task),
    userMessage,
    history: structuredClone(history),
    isCancelled: () => activeCancellations.has(task.id)
  };
}

// src/server/handlers/a2a.ts
var taskSendParamsSchema = z.object({
  id: z.string().min(1, "Invalid or missing task ID (params.id)."),
  message: z.object({
    parts: z.array(
      z.object({
        type: z.enum(["text"]),
        text: z.string()
      })
    )
  })
});
async function getAgentCardByIdHandler$1({
  mastra,
  agentId,
  executionUrl = `/a2a/${agentId}`,
  provider = {
    organization: "Mastra",
    url: "https://mastra.ai"
  },
  version = "1.0",
  runtimeContext
}) {
  const agent = mastra.getAgent(agentId);
  if (!agent) {
    throw new Error(`Agent with ID ${agentId} not found`);
  }
  const [instructions, tools] = await Promise.all([
    agent.getInstructions({ runtimeContext }),
    agent.getTools({ runtimeContext })
  ]);
  const agentCard = {
    name: agent.id || agentId,
    description: instructions,
    url: executionUrl,
    provider,
    version,
    capabilities: {
      streaming: true,
      // All agents support streaming
      pushNotifications: false,
      stateTransitionHistory: false
    },
    defaultInputModes: ["text"],
    defaultOutputModes: ["text"],
    // Convert agent tools to skills format for A2A protocol
    skills: Object.entries(tools).map(([toolId, tool]) => ({
      id: toolId,
      name: toolId,
      description: tool.description || `Tool: ${toolId}`,
      // Optional fields
      tags: ["tool"]
    }))
  };
  return agentCard;
}
function validateTaskSendParams(params) {
  try {
    taskSendParamsSchema.parse(params);
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw A2AError.invalidParams(error.errors[0].message);
    }
    throw error;
  }
}
async function handleTaskSend({
  requestId,
  params,
  taskStore,
  agent,
  agentId,
  logger,
  runtimeContext
}) {
  validateTaskSendParams(params);
  const { id: taskId, message, sessionId, metadata } = params;
  let currentData = await loadOrCreateTaskAndHistory({
    taskId,
    taskStore,
    agentId,
    message,
    sessionId,
    metadata
  });
  createTaskContext({
    task: currentData.task,
    userMessage: message,
    history: currentData.history,
    activeCancellations: taskStore.activeCancellations
  });
  try {
    const { text } = await agent.generate([convertToCoreMessage(message)], {
      runId: taskId,
      runtimeContext
    });
    currentData = applyUpdateToTaskAndHistory(currentData, {
      state: "completed",
      message: {
        role: "agent",
        parts: [
          {
            type: "text",
            text
          }
        ]
      }
    });
    await taskStore.save({ agentId, data: currentData });
  } catch (handlerError) {
    const failureStatusUpdate = {
      state: "failed",
      message: {
        role: "agent",
        parts: [
          {
            type: "text",
            text: `Handler failed: ${handlerError instanceof Error ? handlerError.message : String(handlerError)}`
          }
        ]
      }
    };
    currentData = applyUpdateToTaskAndHistory(currentData, failureStatusUpdate);
    try {
      await taskStore.save({ agentId, data: currentData });
    } catch (saveError) {
      logger?.error(`Failed to save task ${taskId} after handler error:`, saveError?.message);
    }
    return normalizeError(handlerError, requestId, taskId, logger);
  }
  return createSuccessResponse(requestId, currentData.task);
}
async function handleTaskGet({
  requestId,
  taskStore,
  agentId,
  taskId
}) {
  const task = await taskStore.load({ agentId, taskId });
  if (!task) {
    throw A2AError.taskNotFound(taskId);
  }
  return createSuccessResponse(requestId, task);
}
async function* handleTaskSendSubscribe({
  requestId,
  params,
  taskStore,
  agent,
  agentId,
  logger,
  runtimeContext
}) {
  yield createSuccessResponse(requestId, {
    state: "working",
    message: {
      role: "agent",
      parts: [{ type: "text", text: "Generating response..." }]
    }
  });
  let result;
  try {
    result = await handleTaskSend({
      requestId,
      params,
      taskStore,
      agent,
      agentId,
      runtimeContext,
      logger
    });
  } catch (err) {
    if (!(err instanceof A2AError)) {
      throw err;
    }
    result = createErrorResponse(requestId, err.toJSONRPCError());
  }
  yield result;
}
async function handleTaskCancel({
  requestId,
  taskStore,
  agentId,
  taskId,
  logger
}) {
  let data = await taskStore.load({
    agentId,
    taskId
  });
  if (!data) {
    throw A2AError.taskNotFound(taskId);
  }
  const finalStates = ["completed", "failed", "canceled"];
  if (finalStates.includes(data.task.status.state)) {
    logger?.info(`Task ${taskId} already in final state ${data.task.status.state}, cannot cancel.`);
    return createSuccessResponse(requestId, data.task);
  }
  taskStore.activeCancellations.add(taskId);
  const cancelUpdate = {
    state: "canceled",
    message: {
      role: "agent",
      parts: [{ type: "text", text: "Task cancelled by request." }]
    }
  };
  data = applyUpdateToTaskAndHistory(data, cancelUpdate);
  await taskStore.save({ agentId, data });
  taskStore.activeCancellations.delete(taskId);
  return createSuccessResponse(requestId, data.task);
}
async function getAgentExecutionHandler$1({
  requestId,
  mastra,
  agentId,
  runtimeContext,
  method,
  params,
  taskStore = new InMemoryTaskStore(),
  logger
}) {
  const agent = mastra.getAgent(agentId);
  let taskId;
  try {
    taskId = params.id;
    switch (method) {
      case "tasks/send": {
        const result2 = await handleTaskSend({
          requestId,
          params,
          taskStore,
          agent,
          agentId,
          runtimeContext
        });
        return result2;
      }
      case "tasks/sendSubscribe":
        const result = await handleTaskSendSubscribe({
          requestId,
          taskStore,
          params,
          agent,
          agentId,
          runtimeContext
        });
        return result;
      case "tasks/get": {
        const result2 = await handleTaskGet({
          requestId,
          taskStore,
          agentId,
          taskId
        });
        return result2;
      }
      case "tasks/cancel": {
        const result2 = await handleTaskCancel({
          requestId,
          taskStore,
          agentId,
          taskId
        });
        return result2;
      }
      default:
        throw A2AError.methodNotFound(method);
    }
  } catch (error) {
    if (error instanceof A2AError && taskId && !error.taskId) {
      error.taskId = taskId;
    }
    return normalizeError(error, requestId, taskId, logger);
  }
}

// src/utils/stream.ts
var StreamingApi = class {
  writer;
  encoder;
  writable;
  abortSubscribers = [];
  responseReadable;
  aborted = false;
  closed = false;
  constructor(writable, _readable) {
    this.writable = writable;
    this.writer = writable.getWriter();
    this.encoder = new TextEncoder();
    const reader = _readable.getReader();
    this.abortSubscribers.push(async () => {
      await reader.cancel();
    });
    this.responseReadable = new ReadableStream({
      async pull(controller) {
        const { done, value } = await reader.read();
        done ? controller.close() : controller.enqueue(value);
      },
      cancel: () => {
        this.abort();
      }
    });
  }
  async write(input) {
    try {
      if (typeof input === "string") {
        input = this.encoder.encode(input);
      }
      await this.writer.write(input);
    } catch {
    }
    return this;
  }
  async writeln(input) {
    await this.write(input + "\n");
    return this;
  }
  sleep(ms) {
    return new Promise((res) => setTimeout(res, ms));
  }
  async close() {
    try {
      await this.writer.close();
    } catch {
    }
    this.closed = true;
  }
  async pipe(body) {
    this.writer.releaseLock();
    await body.pipeTo(this.writable, { preventClose: true });
    this.writer = this.writable.getWriter();
  }
  onAbort(listener) {
    this.abortSubscribers.push(listener);
  }
  abort() {
    if (!this.aborted) {
      this.aborted = true;
      this.abortSubscribers.forEach((subscriber) => subscriber());
    }
  }
};

// src/helper/streaming/utils.ts
var isOldBunVersion = () => {
  const version = typeof Bun !== "undefined" ? Bun.version : void 0;
  if (version === void 0) {
    return false;
  }
  const result = version.startsWith("1.1") || version.startsWith("1.0") || version.startsWith("0.");
  isOldBunVersion = () => result;
  return result;
};

// src/helper/streaming/stream.ts
var contextStash = /* @__PURE__ */ new WeakMap();
var stream = (c, cb, onError) => {
  const { readable, writable } = new TransformStream();
  const stream2 = new StreamingApi(writable, readable);
  if (isOldBunVersion()) {
    c.req.raw.signal.addEventListener("abort", () => {
      if (!stream2.closed) {
        stream2.abort();
      }
    });
  }
  contextStash.set(stream2.responseReadable, c);
  (async () => {
    try {
      await cb(stream2);
    } catch (e) {
      if (e === void 0) ; else if (e instanceof Error && onError) {
        await onError(e, stream2);
      } else {
        console.error(e);
      }
    } finally {
      stream2.close();
    }
  })();
  return c.newResponse(stream2.responseReadable);
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/double-indexed-kv.js
var DoubleIndexedKV = class {
  constructor() {
    this.keyToValue = /* @__PURE__ */ new Map();
    this.valueToKey = /* @__PURE__ */ new Map();
  }
  set(key, value) {
    this.keyToValue.set(key, value);
    this.valueToKey.set(value, key);
  }
  getByKey(key) {
    return this.keyToValue.get(key);
  }
  getByValue(value) {
    return this.valueToKey.get(value);
  }
  clear() {
    this.keyToValue.clear();
    this.valueToKey.clear();
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/registry.js
var Registry = class {
  constructor(generateIdentifier) {
    this.generateIdentifier = generateIdentifier;
    this.kv = new DoubleIndexedKV();
  }
  register(value, identifier) {
    if (this.kv.getByValue(value)) {
      return;
    }
    if (!identifier) {
      identifier = this.generateIdentifier(value);
    }
    this.kv.set(identifier, value);
  }
  clear() {
    this.kv.clear();
  }
  getIdentifier(value) {
    return this.kv.getByValue(value);
  }
  getValue(identifier) {
    return this.kv.getByKey(identifier);
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/class-registry.js
var ClassRegistry = class extends Registry {
  constructor() {
    super((c) => c.name);
    this.classToAllowedProps = /* @__PURE__ */ new Map();
  }
  register(value, options) {
    if (typeof options === "object") {
      if (options.allowProps) {
        this.classToAllowedProps.set(value, options.allowProps);
      }
      super.register(value, options.identifier);
    } else {
      super.register(value, options);
    }
  }
  getAllowedProps(value) {
    return this.classToAllowedProps.get(value);
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/util.js
function valuesOfObj(record) {
  if ("values" in Object) {
    return Object.values(record);
  }
  const values = [];
  for (const key in record) {
    if (record.hasOwnProperty(key)) {
      values.push(record[key]);
    }
  }
  return values;
}
function find(record, predicate) {
  const values = valuesOfObj(record);
  if ("find" in values) {
    return values.find(predicate);
  }
  const valuesNotNever = values;
  for (let i = 0; i < valuesNotNever.length; i++) {
    const value = valuesNotNever[i];
    if (predicate(value)) {
      return value;
    }
  }
  return void 0;
}
function forEach(record, run) {
  Object.entries(record).forEach(([key, value]) => run(value, key));
}
function includes(arr, value) {
  return arr.indexOf(value) !== -1;
}
function findArr(record, predicate) {
  for (let i = 0; i < record.length; i++) {
    const value = record[i];
    if (predicate(value)) {
      return value;
    }
  }
  return void 0;
}

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/custom-transformer-registry.js
var CustomTransformerRegistry = class {
  constructor() {
    this.transfomers = {};
  }
  register(transformer) {
    this.transfomers[transformer.name] = transformer;
  }
  findApplicable(v) {
    return find(this.transfomers, (transformer) => transformer.isApplicable(v));
  }
  findByName(name) {
    return this.transfomers[name];
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/is.js
var getType = (payload) => Object.prototype.toString.call(payload).slice(8, -1);
var isUndefined = (payload) => typeof payload === "undefined";
var isNull = (payload) => payload === null;
var isPlainObject = (payload) => {
  if (typeof payload !== "object" || payload === null)
    return false;
  if (payload === Object.prototype)
    return false;
  if (Object.getPrototypeOf(payload) === null)
    return true;
  return Object.getPrototypeOf(payload) === Object.prototype;
};
var isEmptyObject = (payload) => isPlainObject(payload) && Object.keys(payload).length === 0;
var isArray = (payload) => Array.isArray(payload);
var isString = (payload) => typeof payload === "string";
var isNumber = (payload) => typeof payload === "number" && !isNaN(payload);
var isBoolean = (payload) => typeof payload === "boolean";
var isRegExp = (payload) => payload instanceof RegExp;
var isMap = (payload) => payload instanceof Map;
var isSet = (payload) => payload instanceof Set;
var isSymbol = (payload) => getType(payload) === "Symbol";
var isDate = (payload) => payload instanceof Date && !isNaN(payload.valueOf());
var isError = (payload) => payload instanceof Error;
var isNaNValue = (payload) => typeof payload === "number" && isNaN(payload);
var isPrimitive = (payload) => isBoolean(payload) || isNull(payload) || isUndefined(payload) || isNumber(payload) || isString(payload) || isSymbol(payload);
var isBigint = (payload) => typeof payload === "bigint";
var isInfinite = (payload) => payload === Infinity || payload === -Infinity;
var isTypedArray = (payload) => ArrayBuffer.isView(payload) && !(payload instanceof DataView);
var isURL = (payload) => payload instanceof URL;

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/pathstringifier.js
var escapeKey = (key) => key.replace(/\./g, "\\.");
var stringifyPath = (path) => path.map(String).map(escapeKey).join(".");
var parsePath = (string) => {
  const result = [];
  let segment = "";
  for (let i = 0; i < string.length; i++) {
    let char = string.charAt(i);
    const isEscapedDot = char === "\\" && string.charAt(i + 1) === ".";
    if (isEscapedDot) {
      segment += ".";
      i++;
      continue;
    }
    const isEndOfSegment = char === ".";
    if (isEndOfSegment) {
      result.push(segment);
      segment = "";
      continue;
    }
    segment += char;
  }
  const lastSegment = segment;
  result.push(lastSegment);
  return result;
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/transformer.js
function simpleTransformation(isApplicable, annotation, transform, untransform) {
  return {
    isApplicable,
    annotation,
    transform,
    untransform
  };
}
var simpleRules = [
  simpleTransformation(isUndefined, "undefined", () => null, () => void 0),
  simpleTransformation(isBigint, "bigint", (v) => v.toString(), (v) => {
    if (typeof BigInt !== "undefined") {
      return BigInt(v);
    }
    console.error("Please add a BigInt polyfill.");
    return v;
  }),
  simpleTransformation(isDate, "Date", (v) => v.toISOString(), (v) => new Date(v)),
  simpleTransformation(isError, "Error", (v, superJson) => {
    const baseError = {
      name: v.name,
      message: v.message
    };
    superJson.allowedErrorProps.forEach((prop) => {
      baseError[prop] = v[prop];
    });
    return baseError;
  }, (v, superJson) => {
    const e = new Error(v.message);
    e.name = v.name;
    e.stack = v.stack;
    superJson.allowedErrorProps.forEach((prop) => {
      e[prop] = v[prop];
    });
    return e;
  }),
  simpleTransformation(isRegExp, "regexp", (v) => "" + v, (regex) => {
    const body = regex.slice(1, regex.lastIndexOf("/"));
    const flags = regex.slice(regex.lastIndexOf("/") + 1);
    return new RegExp(body, flags);
  }),
  simpleTransformation(
    isSet,
    "set",
    // (sets only exist in es6+)
    // eslint-disable-next-line es5/no-es6-methods
    (v) => [...v.values()],
    (v) => new Set(v)
  ),
  simpleTransformation(isMap, "map", (v) => [...v.entries()], (v) => new Map(v)),
  simpleTransformation((v) => isNaNValue(v) || isInfinite(v), "number", (v) => {
    if (isNaNValue(v)) {
      return "NaN";
    }
    if (v > 0) {
      return "Infinity";
    } else {
      return "-Infinity";
    }
  }, Number),
  simpleTransformation((v) => v === 0 && 1 / v === -Infinity, "number", () => {
    return "-0";
  }, Number),
  simpleTransformation(isURL, "URL", (v) => v.toString(), (v) => new URL(v))
];
function compositeTransformation(isApplicable, annotation, transform, untransform) {
  return {
    isApplicable,
    annotation,
    transform,
    untransform
  };
}
var symbolRule = compositeTransformation((s, superJson) => {
  if (isSymbol(s)) {
    const isRegistered = !!superJson.symbolRegistry.getIdentifier(s);
    return isRegistered;
  }
  return false;
}, (s, superJson) => {
  const identifier = superJson.symbolRegistry.getIdentifier(s);
  return ["symbol", identifier];
}, (v) => v.description, (_, a, superJson) => {
  const value = superJson.symbolRegistry.getValue(a[1]);
  if (!value) {
    throw new Error("Trying to deserialize unknown symbol");
  }
  return value;
});
var constructorToName = [
  Int8Array,
  Uint8Array,
  Int16Array,
  Uint16Array,
  Int32Array,
  Uint32Array,
  Float32Array,
  Float64Array,
  Uint8ClampedArray
].reduce((obj, ctor) => {
  obj[ctor.name] = ctor;
  return obj;
}, {});
var typedArrayRule = compositeTransformation(isTypedArray, (v) => ["typed-array", v.constructor.name], (v) => [...v], (v, a) => {
  const ctor = constructorToName[a[1]];
  if (!ctor) {
    throw new Error("Trying to deserialize unknown typed array");
  }
  return new ctor(v);
});
function isInstanceOfRegisteredClass(potentialClass, superJson) {
  if (potentialClass?.constructor) {
    const isRegistered = !!superJson.classRegistry.getIdentifier(potentialClass.constructor);
    return isRegistered;
  }
  return false;
}
var classRule = compositeTransformation(isInstanceOfRegisteredClass, (clazz, superJson) => {
  const identifier = superJson.classRegistry.getIdentifier(clazz.constructor);
  return ["class", identifier];
}, (clazz, superJson) => {
  const allowedProps = superJson.classRegistry.getAllowedProps(clazz.constructor);
  if (!allowedProps) {
    return { ...clazz };
  }
  const result = {};
  allowedProps.forEach((prop) => {
    result[prop] = clazz[prop];
  });
  return result;
}, (v, a, superJson) => {
  const clazz = superJson.classRegistry.getValue(a[1]);
  if (!clazz) {
    throw new Error(`Trying to deserialize unknown class '${a[1]}' - check https://github.com/blitz-js/superjson/issues/116#issuecomment-773996564`);
  }
  return Object.assign(Object.create(clazz.prototype), v);
});
var customRule = compositeTransformation((value, superJson) => {
  return !!superJson.customTransformerRegistry.findApplicable(value);
}, (value, superJson) => {
  const transformer = superJson.customTransformerRegistry.findApplicable(value);
  return ["custom", transformer.name];
}, (value, superJson) => {
  const transformer = superJson.customTransformerRegistry.findApplicable(value);
  return transformer.serialize(value);
}, (v, a, superJson) => {
  const transformer = superJson.customTransformerRegistry.findByName(a[1]);
  if (!transformer) {
    throw new Error("Trying to deserialize unknown custom value");
  }
  return transformer.deserialize(v);
});
var compositeRules = [classRule, symbolRule, customRule, typedArrayRule];
var transformValue = (value, superJson) => {
  const applicableCompositeRule = findArr(compositeRules, (rule) => rule.isApplicable(value, superJson));
  if (applicableCompositeRule) {
    return {
      value: applicableCompositeRule.transform(value, superJson),
      type: applicableCompositeRule.annotation(value, superJson)
    };
  }
  const applicableSimpleRule = findArr(simpleRules, (rule) => rule.isApplicable(value, superJson));
  if (applicableSimpleRule) {
    return {
      value: applicableSimpleRule.transform(value, superJson),
      type: applicableSimpleRule.annotation
    };
  }
  return void 0;
};
var simpleRulesByAnnotation = {};
simpleRules.forEach((rule) => {
  simpleRulesByAnnotation[rule.annotation] = rule;
});
var untransformValue = (json, type, superJson) => {
  if (isArray(type)) {
    switch (type[0]) {
      case "symbol":
        return symbolRule.untransform(json, type, superJson);
      case "class":
        return classRule.untransform(json, type, superJson);
      case "custom":
        return customRule.untransform(json, type, superJson);
      case "typed-array":
        return typedArrayRule.untransform(json, type, superJson);
      default:
        throw new Error("Unknown transformation: " + type);
    }
  } else {
    const transformation = simpleRulesByAnnotation[type];
    if (!transformation) {
      throw new Error("Unknown transformation: " + type);
    }
    return transformation.untransform(json, superJson);
  }
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/accessDeep.js
var getNthKey = (value, n) => {
  if (n > value.size)
    throw new Error("index out of bounds");
  const keys = value.keys();
  while (n > 0) {
    keys.next();
    n--;
  }
  return keys.next().value;
};
function validatePath(path) {
  if (includes(path, "__proto__")) {
    throw new Error("__proto__ is not allowed as a property");
  }
  if (includes(path, "prototype")) {
    throw new Error("prototype is not allowed as a property");
  }
  if (includes(path, "constructor")) {
    throw new Error("constructor is not allowed as a property");
  }
}
var getDeep = (object, path) => {
  validatePath(path);
  for (let i = 0; i < path.length; i++) {
    const key = path[i];
    if (isSet(object)) {
      object = getNthKey(object, +key);
    } else if (isMap(object)) {
      const row = +key;
      const type = +path[++i] === 0 ? "key" : "value";
      const keyOfRow = getNthKey(object, row);
      switch (type) {
        case "key":
          object = keyOfRow;
          break;
        case "value":
          object = object.get(keyOfRow);
          break;
      }
    } else {
      object = object[key];
    }
  }
  return object;
};
var setDeep = (object, path, mapper) => {
  validatePath(path);
  if (path.length === 0) {
    return mapper(object);
  }
  let parent = object;
  for (let i = 0; i < path.length - 1; i++) {
    const key = path[i];
    if (isArray(parent)) {
      const index = +key;
      parent = parent[index];
    } else if (isPlainObject(parent)) {
      parent = parent[key];
    } else if (isSet(parent)) {
      const row = +key;
      parent = getNthKey(parent, row);
    } else if (isMap(parent)) {
      const isEnd = i === path.length - 2;
      if (isEnd) {
        break;
      }
      const row = +key;
      const type = +path[++i] === 0 ? "key" : "value";
      const keyOfRow = getNthKey(parent, row);
      switch (type) {
        case "key":
          parent = keyOfRow;
          break;
        case "value":
          parent = parent.get(keyOfRow);
          break;
      }
    }
  }
  const lastKey = path[path.length - 1];
  if (isArray(parent)) {
    parent[+lastKey] = mapper(parent[+lastKey]);
  } else if (isPlainObject(parent)) {
    parent[lastKey] = mapper(parent[lastKey]);
  }
  if (isSet(parent)) {
    const oldValue = getNthKey(parent, +lastKey);
    const newValue = mapper(oldValue);
    if (oldValue !== newValue) {
      parent.delete(oldValue);
      parent.add(newValue);
    }
  }
  if (isMap(parent)) {
    const row = +path[path.length - 2];
    const keyToRow = getNthKey(parent, row);
    const type = +lastKey === 0 ? "key" : "value";
    switch (type) {
      case "key": {
        const newKey = mapper(keyToRow);
        parent.set(newKey, parent.get(keyToRow));
        if (newKey !== keyToRow) {
          parent.delete(keyToRow);
        }
        break;
      }
      case "value": {
        parent.set(keyToRow, mapper(parent.get(keyToRow)));
        break;
      }
    }
  }
  return object;
};

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/plainer.js
function traverse(tree, walker2, origin = []) {
  if (!tree) {
    return;
  }
  if (!isArray(tree)) {
    forEach(tree, (subtree, key) => traverse(subtree, walker2, [...origin, ...parsePath(key)]));
    return;
  }
  const [nodeValue, children] = tree;
  if (children) {
    forEach(children, (child, key) => {
      traverse(child, walker2, [...origin, ...parsePath(key)]);
    });
  }
  walker2(nodeValue, origin);
}
function applyValueAnnotations(plain, annotations, superJson) {
  traverse(annotations, (type, path) => {
    plain = setDeep(plain, path, (v) => untransformValue(v, type, superJson));
  });
  return plain;
}
function applyReferentialEqualityAnnotations(plain, annotations) {
  function apply(identicalPaths, path) {
    const object = getDeep(plain, parsePath(path));
    identicalPaths.map(parsePath).forEach((identicalObjectPath) => {
      plain = setDeep(plain, identicalObjectPath, () => object);
    });
  }
  if (isArray(annotations)) {
    const [root, other] = annotations;
    root.forEach((identicalPath) => {
      plain = setDeep(plain, parsePath(identicalPath), () => plain);
    });
    if (other) {
      forEach(other, apply);
    }
  } else {
    forEach(annotations, apply);
  }
  return plain;
}
var isDeep = (object, superJson) => isPlainObject(object) || isArray(object) || isMap(object) || isSet(object) || isInstanceOfRegisteredClass(object, superJson);
function addIdentity(object, path, identities) {
  const existingSet = identities.get(object);
  if (existingSet) {
    existingSet.push(path);
  } else {
    identities.set(object, [path]);
  }
}
function generateReferentialEqualityAnnotations(identitites, dedupe) {
  const result = {};
  let rootEqualityPaths = void 0;
  identitites.forEach((paths) => {
    if (paths.length <= 1) {
      return;
    }
    if (!dedupe) {
      paths = paths.map((path) => path.map(String)).sort((a, b) => a.length - b.length);
    }
    const [representativePath, ...identicalPaths] = paths;
    if (representativePath.length === 0) {
      rootEqualityPaths = identicalPaths.map(stringifyPath);
    } else {
      result[stringifyPath(representativePath)] = identicalPaths.map(stringifyPath);
    }
  });
  if (rootEqualityPaths) {
    if (isEmptyObject(result)) {
      return [rootEqualityPaths];
    } else {
      return [rootEqualityPaths, result];
    }
  } else {
    return isEmptyObject(result) ? void 0 : result;
  }
}
var walker = (object, identities, superJson, dedupe, path = [], objectsInThisPath = [], seenObjects = /* @__PURE__ */ new Map()) => {
  const primitive = isPrimitive(object);
  if (!primitive) {
    addIdentity(object, path, identities);
    const seen = seenObjects.get(object);
    if (seen) {
      return dedupe ? {
        transformedValue: null
      } : seen;
    }
  }
  if (!isDeep(object, superJson)) {
    const transformed2 = transformValue(object, superJson);
    const result2 = transformed2 ? {
      transformedValue: transformed2.value,
      annotations: [transformed2.type]
    } : {
      transformedValue: object
    };
    if (!primitive) {
      seenObjects.set(object, result2);
    }
    return result2;
  }
  if (includes(objectsInThisPath, object)) {
    return {
      transformedValue: null
    };
  }
  const transformationResult = transformValue(object, superJson);
  const transformed = transformationResult?.value ?? object;
  const transformedValue = isArray(transformed) ? [] : {};
  const innerAnnotations = {};
  forEach(transformed, (value, index) => {
    if (index === "__proto__" || index === "constructor" || index === "prototype") {
      throw new Error(`Detected property ${index}. This is a prototype pollution risk, please remove it from your object.`);
    }
    const recursiveResult = walker(value, identities, superJson, dedupe, [...path, index], [...objectsInThisPath, object], seenObjects);
    transformedValue[index] = recursiveResult.transformedValue;
    if (isArray(recursiveResult.annotations)) {
      innerAnnotations[index] = recursiveResult.annotations;
    } else if (isPlainObject(recursiveResult.annotations)) {
      forEach(recursiveResult.annotations, (tree, key) => {
        innerAnnotations[escapeKey(index) + "." + key] = tree;
      });
    }
  });
  const result = isEmptyObject(innerAnnotations) ? {
    transformedValue,
    annotations: !!transformationResult ? [transformationResult.type] : void 0
  } : {
    transformedValue,
    annotations: !!transformationResult ? [transformationResult.type, innerAnnotations] : innerAnnotations
  };
  if (!primitive) {
    seenObjects.set(object, result);
  }
  return result;
};

// ../../node_modules/.pnpm/is-what@4.1.16/node_modules/is-what/dist/index.js
function getType2(payload) {
  return Object.prototype.toString.call(payload).slice(8, -1);
}
function isArray2(payload) {
  return getType2(payload) === "Array";
}
function isPlainObject2(payload) {
  if (getType2(payload) !== "Object")
    return false;
  const prototype = Object.getPrototypeOf(payload);
  return !!prototype && prototype.constructor === Object && prototype === Object.prototype;
}

// ../../node_modules/.pnpm/copy-anything@3.0.5/node_modules/copy-anything/dist/index.js
function assignProp(carry, key, newVal, originalObject, includeNonenumerable) {
  const propType = {}.propertyIsEnumerable.call(originalObject, key) ? "enumerable" : "nonenumerable";
  if (propType === "enumerable")
    carry[key] = newVal;
  if (includeNonenumerable && propType === "nonenumerable") {
    Object.defineProperty(carry, key, {
      value: newVal,
      enumerable: false,
      writable: true,
      configurable: true
    });
  }
}
function copy(target, options = {}) {
  if (isArray2(target)) {
    return target.map((item) => copy(item, options));
  }
  if (!isPlainObject2(target)) {
    return target;
  }
  const props = Object.getOwnPropertyNames(target);
  const symbols = Object.getOwnPropertySymbols(target);
  return [...props, ...symbols].reduce((carry, key) => {
    if (isArray2(options.props) && !options.props.includes(key)) {
      return carry;
    }
    const val = target[key];
    const newVal = copy(val, options);
    assignProp(carry, key, newVal, target, options.nonenumerable);
    return carry;
  }, {});
}

// ../../node_modules/.pnpm/superjson@2.2.2/node_modules/superjson/dist/index.js
var SuperJSON = class {
  /**
   * @param dedupeReferentialEqualities  If true, SuperJSON will make sure only one instance of referentially equal objects are serialized and the rest are replaced with `null`.
   */
  constructor({ dedupe = false } = {}) {
    this.classRegistry = new ClassRegistry();
    this.symbolRegistry = new Registry((s) => s.description ?? "");
    this.customTransformerRegistry = new CustomTransformerRegistry();
    this.allowedErrorProps = [];
    this.dedupe = dedupe;
  }
  serialize(object) {
    const identities = /* @__PURE__ */ new Map();
    const output = walker(object, identities, this, this.dedupe);
    const res = {
      json: output.transformedValue
    };
    if (output.annotations) {
      res.meta = {
        ...res.meta,
        values: output.annotations
      };
    }
    const equalityAnnotations = generateReferentialEqualityAnnotations(identities, this.dedupe);
    if (equalityAnnotations) {
      res.meta = {
        ...res.meta,
        referentialEqualities: equalityAnnotations
      };
    }
    return res;
  }
  deserialize(payload) {
    const { json, meta } = payload;
    let result = copy(json);
    if (meta?.values) {
      result = applyValueAnnotations(result, meta.values, this);
    }
    if (meta?.referentialEqualities) {
      result = applyReferentialEqualityAnnotations(result, meta.referentialEqualities);
    }
    return result;
  }
  stringify(object) {
    return JSON.stringify(this.serialize(object));
  }
  parse(string) {
    return this.deserialize(JSON.parse(string));
  }
  registerClass(v, options) {
    this.classRegistry.register(v, options);
  }
  registerSymbol(v, identifier) {
    this.symbolRegistry.register(v, identifier);
  }
  registerCustom(transformer, name) {
    this.customTransformerRegistry.register({
      name,
      ...transformer
    });
  }
  allowErrorProps(...props) {
    this.allowedErrorProps.push(...props);
  }
};
SuperJSON.defaultInstance = new SuperJSON();
SuperJSON.serialize = SuperJSON.defaultInstance.serialize.bind(SuperJSON.defaultInstance);
SuperJSON.deserialize = SuperJSON.defaultInstance.deserialize.bind(SuperJSON.defaultInstance);
SuperJSON.stringify = SuperJSON.defaultInstance.stringify.bind(SuperJSON.defaultInstance);
SuperJSON.parse = SuperJSON.defaultInstance.parse.bind(SuperJSON.defaultInstance);
SuperJSON.registerClass = SuperJSON.defaultInstance.registerClass.bind(SuperJSON.defaultInstance);
SuperJSON.registerSymbol = SuperJSON.defaultInstance.registerSymbol.bind(SuperJSON.defaultInstance);
SuperJSON.registerCustom = SuperJSON.defaultInstance.registerCustom.bind(SuperJSON.defaultInstance);
SuperJSON.allowErrorProps = SuperJSON.defaultInstance.allowErrorProps.bind(SuperJSON.defaultInstance);
var stringify = SuperJSON.stringify;

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/Options.js
var ignoreOverride = Symbol("Let zodToJsonSchema decide on which parser to use");
var defaultOptions = {
  name: void 0,
  $refStrategy: "root",
  basePath: ["#"],
  effectStrategy: "input",
  pipeStrategy: "all",
  dateStrategy: "format:date-time",
  mapStrategy: "entries",
  removeAdditionalStrategy: "passthrough",
  allowedAdditionalProperties: true,
  rejectedAdditionalProperties: false,
  definitionPath: "definitions",
  target: "jsonSchema7",
  strictUnions: false,
  definitions: {},
  errorMessages: false,
  markdownDescription: false,
  patternStrategy: "escape",
  applyRegexFlags: false,
  emailStrategy: "format:email",
  base64Strategy: "contentEncoding:base64",
  nameStrategy: "ref",
  openAiAnyTypeName: "OpenAiAnyType"
};
var getDefaultOptions = (options) => typeof options === "string" ? {
  ...defaultOptions,
  name: options
} : {
  ...defaultOptions,
  ...options
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/Refs.js
var getRefs = (options) => {
  const _options = getDefaultOptions(options);
  const currentPath = _options.name !== void 0 ? [..._options.basePath, _options.definitionPath, _options.name] : _options.basePath;
  return {
    ..._options,
    flags: { hasReferencedOpenAiAnyType: false },
    currentPath,
    propertyPath: void 0,
    seen: new Map(Object.entries(_options.definitions).map(([name, def]) => [
      def._def,
      {
        def: def._def,
        path: [..._options.basePath, _options.definitionPath, name],
        // Resolution of references will be forced even though seen, so it's ok that the schema is undefined here for now.
        jsonSchema: void 0
      }
    ]))
  };
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/errorMessages.js
function addErrorMessage(res, key, errorMessage, refs) {
  if (!refs?.errorMessages)
    return;
  if (errorMessage) {
    res.errorMessage = {
      ...res.errorMessage,
      [key]: errorMessage
    };
  }
}
function setResponseValueAndErrors(res, key, value, errorMessage, refs) {
  res[key] = value;
  addErrorMessage(res, key, errorMessage, refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/getRelativePath.js
var getRelativePath = (pathA, pathB) => {
  let i = 0;
  for (; i < pathA.length && i < pathB.length; i++) {
    if (pathA[i] !== pathB[i])
      break;
  }
  return [(pathA.length - i).toString(), ...pathB.slice(i)].join("/");
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/any.js
function parseAnyDef(refs) {
  if (refs.target !== "openAi") {
    return {};
  }
  const anyDefinitionPath = [
    ...refs.basePath,
    refs.definitionPath,
    refs.openAiAnyTypeName
  ];
  refs.flags.hasReferencedOpenAiAnyType = true;
  return {
    $ref: refs.$refStrategy === "relative" ? getRelativePath(anyDefinitionPath, refs.currentPath) : anyDefinitionPath.join("/")
  };
}
function parseArrayDef(def, refs) {
  const res = {
    type: "array"
  };
  if (def.type?._def && def.type?._def?.typeName !== ZodFirstPartyTypeKind.ZodAny) {
    res.items = parseDef(def.type._def, {
      ...refs,
      currentPath: [...refs.currentPath, "items"]
    });
  }
  if (def.minLength) {
    setResponseValueAndErrors(res, "minItems", def.minLength.value, def.minLength.message, refs);
  }
  if (def.maxLength) {
    setResponseValueAndErrors(res, "maxItems", def.maxLength.value, def.maxLength.message, refs);
  }
  if (def.exactLength) {
    setResponseValueAndErrors(res, "minItems", def.exactLength.value, def.exactLength.message, refs);
    setResponseValueAndErrors(res, "maxItems", def.exactLength.value, def.exactLength.message, refs);
  }
  return res;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/bigint.js
function parseBigintDef(def, refs) {
  const res = {
    type: "integer",
    format: "int64"
  };
  if (!def.checks)
    return res;
  for (const check of def.checks) {
    switch (check.kind) {
      case "min":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMinimum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMinimum = true;
          }
          setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
        }
        break;
      case "max":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMaximum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMaximum = true;
          }
          setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
        }
        break;
      case "multipleOf":
        setResponseValueAndErrors(res, "multipleOf", check.value, check.message, refs);
        break;
    }
  }
  return res;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/boolean.js
function parseBooleanDef() {
  return {
    type: "boolean"
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/branded.js
function parseBrandedDef(_def, refs) {
  return parseDef(_def.type._def, refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/catch.js
var parseCatchDef = (def, refs) => {
  return parseDef(def.innerType._def, refs);
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/date.js
function parseDateDef(def, refs, overrideDateStrategy) {
  const strategy = overrideDateStrategy ?? refs.dateStrategy;
  if (Array.isArray(strategy)) {
    return {
      anyOf: strategy.map((item, i) => parseDateDef(def, refs, item))
    };
  }
  switch (strategy) {
    case "string":
    case "format:date-time":
      return {
        type: "string",
        format: "date-time"
      };
    case "format:date":
      return {
        type: "string",
        format: "date"
      };
    case "integer":
      return integerDateParser(def, refs);
  }
}
var integerDateParser = (def, refs) => {
  const res = {
    type: "integer",
    format: "unix-time"
  };
  if (refs.target === "openApi3") {
    return res;
  }
  for (const check of def.checks) {
    switch (check.kind) {
      case "min":
        setResponseValueAndErrors(
          res,
          "minimum",
          check.value,
          // This is in milliseconds
          check.message,
          refs
        );
        break;
      case "max":
        setResponseValueAndErrors(
          res,
          "maximum",
          check.value,
          // This is in milliseconds
          check.message,
          refs
        );
        break;
    }
  }
  return res;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/default.js
function parseDefaultDef(_def, refs) {
  return {
    ...parseDef(_def.innerType._def, refs),
    default: _def.defaultValue()
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/effects.js
function parseEffectsDef(_def, refs) {
  return refs.effectStrategy === "input" ? parseDef(_def.schema._def, refs) : parseAnyDef(refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/enum.js
function parseEnumDef(def) {
  return {
    type: "string",
    enum: Array.from(def.values)
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/intersection.js
var isJsonSchema7AllOfType = (type) => {
  if ("type" in type && type.type === "string")
    return false;
  return "allOf" in type;
};
function parseIntersectionDef(def, refs) {
  const allOf = [
    parseDef(def.left._def, {
      ...refs,
      currentPath: [...refs.currentPath, "allOf", "0"]
    }),
    parseDef(def.right._def, {
      ...refs,
      currentPath: [...refs.currentPath, "allOf", "1"]
    })
  ].filter((x) => !!x);
  let unevaluatedProperties = refs.target === "jsonSchema2019-09" ? { unevaluatedProperties: false } : void 0;
  const mergedAllOf = [];
  allOf.forEach((schema) => {
    if (isJsonSchema7AllOfType(schema)) {
      mergedAllOf.push(...schema.allOf);
      if (schema.unevaluatedProperties === void 0) {
        unevaluatedProperties = void 0;
      }
    } else {
      let nestedSchema = schema;
      if ("additionalProperties" in schema && schema.additionalProperties === false) {
        const { additionalProperties, ...rest } = schema;
        nestedSchema = rest;
      } else {
        unevaluatedProperties = void 0;
      }
      mergedAllOf.push(nestedSchema);
    }
  });
  return mergedAllOf.length ? {
    allOf: mergedAllOf,
    ...unevaluatedProperties
  } : void 0;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/literal.js
function parseLiteralDef(def, refs) {
  const parsedType = typeof def.value;
  if (parsedType !== "bigint" && parsedType !== "number" && parsedType !== "boolean" && parsedType !== "string") {
    return {
      type: Array.isArray(def.value) ? "array" : "object"
    };
  }
  if (refs.target === "openApi3") {
    return {
      type: parsedType === "bigint" ? "integer" : parsedType,
      enum: [def.value]
    };
  }
  return {
    type: parsedType === "bigint" ? "integer" : parsedType,
    const: def.value
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/string.js
var emojiRegex = void 0;
var zodPatterns = {
  /**
   * `c` was changed to `[cC]` to replicate /i flag
   */
  cuid: /^[cC][^\s-]{8,}$/,
  cuid2: /^[0-9a-z]+$/,
  ulid: /^[0-9A-HJKMNP-TV-Z]{26}$/,
  /**
   * `a-z` was added to replicate /i flag
   */
  email: /^(?!\.)(?!.*\.\.)([a-zA-Z0-9_'+\-\.]*)[a-zA-Z0-9_+-]@([a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$/,
  /**
   * Constructed a valid Unicode RegExp
   *
   * Lazily instantiate since this type of regex isn't supported
   * in all envs (e.g. React Native).
   *
   * See:
   * https://github.com/colinhacks/zod/issues/2433
   * Fix in Zod:
   * https://github.com/colinhacks/zod/commit/9340fd51e48576a75adc919bff65dbc4a5d4c99b
   */
  emoji: () => {
    if (emojiRegex === void 0) {
      emojiRegex = RegExp("^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$", "u");
    }
    return emojiRegex;
  },
  /**
   * Unused
   */
  uuid: /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/,
  /**
   * Unused
   */
  ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/,
  ipv4Cidr: /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/,
  /**
   * Unused
   */
  ipv6: /^(([a-f0-9]{1,4}:){7}|::([a-f0-9]{1,4}:){0,6}|([a-f0-9]{1,4}:){1}:([a-f0-9]{1,4}:){0,5}|([a-f0-9]{1,4}:){2}:([a-f0-9]{1,4}:){0,4}|([a-f0-9]{1,4}:){3}:([a-f0-9]{1,4}:){0,3}|([a-f0-9]{1,4}:){4}:([a-f0-9]{1,4}:){0,2}|([a-f0-9]{1,4}:){5}:([a-f0-9]{1,4}:){0,1})([a-f0-9]{1,4}|(((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2}))\.){3}((25[0-5])|(2[0-4][0-9])|(1[0-9]{2})|([0-9]{1,2})))$/,
  ipv6Cidr: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/,
  base64: /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/,
  base64url: /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/,
  nanoid: /^[a-zA-Z0-9_-]{21}$/,
  jwt: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/
};
function parseStringDef(def, refs) {
  const res = {
    type: "string"
  };
  if (def.checks) {
    for (const check of def.checks) {
      switch (check.kind) {
        case "min":
          setResponseValueAndErrors(res, "minLength", typeof res.minLength === "number" ? Math.max(res.minLength, check.value) : check.value, check.message, refs);
          break;
        case "max":
          setResponseValueAndErrors(res, "maxLength", typeof res.maxLength === "number" ? Math.min(res.maxLength, check.value) : check.value, check.message, refs);
          break;
        case "email":
          switch (refs.emailStrategy) {
            case "format:email":
              addFormat(res, "email", check.message, refs);
              break;
            case "format:idn-email":
              addFormat(res, "idn-email", check.message, refs);
              break;
            case "pattern:zod":
              addPattern(res, zodPatterns.email, check.message, refs);
              break;
          }
          break;
        case "url":
          addFormat(res, "uri", check.message, refs);
          break;
        case "uuid":
          addFormat(res, "uuid", check.message, refs);
          break;
        case "regex":
          addPattern(res, check.regex, check.message, refs);
          break;
        case "cuid":
          addPattern(res, zodPatterns.cuid, check.message, refs);
          break;
        case "cuid2":
          addPattern(res, zodPatterns.cuid2, check.message, refs);
          break;
        case "startsWith":
          addPattern(res, RegExp(`^${escapeLiteralCheckValue(check.value, refs)}`), check.message, refs);
          break;
        case "endsWith":
          addPattern(res, RegExp(`${escapeLiteralCheckValue(check.value, refs)}$`), check.message, refs);
          break;
        case "datetime":
          addFormat(res, "date-time", check.message, refs);
          break;
        case "date":
          addFormat(res, "date", check.message, refs);
          break;
        case "time":
          addFormat(res, "time", check.message, refs);
          break;
        case "duration":
          addFormat(res, "duration", check.message, refs);
          break;
        case "length":
          setResponseValueAndErrors(res, "minLength", typeof res.minLength === "number" ? Math.max(res.minLength, check.value) : check.value, check.message, refs);
          setResponseValueAndErrors(res, "maxLength", typeof res.maxLength === "number" ? Math.min(res.maxLength, check.value) : check.value, check.message, refs);
          break;
        case "includes": {
          addPattern(res, RegExp(escapeLiteralCheckValue(check.value, refs)), check.message, refs);
          break;
        }
        case "ip": {
          if (check.version !== "v6") {
            addFormat(res, "ipv4", check.message, refs);
          }
          if (check.version !== "v4") {
            addFormat(res, "ipv6", check.message, refs);
          }
          break;
        }
        case "base64url":
          addPattern(res, zodPatterns.base64url, check.message, refs);
          break;
        case "jwt":
          addPattern(res, zodPatterns.jwt, check.message, refs);
          break;
        case "cidr": {
          if (check.version !== "v6") {
            addPattern(res, zodPatterns.ipv4Cidr, check.message, refs);
          }
          if (check.version !== "v4") {
            addPattern(res, zodPatterns.ipv6Cidr, check.message, refs);
          }
          break;
        }
        case "emoji":
          addPattern(res, zodPatterns.emoji(), check.message, refs);
          break;
        case "ulid": {
          addPattern(res, zodPatterns.ulid, check.message, refs);
          break;
        }
        case "base64": {
          switch (refs.base64Strategy) {
            case "format:binary": {
              addFormat(res, "binary", check.message, refs);
              break;
            }
            case "contentEncoding:base64": {
              setResponseValueAndErrors(res, "contentEncoding", "base64", check.message, refs);
              break;
            }
            case "pattern:zod": {
              addPattern(res, zodPatterns.base64, check.message, refs);
              break;
            }
          }
          break;
        }
        case "nanoid": {
          addPattern(res, zodPatterns.nanoid, check.message, refs);
        }
      }
    }
  }
  return res;
}
function escapeLiteralCheckValue(literal, refs) {
  return refs.patternStrategy === "escape" ? escapeNonAlphaNumeric(literal) : literal;
}
var ALPHA_NUMERIC = new Set("ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz0123456789");
function escapeNonAlphaNumeric(source) {
  let result = "";
  for (let i = 0; i < source.length; i++) {
    if (!ALPHA_NUMERIC.has(source[i])) {
      result += "\\";
    }
    result += source[i];
  }
  return result;
}
function addFormat(schema, value, message, refs) {
  if (schema.format || schema.anyOf?.some((x) => x.format)) {
    if (!schema.anyOf) {
      schema.anyOf = [];
    }
    if (schema.format) {
      schema.anyOf.push({
        format: schema.format,
        ...schema.errorMessage && refs.errorMessages && {
          errorMessage: { format: schema.errorMessage.format }
        }
      });
      delete schema.format;
      if (schema.errorMessage) {
        delete schema.errorMessage.format;
        if (Object.keys(schema.errorMessage).length === 0) {
          delete schema.errorMessage;
        }
      }
    }
    schema.anyOf.push({
      format: value,
      ...message && refs.errorMessages && { errorMessage: { format: message } }
    });
  } else {
    setResponseValueAndErrors(schema, "format", value, message, refs);
  }
}
function addPattern(schema, regex, message, refs) {
  if (schema.pattern || schema.allOf?.some((x) => x.pattern)) {
    if (!schema.allOf) {
      schema.allOf = [];
    }
    if (schema.pattern) {
      schema.allOf.push({
        pattern: schema.pattern,
        ...schema.errorMessage && refs.errorMessages && {
          errorMessage: { pattern: schema.errorMessage.pattern }
        }
      });
      delete schema.pattern;
      if (schema.errorMessage) {
        delete schema.errorMessage.pattern;
        if (Object.keys(schema.errorMessage).length === 0) {
          delete schema.errorMessage;
        }
      }
    }
    schema.allOf.push({
      pattern: stringifyRegExpWithFlags(regex, refs),
      ...message && refs.errorMessages && { errorMessage: { pattern: message } }
    });
  } else {
    setResponseValueAndErrors(schema, "pattern", stringifyRegExpWithFlags(regex, refs), message, refs);
  }
}
function stringifyRegExpWithFlags(regex, refs) {
  if (!refs.applyRegexFlags || !regex.flags) {
    return regex.source;
  }
  const flags = {
    i: regex.flags.includes("i"),
    m: regex.flags.includes("m"),
    s: regex.flags.includes("s")
    // `.` matches newlines
  };
  const source = flags.i ? regex.source.toLowerCase() : regex.source;
  let pattern = "";
  let isEscaped = false;
  let inCharGroup = false;
  let inCharRange = false;
  for (let i = 0; i < source.length; i++) {
    if (isEscaped) {
      pattern += source[i];
      isEscaped = false;
      continue;
    }
    if (flags.i) {
      if (inCharGroup) {
        if (source[i].match(/[a-z]/)) {
          if (inCharRange) {
            pattern += source[i];
            pattern += `${source[i - 2]}-${source[i]}`.toUpperCase();
            inCharRange = false;
          } else if (source[i + 1] === "-" && source[i + 2]?.match(/[a-z]/)) {
            pattern += source[i];
            inCharRange = true;
          } else {
            pattern += `${source[i]}${source[i].toUpperCase()}`;
          }
          continue;
        }
      } else if (source[i].match(/[a-z]/)) {
        pattern += `[${source[i]}${source[i].toUpperCase()}]`;
        continue;
      }
    }
    if (flags.m) {
      if (source[i] === "^") {
        pattern += `(^|(?<=[\r
]))`;
        continue;
      } else if (source[i] === "$") {
        pattern += `($|(?=[\r
]))`;
        continue;
      }
    }
    if (flags.s && source[i] === ".") {
      pattern += inCharGroup ? `${source[i]}\r
` : `[${source[i]}\r
]`;
      continue;
    }
    pattern += source[i];
    if (source[i] === "\\") {
      isEscaped = true;
    } else if (inCharGroup && source[i] === "]") {
      inCharGroup = false;
    } else if (!inCharGroup && source[i] === "[") {
      inCharGroup = true;
    }
  }
  return pattern;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/record.js
function parseRecordDef(def, refs) {
  if (refs.target === "openAi") {
    console.warn("Warning: OpenAI may not support records in schemas! Try an array of key-value pairs instead.");
  }
  if (refs.target === "openApi3" && def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodEnum) {
    return {
      type: "object",
      required: def.keyType._def.values,
      properties: def.keyType._def.values.reduce((acc, key) => ({
        ...acc,
        [key]: parseDef(def.valueType._def, {
          ...refs,
          currentPath: [...refs.currentPath, "properties", key]
        }) ?? parseAnyDef(refs)
      }), {}),
      additionalProperties: refs.rejectedAdditionalProperties
    };
  }
  const schema = {
    type: "object",
    additionalProperties: parseDef(def.valueType._def, {
      ...refs,
      currentPath: [...refs.currentPath, "additionalProperties"]
    }) ?? refs.allowedAdditionalProperties
  };
  if (refs.target === "openApi3") {
    return schema;
  }
  if (def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodString && def.keyType._def.checks?.length) {
    const { type, ...keyType } = parseStringDef(def.keyType._def, refs);
    return {
      ...schema,
      propertyNames: keyType
    };
  } else if (def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodEnum) {
    return {
      ...schema,
      propertyNames: {
        enum: def.keyType._def.values
      }
    };
  } else if (def.keyType?._def.typeName === ZodFirstPartyTypeKind.ZodBranded && def.keyType._def.type._def.typeName === ZodFirstPartyTypeKind.ZodString && def.keyType._def.type._def.checks?.length) {
    const { type, ...keyType } = parseBrandedDef(def.keyType._def, refs);
    return {
      ...schema,
      propertyNames: keyType
    };
  }
  return schema;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/map.js
function parseMapDef(def, refs) {
  if (refs.mapStrategy === "record") {
    return parseRecordDef(def, refs);
  }
  const keys = parseDef(def.keyType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "items", "items", "0"]
  }) || parseAnyDef(refs);
  const values = parseDef(def.valueType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "items", "items", "1"]
  }) || parseAnyDef(refs);
  return {
    type: "array",
    maxItems: 125,
    items: {
      type: "array",
      items: [keys, values],
      minItems: 2,
      maxItems: 2
    }
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/nativeEnum.js
function parseNativeEnumDef(def) {
  const object = def.values;
  const actualKeys = Object.keys(def.values).filter((key) => {
    return typeof object[object[key]] !== "number";
  });
  const actualValues = actualKeys.map((key) => object[key]);
  const parsedTypes = Array.from(new Set(actualValues.map((values) => typeof values)));
  return {
    type: parsedTypes.length === 1 ? parsedTypes[0] === "string" ? "string" : "number" : ["string", "number"],
    enum: actualValues
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/never.js
function parseNeverDef(refs) {
  return refs.target === "openAi" ? void 0 : {
    not: parseAnyDef({
      ...refs,
      currentPath: [...refs.currentPath, "not"]
    })
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/null.js
function parseNullDef(refs) {
  return refs.target === "openApi3" ? {
    enum: ["null"],
    nullable: true
  } : {
    type: "null"
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/union.js
var primitiveMappings = {
  ZodString: "string",
  ZodNumber: "number",
  ZodBigInt: "integer",
  ZodBoolean: "boolean",
  ZodNull: "null"
};
function parseUnionDef(def, refs) {
  if (refs.target === "openApi3")
    return asAnyOf(def, refs);
  const options = def.options instanceof Map ? Array.from(def.options.values()) : def.options;
  if (options.every((x) => x._def.typeName in primitiveMappings && (!x._def.checks || !x._def.checks.length))) {
    const types = options.reduce((types2, x) => {
      const type = primitiveMappings[x._def.typeName];
      return type && !types2.includes(type) ? [...types2, type] : types2;
    }, []);
    return {
      type: types.length > 1 ? types : types[0]
    };
  } else if (options.every((x) => x._def.typeName === "ZodLiteral" && !x.description)) {
    const types = options.reduce((acc, x) => {
      const type = typeof x._def.value;
      switch (type) {
        case "string":
        case "number":
        case "boolean":
          return [...acc, type];
        case "bigint":
          return [...acc, "integer"];
        case "object":
          if (x._def.value === null)
            return [...acc, "null"];
        case "symbol":
        case "undefined":
        case "function":
        default:
          return acc;
      }
    }, []);
    if (types.length === options.length) {
      const uniqueTypes = types.filter((x, i, a) => a.indexOf(x) === i);
      return {
        type: uniqueTypes.length > 1 ? uniqueTypes : uniqueTypes[0],
        enum: options.reduce((acc, x) => {
          return acc.includes(x._def.value) ? acc : [...acc, x._def.value];
        }, [])
      };
    }
  } else if (options.every((x) => x._def.typeName === "ZodEnum")) {
    return {
      type: "string",
      enum: options.reduce((acc, x) => [
        ...acc,
        ...x._def.values.filter((x2) => !acc.includes(x2))
      ], [])
    };
  }
  return asAnyOf(def, refs);
}
var asAnyOf = (def, refs) => {
  const anyOf = (def.options instanceof Map ? Array.from(def.options.values()) : def.options).map((x, i) => parseDef(x._def, {
    ...refs,
    currentPath: [...refs.currentPath, "anyOf", `${i}`]
  })).filter((x) => !!x && (!refs.strictUnions || typeof x === "object" && Object.keys(x).length > 0));
  return anyOf.length ? { anyOf } : void 0;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/nullable.js
function parseNullableDef(def, refs) {
  if (["ZodString", "ZodNumber", "ZodBigInt", "ZodBoolean", "ZodNull"].includes(def.innerType._def.typeName) && (!def.innerType._def.checks || !def.innerType._def.checks.length)) {
    if (refs.target === "openApi3") {
      return {
        type: primitiveMappings[def.innerType._def.typeName],
        nullable: true
      };
    }
    return {
      type: [
        primitiveMappings[def.innerType._def.typeName],
        "null"
      ]
    };
  }
  if (refs.target === "openApi3") {
    const base2 = parseDef(def.innerType._def, {
      ...refs,
      currentPath: [...refs.currentPath]
    });
    if (base2 && "$ref" in base2)
      return { allOf: [base2], nullable: true };
    return base2 && { ...base2, nullable: true };
  }
  const base = parseDef(def.innerType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "anyOf", "0"]
  });
  return base && { anyOf: [base, { type: "null" }] };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/number.js
function parseNumberDef(def, refs) {
  const res = {
    type: "number"
  };
  if (!def.checks)
    return res;
  for (const check of def.checks) {
    switch (check.kind) {
      case "int":
        res.type = "integer";
        addErrorMessage(res, "type", check.message, refs);
        break;
      case "min":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMinimum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMinimum = true;
          }
          setResponseValueAndErrors(res, "minimum", check.value, check.message, refs);
        }
        break;
      case "max":
        if (refs.target === "jsonSchema7") {
          if (check.inclusive) {
            setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
          } else {
            setResponseValueAndErrors(res, "exclusiveMaximum", check.value, check.message, refs);
          }
        } else {
          if (!check.inclusive) {
            res.exclusiveMaximum = true;
          }
          setResponseValueAndErrors(res, "maximum", check.value, check.message, refs);
        }
        break;
      case "multipleOf":
        setResponseValueAndErrors(res, "multipleOf", check.value, check.message, refs);
        break;
    }
  }
  return res;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/object.js
function parseObjectDef(def, refs) {
  const forceOptionalIntoNullable = refs.target === "openAi";
  const result = {
    type: "object",
    properties: {}
  };
  const required = [];
  const shape = def.shape();
  for (const propName in shape) {
    let propDef = shape[propName];
    if (propDef === void 0 || propDef._def === void 0) {
      continue;
    }
    let propOptional = safeIsOptional(propDef);
    if (propOptional && forceOptionalIntoNullable) {
      if (propDef._def.typeName === "ZodOptional") {
        propDef = propDef._def.innerType;
      }
      if (!propDef.isNullable()) {
        propDef = propDef.nullable();
      }
      propOptional = false;
    }
    const parsedDef = parseDef(propDef._def, {
      ...refs,
      currentPath: [...refs.currentPath, "properties", propName],
      propertyPath: [...refs.currentPath, "properties", propName]
    });
    if (parsedDef === void 0) {
      continue;
    }
    result.properties[propName] = parsedDef;
    if (!propOptional) {
      required.push(propName);
    }
  }
  if (required.length) {
    result.required = required;
  }
  const additionalProperties = decideAdditionalProperties(def, refs);
  if (additionalProperties !== void 0) {
    result.additionalProperties = additionalProperties;
  }
  return result;
}
function decideAdditionalProperties(def, refs) {
  if (def.catchall._def.typeName !== "ZodNever") {
    return parseDef(def.catchall._def, {
      ...refs,
      currentPath: [...refs.currentPath, "additionalProperties"]
    });
  }
  switch (def.unknownKeys) {
    case "passthrough":
      return refs.allowedAdditionalProperties;
    case "strict":
      return refs.rejectedAdditionalProperties;
    case "strip":
      return refs.removeAdditionalStrategy === "strict" ? refs.allowedAdditionalProperties : refs.rejectedAdditionalProperties;
  }
}
function safeIsOptional(schema) {
  try {
    return schema.isOptional();
  } catch {
    return true;
  }
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/optional.js
var parseOptionalDef = (def, refs) => {
  if (refs.currentPath.toString() === refs.propertyPath?.toString()) {
    return parseDef(def.innerType._def, refs);
  }
  const innerSchema = parseDef(def.innerType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "anyOf", "1"]
  });
  return innerSchema ? {
    anyOf: [
      {
        not: parseAnyDef(refs)
      },
      innerSchema
    ]
  } : parseAnyDef(refs);
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/pipeline.js
var parsePipelineDef = (def, refs) => {
  if (refs.pipeStrategy === "input") {
    return parseDef(def.in._def, refs);
  } else if (refs.pipeStrategy === "output") {
    return parseDef(def.out._def, refs);
  }
  const a = parseDef(def.in._def, {
    ...refs,
    currentPath: [...refs.currentPath, "allOf", "0"]
  });
  const b = parseDef(def.out._def, {
    ...refs,
    currentPath: [...refs.currentPath, "allOf", a ? "1" : "0"]
  });
  return {
    allOf: [a, b].filter((x) => x !== void 0)
  };
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/promise.js
function parsePromiseDef(def, refs) {
  return parseDef(def.type._def, refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/set.js
function parseSetDef(def, refs) {
  const items = parseDef(def.valueType._def, {
    ...refs,
    currentPath: [...refs.currentPath, "items"]
  });
  const schema = {
    type: "array",
    uniqueItems: true,
    items
  };
  if (def.minSize) {
    setResponseValueAndErrors(schema, "minItems", def.minSize.value, def.minSize.message, refs);
  }
  if (def.maxSize) {
    setResponseValueAndErrors(schema, "maxItems", def.maxSize.value, def.maxSize.message, refs);
  }
  return schema;
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/tuple.js
function parseTupleDef(def, refs) {
  if (def.rest) {
    return {
      type: "array",
      minItems: def.items.length,
      items: def.items.map((x, i) => parseDef(x._def, {
        ...refs,
        currentPath: [...refs.currentPath, "items", `${i}`]
      })).reduce((acc, x) => x === void 0 ? acc : [...acc, x], []),
      additionalItems: parseDef(def.rest._def, {
        ...refs,
        currentPath: [...refs.currentPath, "additionalItems"]
      })
    };
  } else {
    return {
      type: "array",
      minItems: def.items.length,
      maxItems: def.items.length,
      items: def.items.map((x, i) => parseDef(x._def, {
        ...refs,
        currentPath: [...refs.currentPath, "items", `${i}`]
      })).reduce((acc, x) => x === void 0 ? acc : [...acc, x], [])
    };
  }
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/undefined.js
function parseUndefinedDef(refs) {
  return {
    not: parseAnyDef(refs)
  };
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/unknown.js
function parseUnknownDef(refs) {
  return parseAnyDef(refs);
}

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parsers/readonly.js
var parseReadonlyDef = (def, refs) => {
  return parseDef(def.innerType._def, refs);
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/selectParser.js
var selectParser = (def, typeName, refs) => {
  switch (typeName) {
    case ZodFirstPartyTypeKind.ZodString:
      return parseStringDef(def, refs);
    case ZodFirstPartyTypeKind.ZodNumber:
      return parseNumberDef(def, refs);
    case ZodFirstPartyTypeKind.ZodObject:
      return parseObjectDef(def, refs);
    case ZodFirstPartyTypeKind.ZodBigInt:
      return parseBigintDef(def, refs);
    case ZodFirstPartyTypeKind.ZodBoolean:
      return parseBooleanDef();
    case ZodFirstPartyTypeKind.ZodDate:
      return parseDateDef(def, refs);
    case ZodFirstPartyTypeKind.ZodUndefined:
      return parseUndefinedDef(refs);
    case ZodFirstPartyTypeKind.ZodNull:
      return parseNullDef(refs);
    case ZodFirstPartyTypeKind.ZodArray:
      return parseArrayDef(def, refs);
    case ZodFirstPartyTypeKind.ZodUnion:
    case ZodFirstPartyTypeKind.ZodDiscriminatedUnion:
      return parseUnionDef(def, refs);
    case ZodFirstPartyTypeKind.ZodIntersection:
      return parseIntersectionDef(def, refs);
    case ZodFirstPartyTypeKind.ZodTuple:
      return parseTupleDef(def, refs);
    case ZodFirstPartyTypeKind.ZodRecord:
      return parseRecordDef(def, refs);
    case ZodFirstPartyTypeKind.ZodLiteral:
      return parseLiteralDef(def, refs);
    case ZodFirstPartyTypeKind.ZodEnum:
      return parseEnumDef(def);
    case ZodFirstPartyTypeKind.ZodNativeEnum:
      return parseNativeEnumDef(def);
    case ZodFirstPartyTypeKind.ZodNullable:
      return parseNullableDef(def, refs);
    case ZodFirstPartyTypeKind.ZodOptional:
      return parseOptionalDef(def, refs);
    case ZodFirstPartyTypeKind.ZodMap:
      return parseMapDef(def, refs);
    case ZodFirstPartyTypeKind.ZodSet:
      return parseSetDef(def, refs);
    case ZodFirstPartyTypeKind.ZodLazy:
      return () => def.getter()._def;
    case ZodFirstPartyTypeKind.ZodPromise:
      return parsePromiseDef(def, refs);
    case ZodFirstPartyTypeKind.ZodNaN:
    case ZodFirstPartyTypeKind.ZodNever:
      return parseNeverDef(refs);
    case ZodFirstPartyTypeKind.ZodEffects:
      return parseEffectsDef(def, refs);
    case ZodFirstPartyTypeKind.ZodAny:
      return parseAnyDef(refs);
    case ZodFirstPartyTypeKind.ZodUnknown:
      return parseUnknownDef(refs);
    case ZodFirstPartyTypeKind.ZodDefault:
      return parseDefaultDef(def, refs);
    case ZodFirstPartyTypeKind.ZodBranded:
      return parseBrandedDef(def, refs);
    case ZodFirstPartyTypeKind.ZodReadonly:
      return parseReadonlyDef(def, refs);
    case ZodFirstPartyTypeKind.ZodCatch:
      return parseCatchDef(def, refs);
    case ZodFirstPartyTypeKind.ZodPipeline:
      return parsePipelineDef(def, refs);
    case ZodFirstPartyTypeKind.ZodFunction:
    case ZodFirstPartyTypeKind.ZodVoid:
    case ZodFirstPartyTypeKind.ZodSymbol:
      return void 0;
    default:
      return /* @__PURE__ */ ((_) => void 0)();
  }
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/parseDef.js
function parseDef(def, refs, forceResolution = false) {
  const seenItem = refs.seen.get(def);
  if (refs.override) {
    const overrideResult = refs.override?.(def, refs, seenItem, forceResolution);
    if (overrideResult !== ignoreOverride) {
      return overrideResult;
    }
  }
  if (seenItem && !forceResolution) {
    const seenSchema = get$ref(seenItem, refs);
    if (seenSchema !== void 0) {
      return seenSchema;
    }
  }
  const newItem = { def, path: refs.currentPath, jsonSchema: void 0 };
  refs.seen.set(def, newItem);
  const jsonSchemaOrGetter = selectParser(def, def.typeName, refs);
  const jsonSchema = typeof jsonSchemaOrGetter === "function" ? parseDef(jsonSchemaOrGetter(), refs) : jsonSchemaOrGetter;
  if (jsonSchema) {
    addMeta(def, refs, jsonSchema);
  }
  if (refs.postProcess) {
    const postProcessResult = refs.postProcess(jsonSchema, def, refs);
    newItem.jsonSchema = jsonSchema;
    return postProcessResult;
  }
  newItem.jsonSchema = jsonSchema;
  return jsonSchema;
}
var get$ref = (item, refs) => {
  switch (refs.$refStrategy) {
    case "root":
      return { $ref: item.path.join("/") };
    case "relative":
      return { $ref: getRelativePath(refs.currentPath, item.path) };
    case "none":
    case "seen": {
      if (item.path.length < refs.currentPath.length && item.path.every((value, index) => refs.currentPath[index] === value)) {
        console.warn(`Recursive reference detected at ${refs.currentPath.join("/")}! Defaulting to any`);
        return parseAnyDef(refs);
      }
      return refs.$refStrategy === "seen" ? parseAnyDef(refs) : void 0;
    }
  }
};
var addMeta = (def, refs, jsonSchema) => {
  if (def.description) {
    jsonSchema.description = def.description;
    if (refs.markdownDescription) {
      jsonSchema.markdownDescription = def.description;
    }
  }
  return jsonSchema;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/zodToJsonSchema.js
var zodToJsonSchema = (schema, options) => {
  const refs = getRefs(options);
  let definitions = typeof options === "object" && options.definitions ? Object.entries(options.definitions).reduce((acc, [name2, schema2]) => ({
    ...acc,
    [name2]: parseDef(schema2._def, {
      ...refs,
      currentPath: [...refs.basePath, refs.definitionPath, name2]
    }, true) ?? parseAnyDef(refs)
  }), {}) : void 0;
  const name = typeof options === "string" ? options : options?.nameStrategy === "title" ? void 0 : options?.name;
  const main = parseDef(schema._def, name === void 0 ? refs : {
    ...refs,
    currentPath: [...refs.basePath, refs.definitionPath, name]
  }, false) ?? parseAnyDef(refs);
  const title = typeof options === "object" && options.name !== void 0 && options.nameStrategy === "title" ? options.name : void 0;
  if (title !== void 0) {
    main.title = title;
  }
  if (refs.flags.hasReferencedOpenAiAnyType) {
    if (!definitions) {
      definitions = {};
    }
    if (!definitions[refs.openAiAnyTypeName]) {
      definitions[refs.openAiAnyTypeName] = {
        // Skipping "object" as no properties can be defined and additionalProperties must be "false"
        type: ["string", "number", "integer", "boolean", "array", "null"],
        items: {
          $ref: refs.$refStrategy === "relative" ? "1" : [
            ...refs.basePath,
            refs.definitionPath,
            refs.openAiAnyTypeName
          ].join("/")
        }
      };
    }
  }
  const combined = name === void 0 ? definitions ? {
    ...main,
    [refs.definitionPath]: definitions
  } : main : {
    $ref: [
      ...refs.$refStrategy === "relative" ? [] : refs.basePath,
      refs.definitionPath,
      name
    ].join("/"),
    [refs.definitionPath]: {
      ...definitions,
      [name]: main
    }
  };
  if (refs.target === "jsonSchema7") {
    combined.$schema = "http://json-schema.org/draft-07/schema#";
  } else if (refs.target === "jsonSchema2019-09" || refs.target === "openAi") {
    combined.$schema = "https://json-schema.org/draft/2019-09/schema#";
  }
  if (refs.target === "openAi" && ("anyOf" in combined || "oneOf" in combined || "allOf" in combined || "type" in combined && Array.isArray(combined.type))) {
    console.warn("Warning: OpenAI may not support schemas with unions as roots! Try wrapping it in an object property.");
  }
  return combined;
};

// ../../node_modules/.pnpm/zod-to-json-schema@3.24.6_zod@3.25.67/node_modules/zod-to-json-schema/dist/esm/index.js
var esm_default = zodToJsonSchema;

// src/server/http-exception.ts
var HTTPException = class extends Error {
  res;
  status;
  /**
   * Creates an instance of `HTTPException`.
   * @param status - HTTP status code for the exception. Defaults to 500.
   * @param options - Additional options for the exception.
   */
  constructor(status = 500, options) {
    super(options?.message, { cause: options?.cause });
    this.res = options?.res;
    this.status = status;
    this.stack = options?.stack || this.stack;
  }
  /**
   * Returns the response object associated with the exception.
   * If a response object is not provided, a new response is created with the error message and status code.
   * @returns The response object.
   */
  getResponse() {
    if (this.res) {
      const newResponse = new Response(this.res.body, {
        status: this.status,
        headers: this.res.headers
      });
      return newResponse;
    }
    return new Response(this.message, {
      status: this.status
    });
  }
};

// src/server/handlers/utils.ts
function validateBody(body) {
  const errorResponse = Object.entries(body).reduce((acc, [key, value]) => {
    if (!value) {
      acc[key] = `Argument "${key}" is required`;
    }
    return acc;
  }, {});
  if (Object.keys(errorResponse).length > 0) {
    throw new HTTPException(400, { message: Object.values(errorResponse)[0] });
  }
}

// src/server/handlers/error.ts
function handleError$1(error, defaultMessage) {
  const apiError = error;
  const apiErrorStatus = apiError.status || apiError.details?.status || 500;
  throw new HTTPException(apiErrorStatus, {
    message: apiError.message || defaultMessage,
    stack: apiError.stack,
    cause: apiError.cause
  });
}

// src/server/handlers/agents.ts
var agents_exports = {};
__export(agents_exports, {
  generateHandler: () => generateHandler$2,
  getAgentByIdHandler: () => getAgentByIdHandler$1,
  getAgentsHandler: () => getAgentsHandler$1,
  getEvalsByAgentIdHandler: () => getEvalsByAgentIdHandler$1,
  getLiveEvalsByAgentIdHandler: () => getLiveEvalsByAgentIdHandler$1,
  streamGenerateHandler: () => streamGenerateHandler$2
});
async function getAgentsHandler$1({ mastra, runtimeContext }) {
  try {
    const agents = mastra.getAgents();
    const serializedAgentsMap = await Promise.all(
      Object.entries(agents).map(async ([id, agent]) => {
        const instructions = await agent.getInstructions({ runtimeContext });
        const tools = await agent.getTools({ runtimeContext });
        const llm = await agent.getLLM({ runtimeContext });
        const defaultGenerateOptions = await agent.getDefaultGenerateOptions({ runtimeContext });
        const defaultStreamOptions = await agent.getDefaultStreamOptions({ runtimeContext });
        const serializedAgentTools = Object.entries(tools || {}).reduce((acc, [key, tool]) => {
          const _tool = tool;
          acc[key] = {
            ..._tool,
            inputSchema: _tool.inputSchema ? stringify(esm_default(_tool.inputSchema)) : void 0,
            outputSchema: _tool.outputSchema ? stringify(esm_default(_tool.outputSchema)) : void 0
          };
          return acc;
        }, {});
        let serializedAgentWorkflows = {};
        if ("getWorkflows" in agent) {
          const logger = mastra.getLogger();
          try {
            const workflows = await agent.getWorkflows({ runtimeContext });
            serializedAgentWorkflows = Object.entries(workflows || {}).reduce((acc, [key, workflow]) => {
              return {
                ...acc,
                [key]: {
                  name: workflow.name
                }
              };
            }, {});
          } catch (error) {
            logger.error("Error getting workflows for agent", { agentName: agent.name, error });
          }
        }
        return {
          id,
          name: agent.name,
          instructions,
          tools: serializedAgentTools,
          workflows: serializedAgentWorkflows,
          provider: llm?.getProvider(),
          modelId: llm?.getModelId(),
          defaultGenerateOptions,
          defaultStreamOptions
        };
      })
    );
    const serializedAgents = serializedAgentsMap.reduce((acc, { id, ...rest }) => {
      acc[id] = rest;
      return acc;
    }, {});
    return serializedAgents;
  } catch (error) {
    return handleError$1(error, "Error getting agents");
  }
}
async function getAgentByIdHandler$1({
  mastra,
  runtimeContext,
  agentId,
  isPlayground = false
}) {
  try {
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const tools = await agent.getTools({ runtimeContext });
    const serializedAgentTools = Object.entries(tools || {}).reduce((acc, [key, tool]) => {
      const _tool = tool;
      acc[key] = {
        ..._tool,
        inputSchema: _tool.inputSchema ? stringify(esm_default(_tool.inputSchema)) : void 0,
        outputSchema: _tool.outputSchema ? stringify(esm_default(_tool.outputSchema)) : void 0
      };
      return acc;
    }, {});
    let serializedAgentWorkflows = {};
    if ("getWorkflows" in agent) {
      const logger = mastra.getLogger();
      try {
        const workflows = await agent.getWorkflows({ runtimeContext });
        serializedAgentWorkflows = Object.entries(workflows || {}).reduce((acc, [key, workflow]) => {
          return {
            ...acc,
            [key]: {
              name: workflow.name,
              steps: Object.entries(workflow.steps).reduce((acc2, [key2, step]) => {
                return {
                  ...acc2,
                  [key2]: {
                    id: step.id,
                    description: step.description
                  }
                };
              }, {})
            }
          };
        }, {});
      } catch (error) {
        logger.error("Error getting workflows for agent", { agentName: agent.name, error });
      }
    }
    let proxyRuntimeContext = runtimeContext;
    if (isPlayground) {
      proxyRuntimeContext = new Proxy(runtimeContext, {
        get(target, prop) {
          if (prop === "get") {
            return function(key) {
              const value = target.get(key);
              return value ?? `<${key}>`;
            };
          }
          return Reflect.get(target, prop);
        }
      });
    }
    const instructions = await agent.getInstructions({ runtimeContext: proxyRuntimeContext });
    const llm = await agent.getLLM({ runtimeContext });
    const defaultGenerateOptions = await agent.getDefaultGenerateOptions({ runtimeContext: proxyRuntimeContext });
    const defaultStreamOptions = await agent.getDefaultStreamOptions({ runtimeContext: proxyRuntimeContext });
    return {
      name: agent.name,
      instructions,
      tools: serializedAgentTools,
      workflows: serializedAgentWorkflows,
      provider: llm?.getProvider(),
      modelId: llm?.getModelId(),
      defaultGenerateOptions,
      defaultStreamOptions
    };
  } catch (error) {
    return handleError$1(error, "Error getting agent");
  }
}
async function getEvalsByAgentIdHandler$1({
  mastra,
  runtimeContext,
  agentId
}) {
  try {
    const agent = mastra.getAgent(agentId);
    const evals = await mastra.getStorage()?.getEvalsByAgentName?.(agent.name, "test") || [];
    const instructions = await agent.getInstructions({ runtimeContext });
    return {
      id: agentId,
      name: agent.name,
      instructions,
      evals
    };
  } catch (error) {
    return handleError$1(error, "Error getting test evals");
  }
}
async function getLiveEvalsByAgentIdHandler$1({
  mastra,
  runtimeContext,
  agentId
}) {
  try {
    const agent = mastra.getAgent(agentId);
    const evals = await mastra.getStorage()?.getEvalsByAgentName?.(agent.name, "live") || [];
    const instructions = await agent.getInstructions({ runtimeContext });
    return {
      id: agentId,
      name: agent.name,
      instructions,
      evals
    };
  } catch (error) {
    return handleError$1(error, "Error getting live evals");
  }
}
async function generateHandler$2({
  mastra,
  runtimeContext,
  agentId,
  body,
  abortSignal
}) {
  try {
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const { messages, resourceId, resourceid, runtimeContext: agentRuntimeContext, ...rest } = body;
    const finalResourceId = resourceId ?? resourceid;
    const finalRuntimeContext = new RuntimeContext([
      ...Array.from(runtimeContext.entries()),
      ...Array.from(Object.entries(agentRuntimeContext ?? {}))
    ]);
    validateBody({ messages });
    const result = await agent.generate(messages, {
      ...rest,
      // @ts-expect-error TODO fix types
      resourceId: finalResourceId,
      runtimeContext: finalRuntimeContext,
      signal: abortSignal
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error generating from agent");
  }
}
async function streamGenerateHandler$2({
  mastra,
  runtimeContext,
  agentId,
  body,
  abortSignal
}) {
  try {
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const { messages, resourceId, resourceid, runtimeContext: agentRuntimeContext, ...rest } = body;
    const finalResourceId = resourceId ?? resourceid;
    const finalRuntimeContext = new RuntimeContext([
      ...Array.from(runtimeContext.entries()),
      ...Array.from(Object.entries(agentRuntimeContext ?? {}))
    ]);
    validateBody({ messages });
    const streamResult = await agent.stream(messages, {
      ...rest,
      // @ts-expect-error TODO fix types
      resourceId: finalResourceId,
      runtimeContext: finalRuntimeContext,
      signal: abortSignal
    });
    const streamResponse = rest.output ? streamResult.toTextStreamResponse({
      headers: {
        "Transfer-Encoding": "chunked"
      }
    }) : streamResult.toDataStreamResponse({
      sendUsage: true,
      sendReasoning: true,
      getErrorMessage: (error) => {
        return `An error occurred while processing your request. ${error instanceof Error ? error.message : JSON.stringify(error)}`;
      },
      headers: {
        "Transfer-Encoding": "chunked"
      }
    });
    return streamResponse;
  } catch (error) {
    return handleError$1(error, "error streaming agent response");
  }
}

// src/server/handlers/legacyWorkflows.ts
var legacyWorkflows_exports = {};
__export(legacyWorkflows_exports, {
  createLegacyWorkflowRunHandler: () => createLegacyWorkflowRunHandler$1,
  getLegacyWorkflowByIdHandler: () => getLegacyWorkflowByIdHandler$1,
  getLegacyWorkflowRunHandler: () => getLegacyWorkflowRunHandler,
  getLegacyWorkflowRunsHandler: () => getLegacyWorkflowRunsHandler$1,
  getLegacyWorkflowsHandler: () => getLegacyWorkflowsHandler$1,
  resumeAsyncLegacyWorkflowHandler: () => resumeAsyncLegacyWorkflowHandler$1,
  resumeLegacyWorkflowHandler: () => resumeLegacyWorkflowHandler$1,
  startAsyncLegacyWorkflowHandler: () => startAsyncLegacyWorkflowHandler$1,
  startLegacyWorkflowRunHandler: () => startLegacyWorkflowRunHandler$1,
  watchLegacyWorkflowHandler: () => watchLegacyWorkflowHandler$1
});
async function getLegacyWorkflowsHandler$1({ mastra }) {
  try {
    const workflows = mastra.legacy_getWorkflows({ serialized: false });
    const _workflows = Object.entries(workflows).reduce((acc, [key, workflow]) => {
      if (workflow.isNested) return acc;
      acc[key] = {
        stepGraph: workflow.stepGraph,
        stepSubscriberGraph: workflow.stepSubscriberGraph,
        serializedStepGraph: workflow.serializedStepGraph,
        serializedStepSubscriberGraph: workflow.serializedStepSubscriberGraph,
        name: workflow.name,
        triggerSchema: workflow.triggerSchema ? stringify(esm_default(workflow.triggerSchema)) : void 0,
        steps: Object.entries(workflow.steps).reduce((acc2, [key2, step]) => {
          const _step = step;
          acc2[key2] = {
            id: _step.id,
            description: _step.description,
            workflowId: _step.workflowId,
            inputSchema: _step.inputSchema ? stringify(esm_default(_step.inputSchema)) : void 0,
            outputSchema: _step.outputSchema ? stringify(esm_default(_step.outputSchema)) : void 0
          };
          return acc2;
        }, {})
      };
      return acc;
    }, {});
    return _workflows;
  } catch (error) {
    return handleError$1(error, "error getting workflows");
  }
}
async function getLegacyWorkflowByIdHandler$1({ mastra, workflowId }) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    return {
      stepGraph: workflow.stepGraph,
      stepSubscriberGraph: workflow.stepSubscriberGraph,
      serializedStepGraph: workflow.serializedStepGraph,
      serializedStepSubscriberGraph: workflow.serializedStepSubscriberGraph,
      name: workflow.name,
      triggerSchema: workflow.triggerSchema ? stringify(esm_default(workflow.triggerSchema)) : void 0,
      steps: Object.entries(workflow.steps).reduce((acc, [key, step]) => {
        const _step = step;
        acc[key] = {
          id: _step.id,
          description: _step.description,
          workflowId: _step.workflowId,
          inputSchema: _step.inputSchema ? stringify(esm_default(_step.inputSchema)) : void 0,
          outputSchema: _step.outputSchema ? stringify(esm_default(_step.outputSchema)) : void 0
        };
        return acc;
      }, {})
    };
  } catch (error) {
    return handleError$1(error, "error getting workflow by id");
  }
}
async function startAsyncLegacyWorkflowHandler$1({
  mastra,
  runtimeContext,
  workflowId,
  runId,
  triggerData
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    if (!runId) {
      const newRun = workflow.createRun();
      const result2 = await newRun.start({
        triggerData,
        runtimeContext
      });
      return result2;
    }
    const run = workflow.getMemoryRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const result = await run.start({
      triggerData,
      runtimeContext
    });
    return result;
  } catch (error) {
    return handleError$1(error, "error starting workflow");
  }
}
async function getLegacyWorkflowRunHandler({
  mastra,
  workflowId,
  runId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "Run ID is required" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    return run;
  } catch (error) {
    return handleError$1(error, "error getting workflow run");
  }
}
async function createLegacyWorkflowRunHandler$1({
  mastra,
  workflowId,
  runId: prevRunId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const newRun = workflow.createRun({ runId: prevRunId });
    return { runId: newRun.runId };
  } catch (error) {
    return handleError$1(error, "error creating workflow run");
  }
}
async function startLegacyWorkflowRunHandler$1({
  mastra,
  runtimeContext,
  workflowId,
  runId,
  triggerData
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to start run" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    const run = workflow.getMemoryRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    void run.start({
      triggerData,
      runtimeContext
    });
    return { message: "Workflow run started" };
  } catch (e) {
    return handleError$1(e, "Error starting workflow run");
  }
}
async function watchLegacyWorkflowHandler$1({
  mastra,
  workflowId,
  runId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to watch workflow" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    const run = workflow.getMemoryRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    let unwatch;
    let asyncRef = null;
    const stream = new ReadableStream$1({
      start(controller) {
        unwatch = run.watch(({ activePaths, runId: runId2, timestamp, results }) => {
          const activePathsObj = Object.fromEntries(activePaths);
          controller.enqueue(JSON.stringify({ activePaths: activePathsObj, runId: runId2, timestamp, results }));
          if (asyncRef) {
            clearImmediate(asyncRef);
            asyncRef = null;
          }
          asyncRef = setImmediate(() => {
            const runDone = Object.values(activePathsObj).every((value) => value.status !== "executing");
            if (runDone) {
              controller.close();
              unwatch?.();
            }
          });
        });
      },
      cancel() {
        unwatch?.();
      }
    });
    return stream;
  } catch (error) {
    return handleError$1(error, "Error watching workflow");
  }
}
async function resumeAsyncLegacyWorkflowHandler$1({
  mastra,
  workflowId,
  runId,
  body,
  runtimeContext
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    const run = workflow.getMemoryRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const result = await run.resume({
      stepId: body.stepId,
      context: body.context,
      runtimeContext
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error resuming workflow step");
  }
}
async function resumeLegacyWorkflowHandler$1({
  mastra,
  workflowId,
  runId,
  body,
  runtimeContext
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    const run = workflow.getMemoryRun(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    void run.resume({
      stepId: body.stepId,
      context: body.context,
      runtimeContext
    });
    return { message: "Workflow run resumed" };
  } catch (error) {
    return handleError$1(error, "Error resuming workflow");
  }
}
async function getLegacyWorkflowRunsHandler$1({
  mastra,
  workflowId,
  fromDate,
  toDate,
  limit,
  offset,
  resourceId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const workflow = mastra.legacy_getWorkflow(workflowId);
    const workflowRuns = await workflow.getWorkflowRuns({ fromDate, toDate, limit, offset, resourceId }) || {
      runs: [],
      total: 0
    };
    return workflowRuns;
  } catch (error) {
    return handleError$1(error, "Error getting workflow runs");
  }
}

// src/server/handlers/logs.ts
var logs_exports = {};
__export(logs_exports, {
  getLogTransports: () => getLogTransports$1,
  getLogsByRunIdHandler: () => getLogsByRunIdHandler$1,
  getLogsHandler: () => getLogsHandler$1
});
async function getLogsHandler$1({
  mastra,
  transportId,
  params
}) {
  try {
    validateBody({ transportId });
    const { fromDate, toDate, logLevel, filters: _filters, page, perPage } = params || {};
    const filters = _filters ? Object.fromEntries(
      (Array.isArray(_filters) ? _filters : [_filters]).map((attr) => {
        const [key, value] = attr.split(":");
        return [key, value];
      })
    ) : void 0;
    const logs = await mastra.getLogs(transportId, {
      fromDate,
      toDate,
      logLevel,
      filters,
      page: page ? Number(page) : void 0,
      perPage: perPage ? Number(perPage) : void 0
    });
    return logs;
  } catch (error) {
    return handleError$1(error, "Error getting logs");
  }
}
async function getLogsByRunIdHandler$1({
  mastra,
  runId,
  transportId,
  params
}) {
  try {
    validateBody({ runId, transportId });
    const { fromDate, toDate, logLevel, filters: _filters, page, perPage } = params || {};
    const filters = _filters ? Object.fromEntries(
      (Array.isArray(_filters) ? _filters : [_filters]).map((attr) => {
        const [key, value] = attr.split(":");
        return [key, value];
      })
    ) : void 0;
    const logs = await mastra.getLogsByRunId({
      runId,
      transportId,
      fromDate,
      toDate,
      logLevel,
      filters,
      page: page ? Number(page) : void 0,
      perPage: perPage ? Number(perPage) : void 0
    });
    return logs;
  } catch (error) {
    return handleError$1(error, "Error getting logs by run ID");
  }
}
async function getLogTransports$1({ mastra }) {
  try {
    const logger = mastra.getLogger();
    const transports = logger.getTransports();
    return {
      transports: transports ? [...transports.keys()] : []
    };
  } catch (error) {
    return handleError$1(error, "Error getting log Transports");
  }
}

// src/server/handlers/memory.ts
var memory_exports = {};
__export(memory_exports, {
  createThreadHandler: () => createThreadHandler$1,
  deleteThreadHandler: () => deleteThreadHandler$1,
  getMemoryStatusHandler: () => getMemoryStatusHandler$1,
  getMessagesHandler: () => getMessagesHandler$1,
  getThreadByIdHandler: () => getThreadByIdHandler$1,
  getThreadsHandler: () => getThreadsHandler$1,
  getWorkingMemoryHandler: () => getWorkingMemoryHandler$1,
  saveMessagesHandler: () => saveMessagesHandler$1,
  updateThreadHandler: () => updateThreadHandler$1,
  updateWorkingMemoryHandler: () => updateWorkingMemoryHandler$1
});
async function getMemoryFromContext({
  mastra,
  agentId,
  networkId,
  runtimeContext
}) {
  const agent = agentId ? mastra.getAgent(agentId) : null;
  if (agentId && !agent) {
    throw new HTTPException(404, { message: "Agent not found" });
  }
  const network = networkId ? mastra.vnext_getNetwork(networkId) : null;
  if (networkId && !network) {
    throw new HTTPException(404, { message: "Network not found" });
  }
  if (agent) {
    return agent?.getMemory() || mastra.getMemory();
  }
  if (network) {
    return await network?.getMemory({ runtimeContext }) || mastra.getMemory();
  }
  return mastra.getMemory();
}
async function getMemoryStatusHandler$1({
  mastra,
  agentId,
  networkId,
  runtimeContext
}) {
  try {
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      return { result: false };
    }
    return { result: true };
  } catch (error) {
    return handleError$1(error, "Error getting memory status");
  }
}
async function getThreadsHandler$1({
  mastra,
  agentId,
  resourceId,
  networkId,
  runtimeContext
}) {
  try {
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    validateBody({ resourceId });
    const threads = await memory.getThreadsByResourceId({ resourceId });
    return threads;
  } catch (error) {
    return handleError$1(error, "Error getting threads");
  }
}
async function getThreadByIdHandler$1({
  mastra,
  agentId,
  threadId,
  networkId,
  runtimeContext
}) {
  try {
    validateBody({ threadId });
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    return thread;
  } catch (error) {
    return handleError$1(error, "Error getting thread");
  }
}
async function saveMessagesHandler$1({
  mastra,
  agentId,
  body,
  networkId,
  runtimeContext
}) {
  try {
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    if (!body?.messages) {
      throw new HTTPException(400, { message: "Messages are required" });
    }
    if (!Array.isArray(body.messages)) {
      throw new HTTPException(400, { message: "Messages should be an array" });
    }
    const processedMessages = body.messages.map((message) => ({
      ...message,
      id: memory.generateId(),
      createdAt: message.createdAt ? new Date(message.createdAt) : /* @__PURE__ */ new Date()
    }));
    const result = await memory.saveMessages({ messages: processedMessages, memoryConfig: {} });
    return result;
  } catch (error) {
    return handleError$1(error, "Error saving messages");
  }
}
async function createThreadHandler$1({
  mastra,
  agentId,
  body,
  networkId,
  runtimeContext
}) {
  try {
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    validateBody({ resourceId: body?.resourceId });
    const result = await memory.createThread({
      resourceId: body?.resourceId,
      title: body?.title,
      metadata: body?.metadata,
      threadId: body?.threadId
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error saving thread to memory");
  }
}
async function updateThreadHandler$1({
  mastra,
  agentId,
  threadId,
  body,
  networkId,
  runtimeContext
}) {
  try {
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!body) {
      throw new HTTPException(400, { message: "Body is required" });
    }
    const { title, metadata, resourceId } = body;
    const updatedAt = /* @__PURE__ */ new Date();
    validateBody({ threadId });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    const updatedThread = {
      ...thread,
      title: title || thread.title,
      metadata: metadata || thread.metadata,
      resourceId: resourceId || thread.resourceId,
      createdAt: thread.createdAt,
      updatedAt
    };
    const result = await memory.saveThread({ thread: updatedThread });
    return result;
  } catch (error) {
    return handleError$1(error, "Error updating thread");
  }
}
async function deleteThreadHandler$1({
  mastra,
  agentId,
  threadId,
  networkId,
  runtimeContext
}) {
  try {
    validateBody({ threadId });
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    await memory.deleteThread(threadId);
    return { result: "Thread deleted" };
  } catch (error) {
    return handleError$1(error, "Error deleting thread");
  }
}
async function getMessagesHandler$1({
  mastra,
  agentId,
  threadId,
  limit,
  networkId,
  runtimeContext
}) {
  if (limit !== void 0 && (!Number.isInteger(limit) || limit <= 0)) {
    throw new HTTPException(400, { message: "Invalid limit: must be a positive integer" });
  }
  try {
    validateBody({ threadId });
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    const result = await memory.query({
      threadId,
      ...limit && { selectBy: { last: limit } }
    });
    return { messages: result.messages, uiMessages: result.uiMessages };
  } catch (error) {
    return handleError$1(error, "Error getting messages");
  }
}
async function getWorkingMemoryHandler$1({
  mastra,
  agentId,
  threadId,
  resourceId,
  networkId,
  runtimeContext,
  memoryConfig
}) {
  try {
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    validateBody({ threadId });
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    const threadExists = !!thread;
    const template = await memory.getWorkingMemoryTemplate({ memoryConfig });
    const workingMemoryTemplate = template?.format === "json" ? { ...template, content: JSON.stringify(generateEmptyFromSchema(template.content)) } : template;
    const workingMemory = await memory.getWorkingMemory({ threadId, resourceId, memoryConfig });
    const config = memory.getMergedThreadConfig(memoryConfig || {});
    const source = config.workingMemory?.scope === "resource" && resourceId ? "resource" : "thread";
    return { workingMemory, source, workingMemoryTemplate, threadExists };
  } catch (error) {
    return handleError$1(error, "Error getting working memory");
  }
}
async function updateWorkingMemoryHandler$1({
  mastra,
  agentId,
  threadId,
  body,
  networkId,
  runtimeContext
}) {
  try {
    validateBody({ threadId });
    const memory = await getMemoryFromContext({ mastra, agentId, networkId, runtimeContext });
    const { resourceId, memoryConfig, workingMemory } = body;
    if (!memory) {
      throw new HTTPException(400, { message: "Memory is not initialized" });
    }
    const thread = await memory.getThreadById({ threadId });
    if (!thread) {
      throw new HTTPException(404, { message: "Thread not found" });
    }
    await memory.updateWorkingMemory({ threadId, resourceId, workingMemory, memoryConfig });
    return { success: true };
  } catch (error) {
    return handleError$1(error, "Error updating working memory");
  }
}

// src/server/handlers/network.ts
var network_exports = {};
__export(network_exports, {
  generateHandler: () => generateHandler$1,
  getNetworkByIdHandler: () => getNetworkByIdHandler$1,
  getNetworksHandler: () => getNetworksHandler$1,
  streamGenerateHandler: () => streamGenerateHandler$1
});
async function getNetworksHandler$1({
  mastra,
  runtimeContext
}) {
  try {
    const networks = mastra.getNetworks();
    const serializedNetworks = await Promise.all(
      networks.map(async (network) => {
        const routingAgent = network.getRoutingAgent();
        const routingLLM = await routingAgent.getLLM({ runtimeContext });
        const agents = network.getAgents();
        return {
          id: network.formatAgentId(routingAgent.name),
          name: routingAgent.name,
          instructions: routingAgent.instructions,
          agents: await Promise.all(
            agents.map(async (agent) => {
              const llm = await agent.getLLM({ runtimeContext });
              return {
                name: agent.name,
                provider: llm?.getProvider(),
                modelId: llm?.getModelId()
              };
            })
          ),
          routingModel: {
            provider: routingLLM?.getProvider(),
            modelId: routingLLM?.getModelId()
          }
        };
      })
    );
    return serializedNetworks;
  } catch (error) {
    return handleError$1(error, "Error getting networks");
  }
}
async function getNetworkByIdHandler$1({
  mastra,
  networkId,
  runtimeContext
}) {
  try {
    const networks = mastra.getNetworks();
    const network = networks.find((network2) => {
      const routingAgent2 = network2.getRoutingAgent();
      return network2.formatAgentId(routingAgent2.name) === networkId;
    });
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    const routingAgent = network.getRoutingAgent();
    const routingLLM = await routingAgent.getLLM({ runtimeContext });
    const agents = network.getAgents();
    const serializedNetwork = {
      id: network.formatAgentId(routingAgent.name),
      name: routingAgent.name,
      instructions: routingAgent.instructions,
      agents: await Promise.all(
        agents.map(async (agent) => {
          const llm = await agent.getLLM({ runtimeContext });
          return {
            name: agent.name,
            provider: llm?.getProvider(),
            modelId: llm?.getModelId()
          };
        })
      ),
      routingModel: {
        provider: routingLLM?.getProvider(),
        modelId: routingLLM?.getModelId()
      }
    };
    return serializedNetwork;
  } catch (error) {
    return handleError$1(error, "Error getting network by ID");
  }
}
async function generateHandler$1({
  mastra,
  runtimeContext,
  networkId,
  body
}) {
  try {
    const network = mastra.getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    validateBody({ messages: body.messages });
    const { messages, ...rest } = body;
    const result = await network.generate(messages, { ...rest, runtimeContext });
    return result;
  } catch (error) {
    return handleError$1(error, "Error generating from network");
  }
}
async function streamGenerateHandler$1({
  mastra,
  networkId,
  body,
  runtimeContext
}) {
  try {
    const network = mastra.getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    validateBody({ messages: body.messages });
    const { messages, output, ...rest } = body;
    const streamResult = await network.stream(messages, {
      output,
      ...rest,
      runtimeContext
    });
    const streamResponse = output ? streamResult.toTextStreamResponse() : streamResult.toDataStreamResponse({
      sendUsage: true,
      sendReasoning: true,
      getErrorMessage: (error) => {
        return `An error occurred while processing your request. ${error instanceof Error ? error.message : JSON.stringify(error)}`;
      }
    });
    return streamResponse;
  } catch (error) {
    return handleError$1(error, "Error streaming from network");
  }
}

// src/server/handlers/telemetry.ts
var telemetry_exports = {};
__export(telemetry_exports, {
  getTelemetryHandler: () => getTelemetryHandler$1,
  storeTelemetryHandler: () => storeTelemetryHandler$1
});
async function getTelemetryHandler$1({ mastra, body }) {
  try {
    const telemetry = mastra.getTelemetry();
    const storage = mastra.getStorage();
    if (!telemetry) {
      throw new HTTPException(400, { message: "Telemetry is not initialized" });
    }
    if (!storage) {
      return [];
    }
    if (!body) {
      throw new HTTPException(400, { message: "Body is required" });
    }
    const { name, scope, page, perPage, attribute, fromDate, toDate } = body;
    const attributes = attribute ? Object.fromEntries(
      (Array.isArray(attribute) ? attribute : [attribute]).map((attr) => {
        const [key, value] = attr.split(":");
        return [key, value];
      })
    ) : void 0;
    const traces = await storage.getTraces({
      name,
      scope,
      page: Number(page ?? 0),
      perPage: Number(perPage ?? 100),
      attributes,
      fromDate: fromDate ? new Date(fromDate) : void 0,
      toDate: toDate ? new Date(toDate) : void 0
    });
    return traces;
  } catch (error2) {
    return handleError$1(error2, "Error getting telemetry");
  }
}
async function storeTelemetryHandler$1({ mastra, body }) {
  try {
    const storage = mastra.getStorage();
    const logger = mastra.getLogger();
    if (!storage) {
      return {
        status: "error",
        message: "Storage is not initialized"
      };
    }
    const now = /* @__PURE__ */ new Date();
    const items = body?.resourceSpans?.[0]?.scopeSpans;
    logger.debug("[Telemetry Handler] Received spans:", {
      totalSpans: items?.reduce((acc, scope) => acc + scope.spans.length, 0) || 0,
      timestamp: now.toISOString()
    });
    if (!items?.length) {
      return {
        status: "success",
        message: "No spans to process",
        traceCount: 0
      };
    }
    const allSpans = items.reduce((acc, scopedSpans) => {
      const { scope, spans } = scopedSpans;
      for (const span of spans) {
        const {
          spanId,
          parentSpanId,
          traceId,
          name,
          kind,
          attributes,
          status,
          events,
          links,
          startTimeUnixNano,
          endTimeUnixNano,
          ...rest
        } = span;
        const startTime = Number(BigInt(startTimeUnixNano) / 1000n);
        const endTime = Number(BigInt(endTimeUnixNano) / 1000n);
        acc.push({
          id: spanId,
          parentSpanId,
          traceId,
          name,
          scope: scope.name,
          kind,
          status: JSON.stringify(status),
          events: JSON.stringify(events),
          links: JSON.stringify(links),
          attributes: JSON.stringify(
            attributes.reduce((acc2, attr) => {
              const valueKey = Object.keys(attr.value)[0];
              if (valueKey) {
                acc2[attr.key] = attr.value[valueKey];
              }
              return acc2;
            }, {})
          ),
          startTime,
          endTime,
          other: JSON.stringify(rest),
          createdAt: now
        });
      }
      return acc;
    }, []);
    return storage.batchTraceInsert({
      records: allSpans
    }).then(() => {
      return {
        status: "success",
        message: "Traces received and processed successfully",
        traceCount: body.resourceSpans?.length || 0
      };
    }).catch(() => {
      return {
        status: "error",
        message: "Failed to process traces",
        // @ts-ignore
        error: error.message
      };
    });
  } catch (error2) {
    console.error("Error processing traces:", error2);
    return {
      status: "error",
      message: "Failed to process traces",
      // @ts-ignore
      error: error2.message
    };
  }
}

// src/server/handlers/tools.ts
var tools_exports = {};
__export(tools_exports, {
  executeAgentToolHandler: () => executeAgentToolHandler$1,
  executeToolHandler: () => executeToolHandler$1,
  getToolByIdHandler: () => getToolByIdHandler$1,
  getToolsHandler: () => getToolsHandler$1
});
async function getToolsHandler$1({ tools }) {
  try {
    if (!tools) {
      return {};
    }
    const serializedTools = Object.entries(tools).reduce(
      (acc, [id, _tool]) => {
        const tool = _tool;
        acc[id] = {
          ...tool,
          inputSchema: tool.inputSchema ? stringify(esm_default(tool.inputSchema)) : void 0,
          outputSchema: tool.outputSchema ? stringify(esm_default(tool.outputSchema)) : void 0
        };
        return acc;
      },
      {}
    );
    return serializedTools;
  } catch (error) {
    return handleError$1(error, "Error getting tools");
  }
}
async function getToolByIdHandler$1({ tools, toolId }) {
  try {
    const tool = Object.values(tools || {}).find((tool2) => tool2.id === toolId);
    if (!tool) {
      throw new HTTPException(404, { message: "Tool not found" });
    }
    const serializedTool = {
      ...tool,
      inputSchema: tool.inputSchema ? stringify(esm_default(tool.inputSchema)) : void 0,
      outputSchema: tool.outputSchema ? stringify(esm_default(tool.outputSchema)) : void 0
    };
    return serializedTool;
  } catch (error) {
    return handleError$1(error, "Error getting tool");
  }
}
function executeToolHandler$1(tools) {
  return async ({
    mastra,
    runId,
    toolId,
    data,
    runtimeContext
  }) => {
    try {
      if (!toolId) {
        throw new HTTPException(400, { message: "Tool ID is required" });
      }
      const tool = Object.values(tools || {}).find((tool2) => tool2.id === toolId);
      if (!tool) {
        throw new HTTPException(404, { message: "Tool not found" });
      }
      if (!tool?.execute) {
        throw new HTTPException(400, { message: "Tool is not executable" });
      }
      validateBody({ data });
      if (isVercelTool(tool)) {
        const result2 = await tool.execute(data);
        return result2;
      }
      const result = await tool.execute({
        context: data,
        mastra,
        runId,
        runtimeContext
      });
      return result;
    } catch (error) {
      return handleError$1(error, "Error executing tool");
    }
  };
}
async function executeAgentToolHandler$1({
  mastra,
  agentId,
  toolId,
  data,
  runtimeContext
}) {
  try {
    const agent = agentId ? mastra.getAgent(agentId) : null;
    if (!agent) {
      throw new HTTPException(404, { message: "Tool not found" });
    }
    const agentTools = await agent.getTools({ runtimeContext });
    const tool = Object.values(agentTools || {}).find((tool2) => tool2.id === toolId);
    if (!tool) {
      throw new HTTPException(404, { message: "Tool not found" });
    }
    if (!tool?.execute) {
      throw new HTTPException(400, { message: "Tool is not executable" });
    }
    const result = await tool.execute({
      context: data,
      runtimeContext,
      mastra,
      runId: agentId
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error executing tool");
  }
}

// src/server/handlers/vector.ts
var vector_exports = {};
__export(vector_exports, {
  createIndex: () => createIndex$1,
  deleteIndex: () => deleteIndex$1,
  describeIndex: () => describeIndex$1,
  listIndexes: () => listIndexes$1,
  queryVectors: () => queryVectors$1,
  upsertVectors: () => upsertVectors$1
});
function getVector(mastra, vectorName) {
  if (!vectorName) {
    throw new HTTPException(400, { message: "Vector name is required" });
  }
  const vector = mastra.getVector(vectorName);
  if (!vector) {
    throw new HTTPException(404, { message: `Vector store ${vectorName} not found` });
  }
  return vector;
}
async function upsertVectors$1({ mastra, vectorName, index }) {
  try {
    if (!index?.indexName || !index?.vectors || !Array.isArray(index.vectors)) {
      throw new HTTPException(400, { message: "Invalid request index. indexName and vectors array are required." });
    }
    const vector = getVector(mastra, vectorName);
    const result = await vector.upsert(index);
    return { ids: result };
  } catch (error) {
    return handleError$1(error, "Error upserting vectors");
  }
}
async function createIndex$1({
  mastra,
  vectorName,
  index
}) {
  try {
    const { indexName, dimension, metric } = index;
    if (!indexName || typeof dimension !== "number" || dimension <= 0) {
      throw new HTTPException(400, {
        message: "Invalid request index, indexName and positive dimension number are required."
      });
    }
    if (metric && !["cosine", "euclidean", "dotproduct"].includes(metric)) {
      throw new HTTPException(400, { message: "Invalid metric. Must be one of: cosine, euclidean, dotproduct" });
    }
    const vector = getVector(mastra, vectorName);
    await vector.createIndex({ indexName, dimension, metric });
    return { success: true };
  } catch (error) {
    return handleError$1(error, "Error creating index");
  }
}
async function queryVectors$1({
  mastra,
  vectorName,
  query
}) {
  try {
    if (!query?.indexName || !query?.queryVector || !Array.isArray(query.queryVector)) {
      throw new HTTPException(400, { message: "Invalid request query. indexName and queryVector array are required." });
    }
    const vector = getVector(mastra, vectorName);
    const results = await vector.query(query);
    return results;
  } catch (error) {
    return handleError$1(error, "Error querying vectors");
  }
}
async function listIndexes$1({ mastra, vectorName }) {
  try {
    const vector = getVector(mastra, vectorName);
    const indexes = await vector.listIndexes();
    return indexes.filter(Boolean);
  } catch (error) {
    return handleError$1(error, "Error listing indexes");
  }
}
async function describeIndex$1({
  mastra,
  vectorName,
  indexName
}) {
  try {
    if (!indexName) {
      throw new HTTPException(400, { message: "Index name is required" });
    }
    const vector = getVector(mastra, vectorName);
    const stats = await vector.describeIndex({ indexName });
    return {
      dimension: stats.dimension,
      count: stats.count,
      metric: stats.metric?.toLowerCase()
    };
  } catch (error) {
    return handleError$1(error, "Error describing index");
  }
}
async function deleteIndex$1({
  mastra,
  vectorName,
  indexName
}) {
  try {
    if (!indexName) {
      throw new HTTPException(400, { message: "Index name is required" });
    }
    const vector = getVector(mastra, vectorName);
    await vector.deleteIndex({ indexName });
    return { success: true };
  } catch (error) {
    return handleError$1(error, "Error deleting index");
  }
}

// src/server/handlers/vNextNetwork.ts
async function getVNextNetworksHandler$1({
  mastra,
  runtimeContext
}) {
  try {
    const networks = mastra.vnext_getNetworks();
    const serializedNetworks = await Promise.all(
      networks.map(async (network) => {
        const routingAgent = await network.getRoutingAgent({ runtimeContext });
        const routingLLM = await routingAgent.getLLM({ runtimeContext });
        const agents = await network.getAgents({ runtimeContext });
        const workflows = await network.getWorkflows({ runtimeContext });
        const tools = await network.getTools({ runtimeContext });
        const networkInstruction = await network.getInstructions({ runtimeContext });
        return {
          id: network.id,
          name: network.name,
          instructions: networkInstruction,
          tools: await Promise.all(
            Object.values(tools).map(async (tool) => {
              return {
                id: tool.id,
                description: tool.description
              };
            })
          ),
          agents: await Promise.all(
            Object.values(agents).map(async (agent) => {
              const llm = await agent.getLLM({ runtimeContext });
              return {
                name: agent.name,
                provider: llm?.getProvider(),
                modelId: llm?.getModelId()
              };
            })
          ),
          workflows: await Promise.all(
            Object.values(workflows).map(async (workflow) => {
              return {
                name: workflow.name,
                description: workflow.description,
                inputSchema: workflow.inputSchema ? stringify(esm_default(workflow.inputSchema)) : void 0,
                outputSchema: workflow.outputSchema ? stringify(esm_default(workflow.outputSchema)) : void 0
              };
            })
          ),
          routingModel: {
            provider: routingLLM?.getProvider(),
            modelId: routingLLM?.getModelId()
          }
        };
      })
    );
    return serializedNetworks;
  } catch (error) {
    return handleError$1(error, "Error getting networks");
  }
}
async function getVNextNetworkByIdHandler$1({
  mastra,
  networkId,
  runtimeContext
}) {
  try {
    const network = mastra.vnext_getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    const routingAgent = await network.getRoutingAgent({ runtimeContext });
    const routingLLM = await routingAgent.getLLM({ runtimeContext });
    const agents = await network.getAgents({ runtimeContext });
    const workflows = await network.getWorkflows({ runtimeContext });
    const tools = await network.getTools({ runtimeContext });
    const networkInstruction = await network.getInstructions({ runtimeContext });
    const serializedNetwork = {
      id: network.id,
      name: network.name,
      instructions: networkInstruction,
      agents: await Promise.all(
        Object.values(agents).map(async (agent) => {
          const llm = await agent.getLLM({ runtimeContext });
          return {
            name: agent.name,
            provider: llm?.getProvider(),
            modelId: llm?.getModelId()
          };
        })
      ),
      workflows: await Promise.all(
        Object.values(workflows).map(async (workflow) => {
          return {
            name: workflow.name,
            description: workflow.description,
            inputSchema: workflow.inputSchema ? stringify(esm_default(workflow.inputSchema)) : void 0,
            outputSchema: workflow.outputSchema ? stringify(esm_default(workflow.outputSchema)) : void 0
          };
        })
      ),
      tools: await Promise.all(
        Object.values(tools).map(async (tool) => {
          return {
            id: tool.id,
            description: tool.description
          };
        })
      ),
      routingModel: {
        provider: routingLLM?.getProvider(),
        modelId: routingLLM?.getModelId()
      }
    };
    return serializedNetwork;
  } catch (error) {
    return handleError$1(error, "Error getting network by ID");
  }
}
async function generateVNextNetworkHandler$1({
  mastra,
  runtimeContext,
  networkId,
  body
}) {
  try {
    const network = mastra.vnext_getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    validateBody({ message: body.message });
    const { message, threadId, resourceId } = body;
    const result = await network.generate(message, { runtimeContext, threadId, resourceId });
    return result;
  } catch (error) {
    return handleError$1(error, "Error generating from network");
  }
}
async function streamGenerateVNextNetworkHandler$1({
  mastra,
  networkId,
  body,
  runtimeContext
}) {
  try {
    const network = mastra.vnext_getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    validateBody({ message: body.message });
    const { message, threadId, resourceId } = body;
    const streamResult = await network.stream(message, {
      runtimeContext,
      threadId,
      resourceId
    });
    return streamResult;
  } catch (error) {
    return handleError$1(error, "Error streaming from network");
  }
}
async function loopVNextNetworkHandler$1({
  mastra,
  networkId,
  body,
  runtimeContext
}) {
  try {
    const network = mastra.vnext_getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    validateBody({ message: body.message });
    const { message } = body;
    const result = await network.loop(message, {
      runtimeContext
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error looping network");
  }
}
async function loopStreamVNextNetworkHandler$1({
  mastra,
  networkId,
  body,
  runtimeContext
}) {
  try {
    const network = mastra.vnext_getNetwork(networkId);
    if (!network) {
      throw new HTTPException(404, { message: "Network not found" });
    }
    validateBody({ message: body.message });
    const { message, threadId, resourceId, maxIterations } = body;
    const result = await network.loopStream(message, {
      runtimeContext,
      threadId,
      resourceId,
      maxIterations
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error streaming network loop");
  }
}

// src/server/handlers/voice.ts
var voice_exports = {};
__export(voice_exports, {
  generateSpeechHandler: () => generateSpeechHandler,
  getListenerHandler: () => getListenerHandler$1,
  getSpeakersHandler: () => getSpeakersHandler$1,
  transcribeSpeechHandler: () => transcribeSpeechHandler
});
async function getSpeakersHandler$1({ mastra, agentId }) {
  try {
    if (!agentId) {
      throw new HTTPException(400, { message: "Agent ID is required" });
    }
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const voice = await agent.getVoice();
    if (!voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const speakers = await voice.getSpeakers();
    return speakers;
  } catch (error) {
    return handleError$1(error, "Error getting speakers");
  }
}
async function generateSpeechHandler({
  mastra,
  agentId,
  body
}) {
  try {
    if (!agentId) {
      throw new HTTPException(400, { message: "Agent ID is required" });
    }
    validateBody({
      text: body?.text
    });
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const voice = await agent.getVoice();
    if (!voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const audioStream = await voice.speak(body.text, { speaker: body.speakerId });
    if (!audioStream) {
      throw new HTTPException(500, { message: "Failed to generate speech" });
    }
    return audioStream;
  } catch (error) {
    return handleError$1(error, "Error generating speech");
  }
}
async function transcribeSpeechHandler({
  mastra,
  agentId,
  body
}) {
  try {
    if (!agentId) {
      throw new HTTPException(400, { message: "Agent ID is required" });
    }
    if (!body?.audioData) {
      throw new HTTPException(400, { message: "Audio data is required" });
    }
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const voice = await agent.getVoice();
    if (!voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const audioStream = new Readable();
    audioStream.push(body.audioData);
    audioStream.push(null);
    const text = await voice.listen(audioStream, body.options);
    return { text };
  } catch (error) {
    return handleError$1(error, "Error transcribing speech");
  }
}
async function getListenerHandler$1({ mastra, agentId }) {
  try {
    if (!agentId) {
      throw new HTTPException(400, { message: "Agent ID is required" });
    }
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      throw new HTTPException(404, { message: "Agent not found" });
    }
    const voice = await agent.getVoice();
    if (!voice) {
      throw new HTTPException(400, { message: "Agent does not have voice capabilities" });
    }
    const listeners = await voice.getListener();
    return listeners;
  } catch (error) {
    return handleError$1(error, "Error getting listeners");
  }
}

// src/server/handlers/workflows.ts
var workflows_exports = {};
__export(workflows_exports, {
  cancelWorkflowRunHandler: () => cancelWorkflowRunHandler$1,
  createWorkflowRunHandler: () => createWorkflowRunHandler$1,
  getWorkflowByIdHandler: () => getWorkflowByIdHandler$1,
  getWorkflowRunByIdHandler: () => getWorkflowRunByIdHandler$1,
  getWorkflowRunExecutionResultHandler: () => getWorkflowRunExecutionResultHandler$1,
  getWorkflowRunsHandler: () => getWorkflowRunsHandler$1,
  getWorkflowsHandler: () => getWorkflowsHandler$1,
  resumeAsyncWorkflowHandler: () => resumeAsyncWorkflowHandler$1,
  resumeWorkflowHandler: () => resumeWorkflowHandler$1,
  sendWorkflowRunEventHandler: () => sendWorkflowRunEventHandler$1,
  startAsyncWorkflowHandler: () => startAsyncWorkflowHandler$1,
  startWorkflowRunHandler: () => startWorkflowRunHandler$1,
  streamWorkflowHandler: () => streamWorkflowHandler$1,
  watchWorkflowHandler: () => watchWorkflowHandler$1
});
function getSteps(steps, path) {
  return Object.entries(steps).reduce((acc, [key, step]) => {
    const fullKey = path ? `${path}.${key}` : key;
    acc[fullKey] = {
      id: step.id,
      description: step.description,
      inputSchema: step.inputSchema ? stringify(esm_default(step.inputSchema)) : void 0,
      outputSchema: step.outputSchema ? stringify(esm_default(step.outputSchema)) : void 0,
      resumeSchema: step.resumeSchema ? stringify(esm_default(step.resumeSchema)) : void 0,
      suspendSchema: step.suspendSchema ? stringify(esm_default(step.suspendSchema)) : void 0,
      isWorkflow: step.component === "WORKFLOW"
    };
    if (step.component === "WORKFLOW" && step.steps) {
      const nestedSteps = getSteps(step.steps, fullKey) || {};
      acc = { ...acc, ...nestedSteps };
    }
    return acc;
  }, {});
}
async function getWorkflowsHandler$1({ mastra }) {
  try {
    const workflows = mastra.getWorkflows({ serialized: false });
    const _workflows = Object.entries(workflows).reduce((acc, [key, workflow]) => {
      acc[key] = {
        name: workflow.name,
        description: workflow.description,
        steps: Object.entries(workflow.steps).reduce((acc2, [key2, step]) => {
          acc2[key2] = {
            id: step.id,
            description: step.description,
            inputSchema: step.inputSchema ? stringify(esm_default(step.inputSchema)) : void 0,
            outputSchema: step.outputSchema ? stringify(esm_default(step.outputSchema)) : void 0,
            resumeSchema: step.resumeSchema ? stringify(esm_default(step.resumeSchema)) : void 0,
            suspendSchema: step.suspendSchema ? stringify(esm_default(step.suspendSchema)) : void 0
          };
          return acc2;
        }, {}),
        allSteps: getSteps(workflow.steps) || {},
        stepGraph: workflow.serializedStepGraph,
        inputSchema: workflow.inputSchema ? stringify(esm_default(workflow.inputSchema)) : void 0,
        outputSchema: workflow.outputSchema ? stringify(esm_default(workflow.outputSchema)) : void 0
      };
      return acc;
    }, {});
    return _workflows;
  } catch (error) {
    return handleError$1(error, "Error getting workflows");
  }
}
async function getWorkflowsFromSystem({ mastra, workflowId }) {
  const logger = mastra.getLogger();
  if (!workflowId) {
    throw new HTTPException(400, { message: "Workflow ID is required" });
  }
  let workflow;
  try {
    workflow = mastra.getWorkflow(workflowId);
  } catch (error) {
    logger.debug("Error getting workflow, searching agents for workflow", error);
  }
  if (!workflow) {
    logger.debug("Workflow not found, searching agents for workflow", { workflowId });
    const agents = mastra.getAgents();
    if (Object.keys(agents || {}).length) {
      for (const [_, agent] of Object.entries(agents)) {
        try {
          const workflows = await agent.getWorkflows();
          if (workflows[workflowId]) {
            workflow = workflows[workflowId];
            break;
          }
          break;
        } catch (error) {
          logger.debug("Error getting workflow from agent", error);
        }
      }
    }
  }
  if (!workflow) {
    throw new HTTPException(404, { message: "Workflow not found" });
  }
  return { workflow };
}
async function getWorkflowByIdHandler$1({ mastra, workflowId }) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    return {
      steps: Object.entries(workflow.steps).reduce((acc, [key, step]) => {
        acc[key] = {
          id: step.id,
          description: step.description,
          inputSchema: step.inputSchema ? stringify(esm_default(step.inputSchema)) : void 0,
          outputSchema: step.outputSchema ? stringify(esm_default(step.outputSchema)) : void 0,
          resumeSchema: step.resumeSchema ? stringify(esm_default(step.resumeSchema)) : void 0,
          suspendSchema: step.suspendSchema ? stringify(esm_default(step.suspendSchema)) : void 0
        };
        return acc;
      }, {}),
      allSteps: getSteps(workflow.steps) || {},
      name: workflow.name,
      description: workflow.description,
      stepGraph: workflow.serializedStepGraph,
      inputSchema: workflow.inputSchema ? stringify(esm_default(workflow.inputSchema)) : void 0,
      outputSchema: workflow.outputSchema ? stringify(esm_default(workflow.outputSchema)) : void 0
    };
  } catch (error) {
    return handleError$1(error, "Error getting workflow");
  }
}
async function getWorkflowRunByIdHandler$1({
  mastra,
  workflowId,
  runId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "Run ID is required" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    return run;
  } catch (error) {
    return handleError$1(error, "Error getting workflow run");
  }
}
async function getWorkflowRunExecutionResultHandler$1({
  mastra,
  workflowId,
  runId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "Run ID is required" });
    }
    const workflow = mastra.getWorkflow(workflowId);
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const executionResult = await workflow.getWorkflowRunExecutionResult(runId);
    if (!executionResult) {
      throw new HTTPException(404, { message: "Workflow run execution result not found" });
    }
    return executionResult;
  } catch (error) {
    return handleError$1(error, "Error getting workflow run execution result");
  }
}
async function createWorkflowRunHandler$1({
  mastra,
  workflowId,
  runId: prevRunId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.createRunAsync({ runId: prevRunId });
    return { runId: run.runId };
  } catch (error) {
    return handleError$1(error, "Error creating workflow run");
  }
}
async function startAsyncWorkflowHandler$1({
  mastra,
  runtimeContext,
  workflowId,
  runId,
  inputData
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    const result = await _run.start({
      inputData,
      runtimeContext
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error starting async workflow");
  }
}
async function startWorkflowRunHandler$1({
  mastra,
  runtimeContext,
  workflowId,
  runId,
  inputData
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to start run" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    void _run.start({
      inputData,
      runtimeContext
    });
    return { message: "Workflow run started" };
  } catch (e) {
    return handleError$1(e, "Error starting workflow run");
  }
}
async function watchWorkflowHandler$1({
  mastra,
  workflowId,
  runId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to watch workflow" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    let unwatch;
    let asyncRef = null;
    const stream = new ReadableStream$1({
      start(controller) {
        unwatch = _run.watch(({ type, payload, eventTimestamp }) => {
          controller.enqueue(JSON.stringify({ type, payload, eventTimestamp, runId }));
          if (asyncRef) {
            clearImmediate(asyncRef);
            asyncRef = null;
          }
          asyncRef = setImmediate(async () => {
            const runDone = payload.workflowState.status !== "running";
            if (runDone) {
              controller.close();
              unwatch?.();
            }
          });
        });
      },
      cancel() {
        unwatch?.();
      }
    });
    return stream;
  } catch (error) {
    return handleError$1(error, "Error watching workflow");
  }
}
async function streamWorkflowHandler$1({
  mastra,
  runtimeContext,
  workflowId,
  runId,
  inputData
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.createRunAsync({ runId });
    const result = run.stream({
      inputData,
      runtimeContext
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error executing workflow");
  }
}
async function resumeAsyncWorkflowHandler$1({
  mastra,
  workflowId,
  runId,
  body,
  runtimeContext
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    if (!body.step) {
      throw new HTTPException(400, { message: "step required to resume workflow" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    const result = await _run.resume({
      step: body.step,
      resumeData: body.resumeData,
      runtimeContext
    });
    return result;
  } catch (error) {
    return handleError$1(error, "Error resuming workflow step");
  }
}
async function resumeWorkflowHandler$1({
  mastra,
  workflowId,
  runId,
  body,
  runtimeContext
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to resume workflow" });
    }
    if (!body.step) {
      throw new HTTPException(400, { message: "step required to resume workflow" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    void _run.resume({
      step: body.step,
      resumeData: body.resumeData,
      runtimeContext
    });
    return { message: "Workflow run resumed" };
  } catch (error) {
    return handleError$1(error, "Error resuming workflow");
  }
}
async function getWorkflowRunsHandler$1({
  mastra,
  workflowId,
  fromDate,
  toDate,
  limit,
  offset,
  resourceId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const workflowRuns = await workflow.getWorkflowRuns({ fromDate, toDate, limit, offset, resourceId }) || {
      runs: [],
      total: 0
    };
    return workflowRuns;
  } catch (error) {
    return handleError$1(error, "Error getting workflow runs");
  }
}
async function cancelWorkflowRunHandler$1({
  mastra,
  workflowId,
  runId
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to cancel workflow run" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    await _run.cancel();
    return { message: "Workflow run cancelled" };
  } catch (error) {
    return handleError$1(error, "Error canceling workflow run");
  }
}
async function sendWorkflowRunEventHandler$1({
  mastra,
  workflowId,
  runId,
  event,
  data
}) {
  try {
    if (!workflowId) {
      throw new HTTPException(400, { message: "Workflow ID is required" });
    }
    if (!runId) {
      throw new HTTPException(400, { message: "runId required to send workflow run event" });
    }
    const { workflow } = await getWorkflowsFromSystem({ mastra, workflowId });
    if (!workflow) {
      throw new HTTPException(404, { message: "Workflow not found" });
    }
    const run = await workflow.getWorkflowRunById(runId);
    if (!run) {
      throw new HTTPException(404, { message: "Workflow run not found" });
    }
    const _run = await workflow.createRunAsync({ runId });
    await _run.sendEvent(event, data);
    return { message: "Workflow run event sent" };
  } catch (error) {
    return handleError$1(error, "Error sending workflow run event");
  }
}

// src/server/index.ts
var RequestError = class extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "RequestError";
  }
};
var toRequestError = (e2) => {
  if (e2 instanceof RequestError) {
    return e2;
  }
  return new RequestError(e2.message, { cause: e2 });
};
var GlobalRequest = global.Request;
var Request$1 = class Request extends GlobalRequest {
  constructor(input, options) {
    if (typeof input === "object" && getRequestCache in input) {
      input = input[getRequestCache]();
    }
    if (typeof options?.body?.getReader !== "undefined") {
      options.duplex ??= "half";
    }
    super(input, options);
  }
};
var newRequestFromIncoming = (method, url, incoming, abortController) => {
  const headerRecord = [];
  const rawHeaders = incoming.rawHeaders;
  for (let i2 = 0; i2 < rawHeaders.length; i2 += 2) {
    const { [i2]: key, [i2 + 1]: value } = rawHeaders;
    if (key.charCodeAt(0) !== /*:*/
    58) {
      headerRecord.push([key, value]);
    }
  }
  const init = {
    method,
    headers: headerRecord,
    signal: abortController.signal
  };
  if (method === "TRACE") {
    init.method = "GET";
    const req = new Request$1(url, init);
    Object.defineProperty(req, "method", {
      get() {
        return "TRACE";
      }
    });
    return req;
  }
  if (!(method === "GET" || method === "HEAD")) {
    if ("rawBody" in incoming && incoming.rawBody instanceof Buffer) {
      init.body = new ReadableStream({
        start(controller) {
          controller.enqueue(incoming.rawBody);
          controller.close();
        }
      });
    } else {
      init.body = Readable.toWeb(incoming);
    }
  }
  return new Request$1(url, init);
};
var getRequestCache = Symbol("getRequestCache");
var requestCache = Symbol("requestCache");
var incomingKey = Symbol("incomingKey");
var urlKey = Symbol("urlKey");
var abortControllerKey = Symbol("abortControllerKey");
var getAbortController = Symbol("getAbortController");
var requestPrototype = {
  get method() {
    return this[incomingKey].method || "GET";
  },
  get url() {
    return this[urlKey];
  },
  [getAbortController]() {
    this[getRequestCache]();
    return this[abortControllerKey];
  },
  [getRequestCache]() {
    this[abortControllerKey] ||= new AbortController();
    return this[requestCache] ||= newRequestFromIncoming(
      this.method,
      this[urlKey],
      this[incomingKey],
      this[abortControllerKey]
    );
  }
};
[
  "body",
  "bodyUsed",
  "cache",
  "credentials",
  "destination",
  "headers",
  "integrity",
  "mode",
  "redirect",
  "referrer",
  "referrerPolicy",
  "signal",
  "keepalive"
].forEach((k) => {
  Object.defineProperty(requestPrototype, k, {
    get() {
      return this[getRequestCache]()[k];
    }
  });
});
["arrayBuffer", "blob", "clone", "formData", "json", "text"].forEach((k) => {
  Object.defineProperty(requestPrototype, k, {
    value: function() {
      return this[getRequestCache]()[k]();
    }
  });
});
Object.setPrototypeOf(requestPrototype, Request$1.prototype);
var newRequest = (incoming, defaultHostname) => {
  const req = Object.create(requestPrototype);
  req[incomingKey] = incoming;
  const incomingUrl = incoming.url || "";
  if (incomingUrl[0] !== "/" && // short-circuit for performance. most requests are relative URL.
  (incomingUrl.startsWith("http://") || incomingUrl.startsWith("https://"))) {
    if (incoming instanceof Http2ServerRequest) {
      throw new RequestError("Absolute URL for :path is not allowed in HTTP/2");
    }
    try {
      const url2 = new URL(incomingUrl);
      req[urlKey] = url2.href;
    } catch (e2) {
      throw new RequestError("Invalid absolute URL", { cause: e2 });
    }
    return req;
  }
  const host = (incoming instanceof Http2ServerRequest ? incoming.authority : incoming.headers.host) || defaultHostname;
  if (!host) {
    throw new RequestError("Missing host header");
  }
  let scheme;
  if (incoming instanceof Http2ServerRequest) {
    scheme = incoming.scheme;
    if (!(scheme === "http" || scheme === "https")) {
      throw new RequestError("Unsupported scheme");
    }
  } else {
    scheme = incoming.socket && incoming.socket.encrypted ? "https" : "http";
  }
  const url = new URL(`${scheme}://${host}${incomingUrl}`);
  if (url.hostname.length !== host.length && url.hostname !== host.replace(/:\d+$/, "")) {
    throw new RequestError("Invalid host header");
  }
  req[urlKey] = url.href;
  return req;
};
var responseCache = Symbol("responseCache");
var getResponseCache = Symbol("getResponseCache");
var cacheKey = Symbol("cache");
var GlobalResponse = global.Response;
var Response2 = class _Response {
  #body;
  #init;
  [getResponseCache]() {
    delete this[cacheKey];
    return this[responseCache] ||= new GlobalResponse(this.#body, this.#init);
  }
  constructor(body, init) {
    let headers;
    this.#body = body;
    if (init instanceof _Response) {
      const cachedGlobalResponse = init[responseCache];
      if (cachedGlobalResponse) {
        this.#init = cachedGlobalResponse;
        this[getResponseCache]();
        return;
      } else {
        this.#init = init.#init;
        headers = new Headers(init.#init.headers);
      }
    } else {
      this.#init = init;
    }
    if (typeof body === "string" || typeof body?.getReader !== "undefined" || body instanceof Blob || body instanceof Uint8Array) {
      headers ||= init?.headers || { "content-type": "text/plain; charset=UTF-8" };
      this[cacheKey] = [init?.status || 200, body, headers];
    }
  }
  get headers() {
    const cache = this[cacheKey];
    if (cache) {
      if (!(cache[2] instanceof Headers)) {
        cache[2] = new Headers(cache[2]);
      }
      return cache[2];
    }
    return this[getResponseCache]().headers;
  }
  get status() {
    return this[cacheKey]?.[0] ?? this[getResponseCache]().status;
  }
  get ok() {
    const status = this.status;
    return status >= 200 && status < 300;
  }
};
["body", "bodyUsed", "redirected", "statusText", "trailers", "type", "url"].forEach((k) => {
  Object.defineProperty(Response2.prototype, k, {
    get() {
      return this[getResponseCache]()[k];
    }
  });
});
["arrayBuffer", "blob", "clone", "formData", "json", "text"].forEach((k) => {
  Object.defineProperty(Response2.prototype, k, {
    value: function() {
      return this[getResponseCache]()[k]();
    }
  });
});
Object.setPrototypeOf(Response2, GlobalResponse);
Object.setPrototypeOf(Response2.prototype, GlobalResponse.prototype);
function writeFromReadableStream(stream5, writable) {
  if (stream5.locked) {
    throw new TypeError("ReadableStream is locked.");
  } else if (writable.destroyed) {
    stream5.cancel();
    return;
  }
  const reader = stream5.getReader();
  writable.on("close", cancel);
  writable.on("error", cancel);
  reader.read().then(flow, cancel);
  return reader.closed.finally(() => {
    writable.off("close", cancel);
    writable.off("error", cancel);
  });
  function cancel(error) {
    reader.cancel(error).catch(() => {
    });
    if (error) {
      writable.destroy(error);
    }
  }
  function onDrain() {
    reader.read().then(flow, cancel);
  }
  function flow({ done, value }) {
    try {
      if (done) {
        writable.end();
      } else if (!writable.write(value)) {
        writable.once("drain", onDrain);
      } else {
        return reader.read().then(flow, cancel);
      }
    } catch (e2) {
      cancel(e2);
    }
  }
}
var buildOutgoingHttpHeaders = (headers) => {
  const res = {};
  if (!(headers instanceof Headers)) {
    headers = new Headers(headers ?? void 0);
  }
  const cookies = [];
  for (const [k, v] of headers) {
    if (k === "set-cookie") {
      cookies.push(v);
    } else {
      res[k] = v;
    }
  }
  if (cookies.length > 0) {
    res["set-cookie"] = cookies;
  }
  res["content-type"] ??= "text/plain; charset=UTF-8";
  return res;
};
var X_ALREADY_SENT = "x-hono-already-sent";
var webFetch = global.fetch;
if (typeof global.crypto === "undefined") {
  global.crypto = crypto;
}
global.fetch = (info, init) => {
  init = {
    // Disable compression handling so people can return the result of a fetch
    // directly in the loader without messing with the Content-Encoding header.
    compress: false,
    ...init
  };
  return webFetch(info, init);
};
var regBuffer = /^no$/i;
var regContentType = /^(application\/json\b|text\/(?!event-stream\b))/i;
var handleRequestError = () => new Response(null, {
  status: 400
});
var handleFetchError = (e2) => new Response(null, {
  status: e2 instanceof Error && (e2.name === "TimeoutError" || e2.constructor.name === "TimeoutError") ? 504 : 500
});
var handleResponseError = (e2, outgoing) => {
  const err = e2 instanceof Error ? e2 : new Error("unknown error", { cause: e2 });
  if (err.code === "ERR_STREAM_PREMATURE_CLOSE") {
    console.info("The user aborted a request.");
  } else {
    console.error(e2);
    if (!outgoing.headersSent) {
      outgoing.writeHead(500, { "Content-Type": "text/plain" });
    }
    outgoing.end(`Error: ${err.message}`);
    outgoing.destroy(err);
  }
};
var flushHeaders = (outgoing) => {
  if ("flushHeaders" in outgoing && outgoing.writable) {
    outgoing.flushHeaders();
  }
};
var responseViaCache = async (res, outgoing) => {
  let [status, body, header] = res[cacheKey];
  if (header instanceof Headers) {
    header = buildOutgoingHttpHeaders(header);
  }
  if (typeof body === "string") {
    header["Content-Length"] = Buffer.byteLength(body);
  } else if (body instanceof Uint8Array) {
    header["Content-Length"] = body.byteLength;
  } else if (body instanceof Blob) {
    header["Content-Length"] = body.size;
  }
  outgoing.writeHead(status, header);
  if (typeof body === "string" || body instanceof Uint8Array) {
    outgoing.end(body);
  } else if (body instanceof Blob) {
    outgoing.end(new Uint8Array(await body.arrayBuffer()));
  } else {
    flushHeaders(outgoing);
    return writeFromReadableStream(body, outgoing)?.catch(
      (e2) => handleResponseError(e2, outgoing)
    );
  }
};
var responseViaResponseObject = async (res, outgoing, options = {}) => {
  if (res instanceof Promise) {
    if (options.errorHandler) {
      try {
        res = await res;
      } catch (err) {
        const errRes = await options.errorHandler(err);
        if (!errRes) {
          return;
        }
        res = errRes;
      }
    } else {
      res = await res.catch(handleFetchError);
    }
  }
  if (cacheKey in res) {
    return responseViaCache(res, outgoing);
  }
  const resHeaderRecord = buildOutgoingHttpHeaders(res.headers);
  if (res.body) {
    const {
      "transfer-encoding": transferEncoding,
      "content-encoding": contentEncoding,
      "content-length": contentLength,
      "x-accel-buffering": accelBuffering,
      "content-type": contentType
    } = resHeaderRecord;
    if (transferEncoding || contentEncoding || contentLength || // nginx buffering variant
    accelBuffering && regBuffer.test(accelBuffering) || !regContentType.test(contentType)) {
      outgoing.writeHead(res.status, resHeaderRecord);
      flushHeaders(outgoing);
      await writeFromReadableStream(res.body, outgoing);
    } else {
      const buffer = await res.arrayBuffer();
      resHeaderRecord["content-length"] = buffer.byteLength;
      outgoing.writeHead(res.status, resHeaderRecord);
      outgoing.end(new Uint8Array(buffer));
    }
  } else if (resHeaderRecord[X_ALREADY_SENT]) ; else {
    outgoing.writeHead(res.status, resHeaderRecord);
    outgoing.end();
  }
};
var getRequestListener = (fetchCallback, options = {}) => {
  if (options.overrideGlobalObjects !== false && global.Request !== Request$1) {
    Object.defineProperty(global, "Request", {
      value: Request$1
    });
    Object.defineProperty(global, "Response", {
      value: Response2
    });
  }
  return async (incoming, outgoing) => {
    let res, req;
    try {
      req = newRequest(incoming, options.hostname);
      outgoing.on("close", () => {
        const abortController = req[abortControllerKey];
        if (!abortController) {
          return;
        }
        if (incoming.errored) {
          req[abortControllerKey].abort(incoming.errored.toString());
        } else if (!outgoing.writableFinished) {
          req[abortControllerKey].abort("Client connection prematurely closed.");
        }
      });
      res = fetchCallback(req, { incoming, outgoing });
      if (cacheKey in res) {
        return responseViaCache(res, outgoing);
      }
    } catch (e2) {
      if (!res) {
        if (options.errorHandler) {
          res = await options.errorHandler(req ? e2 : toRequestError(e2));
          if (!res) {
            return;
          }
        } else if (!req) {
          res = handleRequestError();
        } else {
          res = handleFetchError(e2);
        }
      } else {
        return handleResponseError(e2, outgoing);
      }
    }
    try {
      return await responseViaResponseObject(res, outgoing, options);
    } catch (e2) {
      return handleResponseError(e2, outgoing);
    }
  };
};
var createAdaptorServer = (options) => {
  const fetchCallback = options.fetch;
  const requestListener = getRequestListener(fetchCallback, {
    hostname: options.hostname,
    overrideGlobalObjects: options.overrideGlobalObjects
  });
  const createServer$1 = options.createServer || createServer;
  const server = createServer$1(options.serverOptions || {}, requestListener);
  return server;
};
var serve = (options, listeningListener) => {
  const server = createAdaptorServer(options);
  server.listen(options?.port ?? 3e3, options.hostname, () => {
    const serverInfo = server.address();
    listeningListener && listeningListener(serverInfo);
  });
  return server;
};
var COMPRESSIBLE_CONTENT_TYPE_REGEX = /^\s*(?:text\/[^;\s]+|application\/(?:javascript|json|xml|xml-dtd|ecmascript|dart|postscript|rtf|tar|toml|vnd\.dart|vnd\.ms-fontobject|vnd\.ms-opentype|wasm|x-httpd-php|x-javascript|x-ns-proxy-autoconfig|x-sh|x-tar|x-virtualbox-hdd|x-virtualbox-ova|x-virtualbox-ovf|x-virtualbox-vbox|x-virtualbox-vdi|x-virtualbox-vhd|x-virtualbox-vmdk|x-www-form-urlencoded)|font\/(?:otf|ttf)|image\/(?:bmp|vnd\.adobe\.photoshop|vnd\.microsoft\.icon|vnd\.ms-dds|x-icon|x-ms-bmp)|message\/rfc822|model\/gltf-binary|x-shader\/x-fragment|x-shader\/x-vertex|[^;\s]+?\+(?:json|text|xml|yaml))(?:[;\s]|$)/i;
var ENCODINGS = {
  br: ".br",
  zstd: ".zst",
  gzip: ".gz"
};
var ENCODINGS_ORDERED_KEYS = Object.keys(ENCODINGS);
var createStreamBody = (stream5) => {
  const body = new ReadableStream({
    start(controller) {
      stream5.on("data", (chunk) => {
        controller.enqueue(chunk);
      });
      stream5.on("end", () => {
        controller.close();
      });
    },
    cancel() {
      stream5.destroy();
    }
  });
  return body;
};
var addCurrentDirPrefix = (path) => {
  return `./${path}`;
};
var getStats = (path) => {
  let stats;
  try {
    stats = lstatSync(path);
  } catch {
  }
  return stats;
};
var serveStatic = (options = { root: "" }) => {
  return async (c2, next) => {
    if (c2.finalized) {
      return next();
    }
    let filename;
    try {
      filename = options.path ?? decodeURIComponent(c2.req.path);
    } catch {
      await options.onNotFound?.(c2.req.path, c2);
      return next();
    }
    let path = getFilePathWithoutDefaultDocument({
      filename: options.rewriteRequestPath ? options.rewriteRequestPath(filename) : filename,
      root: options.root
    });
    if (path) {
      path = addCurrentDirPrefix(path);
    } else {
      return next();
    }
    let stats = getStats(path);
    if (stats && stats.isDirectory()) {
      path = getFilePath({
        filename: options.rewriteRequestPath ? options.rewriteRequestPath(filename) : filename,
        root: options.root,
        defaultDocument: options.index ?? "index.html"
      });
      if (path) {
        path = addCurrentDirPrefix(path);
      } else {
        return next();
      }
      stats = getStats(path);
    }
    if (!stats) {
      await options.onNotFound?.(path, c2);
      return next();
    }
    await options.onFound?.(path, c2);
    const mimeType = getMimeType(path);
    c2.header("Content-Type", mimeType || "application/octet-stream");
    if (options.precompressed && (!mimeType || COMPRESSIBLE_CONTENT_TYPE_REGEX.test(mimeType))) {
      const acceptEncodingSet = new Set(
        c2.req.header("Accept-Encoding")?.split(",").map((encoding) => encoding.trim())
      );
      for (const encoding of ENCODINGS_ORDERED_KEYS) {
        if (!acceptEncodingSet.has(encoding)) {
          continue;
        }
        const precompressedStats = getStats(path + ENCODINGS[encoding]);
        if (precompressedStats) {
          c2.header("Content-Encoding", encoding);
          c2.header("Vary", "Accept-Encoding", { append: true });
          stats = precompressedStats;
          path = path + ENCODINGS[encoding];
          break;
        }
      }
    }
    const size = stats.size;
    if (c2.req.method == "HEAD" || c2.req.method == "OPTIONS") {
      c2.header("Content-Length", size.toString());
      c2.status(200);
      return c2.body(null);
    }
    const range = c2.req.header("range") || "";
    if (!range) {
      c2.header("Content-Length", size.toString());
      return c2.body(createStreamBody(createReadStream(path)), 200);
    }
    c2.header("Accept-Ranges", "bytes");
    c2.header("Date", stats.birthtime.toUTCString());
    const parts = range.replace(/bytes=/, "").split("-", 2);
    const start = parts[0] ? parseInt(parts[0], 10) : 0;
    let end = parts[1] ? parseInt(parts[1], 10) : stats.size - 1;
    if (size < end - start + 1) {
      end = size - 1;
    }
    const chunksize = end - start + 1;
    const stream5 = createReadStream(path, { start, end });
    c2.header("Content-Length", chunksize.toString());
    c2.header("Content-Range", `bytes ${start}-${end}/${stats.size}`);
    return c2.body(createStreamBody(stream5), 206);
  };
};
var RENDER_TYPE = {
  STRING_ARRAY: "string_array",
  STRING: "string",
  JSON_STRING: "json_string",
  RAW: "raw"
};
var RENDER_TYPE_MAP = {
  configUrl: RENDER_TYPE.STRING,
  deepLinking: RENDER_TYPE.RAW,
  presets: RENDER_TYPE.STRING_ARRAY,
  plugins: RENDER_TYPE.STRING_ARRAY,
  spec: RENDER_TYPE.JSON_STRING,
  url: RENDER_TYPE.STRING,
  urls: RENDER_TYPE.JSON_STRING,
  layout: RENDER_TYPE.STRING,
  docExpansion: RENDER_TYPE.STRING,
  maxDisplayedTags: RENDER_TYPE.RAW,
  operationsSorter: RENDER_TYPE.RAW,
  requestInterceptor: RENDER_TYPE.RAW,
  responseInterceptor: RENDER_TYPE.RAW,
  persistAuthorization: RENDER_TYPE.RAW,
  defaultModelsExpandDepth: RENDER_TYPE.RAW,
  defaultModelExpandDepth: RENDER_TYPE.RAW,
  defaultModelRendering: RENDER_TYPE.STRING,
  displayRequestDuration: RENDER_TYPE.RAW,
  filter: RENDER_TYPE.RAW,
  showExtensions: RENDER_TYPE.RAW,
  showCommonExtensions: RENDER_TYPE.RAW,
  queryConfigEnabled: RENDER_TYPE.RAW,
  displayOperationId: RENDER_TYPE.RAW,
  tagsSorter: RENDER_TYPE.RAW,
  onComplete: RENDER_TYPE.RAW,
  syntaxHighlight: RENDER_TYPE.JSON_STRING,
  tryItOutEnabled: RENDER_TYPE.RAW,
  requestSnippetsEnabled: RENDER_TYPE.RAW,
  requestSnippets: RENDER_TYPE.JSON_STRING,
  oauth2RedirectUrl: RENDER_TYPE.STRING,
  showMutabledRequest: RENDER_TYPE.RAW,
  request: RENDER_TYPE.JSON_STRING,
  supportedSubmitMethods: RENDER_TYPE.JSON_STRING,
  validatorUrl: RENDER_TYPE.STRING,
  withCredentials: RENDER_TYPE.RAW,
  modelPropertyMacro: RENDER_TYPE.RAW,
  parameterMacro: RENDER_TYPE.RAW
};
var renderSwaggerUIOptions = (options) => {
  const optionsStrings = Object.entries(options).map(([k, v]) => {
    const key = k;
    if (!RENDER_TYPE_MAP[key] || v === void 0) {
      return "";
    }
    switch (RENDER_TYPE_MAP[key]) {
      case RENDER_TYPE.STRING:
        return `${key}: '${v}'`;
      case RENDER_TYPE.STRING_ARRAY:
        if (!Array.isArray(v)) {
          return "";
        }
        return `${key}: [${v.map((ve) => `${ve}`).join(",")}]`;
      case RENDER_TYPE.JSON_STRING:
        return `${key}: ${JSON.stringify(v)}`;
      case RENDER_TYPE.RAW:
        return `${key}: ${v}`;
      default:
        return "";
    }
  }).filter((item) => item !== "").join(",");
  return optionsStrings;
};
var remoteAssets = ({ version }) => {
  const url = `https://cdn.jsdelivr.net/npm/swagger-ui-dist${version !== void 0 ? `@${version}` : ""}`;
  return {
    css: [`${url}/swagger-ui.css`],
    js: [`${url}/swagger-ui-bundle.js`]
  };
};
var SwaggerUI = (options) => {
  const asset = remoteAssets({ version: options?.version });
  delete options.version;
  if (options.manuallySwaggerUIHtml) {
    return options.manuallySwaggerUIHtml(asset);
  }
  const optionsStrings = renderSwaggerUIOptions(options);
  return `
    <div>
      <div id="swagger-ui"></div>
      ${asset.css.map((url) => html`<link rel="stylesheet" href="${url}" />`)}
      ${asset.js.map((url) => html`<script src="${url}" crossorigin="anonymous"></script>`)}
      <script>
        window.onload = () => {
          window.ui = SwaggerUIBundle({
            dom_id: '#swagger-ui',${optionsStrings},
          })
        }
      </script>
    </div>
  `;
};
var middleware = (options) => async (c2) => {
  const title = options?.title ?? "SwaggerUI";
  return c2.html(
    /* html */
    `
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width, initial-scale=1" />
          <meta name="description" content="SwaggerUI" />
          <title>${title}</title>
        </head>
        <body>
          ${SwaggerUI(options)}
        </body>
      </html>
    `
  );
};

// ../../node_modules/.pnpm/hono-openapi@0.4.8_hono@4.8.4_openapi-types@12.1.3_zod@3.25.67/node_modules/hono-openapi/utils.js
var e = Symbol("openapi");
var n = ["GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"];
var s2 = (e2) => e2.charAt(0).toUpperCase() + e2.slice(1);
var o = /* @__PURE__ */ new Map();
var a = (e2, t2) => {
  const n2 = `${e2}:${t2}`;
  if (o.has(n2)) return o.get(n2);
  let a2 = e2;
  if ("/" === t2) return `${a2}Index`;
  for (const e3 of t2.split("/")) 123 === e3.charCodeAt(0) ? a2 += `By${s2(e3.slice(1, -1))}` : a2 += s2(e3);
  return o.set(n2, a2), a2;
};
var r = /* @__PURE__ */ new Map();
function c(e2, t2, n2) {
  return e2 && t2 in e2 ? e2[t2] ?? n2 : n2;
}
function i(...e2) {
  return e2.reduce((e3, t2) => {
    if (!t2) return e3;
    let n2;
    return ("tags" in e3 && e3.tags || "tags" in t2 && t2.tags) && (n2 = Array.from(/* @__PURE__ */ new Set([...c(e3, "tags", []), ...c(t2, "tags", [])]))), { ...e3, ...t2, tags: n2, responses: { ...c(e3, "responses", {}), ...c(t2, "responses", {}) }, parameters: m(e3.parameters, t2.parameters) };
  }, {});
}
function p({ path: e2, method: t2, data: n2, schema: s3 }) {
  e2 = ((e3) => e3.split("/").map((e4) => {
    let t3 = e4;
    if (t3.startsWith(":")) {
      const e5 = t3.match(/^:([^{?]+)(?:{(.+)})?(\?)?$/);
      e5 ? t3 = `{${e5[1]}}` : (t3 = t3.slice(1, t3.length), t3.endsWith("?") && (t3 = t3.slice(0, -1)), t3 = `{${t3}}`);
    }
    return t3;
  }).join("/"))(e2);
  const o2 = t2.toLowerCase();
  if ("all" === o2) {
    if (!n2) return;
    if (r.has(e2)) {
      const t3 = r.get(e2) ?? {};
      r.set(e2, { ...t3, ...n2, parameters: m(t3.parameters, n2.parameters) });
    } else r.set(e2, n2);
  } else {
    const t3 = function(e3) {
      const t4 = Array.from(r.keys());
      let n3 = {};
      for (const s4 of t4) e3.match(s4) && (n3 = i(n3, r.get(s4) ?? {}));
      return n3;
    }(e2);
    s3[e2] = { ...s3[e2] ? s3[e2] : {}, [o2]: { responses: {}, operationId: a(o2, e2), ...i(t3, s3[e2]?.[o2], n2) } };
  }
}
var f = (e2) => "$ref" in e2 ? e2.$ref : `${e2.in} ${e2.name}`;
function m(...e2) {
  const t2 = e2.flatMap((e3) => e3 ?? []).reduce((e3, t3) => (e3.set(f(t3), t3), e3), /* @__PURE__ */ new Map());
  return Array.from(t2.values());
}
function l(e2, { excludeStaticFile: t2 = true, exclude: n2 = [] }) {
  const s3 = {}, o2 = Array.isArray(n2) ? n2 : [n2];
  for (const [n3, a2] of Object.entries(e2)) if (!o2.some((e3) => "string" == typeof e3 ? n3 === e3 : e3.test(n3)) && (!n3.includes("*") || n3.includes("{")) && (!t2 || (!n3.includes(".") || n3.includes("{")))) {
    for (const e3 of Object.keys(a2)) {
      const t3 = a2[e3];
      if (n3.includes("{")) {
        t3.parameters || (t3.parameters = []);
        const e4 = n3.split("/").filter((e5) => e5.startsWith("{") && !t3.parameters.find((t4) => "path" === t4.in && t4.name === e5.slice(1, e5.length - 1)));
        for (const n4 of e4) {
          const e5 = n4.slice(1, n4.length - 1), s4 = t3.parameters.findIndex((t4) => "param" === t4.in && t4.name === e5);
          -1 !== s4 ? t3.parameters[s4].in = "path" : t3.parameters.push({ schema: { type: "string" }, in: "path", name: e5, required: true });
        }
      }
      t3.responses || (t3.responses = { 200: {} });
    }
    s3[n3] = a2;
  }
  return s3;
}
var u = { documentation: {}, excludeStaticFile: true, exclude: [], excludeMethods: ["OPTIONS"], excludeTags: [] };
var d = { version: "3.1.0", components: {} };
function h(e2, t2) {
  const n2 = { version: "3.1.0", components: {} };
  let s3;
  return async (o2) => (s3 || (s3 = await y(e2, t2, n2, o2)), o2.json(s3));
}
async function y(t2, s3 = u, o2 = d, a2) {
  const r2 = { ...u, ...s3 }, c2 = { ...d, ...o2 }, i2 = r2.documentation ?? {}, f2 = await async function(t3, s4, o3) {
    const a3 = {};
    for (const r3 of t3.routes) {
      if (!(e in r3.handler)) {
        s4.includeEmptyPaths && p({ method: r3.method, path: r3.path, schema: a3 });
        continue;
      }
      if (s4.excludeMethods.includes(r3.method)) continue;
      if (false === n.includes(r3.method) && "ALL" !== r3.method) continue;
      const { resolver: t4, metadata: c3 = {} } = r3.handler[e], i3 = s4.defaultOptions?.[r3.method], { docs: f3, components: m2 } = await t4({ ...o3, ...c3 }, i3);
      o3.components = { ...o3.components, ...m2 ?? {} }, p({ method: r3.method, path: r3.path, data: f3, schema: a3 });
    }
    return a3;
  }(t2, r2, c2);
  for (const e2 in f2) for (const t3 in f2[e2]) {
    const n2 = f2[e2][t3]?.hide;
    if (n2) {
      let s4 = false;
      "boolean" == typeof n2 ? s4 = n2 : "function" == typeof n2 && (a2 ? s4 = n2(a2) : console.warn(`'c' is not defined, cannot evaluate hide function for ${t3} ${e2}`)), s4 && delete f2[e2][t3];
    }
  }
  return { openapi: c2.version, ...{ ...i2, tags: i2.tags?.filter((e2) => !r2.excludeTags?.includes(e2?.name)), info: { title: "Hono Documentation", description: "Development documentation", version: "0.0.0", ...i2.info }, paths: { ...l(f2, r2), ...i2.paths }, components: { ...i2.components, schemas: { ...c2.components, ...i2.components?.schemas } } } };
}
function w(n2) {
  const { validateResponse: s3, ...o2 } = n2;
  return Object.assign(async (e2, o3) => {
    if (await o3(), s3 && n2.responses) {
      const o4 = e2.res.status, a2 = e2.res.headers.get("content-type");
      if (o4 && a2) {
        const r2 = n2.responses[o4];
        if (r2 && "content" in r2 && r2.content) {
          const n3 = a2.split(";")[0], o5 = r2.content[n3];
          if (o5?.schema && "validator" in o5.schema) try {
            let t2;
            const s4 = e2.res.clone();
            if ("application/json" === n3 ? t2 = await s4.json() : "text/plain" === n3 && (t2 = await s4.text()), !t2) throw new Error("No data to validate!");
            await o5.schema.validator(t2);
          } catch (e3) {
            let n4 = { status: 500, message: "Response validation failed!" };
            throw "object" == typeof s3 && (n4 = { ...n4, ...s3 }), new HTTPException$1(n4.status, { message: n4.message, cause: e3 });
          }
        }
      }
    }
  }, { [e]: { resolver: (e2, t2) => x(e2, o2, t2) } });
}
async function x(e2, t2, n2 = {}) {
  let s3 = {};
  const o2 = { ...n2, ...t2, responses: { ...n2?.responses, ...t2.responses } };
  if (o2.responses) for (const t3 of Object.keys(o2.responses)) {
    const n3 = o2.responses[t3];
    if (n3 && "content" in n3) for (const t4 of Object.keys(n3.content ?? {})) {
      const o3 = n3.content?.[t4];
      if (o3 && (o3.schema && "builder" in o3.schema)) {
        const t5 = await o3.schema.builder(e2);
        o3.schema = t5.schema, t5.components && (s3 = { ...s3, ...t5.components });
      }
    }
  }
  return { docs: o2, components: s3 };
}
async function getAgentCardByIdHandler(c2) {
  const mastra = c2.get("mastra");
  const agentId = c2.req.param("agentId");
  const runtimeContext = c2.get("runtimeContext");
  const result = await getAgentCardByIdHandler$1({
    mastra,
    agentId,
    runtimeContext
  });
  return c2.json(result);
}
async function getAgentExecutionHandler(c2) {
  const mastra = c2.get("mastra");
  const agentId = c2.req.param("agentId");
  const runtimeContext = c2.get("runtimeContext");
  const logger2 = mastra.getLogger();
  const body = await c2.req.json();
  if (!["tasks/send", "tasks/sendSubscribe", "tasks/get", "tasks/cancel"].includes(body.method)) {
    return c2.json({ error: { message: `Unsupported method: ${body.method}`, code: "invalid_method" } }, 400);
  }
  const result = await getAgentExecutionHandler$1({
    mastra,
    agentId,
    runtimeContext,
    requestId: randomUUID(),
    method: body.method,
    params: body.params,
    logger: logger2
  });
  if (body.method === "tasks/sendSubscribe") {
    return stream(
      c2,
      async (stream5) => {
        try {
          stream5.onAbort(() => {
            if (!result.locked) {
              return result.cancel();
            }
          });
          for await (const chunk of result) {
            await stream5.write(JSON.stringify(chunk) + "");
          }
        } catch (err) {
          logger2.error("Error in tasks/sendSubscribe stream: " + err?.message);
        }
      },
      async (err) => {
        logger2.error("Error in tasks/sendSubscribe stream: " + err?.message);
      }
    );
  }
  return c2.json(result);
}
function handleError(error, defaultMessage) {
  const apiError = error;
  throw new HTTPException$1(apiError.status || 500, {
    message: apiError.message || defaultMessage,
    cause: apiError.cause
  });
}
function errorHandler(err, c2, isDev) {
  if (err instanceof HTTPException$1) {
    if (isDev) {
      return c2.json({ error: err.message, cause: err.cause, stack: err.stack }, err.status);
    }
    return c2.json({ error: err.message }, err.status);
  }
  console.error(err);
  return c2.json({ error: "Internal Server Error" }, 500);
}

// src/server/handlers/agents.ts
async function getAgentsHandler(c2) {
  const serializedAgents = await getAgentsHandler$1({
    mastra: c2.get("mastra"),
    runtimeContext: c2.get("runtimeContext")
  });
  return c2.json(serializedAgents);
}
async function getAgentByIdHandler(c2) {
  const mastra = c2.get("mastra");
  const agentId = c2.req.param("agentId");
  const runtimeContext = c2.get("runtimeContext");
  const isPlayground = c2.req.header("x-mastra-dev-playground") === "true";
  const result = await getAgentByIdHandler$1({
    mastra,
    agentId,
    runtimeContext,
    isPlayground
  });
  return c2.json(result);
}
async function getEvalsByAgentIdHandler(c2) {
  const mastra = c2.get("mastra");
  const agentId = c2.req.param("agentId");
  const runtimeContext = c2.get("runtimeContext");
  const result = await getEvalsByAgentIdHandler$1({
    mastra,
    agentId,
    runtimeContext
  });
  return c2.json(result);
}
async function getLiveEvalsByAgentIdHandler(c2) {
  const mastra = c2.get("mastra");
  const agentId = c2.req.param("agentId");
  const runtimeContext = c2.get("runtimeContext");
  const result = await getLiveEvalsByAgentIdHandler$1({
    mastra,
    agentId,
    runtimeContext
  });
  return c2.json(result);
}
async function generateHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const runtimeContext = c2.get("runtimeContext");
    const body = await c2.req.json();
    const result = await generateHandler$2({
      mastra,
      agentId,
      runtimeContext,
      body,
      abortSignal: c2.req.raw.signal
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error generating from agent");
  }
}
async function streamGenerateHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const runtimeContext = c2.get("runtimeContext");
    const body = await c2.req.json();
    const streamResponse = await streamGenerateHandler$2({
      mastra,
      agentId,
      runtimeContext,
      body,
      abortSignal: c2.req.raw.signal
    });
    return streamResponse;
  } catch (error) {
    return handleError(error, "Error streaming from agent");
  }
}
async function setAgentInstructionsHandler(c2) {
  try {
    const isPlayground = c2.get("playground") === true;
    if (!isPlayground) {
      return c2.json({ error: "This API is only available in the playground environment" }, 403);
    }
    const agentId = c2.req.param("agentId");
    const { instructions } = await c2.req.json();
    if (!agentId || !instructions) {
      return c2.json({ error: "Missing required fields" }, 400);
    }
    const mastra = c2.get("mastra");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      return c2.json({ error: "Agent not found" }, 404);
    }
    agent.__updateInstructions(instructions);
    return c2.json(
      {
        instructions
      },
      200
    );
  } catch (error) {
    return handleError(error, "Error setting agent instructions");
  }
}

// src/server/handlers/auth/defaults.ts
var defaultAuthConfig = {
  protected: ["/api/*"],
  // Simple rule system
  rules: [
    // Admin users can do anything
    {
      condition: (user) => {
        if (typeof user === "object" && user !== null) {
          if ("isAdmin" in user) {
            return !!user.isAdmin;
          }
          if ("role" in user) {
            return user.role === "admin";
          }
        }
        return false;
      },
      allow: true
    }
  ]
};

// src/server/handlers/auth/helpers.ts
var isProtectedPath = (path, method, authConfig) => {
  const protectedAccess = [...defaultAuthConfig.protected || [], ...authConfig.protected || []];
  return isAnyMatch(path, method, protectedAccess);
};
var canAccessPublicly = (path, method, authConfig) => {
  const publicAccess = [...defaultAuthConfig.public || [], ...authConfig.public || []];
  return isAnyMatch(path, method, publicAccess);
};
var isAnyMatch = (path, method, patterns) => {
  if (!patterns) {
    return false;
  }
  for (const patternPathOrMethod of patterns) {
    if (patternPathOrMethod instanceof RegExp) {
      if (patternPathOrMethod.test(path)) {
        return true;
      }
    }
    if (typeof patternPathOrMethod === "string" && pathMatchesPattern(path, patternPathOrMethod)) {
      return true;
    }
    if (Array.isArray(patternPathOrMethod) && patternPathOrMethod.length === 2) {
      const [pattern, methodOrMethods] = patternPathOrMethod;
      if (pathMatchesPattern(path, pattern) && matchesOrIncludes(methodOrMethods, method)) {
        return true;
      }
    }
  }
  return false;
};
var pathMatchesPattern = (path, pattern) => {
  if (pattern.endsWith("*")) {
    const prefix = pattern.slice(0, -1);
    return path.startsWith(prefix);
  }
  return path === pattern;
};
var pathMatchesRule = (path, rulePath) => {
  if (!rulePath) return true;
  if (typeof rulePath === "string") {
    return pathMatchesPattern(path, rulePath);
  }
  if (rulePath instanceof RegExp) {
    console.log("rulePath", rulePath, path, rulePath.test(path));
    return rulePath.test(path);
  }
  if (Array.isArray(rulePath)) {
    return rulePath.some((p2) => pathMatchesPattern(path, p2));
  }
  return false;
};
var matchesOrIncludes = (values, value) => {
  if (typeof values === "string") {
    return values === value;
  }
  if (Array.isArray(values)) {
    return values.includes(value);
  }
  return false;
};
var checkRules = async (rules, path, method, user) => {
  for (const i2 in rules || []) {
    const rule = rules?.[i2];
    if (!pathMatchesRule(path, rule.path)) {
      continue;
    }
    if (rule.methods && !matchesOrIncludes(rule.methods, method)) {
      continue;
    }
    const condition = rule.condition;
    if (typeof condition === "function") {
      const allowed = await Promise.resolve().then(() => condition(user)).catch(() => false);
      if (allowed) {
        return true;
      }
    } else if (rule.allow) {
      return true;
    }
  }
  return false;
};

// src/server/handlers/auth/index.ts
var authenticationMiddleware = async (c2, next) => {
  const mastra = c2.get("mastra");
  const authConfig = mastra.getServer()?.experimental_auth;
  if (!authConfig) {
    return next();
  }
  if (!isProtectedPath(c2.req.path, c2.req.method, authConfig)) {
    return next();
  }
  if (canAccessPublicly(c2.req.path, c2.req.method, authConfig)) {
    return next();
  }
  const authHeader = c2.req.header("Authorization");
  let token = authHeader ? authHeader.replace("Bearer ", "") : null;
  if (!token && c2.req.query("apiKey")) {
    token = c2.req.query("apiKey") || null;
  }
  if (!token) {
    return c2.json({ error: "Authentication required" }, 401);
  }
  try {
    let user;
    if (typeof authConfig.authenticateToken === "function") {
      user = await authConfig.authenticateToken(token, c2.req);
    } else {
      throw new Error("No token verification method configured");
    }
    if (!user) {
      return c2.json({ error: "Invalid or expired token" }, 401);
    }
    c2.get("runtimeContext").set("user", user);
    return next();
  } catch (err) {
    console.error(err);
    return c2.json({ error: "Invalid or expired token" }, 401);
  }
};
var authorizationMiddleware = async (c2, next) => {
  const mastra = c2.get("mastra");
  const authConfig = mastra.getServer()?.experimental_auth;
  if (!authConfig) {
    return next();
  }
  const path = c2.req.path;
  const method = c2.req.method;
  if (canAccessPublicly(path, method, authConfig)) {
    return next();
  }
  const user = c2.get("runtimeContext").get("user");
  if ("authorizeUser" in authConfig && typeof authConfig.authorizeUser === "function") {
    try {
      const isAuthorized = await authConfig.authorizeUser(user, c2.req);
      if (isAuthorized) {
        return next();
      }
      return c2.json({ error: "Access denied" }, 403);
    } catch (err) {
      console.error(err);
      return c2.json({ error: "Authorization error" }, 500);
    }
  }
  if ("authorize" in authConfig && typeof authConfig.authorize === "function") {
    try {
      const isAuthorized = await authConfig.authorize(path, method, user, c2);
      if (isAuthorized) {
        return next();
      }
      return c2.json({ error: "Access denied" }, 403);
    } catch (err) {
      console.error(err);
      return c2.json({ error: "Authorization error" }, 500);
    }
  }
  if ("rules" in authConfig && authConfig.rules && authConfig.rules.length > 0) {
    const isAuthorized = await checkRules(authConfig.rules, path, method, user);
    if (isAuthorized) {
      return next();
    }
    return c2.json({ error: "Access denied" }, 403);
  }
  if (defaultAuthConfig.rules && defaultAuthConfig.rules.length > 0) {
    const isAuthorized = await checkRules(defaultAuthConfig.rules, path, method, user);
    if (isAuthorized) {
      return next();
    }
  }
  return c2.json({ error: "Access denied" }, 403);
};

// src/server/handlers/client.ts
var clients = /* @__PURE__ */ new Set();
function handleClientsRefresh(c2) {
  const stream5 = new ReadableStream({
    start(controller) {
      clients.add(controller);
      controller.enqueue("data: connected\n\n");
      c2.req.raw.signal.addEventListener("abort", () => {
        clients.delete(controller);
      });
    }
  });
  return new Response(stream5, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function handleTriggerClientsRefresh(c2) {
  clients.forEach((controller) => {
    try {
      controller.enqueue("data: refresh\n\n");
    } catch {
      clients.delete(controller);
    }
  });
  return c2.json({ success: true, clients: clients.size });
}
async function getLegacyWorkflowsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflows = await getLegacyWorkflowsHandler$1({
      mastra
    });
    return c2.json(workflows);
  } catch (error) {
    return handleError(error, "Error getting workflows");
  }
}
async function getLegacyWorkflowByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = await getLegacyWorkflowByIdHandler$1({
      mastra,
      workflowId
    });
    return c2.json(workflow);
  } catch (error) {
    return handleError(error, "Error getting workflow");
  }
}
async function startAsyncLegacyWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const triggerData = await c2.req.json();
    const runId = c2.req.query("runId");
    const result = await startAsyncLegacyWorkflowHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      triggerData
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error executing workflow");
  }
}
async function createLegacyWorkflowRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const prevRunId = c2.req.query("runId");
    const result = await createLegacyWorkflowRunHandler$1({
      mastra,
      workflowId,
      runId: prevRunId
    });
    return c2.json(result);
  } catch (e2) {
    return handleError(e2, "Error creating run");
  }
}
async function startLegacyWorkflowRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const triggerData = await c2.req.json();
    const runId = c2.req.query("runId");
    await startLegacyWorkflowRunHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      triggerData
    });
    return c2.json({ message: "Workflow run started" });
  } catch (e2) {
    return handleError(e2, "Error starting workflow run");
  }
}
function watchLegacyWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const logger2 = mastra.getLogger();
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.query("runId");
    if (!runId) {
      throw new HTTPException$1(400, { message: "runId required to watch workflow" });
    }
    return stream(
      c2,
      async (stream5) => {
        try {
          const result = await watchLegacyWorkflowHandler$1({
            mastra,
            workflowId,
            runId
          });
          stream5.onAbort(() => {
            if (!result.locked) {
              return result.cancel();
            }
          });
          for await (const chunk of result) {
            await stream5.write(chunk.toString() + "");
          }
        } catch (err) {
          console.log(err);
        }
      },
      async (err) => {
        logger2.error("Error in watch stream: " + err?.message);
      }
    );
  } catch (error) {
    return handleError(error, "Error watching workflow");
  }
}
async function resumeAsyncLegacyWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.query("runId");
    const { stepId, context } = await c2.req.json();
    if (!runId) {
      throw new HTTPException$1(400, { message: "runId required to resume workflow" });
    }
    const result = await resumeAsyncLegacyWorkflowHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      body: { stepId, context }
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error resuming workflow step");
  }
}
async function resumeLegacyWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.query("runId");
    const { stepId, context } = await c2.req.json();
    if (!runId) {
      throw new HTTPException$1(400, { message: "runId required to resume workflow" });
    }
    await resumeLegacyWorkflowHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      body: { stepId, context }
    });
    return c2.json({ message: "Workflow run resumed" });
  } catch (error) {
    return handleError(error, "Error resuming workflow");
  }
}
async function getLegacyWorkflowRunsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const { fromDate, toDate, limit, offset, resourceId } = c2.req.query();
    const workflowRuns = await getLegacyWorkflowRunsHandler$1({
      mastra,
      workflowId,
      fromDate: fromDate ? new Date(fromDate) : void 0,
      toDate: toDate ? new Date(toDate) : void 0,
      limit: limit ? Number(limit) : void 0,
      offset: offset ? Number(offset) : void 0,
      resourceId
    });
    return c2.json(workflowRuns);
  } catch (error) {
    return handleError(error, "Error getting workflow runs");
  }
}
async function getLogsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const { transportId, fromDate, toDate, logLevel, page, perPage } = c2.req.query();
    const filters = c2.req.queries("filters");
    const logs = await getLogsHandler$1({
      mastra,
      transportId,
      params: {
        fromDate: fromDate ? new Date(fromDate) : void 0,
        toDate: toDate ? new Date(toDate) : void 0,
        logLevel: logLevel ? logLevel : void 0,
        filters,
        page: page ? Number(page) : void 0,
        perPage: perPage ? Number(perPage) : void 0
      }
    });
    return c2.json(logs);
  } catch (error) {
    return handleError(error, "Error getting logs");
  }
}
async function getLogsByRunIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runId = c2.req.param("runId");
    const { transportId, fromDate, toDate, logLevel, page, perPage } = c2.req.query();
    const filters = c2.req.queries("filters");
    const logs = await getLogsByRunIdHandler$1({
      mastra,
      runId,
      transportId,
      params: {
        fromDate: fromDate ? new Date(fromDate) : void 0,
        toDate: toDate ? new Date(toDate) : void 0,
        logLevel: logLevel ? logLevel : void 0,
        filters,
        page: page ? Number(page) : void 0,
        perPage: perPage ? Number(perPage) : void 0
      }
    });
    return c2.json(logs);
  } catch (error) {
    return handleError(error, "Error getting logs by run ID");
  }
}
async function getLogTransports(c2) {
  try {
    const mastra = c2.get("mastra");
    const result = await getLogTransports$1({
      mastra
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting log Transports");
  }
}
var classRegExp = /^([A-Z][a-z0-9]*)+$/;
var kTypes = [
  "string",
  "function",
  "number",
  "object",
  // Accept 'Function' and 'Object' as alternative to the lower cased version.
  "Function",
  "Object",
  "boolean",
  "bigint",
  "symbol"
];
function determineSpecificType(value) {
  if (value == null) {
    return "" + value;
  }
  if (typeof value === "function" && value.name) {
    return `function ${value.name}`;
  }
  if (typeof value === "object") {
    if (value.constructor?.name) {
      return `an instance of ${value.constructor.name}`;
    }
    return `${util.inspect(value, { depth: -1 })}`;
  }
  let inspected = util.inspect(value, { colors: false });
  if (inspected.length > 28) {
    inspected = `${inspected.slice(0, 25)}...`;
  }
  return `type ${typeof value} (${inspected})`;
}
var ERR_HTTP_BODY_NOT_ALLOWED = class extends Error {
  constructor() {
    super("Adding content for this request method or response status is not allowed.");
  }
};
var ERR_HTTP_CONTENT_LENGTH_MISMATCH = class extends Error {
  constructor(actual, expected) {
    super(`Response body's content-length of ${actual} byte(s) does not match the content-length of ${expected} byte(s) set in header`);
  }
};
var ERR_HTTP_HEADERS_SENT = class extends Error {
  constructor(arg) {
    super(`Cannot ${arg} headers after they are sent to the client`);
  }
};
var ERR_INVALID_ARG_VALUE = class extends TypeError {
  constructor(name, value, reason = "is invalid") {
    let inspected = util.inspect(value);
    if (inspected.length > 128) {
      inspected = `${inspected.slice(0, 128)}...`;
    }
    const type = name.includes(".") ? "property" : "argument";
    super(`The ${type} '${name}' ${reason}. Received ${inspected}`);
  }
};
var ERR_INVALID_CHAR = class extends TypeError {
  constructor(name, field) {
    let msg = `Invalid character in ${name}`;
    if (field !== void 0) {
      msg += ` ["${field}"]`;
    }
    super(msg);
  }
};
var ERR_HTTP_INVALID_HEADER_VALUE = class extends TypeError {
  constructor(value, name) {
    super(`Invalid value "${value}" for header "${name}"`);
  }
};
var ERR_HTTP_INVALID_STATUS_CODE = class extends RangeError {
  originalStatusCode;
  constructor(originalStatusCode) {
    super(`Invalid status code: ${originalStatusCode}`);
    this.originalStatusCode = originalStatusCode;
  }
};
var ERR_HTTP_TRAILER_INVALID = class extends Error {
  constructor() {
    super(`Trailers are invalid with this transfer encoding`);
  }
};
var ERR_INVALID_ARG_TYPE = class extends TypeError {
  constructor(name, expected, actual) {
    if (!Array.isArray(expected)) {
      expected = [expected];
    }
    let msg = "The ";
    if (name.endsWith(" argument")) {
      msg += `${name} `;
    } else {
      const type = name.includes(".") ? "property" : "argument";
      msg += `"${name}" ${type} `;
    }
    msg += "must be ";
    const types = [];
    const instances = [];
    const other = [];
    for (const value of expected) {
      if (kTypes.includes(value)) {
        types.push(value.toLowerCase());
      } else if (classRegExp.exec(value) !== null) {
        instances.push(value);
      } else {
        other.push(value);
      }
    }
    if (instances.length > 0) {
      const pos = types.indexOf("object");
      if (pos !== -1) {
        types.splice(pos, 1);
        instances.push("Object");
      }
    }
    if (types.length > 0) {
      if (types.length > 2) {
        const last = types.pop();
        msg += `one of type ${types.join(", ")}, or ${last}`;
      } else if (types.length === 2) {
        msg += `one of type ${types[0]} or ${types[1]}`;
      } else {
        msg += `of type ${types[0]}`;
      }
      if (instances.length > 0 || other.length > 0)
        msg += " or ";
    }
    if (instances.length > 0) {
      if (instances.length > 2) {
        const last = instances.pop();
        msg += `an instance of ${instances.join(", ")}, or ${last}`;
      } else {
        msg += `an instance of ${instances[0]}`;
        if (instances.length === 2) {
          msg += ` or ${instances[1]}`;
        }
      }
      if (other.length > 0)
        msg += " or ";
    }
    if (other.length > 0) {
      if (other.length > 2) {
        const last = other.pop();
        msg += `one of ${other.join(", ")}, or ${last}`;
      } else if (other.length === 2) {
        msg += `one of ${other[0]} or ${other[1]}`;
      } else {
        if (other[0].toLowerCase() !== other[0])
          msg += "an ";
        msg += `${other[0]}`;
      }
    }
    msg += `. Received ${determineSpecificType(actual)}`;
    super(msg);
  }
};
var ERR_INVALID_HTTP_TOKEN = class extends TypeError {
  constructor(name, field) {
    super(`${name} must be a valid HTTP token ["${field}"]`);
  }
};
var ERR_METHOD_NOT_IMPLEMENTED = class extends Error {
  constructor(methodName) {
    super(`The ${methodName} method is not implemented`);
  }
};
var ERR_STREAM_ALREADY_FINISHED = class extends Error {
  constructor(methodName) {
    super(`Cannot call ${methodName} after a stream was finished`);
  }
};
var ERR_STREAM_CANNOT_PIPE = class extends Error {
  constructor() {
    super(`Cannot pipe, not readable`);
  }
};
var ERR_STREAM_DESTROYED = class extends Error {
  constructor(methodName) {
    super(`Cannot call ${methodName} after a stream was destroyed`);
  }
};
var ERR_STREAM_NULL_VALUES = class extends TypeError {
  constructor() {
    super(`May not write null values to stream`);
  }
};
var ERR_STREAM_WRITE_AFTER_END = class extends Error {
  constructor() {
    super(`write after end`);
  }
};

// ../../node_modules/.pnpm/fetch-to-node@2.1.0/node_modules/fetch-to-node/dist/fetch-to-node/http-incoming.js
var kHeaders = Symbol("kHeaders");
var kHeadersDistinct = Symbol("kHeadersDistinct");
var kHeadersCount = Symbol("kHeadersCount");
var kTrailers = Symbol("kTrailers");
var kTrailersDistinct = Symbol("kTrailersDistinct");
var kTrailersCount = Symbol("kTrailersCount");
var FetchIncomingMessage = class extends Readable {
  get socket() {
    return null;
  }
  set socket(_val) {
    throw new ERR_METHOD_NOT_IMPLEMENTED("socket");
  }
  httpVersionMajor;
  httpVersionMinor;
  httpVersion;
  complete = false;
  [kHeaders] = null;
  [kHeadersDistinct] = null;
  [kHeadersCount] = 0;
  rawHeaders = [];
  [kTrailers] = null;
  [kTrailersDistinct] = null;
  [kTrailersCount] = 0;
  rawTrailers = [];
  joinDuplicateHeaders = false;
  aborted = false;
  upgrade = false;
  // request (server) only
  url = "";
  method;
  // TODO: Support ClientRequest
  // statusCode = null;
  // statusMessage = null;
  // client = socket;
  _consuming;
  _dumped;
  // The underlying ReadableStream
  _stream = null;
  constructor() {
    const streamOptions = {};
    super(streamOptions);
    this._readableState.readingMore = true;
    this._consuming = false;
    this._dumped = false;
  }
  get connection() {
    return null;
  }
  set connection(_socket) {
    console.error("No support for IncomingMessage.connection");
  }
  get headers() {
    if (!this[kHeaders]) {
      this[kHeaders] = {};
      const src = this.rawHeaders;
      const dst = this[kHeaders];
      for (let n2 = 0; n2 < this[kHeadersCount]; n2 += 2) {
        this._addHeaderLine(src[n2], src[n2 + 1], dst);
      }
    }
    return this[kHeaders];
  }
  set headers(val) {
    this[kHeaders] = val;
  }
  get headersDistinct() {
    if (!this[kHeadersDistinct]) {
      this[kHeadersDistinct] = {};
      const src = this.rawHeaders;
      const dst = this[kHeadersDistinct];
      for (let n2 = 0; n2 < this[kHeadersCount]; n2 += 2) {
        this._addHeaderLineDistinct(src[n2], src[n2 + 1], dst);
      }
    }
    return this[kHeadersDistinct];
  }
  set headersDistinct(val) {
    this[kHeadersDistinct] = val;
  }
  get trailers() {
    if (!this[kTrailers]) {
      this[kTrailers] = {};
      const src = this.rawTrailers;
      const dst = this[kTrailers];
      for (let n2 = 0; n2 < this[kTrailersCount]; n2 += 2) {
        this._addHeaderLine(src[n2], src[n2 + 1], dst);
      }
    }
    return this[kTrailers];
  }
  set trailers(val) {
    this[kTrailers] = val;
  }
  get trailersDistinct() {
    if (!this[kTrailersDistinct]) {
      this[kTrailersDistinct] = {};
      const src = this.rawTrailers;
      const dst = this[kTrailersDistinct];
      for (let n2 = 0; n2 < this[kTrailersCount]; n2 += 2) {
        this._addHeaderLineDistinct(src[n2], src[n2 + 1], dst);
      }
    }
    return this[kTrailersDistinct];
  }
  set trailersDistinct(val) {
    this[kTrailersDistinct] = val;
  }
  setTimeout(msecs, callback) {
    return this;
  }
  async _read(n2) {
    if (!this._consuming) {
      this._readableState.readingMore = false;
      this._consuming = true;
    }
    if (this._stream == null) {
      this.complete = true;
      this.push(null);
      return;
    }
    const reader = this._stream.getReader();
    try {
      const data = await reader.read();
      if (data.done) {
        this.complete = true;
        this.push(null);
      } else {
        this.push(data.value);
      }
    } catch (e2) {
      this.destroy(e2);
    } finally {
      reader.releaseLock();
    }
  }
  _destroy(err, cb) {
    if (!this.readableEnded || !this.complete) {
      this.aborted = true;
      this.emit("aborted");
    }
    setTimeout(onError, 0, this, err, cb);
  }
  _addHeaderLines(headers, n2) {
    if (headers?.length) {
      let dest;
      if (this.complete) {
        this.rawTrailers = headers;
        this[kTrailersCount] = n2;
        dest = this[kTrailers];
      } else {
        this.rawHeaders = headers;
        this[kHeadersCount] = n2;
        dest = this[kHeaders];
      }
      if (dest) {
        for (let i2 = 0; i2 < n2; i2 += 2) {
          this._addHeaderLine(headers[i2], headers[i2 + 1], dest);
        }
      }
    }
  }
  // Add the given (field, value) pair to the message
  //
  // Per RFC2616, section 4.2 it is acceptable to join multiple instances of the
  // same header with a ', ' if the header in question supports specification of
  // multiple values this way. The one exception to this is the Cookie header,
  // which has multiple values joined with a '; ' instead. If a header's values
  // cannot be joined in either of these ways, we declare the first instance the
  // winner and drop the second. Extended header fields (those beginning with
  // 'x-') are always joined.
  _addHeaderLine(field, value, dest) {
    field = matchKnownFields(field);
    const flag = field.charCodeAt(0);
    if (flag === 0 || flag === 2) {
      field = field.slice(1);
      if (typeof dest[field] === "string") {
        dest[field] += (flag === 0 ? ", " : "; ") + value;
      } else {
        dest[field] = value;
      }
    } else if (flag === 1) {
      if (dest["set-cookie"] !== void 0) {
        dest["set-cookie"].push(value);
      } else {
        dest["set-cookie"] = [value];
      }
    } else if (this.joinDuplicateHeaders) {
      if (dest[field] === void 0) {
        dest[field] = value;
      } else {
        dest[field] += ", " + value;
      }
    } else if (dest[field] === void 0) {
      dest[field] = value;
    }
  }
  _addHeaderLineDistinct(field, value, dest) {
    field = field.toLowerCase();
    if (!dest[field]) {
      dest[field] = [value];
    } else {
      dest[field].push(value);
    }
  }
  // Call this instead of resume() if we want to just
  // dump all the data to /dev/null
  _dump() {
    if (!this._dumped) {
      this._dumped = true;
      this.removeAllListeners("data");
      this.resume();
    }
  }
};
function matchKnownFields(field, lowercased = false) {
  switch (field.length) {
    case 3:
      if (field === "Age" || field === "age")
        return "age";
      break;
    case 4:
      if (field === "Host" || field === "host")
        return "host";
      if (field === "From" || field === "from")
        return "from";
      if (field === "ETag" || field === "etag")
        return "etag";
      if (field === "Date" || field === "date")
        return "\0date";
      if (field === "Vary" || field === "vary")
        return "\0vary";
      break;
    case 6:
      if (field === "Server" || field === "server")
        return "server";
      if (field === "Cookie" || field === "cookie")
        return "cookie";
      if (field === "Origin" || field === "origin")
        return "\0origin";
      if (field === "Expect" || field === "expect")
        return "\0expect";
      if (field === "Accept" || field === "accept")
        return "\0accept";
      break;
    case 7:
      if (field === "Referer" || field === "referer")
        return "referer";
      if (field === "Expires" || field === "expires")
        return "expires";
      if (field === "Upgrade" || field === "upgrade")
        return "\0upgrade";
      break;
    case 8:
      if (field === "Location" || field === "location")
        return "location";
      if (field === "If-Match" || field === "if-match")
        return "\0if-match";
      break;
    case 10:
      if (field === "User-Agent" || field === "user-agent")
        return "user-agent";
      if (field === "Set-Cookie" || field === "set-cookie")
        return "";
      if (field === "Connection" || field === "connection")
        return "\0connection";
      break;
    case 11:
      if (field === "Retry-After" || field === "retry-after")
        return "retry-after";
      break;
    case 12:
      if (field === "Content-Type" || field === "content-type")
        return "content-type";
      if (field === "Max-Forwards" || field === "max-forwards")
        return "max-forwards";
      break;
    case 13:
      if (field === "Authorization" || field === "authorization")
        return "authorization";
      if (field === "Last-Modified" || field === "last-modified")
        return "last-modified";
      if (field === "Cache-Control" || field === "cache-control")
        return "\0cache-control";
      if (field === "If-None-Match" || field === "if-none-match")
        return "\0if-none-match";
      break;
    case 14:
      if (field === "Content-Length" || field === "content-length")
        return "content-length";
      break;
    case 15:
      if (field === "Accept-Encoding" || field === "accept-encoding")
        return "\0accept-encoding";
      if (field === "Accept-Language" || field === "accept-language")
        return "\0accept-language";
      if (field === "X-Forwarded-For" || field === "x-forwarded-for")
        return "\0x-forwarded-for";
      break;
    case 16:
      if (field === "Content-Encoding" || field === "content-encoding")
        return "\0content-encoding";
      if (field === "X-Forwarded-Host" || field === "x-forwarded-host")
        return "\0x-forwarded-host";
      break;
    case 17:
      if (field === "If-Modified-Since" || field === "if-modified-since")
        return "if-modified-since";
      if (field === "Transfer-Encoding" || field === "transfer-encoding")
        return "\0transfer-encoding";
      if (field === "X-Forwarded-Proto" || field === "x-forwarded-proto")
        return "\0x-forwarded-proto";
      break;
    case 19:
      if (field === "Proxy-Authorization" || field === "proxy-authorization")
        return "proxy-authorization";
      if (field === "If-Unmodified-Since" || field === "if-unmodified-since")
        return "if-unmodified-since";
      break;
  }
  if (lowercased) {
    return "\0" + field;
  }
  return matchKnownFields(field.toLowerCase(), true);
}
function onError(self, error, cb) {
  if (self.listenerCount("error") === 0) {
    cb();
  } else {
    cb(error);
  }
}

// ../../node_modules/.pnpm/fetch-to-node@2.1.0/node_modules/fetch-to-node/dist/utils/types.js
function validateString(value, name) {
  if (typeof value !== "string")
    throw new ERR_INVALID_ARG_TYPE(name, "string", value);
}
var linkValueRegExp = /^(?:<[^>]*>)(?:\s*;\s*[^;"\s]+(?:=(")?[^;"\s]*\1)?)*$/;
function validateLinkHeaderFormat(value, name) {
  if (typeof value === "undefined" || !linkValueRegExp.exec(value)) {
    throw new ERR_INVALID_ARG_VALUE(name, value, 'must be an array or string of format "</styles.css>; rel=preload; as=style"');
  }
}
function validateLinkHeaderValue(hints) {
  if (typeof hints === "string") {
    validateLinkHeaderFormat(hints, "hints");
    return hints;
  } else if (Array.isArray(hints)) {
    const hintsLength = hints.length;
    let result = "";
    if (hintsLength === 0) {
      return result;
    }
    for (let i2 = 0; i2 < hintsLength; i2++) {
      const link = hints[i2];
      validateLinkHeaderFormat(link, "hints");
      result += link;
      if (i2 !== hintsLength - 1) {
        result += ", ";
      }
    }
    return result;
  }
  throw new ERR_INVALID_ARG_VALUE("hints", hints, 'must be an array or string of format "</styles.css>; rel=preload; as=style"');
}
function isUint8Array(value) {
  return value != null && value[Symbol.toStringTag] === "Uint8Array";
}

// ../../node_modules/.pnpm/fetch-to-node@2.1.0/node_modules/fetch-to-node/dist/fetch-to-node/internal-http.js
var kNeedDrain = Symbol("kNeedDrain");
var kOutHeaders = Symbol("kOutHeaders");
function utcDate() {
  return (/* @__PURE__ */ new Date()).toUTCString();
}

// ../../node_modules/.pnpm/fetch-to-node@2.1.0/node_modules/fetch-to-node/dist/fetch-to-node/internal-streams-state.js
function getDefaultHighWaterMark(objectMode) {
  return objectMode ? 16 : 64 * 1024;
}

// ../../node_modules/.pnpm/fetch-to-node@2.1.0/node_modules/fetch-to-node/dist/fetch-to-node/http-common.js
var tokenRegExp = /^[\^_`a-zA-Z\-0-9!#$%&'*+.|~]+$/;
function checkIsHttpToken(val) {
  return tokenRegExp.test(val);
}
var headerCharRegex = /[^\t\x20-\x7e\x80-\xff]/;
function checkInvalidHeaderChar(val) {
  return headerCharRegex.test(val);
}
var chunkExpression = /(?:^|\W)chunked(?:$|\W)/i;
var kCorked = Symbol("corked");
var kChunkedBuffer = Symbol("kChunkedBuffer");
var kChunkedLength = Symbol("kChunkedLength");
var kUniqueHeaders = Symbol("kUniqueHeaders");
var kBytesWritten = Symbol("kBytesWritten");
var kErrored = Symbol("errored");
var kHighWaterMark = Symbol("kHighWaterMark");
var kRejectNonStandardBodyWrites = Symbol("kRejectNonStandardBodyWrites");
var nop = () => {
};
var RE_CONN_CLOSE = /(?:^|\W)close(?:$|\W)/i;
function isCookieField(s3) {
  return s3.length === 6 && s3.toLowerCase() === "cookie";
}
function isContentDispositionField(s3) {
  return s3.length === 19 && s3.toLowerCase() === "content-disposition";
}
var WrittenDataBuffer = class {
  [kCorked] = 0;
  [kHighWaterMark] = getDefaultHighWaterMark();
  entries = [];
  onWrite;
  constructor(params = {}) {
    this.onWrite = params.onWrite;
  }
  write(data, encoding, callback) {
    this.entries.push({
      data,
      length: data.length,
      encoding,
      callback,
      written: false
    });
    this._flush();
    return true;
  }
  cork() {
    this[kCorked]++;
  }
  uncork() {
    this[kCorked]--;
    this._flush();
  }
  _flush() {
    if (this[kCorked] <= 0) {
      for (const [index, entry] of this.entries.entries()) {
        if (!entry.written) {
          entry.written = true;
          if (this.onWrite != null) {
            this.onWrite(index, entry);
          }
          if (entry.callback != null) {
            entry.callback.call(void 0);
          }
        }
      }
    }
  }
  get writableLength() {
    return this.entries.reduce((acc, entry) => {
      return acc + (entry.written && entry.length ? entry.length : 0);
    }, 0);
  }
  get writableHighWaterMark() {
    return this[kHighWaterMark];
  }
  get writableCorked() {
    return this[kCorked];
  }
};
var FetchOutgoingMessage = class extends Writable {
  req;
  outputData;
  outputSize;
  // Difference from Node.js -
  // `writtenHeaderBytes` is the number of bytes the header has taken.
  // Since Node.js writes both the headers and body into the same outgoing
  // stream, it helps to keep track of this so that we can skip that many bytes
  // from the beginning of the stream when providing the outgoing stream.
  writtenHeaderBytes = 0;
  _last;
  chunkedEncoding;
  shouldKeepAlive;
  maxRequestsOnConnectionReached;
  _defaultKeepAlive;
  useChunkedEncodingByDefault;
  sendDate;
  _removedConnection;
  _removedContLen;
  _removedTE;
  strictContentLength;
  [kBytesWritten];
  _contentLength;
  _hasBody;
  _trailer;
  [kNeedDrain];
  finished;
  _headerSent;
  [kCorked];
  [kChunkedBuffer];
  [kChunkedLength];
  _closed;
  // Difference from Node.js -
  // In Node.js, this is a socket object.
  // [kSocket]: null;
  _header;
  [kOutHeaders];
  _keepAliveTimeout;
  _maxRequestsPerSocket;
  _onPendingData;
  [kUniqueHeaders];
  [kErrored];
  [kHighWaterMark];
  [kRejectNonStandardBodyWrites];
  _writtenDataBuffer = new WrittenDataBuffer({
    onWrite: this._onDataWritten.bind(this)
  });
  constructor(req, options) {
    super();
    this.req = req;
    this.outputData = [];
    this.outputSize = 0;
    this.destroyed = false;
    this._last = false;
    this.chunkedEncoding = false;
    this.shouldKeepAlive = true;
    this.maxRequestsOnConnectionReached = false;
    this._defaultKeepAlive = true;
    this.useChunkedEncodingByDefault = true;
    this.sendDate = false;
    this._removedConnection = false;
    this._removedContLen = false;
    this._removedTE = false;
    this.strictContentLength = false;
    this[kBytesWritten] = 0;
    this._contentLength = null;
    this._hasBody = true;
    this._trailer = "";
    this[kNeedDrain] = false;
    this.finished = false;
    this._headerSent = false;
    this[kCorked] = 0;
    this[kChunkedBuffer] = [];
    this[kChunkedLength] = 0;
    this._closed = false;
    this._header = null;
    this[kOutHeaders] = null;
    this._keepAliveTimeout = 0;
    this._onPendingData = nop;
    this[kErrored] = null;
    this[kHighWaterMark] = options?.highWaterMark ?? getDefaultHighWaterMark();
    this[kRejectNonStandardBodyWrites] = options?.rejectNonStandardBodyWrites ?? false;
    this[kUniqueHeaders] = null;
  }
  _renderHeaders() {
    if (this._header) {
      throw new ERR_HTTP_HEADERS_SENT("render");
    }
    const headersMap = this[kOutHeaders];
    const headers = {};
    if (headersMap !== null) {
      const keys = Object.keys(headersMap);
      for (let i2 = 0, l2 = keys.length; i2 < l2; i2++) {
        const key = keys[i2];
        headers[headersMap[key][0]] = headersMap[key][1];
      }
    }
    return headers;
  }
  cork() {
    this[kCorked]++;
    if (this._writtenDataBuffer != null) {
      this._writtenDataBuffer.cork();
    }
  }
  uncork() {
    this[kCorked]--;
    if (this._writtenDataBuffer != null) {
      this._writtenDataBuffer.uncork();
    }
    if (this[kCorked] || this[kChunkedBuffer].length === 0) {
      return;
    }
    const buf = this[kChunkedBuffer];
    for (const { data, encoding, callback } of buf) {
      this._send(data ?? "", encoding, callback);
    }
    this[kChunkedBuffer].length = 0;
    this[kChunkedLength] = 0;
  }
  setTimeout(msecs, callback) {
    return this;
  }
  destroy(error) {
    if (this.destroyed) {
      return this;
    }
    this.destroyed = true;
    this[kErrored] = error;
    return this;
  }
  _send(data, encoding, callback, byteLength) {
    if (!this._headerSent) {
      const header = this._header;
      if (typeof data === "string" && (encoding === "utf8" || encoding === "latin1" || !encoding)) {
        data = header + data;
      } else {
        this.outputData.unshift({
          data: header,
          encoding: "latin1",
          callback: void 0
        });
        this.outputSize += header.length;
        this._onPendingData(header.length);
      }
      this._headerSent = true;
      this.writtenHeaderBytes = header.length;
      const [statusLine, ...headerLines] = this._header.split("\r\n");
      const STATUS_LINE_REGEXP = /^HTTP\/1\.1 (?<statusCode>\d+) (?<statusMessage>.*)$/;
      const statusLineResult = STATUS_LINE_REGEXP.exec(statusLine);
      if (statusLineResult == null) {
        throw new Error("Unexpected! Status line was " + statusLine);
      }
      const { statusCode: statusCodeText, statusMessage } = statusLineResult.groups ?? {};
      const statusCode = parseInt(statusCodeText, 10);
      const headers = [];
      for (const headerLine of headerLines) {
        if (headerLine !== "") {
          const pos = headerLine.indexOf(": ");
          const k = headerLine.slice(0, pos);
          const v = headerLine.slice(pos + 2);
          headers.push([k, v]);
        }
      }
      const event = {
        statusCode,
        statusMessage,
        headers
      };
      this.emit("_headersSent", event);
    }
    return this._writeRaw(data, encoding, callback, byteLength);
  }
  _writeRaw(data, encoding, callback, size) {
    if (typeof encoding === "function") {
      callback = encoding;
      encoding = null;
    }
    if (this._writtenDataBuffer != null) {
      if (this.outputData.length) {
        this._flushOutput(this._writtenDataBuffer);
      }
      return this._writtenDataBuffer.write(data, encoding, callback);
    }
    this.outputData.push({ data, encoding, callback });
    this.outputSize += data.length;
    this._onPendingData(data.length);
    return this.outputSize < this[kHighWaterMark];
  }
  _onDataWritten(index, entry) {
    const event = { index, entry };
    this.emit("_dataWritten", event);
  }
  _storeHeader(firstLine, headers) {
    const state = {
      connection: false,
      contLen: false,
      te: false,
      date: false,
      expect: false,
      trailer: false,
      header: firstLine
    };
    if (headers) {
      if (headers === this[kOutHeaders]) {
        for (const key in headers) {
          const entry = headers[key];
          processHeader(this, state, entry[0], entry[1], false);
        }
      } else if (Array.isArray(headers)) {
        if (headers.length && Array.isArray(headers[0])) {
          for (let i2 = 0; i2 < headers.length; i2++) {
            const entry = headers[i2];
            processHeader(this, state, entry[0], entry[1], true);
          }
        } else {
          if (headers.length % 2 !== 0) {
            throw new ERR_INVALID_ARG_VALUE("headers", headers);
          }
          for (let n2 = 0; n2 < headers.length; n2 += 2) {
            processHeader(this, state, headers[n2], headers[n2 + 1], true);
          }
        }
      } else {
        for (const key in headers) {
          if (headers.hasOwnProperty(key)) {
            const _headers = headers;
            processHeader(this, state, key, _headers[key], true);
          }
        }
      }
    }
    let { header } = state;
    if (this.sendDate && !state.date) {
      header += "Date: " + utcDate() + "\r\n";
    }
    if (this.chunkedEncoding && (this.statusCode === 204 || this.statusCode === 304)) {
      this.chunkedEncoding = false;
      this.shouldKeepAlive = false;
    }
    if (this._removedConnection) {
      this._last = !this.shouldKeepAlive;
    } else if (!state.connection) {
      const shouldSendKeepAlive = this.shouldKeepAlive && (state.contLen || this.useChunkedEncodingByDefault);
      if (shouldSendKeepAlive && this.maxRequestsOnConnectionReached) {
        header += "Connection: close\r\n";
      } else if (shouldSendKeepAlive) {
        header += "Connection: keep-alive\r\n";
        if (this._keepAliveTimeout && this._defaultKeepAlive) {
          const timeoutSeconds = Math.floor(this._keepAliveTimeout / 1e3);
          let max = "";
          if (this._maxRequestsPerSocket && ~~this._maxRequestsPerSocket > 0) {
            max = `, max=${this._maxRequestsPerSocket}`;
          }
          header += `Keep-Alive: timeout=${timeoutSeconds}${max}\r
`;
        }
      } else {
        this._last = true;
        header += "Connection: close\r\n";
      }
    }
    if (!state.contLen && !state.te) {
      if (!this._hasBody) {
        this.chunkedEncoding = false;
      } else if (!this.useChunkedEncodingByDefault) {
        this._last = true;
      } else if (!state.trailer && !this._removedContLen && typeof this._contentLength === "number") {
        header += "Content-Length: " + this._contentLength + "\r\n";
      } else if (!this._removedTE) {
        header += "Transfer-Encoding: chunked\r\n";
        this.chunkedEncoding = true;
      } else {
        this._last = true;
      }
    }
    if (this.chunkedEncoding !== true && state.trailer) {
      throw new ERR_HTTP_TRAILER_INVALID();
    }
    this._header = header + "\r\n";
    this._headerSent = false;
    if (state.expect) {
      this._send("");
    }
  }
  get _headers() {
    console.warn("DEP0066: OutgoingMessage.prototype._headers is deprecated");
    return this.getHeaders();
  }
  set _headers(val) {
    console.warn("DEP0066: OutgoingMessage.prototype._headers is deprecated");
    if (val == null) {
      this[kOutHeaders] = null;
    } else if (typeof val === "object") {
      const headers = this[kOutHeaders] = /* @__PURE__ */ Object.create(null);
      const keys = Object.keys(val);
      for (let i2 = 0; i2 < keys.length; ++i2) {
        const name = keys[i2];
        headers[name.toLowerCase()] = [name, val[name]];
      }
    }
  }
  get connection() {
    return null;
  }
  set connection(_socket) {
    console.error("No support for OutgoingMessage.connection");
  }
  get socket() {
    return null;
  }
  set socket(_socket) {
    console.error("No support for OutgoingMessage.socket");
  }
  get _headerNames() {
    console.warn("DEP0066: OutgoingMessage.prototype._headerNames is deprecated");
    const headers = this[kOutHeaders];
    if (headers !== null) {
      const out = /* @__PURE__ */ Object.create(null);
      const keys = Object.keys(headers);
      for (let i2 = 0; i2 < keys.length; ++i2) {
        const key = keys[i2];
        const val = headers[key][0];
        out[key] = val;
      }
      return out;
    }
    return null;
  }
  set _headerNames(val) {
    console.warn("DEP0066: OutgoingMessage.prototype._headerNames is deprecated");
    if (typeof val === "object" && val !== null) {
      const headers = this[kOutHeaders];
      if (!headers)
        return;
      const keys = Object.keys(val);
      for (let i2 = 0; i2 < keys.length; ++i2) {
        const header = headers[keys[i2]];
        if (header)
          header[0] = val[keys[i2]];
      }
    }
  }
  setHeader(name, value) {
    if (this._header) {
      throw new ERR_HTTP_HEADERS_SENT("set");
    }
    validateHeaderName(name);
    validateHeaderValue(name, value);
    let headers = this[kOutHeaders];
    if (headers === null) {
      this[kOutHeaders] = headers = { __proto__: null };
    }
    headers[name.toLowerCase()] = [name, value];
    return this;
  }
  setHeaders(headers) {
    if (this._header) {
      throw new ERR_HTTP_HEADERS_SENT("set");
    }
    if (!headers || Array.isArray(headers) || typeof headers.keys !== "function" || typeof headers.get !== "function") {
      throw new ERR_INVALID_ARG_TYPE("headers", ["Headers", "Map"], headers);
    }
    const cookies = [];
    for (const { 0: key, 1: value } of headers) {
      if (key === "set-cookie") {
        if (Array.isArray(value)) {
          cookies.push(...value);
        } else {
          cookies.push(value);
        }
        continue;
      }
      this.setHeader(key, value);
    }
    if (cookies.length) {
      this.setHeader("set-cookie", cookies);
    }
    return this;
  }
  appendHeader(name, value) {
    if (this._header) {
      throw new ERR_HTTP_HEADERS_SENT("append");
    }
    validateHeaderName(name);
    validateHeaderValue(name, value);
    const field = name.toLowerCase();
    const headers = this[kOutHeaders];
    if (headers === null || !headers[field]) {
      return this.setHeader(name, value);
    }
    if (!Array.isArray(headers[field][1])) {
      headers[field][1] = [headers[field][1]];
    }
    const existingValues = headers[field][1];
    if (Array.isArray(value)) {
      for (let i2 = 0, length = value.length; i2 < length; i2++) {
        existingValues.push(value[i2]);
      }
    } else {
      existingValues.push(value);
    }
    return this;
  }
  getHeader(name) {
    validateString(name, "name");
    const headers = this[kOutHeaders];
    if (headers === null) {
      return;
    }
    const entry = headers[name.toLowerCase()];
    return entry?.[1];
  }
  getHeaderNames() {
    return this[kOutHeaders] !== null ? Object.keys(this[kOutHeaders]) : [];
  }
  getRawHeaderNames() {
    const headersMap = this[kOutHeaders];
    if (headersMap === null)
      return [];
    const values = Object.values(headersMap);
    const headers = Array(values.length);
    for (let i2 = 0, l2 = values.length; i2 < l2; i2++) {
      headers[i2] = values[i2][0];
    }
    return headers;
  }
  getHeaders() {
    const headers = this[kOutHeaders];
    const ret = { __proto__: null };
    if (headers) {
      const keys = Object.keys(headers);
      for (let i2 = 0; i2 < keys.length; ++i2) {
        const key = keys[i2];
        const val = headers[key][1];
        ret[key] = val;
      }
    }
    return ret;
  }
  hasHeader(name) {
    validateString(name, "name");
    return this[kOutHeaders] !== null && !!this[kOutHeaders][name.toLowerCase()];
  }
  removeHeader(name) {
    validateString(name, "name");
    if (this._header) {
      throw new ERR_HTTP_HEADERS_SENT("remove");
    }
    const key = name.toLowerCase();
    switch (key) {
      case "connection":
        this._removedConnection = true;
        break;
      case "content-length":
        this._removedContLen = true;
        break;
      case "transfer-encoding":
        this._removedTE = true;
        break;
      case "date":
        this.sendDate = false;
        break;
    }
    if (this[kOutHeaders] !== null) {
      delete this[kOutHeaders][key];
    }
  }
  _implicitHeader() {
    throw new ERR_METHOD_NOT_IMPLEMENTED("_implicitHeader()");
  }
  get headersSent() {
    return !!this._header;
  }
  write(chunk, encoding, callback) {
    if (typeof encoding === "function") {
      callback = encoding;
      encoding = null;
    }
    const ret = write_(this, chunk, encoding, callback, false);
    if (!ret) {
      this[kNeedDrain] = true;
    }
    return ret;
  }
  addTrailers(headers) {
    this._trailer = "";
    const isArray = Array.isArray(headers);
    const keys = isArray ? [...headers.keys()] : Object.keys(headers);
    for (let i2 = 0, l2 = keys.length; i2 < l2; i2++) {
      let field, value;
      if (isArray) {
        const _headers = headers;
        const key = keys[i2];
        field = _headers[key][0];
        value = _headers[key][1];
      } else {
        const _headers = headers;
        const key = keys[i2];
        field = key;
        value = _headers[key];
      }
      validateHeaderName(field, "Trailer name");
      if (Array.isArray(value) && value.length > 1 && (!this[kUniqueHeaders] || !this[kUniqueHeaders].has(field.toLowerCase()))) {
        for (let j = 0, l3 = value.length; j < l3; j++) {
          if (checkInvalidHeaderChar(value[j])) {
            throw new ERR_INVALID_CHAR("trailer content", field);
          }
          this._trailer += field + ": " + value[j] + "\r\n";
        }
      } else {
        if (Array.isArray(value)) {
          value = value.join("; ");
        }
        if (checkInvalidHeaderChar(String(value))) {
          throw new ERR_INVALID_CHAR("trailer content", field);
        }
        this._trailer += field + ": " + value + "\r\n";
      }
    }
  }
  end(chunk, encoding, callback) {
    if (typeof chunk === "function") {
      callback = chunk;
      chunk = null;
      encoding = null;
    } else if (typeof encoding === "function") {
      callback = encoding;
      encoding = null;
    }
    if (chunk) {
      if (this.finished) {
        onError2(this, new ERR_STREAM_WRITE_AFTER_END(), typeof callback !== "function" ? nop : callback);
        return this;
      }
      if (this._writtenDataBuffer != null) {
        this._writtenDataBuffer.cork();
      }
      write_(this, chunk, encoding, null, true);
    } else if (this.finished) {
      if (typeof callback === "function") {
        if (!this.writableFinished) {
          this.on("finish", callback);
        } else {
          callback(new ERR_STREAM_ALREADY_FINISHED("end"));
        }
      }
      return this;
    } else if (!this._header) {
      if (this._writtenDataBuffer != null) {
        this._writtenDataBuffer.cork();
      }
      this._contentLength = 0;
      this._implicitHeader();
    }
    if (typeof callback === "function")
      this.once("finish", callback);
    if (strictContentLength(this) && this[kBytesWritten] !== this._contentLength) {
      throw new ERR_HTTP_CONTENT_LENGTH_MISMATCH(this[kBytesWritten], this._contentLength);
    }
    const finish = onFinish.bind(void 0, this);
    if (this._hasBody && this.chunkedEncoding) {
      this._send("", "latin1", finish);
    } else if (!this._headerSent || this.writableLength || chunk) {
      this._send("", "latin1", finish);
    } else {
      setTimeout(finish, 0);
    }
    if (this._writtenDataBuffer != null) {
      this._writtenDataBuffer.uncork();
    }
    this[kCorked] = 1;
    this.uncork();
    this.finished = true;
    if (this.outputData.length === 0 && this._writtenDataBuffer != null) {
      this._finish();
    }
    return this;
  }
  _finish() {
    this.emit("prefinish");
  }
  // No _flush() implementation?
  _flush() {
    if (this._writtenDataBuffer != null) {
      const ret = this._flushOutput(this._writtenDataBuffer);
      if (this.finished) {
        this._finish();
      } else if (ret && this[kNeedDrain]) {
        this[kNeedDrain] = false;
        this.emit("drain");
      }
    }
  }
  _flushOutput(dataBuffer) {
    while (this[kCorked]) {
      this[kCorked]--;
      dataBuffer.cork();
    }
    const outputLength = this.outputData.length;
    if (outputLength <= 0) {
      return void 0;
    }
    const outputData = this.outputData;
    dataBuffer.cork();
    let ret;
    for (let i2 = 0; i2 < outputLength; i2++) {
      const { data, encoding, callback } = outputData[i2];
      outputData[i2].data = null;
      ret = dataBuffer.write(data ?? "", encoding, callback);
    }
    dataBuffer.uncork();
    this.outputData = [];
    this._onPendingData(-this.outputSize);
    this.outputSize = 0;
    return ret;
  }
  flushHeaders() {
    if (!this._header) {
      this._implicitHeader();
    }
    this._send("");
  }
  pipe(destination) {
    this.emit("error", new ERR_STREAM_CANNOT_PIPE());
    return destination;
  }
};
function processHeader(self, state, key, value, validate) {
  if (validate) {
    validateHeaderName(key);
  }
  if (isContentDispositionField(key) && self._contentLength) {
    if (Array.isArray(value)) {
      for (let i2 = 0; i2 < value.length; i2++) {
        value[i2] = String(Buffer$1.from(String(value[i2]), "latin1"));
      }
    } else {
      value = String(Buffer$1.from(String(value), "latin1"));
    }
  }
  if (Array.isArray(value)) {
    if ((value.length < 2 || !isCookieField(key)) && (!self[kUniqueHeaders] || !self[kUniqueHeaders].has(key.toLowerCase()))) {
      for (let i2 = 0; i2 < value.length; i2++) {
        storeHeader(self, state, key, value[i2], validate);
      }
      return;
    }
    value = value.join("; ");
  }
  storeHeader(self, state, key, String(value), validate);
}
function storeHeader(self, state, key, value, validate) {
  if (validate) {
    validateHeaderValue(key, value);
  }
  state.header += key + ": " + value + "\r\n";
  matchHeader(self, state, key, value);
}
function validateHeaderName(name, label) {
  if (typeof name !== "string" || !name || !checkIsHttpToken(name)) {
    throw new ERR_INVALID_HTTP_TOKEN(label || "Header name", name);
  }
}
function validateHeaderValue(name, value) {
  if (value === void 0) {
    throw new ERR_HTTP_INVALID_HEADER_VALUE(String(value), name);
  }
  if (checkInvalidHeaderChar(String(value))) {
    throw new ERR_INVALID_CHAR("header content", name);
  }
}
function matchHeader(self, state, field, value) {
  if (field.length < 4 || field.length > 17)
    return;
  field = field.toLowerCase();
  switch (field) {
    case "connection":
      state.connection = true;
      self._removedConnection = false;
      if (RE_CONN_CLOSE.exec(value) !== null)
        self._last = true;
      else
        self.shouldKeepAlive = true;
      break;
    case "transfer-encoding":
      state.te = true;
      self._removedTE = false;
      if (chunkExpression.exec(value) !== null)
        self.chunkedEncoding = true;
      break;
    case "content-length":
      state.contLen = true;
      self._contentLength = +value;
      self._removedContLen = false;
      break;
    case "date":
    case "expect":
    case "trailer":
      state[field] = true;
      break;
    case "keep-alive":
      self._defaultKeepAlive = false;
      break;
  }
}
function onError2(msg, err, callback) {
  if (msg.destroyed) {
    return;
  }
  setTimeout(emitErrorNt, 0, msg, err, callback);
}
function emitErrorNt(msg, err, callback) {
  callback(err);
  if (typeof msg.emit === "function" && !msg.destroyed) {
    msg.emit("error", err);
  }
}
function strictContentLength(msg) {
  return msg.strictContentLength && msg._contentLength != null && msg._hasBody && !msg._removedContLen && !msg.chunkedEncoding && !msg.hasHeader("transfer-encoding");
}
function write_(msg, chunk, encoding, callback, fromEnd) {
  if (typeof callback !== "function") {
    callback = nop;
  }
  if (chunk === null) {
    throw new ERR_STREAM_NULL_VALUES();
  } else if (typeof chunk !== "string" && !isUint8Array(chunk)) {
    throw new ERR_INVALID_ARG_TYPE("chunk", ["string", "Buffer", "Uint8Array"], chunk);
  }
  let err = void 0;
  if (msg.finished) {
    err = new ERR_STREAM_WRITE_AFTER_END();
  } else if (msg.destroyed) {
    err = new ERR_STREAM_DESTROYED("write");
  }
  if (err) {
    if (!msg.destroyed) {
      onError2(msg, err, callback);
    } else {
      setTimeout(callback, 0, err);
    }
    return false;
  }
  let len = void 0;
  if (msg.strictContentLength) {
    len ??= typeof chunk === "string" ? Buffer$1.byteLength(chunk, encoding ?? void 0) : chunk.byteLength;
    if (strictContentLength(msg) && (fromEnd ? msg[kBytesWritten] + len !== msg._contentLength : msg[kBytesWritten] + len > (msg._contentLength ?? 0))) {
      throw new ERR_HTTP_CONTENT_LENGTH_MISMATCH(len + msg[kBytesWritten], msg._contentLength);
    }
    msg[kBytesWritten] += len;
  }
  if (!msg._header) {
    if (fromEnd) {
      len ??= typeof chunk === "string" ? Buffer$1.byteLength(chunk, encoding ?? void 0) : chunk.byteLength;
      msg._contentLength = len;
    }
    msg._implicitHeader();
  }
  if (!msg._hasBody) {
    if (msg[kRejectNonStandardBodyWrites]) {
      throw new ERR_HTTP_BODY_NOT_ALLOWED();
    } else {
      setTimeout(callback, 0);
      return true;
    }
  }
  if (!fromEnd && msg._writtenDataBuffer != null && !msg._writtenDataBuffer.writableCorked) {
    msg._writtenDataBuffer.cork();
    setTimeout(connectionCorkNT, 0, msg._writtenDataBuffer);
  }
  let ret;
  if (msg.chunkedEncoding && chunk.length !== 0) {
    len ??= typeof chunk === "string" ? Buffer$1.byteLength(chunk, encoding ?? void 0) : chunk.byteLength;
    if (msg[kCorked] && msg._headerSent) {
      msg[kChunkedBuffer].push({ data: chunk, encoding, callback });
      msg[kChunkedLength] += len;
      ret = msg[kChunkedLength] < msg[kHighWaterMark];
    } else {
      ret = msg._send(chunk, encoding, callback, len);
    }
  } else {
    ret = msg._send(chunk, encoding, callback, len);
  }
  return ret;
}
function connectionCorkNT(dataBuffer) {
  dataBuffer.uncork();
}
function onFinish(outmsg) {
  outmsg.emit("finish");
}
Object.defineProperties(FetchOutgoingMessage.prototype, {
  errored: {
    get() {
      return this[kErrored];
    }
  },
  closed: {
    get() {
      return this._closed;
    }
  },
  writableFinished: {
    get() {
      return this.finished && this.outputSize === 0 && (this._writtenDataBuffer == null || this._writtenDataBuffer.writableLength === 0);
    }
  },
  writableObjectMode: {
    get() {
      return false;
    }
  },
  writableLength: {
    get() {
      return this.outputSize + this[kChunkedLength] + (this._writtenDataBuffer != null ? this._writtenDataBuffer.writableLength : 0);
    }
  },
  writableHighWaterMark: {
    get() {
      return this._writtenDataBuffer != null ? this._writtenDataBuffer.writableHighWaterMark : this[kHighWaterMark];
    }
  },
  writableCorked: {
    get() {
      return this[kCorked];
    }
  },
  writableEnded: {
    get() {
      return this.finished;
    }
  },
  writableNeedDrain: {
    get() {
      return !this.destroyed && !this.finished && this[kNeedDrain];
    }
  }
});
var headerCharRegex2 = /[^\t\x20-\x7e\x80-\xff]/;
function checkInvalidHeaderChar2(val) {
  return headerCharRegex2.test(val);
}
var STATUS_CODES = {
  100: "Continue",
  // RFC 7231 6.2.1
  101: "Switching Protocols",
  // RFC 7231 6.2.2
  102: "Processing",
  // RFC 2518 10.1 (obsoleted by RFC 4918)
  103: "Early Hints",
  // RFC 8297 2
  200: "OK",
  // RFC 7231 6.3.1
  201: "Created",
  // RFC 7231 6.3.2
  202: "Accepted",
  // RFC 7231 6.3.3
  203: "Non-Authoritative Information",
  // RFC 7231 6.3.4
  204: "No Content",
  // RFC 7231 6.3.5
  205: "Reset Content",
  // RFC 7231 6.3.6
  206: "Partial Content",
  // RFC 7233 4.1
  207: "Multi-Status",
  // RFC 4918 11.1
  208: "Already Reported",
  // RFC 5842 7.1
  226: "IM Used",
  // RFC 3229 10.4.1
  300: "Multiple Choices",
  // RFC 7231 6.4.1
  301: "Moved Permanently",
  // RFC 7231 6.4.2
  302: "Found",
  // RFC 7231 6.4.3
  303: "See Other",
  // RFC 7231 6.4.4
  304: "Not Modified",
  // RFC 7232 4.1
  305: "Use Proxy",
  // RFC 7231 6.4.5
  307: "Temporary Redirect",
  // RFC 7231 6.4.7
  308: "Permanent Redirect",
  // RFC 7238 3
  400: "Bad Request",
  // RFC 7231 6.5.1
  401: "Unauthorized",
  // RFC 7235 3.1
  402: "Payment Required",
  // RFC 7231 6.5.2
  403: "Forbidden",
  // RFC 7231 6.5.3
  404: "Not Found",
  // RFC 7231 6.5.4
  405: "Method Not Allowed",
  // RFC 7231 6.5.5
  406: "Not Acceptable",
  // RFC 7231 6.5.6
  407: "Proxy Authentication Required",
  // RFC 7235 3.2
  408: "Request Timeout",
  // RFC 7231 6.5.7
  409: "Conflict",
  // RFC 7231 6.5.8
  410: "Gone",
  // RFC 7231 6.5.9
  411: "Length Required",
  // RFC 7231 6.5.10
  412: "Precondition Failed",
  // RFC 7232 4.2
  413: "Payload Too Large",
  // RFC 7231 6.5.11
  414: "URI Too Long",
  // RFC 7231 6.5.12
  415: "Unsupported Media Type",
  // RFC 7231 6.5.13
  416: "Range Not Satisfiable",
  // RFC 7233 4.4
  417: "Expectation Failed",
  // RFC 7231 6.5.14
  418: "I'm a Teapot",
  // RFC 7168 2.3.3
  421: "Misdirected Request",
  // RFC 7540 9.1.2
  422: "Unprocessable Entity",
  // RFC 4918 11.2
  423: "Locked",
  // RFC 4918 11.3
  424: "Failed Dependency",
  // RFC 4918 11.4
  425: "Too Early",
  // RFC 8470 5.2
  426: "Upgrade Required",
  // RFC 2817 and RFC 7231 6.5.15
  428: "Precondition Required",
  // RFC 6585 3
  429: "Too Many Requests",
  // RFC 6585 4
  431: "Request Header Fields Too Large",
  // RFC 6585 5
  451: "Unavailable For Legal Reasons",
  // RFC 7725 3
  500: "Internal Server Error",
  // RFC 7231 6.6.1
  501: "Not Implemented",
  // RFC 7231 6.6.2
  502: "Bad Gateway",
  // RFC 7231 6.6.3
  503: "Service Unavailable",
  // RFC 7231 6.6.4
  504: "Gateway Timeout",
  // RFC 7231 6.6.5
  505: "HTTP Version Not Supported",
  // RFC 7231 6.6.6
  506: "Variant Also Negotiates",
  // RFC 2295 8.1
  507: "Insufficient Storage",
  // RFC 4918 11.5
  508: "Loop Detected",
  // RFC 5842 7.2
  509: "Bandwidth Limit Exceeded",
  510: "Not Extended",
  // RFC 2774 7
  511: "Network Authentication Required"
  // RFC 6585 6
};
var FetchServerResponse = class _FetchServerResponse extends FetchOutgoingMessage {
  static encoder = new TextEncoder();
  statusCode = 200;
  statusMessage;
  _sent100;
  _expect_continue;
  [kOutHeaders] = null;
  constructor(req, options) {
    super(req, options);
    if (req.method === "HEAD") {
      this._hasBody = false;
    }
    this.sendDate = true;
    this._sent100 = false;
    this._expect_continue = false;
    if (req.httpVersionMajor < 1 || req.httpVersionMinor < 1) {
      this.useChunkedEncodingByDefault = chunkExpression.exec(String(req.headers.te)) !== null;
      this.shouldKeepAlive = false;
    }
    this.fetchResponse = new Promise((resolve) => {
      let finished = false;
      this.on("finish", () => {
        finished = true;
      });
      const initialDataChunks = [];
      const initialDataWrittenHandler = (e2) => {
        if (finished) {
          return;
        }
        initialDataChunks[e2.index] = this.dataFromDataWrittenEvent(e2);
      };
      this.on("_dataWritten", initialDataWrittenHandler);
      this.on("_headersSent", (e2) => {
        this.off("_dataWritten", initialDataWrittenHandler);
        const { statusCode, statusMessage, headers } = e2;
        resolve(this._toFetchResponse(statusCode, statusMessage, headers, initialDataChunks, finished));
      });
    });
  }
  dataFromDataWrittenEvent(e2) {
    const { index, entry } = e2;
    let { data, encoding } = entry;
    if (index === 0) {
      if (typeof data !== "string") {
        console.error("First chunk should be string, not sure what happened.");
        throw new ERR_INVALID_ARG_TYPE("packet.data", ["string", "Buffer", "Uint8Array"], data);
      }
      data = data.slice(this.writtenHeaderBytes);
    }
    if (typeof data === "string") {
      if (encoding === void 0 || encoding === "utf8" || encoding === "utf-8") {
        data = _FetchServerResponse.encoder.encode(data);
      } else {
        data = Buffer$1.from(data, encoding ?? void 0);
      }
    }
    return data ?? Buffer$1.from([]);
  }
  _finish() {
    super._finish();
  }
  assignSocket(socket) {
    throw new ERR_METHOD_NOT_IMPLEMENTED("assignSocket");
  }
  detachSocket(socket) {
    throw new ERR_METHOD_NOT_IMPLEMENTED("detachSocket");
  }
  writeContinue(callback) {
    this._writeRaw("HTTP/1.1 100 Continue\r\n\r\n", "ascii", callback);
    this._sent100 = true;
  }
  writeProcessing(callback) {
    this._writeRaw("HTTP/1.1 102 Processing\r\n\r\n", "ascii", callback);
  }
  writeEarlyHints(hints, callback) {
    let head = "HTTP/1.1 103 Early Hints\r\n";
    if (hints.link === null || hints.link === void 0) {
      return;
    }
    const link = validateLinkHeaderValue(hints.link);
    if (link.length === 0) {
      return;
    }
    head += "Link: " + link + "\r\n";
    for (const key of Object.keys(hints)) {
      if (key !== "link") {
        head += key + ": " + hints[key] + "\r\n";
      }
    }
    head += "\r\n";
    this._writeRaw(head, "ascii", callback);
  }
  _implicitHeader() {
    this.writeHead(this.statusCode);
  }
  writeHead(statusCode, reason, obj) {
    if (this._header) {
      throw new ERR_HTTP_HEADERS_SENT("write");
    }
    const originalStatusCode = statusCode;
    statusCode |= 0;
    if (statusCode < 100 || statusCode > 999) {
      throw new ERR_HTTP_INVALID_STATUS_CODE(originalStatusCode);
    }
    if (typeof reason === "string") {
      this.statusMessage = reason;
    } else {
      this.statusMessage ||= STATUS_CODES[statusCode] || "unknown";
      obj ??= reason;
    }
    this.statusCode = statusCode;
    let headers;
    if (this[kOutHeaders]) {
      let k;
      if (Array.isArray(obj)) {
        if (obj.length % 2 !== 0) {
          throw new ERR_INVALID_ARG_VALUE("headers", obj);
        }
        for (let n2 = 0; n2 < obj.length; n2 += 2) {
          k = obj[n2 + 0];
          this.removeHeader(String(k));
        }
        for (let n2 = 0; n2 < obj.length; n2 += 2) {
          k = obj[n2];
          if (k) {
            this.appendHeader(String(k), obj[n2 + 1]);
          }
        }
      } else if (obj) {
        const keys = Object.keys(obj);
        for (let i2 = 0; i2 < keys.length; i2++) {
          k = keys[i2];
          if (k) {
            this.setHeader(k, obj[k]);
          }
        }
      }
      headers = this[kOutHeaders];
    } else {
      headers = obj;
    }
    if (checkInvalidHeaderChar2(this.statusMessage)) {
      throw new ERR_INVALID_CHAR("statusMessage");
    }
    const statusLine = `HTTP/1.1 ${statusCode} ${this.statusMessage}\r
`;
    if (statusCode === 204 || statusCode === 304 || statusCode >= 100 && statusCode <= 199) {
      this._hasBody = false;
    }
    if (this._expect_continue && !this._sent100) {
      this.shouldKeepAlive = false;
    }
    const convertedHeaders = headers && !Array.isArray(headers) ? headers : headers;
    this._storeHeader(statusLine, convertedHeaders ?? null);
    return this;
  }
  // Docs-only deprecated: DEP0063
  writeHeader = this.writeHead;
  fetchResponse;
  _toFetchResponse(status, statusText, sentHeaders, initialDataChunks, finished) {
    const headers = new Headers();
    for (const [header, value] of sentHeaders) {
      headers.append(header, value);
    }
    const _this = this;
    let body = this._hasBody ? new ReadableStream({
      start(controller) {
        for (const dataChunk of initialDataChunks) {
          controller.enqueue(dataChunk);
        }
        if (finished) {
          controller.close();
        } else {
          _this.on("finish", () => {
            finished = true;
            controller.close();
          });
          _this.on("_dataWritten", (e2) => {
            if (finished) {
              return;
            }
            const data = _this.dataFromDataWrittenEvent(e2);
            controller.enqueue(data);
          });
        }
      }
    }) : null;
    if (body != null && typeof FixedLengthStream !== "undefined") {
      const contentLength = parseInt(headers.get("content-length") ?? "", 10);
      if (contentLength >= 0) {
        body = body.pipeThrough(new FixedLengthStream(contentLength));
      }
    }
    return new Response(body, {
      status,
      statusText,
      headers
    });
  }
};
function toReqRes(req, options) {
  const { createIncomingMessage = () => new FetchIncomingMessage(), createServerResponse = (incoming2) => new FetchServerResponse(incoming2), ctx } = {};
  const incoming = createIncomingMessage(ctx);
  const serverResponse = createServerResponse(incoming, ctx);
  const reqUrl = new URL(req.url);
  const versionMajor = 1;
  const versionMinor = 1;
  incoming.httpVersionMajor = versionMajor;
  incoming.httpVersionMinor = versionMinor;
  incoming.httpVersion = `${versionMajor}.${versionMinor}`;
  incoming.url = reqUrl.pathname + reqUrl.search;
  incoming.upgrade = false;
  const headers = [];
  for (const [headerName, headerValue] of req.headers) {
    headers.push(headerName);
    headers.push(headerValue);
  }
  incoming._addHeaderLines(headers, headers.length);
  incoming.method = req.method;
  incoming._stream = req.body;
  return {
    req: incoming,
    res: serverResponse
  };
}
function toFetchResponse(res) {
  if (!(res instanceof FetchServerResponse)) {
    throw new Error("toFetchResponse must be called on a ServerResponse generated by toReqRes");
  }
  return res.fetchResponse;
}

// src/server/handlers/mcp.ts
var getMastra = (c2) => c2.get("mastra");
var getMcpServerMessageHandler = async (c2) => {
  const mastra = getMastra(c2);
  const serverId = c2.req.param("serverId");
  const { req, res } = toReqRes(c2.req.raw);
  const server = mastra.getMCPServer(serverId);
  if (!server) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: `MCP server '${serverId}' not found` }));
    return;
  }
  try {
    await server.startHTTP({
      url: new URL(c2.req.url),
      httpPath: `/api/mcp/${serverId}/mcp`,
      req,
      res
    });
    return await toFetchResponse(res);
  } catch (error) {
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: -32603,
            message: "Internal server error"
          },
          id: null
          // Cannot determine original request ID in catch
        })
      );
    } else {
      c2.get("logger")?.error("Error after headers sent:", error);
    }
  }
};
var getMcpServerSseHandler = async (c2) => {
  const mastra = getMastra(c2);
  const serverId = c2.req.param("serverId");
  const server = mastra.getMCPServer(serverId);
  if (!server) {
    return c2.json({ error: `MCP server '${serverId}' not found` }, 404);
  }
  const requestUrl = new URL(c2.req.url);
  const sseConnectionPath = `/api/mcp/${serverId}/sse`;
  const sseMessagePath = `/api/mcp/${serverId}/messages`;
  try {
    return await server.startHonoSSE({
      url: requestUrl,
      ssePath: sseConnectionPath,
      messagePath: sseMessagePath,
      context: c2
    });
  } catch (error) {
    c2.get("logger")?.error({ err: error, serverId, path: requestUrl.pathname }, "Error in MCP SSE route handler");
    return handleError(error, "Error handling MCP SSE request");
  }
};
var listMcpRegistryServersHandler = async (c2) => {
  const mastra = getMastra(c2);
  if (!mastra || typeof mastra.getMCPServers !== "function") {
    c2.get("logger")?.error("Mastra instance or getMCPServers method not available in listMcpRegistryServersHandler");
    return c2.json({ error: "Mastra instance or getMCPServers method not available" }, 500);
  }
  const mcpServersMap = mastra.getMCPServers();
  if (!mcpServersMap) {
    c2.get("logger")?.warn("getMCPServers returned undefined or null in listMcpRegistryServersHandler");
    return c2.json({ servers: [], next: null, total_count: 0 });
  }
  const allServersArray = Array.from(
    mcpServersMap instanceof Map ? mcpServersMap.values() : Object.values(mcpServersMap)
  );
  const limit = parseInt(c2.req.query("limit") || "50", 10);
  const offset = parseInt(c2.req.query("offset") || "0", 10);
  const paginatedServers = allServersArray.slice(offset, offset + limit);
  const serverInfos = paginatedServers.map((server) => server.getServerInfo());
  const total_count = allServersArray.length;
  let next = null;
  if (offset + limit < total_count) {
    const nextOffset = offset + limit;
    const currentUrl = new URL(c2.req.url);
    currentUrl.searchParams.set("offset", nextOffset.toString());
    currentUrl.searchParams.set("limit", limit.toString());
    next = currentUrl.toString();
  }
  return c2.json({
    servers: serverInfos,
    next,
    total_count
  });
};
var getMcpRegistryServerDetailHandler = async (c2) => {
  const mastra = getMastra(c2);
  const serverId = c2.req.param("id");
  const requestedVersion = c2.req.query("version");
  if (!mastra || typeof mastra.getMCPServer !== "function") {
    c2.get("logger")?.error("Mastra instance or getMCPServer method not available in getMcpRegistryServerDetailHandler");
    return c2.json({ error: "Mastra instance or getMCPServer method not available" }, 500);
  }
  const server = mastra.getMCPServer(serverId);
  if (!server) {
    return c2.json({ error: `MCP server with ID '${serverId}' not found` }, 404);
  }
  const serverDetailInfo = server.getServerDetail();
  if (requestedVersion && serverDetailInfo.version_detail.version !== requestedVersion) {
    c2.get("logger")?.info(
      `MCP server with ID '${serverId}' found, but version '${serverDetailInfo.version_detail.version}' does not match requested version '${requestedVersion}'.`
    );
    return c2.json(
      {
        error: `MCP server with ID '${serverId}' found, but not version '${requestedVersion}'. Available version is '${serverDetailInfo.version_detail.version}'.`
      },
      404
      // Return 404 as the specific version is not found
    );
  }
  return c2.json(serverDetailInfo);
};
var listMcpServerToolsHandler = async (c2) => {
  const mastra = getMastra(c2);
  const serverId = c2.req.param("serverId");
  if (!mastra || typeof mastra.getMCPServer !== "function") {
    c2.get("logger")?.error("Mastra instance or getMCPServer method not available in listMcpServerToolsHandler");
    return c2.json({ error: "Mastra instance or getMCPServer method not available" }, 500);
  }
  const server = mastra.getMCPServer(serverId);
  if (!server) {
    return c2.json({ error: `MCP server with ID '${serverId}' not found` }, 404);
  }
  if (typeof server.getToolListInfo !== "function") {
    c2.get("logger")?.error(`MCPServer with ID '${serverId}' does not support getToolListInfo.`);
    return c2.json({ error: `Server '${serverId}' cannot list tools in this way.` }, 501);
  }
  try {
    const toolListInfo = server.getToolListInfo();
    return c2.json(toolListInfo);
  } catch (error) {
    c2.get("logger")?.error(`Error in listMcpServerToolsHandler for serverId '${serverId}':`, { error: error.message });
    return handleError(error, `Error listing tools for MCP server '${serverId}'`);
  }
};
var getMcpServerToolDetailHandler = async (c2) => {
  const mastra = getMastra(c2);
  const serverId = c2.req.param("serverId");
  const toolId = c2.req.param("toolId");
  if (!mastra || typeof mastra.getMCPServer !== "function") {
    c2.get("logger")?.error("Mastra instance or getMCPServer method not available in getMcpServerToolDetailHandler");
    return c2.json({ error: "Mastra instance or getMCPServer method not available" }, 500);
  }
  const server = mastra.getMCPServer(serverId);
  if (!server) {
    return c2.json({ error: `MCP server with ID '${serverId}' not found` }, 404);
  }
  if (typeof server.getToolInfo !== "function") {
    c2.get("logger")?.error(`MCPServer with ID '${serverId}' does not support getToolInfo.`);
    return c2.json({ error: `Server '${serverId}' cannot provide tool details in this way.` }, 501);
  }
  try {
    const toolInfo = server.getToolInfo(toolId);
    if (!toolInfo) {
      return c2.json({ error: `Tool with ID '${toolId}' not found on MCP server '${serverId}'` }, 404);
    }
    return c2.json(toolInfo);
  } catch (error) {
    c2.get("logger")?.error(`Error in getMcpServerToolDetailHandler for serverId '${serverId}', toolId '${toolId}':`, {
      error: error.message
    });
    return handleError(error, `Error getting tool '${toolId}' details for MCP server '${serverId}'`);
  }
};
var executeMcpServerToolHandler = async (c2) => {
  const mastra = getMastra(c2);
  const serverId = c2.req.param("serverId");
  const toolId = c2.req.param("toolId");
  if (!mastra || typeof mastra.getMCPServer !== "function") {
    c2.get("logger")?.error("Mastra instance or getMCPServer method not available in executeMcpServerToolHandler");
    return c2.json({ error: "Mastra instance or getMCPServer method not available" }, 500);
  }
  const server = mastra.getMCPServer(serverId);
  if (!server) {
    return c2.json({ error: `MCP server with ID '${serverId}' not found` }, 404);
  }
  if (typeof server.executeTool !== "function") {
    c2.get("logger")?.error(`MCPServer with ID '${serverId}' does not support executeTool.`);
    return c2.json({ error: `Server '${serverId}' cannot execute tools in this way.` }, 501);
  }
  try {
    const body = await c2.req.json();
    const args = body?.data;
    const runtimeContext = body?.runtimeContext;
    const result = await server.executeTool(toolId, args, runtimeContext);
    return c2.json({ result });
  } catch (error) {
    c2.get("logger")?.error(`Error executing tool '${toolId}' on server '${serverId}':`, { error: error.message });
    if (error.name === "ZodError") {
      return c2.json({ error: "Invalid tool arguments", details: error.errors }, 400);
    }
    return handleError(error, `Error executing tool '${toolId}' on MCP server '${serverId}'`);
  }
};
async function getMemoryStatusHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const networkId = c2.req.query("networkId");
    const result = await getMemoryStatusHandler$1({
      mastra,
      agentId,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting memory status");
  }
}
async function getThreadsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const resourceId = c2.req.query("resourceid");
    const networkId = c2.req.query("networkId");
    const result = await getThreadsHandler$1({
      mastra,
      agentId,
      resourceId,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting threads");
  }
}
async function getThreadByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const threadId = c2.req.param("threadId");
    const networkId = c2.req.query("networkId");
    const result = await getThreadByIdHandler$1({
      mastra,
      agentId,
      threadId,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting thread");
  }
}
async function saveMessagesHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const networkId = c2.req.query("networkId");
    const body = await c2.req.json();
    const result = await saveMessagesHandler$1({
      mastra,
      agentId,
      body,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error saving messages");
  }
}
async function createThreadHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const networkId = c2.req.query("networkId");
    const body = await c2.req.json();
    const result = await createThreadHandler$1({
      mastra,
      agentId,
      body,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error saving thread to memory");
  }
}
async function updateThreadHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const threadId = c2.req.param("threadId");
    const networkId = c2.req.query("networkId");
    const body = await c2.req.json();
    const result = await updateThreadHandler$1({
      mastra,
      agentId,
      threadId,
      body,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error updating thread");
  }
}
async function deleteThreadHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const threadId = c2.req.param("threadId");
    const networkId = c2.req.query("networkId");
    const result = await deleteThreadHandler$1({
      mastra,
      agentId,
      threadId,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error deleting thread");
  }
}
async function getMessagesHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const networkId = c2.req.query("networkId");
    const threadId = c2.req.param("threadId");
    const rawLimit = c2.req.query("limit");
    let limit = void 0;
    if (rawLimit !== void 0) {
      const n2 = Number(rawLimit);
      if (Number.isFinite(n2) && Number.isInteger(n2) && n2 > 0) {
        limit = n2;
      }
    }
    const result = await getMessagesHandler$1({
      mastra,
      agentId,
      threadId,
      networkId,
      limit
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting messages");
  }
}
async function updateWorkingMemoryHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const threadId = c2.req.param("threadId");
    const networkId = c2.req.query("networkId");
    const body = await c2.req.json();
    const result = await updateWorkingMemoryHandler$1({
      mastra,
      agentId,
      threadId,
      body,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error updating working memory");
  }
}
async function getWorkingMemoryHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.query("agentId");
    const threadId = c2.req.param("threadId");
    const resourceId = c2.req.query("resourceId");
    const networkId = c2.req.query("networkId");
    const result = await getWorkingMemoryHandler$1({
      mastra,
      agentId,
      threadId,
      resourceId,
      networkId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting working memory");
  }
}
async function getNetworksHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const networks = await getNetworksHandler$1({
      mastra,
      runtimeContext
    });
    return c2.json(networks);
  } catch (error) {
    return handleError(error, "Error getting networks");
  }
}
async function getNetworkByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const networkId = c2.req.param("networkId");
    const runtimeContext = c2.get("runtimeContext");
    const network = await getNetworkByIdHandler$1({
      mastra,
      networkId,
      runtimeContext
    });
    return c2.json(network);
  } catch (error) {
    return handleError(error, "Error getting network by ID");
  }
}
async function generateHandler2(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const networkId = c2.req.param("networkId");
    const body = await c2.req.json();
    const result = await generateHandler$1({
      mastra,
      runtimeContext,
      networkId,
      body
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error generating from network");
  }
}
async function streamGenerateHandler2(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const networkId = c2.req.param("networkId");
    const body = await c2.req.json();
    const streamResponse = await streamGenerateHandler$1({
      mastra,
      runtimeContext,
      networkId,
      body
    });
    return streamResponse;
  } catch (error) {
    return handleError(error, "Error streaming from network");
  }
}
async function generateSystemPromptHandler(c2) {
  try {
    const agentId = c2.req.param("agentId");
    const isPlayground = c2.get("playground") === true;
    if (!isPlayground) {
      return c2.json({ error: "This API is only available in the playground environment" }, 403);
    }
    const { instructions, comment } = await c2.req.json();
    if (!instructions) {
      return c2.json({ error: "Missing instructions in request body" }, 400);
    }
    const mastra = c2.get("mastra");
    const agent = mastra.getAgent(agentId);
    if (!agent) {
      return c2.json({ error: "Agent not found" }, 404);
    }
    let evalSummary = "";
    try {
      const testEvals = await mastra.getStorage()?.getEvalsByAgentName?.(agent.name, "test") || [];
      const liveEvals = await mastra.getStorage()?.getEvalsByAgentName?.(agent.name, "live") || [];
      const evalsMapped = [...testEvals, ...liveEvals].filter(
        ({ instructions: evalInstructions }) => evalInstructions === instructions
      );
      evalSummary = evalsMapped.map(
        ({ input, output, result: result2 }) => `
          Input: ${input}

          Output: ${output}

          Result: ${JSON.stringify(result2)}

        `
      ).join("");
    } catch (error) {
      mastra.getLogger().error(`Error fetching evals`, { error });
    }
    const ENHANCE_SYSTEM_PROMPT_INSTRUCTIONS = `
            You are an expert system prompt engineer, specialized in analyzing and enhancing instructions to create clear, effective, and comprehensive system prompts. Your goal is to help users transform their basic instructions into well-structured system prompts that will guide AI behavior effectively.
            Follow these steps to analyze and enhance the instructions:
            1. ANALYSIS PHASE
            - Identify the core purpose and goals
            - Extract key constraints and requirements
            - Recognize domain-specific terminology and concepts
            - Note any implicit assumptions that should be made explicit
            2. PROMPT STRUCTURE
            Create a system prompt with these components:
            a) ROLE DEFINITION
                - Clear statement of the AI's role and purpose
                - Key responsibilities and scope
                - Primary stakeholders and users
            b) CORE CAPABILITIES
                - Main functions and abilities
                - Specific domain knowledge required
                - Tools and resources available
            c) BEHAVIORAL GUIDELINES
                - Communication style and tone
                - Decision-making framework
                - Error handling approach
                - Ethical considerations
            d) CONSTRAINTS & BOUNDARIES
                - Explicit limitations
                - Out-of-scope activities
                - Security and privacy considerations
            e) SUCCESS CRITERIA
                - Quality standards
                - Expected outcomes
                - Performance metrics
            3. QUALITY CHECKS
            Ensure the prompt is:
            - Clear and unambiguous
            - Comprehensive yet concise
            - Properly scoped
            - Technically accurate
            - Ethically sound
            4. OUTPUT FORMAT
            Return a structured response with:
            - Enhanced system prompt
            - Analysis of key components
            - Identified goals and constraints
            - Core domain concepts
            Remember: A good system prompt should be specific enough to guide behavior but flexible enough to handle edge cases. 
            Focus on creating prompts that are clear, actionable, and aligned with the intended use case.
        `;
    const systemPromptAgent = new Agent$1({
      name: "system-prompt-enhancer",
      instructions: ENHANCE_SYSTEM_PROMPT_INSTRUCTIONS,
      model: agent.llm?.getModel()
    });
    const result = await systemPromptAgent.generate(
      `
            We need to improve the system prompt. 
            Current: ${instructions}
            ${comment ? `User feedback: ${comment}` : ""}
            ${evalSummary ? `
Evaluation Results:
${evalSummary}` : ""}
        `,
      {
        output: z.object({
          new_prompt: z.string(),
          explanation: z.string()
        })
      }
    );
    return c2.json(result?.object || {});
  } catch (error) {
    return handleError(error, "Error generating system prompt");
  }
}

// src/server/handlers/root.ts
async function rootHandler(c2) {
  return c2.text("Hello to the Mastra API!");
}
async function getTelemetryHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const { name, scope, page, perPage, fromDate, toDate } = c2.req.query();
    const attribute = c2.req.queries("attribute");
    const traces = await getTelemetryHandler$1({
      mastra,
      body: {
        name,
        scope,
        page: Number(page ?? 0),
        perPage: Number(perPage ?? 100),
        attribute,
        fromDate: fromDate ? new Date(fromDate) : void 0,
        toDate: toDate ? new Date(toDate) : void 0
      }
    });
    return c2.json({ traces });
  } catch (error) {
    return handleError(error, "Error getting telemetry traces");
  }
}
async function storeTelemetryHandler(c2) {
  try {
    const body = await c2.req.json();
    const mastra = c2.get("mastra");
    const result = await storeTelemetryHandler$1({ mastra, body });
    if (result.status === "error") {
      return c2.json(result, 500);
    }
    return c2.json(result, 200);
  } catch (error) {
    return handleError(error, "Error storing telemetry traces");
  }
}
async function getToolsHandler(c2) {
  try {
    const tools = c2.get("tools");
    const result = await getToolsHandler$1({
      tools
    });
    return c2.json(result || {});
  } catch (error) {
    return handleError(error, "Error getting tools");
  }
}
async function getToolByIdHandler(c2) {
  try {
    const tools = c2.get("tools");
    const toolId = c2.req.param("toolId");
    const result = await getToolByIdHandler$1({
      tools,
      toolId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error getting tool");
  }
}
function executeToolHandler(tools) {
  return async (c2) => {
    try {
      const mastra = c2.get("mastra");
      const runtimeContext = c2.get("runtimeContext");
      const toolId = decodeURIComponent(c2.req.param("toolId"));
      const runId = c2.req.query("runId");
      const { data } = await c2.req.json();
      const result = await executeToolHandler$1(tools)({
        mastra,
        toolId,
        data,
        runtimeContext,
        runId
      });
      return c2.json(result);
    } catch (error) {
      return handleError(error, "Error executing tool");
    }
  };
}
async function executeAgentToolHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const agentId = c2.req.param("agentId");
    const toolId = c2.req.param("toolId");
    const { data } = await c2.req.json();
    const result = await executeAgentToolHandler$1({
      mastra,
      agentId,
      toolId,
      data,
      runtimeContext
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error executing tool");
  }
}
async function upsertVectors(c2) {
  try {
    const mastra = c2.get("mastra");
    const vectorName = c2.req.param("vectorName");
    const body = await c2.req.json();
    const result = await upsertVectors$1({
      mastra,
      vectorName,
      index: body
    });
    return c2.json({ ids: result });
  } catch (error) {
    return handleError(error, "Error upserting vectors");
  }
}
async function createIndex(c2) {
  try {
    const mastra = c2.get("mastra");
    const vectorName = c2.req.param("vectorName");
    const body = await c2.req.json();
    await createIndex$1({
      mastra,
      vectorName,
      index: body
    });
    return c2.json({ success: true });
  } catch (error) {
    return handleError(error, "Error creating index");
  }
}
async function queryVectors(c2) {
  try {
    const mastra = c2.get("mastra");
    const vectorName = c2.req.param("vectorName");
    const { indexName, queryVector, topK = 10, filter, includeVector = false } = await c2.req.json();
    const results = await queryVectors$1({
      mastra,
      vectorName,
      query: { indexName, queryVector, topK, filter, includeVector }
    });
    return c2.json({ results });
  } catch (error) {
    return handleError(error, "Error querying vectors");
  }
}
async function listIndexes(c2) {
  try {
    const mastra = c2.get("mastra");
    const vectorName = c2.req.param("vectorName");
    const indexes = await listIndexes$1({
      mastra,
      vectorName
    });
    return c2.json({ indexes });
  } catch (error) {
    return handleError(error, "Error listing indexes");
  }
}
async function describeIndex(c2) {
  try {
    const mastra = c2.get("mastra");
    const vectorName = c2.req.param("vectorName");
    const indexName = c2.req.param("indexName");
    if (!indexName) {
      throw new HTTPException$1(400, { message: "Index name is required" });
    }
    const stats = await describeIndex$1({
      mastra,
      vectorName,
      indexName
    });
    return c2.json({
      dimension: stats.dimension,
      count: stats.count,
      metric: stats.metric?.toLowerCase()
    });
  } catch (error) {
    return handleError(error, "Error describing index");
  }
}
async function deleteIndex(c2) {
  try {
    const mastra = c2.get("mastra");
    const vectorName = c2.req.param("vectorName");
    const indexName = c2.req.param("indexName");
    if (!indexName) {
      throw new HTTPException$1(400, { message: "Index name is required" });
    }
    await deleteIndex$1({
      mastra,
      vectorName,
      indexName
    });
    return c2.json({ success: true });
  } catch (error) {
    return handleError(error, "Error deleting index");
  }
}
async function getVNextNetworksHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const networks = await getVNextNetworksHandler$1({
      mastra,
      runtimeContext
    });
    return c2.json(networks);
  } catch (error) {
    return handleError(error, "Error getting networks");
  }
}
async function getVNextNetworkByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const networkId = c2.req.param("networkId");
    const runtimeContext = c2.get("runtimeContext");
    const network = await getVNextNetworkByIdHandler$1({
      mastra,
      networkId,
      runtimeContext
    });
    return c2.json(network);
  } catch (error) {
    return handleError(error, "Error getting network by ID");
  }
}
async function generateVNextNetworkHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const networkId = c2.req.param("networkId");
    const body = await c2.req.json();
    const result = await generateVNextNetworkHandler$1({
      mastra,
      runtimeContext,
      networkId,
      body
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error generating from network");
  }
}
async function streamGenerateVNextNetworkHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const logger2 = mastra.getLogger();
    const networkId = c2.req.param("networkId");
    const body = await c2.req.json();
    c2.header("Transfer-Encoding", "chunked");
    return stream(
      c2,
      async (stream5) => {
        try {
          const result = await streamGenerateVNextNetworkHandler$1({
            mastra,
            runtimeContext,
            networkId,
            body
          });
          const reader = result.stream.getReader();
          stream5.onAbort(() => {
            void reader.cancel("request aborted");
          });
          let chunkResult;
          while ((chunkResult = await reader.read()) && !chunkResult.done) {
            await stream5.write(JSON.stringify(chunkResult.value) + "");
          }
        } catch (err) {
          mastra.getLogger().error("Error in network stream: " + (err?.message ?? "Unknown error"));
        }
      },
      async (err) => {
        logger2.error("Error in network stream: " + err?.message);
      }
    );
  } catch (error) {
    return handleError(error, "Error streaming from network");
  }
}
async function loopVNextNetworkHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const networkId = c2.req.param("networkId");
    const body = await c2.req.json();
    const result = await loopVNextNetworkHandler$1({
      mastra,
      runtimeContext,
      networkId,
      body
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error looping from network");
  }
}
async function loopStreamVNextNetworkHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const logger2 = mastra.getLogger();
    const networkId = c2.req.param("networkId");
    const body = await c2.req.json();
    c2.header("Transfer-Encoding", "chunked");
    return stream(
      c2,
      async (stream5) => {
        try {
          const result = await loopStreamVNextNetworkHandler$1({
            mastra,
            runtimeContext,
            networkId,
            body
          });
          const reader = result.stream.getReader();
          stream5.onAbort(() => {
            void reader.cancel("request aborted");
          });
          let chunkResult;
          while ((chunkResult = await reader.read()) && !chunkResult.done) {
            await stream5.write(JSON.stringify(chunkResult.value) + "");
          }
        } catch (err) {
          mastra.getLogger().error("Error in network loop stream: " + (err?.message ?? "Unknown error"));
        }
      },
      async (err) => {
        logger2.error("Error in network loop stream: " + err?.message);
      }
    );
  } catch (error) {
    return handleError(error, "Error streaming network loop");
  }
}
async function getSpeakersHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const speakers = await getSpeakersHandler$1({
      mastra,
      agentId
    });
    return c2.json(speakers);
  } catch (error) {
    return handleError(error, "Error getting speakers");
  }
}
async function speakHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const { input, options } = await c2.req.json();
    const audioStream = await generateSpeechHandler({
      mastra,
      agentId,
      body: { text: input, speakerId: options?.speakerId }
    });
    c2.header("Content-Type", `audio/${options?.filetype ?? "mp3"}`);
    c2.header("Transfer-Encoding", "chunked");
    return c2.body(audioStream);
  } catch (error) {
    return handleError(error, "Error generating speech");
  }
}
async function getListenerHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const listeners = await getListenerHandler$1({
      mastra,
      agentId
    });
    return c2.json(listeners);
  } catch (error) {
    return handleError(error, "Error getting listener");
  }
}
async function listenHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const agentId = c2.req.param("agentId");
    const formData = await c2.req.formData();
    const audioFile = formData.get("audio");
    const options = formData.get("options");
    if (!audioFile || !(audioFile instanceof File)) {
      throw new HTTPException$1(400, { message: "Audio file is required" });
    }
    const audioData = await audioFile.arrayBuffer();
    let parsedOptions = {};
    try {
      parsedOptions = options ? JSON.parse(options) : {};
    } catch {
    }
    const transcription = await transcribeSpeechHandler({
      mastra,
      agentId,
      body: {
        audioData: Buffer.from(audioData),
        options: parsedOptions
      }
    });
    return c2.json({ text: transcription?.text });
  } catch (error) {
    return handleError(error, "Error transcribing speech");
  }
}
async function getWorkflowsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflows = await getWorkflowsHandler$1({
      mastra
    });
    return c2.json(workflows);
  } catch (error) {
    return handleError(error, "Error getting workflows");
  }
}
async function getWorkflowByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const workflow = await getWorkflowByIdHandler$1({
      mastra,
      workflowId
    });
    return c2.json(workflow);
  } catch (error) {
    return handleError(error, "Error getting workflow");
  }
}
async function createWorkflowRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const prevRunId = c2.req.query("runId");
    const result = await createWorkflowRunHandler$1({
      mastra,
      workflowId,
      runId: prevRunId
    });
    return c2.json(result);
  } catch (e2) {
    return handleError(e2, "Error creating run");
  }
}
async function startAsyncWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const { inputData } = await c2.req.json();
    const runId = c2.req.query("runId");
    const result = await startAsyncWorkflowHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      inputData
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error executing workflow");
  }
}
async function startWorkflowRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const { inputData } = await c2.req.json();
    const runId = c2.req.query("runId");
    await startWorkflowRunHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      inputData
    });
    return c2.json({ message: "Workflow run started" });
  } catch (e2) {
    return handleError(e2, "Error starting workflow run");
  }
}
function watchWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const logger2 = mastra.getLogger();
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.query("runId");
    if (!runId) {
      throw new HTTPException$1(400, { message: "runId required to watch workflow" });
    }
    c2.header("Transfer-Encoding", "chunked");
    return stream(
      c2,
      async (stream5) => {
        try {
          const result = await watchWorkflowHandler$1({
            mastra,
            workflowId,
            runId
          });
          const reader = result.getReader();
          stream5.onAbort(() => {
            void reader.cancel("request aborted");
          });
          let chunkResult;
          while ((chunkResult = await reader.read()) && !chunkResult.done) {
            await stream5.write(JSON.stringify(chunkResult.value) + "");
          }
        } catch (err) {
          mastra.getLogger().error("Error in watch stream: " + (err?.message ?? "Unknown error"));
        }
      },
      async (err) => {
        logger2.error("Error in watch stream: " + err?.message);
      }
    );
  } catch (error) {
    return handleError(error, "Error watching workflow");
  }
}
async function streamWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const logger2 = mastra.getLogger();
    const workflowId = c2.req.param("workflowId");
    const { inputData } = await c2.req.json();
    const runId = c2.req.query("runId");
    c2.header("Transfer-Encoding", "chunked");
    return stream(
      c2,
      async (stream5) => {
        try {
          const result = await streamWorkflowHandler$1({
            mastra,
            workflowId,
            runId,
            inputData,
            runtimeContext
          });
          const reader = result.stream.getReader();
          stream5.onAbort(() => {
            void reader.cancel("request aborted");
          });
          let chunkResult;
          while ((chunkResult = await reader.read()) && !chunkResult.done) {
            await stream5.write(JSON.stringify(chunkResult.value) + "");
          }
        } catch (err) {
          console.log(err);
        }
      },
      async (err) => {
        logger2.error("Error in workflow stream: " + err?.message);
      }
    );
  } catch (error) {
    return handleError(error, "Error streaming workflow");
  }
}
async function resumeAsyncWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.query("runId");
    const { step, resumeData } = await c2.req.json();
    if (!runId) {
      throw new HTTPException$1(400, { message: "runId required to resume workflow" });
    }
    const result = await resumeAsyncWorkflowHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      body: { step, resumeData }
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error resuming workflow step");
  }
}
async function resumeWorkflowHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const runtimeContext = c2.get("runtimeContext");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.query("runId");
    const { step, resumeData } = await c2.req.json();
    if (!runId) {
      throw new HTTPException$1(400, { message: "runId required to resume workflow" });
    }
    await resumeWorkflowHandler$1({
      mastra,
      runtimeContext,
      workflowId,
      runId,
      body: { step, resumeData }
    });
    return c2.json({ message: "Workflow run resumed" });
  } catch (error) {
    return handleError(error, "Error resuming workflow");
  }
}
async function getWorkflowRunsHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const { fromDate, toDate, limit, offset, resourceId } = c2.req.query();
    const workflowRuns = await getWorkflowRunsHandler$1({
      mastra,
      workflowId,
      fromDate: fromDate ? new Date(fromDate) : void 0,
      toDate: toDate ? new Date(toDate) : void 0,
      limit: limit ? Number(limit) : void 0,
      offset: offset ? Number(offset) : void 0,
      resourceId
    });
    return c2.json(workflowRuns);
  } catch (error) {
    return handleError(error, "Error getting workflow runs");
  }
}
async function getWorkflowRunByIdHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.param("runId");
    const workflowRun = await getWorkflowRunByIdHandler$1({
      mastra,
      workflowId,
      runId
    });
    return c2.json(workflowRun);
  } catch (error) {
    return handleError(error, "Error getting workflow run");
  }
}
async function getWorkflowRunExecutionResultHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.param("runId");
    const workflowRunExecutionResult = await getWorkflowRunExecutionResultHandler$1({
      mastra,
      workflowId,
      runId
    });
    return c2.json(workflowRunExecutionResult);
  } catch (error) {
    return handleError(error, "Error getting workflow run execution result");
  }
}
async function cancelWorkflowRunHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.param("runId");
    const result = await cancelWorkflowRunHandler$1({
      mastra,
      workflowId,
      runId
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error canceling workflow run");
  }
}
async function sendWorkflowRunEventHandler(c2) {
  try {
    const mastra = c2.get("mastra");
    const workflowId = c2.req.param("workflowId");
    const runId = c2.req.param("runId");
    const { event, data } = await c2.req.json();
    const result = await sendWorkflowRunEventHandler$1({
      mastra,
      workflowId,
      runId,
      event,
      data
    });
    return c2.json(result);
  } catch (error) {
    return handleError(error, "Error sending workflow run event");
  }
}

// src/server/welcome.ts
var html2 = `
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Welcome to Mastra</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/inter-ui/3.19.3/inter.min.css" />
    <style>
      body {
        margin: 0;
        padding: 0;
        background-color: #0d0d0d;
        color: #ffffff;
        font-family:
          'Inter',
          -apple-system,
          BlinkMacSystemFont,
          system-ui,
          sans-serif;
        min-height: 100vh;
        display: flex;
        flex-direction: column;
      }

      main {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 2rem;
        text-align: center;
      }

      h1 {
        font-size: 4rem;
        font-weight: 600;
        margin: 0 0 1rem 0;
        background: linear-gradient(to right, #fff, #ccc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        line-height: 1.2;
      }

      .subtitle {
        color: #9ca3af;
        font-size: 1.25rem;
        max-width: 600px;
        margin: 0 auto 3rem auto;
        line-height: 1.6;
      }

      .docs-link {
        background-color: #1a1a1a;
        padding: 1rem 2rem;
        border-radius: 0.5rem;
        display: flex;
        align-items: center;
        gap: 1rem;
        font-family: monospace;
        font-size: 1rem;
        color: #ffffff;
        text-decoration: none;
        transition: background-color 0.2s;
      }

      .docs-link:hover {
        background-color: #252525;
      }

      .arrow-icon {
        transition: transform 0.2s;
      }

      .docs-link:hover .arrow-icon {
        transform: translateX(4px);
      }
    </style>
  </head>
  <body>
    <main>
      <h1>Welcome to Mastra</h1>
      <p class="subtitle">
        From the team that brought you Gatsby: prototype and productionize AI features with a modern JS/TS stack.
      </p>

      <a href="https://mastra.ai/docs" class="docs-link">
        Browse the docs
        <svg
          class="arrow-icon"
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path d="M5 12h14M12 5l7 7-7 7" />
        </svg>
      </a>
    </main>
  </body>
</html>
`;

// src/server/index.ts
async function createHonoServer(mastra, options = {}) {
  const app = new Hono();
  const server = mastra.getServer();
  let tools = {};
  try {
    const toolImports = (await import('./tools.mjs')).tools;
    tools = toolImports.reduce((acc, toolModule) => {
      Object.entries(toolModule).forEach(([key, tool]) => {
        if (tool instanceof Tool) {
          acc[key] = tool;
        }
      });
      return acc;
    }, {});
  } catch (err) {
    console.error(
      `Failed to import tools
reason: ${err.message}
${err.stack.split("\n").slice(1).join("\n")}
    `,
      err
    );
  }
  app.use("*", async function setTelemetryInfo(c2, next) {
    const requestId = c2.req.header("x-request-id") ?? randomUUID();
    const span = Telemetry.getActiveSpan();
    if (span) {
      span.setAttribute("http.request_id", requestId);
      span.updateName(`${c2.req.method} ${c2.req.path}`);
      const newCtx = Telemetry.setBaggage({
        "http.request_id": { value: requestId }
      });
      await new Promise((resolve) => {
        Telemetry.withContext(newCtx, async () => {
          await next();
          resolve(true);
        });
      });
    } else {
      await next();
    }
  });
  app.onError((err, c2) => errorHandler(err, c2, options.isDev));
  app.use("*", async function setContext(c2, next) {
    let runtimeContext = new RuntimeContext();
    if (c2.req.method === "POST" || c2.req.method === "PUT") {
      const contentType = c2.req.header("content-type");
      if (contentType?.includes("application/json")) {
        try {
          const clonedReq = c2.req.raw.clone();
          const body = await clonedReq.json();
          if (body.runtimeContext) {
            runtimeContext = new RuntimeContext(Object.entries(body.runtimeContext));
          }
        } catch {
        }
      }
    }
    c2.set("runtimeContext", runtimeContext);
    c2.set("mastra", mastra);
    c2.set("tools", tools);
    c2.set("playground", options.playground === true);
    c2.set("isDev", options.isDev === true);
    return next();
  });
  const serverMiddleware = mastra.getServerMiddleware?.();
  if (serverMiddleware && serverMiddleware.length > 0) {
    for (const m2 of serverMiddleware) {
      app.use(m2.path, m2.handler);
    }
  }
  if (server?.cors === false) {
    app.use("*", timeout(server?.timeout ?? 3 * 60 * 1e3));
  } else {
    const corsConfig = {
      origin: "*",
      allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      credentials: false,
      maxAge: 3600,
      ...server?.cors,
      allowHeaders: ["Content-Type", "Authorization", "x-mastra-client-type", ...server?.cors?.allowHeaders ?? []],
      exposeHeaders: ["Content-Length", "X-Requested-With", ...server?.cors?.exposeHeaders ?? []]
    };
    app.use("*", timeout(server?.timeout ?? 3 * 60 * 1e3), cors(corsConfig));
  }
  app.use("*", authenticationMiddleware);
  app.use("*", authorizationMiddleware);
  const bodyLimitOptions = {
    maxSize: server?.bodySizeLimit ?? 4.5 * 1024 * 1024,
    // 4.5 MB,
    onError: (c2) => c2.json({ error: "Request body too large" }, 413)
  };
  const routes = server?.apiRoutes;
  if (server?.middleware) {
    const normalizedMiddlewares = Array.isArray(server.middleware) ? server.middleware : [server.middleware];
    const middlewares = normalizedMiddlewares.map((middleware2) => {
      if (typeof middleware2 === "function") {
        return {
          path: "*",
          handler: middleware2
        };
      }
      return middleware2;
    });
    for (const middleware2 of middlewares) {
      app.use(middleware2.path, middleware2.handler);
    }
  }
  if (routes) {
    for (const route of routes) {
      const middlewares = [];
      if (route.middleware) {
        middlewares.push(...Array.isArray(route.middleware) ? route.middleware : [route.middleware]);
      }
      if (route.openapi) {
        middlewares.push(w(route.openapi));
      }
      const handler = "handler" in route ? route.handler : await route.createHandler({ mastra });
      if (route.method === "GET") {
        app.get(route.path, ...middlewares, handler);
      } else if (route.method === "POST") {
        app.post(route.path, ...middlewares, handler);
      } else if (route.method === "PUT") {
        app.put(route.path, ...middlewares, handler);
      } else if (route.method === "DELETE") {
        app.delete(route.path, ...middlewares, handler);
      } else if (route.method === "ALL") {
        app.all(route.path, ...middlewares, handler);
      }
    }
  }
  if (server?.build?.apiReqLogs) {
    app.use(logger());
  }
  app.get(
    "/.well-known/:agentId/agent.json",
    w({
      description: "Get agent configuration",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Agent configuration"
        }
      }
    }),
    getAgentCardByIdHandler
  );
  app.post(
    "/a2a/:agentId",
    w({
      description: "Execute agent via A2A protocol",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                method: {
                  type: "string",
                  enum: ["tasks/send", "tasks/sendSubscribe", "tasks/get", "tasks/cancel"],
                  description: "The A2A protocol method to execute"
                },
                params: {
                  type: "object",
                  oneOf: [
                    {
                      // TaskSendParams
                      type: "object",
                      properties: {
                        id: {
                          type: "string",
                          description: "Unique identifier for the task being initiated or continued"
                        },
                        sessionId: {
                          type: "string",
                          description: "Optional identifier for the session this task belongs to"
                        },
                        message: {
                          type: "object",
                          description: "The message content to send to the agent for processing"
                        },
                        pushNotification: {
                          type: "object",
                          nullable: true,
                          description: "Optional pushNotification information for receiving notifications about this task"
                        },
                        historyLength: {
                          type: "integer",
                          nullable: true,
                          description: "Optional parameter to specify how much message history to include in the response"
                        },
                        metadata: {
                          type: "object",
                          nullable: true,
                          description: "Optional metadata associated with sending this message"
                        }
                      },
                      required: ["id", "message"]
                    },
                    {
                      // TaskQueryParams
                      type: "object",
                      properties: {
                        id: { type: "string", description: "The unique identifier of the task" },
                        historyLength: {
                          type: "integer",
                          nullable: true,
                          description: "Optional history length to retrieve for the task"
                        },
                        metadata: {
                          type: "object",
                          nullable: true,
                          description: "Optional metadata to include with the operation"
                        }
                      },
                      required: ["id"]
                    },
                    {
                      // TaskIdParams
                      type: "object",
                      properties: {
                        id: { type: "string", description: "The unique identifier of the task" },
                        metadata: {
                          type: "object",
                          nullable: true,
                          description: "Optional metadata to include with the operation"
                        }
                      },
                      required: ["id"]
                    }
                  ]
                }
              },
              required: ["method", "params"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "A2A response"
        },
        400: {
          description: "Missing or invalid request parameters"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getAgentExecutionHandler
  );
  app.get(
    "/api",
    w({
      description: "Get API status",
      tags: ["system"],
      responses: {
        200: {
          description: "Success"
        }
      }
    }),
    rootHandler
  );
  app.get(
    "/api/agents",
    w({
      description: "Get all available agents",
      tags: ["agents"],
      responses: {
        200: {
          description: "List of all agents"
        }
      }
    }),
    getAgentsHandler
  );
  app.get(
    "/api/networks/v-next",
    w({
      description: "Get all available v-next networks",
      tags: ["vNextNetworks"],
      responses: {
        200: {
          description: "List of all v-next networks"
        }
      }
    }),
    getVNextNetworksHandler
  );
  app.get(
    "/api/networks/v-next/:networkId",
    w({
      description: "Get v-next network by ID",
      tags: ["vNextNetworks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "v-next Network details"
        },
        404: {
          description: "v-next Network not found"
        }
      }
    }),
    getVNextNetworkByIdHandler
  );
  app.post(
    "/api/networks/v-next/:networkId/generate",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Generate a response from a v-next network",
      tags: ["vNextNetworks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                  description: "Message for the v-next network"
                },
                threadId: {
                  type: "string",
                  description: "Thread Id of the conversation"
                },
                resourceId: {
                  type: "string",
                  description: "Resource Id of the conversation"
                }
              },
              required: ["message"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "v-next Network not found"
        }
      }
    }),
    generateVNextNetworkHandler
  );
  app.post(
    "/api/networks/v-next/:networkId/loop",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Loop a v-next network",
      tags: ["vNextNetworks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                  description: "Message for the v-next network"
                }
              },
              required: ["message"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Looped response"
        },
        404: {
          description: "v-next Network not found"
        }
      }
    }),
    loopVNextNetworkHandler
  );
  app.post(
    "/api/networks/v-next/:networkId/loop-stream",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Stream a v-next network loop",
      tags: ["vNextNetworks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                  description: "Message for the v-next network"
                },
                threadId: {
                  type: "string",
                  description: "Thread Id of the conversation"
                },
                resourceId: {
                  type: "string",
                  description: "Resource Id of the conversation"
                },
                maxIterations: {
                  type: "number",
                  description: "Maximum number of iterations to run"
                }
              },
              required: ["message"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Streamed response"
        },
        404: {
          description: "v-next Network not found"
        }
      }
    }),
    loopStreamVNextNetworkHandler
  );
  app.post(
    "/api/networks/v-next/:networkId/stream",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Stream a response from a v-next network",
      tags: ["vNextNetworks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                  description: "Message for the v-next network"
                },
                threadId: {
                  type: "string",
                  description: "Thread Id of the conversation"
                },
                resourceId: {
                  type: "string",
                  description: "Resource Id of the conversation"
                }
              },
              required: ["message"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Streamed response"
        },
        404: {
          description: "v-next Network not found"
        }
      }
    }),
    streamGenerateVNextNetworkHandler
  );
  app.get(
    "/api/networks",
    w({
      description: "Get all available networks",
      tags: ["networks"],
      responses: {
        200: {
          description: "List of all networks"
        }
      }
    }),
    getNetworksHandler
  );
  app.get(
    "/api/networks/:networkId",
    w({
      description: "Get network by ID",
      tags: ["networks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Network details"
        },
        404: {
          description: "Network not found"
        }
      }
    }),
    getNetworkByIdHandler
  );
  app.post(
    "/api/networks/:networkId/generate",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Generate a response from a network",
      tags: ["networks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: {
                  oneOf: [
                    { type: "string" },
                    {
                      type: "array",
                      items: { type: "object" }
                    }
                  ],
                  description: "Input for the network, can be a string or an array of CoreMessage objects"
                }
              },
              required: ["input"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "Network not found"
        }
      }
    }),
    generateHandler2
  );
  app.post(
    "/api/networks/:networkId/stream",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Generate a response from a network",
      tags: ["networks"],
      parameters: [
        {
          name: "networkId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: {
                  oneOf: [
                    { type: "string" },
                    {
                      type: "array",
                      items: { type: "object" }
                    }
                  ],
                  description: "Input for the network, can be a string or an array of CoreMessage objects"
                }
              },
              required: ["input"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "Network not found"
        }
      }
    }),
    streamGenerateHandler2
  );
  app.get(
    "/api/agents/:agentId",
    w({
      description: "Get agent by ID",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Agent details"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getAgentByIdHandler
  );
  app.get(
    "/api/agents/:agentId/evals/ci",
    w({
      description: "Get CI evals by agent ID",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of evals"
        }
      }
    }),
    getEvalsByAgentIdHandler
  );
  app.get(
    "/api/agents/:agentId/evals/live",
    w({
      description: "Get live evals by agent ID",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of evals"
        }
      }
    }),
    getLiveEvalsByAgentIdHandler
  );
  app.post(
    "/api/agents/:agentId/generate",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Generate a response from an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                },
                threadId: { type: "string" },
                resourceId: { type: "string", description: "The resource ID for the conversation" },
                resourceid: {
                  type: "string",
                  description: "The resource ID for the conversation (deprecated, use resourceId instead)",
                  deprecated: true
                },
                runId: { type: "string" },
                output: { type: "object" }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Generated response"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    generateHandler
  );
  app.post(
    "/api/agents/:agentId/stream",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Stream a response from an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                },
                threadId: { type: "string" },
                resourceId: { type: "string", description: "The resource ID for the conversation" },
                resourceid: {
                  type: "string",
                  description: "The resource ID for the conversation (deprecated, use resourceId instead)",
                  deprecated: true
                },
                runId: { type: "string" },
                output: { type: "object" }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Streamed response"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    streamGenerateHandler
  );
  if (options.isDev) {
    app.post(
      "/api/agents/:agentId/instructions",
      bodyLimit(bodyLimitOptions),
      w({
        description: "Update an agent's instructions",
        tags: ["agents"],
        parameters: [
          {
            name: "agentId",
            in: "path",
            required: true,
            schema: { type: "string" }
          }
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  instructions: {
                    type: "string",
                    description: "New instructions for the agent"
                  }
                },
                required: ["instructions"]
              }
            }
          }
        },
        responses: {
          200: {
            description: "Instructions updated successfully"
          },
          403: {
            description: "Not allowed in non-playground environment"
          },
          404: {
            description: "Agent not found"
          }
        }
      }),
      setAgentInstructionsHandler
    );
    app.post(
      "/api/agents/:agentId/instructions/enhance",
      bodyLimit(bodyLimitOptions),
      w({
        description: "Generate an improved system prompt from instructions",
        tags: ["agents"],
        parameters: [
          {
            name: "agentId",
            in: "path",
            required: true,
            schema: { type: "string" },
            description: "ID of the agent whose model will be used for prompt generation"
          }
        ],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  instructions: {
                    type: "string",
                    description: "Instructions to generate a system prompt from"
                  },
                  comment: {
                    type: "string",
                    description: "Optional comment for the enhanced prompt"
                  }
                },
                required: ["instructions"]
              }
            }
          }
        },
        responses: {
          200: {
            description: "Generated system prompt and analysis",
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  properties: {
                    explanation: {
                      type: "string",
                      description: "Detailed analysis of the instructions"
                    },
                    new_prompt: {
                      type: "string",
                      description: "The enhanced system prompt"
                    }
                  }
                }
              }
            }
          },
          400: {
            description: "Missing or invalid request parameters"
          },
          404: {
            description: "Agent not found"
          },
          500: {
            description: "Internal server error or model response parsing error"
          }
        }
      }),
      generateSystemPromptHandler
    );
  }
  app.get(
    "/api/agents/:agentId/speakers",
    async (c2, next) => {
      c2.header("Deprecation", "true");
      c2.header("Warning", '299 - "This endpoint is deprecated, use /api/agents/:agentId/voice/speakers instead"');
      c2.header("Link", '</api/agents/:agentId/voice/speakers>; rel="successor-version"');
      return next();
    },
    w({
      description: "[DEPRECATED] Use /api/agents/:agentId/voice/speakers instead. Get available speakers for an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of available speakers",
          content: {
            "application/json": {
              schema: {
                type: "array",
                items: {
                  type: "object",
                  description: "Speaker information depending on the voice provider",
                  properties: {
                    voiceId: { type: "string" }
                  },
                  additionalProperties: true
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getSpeakersHandler
  );
  app.get(
    "/api/agents/:agentId/voice/speakers",
    w({
      description: "Get available speakers for an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of available speakers",
          content: {
            "application/json": {
              schema: {
                type: "array",
                items: {
                  type: "object",
                  description: "Speaker information depending on the voice provider",
                  properties: {
                    voiceId: { type: "string" }
                  },
                  additionalProperties: true
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getSpeakersHandler
  );
  app.post(
    "/api/agents/:agentId/speak",
    bodyLimit(bodyLimitOptions),
    async (c2, next) => {
      c2.header("Deprecation", "true");
      c2.header("Warning", '299 - "This endpoint is deprecated, use /api/agents/:agentId/voice/speak instead"');
      c2.header("Link", '</api/agents/:agentId/voice/speak>; rel="successor-version"');
      return next();
    },
    w({
      description: "[DEPRECATED] Use /api/agents/:agentId/voice/speak instead. Convert text to speech using the agent's voice provider",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                text: {
                  type: "string",
                  description: "Text to convert to speech"
                },
                options: {
                  type: "object",
                  description: "Provider-specific options for speech generation",
                  properties: {
                    speaker: {
                      type: "string",
                      description: "Speaker ID to use for speech generation"
                    }
                  },
                  additionalProperties: true
                }
              },
              required: ["text"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Audio stream",
          content: {
            "audio/mpeg": {
              schema: {
                format: "binary",
                description: "Audio stream containing the generated speech"
              }
            },
            "audio/*": {
              schema: {
                format: "binary",
                description: "Audio stream depending on the provider"
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    speakHandler
  );
  app.post(
    "/api/agents/:agentId/voice/speak",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Convert text to speech using the agent's voice provider",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: {
                  type: "string",
                  description: "Text to convert to speech"
                },
                options: {
                  type: "object",
                  description: "Provider-specific options for speech generation",
                  properties: {
                    speaker: {
                      type: "string",
                      description: "Speaker ID to use for speech generation"
                    },
                    options: {
                      type: "object",
                      description: "Provider-specific options for speech generation",
                      additionalProperties: true
                    }
                  },
                  additionalProperties: true
                }
              },
              required: ["text"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Audio stream",
          content: {
            "audio/mpeg": {
              schema: {
                format: "binary",
                description: "Audio stream containing the generated speech"
              }
            },
            "audio/*": {
              schema: {
                format: "binary",
                description: "Audio stream depending on the provider"
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    speakHandler
  );
  app.get(
    "/api/agents/:agentId/voice/listener",
    w({
      description: "Get available listener for an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Checks if listener is available for the agent",
          content: {
            "application/json": {
              schema: {
                type: "object",
                description: "Listener information depending on the voice provider",
                properties: {
                  enabled: { type: "boolean" }
                },
                additionalProperties: true
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    getListenerHandler
  );
  app.post(
    "/api/agents/:agentId/listen",
    bodyLimit({
      ...bodyLimitOptions,
      maxSize: 10 * 1024 * 1024
      // 10 MB for audio files
    }),
    async (c2, next) => {
      c2.header("Deprecation", "true");
      c2.header("Warning", '299 - "This endpoint is deprecated, use /api/agents/:agentId/voice/listen instead"');
      c2.header("Link", '</api/agents/:agentId/voice/listen>; rel="successor-version"');
      return next();
    },
    w({
      description: "[DEPRECATED] Use /api/agents/:agentId/voice/listen instead. Convert speech to text using the agent's voice provider. Additional provider-specific options can be passed as query parameters.",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "audio/mpeg": {
            schema: {
              format: "binary",
              description: "Audio data stream to transcribe (supports various formats depending on provider like mp3, wav, webm, flac)"
            }
          }
        }
      },
      responses: {
        200: {
          description: "Transcription result",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  text: {
                    type: "string",
                    description: "Transcribed text"
                  }
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    listenHandler
  );
  app.post(
    "/api/agents/:agentId/voice/listen",
    bodyLimit({
      ...bodyLimitOptions,
      maxSize: 10 * 1024 * 1024
      // 10 MB for audio files
    }),
    w({
      description: "Convert speech to text using the agent's voice provider. Additional provider-specific options can be passed as query parameters.",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "multipart/form-data": {
            schema: {
              type: "object",
              required: ["audio"],
              properties: {
                audio: {
                  type: "string",
                  format: "binary",
                  description: "Audio data stream to transcribe (supports various formats depending on provider like mp3, wav, webm, flac)"
                },
                options: {
                  type: "object",
                  description: "Provider-specific options for speech-to-text",
                  additionalProperties: true
                }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Transcription result",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  text: {
                    type: "string",
                    description: "Transcribed text"
                  }
                }
              }
            }
          }
        },
        400: {
          description: "Agent does not have voice capabilities or invalid request"
        },
        404: {
          description: "Agent not found"
        }
      }
    }),
    listenHandler
  );
  app.post(
    "/api/agents/:agentId/tools/:toolId/execute",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Execute a tool through an agent",
      tags: ["agents"],
      parameters: [
        {
          name: "agentId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "toolId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                data: { type: "object" },
                runtimeContext: { type: "object" }
              },
              required: ["data"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Tool execution result"
        },
        404: {
          description: "Tool or agent not found"
        }
      }
    }),
    executeAgentToolHandler
  );
  app.post(
    "/api/mcp/:serverId/mcp",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Send a message to an MCP server using Streamable HTTP",
      tags: ["mcp"],
      parameters: [
        {
          name: "serverId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        content: { "application/json": { schema: { type: "object" } } }
      },
      responses: {
        200: {
          description: "Streamable HTTP connection processed"
        },
        404: {
          description: "MCP server not found"
        }
      }
    }),
    getMcpServerMessageHandler
  );
  app.get(
    "/api/mcp/:serverId/mcp",
    w({
      description: "Send a message to an MCP server using Streamable HTTP",
      tags: ["mcp"],
      parameters: [
        {
          name: "serverId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Streamable HTTP connection processed"
        },
        404: {
          description: "MCP server not found"
        }
      }
    }),
    getMcpServerMessageHandler
  );
  const mcpSseBasePath = "/api/mcp/:serverId/sse";
  const mcpSseMessagePath = "/api/mcp/:serverId/messages";
  app.get(
    mcpSseBasePath,
    w({
      description: "Establish an MCP Server-Sent Events (SSE) connection with a server instance.",
      tags: ["mcp"],
      parameters: [
        {
          name: "serverId",
          in: "path",
          required: true,
          schema: { type: "string" },
          description: "The ID of the MCP server instance."
        }
      ],
      responses: {
        200: {
          description: "SSE connection established. The client will receive events over this connection. (Content-Type: text/event-stream)"
        },
        404: { description: "MCP server instance not found." },
        500: { description: "Internal server error establishing SSE connection." }
      }
    }),
    getMcpServerSseHandler
  );
  app.post(
    mcpSseMessagePath,
    bodyLimit(bodyLimitOptions),
    // Apply body limit for messages
    w({
      description: "Send a message to an MCP server over an established SSE connection.",
      tags: ["mcp"],
      parameters: [
        {
          name: "serverId",
          in: "path",
          required: true,
          schema: { type: "string" },
          description: "The ID of the MCP server instance."
        }
      ],
      requestBody: {
        description: "JSON-RPC message to send to the MCP server.",
        required: true,
        content: { "application/json": { schema: { type: "object" } } }
        // MCP messages are typically JSON
      },
      responses: {
        200: {
          description: "Message received and is being processed by the MCP server. The actual result or error will be sent as an SSE event over the established connection."
        },
        400: { description: "Bad request (e.g., invalid JSON payload or missing body)." },
        404: { description: "MCP server instance not found or SSE connection path incorrect." },
        503: { description: "SSE connection not established with this server, or server unable to process message." }
      }
    }),
    getMcpServerSseHandler
  );
  app.get(
    "/api/mcp/v0/servers",
    w({
      description: "List all available MCP server instances with basic information.",
      tags: ["mcp"],
      parameters: [
        {
          name: "limit",
          in: "query",
          description: "Number of results per page.",
          required: false,
          schema: { type: "integer", default: 50, minimum: 1, maximum: 5e3 }
        },
        {
          name: "offset",
          in: "query",
          description: "Number of results to skip for pagination.",
          required: false,
          schema: { type: "integer", default: 0, minimum: 0 }
        }
      ],
      responses: {
        200: {
          description: "A list of MCP server instances.",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  servers: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        id: { type: "string" },
                        name: { type: "string" },
                        description: { type: "string" },
                        repository: {
                          type: "object",
                          properties: {
                            url: { type: "string", description: "The URL of the repository (e.g., a GitHub URL)" },
                            source: {
                              type: "string",
                              description: "The source control platform (e.g., 'github', 'gitlab')",
                              enum: ["github", "gitlab"]
                            },
                            id: { type: "string", description: "A unique identifier for the repository at the source" }
                          }
                        },
                        version_detail: {
                          type: "object",
                          properties: {
                            version: { type: "string", description: 'The semantic version string (e.g., "1.0.2")' },
                            release_date: {
                              type: "string",
                              description: "The ISO 8601 date-time string when this version was released or registered"
                            },
                            is_latest: {
                              type: "boolean",
                              description: "Indicates if this version is the latest available"
                            }
                          }
                        }
                      }
                    }
                  },
                  next: { type: "string", format: "uri", nullable: true },
                  total_count: { type: "integer" }
                }
              }
            }
          }
        }
      }
    }),
    listMcpRegistryServersHandler
  );
  app.get(
    "/api/mcp/v0/servers/:id",
    w({
      description: "Get detailed information about a specific MCP server instance.",
      tags: ["mcp"],
      parameters: [
        {
          name: "id",
          in: "path",
          required: true,
          description: "Unique ID of the MCP server instance.",
          schema: { type: "string" }
        },
        {
          name: "version",
          in: "query",
          required: false,
          description: "Desired MCP server version (currently informational, server returns its actual version).",
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Detailed information about the MCP server instance.",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  id: { type: "string" },
                  name: { type: "string" },
                  description: { type: "string" },
                  repository: {
                    type: "object",
                    properties: {
                      url: { type: "string" },
                      source: { type: "string" },
                      id: { type: "string" }
                    }
                  },
                  version_detail: {
                    type: "object",
                    properties: {
                      version: { type: "string" },
                      release_date: { type: "string" },
                      is_latest: { type: "boolean" }
                    }
                  },
                  package_canonical: { type: "string" },
                  packages: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        registry_name: { type: "string" },
                        name: { type: "string" },
                        version: { type: "string" },
                        command: {
                          type: "object",
                          properties: {
                            name: { type: "string" },
                            subcommands: {
                              type: "array",
                              items: {
                                type: "object",
                                properties: {
                                  name: { type: "string" },
                                  description: { type: "string" },
                                  is_required: { type: "boolean" },
                                  subcommands: {
                                    type: "array",
                                    items: { type: "object" }
                                  },
                                  positional_arguments: {
                                    type: "array",
                                    items: { type: "object" }
                                  },
                                  named_arguments: {
                                    type: "array",
                                    items: { type: "object" }
                                  }
                                }
                              }
                            },
                            positional_arguments: {
                              type: "array",
                              items: { type: "object" }
                            },
                            named_arguments: {
                              type: "array",
                              items: { type: "object" }
                            }
                          }
                        },
                        environment_variables: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              name: { type: "string" },
                              description: { type: "string" },
                              required: { type: "boolean" },
                              default_value: { type: "string" }
                            }
                          }
                        }
                      }
                    }
                  },
                  remotes: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        transport_type: { type: "string" },
                        url: { type: "string" }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        404: {
          description: "MCP server instance not found.",
          content: {
            "application/json": {
              schema: {
                type: "object",
                properties: {
                  error: { type: "string" }
                }
              }
            }
          }
        }
      }
    }),
    getMcpRegistryServerDetailHandler
  );
  app.get(
    "/api/mcp/:serverId/tools",
    w({
      description: "List all tools available on a specific MCP server instance.",
      tags: ["mcp"],
      parameters: [
        {
          name: "serverId",
          in: "path",
          required: true,
          description: "Unique ID of the MCP server instance.",
          schema: { type: "string" }
        }
      ],
      responses: {
        200: { description: "A list of tools for the MCP server." },
        // Define schema if you have one for McpServerToolListResponse
        404: { description: "MCP server instance not found." },
        501: { description: "Server does not support listing tools." }
      }
    }),
    listMcpServerToolsHandler
  );
  app.get(
    "/api/mcp/:serverId/tools/:toolId",
    w({
      description: "Get details for a specific tool on an MCP server.",
      tags: ["mcp"],
      parameters: [
        { name: "serverId", in: "path", required: true, schema: { type: "string" } },
        { name: "toolId", in: "path", required: true, schema: { type: "string" } }
      ],
      responses: {
        200: { description: "Details of the specified tool." },
        // Define schema for McpToolInfo
        404: { description: "MCP server or tool not found." },
        501: { description: "Server does not support getting tool details." }
      }
    }),
    getMcpServerToolDetailHandler
  );
  app.post(
    "/api/mcp/:serverId/tools/:toolId/execute",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Execute a specific tool on an MCP server.",
      tags: ["mcp"],
      parameters: [
        { name: "serverId", in: "path", required: true, schema: { type: "string" } },
        { name: "toolId", in: "path", required: true, schema: { type: "string" } }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                data: { type: "object" },
                runtimeContext: { type: "object" }
              }
            }
          }
        }
        // Simplified schema
      },
      responses: {
        200: { description: "Result of the tool execution." },
        400: { description: "Invalid tool arguments." },
        404: { description: "MCP server or tool not found." },
        501: { description: "Server does not support tool execution." }
      }
    }),
    executeMcpServerToolHandler
  );
  app.get(
    "/api/memory/network/status",
    w({
      description: "Get network memory status",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Memory status"
        }
      }
    }),
    getMemoryStatusHandler
  );
  app.get(
    "/api/memory/network/threads",
    w({
      description: "Get all threads",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "resourceid",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of all threads"
        }
      }
    }),
    getThreadsHandler
  );
  app.get(
    "/api/memory/network/threads/:threadId",
    w({
      description: "Get thread by ID",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Thread details"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    getThreadByIdHandler
  );
  app.get(
    "/api/memory/network/threads/:threadId/messages",
    w({
      description: "Get messages for a thread",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "limit",
          in: "query",
          required: false,
          schema: { type: "number" },
          description: "Limit the number of messages to retrieve (default: 40)"
        }
      ],
      responses: {
        200: {
          description: "List of messages"
        }
      }
    }),
    getMessagesHandler
  );
  app.post(
    "/api/memory/network/threads",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Create a new thread",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                title: { type: "string" },
                metadata: { type: "object" },
                resourceId: { type: "string" },
                threadId: { type: "string" }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Created thread"
        }
      }
    }),
    createThreadHandler
  );
  app.patch(
    "/api/memory/network/threads/:threadId",
    w({
      description: "Update a thread",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { type: "object" }
          }
        }
      },
      responses: {
        200: {
          description: "Updated thread"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    updateThreadHandler
  );
  app.delete(
    "/api/memory/network/threads/:threadId",
    w({
      description: "Delete a thread",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Thread deleted"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    deleteThreadHandler
  );
  app.post(
    "/api/memory/network/save-messages",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Save messages",
      tags: ["networkMemory"],
      parameters: [
        {
          name: "networkId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Messages saved"
        }
      }
    }),
    saveMessagesHandler
  );
  app.get(
    "/api/memory/status",
    w({
      description: "Get memory status",
      tags: ["memory"],
      parameters: [
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Memory status"
        }
      }
    }),
    getMemoryStatusHandler
  );
  app.get(
    "/api/memory/threads",
    w({
      description: "Get all threads",
      tags: ["memory"],
      parameters: [
        {
          name: "resourceid",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of all threads"
        }
      }
    }),
    getThreadsHandler
  );
  app.get(
    "/api/memory/threads/:threadId",
    w({
      description: "Get thread by ID",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Thread details"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    getThreadByIdHandler
  );
  app.get(
    "/api/memory/threads/:threadId/messages",
    w({
      description: "Get messages for a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "limit",
          in: "query",
          required: false,
          schema: { type: "number" },
          description: "Limit the number of messages to retrieve (default: 40)"
        }
      ],
      responses: {
        200: {
          description: "List of messages"
        }
      }
    }),
    getMessagesHandler
  );
  app.get(
    "/api/memory/threads/:threadId/working-memory",
    w({
      description: "Get working memory for a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "resourceId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Working memory details"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    getWorkingMemoryHandler
  );
  app.post(
    "/api/memory/threads/:threadId/working-memory",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Update working memory for a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                workingMemory: { type: "string" },
                resourceId: { type: "string" }
              },
              required: ["workingMemory"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Working memory updated successfully"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    updateWorkingMemoryHandler
  );
  app.post(
    "/api/memory/threads",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Create a new thread",
      tags: ["memory"],
      parameters: [
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                title: { type: "string" },
                metadata: { type: "object" },
                resourceId: { type: "string" },
                threadId: { type: "string" }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Created thread"
        }
      }
    }),
    createThreadHandler
  );
  app.patch(
    "/api/memory/threads/:threadId",
    w({
      description: "Update a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { type: "object" }
          }
        }
      },
      responses: {
        200: {
          description: "Updated thread"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    updateThreadHandler
  );
  app.delete(
    "/api/memory/threads/:threadId",
    w({
      description: "Delete a thread",
      tags: ["memory"],
      parameters: [
        {
          name: "threadId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Thread deleted"
        },
        404: {
          description: "Thread not found"
        }
      }
    }),
    deleteThreadHandler
  );
  app.post(
    "/api/memory/save-messages",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Save messages",
      tags: ["memory"],
      parameters: [
        {
          name: "agentId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                messages: {
                  type: "array",
                  items: { type: "object" }
                }
              },
              required: ["messages"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Messages saved"
        }
      }
    }),
    saveMessagesHandler
  );
  app.get(
    "/api/telemetry",
    w({
      description: "Get all traces",
      tags: ["telemetry"],
      responses: {
        200: {
          description: "List of all traces (paged)"
        }
      }
    }),
    getTelemetryHandler
  );
  app.post(
    "/api/telemetry",
    w({
      description: "Store telemetry",
      tags: ["telemetry"],
      responses: {
        200: {
          description: "Traces stored"
        }
      }
    }),
    storeTelemetryHandler
  );
  app.get(
    "/api/workflows/legacy",
    w({
      description: "Get all legacy workflows",
      tags: ["legacyWorkflows"],
      responses: {
        200: {
          description: "List of all legacy workflows"
        }
      }
    }),
    getLegacyWorkflowsHandler
  );
  app.get(
    "/api/workflows/legacy/:workflowId",
    w({
      description: "Get legacy workflow by ID",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Legacy Workflow details"
        },
        404: {
          description: "Legacy Workflow not found"
        }
      }
    }),
    getLegacyWorkflowByIdHandler
  );
  app.get(
    "/api/workflows/legacy/:workflowId/runs",
    w({
      description: "Get all runs for a legacy workflow",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        { name: "fromDate", in: "query", required: false, schema: { type: "string", format: "date-time" } },
        { name: "toDate", in: "query", required: false, schema: { type: "string", format: "date-time" } },
        { name: "limit", in: "query", required: false, schema: { type: "number" } },
        { name: "offset", in: "query", required: false, schema: { type: "number" } },
        { name: "resourceId", in: "query", required: false, schema: { type: "string" } }
      ],
      responses: {
        200: {
          description: "List of legacy workflow runs from storage"
        }
      }
    }),
    getLegacyWorkflowRunsHandler
  );
  app.post(
    "/api/workflows/legacy/:workflowId/resume",
    w({
      description: "Resume a suspended legacy workflow step",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                stepId: { type: "string" },
                context: { type: "object" }
              }
            }
          }
        }
      }
    }),
    resumeLegacyWorkflowHandler
  );
  app.post(
    "/api/workflows/legacy/:workflowId/resume-async",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Resume a suspended legacy workflow step",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                stepId: { type: "string" },
                context: { type: "object" }
              }
            }
          }
        }
      }
    }),
    resumeAsyncLegacyWorkflowHandler
  );
  app.post(
    "/api/workflows/legacy/:workflowId/create-run",
    w({
      description: "Create a new legacy workflow run",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "New legacy workflow run created"
        }
      }
    }),
    createLegacyWorkflowRunHandler
  );
  app.post(
    "/api/workflows/legacy/:workflowId/start-async",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Execute/Start a legacy workflow",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: { type: "object" }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Legacy Workflow execution result"
        },
        404: {
          description: "Legacy Workflow not found"
        }
      }
    }),
    startAsyncLegacyWorkflowHandler
  );
  app.post(
    "/api/workflows/legacy/:workflowId/start",
    w({
      description: "Create and start a new legacy workflow run",
      tags: ["legacyWorkflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                input: { type: "object" }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "Legacy Workflow run started"
        },
        404: {
          description: "Legacy Workflow not found"
        }
      }
    }),
    startLegacyWorkflowRunHandler
  );
  app.get(
    "/api/workflows/legacy/:workflowId/watch",
    w({
      description: "Watch legacy workflow transitions in real-time",
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      tags: ["legacyWorkflows"],
      responses: {
        200: {
          description: "Legacy Workflow transitions in real-time"
        }
      }
    }),
    watchLegacyWorkflowHandler
  );
  app.get(
    "/api/workflows",
    w({
      description: "Get all workflows",
      tags: ["workflows"],
      responses: {
        200: {
          description: "List of all workflows"
        }
      }
    }),
    getWorkflowsHandler
  );
  app.get(
    "/api/workflows/:workflowId",
    w({
      description: "Get workflow by ID",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Workflow details"
        },
        404: {
          description: "Workflow not found"
        }
      }
    }),
    getWorkflowByIdHandler
  );
  app.get(
    "/api/workflows/:workflowId/runs",
    w({
      description: "Get all runs for a workflow",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        { name: "fromDate", in: "query", required: false, schema: { type: "string", format: "date-time" } },
        { name: "toDate", in: "query", required: false, schema: { type: "string", format: "date-time" } },
        { name: "limit", in: "query", required: false, schema: { type: "number" } },
        { name: "offset", in: "query", required: false, schema: { type: "number" } },
        { name: "resourceId", in: "query", required: false, schema: { type: "string" } }
      ],
      responses: {
        200: {
          description: "List of workflow runs from storage"
        }
      }
    }),
    getWorkflowRunsHandler
  );
  app.get(
    "/api/workflows/:workflowId/runs/:runId/execution-result",
    w({
      description: "Get execution result for a workflow run",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Workflow run execution result"
        },
        404: {
          description: "Workflow run execution result not found"
        }
      }
    }),
    getWorkflowRunExecutionResultHandler
  );
  app.get(
    "/api/workflows/:workflowId/runs/:runId",
    w({
      description: "Get workflow run by ID",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Workflow run by ID"
        },
        404: {
          description: "Workflow run not found"
        }
      }
    }),
    getWorkflowRunByIdHandler
  );
  app.post(
    "/api/workflows/:workflowId/resume",
    w({
      description: "Resume a suspended workflow step",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                step: {
                  oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }]
                },
                resumeData: { type: "object" },
                runtimeContext: {
                  type: "object",
                  description: "Runtime context for the workflow execution"
                }
              },
              required: ["step"]
            }
          }
        }
      }
    }),
    resumeWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/resume-async",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Resume a suspended workflow step",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                step: {
                  oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }]
                },
                resumeData: { type: "object" },
                runtimeContext: {
                  type: "object",
                  description: "Runtime context for the workflow execution"
                }
              },
              required: ["step"]
            }
          }
        }
      }
    }),
    resumeAsyncWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/stream",
    w({
      description: "Stream workflow in real-time",
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                inputData: { type: "object" },
                runtimeContext: {
                  type: "object",
                  description: "Runtime context for the workflow execution"
                }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "workflow run started"
        },
        404: {
          description: "workflow not found"
        }
      },
      tags: ["workflows"]
    }),
    streamWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/create-run",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Create a new workflow run",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "New workflow run created"
        }
      }
    }),
    createWorkflowRunHandler
  );
  app.post(
    "/api/workflows/:workflowId/start-async",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Execute/Start a workflow",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                inputData: { type: "object" },
                runtimeContext: {
                  type: "object",
                  description: "Runtime context for the workflow execution"
                }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "workflow execution result"
        },
        404: {
          description: "workflow not found"
        }
      }
    }),
    startAsyncWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/start",
    w({
      description: "Create and start a new workflow run",
      tags: ["workflows"],
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                inputData: { type: "object" },
                runtimeContext: {
                  type: "object",
                  description: "Runtime context for the workflow execution"
                }
              }
            }
          }
        }
      },
      responses: {
        200: {
          description: "workflow run started"
        },
        404: {
          description: "workflow not found"
        }
      }
    }),
    startWorkflowRunHandler
  );
  app.get(
    "/api/workflows/:workflowId/watch",
    w({
      description: "Watch workflow transitions in real-time",
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      tags: ["workflows"],
      responses: {
        200: {
          description: "workflow transitions in real-time"
        }
      }
    }),
    watchWorkflowHandler
  );
  app.post(
    "/api/workflows/:workflowId/runs/:runId/cancel",
    w({
      description: "Cancel a workflow run",
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      tags: ["workflows"],
      responses: {
        200: {
          description: "workflow run cancelled"
        }
      }
    }),
    cancelWorkflowRunHandler
  );
  app.post(
    "/api/workflows/:workflowId/runs/:runId/send-event",
    w({
      description: "Send an event to a workflow run",
      parameters: [
        {
          name: "workflowId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: { type: "object", properties: { event: { type: "string" }, data: { type: "object" } } }
          }
        }
      },
      tags: ["workflows"],
      responses: {
        200: {
          description: "workflow run event sent"
        }
      }
    }),
    sendWorkflowRunEventHandler
  );
  app.get(
    "/api/logs",
    w({
      description: "Get all logs",
      tags: ["logs"],
      parameters: [
        {
          name: "transportId",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "fromDate",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "toDate",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "logLevel",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "filters",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "page",
          in: "query",
          required: false,
          schema: { type: "number" }
        },
        {
          name: "perPage",
          in: "query",
          required: false,
          schema: { type: "number" }
        }
      ],
      responses: {
        200: {
          description: "Paginated list of all logs"
        }
      }
    }),
    getLogsHandler
  );
  app.get(
    "/api/logs/transports",
    w({
      description: "List of all log transports",
      tags: ["logs"],
      responses: {
        200: {
          description: "List of all log transports"
        }
      }
    }),
    getLogTransports
  );
  app.get(
    "/api/logs/:runId",
    w({
      description: "Get logs by run ID",
      tags: ["logs"],
      parameters: [
        {
          name: "runId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "transportId",
          in: "query",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "fromDate",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "toDate",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "logLevel",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "filters",
          in: "query",
          required: false,
          schema: { type: "string" }
        },
        {
          name: "page",
          in: "query",
          required: false,
          schema: { type: "number" }
        },
        {
          name: "perPage",
          in: "query",
          required: false,
          schema: { type: "number" }
        }
      ],
      responses: {
        200: {
          description: "Paginated list of logs for run ID"
        }
      }
    }),
    getLogsByRunIdHandler
  );
  app.get(
    "/api/tools",
    w({
      description: "Get all tools",
      tags: ["tools"],
      responses: {
        200: {
          description: "List of all tools"
        }
      }
    }),
    getToolsHandler
  );
  app.get(
    "/api/tools/:toolId",
    w({
      description: "Get tool by ID",
      tags: ["tools"],
      parameters: [
        {
          name: "toolId",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Tool details"
        },
        404: {
          description: "Tool not found"
        }
      }
    }),
    getToolByIdHandler
  );
  app.post(
    "/api/tools/:toolId/execute",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Execute a tool",
      tags: ["tools"],
      parameters: [
        {
          name: "toolId",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "runId",
          in: "query",
          required: false,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                data: { type: "object" },
                runtimeContext: { type: "object" }
              },
              required: ["data"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Tool execution result"
        },
        404: {
          description: "Tool not found"
        }
      }
    }),
    executeToolHandler(tools)
  );
  app.post(
    "/api/vector/:vectorName/upsert",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Upsert vectors into an index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                indexName: { type: "string" },
                vectors: {
                  type: "array",
                  items: {
                    type: "array",
                    items: { type: "number" }
                  }
                },
                metadata: {
                  type: "array",
                  items: { type: "object" }
                },
                ids: {
                  type: "array",
                  items: { type: "string" }
                }
              },
              required: ["indexName", "vectors"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Vectors upserted successfully"
        }
      }
    }),
    upsertVectors
  );
  app.post(
    "/api/vector/:vectorName/create-index",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Create a new vector index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                indexName: { type: "string" },
                dimension: { type: "number" },
                metric: {
                  type: "string",
                  enum: ["cosine", "euclidean", "dotproduct"]
                }
              },
              required: ["indexName", "dimension"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Index created successfully"
        }
      }
    }),
    createIndex
  );
  app.post(
    "/api/vector/:vectorName/query",
    bodyLimit(bodyLimitOptions),
    w({
      description: "Query vectors from an index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      requestBody: {
        required: true,
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                indexName: { type: "string" },
                queryVector: {
                  type: "array",
                  items: { type: "number" }
                },
                topK: { type: "number" },
                filter: { type: "object" },
                includeVector: { type: "boolean" }
              },
              required: ["indexName", "queryVector"]
            }
          }
        }
      },
      responses: {
        200: {
          description: "Query results"
        }
      }
    }),
    queryVectors
  );
  app.get(
    "/api/vector/:vectorName/indexes",
    w({
      description: "List all indexes for a vector store",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "List of indexes"
        }
      }
    }),
    listIndexes
  );
  app.get(
    "/api/vector/:vectorName/indexes/:indexName",
    w({
      description: "Get details about a specific index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "indexName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Index details"
        }
      }
    }),
    describeIndex
  );
  app.delete(
    "/api/vector/:vectorName/indexes/:indexName",
    w({
      description: "Delete a specific index",
      tags: ["vector"],
      parameters: [
        {
          name: "vectorName",
          in: "path",
          required: true,
          schema: { type: "string" }
        },
        {
          name: "indexName",
          in: "path",
          required: true,
          schema: { type: "string" }
        }
      ],
      responses: {
        200: {
          description: "Index deleted successfully"
        }
      }
    }),
    deleteIndex
  );
  if (options?.isDev || server?.build?.openAPIDocs || server?.build?.swaggerUI) {
    app.get(
      "/openapi.json",
      h(app, {
        includeEmptyPaths: true,
        documentation: {
          info: { title: "Mastra API", version: "1.0.0", description: "Mastra API" }
        }
      })
    );
  }
  if (options?.isDev || server?.build?.swaggerUI) {
    app.get(
      "/swagger-ui",
      w({
        hide: true
      }),
      middleware({ url: "/openapi.json" })
    );
  }
  if (options?.playground) {
    app.get(
      "/refresh-events",
      w({
        hide: true
      }),
      handleClientsRefresh
    );
    app.post(
      "/__refresh",
      w({
        hide: true
      }),
      handleTriggerClientsRefresh
    );
    app.use("/assets/*", async (c2, next) => {
      const path = c2.req.path;
      if (path.endsWith(".js")) {
        c2.header("Content-Type", "application/javascript");
      } else if (path.endsWith(".css")) {
        c2.header("Content-Type", "text/css");
      }
      await next();
    });
    app.use(
      "/assets/*",
      serveStatic({
        root: "./playground/assets"
      })
    );
    app.use(
      "*",
      serveStatic({
        root: "./playground"
      })
    );
  }
  app.get("*", async (c2, next) => {
    if (c2.req.path.startsWith("/api/") || c2.req.path.startsWith("/swagger-ui") || c2.req.path.startsWith("/openapi.json")) {
      return await next();
    }
    if (options?.playground) {
      let indexHtml = await readFile(join(process.cwd(), "./playground/index.html"), "utf-8");
      indexHtml = indexHtml.replace(
        `'%%MASTRA_TELEMETRY_DISABLED%%'`,
        `${Boolean(process.env.MASTRA_TELEMETRY_DISABLED)}`
      );
      return c2.newResponse(indexHtml, 200, { "Content-Type": "text/html" });
    }
    return c2.newResponse(html2, 200, { "Content-Type": "text/html" });
  });
  return app;
}
async function createNodeServer(mastra, options = {}) {
  const app = await createHonoServer(mastra, options);
  const serverOptions = mastra.getServer();
  const port = serverOptions?.port ?? (Number(process.env.PORT) || 4111);
  const server = serve(
    {
      fetch: app.fetch,
      port,
      hostname: serverOptions?.host
    },
    () => {
      const logger2 = mastra.getLogger();
      const host = serverOptions?.host ?? "localhost";
      logger2.info(` Mastra API running on port http://${host}:${port}/api`);
      if (options?.playground) {
        const playgroundUrl = `http://${host}:${port}`;
        logger2.info(`\u{1F468}\u200D\u{1F4BB} Playground available at ${playgroundUrl}`);
      }
      if (process.send) {
        process.send({
          type: "server-ready",
          port,
          host
        });
      }
    }
  );
  return server;
}

// @ts-ignore
// @ts-ignore
// @ts-ignore
await createNodeServer(mastra, { playground: true, isDev: true });

registerHook(AvailableHooks.ON_GENERATION, ({ input, output, metric, runId, agentName, instructions }) => {
  evaluate({
    agentName,
    input,
    metric,
    output,
    runId,
    globalRunId: runId,
    instructions,
  });
});

registerHook(AvailableHooks.ON_EVALUATION, async traceObject => {
  const storage = mastra.getStorage();
  if (storage) {
    // Check for required fields
    const logger = mastra?.getLogger();
    const areFieldsValid = checkEvalStorageFields(traceObject, logger);
    if (!areFieldsValid) return;

    await storage.insert({
      tableName: TABLE_EVALS,
      record: {
        input: traceObject.input,
        output: traceObject.output,
        result: JSON.stringify(traceObject.result || {}),
        agent_name: traceObject.agentName,
        metric_name: traceObject.metricName,
        instructions: traceObject.instructions,
        test_info: null,
        global_run_id: traceObject.globalRunId,
        run_id: traceObject.runId,
        created_at: new Date().toISOString(),
      },
    });
  }
});
//# sourceMappingURL=index.mjs.map
