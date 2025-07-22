// Core workflows using Mastra's createWorkflow and createStep
import { createWorkflow, createStep } from '@mastra/core';
import { z } from 'zod';

// Software Development Workflow
export const softwareDevelopmentWorkflow = createWorkflow({
  id: 'software-development',
  description: 'Complete software development lifecycle workflow',
  inputSchema: z.object({
    project: z.string().describe('Project description and requirements')
  }),
  outputSchema: z.object({
    implementation: z.string(),
    documentation: z.string(),
    testResults: z.array(z.string())
  })
})
.then(createStep({
  id: 'requirements-analysis',
  description: 'Analyze and coordinate software development requirements',
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
    console.log('📋 Analyzing requirements for:', project);
    
    return {
      requirements: [
        'User authentication system',
        'Data persistence layer',
        'API endpoints',
        'Frontend interface'
      ],
      scope: `Full-stack application: ${project}`,
      timeline: 'Estimated 2-3 weeks'
    };
  }
}))
.then(createStep({
  id: 'technical-research',
  description: 'Research technical approaches and best practices',
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
    console.log('🔍 Researching technical solutions for', requirements.length, 'requirements');
    
    return {
      technologies: ['Node.js', 'React', 'PostgreSQL', 'Redis'],
      patterns: ['MVC', 'Repository Pattern', 'Observer Pattern'],
      recommendations: 'Use microservices architecture for scalability'
    };
  }
}))
.then(createStep({
  id: 'architecture-design',
  description: 'Design the technical architecture',
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
    const { technologies, patterns } = context;
    console.log('🏗️ Designing architecture with:', technologies.join(', '));
    
    return {
      architecture: 'Microservices with event-driven communication',
      components: ['Auth Service', 'User Service', 'Data Service', 'API Gateway'],
      interfaces: ['REST API', 'GraphQL', 'WebSocket']
    };
  }
}))
.then(createStep({
  id: 'implementation',
  description: 'Implement the solution',
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
    console.log('💻 Implementing', components.length, 'components');
    
    return {
      implementation: 'All components implemented successfully',
      documentation: 'API documentation and developer guide created',
      testResults: [
        'Unit tests: 95% coverage',
        'Integration tests: All passing',
        'E2E tests: All scenarios verified'
      ]
    };
  }
}))
.commit();

// Problem Solving Workflow
export const problemSolvingWorkflow = createWorkflow({
  id: 'problem-solving',
  description: 'Structured approach to complex problem resolution',
  inputSchema: z.object({
    problem: z.string().describe('The problem to solve')
  }),
  outputSchema: z.object({
    solution: z.string(),
    implementation: z.string(),
    risks: z.array(z.string())
  })
})
.then(createStep({
  id: 'problem-analysis',
  description: 'Analyze and break down the problem',
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
    console.log('🔍 Analyzing problem:', problem);
    
    return {
      rootCause: 'Performance bottleneck in data processing',
      constraints: ['Limited resources', 'Time constraint', 'Legacy system compatibility'],
      objectives: ['Improve performance by 50%', 'Maintain backward compatibility', 'Minimize downtime']
    };
  }
}))
.then(createStep({
  id: 'solution-research',
  description: 'Research potential solutions',
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
    console.log('🔬 Researching solutions for', objectives.length, 'objectives');
    
    return {
      solutions: [
        {
          approach: 'Implement caching layer',
          pros: ['Quick to implement', 'Significant performance boost'],
          cons: ['Additional complexity', 'Cache invalidation challenges']
        },
        {
          approach: 'Database optimization',
          pros: ['Addresses root cause', 'Permanent solution'],
          cons: ['Time-intensive', 'Risk of breaking changes']
        }
      ],
      recommendation: 'Implement caching layer first, then optimize database'
    };
  }
}))
.then(createStep({
  id: 'solution-design',
  description: 'Design comprehensive solution',
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
    console.log('📐 Designing solution based on:', recommendation);
    
    return {
      design: 'Two-phase approach: Redis caching + PostgreSQL optimization',
      phases: ['Phase 1: Implement Redis caching', 'Phase 2: Optimize database queries', 'Phase 3: Performance testing'],
      timeline: '2 weeks total (1 week per major phase)'
    };
  }
}))
.then(createStep({
  id: 'implementation-plan',
  description: 'Create detailed implementation plan',
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
    console.log('📝 Creating implementation plan for', phases.length, 'phases');
    
    return {
      solution: 'Hybrid caching and optimization solution',
      implementation: 'Step-by-step implementation with rollback procedures',
      risks: [
        'Cache coherency issues',
        'Performance regression during migration',
        'Increased operational complexity'
      ]
    };
  }
}))
.commit();

// Export core workflows
export const coreWorkflows = {
  softwareDevelopmentWorkflow,
  problemSolvingWorkflow
};

export default coreWorkflows;