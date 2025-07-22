// Complex Multi-Agent Workflows Index
import { startupLaunchWorkflow } from './startup-launch-workflow.js';
import { incidentResponseWorkflow } from './incident-response-workflow.js';
import { aiProductDevelopmentWorkflow, feedbackLoop as feedbackLoopWorkflow } from './ai-product-development-workflow.js';
import { enterpriseMigrationWorkflow } from './enterprise-migration-workflow.js';
import { productPivotWorkflow } from './product-pivot-workflow.js';
import { securityBreachResponseWorkflow } from './security-breach-response-workflow.js';

// Export all complex workflows
export const complexWorkflows = {
  // Startup and Product Development
  startupLaunch: startupLaunchWorkflow,
  aiProductDevelopment: aiProductDevelopmentWorkflow,
  aiProductFeedbackLoop: feedbackLoopWorkflow,
  productPivot: productPivotWorkflow,
  
  // Crisis and Incident Management
  incidentResponse: incidentResponseWorkflow,
  securityBreachResponse: securityBreachResponseWorkflow,
  
  // Enterprise Operations
  enterpriseMigration: enterpriseMigrationWorkflow
};

// Workflow Categories for Easy Discovery
export const workflowCategories = {
  productDevelopment: [
    'startupLaunch',
    'aiProductDevelopment',
    'aiProductFeedbackLoop',
    'productPivot'
  ],
  
  crisisManagement: [
    'incidentResponse',
    'securityBreachResponse'
  ],
  
  enterpriseOperations: [
    'enterpriseMigration'
  ]
};

// Workflow Metadata for UI Display
export const workflowMetadata = {
  startupLaunch: {
    name: 'Startup Launch Workflow',
    description: 'Complete startup launch from idea to market with 6-agent coordination',
    agents: 6,
    estimatedDuration: '3-6 months',
    complexity: 'High',
    category: 'Product Development'
  },
  
  incidentResponse: {
    name: 'Incident Response Workflow',
    description: 'Rapid incident response with parallel investigation and mitigation',
    agents: 6,
    estimatedDuration: '1-24 hours',
    complexity: 'Critical',
    category: 'Crisis Management'
  },
  
  aiProductDevelopment: {
    name: 'AI Product Development Workflow',
    description: 'End-to-end AI/ML product development with ethics and compliance',
    agents: 6,
    estimatedDuration: '4-8 weeks',
    complexity: 'Very High',
    category: 'Product Development'
  },
  
  enterpriseMigration: {
    name: 'Enterprise Migration Workflow',
    description: 'Large-scale system migration with phased rollout and validation',
    agents: 6,
    estimatedDuration: '30-90 days',
    complexity: 'Enterprise',
    category: 'Enterprise Operations'
  },
  
  productPivot: {
    name: 'Product Pivot Workflow',
    description: 'Strategic product transformation with market and technical analysis',
    agents: 6,
    estimatedDuration: '2-4 weeks',
    complexity: 'High',
    category: 'Product Development'
  },
  
  securityBreachResponse: {
    name: 'Security Breach Response Workflow',
    description: 'Critical security incident response with compliance and notification',
    agents: 6,
    estimatedDuration: '1-72 hours',
    complexity: 'Critical',
    category: 'Crisis Management'
  }
};

// Helper function to get workflows by complexity
export function getWorkflowsByComplexity(complexity) {
  return Object.entries(workflowMetadata)
    .filter(([_, metadata]) => metadata.complexity === complexity)
    .map(([id, _]) => id);
}

// Helper function to get workflows by category
export function getWorkflowsByCategory(category) {
  return workflowCategories[category] || [];
}

// Helper function to get workflow info
export function getWorkflowInfo(workflowId) {
  return {
    workflow: complexWorkflows[workflowId],
    metadata: workflowMetadata[workflowId]
  };
}