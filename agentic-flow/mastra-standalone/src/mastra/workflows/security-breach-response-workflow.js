import { createWorkflow, createStep } from '@mastra/core';

// Security Breach Response Workflow - High-Stakes Crisis Management
// Coordinates all 6 agents for immediate response, investigation, and recovery

// Step 1: Initial Detection and Alert
const detectBreachStep = createStep({
  id: 'detect-breach',
  name: 'Detect Security Breach',
  description: 'Initial breach detection and severity assessment',
  execute: async ({ context }) => {
    const { breachIndicators, timestamp, source } = context;
    
    // Immediate alert to all agents
    const alertData = {
      severity: 'CRITICAL',
      timestamp,
      source,
      indicators: breachIndicators,
      status: 'ACTIVE_BREACH'
    };
    
    return {
      alertData,
      incidentId: `INC-${Date.now()}`,
      initialAssessment: {
        type: breachIndicators.type || 'UNKNOWN',
        scope: breachIndicators.scope || 'INVESTIGATING',
        impact: breachIndicators.impact || 'ASSESSING'
      }
    };
  }
});

// Step 2: Crisis Team Assembly
const assembleCrisisTeamStep = createStep({
  id: 'assemble-crisis-team',
  name: 'Assemble Crisis Response Team',
  description: 'Activate all agents in crisis mode',
  execute: async ({ context, prevResult }) => {
    const { alertData, incidentId } = prevResult;
    
    // Activate all 6 agents with specific crisis roles
    const crisisTeam = {
      agentCoordinator: {
        agent: 'Agent Coordinator',
        role: 'Crisis Commander',
        responsibilities: ['Overall coordination', 'Decision making', 'Resource allocation'],
        status: 'ACTIVATED'
      },
      researchAnalyst: {
        agent: 'Research Analyst',
        role: 'Threat Intelligence Lead',
        responsibilities: ['Threat analysis', 'Attack vector identification', 'Intelligence gathering'],
        status: 'ACTIVATED'
      },
      codeArchitect: {
        agent: 'Code Architect',
        role: 'Technical Response Lead',
        responsibilities: ['System analysis', 'Vulnerability assessment', 'Technical remediation'],
        status: 'ACTIVATED'
      },
      testingExpert: {
        agent: 'Testing Expert',
        role: 'Forensics Specialist',
        responsibilities: ['Evidence collection', 'Impact analysis', 'System validation'],
        status: 'ACTIVATED'
      },
      docWriter: {
        agent: 'Documentation Writer',
        role: 'Communications Lead',
        responsibilities: ['Stakeholder updates', 'Compliance reporting', 'Public relations'],
        status: 'ACTIVATED'
      },
      reviewSpecialist: {
        agent: 'Review Specialist',
        role: 'Compliance Officer',
        responsibilities: ['Regulatory compliance', 'Legal coordination', 'Audit trail'],
        status: 'ACTIVATED'
      }
    };
    
    return {
      ...prevResult,
      crisisTeam,
      activationTime: new Date().toISOString()
    };
  }
});

// Step 3: Parallel Track - Technical Investigation
const technicalInvestigationStep = createStep({
  id: 'technical-investigation',
  name: 'Technical Investigation Track',
  description: 'Parallel technical response and investigation',
  execute: async ({ context, prevResult }) => {
    const { incidentId, crisisTeam } = prevResult;
    
    // Research Analyst: Threat Analysis
    const threatAnalysis = {
      attackVector: 'ANALYZING',
      threatActor: 'IDENTIFYING',
      methodology: 'INVESTIGATING',
      indicators: []
    };
    
    // Code Architect: System Analysis
    const systemAnalysis = {
      affectedSystems: [],
      vulnerabilities: [],
      exploitMethods: [],
      dataExposure: 'ASSESSING'
    };
    
    // Testing Expert: Forensics
    const forensics = {
      evidenceCollected: [],
      timeline: [],
      affectedData: [],
      intrusionPath: 'TRACING'
    };
    
    return {
      ...prevResult,
      technicalFindings: {
        threatAnalysis,
        systemAnalysis,
        forensics,
        status: 'IN_PROGRESS'
      }
    };
  }
});

// Step 4: Parallel Track - Communication Response
const communicationResponseStep = createStep({
  id: 'communication-response',
  name: 'Communication Response Track',
  description: 'Parallel stakeholder and regulatory communication',
  execute: async ({ context, prevResult }) => {
    const { incidentId, alertData } = prevResult;
    
    // Documentation Writer: Stakeholder Communications
    const stakeholderComms = {
      internalNotifications: {
        executives: 'DRAFTED',
        employees: 'PENDING',
        boardMembers: 'SCHEDULED'
      },
      externalNotifications: {
        customers: 'PREPARING',
        partners: 'QUEUED',
        publicStatement: 'DRAFTING'
      }
    };
    
    // Review Specialist: Compliance Reporting
    const complianceReporting = {
      regulatoryBodies: {
        gdpr: alertData.severity === 'CRITICAL' ? 'REQUIRED' : 'MONITORING',
        hipaa: 'ASSESSING',
        pci: 'EVALUATING',
        sox: 'REVIEWING'
      },
      notificationDeadlines: {
        gdpr: '72_HOURS',
        statePrivacyLaws: '24_HOURS',
        contractualObligations: 'REVIEWING'
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
        status: 'EXECUTING'
      }
    };
  }
});

// Step 5: Containment Actions
const containmentStep = createStep({
  id: 'containment',
  name: 'Execute Containment Measures',
  description: 'Implement immediate containment to prevent spread',
  execute: async ({ context, prevResult }) => {
    const { technicalFindings } = prevResult;
    
    const containmentActions = {
      immediate: {
        networkIsolation: 'EXECUTING',
        accountSuspension: 'IN_PROGRESS',
        serviceShutdown: 'EVALUATING',
        accessRevocation: 'IMPLEMENTING'
      },
      shortTerm: {
        patchDeployment: 'PREPARING',
        configurationChanges: 'PLANNING',
        monitoringEnhancement: 'DEPLOYING',
        backupValidation: 'VERIFYING'
      },
      validation: {
        containmentEffectiveness: 'MONITORING',
        lateralMovementCheck: 'SCANNING',
        persistenceMechanisms: 'INVESTIGATING'
      }
    };
    
    return {
      ...prevResult,
      containmentActions,
      containmentStartTime: new Date().toISOString()
    };
  }
});

// Step 6: Eradication Process
const eradicationStep = createStep({
  id: 'eradication',
  name: 'Eradicate Threat',
  description: 'Remove all traces of the security breach',
  execute: async ({ context, prevResult }) => {
    const { technicalFindings, containmentActions } = prevResult;
    
    const eradicationPlan = {
      malwareRemoval: {
        scanResults: 'EXECUTING',
        cleanupActions: 'QUEUED',
        verificationScans: 'SCHEDULED'
      },
      vulnerabilityPatching: {
        criticalPatches: 'DEPLOYING',
        systemUpdates: 'TESTING',
        configurationHardening: 'IMPLEMENTING'
      },
      accessRemediation: {
        compromisedAccounts: 'RESETTING',
        privilegeReview: 'CONDUCTING',
        mfaEnforcement: 'ENABLING'
      },
      dataIntegrity: {
        corruptionCheck: 'SCANNING',
        backupRestoration: 'EVALUATING',
        integrityValidation: 'PENDING'
      }
    };
    
    return {
      ...prevResult,
      eradicationPlan,
      eradicationStatus: 'IN_PROGRESS'
    };
  }
});

// Step 7: Recovery Operations
const recoveryStep = createStep({
  id: 'recovery',
  name: 'System Recovery',
  description: 'Restore normal operations with enhanced security',
  execute: async ({ context, prevResult }) => {
    const { eradicationPlan } = prevResult;
    
    const recoveryOperations = {
      systemRestoration: {
        serviceReactivation: 'PHASED',
        dataRestoration: 'VALIDATING',
        functionalityTesting: 'EXECUTING',
        performanceBaseline: 'MONITORING'
      },
      securityEnhancements: {
        monitoringUpgrade: 'DEPLOYED',
        detectionRules: 'ENHANCED',
        responseAutomation: 'CONFIGURED',
        accessControls: 'STRENGTHENED'
      },
      businessContinuity: {
        operationalStatus: 'RESTORING',
        customerServices: 'PHASED_ACTIVATION',
        partnerIntegrations: 'TESTING',
        revenueImpact: 'ASSESSING'
      }
    };
    
    return {
      ...prevResult,
      recoveryOperations,
      recoveryStartTime: new Date().toISOString()
    };
  }
});

// Step 8: Customer Notification
const customerNotificationStep = createStep({
  id: 'customer-notification',
  name: 'Customer Notification Process',
  description: 'Execute customer notification with regulatory compliance',
  execute: async ({ context, prevResult }) => {
    const { communicationStatus, technicalFindings } = prevResult;
    
    const notificationPlan = {
      affectedCustomers: {
        identification: 'COMPLETED',
        segmentation: 'BY_IMPACT_LEVEL',
        totalCount: 'CALCULATING',
        dataTypes: 'CATALOGING'
      },
      notificationChannels: {
        email: {
          template: 'APPROVED',
          scheduling: 'BATCHED',
          personalization: 'CONFIGURED'
        },
        portal: {
          announcement: 'POSTED',
          faq: 'PUBLISHED',
          supportResources: 'AVAILABLE'
        },
        directContact: {
          highValueAccounts: 'CALLING',
          enterpriseClients: 'SCHEDULED',
          regulatoryRequired: 'PRIORITIZED'
        }
      },
      supportPreparation: {
        callCenterBriefing: 'COMPLETED',
        scriptApproval: 'FINALIZED',
        resourceAllocation: 'SCALED_UP',
        escalationPaths: 'DEFINED'
      },
      legalCompliance: {
        notificationContent: 'LEGALLY_REVIEWED',
        timingCompliance: 'VERIFIED',
        documentationTrail: 'MAINTAINED',
        regulatoryFiling: 'SUBMITTED'
      }
    };
    
    return {
      ...prevResult,
      notificationPlan,
      notificationExecutionTime: new Date().toISOString()
    };
  }
});

// Step 9: Lessons Learned
const lessonsLearnedStep = createStep({
  id: 'lessons-learned',
  name: 'Post-Incident Analysis',
  description: 'Comprehensive review and improvement planning',
  execute: async ({ context, prevResult }) => {
    const { incidentId, technicalFindings, containmentActions, recoveryOperations } = prevResult;
    
    const postIncidentAnalysis = {
      incidentReview: {
        timeline: {
          detectionDelay: 'ANALYZING',
          responseTime: 'MEASURING',
          containmentDuration: 'CALCULATING',
          totalDowntime: 'COMPUTING'
        },
        effectiveness: {
          detectionCapabilities: 'EVALUATING',
          responseProcesses: 'ASSESSING',
          communicationFlow: 'REVIEWING',
          technicalMeasures: 'ANALYZING'
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
          financialImpact: 'CALCULATING',
          reputationalImpact: 'ASSESSING',
          operationalImpact: 'MEASURED',
          customerImpact: 'QUANTIFIED'
        },
        performanceMetrics: {
          mttr: 'CALCULATED',
          detectionAccuracy: 'MEASURED',
          containmentSpeed: 'TRACKED',
          recoveryEfficiency: 'EVALUATED'
        }
      }
    };
    
    return {
      ...prevResult,
      postIncidentAnalysis,
      incidentClosed: false,
      followUpActions: 'SCHEDULED'
    };
  }
});

// Step 10: Final Coordination and Closure
const finalCoordinationStep = createStep({
  id: 'final-coordination',
  name: 'Final Coordination and Incident Closure',
  description: 'Ensure all actions complete and incident properly closed',
  execute: async ({ context, prevResult }) => {
    const { incidentId, crisisTeam, postIncidentAnalysis } = prevResult;
    
    const closureChecklist = {
      technicalClosure: {
        allSystemsOperational: 'VERIFIED',
        securityPostureEnhanced: 'CONFIRMED',
        monitoringActive: 'VALIDATED',
        backupsVerified: 'TESTED'
      },
      communicationClosure: {
        stakeholdersNotified: 'COMPLETED',
        regulatoryCompliance: 'FILED',
        publicRelations: 'MANAGED',
        customerSupport: 'ONGOING'
      },
      documentationClosure: {
        incidentReport: 'FINALIZED',
        technicalPostmortem: 'DOCUMENTED',
        complianceRecords: 'ARCHIVED',
        lessonsLearned: 'DISTRIBUTED'
      },
      teamDebriefing: {
        agentPerformance: 'REVIEWED',
        coordinationEffectiveness: 'ASSESSED',
        improvementAreas: 'IDENTIFIED',
        recognitionNeeds: 'NOTED'
      }
    };
    
    return {
      incidentId,
      status: 'CLOSED',
      closureTime: new Date().toISOString(),
      closureChecklist,
      finalMetrics: {
        totalDuration: 'CALCULATED',
        businessImpact: 'QUANTIFIED',
        lessonsImplemented: 'TRACKED',
        residualRisk: 'ASSESSED'
      },
      followUp: {
        thirtyDayReview: 'SCHEDULED',
        quarterlyUpdate: 'PLANNED',
        annualDrillUpdate: 'QUEUED'
      }
    };
  }
});

// Create the Security Breach Response Workflow
export const securityBreachResponseWorkflow = createWorkflow({
  id: 'security-breach-response',
  name: 'Security Breach Response Workflow',
  description: 'High-stakes crisis management workflow coordinating all agents for security incident response',
  
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
    retries: 0, // No retries in crisis mode - must succeed
    timeout: 86400000, // 24 hours maximum
    parallel: true,
    errorHandling: 'ESCALATE',
    
    notifications: {
      onStart: ['security-team', 'executives', 'legal'],
      onError: ['ciso', 'ceo', 'board'],
      onComplete: ['all-stakeholders']
    },
    
    compliance: {
      frameworks: ['GDPR', 'CCPA', 'HIPAA', 'PCI-DSS', 'SOX'],
      auditLog: true,
      encryption: true,
      dataRetention: '7_YEARS'
    },
    
    escalation: {
      levels: [
        { threshold: '5_MINUTES', notify: ['security-team'] },
        { threshold: '15_MINUTES', notify: ['ciso', 'cto'] },
        { threshold: '30_MINUTES', notify: ['ceo', 'legal'] },
        { threshold: '1_HOUR', notify: ['board', 'external-counsel'] }
      ]
    }
  }
});

// Export crisis mode triggers
export const crisisTriggers = {
  dataBreachDetected: (indicators) => ({
    workflow: 'security-breach-response',
    priority: 'CRITICAL',
    context: { breachIndicators: indicators, timestamp: new Date().toISOString() }
  }),
  
  ransomwareDetected: (details) => ({
    workflow: 'security-breach-response',
    priority: 'CRITICAL',
    context: { 
      breachIndicators: { type: 'RANSOMWARE', ...details },
      timestamp: new Date().toISOString()
    }
  }),
  
  unauthorizedAccess: (accessDetails) => ({
    workflow: 'security-breach-response',
    priority: 'HIGH',
    context: {
      breachIndicators: { type: 'UNAUTHORIZED_ACCESS', ...accessDetails },
      timestamp: new Date().toISOString()
    }
  }),
  
  dataExfiltration: (exfilDetails) => ({
    workflow: 'security-breach-response',
    priority: 'CRITICAL',
    context: {
      breachIndicators: { type: 'DATA_EXFILTRATION', ...exfilDetails },
      timestamp: new Date().toISOString()
    }
  })
};

// Export compliance templates
export const complianceTemplates = {
  gdprNotification: {
    deadline: '72_HOURS',
    requiredInfo: ['nature_of_breach', 'data_categories', 'affected_individuals', 'consequences', 'measures_taken'],
    authorities: ['supervisory_authority', 'data_protection_officer']
  },
  
  ccpaNotification: {
    deadline: 'WITHOUT_UNREASONABLE_DELAY',
    requiredInfo: ['breach_date', 'data_types', 'contact_info', 'remediation_steps'],
    format: 'CLEAR_AND_CONSPICUOUS'
  },
  
  hipaaNotification: {
    deadline: '60_DAYS',
    requiredInfo: ['phi_involved', 'breach_circumstances', 'mitigation_steps', 'prevention_measures'],
    authorities: ['hhs_secretary', 'affected_individuals', 'media_if_500_plus']
  }
};

export default securityBreachResponseWorkflow;