import { createWorkflow, createStep } from '@mastra/core';
import { z } from 'zod';

/**
 * Critical Incident Response Workflow
 * 
 * Coordinates 6 specialized agents for rapid incident response:
 * 1. Detection Agent - Monitors and validates incidents
 * 2. Diagnosis Agent - Root cause analysis
 * 3. Mitigation Agent - Immediate response actions
 * 4. Recovery Agent - System restoration
 * 5. Communication Agent - Stakeholder updates
 * 6. PostMortem Agent - Learning and improvement
 */

// Input schema for incident response
const IncidentSchema = z.object({
  severity: z.enum(['P0', 'P1', 'P2', 'P3']),
  type: z.enum(['outage', 'security', 'performance', 'data_loss', 'unknown']),
  initialAlert: z.object({
    source: z.string(),
    timestamp: z.string(),
    description: z.string(),
    affectedSystems: z.array(z.string()),
    metrics: z.record(z.any()).optional()
  }),
  escalationThreshold: z.number().default(300), // seconds before escalation
  autoMitigate: z.boolean().default(true)
});

// Detection step - validates and enriches incident data
const detectionStep = createStep({
  id: 'incident-detection',
  description: 'Validate incident and gather initial telemetry',
  execute: async ({ context, agents }) => {
    const { detectionAgent } = agents;
    const { initialAlert, severity } = context.input;
    
    console.log(`🚨 INCIDENT DETECTED: ${severity} - ${initialAlert.description}`);
    
    // Parallel validation and enrichment
    const [validation, telemetry, impactAnalysis] = await Promise.all([
      detectionAgent.execute({
        task: 'validate_incident',
        data: initialAlert,
        priority: severity === 'P0' ? 'critical' : 'high'
      }),
      detectionAgent.execute({
        task: 'gather_telemetry',
        systems: initialAlert.affectedSystems,
        timeRange: { start: '-10m', end: 'now' }
      }),
      detectionAgent.execute({
        task: 'assess_impact',
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
      startTime: new Date().toISOString()
    };
  }
});

// Parallel diagnosis tracks
const diagnosisStep = createStep({
  id: 'parallel-diagnosis',
  description: 'Run parallel diagnosis tracks for rapid root cause analysis',
  execute: async ({ context, agents }) => {
    const { diagnosisAgent, detectionAgent } = agents;
    const { telemetry, impact } = context.previousSteps['incident-detection'];
    
    console.log('🔍 Starting parallel diagnosis tracks...');
    
    // Launch parallel investigation tracks
    const diagnosisTracks = await Promise.allSettled([
      // Track 1: System logs analysis
      diagnosisAgent.execute({
        task: 'analyze_logs',
        systems: context.input.initialAlert.affectedSystems,
        patterns: ['error', 'exception', 'timeout', 'crash'],
        timeWindow: '-30m'
      }),
      
      // Track 2: Performance metrics
      diagnosisAgent.execute({
        task: 'analyze_metrics',
        metrics: ['cpu', 'memory', 'disk', 'network', 'latency'],
        anomalyDetection: true,
        baseline: 'last_7d'
      }),
      
      // Track 3: Recent changes
      diagnosisAgent.execute({
        task: 'check_recent_changes',
        scope: ['deployments', 'config_changes', 'infrastructure'],
        timeWindow: '-24h'
      }),
      
      // Track 4: Dependency analysis
      diagnosisAgent.execute({
        task: 'trace_dependencies',
        startingPoints: context.input.initialAlert.affectedSystems,
        depth: 3
      }),
      
      // Track 5: Historical pattern matching
      diagnosisAgent.execute({
        task: 'match_historical_incidents',
        similarity_threshold: 0.7,
        lookback: '90d'
      })
    ]);
    
    // Process results and determine most likely causes
    const causes = [];
    diagnosisTracks.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value.findings) {
        causes.push(...result.value.findings);
      }
    });
    
    // Rank causes by confidence
    const rankedCauses = causes
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 5);
    
    return {
      primaryCause: rankedCauses[0] || { type: 'unknown', confidence: 0 },
      alternativeCauses: rankedCauses.slice(1),
      diagnosisTime: new Date().toISOString(),
      investigationPaths: diagnosisTracks.length
    };
  }
});

// Mitigation decision tree
const mitigationStep = createStep({
  id: 'rapid-mitigation',
  description: 'Execute mitigation based on diagnosis and severity',
  execute: async ({ context, agents }) => {
    const { mitigationAgent, communicationAgent } = agents;
    const { primaryCause } = context.previousSteps['parallel-diagnosis'];
    const { severity, autoMitigate } = context.input;
    
    console.log('🛡️ Initiating mitigation strategies...');
    
    // Decision tree for mitigation
    let mitigationPlan;
    
    if (severity === 'P0') {
      // Critical incident - immediate automated response
      mitigationPlan = await mitigationAgent.execute({
        task: 'emergency_response',
        cause: primaryCause,
        actions: [
          'circuit_breaker_activation',
          'traffic_rerouting',
          'failover_initiation',
          'cache_warming'
        ],
        parallel: true,
        skipApproval: autoMitigate
      });
      
      // Notify on-call immediately
      await communicationAgent.execute({
        task: 'page_oncall',
        severity: 'P0',
        message: `Critical incident: ${primaryCause.description}`,
        escalation: 'immediate'
      });
      
    } else if (severity === 'P1') {
      // High priority - automated with verification
      mitigationPlan = await mitigationAgent.execute({
        task: 'standard_response',
        cause: primaryCause,
        actions: [
          'scale_resources',
          'restart_services',
          'clear_caches',
          'apply_patches'
        ],
        verifyBefore: true
      });
      
    } else {
      // Lower priority - gather options for manual review
      mitigationPlan = await mitigationAgent.execute({
        task: 'propose_solutions',
        cause: primaryCause,
        generateOptions: 3,
        includeRiskAssessment: true
      });
    }
    
    // Execute mitigation with monitoring
    const mitigationResults = await Promise.all(
      mitigationPlan.actions.map(async (action) => {
        const result = await mitigationAgent.execute({
          task: 'execute_action',
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
      startTime: new Date().toISOString()
    };
  }
});

// Recovery orchestration
const recoveryStep = createStep({
  id: 'system-recovery',
  description: 'Orchestrate system recovery and validation',
  execute: async ({ context, agents }) => {
    const { recoveryAgent, detectionAgent } = agents;
    const { executedActions } = context.previousSteps['rapid-mitigation'];
    
    console.log('🔧 Starting recovery operations...');
    
    // Recovery phases
    const recoveryPhases = [
      // Phase 1: Stabilization
      {
        name: 'stabilization',
        tasks: [
          'verify_service_health',
          'check_error_rates',
          'monitor_resource_usage'
        ],
        duration: 60 // seconds
      },
      
      // Phase 2: Gradual restoration
      {
        name: 'restoration',
        tasks: [
          'gradual_traffic_increase',
          'cache_rebuilding',
          'connection_pool_recovery'
        ],
        duration: 180
      },
      
      // Phase 3: Full recovery
      {
        name: 'full_recovery',
        tasks: [
          'restore_full_capacity',
          'verify_all_endpoints',
          'check_data_consistency'
        ],
        duration: 120
      }
    ];
    
    const recoveryResults = [];
    
    for (const phase of recoveryPhases) {
      console.log(`📊 Executing ${phase.name} phase...`);
      
      const phaseResults = await Promise.all(
        phase.tasks.map(task => 
          recoveryAgent.execute({
            task,
            monitoring: {
              interval: 10,
              duration: phase.duration,
              alertOnAnomaly: true
            }
          })
        )
      );
      
      // Validate phase success
      const phaseValidation = await detectionAgent.execute({
        task: 'validate_recovery_phase',
        phase: phase.name,
        results: phaseResults,
        acceptanceCriteria: {
          errorRate: 0.001,
          latencyP99: 200,
          availabilty: 0.999
        }
      });
      
      if (!phaseValidation.passed) {
        // Rollback if phase fails
        await recoveryAgent.execute({
          task: 'rollback_phase',
          phase: phase.name,
          reason: phaseValidation.failures
        });
        break;
      }
      
      recoveryResults.push({
        phase: phase.name,
        status: 'completed',
        metrics: phaseValidation.metrics
      });
    }
    
    return {
      recoveryPhases: recoveryResults,
      systemStatus: recoveryResults.length === recoveryPhases.length ? 'recovered' : 'partial',
      recoveryTime: new Date().toISOString()
    };
  }
});

// Real-time communication
const communicationStep = createStep({
  id: 'stakeholder-communication',
  description: 'Manage real-time communication throughout incident',
  execute: async ({ context, agents }) => {
    const { communicationAgent } = agents;
    const incidentData = context.previousSteps;
    
    console.log('📢 Managing stakeholder communications...');
    
    // Communication matrix based on severity and progress
    const stakeholders = {
      P0: ['cto', 'vp_engineering', 'oncall_team', 'support_leads', 'pr_team'],
      P1: ['engineering_leads', 'oncall_team', 'support_team'],
      P2: ['team_leads', 'oncall_secondary'],
      P3: ['team_members']
    };
    
    const updates = [
      {
        stage: 'initial',
        template: 'incident_detected',
        data: {
          severity: context.input.severity,
          impact: incidentData['incident-detection'].impact,
          startTime: incidentData['incident-detection'].startTime
        }
      },
      {
        stage: 'diagnosis',
        template: 'root_cause_identified',
        data: {
          cause: incidentData['parallel-diagnosis'].primaryCause,
          diagnosisTime: incidentData['parallel-diagnosis'].diagnosisTime
        }
      },
      {
        stage: 'mitigation',
        template: 'mitigation_in_progress',
        data: {
          actions: incidentData['rapid-mitigation'].executedActions,
          estimatedTime: '15-30 minutes'
        }
      },
      {
        stage: 'recovery',
        template: 'system_recovering',
        data: {
          status: incidentData['system-recovery'].systemStatus,
          metrics: incidentData['system-recovery'].recoveryPhases
        }
      }
    ];
    
    // Send updates to appropriate stakeholders
    const communicationResults = await Promise.all(
      updates.map(update => 
        communicationAgent.execute({
          task: 'send_update',
          recipients: stakeholders[context.input.severity],
          template: update.template,
          data: update.data,
          channels: ['slack', 'email', 'sms'],
          priority: context.input.severity === 'P0' ? 'immediate' : 'high'
        })
      )
    );
    
    // Create public status page update
    if (context.input.severity === 'P0' || context.input.severity === 'P1') {
      await communicationAgent.execute({
        task: 'update_status_page',
        status: incidentData['system-recovery'].systemStatus === 'recovered' 
          ? 'operational' 
          : 'partial_outage',
        message: 'We are investigating issues with system performance',
        affectedServices: context.input.initialAlert.affectedSystems
      });
    }
    
    return {
      notificationsSent: communicationResults.length,
      stakeholdersNotified: stakeholders[context.input.severity].length,
      statusPageUpdated: ['P0', 'P1'].includes(context.input.severity)
    };
  }
});

// Post-mortem and learning
const postMortemStep = createStep({
  id: 'post-mortem-analysis',
  description: 'Conduct blameless post-mortem and capture learnings',
  execute: async ({ context, agents }) => {
    const { postMortemAgent } = agents;
    const fullIncidentData = {
      input: context.input,
      ...context.previousSteps
    };
    
    console.log('📝 Conducting post-mortem analysis...');
    
    // Comprehensive post-mortem analysis
    const analysis = await postMortemAgent.execute({
      task: 'generate_postmortem',
      incidentData: fullIncidentData,
      sections: [
        'incident_summary',
        'timeline',
        'root_cause_analysis',
        'impact_assessment',
        'what_went_well',
        'what_went_wrong',
        'action_items',
        'prevention_measures'
      ]
    });
    
    // Extract actionable improvements
    const improvements = await Promise.all([
      postMortemAgent.execute({
        task: 'identify_monitoring_gaps',
        telemetry: fullIncidentData['incident-detection'].telemetry,
        incident: context.input.initialAlert
      }),
      
      postMortemAgent.execute({
        task: 'suggest_automation',
        mitigationSteps: fullIncidentData['rapid-mitigation'].executedActions,
        recoverySteps: fullIncidentData['system-recovery'].recoveryPhases
      }),
      
      postMortemAgent.execute({
        task: 'update_runbooks',
        incident: context.input,
        resolution: fullIncidentData['rapid-mitigation'].mitigationPlan
      })
    ]);
    
    // Calculate incident metrics
    const metrics = {
      timeToDetect: calculateTimeDiff(
        context.input.initialAlert.timestamp,
        fullIncidentData['incident-detection'].startTime
      ),
      timeToMitigate: calculateTimeDiff(
        fullIncidentData['incident-detection'].startTime,
        fullIncidentData['rapid-mitigation'].startTime
      ),
      timeToRecover: calculateTimeDiff(
        fullIncidentData['rapid-mitigation'].startTime,
        fullIncidentData['system-recovery'].recoveryTime
      ),
      totalDowntime: calculateTimeDiff(
        context.input.initialAlert.timestamp,
        fullIncidentData['system-recovery'].recoveryTime
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

// Helper function for time calculations
function calculateTimeDiff(start, end) {
  const diff = new Date(end) - new Date(start);
  return {
    milliseconds: diff,
    seconds: Math.floor(diff / 1000),
    minutes: Math.floor(diff / 60000)
  };
}

// Create the incident response workflow
export const incidentResponseWorkflow = createWorkflow({
  id: 'critical-incident-response',
  name: 'Critical Incident Response Workflow',
  description: 'Multi-agent orchestration for rapid incident response and recovery',
  
  inputSchema: IncidentSchema,
  
  agents: {
    detectionAgent: {
      id: 'detection-specialist',
      capabilities: ['monitoring', 'validation', 'telemetry', 'impact_analysis'],
      priority: 'critical'
    },
    diagnosisAgent: {
      id: 'diagnosis-specialist',
      capabilities: ['log_analysis', 'metric_analysis', 'pattern_matching', 'rca'],
      priority: 'critical'
    },
    mitigationAgent: {
      id: 'mitigation-specialist',
      capabilities: ['emergency_response', 'automation', 'rollback', 'patching'],
      priority: 'critical'
    },
    recoveryAgent: {
      id: 'recovery-specialist',
      capabilities: ['service_restoration', 'validation', 'monitoring', 'rollback'],
      priority: 'high'
    },
    communicationAgent: {
      id: 'communication-specialist',
      capabilities: ['notifications', 'status_updates', 'escalation', 'reporting'],
      priority: 'high'
    },
    postMortemAgent: {
      id: 'postmortem-specialist',
      capabilities: ['analysis', 'documentation', 'improvement', 'learning'],
      priority: 'medium'
    }
  },
  
  steps: [
    detectionStep,
    diagnosisStep,
    mitigationStep,
    recoveryStep,
    communicationStep,
    postMortemStep
  ],
  
  // Workflow-level configurations
  config: {
    timeout: 3600000, // 1 hour max for entire incident
    retryPolicy: {
      maxAttempts: 3,
      backoffMultiplier: 2,
      initialDelay: 1000
    },
    parallelExecution: true,
    realTimeMonitoring: true,
    escalationRules: {
      P0: {
        escalateAfter: 300, // 5 minutes
        notifyLevels: ['director', 'vp', 'cto']
      },
      P1: {
        escalateAfter: 900, // 15 minutes
        notifyLevels: ['manager', 'director']
      }
    }
  },
  
  // Error handling
  onError: async (error, context) => {
    console.error('❌ Workflow error:', error);
    
    // Emergency fallback
    if (context.input.severity === 'P0') {
      // Activate emergency protocols
      await context.agents.mitigationAgent.execute({
        task: 'emergency_fallback',
        error: error.message,
        action: 'activate_dr_site'
      });
    }
    
    // Always notify on workflow failure
    await context.agents.communicationAgent.execute({
      task: 'notify_failure',
      error: error.message,
      context: context.currentStep
    });
  },
  
  // Success handler
  onSuccess: async (result, context) => {
    console.log('✅ Incident resolved successfully');
    
    // Schedule follow-up review
    await context.agents.postMortemAgent.execute({
      task: 'schedule_review',
      incidentId: context.executionId,
      scheduledFor: '+2d',
      participants: ['engineering_team', 'sre_team', 'product_team']
    });
    
    // Update incident database
    await context.agents.postMortemAgent.execute({
      task: 'update_incident_db',
      incident: {
        id: context.executionId,
        ...result,
        status: 'resolved'
      }
    });
  }
});

// Export for use in applications
export default incidentResponseWorkflow;