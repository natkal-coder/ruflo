import { createTool } from '@mastra/core';
import { z } from 'zod';

const calculateRiskScore = (vulnerabilities) => {
  const weights = { critical: 10, high: 7, medium: 4, low: 1 };
  return vulnerabilities.reduce((score, vuln) => score + (weights[vuln.severity] || 0), 0);
};
const knownVulnerabilities = {
  "SQL Injection": { severity: "critical", cvss: 9.8, cve: "CVE-2024-1234" },
  "XSS": { severity: "high", cvss: 7.5, cve: "CVE-2024-1235" },
  "CSRF": { severity: "medium", cvss: 6.1, cve: "CVE-2024-1236" },
  "Weak Encryption": { severity: "high", cvss: 7.8, cve: "CVE-2024-1237" },
  "Outdated Dependencies": { severity: "medium", cvss: 5.3, cve: "CVE-2024-1238" }
};
const complianceFrameworks = {
  "SOC2": ["access-control", "encryption", "monitoring", "incident-response"],
  "ISO27001": ["risk-assessment", "access-management", "security-policy", "audit"],
  "GDPR": ["data-protection", "privacy", "consent", "breach-notification"],
  "HIPAA": ["encryption", "access-control", "audit-logs", "integrity"]
};
const vulnerabilityScanner = createTool({
  name: "vulnerability-scanner",
  description: "Scan systems and applications for known vulnerabilities",
  inputSchema: z.object({
    target: z.string().describe("Target system or application to scan"),
    scanType: z.enum(["quick", "full", "custom"]).describe("Type of vulnerability scan"),
    includePatches: z.boolean().optional().describe("Include patch recommendations")
  }),
  outputSchema: z.object({
    vulnerabilities: z.array(z.object({
      name: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
      cvss: z.number(),
      cve: z.string(),
      affected: z.string(),
      recommendation: z.string()
    })),
    riskScore: z.number(),
    scanDuration: z.number(),
    reportId: z.string()
  }),
  execute: async ({ target, scanType, includePatches = true }) => {
    const scanDuration = scanType === "full" ? 2500 : scanType === "quick" ? 800 : 1500;
    await new Promise((resolve) => setTimeout(resolve, scanDuration));
    const vulnerabilities = Object.entries(knownVulnerabilities).filter(() => Math.random() > 0.4).map(([name, details]) => ({
      name,
      ...details,
      affected: `${target}/${Math.random() > 0.5 ? "api" : "web"}`,
      recommendation: includePatches ? `Apply security patch ${details.cve}-FIX or upgrade to latest version` : "Contact security team for remediation"
    }));
    const riskScore = calculateRiskScore(vulnerabilities);
    return {
      vulnerabilities,
      riskScore,
      scanDuration,
      reportId: `VULN-${Date.now()}`
    };
  }
});
const penetrationTester = createTool({
  name: "penetration-tester",
  description: "Conduct penetration testing to identify security weaknesses",
  inputSchema: z.object({
    target: z.string().describe("Target system for penetration testing"),
    testType: z.enum(["blackbox", "whitebox", "graybox"]).describe("Type of penetration test"),
    scope: z.array(z.string()).describe("Specific areas to test")
  }),
  outputSchema: z.object({
    exploits: z.array(z.object({
      technique: z.string(),
      success: z.boolean(),
      impact: z.enum(["critical", "high", "medium", "low"]),
      details: z.string()
    })),
    recommendations: z.array(z.string()),
    overallRisk: z.enum(["critical", "high", "medium", "low"]),
    reportId: z.string()
  }),
  execute: async ({ target, testType, scope }) => {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const techniques = [
      "SQL Injection",
      "XSS Attack",
      "Buffer Overflow",
      "Privilege Escalation",
      "Session Hijacking",
      "Directory Traversal",
      "CSRF Attack"
    ];
    const exploits = techniques.filter(() => Math.random() > 0.6).map((technique) => ({
      technique,
      success: Math.random() > 0.3,
      impact: ["critical", "high", "medium", "low"][Math.floor(Math.random() * 4)],
      details: `${testType} test attempted ${technique} on ${target} - ${scope.join(", ")}`
    }));
    const criticalCount = exploits.filter((e) => e.success && e.impact === "critical").length;
    const overallRisk = criticalCount > 0 ? "critical" : exploits.some((e) => e.success && e.impact === "high") ? "high" : "medium";
    return {
      exploits,
      recommendations: [
        "Implement input validation and sanitization",
        "Use parameterized queries to prevent SQL injection",
        "Enable security headers (CSP, X-Frame-Options)",
        "Implement rate limiting and CAPTCHA",
        "Regular security training for development team"
      ].slice(0, Math.floor(Math.random() * 3) + 3),
      overallRisk,
      reportId: `PENTEST-${Date.now()}`
    };
  }
});
const accessControlAuditor = createTool({
  name: "access-control-auditor",
  description: "Audit user access controls and permissions",
  inputSchema: z.object({
    system: z.string().describe("System to audit"),
    auditType: z.enum(["users", "roles", "permissions", "full"]).describe("Type of access audit"),
    includeInactive: z.boolean().optional().describe("Include inactive accounts")
  }),
  outputSchema: z.object({
    findings: z.array(z.object({
      type: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
      description: z.string(),
      affectedUsers: z.number()
    })),
    totalUsers: z.number(),
    privilegedUsers: z.number(),
    recommendations: z.array(z.string()),
    reportId: z.string()
  }),
  execute: async ({ system, auditType, includeInactive = false }) => {
    await new Promise((resolve) => setTimeout(resolve, 1e3));
    const totalUsers = Math.floor(Math.random() * 500) + 100;
    const privilegedUsers = Math.floor(totalUsers * 0.15);
    const findings = [
      {
        type: "Excessive Privileges",
        severity: "high",
        description: "Users with admin access who haven't logged in for 90+ days",
        affectedUsers: Math.floor(Math.random() * 20) + 5
      },
      {
        type: "Weak Password Policy",
        severity: "medium",
        description: "Accounts without MFA enabled",
        affectedUsers: Math.floor(Math.random() * 50) + 20
      },
      {
        type: "Orphaned Accounts",
        severity: "high",
        description: "Active accounts for terminated employees",
        affectedUsers: Math.floor(Math.random() * 10) + 2
      },
      {
        type: "Shared Credentials",
        severity: "critical",
        description: "Service accounts with shared passwords",
        affectedUsers: Math.floor(Math.random() * 5) + 1
      }
    ].filter(() => Math.random() > 0.3);
    return {
      findings,
      totalUsers,
      privilegedUsers,
      recommendations: [
        "Implement principle of least privilege",
        "Enable MFA for all privileged accounts",
        "Regular access reviews (quarterly)",
        "Automate user deprovisioning",
        "Implement password rotation policy"
      ],
      reportId: `ACCESS-${Date.now()}`
    };
  }
});
const encryptionAnalyzer = createTool({
  name: "encryption-analyzer",
  description: "Analyze encryption methods and identify weaknesses",
  inputSchema: z.object({
    target: z.string().describe("System or data to analyze"),
    checkType: z.enum(["atRest", "inTransit", "both"]).describe("Type of encryption to check"),
    includeAlgorithms: z.boolean().optional().describe("Include algorithm analysis")
  }),
  outputSchema: z.object({
    encryptionStatus: z.object({
      atRest: z.boolean().optional(),
      inTransit: z.boolean().optional()
    }),
    algorithms: z.array(z.object({
      name: z.string(),
      strength: z.enum(["strong", "moderate", "weak", "broken"]),
      keySize: z.number(),
      recommendation: z.string()
    })),
    vulnerabilities: z.array(z.string()),
    complianceStatus: z.object({
      pci: z.boolean(),
      hipaa: z.boolean(),
      gdpr: z.boolean()
    }),
    reportId: z.string()
  }),
  execute: async ({ target, checkType, includeAlgorithms = true }) => {
    await new Promise((resolve) => setTimeout(resolve, 800));
    const algorithms = includeAlgorithms ? [
      { name: "AES-256", strength: "strong", keySize: 256, recommendation: "Continue using" },
      { name: "RSA-2048", strength: "moderate", keySize: 2048, recommendation: "Consider upgrading to RSA-4096" },
      { name: "SHA-1", strength: "broken", keySize: 160, recommendation: "Migrate to SHA-256 immediately" },
      { name: "TLS 1.3", strength: "strong", keySize: 256, recommendation: "Current best practice" }
    ].filter(() => Math.random() > 0.3) : [];
    const vulnerabilities = [];
    if (algorithms.some((a) => a.strength === "weak" || a.strength === "broken")) {
      vulnerabilities.push("Weak encryption algorithms detected");
    }
    if (Math.random() > 0.5) {
      vulnerabilities.push("SSL/TLS configuration allows weak ciphers");
    }
    if (Math.random() > 0.7) {
      vulnerabilities.push("Encryption keys stored in plaintext");
    }
    return {
      encryptionStatus: {
        ...checkType !== "inTransit" && { atRest: Math.random() > 0.2 },
        ...checkType !== "atRest" && { inTransit: Math.random() > 0.1 }
      },
      algorithms,
      vulnerabilities,
      complianceStatus: {
        pci: vulnerabilities.length === 0,
        hipaa: algorithms.every((a) => a.strength !== "broken"),
        gdpr: vulnerabilities.length < 2
      },
      reportId: `ENCRYPT-${Date.now()}`
    };
  }
});
const threatModeler = createTool({
  name: "threat-modeler",
  description: "Create threat models and identify potential attack vectors",
  inputSchema: z.object({
    system: z.string().describe("System to model"),
    methodology: z.enum(["STRIDE", "PASTA", "VAST"]).describe("Threat modeling methodology"),
    includeActors: z.boolean().optional().describe("Include threat actor analysis")
  }),
  outputSchema: z.object({
    threats: z.array(z.object({
      category: z.string(),
      description: z.string(),
      likelihood: z.enum(["high", "medium", "low"]),
      impact: z.enum(["critical", "high", "medium", "low"]),
      mitigations: z.array(z.string())
    })),
    attackVectors: z.array(z.string()),
    threatActors: z.array(z.object({
      type: z.string(),
      motivation: z.string(),
      capability: z.enum(["advanced", "intermediate", "basic"])
    })).optional(),
    riskMatrix: z.object({
      critical: z.number(),
      high: z.number(),
      medium: z.number(),
      low: z.number()
    }),
    reportId: z.string()
  }),
  execute: async ({ system, methodology, includeActors = false }) => {
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const strideCategories = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"];
    const threats = strideCategories.filter(() => Math.random() > 0.4).map((category) => ({
      category,
      description: `${category} threat identified in ${system} using ${methodology}`,
      likelihood: ["high", "medium", "low"][Math.floor(Math.random() * 3)],
      impact: ["critical", "high", "medium", "low"][Math.floor(Math.random() * 4)],
      mitigations: [
        "Implement strong authentication",
        "Add audit logging",
        "Enable encryption",
        "Apply rate limiting",
        "Use input validation"
      ].slice(0, Math.floor(Math.random() * 3) + 2)
    }));
    const threatActors = includeActors ? [
      { type: "Nation State", motivation: "Espionage", capability: "advanced" },
      { type: "Cybercriminal", motivation: "Financial Gain", capability: "intermediate" },
      { type: "Hacktivist", motivation: "Ideological", capability: "intermediate" },
      { type: "Insider Threat", motivation: "Revenge/Profit", capability: "basic" }
    ].filter(() => Math.random() > 0.5) : void 0;
    const riskMatrix = threats.reduce((matrix, threat) => {
      matrix[threat.impact]++;
      return matrix;
    }, { critical: 0, high: 0, medium: 0, low: 0 });
    return {
      threats,
      attackVectors: [
        "Phishing emails",
        "Malware injection",
        "Supply chain compromise",
        "Zero-day exploits",
        "Social engineering",
        "Physical access"
      ].filter(() => Math.random() > 0.5),
      threatActors,
      riskMatrix,
      reportId: `THREAT-${Date.now()}`
    };
  }
});
const incidentResponseSimulator = createTool({
  name: "incident-response-simulator",
  description: "Simulate security incidents and test response procedures",
  inputSchema: z.object({
    incidentType: z.enum(["breach", "malware", "ddos", "insider", "ransomware"]).describe("Type of incident to simulate"),
    severity: z.enum(["critical", "high", "medium", "low"]).describe("Incident severity"),
    testResponse: z.boolean().optional().describe("Test current response procedures")
  }),
  outputSchema: z.object({
    incident: z.object({
      type: z.string(),
      severity: z.string(),
      timeline: z.array(z.object({
        time: z.string(),
        event: z.string(),
        action: z.string()
      })),
      affectedSystems: z.array(z.string())
    }),
    responseMetrics: z.object({
      detectionTime: z.number(),
      containmentTime: z.number(),
      recoveryTime: z.number(),
      totalDowntime: z.number()
    }),
    recommendations: z.array(z.string()),
    lessonsLearned: z.array(z.string()),
    reportId: z.string()
  }),
  execute: async ({ incidentType, severity, testResponse = true }) => {
    await new Promise((resolve) => setTimeout(resolve, 1e3));
    const baseTime = /* @__PURE__ */ new Date();
    const timeline = [
      { time: baseTime.toISOString(), event: "Initial compromise detected", action: "Alert triggered" },
      { time: new Date(baseTime.getTime() + 3e5).toISOString(), event: "Incident confirmed", action: "Response team activated" },
      { time: new Date(baseTime.getTime() + 9e5).toISOString(), event: "Containment initiated", action: "Affected systems isolated" },
      { time: new Date(baseTime.getTime() + 18e5).toISOString(), event: "Recovery started", action: "Systems restoration begun" },
      { time: new Date(baseTime.getTime() + 36e5).toISOString(), event: "Incident resolved", action: "Normal operations resumed" }
    ];
    const affectedSystems = [
      "Web Server Farm",
      "Database Cluster",
      "API Gateway",
      "User Authentication Service",
      "File Storage System"
    ].filter(() => Math.random() > 0.5);
    const detectionTime = severity === "critical" ? 5 : severity === "high" ? 15 : 30;
    const containmentTime = severity === "critical" ? 30 : severity === "high" ? 60 : 120;
    const recoveryTime = severity === "critical" ? 240 : severity === "high" ? 360 : 480;
    return {
      incident: {
        type: incidentType,
        severity,
        timeline,
        affectedSystems
      },
      responseMetrics: {
        detectionTime,
        containmentTime,
        recoveryTime,
        totalDowntime: detectionTime + containmentTime + recoveryTime
      },
      recommendations: [
        "Improve monitoring and alerting systems",
        "Update incident response playbooks",
        "Conduct regular incident response drills",
        "Implement automated containment procedures",
        "Enhance backup and recovery processes"
      ],
      lessonsLearned: [
        "Need faster detection mechanisms",
        "Communication protocols require improvement",
        "Automation can reduce response time",
        "Regular training improves team effectiveness"
      ].filter(() => Math.random() > 0.3),
      reportId: `INCIDENT-${Date.now()}`
    };
  }
});
const complianceChecker = createTool({
  name: "compliance-checker",
  description: "Check compliance with security standards and regulations",
  inputSchema: z.object({
    framework: z.enum(["SOC2", "ISO27001", "GDPR", "HIPAA", "PCI-DSS"]).describe("Compliance framework to check"),
    scope: z.array(z.string()).describe("Systems or processes to audit"),
    generateReport: z.boolean().optional().describe("Generate detailed compliance report")
  }),
  outputSchema: z.object({
    complianceScore: z.number(),
    requirements: z.array(z.object({
      category: z.string(),
      requirement: z.string(),
      status: z.enum(["compliant", "partial", "non-compliant"]),
      evidence: z.string(),
      gap: z.string().optional()
    })),
    criticalGaps: z.array(z.string()),
    recommendations: z.array(z.object({
      priority: z.enum(["immediate", "high", "medium", "low"]),
      action: z.string(),
      timeline: z.string()
    })),
    certificationReady: z.boolean(),
    reportId: z.string()
  }),
  execute: async ({ framework, scope, generateReport = true }) => {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const frameworkRequirements = complianceFrameworks[framework] || [];
    const requirements = frameworkRequirements.map((category) => {
      const status = Math.random() > 0.7 ? "non-compliant" : Math.random() > 0.3 ? "compliant" : "partial";
      return {
        category,
        requirement: `${framework} requirement for ${category}`,
        status,
        evidence: status === "compliant" ? "Documentation and controls verified" : "Limited evidence available",
        gap: status !== "compliant" ? `Missing controls for ${category} in ${scope.join(", ")}` : void 0
      };
    });
    const complianceScore = Math.round(
      requirements.filter((r) => r.status === "compliant").length / requirements.length * 100
    );
    const criticalGaps = requirements.filter((r) => r.status === "non-compliant").map((r) => r.gap).filter(Boolean);
    return {
      complianceScore,
      requirements,
      criticalGaps,
      recommendations: [
        { priority: "immediate", action: "Implement missing security controls", timeline: "30 days" },
        { priority: "high", action: "Update security policies and procedures", timeline: "60 days" },
        { priority: "medium", action: "Conduct security awareness training", timeline: "90 days" },
        { priority: "low", action: "Review and update documentation", timeline: "120 days" }
      ].filter(() => Math.random() > 0.3),
      certificationReady: complianceScore >= 80,
      reportId: `COMPLIANCE-${Date.now()}`
    };
  }
});
const securityMonitor = createTool({
  name: "security-monitor",
  description: "Monitor security events and detect anomalies",
  inputSchema: z.object({
    timeRange: z.enum(["1h", "24h", "7d", "30d"]).describe("Time range to monitor"),
    systems: z.array(z.string()).describe("Systems to monitor"),
    alertThreshold: z.enum(["low", "medium", "high"]).optional().describe("Alert sensitivity")
  }),
  outputSchema: z.object({
    events: z.array(z.object({
      timestamp: z.string(),
      type: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
      source: z.string(),
      description: z.string()
    })),
    anomalies: z.array(z.object({
      type: z.string(),
      confidence: z.number(),
      details: z.string()
    })),
    metrics: z.object({
      totalEvents: z.number(),
      criticalEvents: z.number(),
      falsePositives: z.number(),
      meanTimeToDetect: z.number()
    }),
    trends: z.array(z.string()),
    reportId: z.string()
  }),
  execute: async ({ timeRange, systems, alertThreshold = "medium" }) => {
    await new Promise((resolve) => setTimeout(resolve, 1e3));
    const eventTypes = [
      "Failed Login Attempt",
      "Privilege Escalation",
      "Unusual Network Traffic",
      "File Integrity Change",
      "Malware Detection",
      "Policy Violation"
    ];
    const numEvents = timeRange === "1h" ? 50 : timeRange === "24h" ? 500 : timeRange === "7d" ? 2e3 : 5e3;
    const events = Array.from({ length: Math.min(numEvents, 20) }, () => ({
      timestamp: new Date(Date.now() - Math.random() * 864e5).toISOString(),
      type: eventTypes[Math.floor(Math.random() * eventTypes.length)],
      severity: ["critical", "high", "medium", "low"][Math.floor(Math.random() * 4)],
      source: systems[Math.floor(Math.random() * systems.length)],
      description: "Automated security event detection"
    }));
    const anomalies = [
      { type: "Unusual Login Pattern", confidence: 0.85, details: "Multiple login attempts from new locations" },
      { type: "Data Exfiltration Attempt", confidence: 0.72, details: "Large data transfer to external IP" },
      { type: "Suspicious Process Execution", confidence: 0.91, details: "Unknown process with elevated privileges" }
    ].filter(() => Math.random() > 0.6);
    return {
      events: events.slice(0, 10),
      anomalies,
      metrics: {
        totalEvents: numEvents,
        criticalEvents: Math.floor(numEvents * 0.05),
        falsePositives: Math.floor(numEvents * 0.02),
        meanTimeToDetect: alertThreshold === "low" ? 2 : alertThreshold === "medium" ? 5 : 10
      },
      trends: [
        "Increase in failed authentication attempts",
        "Decrease in malware detections",
        "Stable network traffic patterns",
        "Rising privilege escalation attempts"
      ].filter(() => Math.random() > 0.5),
      reportId: `MONITOR-${Date.now()}`
    };
  }
});
const authenticationTester = createTool({
  name: "authentication-tester",
  description: "Test authentication mechanisms and identify weaknesses",
  inputSchema: z.object({
    authSystem: z.string().describe("Authentication system to test"),
    testTypes: z.array(z.enum(["password", "mfa", "sso", "biometric", "token"])).describe("Types of auth to test"),
    includeBypass: z.boolean().optional().describe("Include bypass attempt tests")
  }),
  outputSchema: z.object({
    testResults: z.array(z.object({
      testType: z.string(),
      method: z.string(),
      result: z.enum(["passed", "failed", "vulnerable"]),
      details: z.string()
    })),
    vulnerabilities: z.array(z.object({
      type: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
      exploitability: z.enum(["easy", "moderate", "difficult"])
    })),
    securityScore: z.number(),
    recommendations: z.array(z.string()),
    reportId: z.string()
  }),
  execute: async ({ authSystem, testTypes, includeBypass = false }) => {
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const testMethods = {
      password: ["Brute Force", "Dictionary Attack", "Password Spray"],
      mfa: ["MFA Bypass", "Token Prediction", "Recovery Flow"],
      sso: ["SAML Injection", "Token Manipulation", "Session Fixation"],
      biometric: ["Presentation Attack", "Template Extraction", "Liveness Detection"],
      token: ["Token Forging", "Replay Attack", "Token Leakage"]
    };
    const testResults = testTypes.flatMap(
      (type) => (testMethods[type] || []).map((method) => ({
        testType: type,
        method,
        result: Math.random() > 0.7 ? "vulnerable" : Math.random() > 0.3 ? "passed" : "failed",
        details: `Testing ${method} on ${authSystem} authentication system`
      }))
    );
    const vulnerabilities = testResults.filter((r) => r.result === "vulnerable").map((r) => ({
      type: r.method,
      severity: ["critical", "high", "medium"][Math.floor(Math.random() * 3)],
      exploitability: ["easy", "moderate", "difficult"][Math.floor(Math.random() * 3)]
    }));
    const passedTests = testResults.filter((r) => r.result === "passed").length;
    const securityScore = Math.round(passedTests / testResults.length * 100);
    return {
      testResults,
      vulnerabilities,
      securityScore,
      recommendations: [
        "Implement account lockout policies",
        "Enable MFA for all accounts",
        "Use secure token generation",
        "Implement session timeout",
        "Add CAPTCHA for failed attempts",
        "Monitor authentication logs"
      ].filter(() => Math.random() > 0.4),
      reportId: `AUTH-${Date.now()}`
    };
  }
});
const firewallAnalyzer = createTool({
  name: "firewall-analyzer",
  description: "Analyze firewall rules and configurations for security issues",
  inputSchema: z.object({
    firewallType: z.enum(["network", "application", "cloud", "host"]).describe("Type of firewall"),
    configFile: z.string().optional().describe("Configuration file path or content"),
    checkCompliance: z.boolean().optional().describe("Check against best practices")
  }),
  outputSchema: z.object({
    rules: z.array(z.object({
      ruleId: z.string(),
      source: z.string(),
      destination: z.string(),
      port: z.string(),
      protocol: z.string(),
      action: z.enum(["allow", "deny"]),
      risk: z.enum(["high", "medium", "low", "none"])
    })),
    issues: z.array(z.object({
      type: z.string(),
      severity: z.enum(["critical", "high", "medium", "low"]),
      description: z.string(),
      affectedRules: z.array(z.string())
    })),
    statistics: z.object({
      totalRules: z.number(),
      allowRules: z.number(),
      denyRules: z.number(),
      riskyRules: z.number()
    }),
    recommendations: z.array(z.string()),
    reportId: z.string()
  }),
  execute: async ({ firewallType, configFile, checkCompliance = true }) => {
    await new Promise((resolve) => setTimeout(resolve, 1e3));
    const rules = Array.from({ length: Math.floor(Math.random() * 20) + 10 }, (_, i) => {
      const isAllow = Math.random() > 0.3;
      const isRisky = isAllow && Math.random() > 0.7;
      return {
        ruleId: `FW-${i + 1}`,
        source: Math.random() > 0.5 ? "0.0.0.0/0" : `192.168.${Math.floor(Math.random() * 255)}.0/24`,
        destination: Math.random() > 0.5 ? "any" : `10.0.${Math.floor(Math.random() * 255)}.0/24`,
        port: ["22", "80", "443", "3389", "any"][Math.floor(Math.random() * 5)],
        protocol: ["tcp", "udp", "any"][Math.floor(Math.random() * 3)],
        action: isAllow ? "allow" : "deny",
        risk: isRisky ? "high" : isAllow && Math.random() > 0.5 ? "medium" : "low"
      };
    });
    const issues = [];
    if (rules.some((r) => r.source === "0.0.0.0/0" && r.port === "22" && r.action === "allow")) {
      issues.push({
        type: "SSH Open to Internet",
        severity: "critical",
        description: "SSH port exposed to the entire internet",
        affectedRules: rules.filter((r) => r.port === "22" && r.source === "0.0.0.0/0").map((r) => r.ruleId)
      });
    }
    if (rules.some((r) => r.port === "any" && r.action === "allow")) {
      issues.push({
        type: "Overly Permissive Rule",
        severity: "high",
        description: "Rules allowing any port increase attack surface",
        affectedRules: rules.filter((r) => r.port === "any" && r.action === "allow").map((r) => r.ruleId)
      });
    }
    const statistics = {
      totalRules: rules.length,
      allowRules: rules.filter((r) => r.action === "allow").length,
      denyRules: rules.filter((r) => r.action === "deny").length,
      riskyRules: rules.filter((r) => r.risk === "high").length
    };
    return {
      rules: rules.slice(0, 10),
      // Return first 10 rules for brevity
      issues,
      statistics,
      recommendations: [
        "Implement principle of least privilege for firewall rules",
        "Remove or restrict rules with source 0.0.0.0/0",
        'Use specific ports instead of "any"',
        "Regularly review and audit firewall rules",
        "Implement egress filtering",
        "Enable logging for all deny rules"
      ].filter(() => Math.random() > 0.3),
      reportId: `FIREWALL-${Date.now()}`
    };
  }
});
const securityTools = {
  vulnerabilityScanner,
  penetrationTester,
  accessControlAuditor,
  encryptionAnalyzer,
  threatModeler,
  incidentResponseSimulator,
  complianceChecker,
  securityMonitor,
  authenticationTester,
  firewallAnalyzer
};

export { securityTools };
//# sourceMappingURL=391f86de-3a1d-406b-9aec-c0221962c9c9.mjs.map
