export type VulnerabilityCategory = 
  | 'SAST' 
  | 'SCA' 
  | 'SECRETS' 
  | 'CONFIG' 
  | 'DAST' 
  | 'MOBILE_STATIC' 
  | 'BINARY_STATIC'
  | 'WEB_RECON'
  | 'SECURITY_HEADERS'
  | 'API_EXPOSURE'
  | 'SSL_TLS';

export type FindingCategory = VulnerabilityCategory;

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type SeverityLevel = Severity;

export type NavigationTab = 'overview' | 'scans' | 'redteam' | 'remediation' | 'compliance' | 'threat_intel' | 'settings';

export type TargetPlatform = 'web' | 'android' | 'ios' | 'windows' | 'macos' | 'cloud';

export type FindingStatus = 
  | 'DETECTED' 
  | 'PATCH_PENDING' 
  | 'PATCH_APPLIED' 
  | 'TESTING' 
  | 'VERIFIED_RESOLVED' 
  | 'UNRESOLVED' 
  | 'FALSE_POSITIVE' 
  | 'IGNORED';

export interface ProposedPatch {
  beforeCode: string;
  afterCode: string;
  diff: string;
  explanation: string;
  fileModified: string;
  startLine: number;
  endLine: number;
  safetyRating: 'SAFE_AUTOMATIC' | 'REQUIRES_REVIEW' | 'BREAKING_CHANGE_POSSIBLE';
  breakingChangeRisk: string;
}

export interface SecurityTestCase {
  name: string;
  description: string;
  inputPayload: string;
  expectedOutcome: string;
  testScriptCode: string;
}

export interface VulnerabilityFinding {
  id: string;
  title: string;
  category: VulnerabilityCategory;
  severity: Severity;
  confidence: number; // 0 - 100%
  cwe: string; // e.g., 'CWE-89'
  cweName: string; // e.g., 'Improper Neutralization of Special Elements used in an SQL Command'
  cvssScore: number; // e.g. 9.8
  file: string;
  line: number;
  endLine?: number;
  codeSnippet: string;
  description: string;
  rootCause: string;
  attackScenario: string;
  businessImpact: string;
  recommendation: string;
  proposedPatch?: ProposedPatch;
  testCase?: SecurityTestCase;
  status: FindingStatus;
  verifiedAt?: string;
  platform?: TargetPlatform;
  complianceTags?: {
    owasp?: string[]; // e.g. ["A03:2021-Injection"]
    nist?: string[];  // e.g. ["SI-10", "AC-3"]
    soc2?: string[];  // e.g. ["CC6.1", "CC6.6"]
    pci?: string[];   // e.g. ["Req 6.5.1", "Req 8.2"]
    hipaa?: string[]; // e.g. ["164.312(a)(1)"]
    iso27001?: string[]; // e.g. ["A.8.28", "A.8.9"]
  };
  verificationProof?: {
    testPassed: boolean;
    beforeExecutionLog: string;
    afterExecutionLog: string;
    rescanConfirmedClean: boolean;
    verificationHash: string;
  };
  // Dependency specific fields (for SCA)
  dependencyInfo?: {
    packageName: string;
    currentVersion: string;
    fixedVersion: string;
    cveList: string[];
    isDirect: boolean;
    breakingChanges: boolean;
  };
}

export interface ProjectFile {
  path: string;
  content: string;
  language: string;
  size: number;
  isModified?: boolean;
  originalContent?: string;
}

export interface DiscoveredEndpoint {
  path: string;
  method: string;
  status: number;
  exposureType: 'PUBLIC_API' | 'SENSITIVE_DEBUG' | 'ADMIN_PORTAL' | 'GRAPHQL' | 'DOCS';
  riskLevel: Severity;
}

export interface DnsRecordAudit {
  type: string;
  value: string;
  status: 'SECURE' | 'WARNING' | 'CRITICAL';
  details: string;
}

export interface CookieAuditItem {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  status: 'SAFE' | 'VULNERABLE';
}

export interface WebsiteMetadata {
  url: string;
  hostname: string;
  ipAddress?: string;
  serverHeader?: string;
  tlsVersion?: string;
  cipherSuite?: string;
  certificateIssuer?: string;
  certificateExpires?: string;
  securityHeadersGrade?: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  wafDetected?: string;
  technologies?: string[];
  discoveredEndpoints?: DiscoveredEndpoint[];
  dnsRecords?: DnsRecordAudit[];
  cookieAudit?: CookieAuditItem[];
  status?: number;
  responseTimeMs?: number;
  tlsInfo?: any;
  headers?: Record<string, string>;
}

export interface ScanTarget {
  id: string;
  name: string;
  type: 'apk' | 'exe' | 'ipa' | 'dmg' | 'zip' | 'repo' | 'snippet' | 'benchmark' | 'url';
  platform?: TargetPlatform;
  language: string;
  description?: string;
  files: ProjectFile[];
  totalLines: number;
  scannedAt: string;
  binaryMetadata?: {
    architecture?: string;
    targetSdk?: string;
    minSdk?: string;
    bundleId?: string;
    versionName?: string;
    signed?: boolean;
    aslrEnabled?: boolean;
    depEnabled?: boolean;
    hardenedRuntime?: boolean;
    entitlements?: string[];
    permissions?: string[];
  };
  websiteMetadata?: WebsiteMetadata;
}

export interface AttackChain {
  id: string;
  title: string;
  severity: Severity;
  findingsInvolved: string[]; // finding IDs
  narrative: string;
  potentialImpact: string;
}

export interface AIAnalystInsight {
  summary: string;
  executiveTakeaway: string;
  immediatePriorities: string[];
  blastRadiusScore: number; // 0 - 100
  blastRadiusSummary: string;
  attackChains: AttackChain[];
  remediationRoadmap: {
    phase: string;
    actions: string[];
    estimatedEffort: string;
  }[];
}

export interface ScanResult {
  scanId: string;
  target: ScanTarget;
  findings: VulnerabilityFinding[];
  timestamp: string;
  scoreBefore: number;
  scoreCurrent: number;
  metrics: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    resolvedCount: number;
    verifiedPercentage: number;
  };
  aiInsight: AIAnalystInsight;
}

export interface ChatMessage {
  id: string;
  sender: 'user' | 'analyst' | 'system';
  text: string;
  timestamp: string;
  relatedFindingId?: string;
  suggestedActions?: string[];
}

export type ComplianceFramework = 'OWASP_TOP_10' | 'NIST_800_53' | 'SOC2_TYPE_II' | 'ISO_27001' | 'PCI_DSS_V4' | 'HIPAA';

export interface ComplianceRequirement {
  id: string;
  code: string;
  name: string;
  description: string;
  category: string;
  framework: ComplianceFramework;
  findingsAffected: string[]; // Finding IDs
  status: 'COMPLIANT' | 'NON_COMPLIANT' | 'REMEDIATED';
}

export interface PlatformSettings {
  aiModel: string;
  enableSAST: boolean;
  enableSCA: boolean;
  enableSecrets: boolean;
  enableConfig: boolean;
  enableMobileStatic: boolean;
  enableBinaryStatic: boolean;
  enableWebRecon: boolean;
  enableSecurityHeaders: boolean;
  enableRedTeamSimulation?: boolean;
  enablePurpleTeamAudit?: boolean;
  autoGeneratePatches: boolean;
  autoVerifyPatches: boolean;
  complianceStandard: ComplianceFramework;
  minSeverityThreshold: Severity;
  strictMode: boolean;
}

// -------------------------------------------------------------
// RED TEAM & ADVERSARY SIMULATION SUBSYSTEM TYPES
// -------------------------------------------------------------

export type ExploitStatus = 
  | 'CONFIRMED_EXPLOITABLE' 
  | 'POTENTIALLY_EXPLOITABLE' 
  | 'NOT_EXPLOITABLE' 
  | 'SAFE_BLOCKED';

export interface ScopeAuthorizationConfig {
  targetUrlOrRepo: string;
  isAuthorized: boolean;
  authorizationSigner: string;
  scopeInclusions: {
    webApplication: boolean;
    restAndGraphqlApis: boolean;
    testDatabaseSandbox: boolean;
    mobileEndpoints: boolean;
  };
  scopeExclusions: {
    productionDatabases: boolean;
    thirdPartyServices: boolean;
    externalCloudInfrastructure: boolean;
    destructiveDenialOfService: boolean;
  };
  allowedTestingModes: {
    activeExploitation: boolean;
    authenticationTesting: boolean;
    authorizationPrivilegeTesting: boolean;
    injectionValidation: boolean;
    dataExfiltrationSimulation: boolean;
  };
  sandboxEnvironment: {
    type: 'DOCKER_CONTAINER' | 'ISOLATED_MICRO_VM' | 'SYNTHETIC_MEMORY_HARNESS';
    syntheticDataOnly: boolean;
    disposableInstanceId: string;
    networkIsolationLevel: 'STRICT_AIR_GAPPED' | 'EGRESS_PROXY_ONLY' | 'SYNTHETIC_MOCK';
    status: 'READY' | 'PROVISIONING' | 'EXECUTING' | 'DESTROYED';
  };
}

export interface AttackPathNode {
  id: string;
  label: string;
  category: 'ENTRY_POINT' | 'AUTHENTICATION' | 'VULNERABILITY' | 'PRIVILEGE_ESCALATION' | 'LATERAL_MOVEMENT' | 'DATA_EXFILTRATION' | 'IMPACT';
  findingId?: string;
  details: string;
  status: 'EXPLOITED' | 'MITIGATED' | 'BLOCKED' | 'PENDING';
  severity?: Severity;
  targetAsset: string;
  techniqueCWE?: string;
}

export interface AttackPathEdge {
  from: string;
  to: string;
  label?: string;
  protocol?: string;
}

export interface AttackPathGraph {
  id: string;
  title: string;
  severity: Severity;
  riskScore: number; // 0 - 100
  narrative: string;
  businessImpact: string;
  rootCause: string;
  recommendedFix: string;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  isMitigated: boolean;
  remediationFindingIds: string[];
}

export interface ExploitValidationRecord {
  id: string; // e.g. "RT-2026-00182"
  findingId: string;
  vulnerabilityTitle: string;
  cwe: string;
  status: ExploitStatus;
  confidenceScore: number; // e.g. 98%
  affectedEndpoint: string;
  payloadSent: string;
  payloadType: 'NON_DESTRUCTIVE_BENIGN_PROBE' | 'SYNTHETIC_AUTH_BYPASS' | 'TAINT_PROPAGATION_PROBE' | 'MEMORY_SAFE_READ';
  evidenceProof: string;
  technicalDetails: string;
  dataAccessed: string;
  productionImpact: 'NONE' | 'ISOLATED_TEST_ONLY';
  timestamp: string;
  executionTimeMs: number;
  isResolved: boolean;
}

export interface PurpleTeamDefenseAudit {
  attackId: string;
  attackName: string;
  techniqueMITRE: string;
  targetService: string;
  simulatedAttackOutcome: 'ATTACK_SUCCESSFUL' | 'ATTACK_BLOCKED' | 'EXPLOIT_CONFIRMED';
  
  // Blue Team Defense Controls
  wafDetection: {
    status: 'DETECTED_AND_BLOCKED' | 'DETECTED_ONLY' | 'NOT_DETECTED';
    ruleTriggered?: string;
    latencySeconds?: number;
  };
  idsDetection: {
    status: 'DETECTED' | 'NOT_DETECTED' | 'UNMONITORED';
    signatureName?: string;
  };
  applicationLogging: {
    status: 'AUDIT_LOG_RECORDED' | 'INSUFFICIENT_LOGGING' | 'NO_LOG';
    logSnippet?: string;
  };
  siemAlertGenerated: boolean;
  alertPriority?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  detectionTimeSeconds: number; // e.g. 1.8s
  
  // Blue Team Evaluation & Defense Gap
  defenseScore: number; // 0 - 100
  defenseGapAnalysis: string;
  blueTeamRecommendation: string;
}

export interface RedTeamSimulationReport {
  target: ScanTarget;
  scope: ScopeAuthorizationConfig;
  simulationTimestamp: string;
  totalExploitsAttempted: number;
  confirmedExploitableCount: number;
  blockedCount: number;
  attackPathCount: number;
  purpleTeamOverallScore: number; // 0 - 100
  attackPaths: AttackPathGraph[];
  exploitValidations: ExploitValidationRecord[];
  purpleTeamAudits: PurpleTeamDefenseAudit[];
  aiAdversaryNarrative: {
    executiveSummary: string;
    threatActorPersona: string;
    killChainBreakdown: string[];
    criticalVulnerabilityChain: string;
    defensiveHardeningActionItems: string[];
  };
}
