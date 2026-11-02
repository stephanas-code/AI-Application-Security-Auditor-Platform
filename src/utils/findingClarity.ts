import { VulnerabilityFinding } from '../types';

export interface FindingClarityDetails {
  vulnerabilityTypeLabel: string;
  plainSummary: string;
  detectionEngine: string;
  detectionExplanation: string;
  verificationEnvironment: string;
  safeVerificationSteps: string[];
  remediationSteps: string[];
}

export function getFindingClarityDetails(finding: VulnerabilityFinding): FindingClarityDetails {
  const cat = finding.category;
  const platform = finding.platform || 'web';
  const titleLower = finding.title.toLowerCase();

  // 1. Determine Detection Engine & Explanation
  let detectionEngine = 'Static AST & Pattern Analyzer (Semgrep / Engine Core)';
  let detectionExplanation = `Detected by scanning ${finding.file} at line ${finding.line} and matching the code pattern against ${finding.cwe} (${finding.cweName}).`;

  if (cat === 'SECURITY_HEADERS' || cat === 'SSL_TLS' || finding.file.includes('nginx') || finding.file.includes('headers')) {
    detectionEngine = 'HTTP Response & TLS Configuration Inspector';
    detectionExplanation = `Detected during live HTTP header and configuration inspection of ${finding.file} (line ${finding.line}), where the required security policy was missing or misconfigured.`;
  } else if (cat === 'SCA' || finding.dependencyInfo) {
    detectionEngine = 'Software Composition Analysis (Trivy / OSV Database)';
    detectionExplanation = `Detected by cross-referencing package manifest ${finding.file} (${finding.dependencyInfo?.packageName || 'dependency'}@${finding.dependencyInfo?.currentVersion || 'current'}) against known CVE advisories.`;
  } else if (cat === 'SECRETS') {
    detectionEngine = 'Secret & Credential Entropy Scanner (Gitleaks)';
    detectionExplanation = `Detected high-entropy credential or hardcoded key pattern in ${finding.file} at line ${finding.line}.`;
  } else if (platform === 'android' || platform === 'ios') {
    detectionEngine = 'Mobile Package & Manifest Static Analyzer';
    detectionExplanation = `Detected by inspecting mobile application manifest and configuration properties in ${finding.file} at line ${finding.line}.`;
  } else if (platform === 'windows' || platform === 'macos') {
    detectionEngine = 'Binary Header & Entitlement Static Inspector';
    detectionExplanation = `Detected by inspecting binary security flags, compilation headers, or entitlements in ${finding.file} at line ${finding.line}.`;
  }

  // 2. Determine Safe Non-Destructive Verification Steps
  let verificationEnvironment = 'Browser DevTools (Network Inspector) / Source Code Review';
  let safeVerificationSteps: string[] = [];

  if (cat === 'SECURITY_HEADERS' || titleLower.includes('header') || titleLower.includes('csp') || titleLower.includes('hsts') || titleLower.includes('cors') || titleLower.includes('frame')) {
    verificationEnvironment = 'Web Browser Developer Tools (Network Tab)';
    safeVerificationSteps = [
      'Open the target URL in your web browser and open Developer Tools (F12 or Right-Click → Inspect).',
      'Select the "Network" tab and reload the page to capture the primary document response.',
      `Click the main request and inspect the "Response Headers" section to verify whether the header (${finding.title}) is missing or permissively configured.`,
      `Confirm the configuration in ${finding.file} around line ${finding.line} matches the reported finding.`
    ];
  } else if (cat === 'SCA' && finding.dependencyInfo) {
    verificationEnvironment = 'Package Manifest & Lockfile Audit';
    safeVerificationSteps = [
      `Open ${finding.file} at line ${finding.line} and check the declared version of "${finding.dependencyInfo.packageName}".`,
      `Verify that the installed version (${finding.dependencyInfo.currentVersion}) is earlier than the patched release (${finding.dependencyInfo.fixedVersion}).`,
      `Run your package manager audit command (e.g., npm audit or pip-audit) to confirm the advisory (${finding.dependencyInfo.cveId}).`
    ];
  } else if (cat === 'SECRETS') {
    verificationEnvironment = 'Repository & Configuration Audit';
    safeVerificationSteps = [
      `Open ${finding.file} and inspect line ${finding.line} to confirm whether a credential, token, or private key literal is committed in plain text.`,
      'Check version control history to determine if the secret was exposed in previous commits.',
      'Verify whether the key is currently active in the target environment configuration.'
    ];
  } else if (platform === 'android' || platform === 'ios') {
    verificationEnvironment = 'Mobile Manifest & Static Configuration Review';
    safeVerificationSteps = [
      `Inspect the extracted manifest or configuration file (${finding.file}) at line ${finding.line}.`,
      `Verify the security attribute or permission flag highlighted in the code snippet (${finding.codeSnippet.trim()}).`,
      'Confirm that the setting is enabled in production build variants rather than restricted to debug builds.'
    ];
  } else if (platform === 'windows' || platform === 'macos') {
    verificationEnvironment = 'Binary Security Flags & Build Configuration Review';
    safeVerificationSteps = [
      `Review the binary configuration or build script in ${finding.file} at line ${finding.line}.`,
      `Check the compiler/linker hardening flags (such as ASLR, DEP, or Hardened Runtime entitlements) shown in the snippet.`,
      'Confirm via static header inspection that the protection flag is disabled or omitted.'
    ];
  } else {
    verificationEnvironment = 'Source Code & Endpoint Configuration Review';
    safeVerificationSteps = [
      `Locate ${finding.file} at line ${finding.line} in the workspace.`,
      `Trace the data flow into the highlighted sink (${finding.codeSnippet.trim()}) to confirm whether untrusted input or unvalidated configuration reaches it.`,
      'Run the non-destructive unit verification check in the Remediation modal to confirm the behavior before and after patching.'
    ];
  }

  // 3. Determine Remediation & Patch Steps
  const remediationSteps: string[] = [
    finding.recommendation,
    finding.proposedPatch
      ? `Apply the proposed patch in ${finding.proposedPatch.fileModified} (lines ${finding.proposedPatch.startLine}–${finding.proposedPatch.endLine}): ${finding.proposedPatch.explanation}`
      : `Update ${finding.file} at line ${finding.line} to enforce strict input validation and secure defaults.`,
    'Re-run the security scanner after applying the fix to confirm the finding status changes to VERIFIED CLEAN.'
  ];

  return {
    vulnerabilityTypeLabel: `${finding.cwe}: ${finding.cweName}`,
    plainSummary: finding.description,
    detectionEngine,
    detectionExplanation,
    verificationEnvironment,
    safeVerificationSteps,
    remediationSteps
  };
}

