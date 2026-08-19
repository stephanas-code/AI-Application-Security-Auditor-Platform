import React, { useState, useEffect } from 'react';
import confetti from 'canvas-confetti';
import { 
  ScanTarget, 
  ScanResult, 
  VulnerabilityFinding, 
  ProposedPatch, 
  NavigationTab, 
  PlatformSettings 
} from './types';
import { BENCHMARK_PROJECTS } from './data/benchmarkProjects';
import { SecurityEngine } from './services/securityEngine';

import { Sidebar } from './components/Sidebar';
import { OverviewView } from './components/views/OverviewView';
import { SecurityScansView } from './components/views/SecurityScansView';
import { RedTeamDashboardView } from './components/views/RedTeamDashboardView';
import { RemediationHubView } from './components/views/RemediationHubView';
import { ComplianceMapView } from './components/views/ComplianceMapView';
import { ThreatIntelForensicsView } from './components/views/ThreatIntelForensicsView';
import { SettingsView } from './components/views/SettingsView';

import { RemediationModal } from './components/RemediationModal';
import { ProjectIntakeModal } from './components/ProjectIntakeModal';
import { AuditReportModal } from './components/AuditReportModal';
import { AIAnalystChat } from './components/AIAnalystChat';

import { 
  ShieldCheck, 
  MessageSquare, 
  PlusCircle, 
  RefreshCw, 
  FileText,
  Sparkles,
  Smartphone,
  Monitor,
  Apple,
  Terminal,
  Layers
} from 'lucide-react';

export default function App() {
  const [currentTarget, setCurrentTarget] = useState<ScanTarget>(BENCHMARK_PROJECTS[0]!);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [currentTab, setCurrentTab] = useState<NavigationTab>('overview');

  // Platform Settings State
  const [platformSettings, setPlatformSettings] = useState<PlatformSettings>({
    aiModel: 'gemini-2.5-pro',
    enableSAST: true,
    enableSCA: true,
    enableSecrets: true,
    enableConfig: true,
    enableMobileStatic: true,
    enableBinaryStatic: true,
    autoGeneratePatches: true,
    autoVerifyPatches: true,
    complianceStandard: 'OWASP_TOP_10',
    minSeverityThreshold: 'LOW',
    strictMode: true
  });

  // Modal & Drawer States
  const [isIntakeOpen, setIsIntakeOpen] = useState(false);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [remediationTab, setRemediationTab] = useState<'explain' | 'recommend' | 'fix' | 'verify'>('explain');
  const [isVerifying, setIsVerifying] = useState(false);
  const [isFixingAll, setIsFixingAll] = useState(false);

  // Initial Scan on Mount
  useEffect(() => {
    runScan(BENCHMARK_PROJECTS[0]!);
  }, []);

  const runScan = async (target: ScanTarget) => {
    setIsScanning(true);
    try {
      const result = await SecurityEngine.scanCodebaseAsync(target);
      setScanResult(result);
    } catch (e) {
      const fallback = SecurityEngine.scanCodebase(target);
      setScanResult(fallback);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectTarget = (target: ScanTarget) => {
    setCurrentTarget(target);
    runScan(target);
    setCurrentTab('overview');
  };

  const handleRescan = async () => {
    if (!currentTarget || !scanResult) return;
    setIsScanning(true);
    try {
      const updated = SecurityEngine.verifyAndRescan(currentTarget, scanResult.findings);
      setScanResult(updated);
    } finally {
      setIsScanning(false);
    }
  };

  const handleOpenFindingModal = (finding: VulnerabilityFinding, initialTab: 'explain' | 'recommend' | 'fix' = 'explain') => {
    setSelectedFinding(finding);
    setRemediationTab(initialTab);
  };

  // The Core Fix → Test → Rescan → Verify Action
  const handleApplyAndVerify = async (finding: VulnerabilityFinding, patch: ProposedPatch) => {
    if (!scanResult) return;
    setIsVerifying(true);

    try {
      // 1. Apply patch into target file memory
      const targetFileIndex = currentTarget.files.findIndex(f => f.path === patch.fileModified);
      let updatedFiles = [...currentTarget.files];

      if (targetFileIndex >= 0) {
        const file = updatedFiles[targetFileIndex]!;
        let newContent = file.content;

        if (newContent.includes(patch.beforeCode)) {
          newContent = newContent.replace(patch.beforeCode, patch.afterCode);
        } else {
          // Fallback replacement if exact chunk slightly altered
          const lines = newContent.split('\n');
          const start = Math.max(0, patch.startLine - 1);
          const end = Math.min(lines.length, patch.endLine);
          lines.splice(start, end - start, patch.afterCode);
          newContent = lines.join('\n');
        }

        updatedFiles[targetFileIndex] = {
          ...file,
          content: newContent,
          isModified: true
        };
      }

      const updatedTarget: ScanTarget = {
        ...currentTarget,
        files: updatedFiles
      };
      setCurrentTarget(updatedTarget);

      // 2. Call backend sandbox test runner
      await fetch('/api/verify-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          findingId: finding.id,
          proposedPatch: patch,
          testCase: finding.testCase
        })
      });

      // 3. Automated Rescan & Verification Evaluation
      const updatedScanResult = SecurityEngine.verifyAndRescan(updatedTarget, scanResult.findings);
      setScanResult(updatedScanResult);

      // Update selected finding state with verification proof
      const verifiedFinding = updatedScanResult.findings.find(f => f.id === finding.id);
      if (verifiedFinding) {
        setSelectedFinding(verifiedFinding);
      }

      // Check if all findings resolved!
      const activeRemaining = updatedScanResult.findings.filter(f => f.status !== 'VERIFIED_RESOLVED').length;
      if (activeRemaining === 0) {
        confetti({
          particleCount: 100,
          spread: 70,
          origin: { y: 0.6 }
        });
      }
    } catch (err) {
      console.error('Error applying patch and verifying:', err);
    } finally {
      setIsVerifying(false);
    }
  };

  // Batch Auto-Remediate & Verify All Patches
  const handleAutoFixAll = async () => {
    if (!scanResult) return;
    setIsFixingAll(true);

    const activeFindings = scanResult.findings.filter(f => f.status !== 'VERIFIED_RESOLVED');
    let updatedFiles = [...currentTarget.files];

    for (const f of activeFindings) {
      if (f.proposedPatch) {
        const fileIdx = updatedFiles.findIndex(file => file.path === f.proposedPatch!.fileModified);
        if (fileIdx >= 0) {
          const file = updatedFiles[fileIdx]!;
          if (file.content.includes(f.proposedPatch.beforeCode)) {
            updatedFiles[fileIdx] = {
              ...file,
              content: file.content.replace(f.proposedPatch.beforeCode, f.proposedPatch.afterCode),
              isModified: true
            };
          }
        }
      }
    }

    const updatedTarget = {
      ...currentTarget,
      files: updatedFiles
    };
    setCurrentTarget(updatedTarget);

    await new Promise(r => setTimeout(r, 600));

    const freshResult = SecurityEngine.verifyAndRescan(updatedTarget, scanResult.findings);
    setScanResult(freshResult);
    setIsFixingAll(false);

    confetti({
      particleCount: 120,
      spread: 80,
      origin: { y: 0.6 }
    });
  };

  return (
    <div className="min-h-screen bg-[#0A0A0A] text-[#E5E5E5] flex font-sans selection:bg-[#FF3B30] selection:text-black">
      
      {/* 1. Left Sidebar Navigation */}
      {scanResult && (
        <Sidebar
          currentTab={currentTab}
          onSelectTab={setCurrentTab}
          target={currentTarget}
          scanResult={scanResult}
          onOpenIntake={() => setIsIntakeOpen(true)}
          onOpenReport={() => setIsReportOpen(true)}
          onRescan={handleRescan}
          isRescanning={isScanning}
        />
      )}

      {/* 2. Main Content Workspace */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto max-h-screen">
        
        {/* Top Floating App Bar */}
        <header className="sticky top-0 z-40 bg-[#0A0A0A]/90 backdrop-blur-md border-b border-[#1F1F1F] px-6 py-3 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono font-bold text-gray-500 uppercase tracking-widest">
                Active Audit Workspace:
              </span>
              <span className="text-xs font-bold text-white bg-[#141414] px-2.5 py-1 rounded-lg border border-[#1F1F1F]">
                {currentTarget.name}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-400 border border-blue-900/50 uppercase font-bold">
                {currentTarget.platform || 'web'}
              </span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* AI Assistant Chat Trigger */}
            <button
              onClick={() => setIsChatOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-[#141414] hover:bg-[#1E1E1E] border border-[#1F1F1F] text-gray-300 hover:text-white text-xs font-mono transition-all"
            >
              <MessageSquare className="h-3.5 w-3.5 text-blue-400" />
              <span>AI Security Analyst</span>
            </button>

            {/* Ingest Binary or Target */}
            <button
              onClick={() => setIsIntakeOpen(true)}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow"
            >
              <PlusCircle className="h-3.5 w-3.5" />
              <span>Upload / Ingest</span>
            </button>
          </div>
        </header>

        {/* Dynamic Page Views */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          {scanResult && (
            <>
              {/* VIEW 1: OVERVIEW */}
              {currentTab === 'overview' && (
                <OverviewView
                  scanResult={scanResult}
                  target={currentTarget}
                  onNavigate={setCurrentTab}
                  onSelectFinding={(f) => {
                    setSelectedFinding(f);
                    setCurrentTab('scans');
                  }}
                  onApplyPatch={(f) => {
                    setSelectedFinding(f);
                    handleOpenFindingModal(f, 'fix');
                  }}
                  onAutoFixAll={handleAutoFixAll}
                  isFixingAll={isFixingAll}
                />
              )}

              {/* VIEW 2: SECURITY SCANS */}
              {currentTab === 'scans' && (
                <SecurityScansView
                  scanResult={scanResult}
                  target={currentTarget}
                  selectedFinding={selectedFinding}
                  onSelectFinding={(f) => setSelectedFinding(f)}
                  onOpenRemediation={(f) => {
                    setSelectedFinding(f);
                    handleOpenFindingModal(f, 'fix');
                  }}
                />
              )}

              {/* VIEW: RED TEAM / ADVERSARY SIMULATION */}
              {currentTab === 'redteam' && (
                <RedTeamDashboardView
                  target={currentTarget}
                  findings={scanResult.findings}
                  onOpenFindingModal={(f, tab) => handleOpenFindingModal(f, tab || 'explain')}
                  onNavigateToRemediation={() => setCurrentTab('remediation')}
                  onRescan={handleRescan}
                />
              )}

              {/* VIEW 3: REMEDIATION HUB */}
              {currentTab === 'remediation' && (
                <RemediationHubView
                  scanResult={scanResult}
                  target={currentTarget}
                  onApplyPatch={(f) => {
                    if (f.proposedPatch) {
                      handleApplyAndVerify(f, f.proposedPatch);
                    }
                  }}
                  onApplyAllPatches={handleAutoFixAll}
                  onRescan={handleRescan}
                  isRescanning={isScanning}
                />
              )}

              {/* VIEW: THREAT INTEL & FORENSICS */}
              {currentTab === 'threat_intel' && (
                <ThreatIntelForensicsView
                  target={currentTarget}
                  scanResult={scanResult}
                  onNavigateToScans={() => setCurrentTab('scans')}
                  onNavigateToRedTeam={() => setCurrentTab('redteam')}
                />
              )}

              {/* VIEW 4: COMPLIANCE MAP */}
              {currentTab === 'compliance' && (
                <ComplianceMapView
                  scanResult={scanResult}
                  onNavigate={setCurrentTab}
                  onSelectFinding={(f) => {
                    setSelectedFinding(f);
                    setCurrentTab('scans');
                  }}
                />
              )}

              {/* VIEW 5: SETTINGS */}
              {currentTab === 'settings' && (
                <SettingsView
                  settings={platformSettings}
                  onSaveSettings={(newSettings) => setPlatformSettings(newSettings)}
                />
              )}
            </>
          )}
        </main>
      </div>

      {/* MODAL: 3-Tier Remediation Engine Modal */}
      <RemediationModal
        finding={selectedFinding}
        initialTab={remediationTab}
        onClose={() => setSelectedFinding(null)}
        onApplyAndVerify={handleApplyAndVerify}
        isVerifying={isVerifying}
      />

      {/* MODAL: Target Intake Modal (APK, EXE, IPA, DMG, ZIP) */}
      <ProjectIntakeModal
        isOpen={isIntakeOpen}
        onClose={() => setIsIntakeOpen(false)}
        onSelectTarget={handleSelectTarget}
      />

      {/* MODAL: Audit Report Modal */}
      <AuditReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        scanResult={scanResult}
      />

      {/* DRAWER: AI Security Analyst Chat */}
      <AIAnalystChat
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        findings={scanResult?.findings || []}
        currentScore={scanResult?.scoreCurrent || 100}
      />
    </div>
  );
}
