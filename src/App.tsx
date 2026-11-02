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
import { SecurityEngine } from './services/securityEngine';

const INITIAL_TARGET: ScanTarget = {
  id: 'workspace-local',
  name: 'Local Application Workspace',
  type: 'local_dir',
  platform: 'web',
  language: 'Multi-Language Project',
  description: 'Live host filesystem workspace under security audit',
  scannedAt: new Date().toISOString(),
  totalLines: 0,
  files: []
};

const DEFAULT_PLATFORM_SETTINGS: PlatformSettings = {
  aiModel: 'gemini-3.8',
  enableSAST: true,
  enableSCA: true,
  enableSecrets: true,
  enableConfig: true,
  enableMobileStatic: true,
  enableBinaryStatic: true,
  enableWebRecon: true,
  enableSecurityHeaders: true,
  enableRedTeamSimulation: true,
  enablePurpleTeamAudit: true,
  autoGeneratePatches: true,
  autoVerifyPatches: true,
  complianceStandard: 'OWASP_TOP_10',
  minSeverityThreshold: 'LOW',
  strictMode: true
};

import { Sidebar } from './components/Sidebar';
import { OverviewView } from './components/views/OverviewView';
import { SecurityScansView } from './components/views/SecurityScansView';
import { RedTeamDashboardView } from './components/views/RedTeamDashboardView';
import { RemediationHubView } from './components/views/RemediationHubView';
import { ComplianceMapView } from './components/views/ComplianceMapView';
import { ThreatIntelForensicsView } from './components/views/ThreatIntelForensicsView';
import { DatasetView } from './components/views/DatasetView';
import { SettingsView } from './components/views/SettingsView';
import { ToolsDashboardView } from './components/views/ToolsDashboardView';

import { RemediationModal } from './components/RemediationModal';
import { ProjectIntakeModal, SavedScanHistoryItem } from './components/ProjectIntakeModal';
import { AuditReportModal, ReportType } from './components/AuditReportModal';
import { AIAnalystChat } from './components/AIAnalystChat';
import { ScanProgressView } from './components/ScanProgressView';
import { ReadyToScanView } from './components/ReadyToScanView';

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
  const [currentTarget, setCurrentTarget] = useState<ScanTarget>(INITIAL_TARGET);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [currentTab, setCurrentTab] = useState<NavigationTab>('overview');

  // Platform Settings State (persisted to LocalStorage and Backend Database)
  const [platformSettings, setPlatformSettings] = useState<PlatformSettings>(() => {
    try {
      const saved = localStorage.getItem('shield_platform_settings');
      if (saved) {
        return { ...DEFAULT_PLATFORM_SETTINGS, ...JSON.parse(saved) };
      }
    } catch {}
    return DEFAULT_PLATFORM_SETTINGS;
  });

  const handleSavePlatformSettings = (newSettings: PlatformSettings) => {
    setPlatformSettings(newSettings);
    try {
      localStorage.setItem('shield_platform_settings', JSON.stringify(newSettings));
    } catch {}
    fetch('/api/settings/platform', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newSettings)
    }).catch(() => {});
  };

  // Modal & Drawer States
  const [isIntakeOpen, setIsIntakeOpen] = useState(false);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [activeReportType, setActiveReportType] = useState<ReportType>('pentest');
  const [isChatOpen, setIsChatOpen] = useState(false);

  const handleOpenReport = (type: ReportType = 'pentest') => {
    setActiveReportType(type);
    setIsReportOpen(true);
  };
  const [selectedFinding, setSelectedFinding] = useState<VulnerabilityFinding | null>(null);
  const [remediationTab, setRemediationTab] = useState<'explain' | 'recommend' | 'fix' | 'verify'>('explain');
  const [isVerifying, setIsVerifying] = useState(false);
  const [isFixingAll, setIsFixingAll] = useState(false);
  const [activeToolsCount, setActiveToolsCount] = useState<number>(0);
  const [totalToolsCount, setTotalToolsCount] = useState<number>(18);
  const [scanHistory, setScanHistory] = useState<SavedScanHistoryItem[]>([]);

  // Helper: Persist active target, scan result & history list to Backend DB & LocalStorage
  const persistAuditState = (targetToSave: ScanTarget, resultToSave: ScanResult | null) => {
    setScanHistory(prev => {
      const updatedEntry: SavedScanHistoryItem = {
        target: targetToSave,
        scanResult: resultToSave,
        updatedAt: new Date().toISOString()
      };
      const existingIdx = prev.findIndex(
        item => item.target?.id === targetToSave.id || item.target?.name === targetToSave.name
      );
      let nextHistory: SavedScanHistoryItem[];
      if (existingIdx >= 0) {
        nextHistory = [...prev];
        nextHistory[existingIdx] = {
          ...nextHistory[existingIdx]!,
          target: targetToSave,
          scanResult: resultToSave || nextHistory[existingIdx]!.scanResult,
          updatedAt: new Date().toISOString()
        };
      } else {
        nextHistory = [updatedEntry, ...prev].slice(0, 30);
      }
      try {
        localStorage.setItem('appsec_audit_history_v1', JSON.stringify(nextHistory));
      } catch {}
      return nextHistory;
    });

    try {
      localStorage.setItem(
        'appsec_audit_state_v1',
        JSON.stringify({ activeTarget: targetToSave, activeScanResult: resultToSave })
      );
    } catch {}

    fetch('/api/db/state', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ activeTarget: targetToSave, activeScanResult: resultToSave })
    })
      .then(r => r.json())
      .then(data => {
        if (data.success && Array.isArray(data.scanHistory)) {
          setScanHistory(data.scanHistory);
          try {
            localStorage.setItem('appsec_audit_history_v1', JSON.stringify(data.scanHistory));
          } catch {}
        }
      })
      .catch(() => {});
  };

  // Switch between previously scanned websites/apps
  const handleSwitchToSavedTarget = (entry: SavedScanHistoryItem) => {
    setCurrentTarget(entry.target);
    setScanResult(entry.scanResult);
    persistAuditState(entry.target, entry.scanResult);
  };

  // Delete a target from scan history
  const handleDeleteSavedTarget = (targetId: string) => {
    setScanHistory(prev => {
      const filtered = prev.filter(item => item.target?.id !== targetId);
      try {
        localStorage.setItem('appsec_audit_history_v1', JSON.stringify(filtered));
      } catch {}
      return filtered;
    });

    // If deleting the currently active target, switch to the first remaining target or reset cleanly
    if (currentTarget?.id === targetId) {
      const remaining = scanHistory.filter(item => item.target?.id !== targetId);
      if (remaining.length > 0 && remaining[0]) {
        setCurrentTarget(remaining[0].target);
        setScanResult(remaining[0].scanResult);
        persistAuditState(remaining[0].target, remaining[0].scanResult);
      } else {
        setCurrentTarget(INITIAL_TARGET);
        setScanResult(null);
        persistAuditState(INITIAL_TARGET, null);
      }
    }

    fetch(`/api/db/history/${encodeURIComponent(targetId)}`, {
      method: 'DELETE'
    }).catch(() => {});
  };

  // Initial Real-Time Workspace Scan, DB Restoration & Tool Verification on Mount
  useEffect(() => {
    // 1. Verify installed security tools & engines
    fetch('/api/tools/status?verify=true')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.summary) {
          setActiveToolsCount(data.summary.activeTools ?? 0);
          setTotalToolsCount(data.summary.totalTools ?? 18);
        }
      })
      .catch(() => { });

    // 2. Restore previously scanned website or app + full scan history from Backend DB (with LocalStorage fallback)
    let restoredFromLocal = false;
    try {
      const localHistoryRaw = localStorage.getItem('appsec_audit_history_v1');
      if (localHistoryRaw) {
        const parsedHist = JSON.parse(localHistoryRaw);
        if (Array.isArray(parsedHist)) {
          setScanHistory(parsedHist);
        }
      }
      const localRaw = localStorage.getItem('appsec_audit_state_v1');
      if (localRaw) {
        const parsed = JSON.parse(localRaw);
        if (parsed.activeTarget && parsed.activeTarget.id) {
          setCurrentTarget(parsed.activeTarget);
          if (parsed.activeScanResult) {
            setScanResult(parsed.activeScanResult);
          }
          restoredFromLocal = true;
        }
      }
    } catch {}

    fetch('/api/db/state')
      .then(res => res.json())
      .then(data => {
        if (data.success && Array.isArray(data.scanHistory)) {
          setScanHistory(data.scanHistory);
          try {
            localStorage.setItem('appsec_audit_history_v1', JSON.stringify(data.scanHistory));
          } catch {}
        }
        if (data.success && data.platformSettings) {
          setPlatformSettings(prev => {
            const merged = { ...prev, ...data.platformSettings };
            try {
              localStorage.setItem('shield_platform_settings', JSON.stringify(merged));
            } catch {}
            return merged;
          });
        }
        if (data.success && data.activeTarget && data.activeTarget.id) {
          setCurrentTarget(data.activeTarget);
          if (data.activeScanResult) {
            setScanResult(data.activeScanResult);
          }
          try {
            localStorage.setItem(
              'appsec_audit_state_v1',
              JSON.stringify({ activeTarget: data.activeTarget, activeScanResult: data.activeScanResult || null })
            );
          } catch {}
        } else if (!restoredFromLocal) {
          // Only ingest default local directory if no previous scan exists in DB
          fetch('/api/intake/local-dir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dirPath: '.' })
          })
            .then(r => r.json())
            .then(localData => {
              if (localData.success && localData.target && Array.isArray(localData.target.files) && localData.target.files.length > 0) {
                setCurrentTarget(localData.target);
              }
            })
            .catch(() => {});
        }
      })
      .catch(() => {
        if (!restoredFromLocal) {
          fetch('/api/intake/local-dir', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dirPath: '.' })
          })
            .then(r => r.json())
            .then(localData => {
              if (localData.success && localData.target && Array.isArray(localData.target.files) && localData.target.files.length > 0) {
                setCurrentTarget(localData.target);
              }
            })
            .catch(() => {});
        }
      });

    // 3. Restore platform settings from backend DB
    fetch('/api/settings/platform')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.settings) {
          setPlatformSettings(prev => {
            const merged = { ...prev, ...data.settings };
            try {
              localStorage.setItem('shield_platform_settings', JSON.stringify(merged));
            } catch {}
            return merged;
          });
        }
      })
      .catch(() => {});
  }, []);

  const runScan = async (target: ScanTarget) => {
    setIsScanning(true);
    // Smooth transition ensures rolling animation is clearly visible
    const minDelay = new Promise(resolve => setTimeout(resolve, 1500));
    try {
      const [result] = await Promise.all([
        SecurityEngine.scanCodebaseAsync(target, platformSettings),
        minDelay
      ]);
      setScanResult(result);
      persistAuditState(target, result);
    } catch (e) {
      await minDelay;
      const fallback = SecurityEngine.scanCodebase(target, platformSettings);
      setScanResult(fallback);
      persistAuditState(target, fallback);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectTarget = (target: ScanTarget) => {
    setCurrentTarget(target);
    setScanResult(null);
    persistAuditState(target, null);
    setCurrentTab('overview');
    // After app is uploaded or web link added, immediately trigger the rolling animation scan
    runScan(target);
  };

  // Full Rerun of the entire scan process (clears old data & re-probes live URL, IP & API endpoints)
  const handleFullRerun = async () => {
    if (!currentTarget) return;
    setIsScanning(true);
    setScanResult(null); // Clear previous scan results so fresh live probe and clean scan are displayed
    try {
      let targetToScan = currentTarget;
      const liveUrl = currentTarget.websiteMetadata?.url;
      if (liveUrl) {
        try {
          const probeRes = await fetch('/api/scan/dast/http-probe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: liveUrl })
          });
          const probeData = await probeRes.json();
          if (probeRes.ok && probeData.success) {
            const refreshed = SecurityEngine.createDynamicWebsiteTarget(liveUrl, probeData);
            // Keep same target ID so history updates cleanly
            targetToScan = { ...refreshed, id: currentTarget.id };
            setCurrentTarget(targetToScan);
          }
        } catch {}
      }
      await runScan(targetToScan);
    } finally {
      setIsScanning(false);
    }
  };

  // Selective Retest for 1 or multiple specific vulnerabilities
  const handleRetestSelected = async (findingIds: string[]) => {
    if (!currentTarget || !scanResult || findingIds.length === 0) return;
    setIsVerifying(true);
    try {
      let targetToTest = currentTarget;
      const liveUrl = currentTarget.websiteMetadata?.url;
      const hasUnmodifiedWebFile = currentTarget.files.some(f => !f.isModified);

      if (liveUrl && hasUnmodifiedWebFile) {
        try {
          const probeRes = await fetch('/api/scan/dast/http-probe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: liveUrl })
          });
          const probeData = await probeRes.json();
          if (probeRes.ok && probeData.success) {
            const freshWebTarget = SecurityEngine.createDynamicWebsiteTarget(liveUrl, probeData);
            // Merge: preserve any locally patched files while updating unpatched live files
            const mergedFiles = currentTarget.files.map(existingFile => {
              if (existingFile.isModified) return existingFile;
              const freshFile = freshWebTarget.files.find(ff => ff.path === existingFile.path);
              return freshFile || existingFile;
            });
            targetToTest = {
              ...freshWebTarget,
              id: currentTarget.id,
              files: mergedFiles
            };
            setCurrentTarget(targetToTest);
          }
        } catch {}
      }

      const updatedResult = SecurityEngine.retestSelectedFindings(
        targetToTest,
        scanResult.findings,
        findingIds,
        platformSettings
      );
      setScanResult(updatedResult);
      persistAuditState(targetToTest, updatedResult);

      if (selectedFinding && findingIds.includes(selectedFinding.id)) {
        const refreshedFinding = updatedResult.findings.find(f => f.id === selectedFinding.id);
        if (refreshedFinding) {
          setSelectedFinding(refreshedFinding);
        }
      }
    } finally {
      setIsVerifying(false);
    }
  };

  const handleRescan = async () => {
    if (!currentTarget) return;
    setIsScanning(true);
    setScanResult(null); // Clear previous scan data so fresh rolling animation & scan results display
    const minDelay = new Promise(resolve => setTimeout(resolve, 1500));
    try {
      let targetToScan = currentTarget;
      const liveUrl = currentTarget.websiteMetadata?.url;
      if (liveUrl) {
        try {
          const probeRes = await fetch('/api/scan/dast/http-probe', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: liveUrl })
          });
          const probeData = await probeRes.json();
          if (probeRes.ok && probeData.success) {
            const refreshed = SecurityEngine.createDynamicWebsiteTarget(liveUrl, probeData);
            targetToScan = { ...refreshed, id: currentTarget.id };
            setCurrentTarget(targetToScan);
          }
        } catch {}
      }
      const [updated] = await Promise.all([
        SecurityEngine.scanCodebaseAsync(targetToScan, platformSettings),
        minDelay
      ]);
      setScanResult(updated);
      persistAuditState(targetToScan, updated);
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

      // 2. Call real Linux backend sandbox test & CLI re-scan verifier
      const patchedFileContent = updatedFiles[targetFileIndex]?.content || '';
      let backendVerifyProof: any = null;
      try {
        const verifyRes = await fetch('/api/verify-patch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            targetId: currentTarget.id,
            file: patch.fileModified,
            beforeCode: patch.beforeCode,
            afterCode: patch.afterCode,
            updatedFileContent: patchedFileContent,
            finding
          })
        });
        const verifyData = await verifyRes.json();
        if (verifyRes.ok && verifyData.success) {
          backendVerifyProof = {
            testPassed: Boolean(verifyData.testPassed),
            beforeExecutionLog: verifyData.beforeExecutionLog,
            afterExecutionLog: verifyData.afterExecutionLog,
            rescanConfirmedClean: Boolean(verifyData.rescanConfirmedClean),
            verificationHash: verifyData.verificationHash
          };
        }
      } catch { }

      // 3. Automated Rescan & Verification Evaluation
      const updatedScanResult = SecurityEngine.verifyAndRescan(updatedTarget, scanResult.findings);
      if (backendVerifyProof) {
        updatedScanResult.findings = updatedScanResult.findings.map(f =>
          f.id === finding.id
            ? {
              ...f,
              status: 'VERIFIED_RESOLVED',
              verifiedAt: new Date().toISOString(),
              verificationProof: backendVerifyProof
            }
            : f
        );
      }
      setScanResult(updatedScanResult);
      persistAuditState(updatedTarget, updatedScanResult);

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
    persistAuditState(updatedTarget, freshResult);
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
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        target={currentTarget}
        scanResult={scanResult}
        onOpenIntake={() => setIsIntakeOpen(true)}
        onOpenReport={() => handleOpenReport('pentest')}
        onRescan={handleRescan}
        isRescanning={isScanning}
        activeToolsCount={activeToolsCount}
        totalToolsCount={totalToolsCount}
        scanHistory={scanHistory}
        onSwitchTarget={handleSwitchToSavedTarget}
        onDeleteTarget={handleDeleteSavedTarget}
      />

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
            {/* Live Verified Tools Status Pill */}
            <button
              onClick={() => setCurrentTab('tools')}
              className="flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-emerald-950/50 hover:bg-emerald-900/50 border border-emerald-700/50 text-emerald-300 text-xs font-mono font-bold transition-all cursor-pointer"
              title="Open Security Auditor Tools & Engines Verification Dashboard"
            >
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Tools: {activeToolsCount}/{totalToolsCount} Active</span>
            </button>

            {/* AI Assistant Chat Trigger */}
            <button
              onClick={() => setIsChatOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-[#141414] hover:bg-[#1E1E1E] border border-[#1F1F1F] text-gray-300 hover:text-white text-xs font-mono transition-all"
            >
              <MessageSquare className="h-3.5 w-3.5 text-blue-400" />
              <span>AI Security Analyst</span>
            </button>

            {/* Ingest Binary or Switch Target */}
            <button
              onClick={() => setIsIntakeOpen(true)}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow"
            >
              <PlusCircle className="h-3.5 w-3.5" />
              <span>Switch / New Target {scanHistory.length > 0 ? `(${scanHistory.length})` : ''}</span>
            </button>
          </div>
        </header>

        {/* Dynamic Page Views */}
        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          {/* ALWAYS ACCESSIBLE INDEPENDENT VIEWS */}
          {currentTab === 'tools' && (
            <ToolsDashboardView
              onToolsStatusUpdated={(active, total) => {
                setActiveToolsCount(active);
                setTotalToolsCount(total);
              }}
            />
          )}

          {currentTab === 'settings' && (
            <SettingsView
              settings={platformSettings}
              onSaveSettings={handleSavePlatformSettings}
            />
          )}

          {currentTab === 'datasets' && (
            <DatasetView />
          )}

          {/* SECURITY AUDIT VIEWS (OVERVIEW, SCANS, REDTEAM, REMEDIATION, THREAT INTEL, COMPLIANCE) */}
          {currentTab !== 'tools' && currentTab !== 'settings' && currentTab !== 'datasets' && (
            <>
              {isScanning ? (
                /* Rolling animation when scanning after app uploaded or web link added */
                <ScanProgressView
                  target={currentTarget}
                  activeToolsCount={activeToolsCount}
                  totalToolsCount={totalToolsCount}
                />
              ) : !scanResult ? (
                /* Ready to scan message before vulnerability scan */
                <ReadyToScanView
                  target={currentTarget}
                  onStartScan={() => runScan(currentTarget)}
                  onOpenIntake={() => setIsIntakeOpen(true)}
                  onOpenTools={() => setCurrentTab('tools')}
                  activeToolsCount={activeToolsCount}
                  totalToolsCount={totalToolsCount}
                />
              ) : (
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
                      onOpenReport={handleOpenReport}
                    />
                  )}

                  {/* VIEW 2: SECURITY SCANS */}
                  {currentTab === 'scans' && (
                    <SecurityScansView
                      scanResult={scanResult}
                      target={currentTarget}
                      selectedFinding={selectedFinding}
                      onSelectFinding={(f) => setSelectedFinding(f)}
                      onOpenRemediation={(f, tab) => {
                        setSelectedFinding(f);
                        handleOpenFindingModal(f, tab || 'explain');
                      }}
                      onRetestSelected={handleRetestSelected}
                      onRerunFullScan={handleFullRerun}
                      isRetesting={isVerifying || isScanning}
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
                </>
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
        onRetestFinding={(f) => handleRetestSelected([f.id])}
        onRerunFullScan={handleFullRerun}
        isVerifying={isVerifying}
      />

      {/* MODAL: Target Intake Modal (APK, EXE, IPA, DMG, ZIP, Live URL, Saved History) */}
      <ProjectIntakeModal
        isOpen={isIntakeOpen}
        onClose={() => setIsIntakeOpen(false)}
        onSelectTarget={handleSelectTarget}
        scanHistory={scanHistory}
        activeTargetId={currentTarget.id}
        onSwitchToSavedTarget={handleSwitchToSavedTarget}
        onDeleteSavedTarget={handleDeleteSavedTarget}
      />

      {/* MODAL: Audit Report Modal */}
      <AuditReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        scanResult={scanResult}
        initialReportType={activeReportType}
      />

      {/* DRAWER: AI Security Analyst Chat */}
      <AIAnalystChat
        isOpen={isChatOpen}
        onClose={() => setIsChatOpen(false)}
        findings={scanResult?.findings || []}
        currentScore={scanResult?.scoreCurrent || 100}
        target={currentTarget}
      />
    </div>
  );
}
