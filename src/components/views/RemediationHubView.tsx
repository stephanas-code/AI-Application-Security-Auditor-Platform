import React, { useState } from 'react';
import { 
  ScanResult, 
  VulnerabilityFinding, 
  ScanTarget,
  ProposedPatch
} from '../../types';
import { 
  Wrench, 
  CheckCircle2, 
  Zap, 
  ShieldCheck, 
  AlertTriangle, 
  FileCode, 
  ArrowRight, 
  Play, 
  Terminal, 
  Check, 
  RefreshCw,
  Sparkles,
  Lock,
  Layers
} from 'lucide-react';

interface RemediationHubViewProps {
  scanResult: ScanResult;
  target: ScanTarget;
  onApplyPatch: (finding: VulnerabilityFinding) => void;
  onApplyAllPatches: () => void;
  onRescan: () => void;
  isRescanning?: boolean;
}

export const RemediationHubView: React.FC<RemediationHubViewProps> = ({
  scanResult,
  target,
  onApplyPatch,
  onApplyAllPatches,
  onRescan,
  isRescanning
}) => {
  const [activeFilter, setActiveFilter] = useState<'ALL' | 'PENDING' | 'RESOLVED'>('PENDING');
  const [executingTestId, setExecutingTestId] = useState<string | null>(null);

  const findingsWithPatches = scanResult.findings.filter(f => f.proposedPatch);
  
  const pendingPatches = findingsWithPatches.filter(f => f.status !== 'VERIFIED_RESOLVED');
  const resolvedPatches = findingsWithPatches.filter(f => f.status === 'VERIFIED_RESOLVED');

  const displayedFindings = findingsWithPatches.filter(f => {
    if (activeFilter === 'PENDING') return f.status !== 'VERIFIED_RESOLVED';
    if (activeFilter === 'RESOLVED') return f.status === 'VERIFIED_RESOLVED';
    return true;
  });

  const handleRunVerificationTest = (findingId: string) => {
    setExecutingTestId(findingId);
    setTimeout(() => {
      setExecutingTestId(null);
      onRescan();
    }, 1200);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Action Header */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Wrench className="h-5 w-5 text-emerald-400" />
            <h1 className="text-base font-black text-white uppercase tracking-wider">
              Autonomous Remediation & Verification Hub
            </h1>
          </div>
          <p className="text-xs text-gray-400 mt-1 max-w-2xl leading-relaxed">
            Review AI-generated syntactic patches, inspect unified diffs, apply deterministic fixes, and execute cryptographic verification tests.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          {pendingPatches.length > 0 && (
            <button
              onClick={onApplyAllPatches}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-black font-black text-xs uppercase tracking-wider transition-all shadow-lg"
            >
              <Zap className="h-4 w-4" />
              <span>Apply All ({pendingPatches.length}) Safe Patches</span>
            </button>
          )}
          <button
            onClick={onRescan}
            disabled={isRescanning}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#1A1A1A] hover:bg-[#222222] border border-[#2A2A2A] text-white font-bold text-xs uppercase tracking-wider transition-all disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRescanning ? 'animate-spin text-blue-400' : ''}`} />
            <span>Re-Verify Target</span>
          </button>
        </div>
      </div>

      {/* Stats Summary Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F]">
          <span className="text-[11px] font-mono text-gray-500 uppercase block">Total Fixes Generated</span>
          <span className="text-xl font-black text-white mt-1 block">{findingsWithPatches.length}</span>
        </div>
        <div className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F]">
          <span className="text-[11px] font-mono text-gray-500 uppercase block">Pending Patches</span>
          <span className="text-xl font-black text-amber-400 mt-1 block">{pendingPatches.length}</span>
        </div>
        <div className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F]">
          <span className="text-[11px] font-mono text-gray-500 uppercase block">Verified Resolved</span>
          <span className="text-xl font-black text-emerald-400 mt-1 block">{resolvedPatches.length}</span>
        </div>
        <div className="p-4 rounded-xl bg-[#141414] border border-[#1F1F1F]">
          <span className="text-[11px] font-mono text-gray-500 uppercase block">Verification Confidence</span>
          <span className="text-xl font-black text-blue-400 mt-1 block">
            {scanResult.metrics.verifiedPercentage}% Verified
          </span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center space-x-2 border-b border-[#1F1F1F] pb-2">
        <button
          onClick={() => setActiveFilter('PENDING')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeFilter === 'PENDING'
              ? 'bg-amber-950 text-amber-300 border border-amber-800'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          Pending Fixes ({pendingPatches.length})
        </button>
        <button
          onClick={() => setActiveFilter('RESOLVED')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeFilter === 'RESOLVED'
              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          Verified Resolved ({resolvedPatches.length})
        </button>
        <button
          onClick={() => setActiveFilter('ALL')}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
            activeFilter === 'ALL'
              ? 'bg-[#222222] text-white'
              : 'text-gray-400 hover:text-white'
          }`}
        >
          All ({findingsWithPatches.length})
        </button>
      </div>

      {/* Patch Cards List */}
      <div className="space-y-4">
        {displayedFindings.map((finding) => {
          const patch = finding.proposedPatch!;
          const isResolved = finding.status === 'VERIFIED_RESOLVED';
          const isRunningTest = executingTestId === finding.id;

          return (
            <div
              key={finding.id}
              className={`p-5 rounded-2xl border transition-all ${
                isResolved
                  ? 'bg-[#101712] border-emerald-900/50'
                  : 'bg-[#111111] border-[#1F1F1F] hover:border-[#333333]'
              }`}
            >
              {/* Card Header */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#1A1A1A]">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      isResolved ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                      finding.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                      'bg-orange-950 text-orange-400 border border-orange-800'
                    }`}>
                      {isResolved ? 'VERIFIED RESOLVED' : finding.severity}
                    </span>
                    <span className="text-xs font-bold text-white">{finding.title}</span>
                  </div>
                  <p className="text-xs font-mono text-gray-500">{finding.file}:{finding.line} • {finding.cwe}</p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  {isResolved ? (
                    <div className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-emerald-950/60 border border-emerald-800 text-emerald-400 text-xs font-mono font-bold">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      <span>Fix Verified & Clean</span>
                    </div>
                  ) : (
                    <button
                      onClick={() => onApplyPatch(finding)}
                      className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-black font-black text-xs uppercase tracking-wider transition-all shadow"
                    >
                      <Zap className="h-3.5 w-3.5" />
                      <span>Apply Patch</span>
                    </button>
                  )}

                  {finding.testCase && (
                    <button
                      onClick={() => handleRunVerificationTest(finding.id)}
                      disabled={isRunningTest}
                      className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-[#1E1E1E] hover:bg-[#2A2A2A] border border-[#2E2E2E] text-gray-300 hover:text-white text-xs font-mono font-bold transition-all disabled:opacity-50"
                    >
                      <Play className={`h-3 w-3 text-blue-400 ${isRunningTest ? 'animate-spin' : ''}`} />
                      <span>{isRunningTest ? 'Verifying...' : 'Run Unit Test'}</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Patch Explanation & Safety */}
              <div className="py-3 flex items-center justify-between text-xs text-gray-400">
                <span className="leading-relaxed">{patch.explanation}</span>
                <span className="px-2 py-0.5 rounded bg-[#1A1A1A] border border-[#2A2A2A] font-mono text-[10px] text-emerald-400 shrink-0 ml-3">
                  Safety: {patch.safetyRating.replace('_', ' ')}
                </span>
              </div>

              {/* Code Diff Display */}
              <div className="mt-2 rounded-xl overflow-hidden border border-[#222222] bg-black font-mono text-xs">
                <div className="px-4 py-2 bg-[#161616] border-b border-[#222222] flex items-center justify-between text-gray-400 text-[11px]">
                  <span>Unified Code Diff • {finding.file}</span>
                  <span className="text-gray-500">Lines {patch.startLine} - {patch.endLine}</span>
                </div>
                <div className="p-3 text-[11px] overflow-x-auto leading-relaxed space-y-0.5">
                  {patch.diff.split('\n').map((line, idx) => {
                    const isAddition = line.startsWith('+');
                    const isDeletion = line.startsWith('-');
                    return (
                      <div
                        key={idx}
                        className={`px-2 py-0.5 rounded ${
                          isAddition ? 'bg-emerald-950/40 text-emerald-300 font-bold' :
                          isDeletion ? 'bg-red-950/40 text-red-400 line-through opacity-80' :
                          'text-gray-400'
                        }`}
                      >
                        {line}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Cryptographic Verification Proof (If Resolved) */}
              {isResolved && finding.verificationProof && (
                <div className="mt-3 p-3 rounded-xl bg-[#0B150F] border border-emerald-900/60 font-mono text-xs space-y-2">
                  <div className="flex items-center justify-between text-emerald-400 text-[11px] font-bold">
                    <span className="flex items-center space-x-1.5">
                      <ShieldCheck className="h-4 w-4" />
                      <span>Cryptographic Verification Certificate</span>
                    </span>
                    <span className="text-gray-400">{finding.verificationProof.verificationHash}</span>
                  </div>
                  <pre className="text-[10px] text-emerald-200/90 leading-snug whitespace-pre-wrap">
                    {finding.verificationProof.afterExecutionLog}
                  </pre>
                </div>
              )}
            </div>
          );
        })}

        {displayedFindings.length === 0 && (
          <div className="p-12 text-center bg-[#111111] border border-[#1F1F1F] rounded-2xl text-xs text-gray-500 font-mono">
            {activeFilter === 'PENDING' ? 'All vulnerability patches have been applied and verified!' : 'No patches in this view.'}
          </div>
        )}
      </div>
    </div>
  );
};
