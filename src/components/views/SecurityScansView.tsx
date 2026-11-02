import React, { useState } from 'react';
import { 
  VulnerabilityFinding, 
  ScanResult, 
  ScanTarget, 
  FindingCategory, 
  SeverityLevel 
} from '../../types';
import { CodebaseViewer } from '../CodebaseViewer';
import { DASTProbeSimulator } from '../DASTProbeSimulator';
import { getFindingClarityDetails } from '../../utils/findingClarity';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  Smartphone, 
  Monitor, 
  FileCode, 
  Key, 
  Package, 
  Server, 
  CheckCircle2, 
  Zap,
  Play,
  Eye,
  RefreshCw,
  CheckSquare,
  Square,
  Radar,
  Wrench
} from 'lucide-react';

interface SecurityScansViewProps {
  scanResult: ScanResult;
  target: ScanTarget;
  selectedFinding: VulnerabilityFinding | null;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  onOpenRemediation: (finding: VulnerabilityFinding, initialTab?: 'explain' | 'recommend' | 'fix') => void;
  onRetestSelected?: (findingIds: string[]) => void;
  onRerunFullScan?: () => void;
  isRetesting?: boolean;
}

export const SecurityScansView: React.FC<SecurityScansViewProps> = ({
  scanResult,
  target,
  selectedFinding,
  onSelectFinding,
  onOpenRemediation,
  onRetestSelected,
  onRerunFullScan,
  isRetesting = false
}) => {
  const [categoryFilter, setCategoryFilter] = useState<FindingCategory | 'ALL'>('ALL');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'ALL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeInspectorTab, setActiveInspectorTab] = useState<'code' | 'dast' | 'details'>('code');
  const [selectedRetestIds, setSelectedRetestIds] = useState<string[]>([]);

  const categories: Array<{ id: FindingCategory | 'ALL'; label: string; icon: any }> = [
    { id: 'ALL', label: 'All Categories', icon: Filter },
    { id: 'SAST', label: 'Static Code (SAST)', icon: FileCode },
    { id: 'SECRETS', label: 'Secrets & Keys', icon: Key },
    { id: 'SCA', label: 'Dependencies (SCA)', icon: Package },
    { id: 'CONFIG', label: 'Config & Infra', icon: Server },
    { id: 'MOBILE_STATIC', label: 'Mobile (APK/IPA)', icon: Smartphone },
    { id: 'BINARY_STATIC', label: 'Binary (EXE/DMG)', icon: Monitor }
  ];

  const filteredFindings = scanResult.findings.filter(f => {
    if (categoryFilter !== 'ALL' && f.category !== categoryFilter) return false;
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        f.title.toLowerCase().includes(q) ||
        f.cwe.toLowerCase().includes(q) ||
        f.file.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const activeFinding = selectedFinding || filteredFindings[0] || null;
  const activeClarity = activeFinding ? getFindingClarityDetails(activeFinding) : null;

  const toggleRetestSelection = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedRetestIds(prev =>
      prev.includes(id) ? prev.filter(item => item !== id) : [...prev, id]
    );
  };

  const toggleSelectAllFiltered = () => {
    if (selectedRetestIds.length === filteredFindings.length && filteredFindings.length > 0) {
      setSelectedRetestIds([]);
    } else {
      setSelectedRetestIds(filteredFindings.map(f => f.id));
    }
  };

  return (
    <div className="space-y-5 pb-12">
      {/* Header & Filter Controls */}
      <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <ShieldAlert className="h-5 w-5 text-blue-400" />
              <h1 className="text-base font-black text-white uppercase tracking-wider">Security Vulnerability Scanner</h1>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Multi-engine inspection across SAST, Secrets, SCA, Cloud Config, Web Headers, and Mobile/Desktop Binary signatures.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Search Bar */}
            <div className="relative min-w-[230px]">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-gray-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings, CWE, files..."
                className="w-full pl-9 pr-3 py-2 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white placeholder-gray-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>

            {/* Rerun Full Process Button */}
            {onRerunFullScan && (
              <button
                onClick={onRerunFullScan}
                disabled={isRetesting}
                className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-bold uppercase tracking-wider transition-all shadow cursor-pointer"
                title="Rerun the entire vulnerability scan process from scratch"
              >
                <RefreshCw className={`h-3.5 w-3.5 ${isRetesting ? 'animate-spin' : ''}`} />
                <span>Rerun Full Scan</span>
              </button>
            )}
          </div>
        </div>

        {/* Categories Bar */}
        <div className="flex items-center space-x-1.5 overflow-x-auto pb-1">
          {categories.map((cat) => {
            const Icon = cat.icon;
            const count = cat.id === 'ALL' 
              ? scanResult.findings.length 
              : scanResult.findings.filter(f => f.category === cat.id).length;
            const isActive = categoryFilter === cat.id;

            return (
              <button
                key={cat.id}
                onClick={() => setCategoryFilter(cat.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all cursor-pointer ${
                  isActive
                    ? 'bg-blue-600 text-white shadow'
                    : 'bg-[#161616] text-gray-400 hover:text-white border border-[#1F1F1F]'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{cat.label}</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono ${isActive ? 'bg-blue-800 text-white' : 'bg-[#222222] text-gray-400'}`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        {/* Severity Selector */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-[#1A1A1A] text-xs font-mono">
          <span className="text-gray-500 text-[11px] uppercase tracking-wider font-bold">Severity:</span>
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-lg text-[10px] font-bold uppercase transition-all cursor-pointer ${
                severityFilter === sev
                  ? sev === 'CRITICAL' ? 'bg-red-600 text-white' :
                    sev === 'HIGH' ? 'bg-orange-600 text-white' :
                    sev === 'MEDIUM' ? 'bg-amber-600 text-black' :
                    'bg-blue-600 text-white'
                  : 'bg-[#161616] text-gray-400 hover:text-white border border-[#1F1F1F]'
              }`}
            >
              {sev}
            </button>
          ))}
          <span className="text-gray-500 ml-auto text-[11px]">
            Showing {filteredFindings.length} of {scanResult.findings.length} findings
          </span>
        </div>
      </div>

      {/* Main 2-Column Finding Explorer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Left Column: Finding Cards List (5 Cols) */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3 bg-[#111111] border border-[#1F1F1F] rounded-xl flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-gray-400">
            <div className="flex items-center space-x-2">
              <button
                onClick={toggleSelectAllFiltered}
                className="flex items-center space-x-1.5 text-gray-300 hover:text-white cursor-pointer"
                title="Select or deselect findings to retest"
              >
                {selectedRetestIds.length === filteredFindings.length && filteredFindings.length > 0 ? (
                  <CheckSquare className="h-4 w-4 text-blue-400" />
                ) : (
                  <Square className="h-4 w-4 text-gray-500" />
                )}
                <span className="font-bold">Finding Records ({filteredFindings.length})</span>
              </button>
            </div>

            <div className="flex items-center space-x-2">
              {selectedRetestIds.length > 0 && onRetestSelected && (
                <button
                  onClick={() => onRetestSelected(selectedRetestIds)}
                  disabled={isRetesting}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-[10px] font-bold uppercase tracking-wider transition-all cursor-pointer"
                >
                  <RefreshCw className={`h-3 w-3 ${isRetesting ? 'animate-spin' : ''}`} />
                  <span>Retest Selected ({selectedRetestIds.length})</span>
                </button>
              )}
            </div>
          </div>

          <div className="space-y-2.5 max-h-[750px] overflow-y-auto pr-1">
            {filteredFindings.map((finding) => {
              const isSelected = activeFinding?.id === finding.id;
              const isResolved = finding.status === 'VERIFIED_RESOLVED';
              const isChecked = selectedRetestIds.includes(finding.id);

              return (
                <div
                  key={finding.id}
                  onClick={() => onSelectFinding(finding)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-[#181818] border-blue-500/80 shadow-lg'
                      : isResolved
                      ? 'bg-[#101914] border-emerald-900/40 hover:border-emerald-700/60 opacity-85'
                      : 'bg-[#141414] border-[#1F1F1F] hover:border-[#333333] hover:bg-[#161616]'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-start space-x-2.5 min-w-0">
                      {/* Select Checkbox for Selective Retest */}
                      <button
                        type="button"
                        onClick={(e) => toggleRetestSelection(finding.id, e)}
                        className="mt-0.5 text-gray-500 hover:text-blue-400 transition-colors cursor-pointer shrink-0"
                        title="Select this vulnerability to retest"
                      >
                        {isChecked ? (
                          <CheckSquare className="h-4 w-4 text-blue-400" />
                        ) : (
                          <Square className="h-4 w-4" />
                        )}
                      </button>

                      <div className="space-y-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                            isResolved ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                            finding.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                            finding.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                            'bg-amber-950 text-amber-400 border border-amber-800'
                          }`}>
                            {isResolved ? 'RESOLVED' : finding.severity}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-[#1C1C1C] text-gray-400 font-mono text-[9px] border border-[#2A2A2A]">
                            {finding.cwe}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-blue-950/60 text-blue-400 font-mono text-[9px] border border-blue-900/50 uppercase">
                            {finding.category}
                          </span>
                        </div>
                        <h4 className="text-xs font-bold text-white truncate">{finding.title}</h4>
                        <p className="text-[11px] font-mono text-gray-500 truncate">{finding.file}:{finding.line}</p>
                      </div>
                    </div>

                    <div className="text-right shrink-0">
                      <span className="text-[10px] font-mono font-bold text-gray-400 block">CVSS {finding.cvssScore}</span>
                      {finding.proposedPatch && !isResolved && (
                        <span className="inline-flex items-center space-x-1 text-[10px] font-mono text-blue-400 mt-1">
                          <Zap className="h-3 w-3" />
                          <span>Patch Ready</span>
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Action Bar inside Finding Record Card: View More, Retest, Remediate */}
                  <div className="flex items-center justify-between gap-2 mt-3 pt-2.5 border-t border-[#1F1F1F]/80">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenRemediation(finding, 'explain');
                      }}
                      className="flex-1 flex items-center justify-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-[#1E1E1E] hover:bg-[#282828] border border-blue-500/40 text-blue-400 hover:text-blue-300 text-[10px] font-bold uppercase tracking-wider transition-all cursor-pointer"
                    >
                      <Eye className="h-3 w-3" />
                      <span>View More</span>
                    </button>

                    {onRetestSelected && (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          onRetestSelected([finding.id]);
                        }}
                        disabled={isRetesting}
                        className="flex items-center justify-center space-x-1 px-2.5 py-1.5 rounded-lg bg-[#1A1A1A] hover:bg-[#252525] border border-[#2D2D2D] text-emerald-400 hover:text-emerald-300 text-[10px] font-bold uppercase tracking-wider transition-all cursor-pointer"
                        title="Retest only this vulnerability"
                      >
                        <RefreshCw className={`h-3 w-3 ${isRetesting ? 'animate-spin' : ''}`} />
                        <span>Retest</span>
                      </button>
                    )}

                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpenRemediation(finding, 'fix');
                      }}
                      className="flex items-center justify-center space-x-1 px-2.5 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 text-[10px] font-bold uppercase tracking-wider transition-all cursor-pointer"
                    >
                      <Zap className="h-3 w-3" />
                      <span>{isResolved ? 'Proof' : 'Patch'}</span>
                    </button>
                  </div>
                </div>
              );
            })}

            {filteredFindings.length === 0 && (
              <div className="p-8 text-center bg-[#111111] border border-[#1F1F1F] rounded-2xl text-xs text-gray-500 font-mono">
                No vulnerabilities match the current filter selection.
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Deep Inspection Panel (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          {activeFinding ? (
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-5">
              {/* Finding Title & Top Actions */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-[#1F1F1F]">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                      activeFinding.status === 'VERIFIED_RESOLVED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                      activeFinding.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                      'bg-orange-950 text-orange-400 border border-orange-800'
                    }`}>
                      {activeFinding.status === 'VERIFIED_RESOLVED' ? 'VERIFIED RESOLVED' : activeFinding.severity}
                    </span>
                    <span className="text-xs font-mono text-gray-400">{activeFinding.cwe} ({activeFinding.cweName})</span>
                  </div>
                  <h2 className="text-base font-bold text-white mt-1.5">{activeFinding.title}</h2>
                  <p className="text-xs font-mono text-gray-500 mt-0.5">{activeFinding.file} (Line {activeFinding.line})</p>
                </div>

                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    onClick={() => onOpenRemediation(activeFinding, 'explain')}
                    className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-[#1E1E1E] hover:bg-[#282828] border border-blue-500/40 text-blue-400 hover:text-blue-300 text-xs font-bold uppercase tracking-wider transition-all cursor-pointer"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    <span>View More</span>
                  </button>

                  {onRetestSelected && (
                    <button
                      onClick={() => onRetestSelected([activeFinding.id])}
                      disabled={isRetesting}
                      className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-700/50 text-emerald-300 text-xs font-bold uppercase tracking-wider transition-all cursor-pointer"
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${isRetesting ? 'animate-spin' : ''}`} />
                      <span>Retest Vuln</span>
                    </button>
                  )}

                  {activeFinding.proposedPatch && (
                    <button
                      onClick={() => onOpenRemediation(activeFinding, 'fix')}
                      className="flex items-center space-x-1.5 px-4 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow cursor-pointer"
                    >
                      <Zap className="h-3.5 w-3.5" />
                      <span>Remediate / Patch</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Inspector View Mode Tabs */}
              <div className="flex items-center space-x-2 border-b border-[#1F1F1F] pb-2">
                <button
                  onClick={() => setActiveInspectorTab('code')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    activeInspectorTab === 'code'
                      ? 'bg-[#222222] text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Codebase & Highlight
                </button>
                <button
                  onClick={() => setActiveInspectorTab('details')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                    activeInspectorTab === 'details'
                      ? 'bg-[#222222] text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  Full Vulnerability Details
                </button>
                {activeFinding.testCase && (
                  <button
                    onClick={() => setActiveInspectorTab('dast')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all flex items-center space-x-1.5 cursor-pointer ${
                      activeInspectorTab === 'dast'
                        ? 'bg-[#222222] text-white'
                        : 'text-gray-400 hover:text-white'
                    }`}
                  >
                    <Play className="h-3 w-3 text-emerald-400" />
                    <span>Dynamic DAST Probe</span>
                  </button>
                )}
              </div>

              {/* Tab 1: Code View */}
              {activeInspectorTab === 'code' && (
                <div className="space-y-4">
                  <CodebaseViewer
                    target={target}
                    findings={scanResult.findings}
                    activeFinding={activeFinding}
                    onOpenFinding={(f, tab) => onOpenRemediation(f, tab || 'explain')}
                  />
                  <div className="p-4 rounded-xl bg-[#161616] border border-[#1F1F1F] flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-gray-400">
                    <div>
                      <span className="font-bold text-white block mb-1">Security Impact & Detection Summary:</span>
                      {activeFinding.businessImpact || activeFinding.description}
                    </div>
                    <button
                      onClick={() => onOpenRemediation(activeFinding, 'explain')}
                      className="px-3.5 py-2 rounded-xl bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 font-bold uppercase tracking-wider text-xs shrink-0 flex items-center space-x-1.5 cursor-pointer"
                    >
                      <Eye className="h-3.5 w-3.5" />
                      <span>View More Details</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Tab 2: Detailed Root Cause, Detection, Verification & Patch Analysis */}
              {activeInspectorTab === 'details' && activeClarity && (
                <div className="space-y-4">
                  <div className="p-4 rounded-xl bg-[#161616] border border-[#1F1F1F] space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-red-400 font-bold">1. Vulnerability Type & Root Cause</span>
                    <p className="text-xs text-gray-200 leading-relaxed">{activeClarity.plainSummary}</p>
                    <p className="text-xs text-blue-300 italic pt-1">Root Cause: {activeFinding.rootCause}</p>
                  </div>

                  <div className="p-4 rounded-xl bg-[#161616] border border-[#1F1F1F] space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
                      <Radar className="h-3.5 w-3.5" />
                      <span>2. How Detected ({activeClarity.detectionEngine})</span>
                    </span>
                    <p className="text-xs text-gray-300 leading-relaxed">{activeClarity.detectionExplanation}</p>
                  </div>

                  <div className="p-4 rounded-xl bg-[#161616] border border-amber-900/30 space-y-2">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
                      <Eye className="h-3.5 w-3.5" />
                      <span>3. Safe Verification Steps ({activeClarity.verificationEnvironment})</span>
                    </span>
                    <ol className="text-xs text-gray-300 space-y-1.5 list-decimal list-inside leading-relaxed">
                      {activeClarity.safeVerificationSteps.map((s, idx) => (
                        <li key={idx}>{s}</li>
                      ))}
                    </ol>
                  </div>

                  <div className="p-4 rounded-xl bg-[#161616] border border-emerald-900/30 space-y-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1.5">
                      <Wrench className="h-3.5 w-3.5" />
                      <span>4. Recommended Patch & Engineering Fix</span>
                    </span>
                    <p className="text-xs text-gray-300 leading-relaxed">{activeFinding.recommendation}</p>
                  </div>
                </div>
              )}

              {/* Tab 3: DAST Probe Simulator */}
              {activeInspectorTab === 'dast' && activeFinding.testCase && (
                <div className="space-y-4">
                  <DASTProbeSimulator
                    finding={activeFinding}
                    testCase={activeFinding.testCase}
                  />
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center bg-[#111111] border border-[#1F1F1F] rounded-2xl text-xs text-gray-500 font-mono">
              Select a finding from the left panel to inspect code context and vulnerability analysis.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
