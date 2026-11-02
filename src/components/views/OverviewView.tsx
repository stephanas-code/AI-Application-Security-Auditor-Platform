import React from 'react';
import { 
  ScanResult, 
  VulnerabilityFinding, 
  NavigationTab,
  ScanTarget 
} from '../../types';
import { SecurityScoreCard } from '../SecurityScoreCard';
import { 
  AlertTriangle, 
  ShieldCheck, 
  Flame, 
  ArrowRight, 
  Zap, 
  Sparkles, 
  CheckCircle2, 
  Layers,
  Printer,
  FileText,
  Globe,
  Key,
  Server,
  Terminal,
  Shield
} from 'lucide-react';

interface OverviewViewProps {
  scanResult: ScanResult;
  target: ScanTarget;
  onNavigate: (tab: NavigationTab) => void;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
  onApplyPatch: (finding: VulnerabilityFinding) => void;
  onAutoFixAll: () => void;
  isFixingAll: boolean;
  onOpenReport?: (type: 'pentest' | 'recon' | 'api_vuln' | 'exposed_urls') => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  scanResult,
  target,
  onNavigate,
  onSelectFinding,
  onApplyPatch,
  onAutoFixAll,
  isFixingAll,
  onOpenReport
}) => {
  const { findings, scoreBefore, scoreCurrent, metrics, aiInsight } = scanResult;
  const websiteMeta = target.websiteMetadata;

  const criticalFindings = findings.filter(
    f => f.severity === 'CRITICAL' && f.status !== 'VERIFIED_RESOLVED'
  );
  
  const highFindings = findings.filter(
    f => f.severity === 'HIGH' && f.status !== 'VERIFIED_RESOLVED'
  );

  const resolvedFindings = findings.filter(f => f.status === 'VERIFIED_RESOLVED');

  return (
    <div className="space-y-6 pb-12">
      {/* Top Status Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-[#141414] via-[#111111] to-[#141414] border border-[#1F1F1F] flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider">
              Autonomous Security Audit Complete
            </span>
          </div>
          <h1 className="text-xl font-black text-white mt-1">
            {target.name}
          </h1>
          <p className="text-xs text-gray-400 mt-1 max-w-2xl leading-relaxed">
            {aiInsight.summary}
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={() => onNavigate('remediation')}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#FF3B30] hover:bg-[#D32F2F] text-black font-black text-xs uppercase tracking-wider transition-all shadow-lg"
          >
            <Zap className="h-4 w-4" />
            <span>Remediation Hub</span>
          </button>
          <button
            onClick={() => onNavigate('scans')}
            className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-[#1A1A1A] hover:bg-[#222222] border border-[#2A2A2A] text-white font-bold text-xs uppercase tracking-wider transition-all"
          >
            <span>Explore {findings.length} Scans</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Security Score Card */}
      <SecurityScoreCard
        scoreBefore={scoreBefore}
        scoreCurrent={scoreCurrent}
        findings={findings}
        onAutoFixAll={onAutoFixAll}
        isFixingAll={isFixingAll}
      />

      {/* Audit & Penetration Test PDF Reports Center */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-xl bg-gradient-to-br from-red-500 to-rose-700 flex items-center justify-center font-bold text-white shadow">
              <Printer className="h-4 w-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <span>Audit & Penetration Test PDF Reports Center</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-900">
                  OFFICIAL AUDIT REPORTS
                </span>
              </h3>
              <p className="text-xs text-gray-400">
                Generate and export certified vulnerability dossiers, network recon telemetry, OWASP API audits, and exposed route maps with terminal execution outputs.
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 pt-1">
          {/* Card 1: Recon PDF */}
          <div className="p-4 rounded-xl bg-[#161616] border border-[#222222] hover:border-blue-500/50 transition-all flex flex-col justify-between space-y-3 group">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-blue-950/80 text-blue-400 border border-blue-900">
                  RECON & NETWORK
                </span>
                <Globe className="h-4 w-4 text-blue-400 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="text-xs font-bold text-white">Recon & Infrastructure PDF</h4>
              <p className="text-[11px] text-gray-400 leading-relaxed">
                DNS zone records (A, MX, TXT, SPF, DMARC), TLS 1.3 handshake, cipher suite verification, and Nmap network telemetry outputs.
              </p>
            </div>
            <div className="p-2 bg-black rounded font-mono text-[10px] text-gray-400 border border-[#222222] truncate">
              <span className="text-emerald-400">$ nmap</span> -sV -p 80,443 {websiteMeta?.hostname || 'target'}
            </div>
            <button
              onClick={() => onOpenReport ? onOpenReport('recon') : null}
              className="w-full py-2 rounded-lg bg-[#222222] hover:bg-blue-600 text-gray-200 hover:text-white text-xs font-bold font-mono transition-all flex items-center justify-center space-x-1.5 shadow"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>Generate Recon PDF</span>
            </button>
          </div>

          {/* Card 2: API Vuln PDF */}
          <div className="p-4 rounded-xl bg-[#161616] border border-[#222222] hover:border-amber-500/50 transition-all flex flex-col justify-between space-y-3 group">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-950/80 text-amber-400 border border-amber-900">
                  OWASP API TOP 10
                </span>
                <Key className="h-4 w-4 text-amber-400 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="text-xs font-bold text-white">API Vulnerabilities & CVEs PDF</h4>
              <p className="text-[11px] text-gray-400 leading-relaxed">
                OWASP API Top 10 breakdown (BOLA, Rate Limiting, Mass Assignment, GraphQL introspection), CVE references, and remediation diffs.
              </p>
            </div>
            <div className="p-2 bg-black rounded font-mono text-[10px] text-gray-400 border border-[#222222] truncate">
              <span className="text-emerald-400">$ curl</span> -k -s -I /api/v1/users (CVE-2023-45857)
            </div>
            <button
              onClick={() => onOpenReport ? onOpenReport('api_vuln') : null}
              className="w-full py-2 rounded-lg bg-[#222222] hover:bg-amber-600 text-gray-200 hover:text-white text-xs font-bold font-mono transition-all flex items-center justify-center space-x-1.5 shadow"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>Generate API Vuln PDF</span>
            </button>
          </div>

          {/* Card 3: Exposed URLs PDF */}
          <div className="p-4 rounded-xl bg-[#161616] border border-[#222222] hover:border-purple-500/50 transition-all flex flex-col justify-between space-y-3 group">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-950/80 text-purple-400 border border-purple-900">
                  ATTACK SURFACE
                </span>
                <Server className="h-4 w-4 text-purple-400 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="text-xs font-bold text-white">Exposed URLs & Routes PDF</h4>
              <p className="text-[11px] text-gray-400 leading-relaxed">
                Complete inventory of probed admin portals, actuator debug endpoints, public API schemas, and HTTP status codes (200, 301, 401, 403).
              </p>
            </div>
            <div className="p-2 bg-black rounded font-mono text-[10px] text-gray-400 border border-[#222222] truncate">
              <span className="text-emerald-400">$ curl</span> -sI /admin (HTTP 200 Exposed)
            </div>
            <button
              onClick={() => onOpenReport ? onOpenReport('exposed_urls') : null}
              className="w-full py-2 rounded-lg bg-[#222222] hover:bg-purple-600 text-gray-200 hover:text-white text-xs font-bold font-mono transition-all flex items-center justify-center space-x-1.5 shadow"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>Generate Exposed URLs PDF</span>
            </button>
          </div>

          {/* Card 4: Pentest PDF */}
          <div className="p-4 rounded-xl bg-[#161616] border border-[#222222] hover:border-red-500/50 transition-all flex flex-col justify-between space-y-3 group">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[9px] font-mono font-bold bg-red-950/80 text-red-400 border border-red-900">
                  FULL PENTEST
                </span>
                <Flame className="h-4 w-4 text-red-400 group-hover:scale-110 transition-transform" />
              </div>
              <h4 className="text-xs font-bold text-white">Executive Pentest Dossier PDF</h4>
              <p className="text-[11px] text-gray-400 leading-relaxed">
                Complete certified penetration test report with CVSS ratings, Red Team compound attack chains, CLI tool logs, and SHA-256 integrity proofs.
              </p>
            </div>
            <div className="p-2 bg-black rounded font-mono text-[10px] text-gray-400 border border-[#222222] truncate">
              <span className="text-emerald-400">$ semgrep + gitleaks + nmap</span>
            </div>
            <button
              onClick={() => onOpenReport ? onOpenReport('pentest') : null}
              className="w-full py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold font-mono transition-all flex items-center justify-center space-x-1.5 shadow"
            >
              <Printer className="h-3.5 w-3.5" />
              <span>Generate Pentest PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* Blast Radius & Attack Chains */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Blast Radius & Risk Index */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-1.5">
                <Flame className="h-4 w-4 text-orange-400" />
                <span>Exploit Blast Radius</span>
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                aiInsight.blastRadiusScore > 70 ? 'bg-red-950 text-red-400 border border-red-800' :
                aiInsight.blastRadiusScore > 40 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                'bg-emerald-950 text-emerald-400 border border-emerald-800'
              }`}>
                {aiInsight.blastRadiusScore}/100 INDEX
              </span>
            </div>

            <div className="mt-4">
              <div className="w-full bg-[#1A1A1A] h-2.5 rounded-full overflow-hidden">
                <div 
                  className={`h-full transition-all duration-700 ${
                    aiInsight.blastRadiusScore > 70 ? 'bg-red-500' :
                    aiInsight.blastRadiusScore > 40 ? 'bg-amber-500' : 'bg-emerald-500'
                  }`}
                  style={{ width: `${aiInsight.blastRadiusScore}%` }}
                />
              </div>
            </div>

            <p className="text-xs text-gray-400 mt-3 leading-relaxed">
              {aiInsight.blastRadiusSummary}
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-[#1F1F1F] flex items-center justify-between text-[11px] font-mono text-gray-500">
            <span>Verified Fix Rate: {metrics.verifiedPercentage}%</span>
            <span className="text-emerald-400 font-bold">{resolvedFindings.length} Resolved</span>
          </div>
        </div>

        {/* Attack Chains List */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Layers className="h-4 w-4 text-red-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Compound Exploit Attack Chains</h3>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono text-gray-500">
                {aiInsight.attackChains?.length || 0} Multi-Stage Vectors
              </span>
              <button
                onClick={() => onNavigate('redteam')}
                className="px-2.5 py-1 bg-red-950/80 hover:bg-red-900 border border-red-800 text-red-300 rounded-lg text-[10px] font-mono font-bold uppercase transition-all flex items-center space-x-1"
              >
                <span>Red Team Engine</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {aiInsight.attackChains?.map((chain) => (
              <div 
                key={chain.id}
                className="p-3.5 rounded-xl bg-[#161616] border border-red-900/30 hover:border-red-700/50 transition-all space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white truncate">{chain.title}</span>
                  <span className="text-[9px] font-mono text-red-400 font-bold uppercase">{chain.severity}</span>
                </div>
                <p className="text-xs text-gray-400 leading-relaxed line-clamp-2">
                  {chain.narrative}
                </p>
                <div className="p-1.5 rounded bg-black/50 text-[10px] text-gray-300 font-mono truncate">
                  <span className="text-red-400 font-bold">Impact:</span> {chain.potentialImpact}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Immediate Priorities & AI Roadmap */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Urgent Remediation Queue */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-[#FF3B30]" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Immediate Fix Priorities</h3>
            </div>
            <span className="text-xs font-mono text-red-400">
              {criticalFindings.length + highFindings.length} High/Critical Active
            </span>
          </div>

          <div className="space-y-2.5">
            {criticalFindings.concat(highFindings).slice(0, 4).map((finding) => (
              <div
                key={finding.id}
                className="p-3.5 rounded-xl bg-[#161616] border border-[#1F1F1F] hover:border-[#333333] flex items-center justify-between gap-3 transition-all"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                      finding.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-orange-950 text-orange-400 border border-orange-800'
                    }`}>
                      {finding.severity}
                    </span>
                    <h4 className="text-xs font-bold text-white truncate">{finding.title}</h4>
                  </div>
                  <p className="text-[11px] font-mono text-gray-500 truncate">
                    {finding.file}:{finding.line} • {finding.cwe}
                  </p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => onSelectFinding(finding)}
                    className="px-2.5 py-1.5 rounded-lg bg-[#222222] hover:bg-[#2A2A2A] text-xs text-gray-300 hover:text-white font-medium transition-all"
                  >
                    Inspect
                  </button>
                  {finding.proposedPatch && (
                    <button
                      onClick={() => onApplyPatch(finding)}
                      className="px-2.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs text-white font-bold transition-all shadow"
                    >
                      Fix Now
                    </button>
                  )}
                </div>
              </div>
            ))}

            {criticalFindings.length + highFindings.length === 0 && (
              <div className="p-6 text-center text-xs text-emerald-400 font-mono bg-emerald-950/20 border border-emerald-900/40 rounded-xl flex items-center justify-center space-x-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span>Zero critical vulnerabilities remaining. Codebase is in compliance.</span>
              </div>
            )}
          </div>
        </div>

        {/* AI Remediation Roadmap */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Sparkles className="h-4 w-4 text-blue-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">AI Remediation Roadmap</h3>
            </div>
            <span className="text-xs font-mono text-gray-500">Autonomous Strategy</span>
          </div>

          <div className="space-y-3">
            {aiInsight.remediationRoadmap?.map((phase, idx) => (
              <div key={idx} className="p-3 rounded-xl bg-[#161616] border border-[#1F1F1F] space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-blue-400">{phase.phase}</span>
                  <span className="text-[10px] font-mono text-gray-500">{phase.estimatedEffort}</span>
                </div>
                <ul className="text-xs text-gray-400 space-y-1 pl-4 list-disc">
                  {phase.actions.map((act, aIdx) => (
                    <li key={aIdx} className="leading-snug">{act}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
