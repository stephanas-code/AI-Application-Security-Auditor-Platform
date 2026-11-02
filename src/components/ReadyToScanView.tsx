import React from 'react';
import {
  ShieldCheck,
  Play,
  Upload,
  Wrench,
  Globe,
  Terminal,
  Smartphone,
  Monitor,
  FileCode,
  CheckCircle2,
  Layers,
  Sparkles,
  Search,
  Lock
} from 'lucide-react';
import { ScanTarget } from '../types';

interface ReadyToScanViewProps {
  target: ScanTarget;
  onStartScan: () => void;
  onOpenIntake: () => void;
  onOpenTools: () => void;
  activeToolsCount?: number;
  totalToolsCount?: number;
}

export const ReadyToScanView: React.FC<ReadyToScanViewProps> = ({
  target,
  onStartScan,
  onOpenIntake,
  onOpenTools,
  activeToolsCount = 12,
  totalToolsCount = 18
}) => {
  const getPlatformIcon = () => {
    switch (target.platform) {
      case 'android': return Smartphone;
      case 'ios': return Smartphone;
      case 'windows': return Monitor;
      case 'macos': return Monitor;
      default: return target.type === 'website_recon' ? Globe : Terminal;
    }
  };

  const PlatformIcon = getPlatformIcon();

  return (
    <div className="flex flex-col items-center justify-center min-h-[72vh] px-4 py-8 max-w-4xl mx-auto">

      {/* 1. Shield Icon Badge */}
      <div className="relative mb-6">
        <div className="absolute inset-0 rounded-3xl bg-emerald-500/10 blur-xl animate-pulse" />
        <div className="relative flex items-center justify-center w-24 h-24 rounded-3xl bg-[#0D1512] border-2 border-emerald-500/40 shadow-[0_0_35px_rgba(16,185,129,0.25)]">
          <ShieldCheck className="h-12 w-12 text-emerald-400" />
        </div>
      </div>

      {/* 2. Exact Required Heading Message */}
      <div className="text-center space-y-2 mb-8">
        <h1 className="text-3xl md:text-4xl font-extrabold text-white tracking-tight">
          Ready to scan vulnerability.
        </h1>
        <p className="text-sm text-gray-400 max-w-xl mx-auto">
          Target workspace ingested and verified. Security auditor engines, static analyzers, and vulnerability databases stand ready to audit this target.
        </p>
      </div>

      {/* 3. Target Ingest Overview Card */}
      <div className="w-full max-w-2xl bg-[#111111] border border-[#222222] rounded-2xl p-6 shadow-2xl mb-8 space-y-5">
        <div className="flex items-center justify-between pb-4 border-b border-[#1C1C1C]">
          <div className="flex items-center space-x-3.5">
            <div className="p-3 rounded-xl bg-[#1A1A1A] border border-[#262626] text-blue-400">
              <PlatformIcon className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-white">{target.name}</h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800/40 uppercase">
                  {target.platform || 'web'}
                </span>
              </div>
              <p className="text-xs font-mono text-gray-400 mt-0.5">
                {target.language || 'Multi-Language / Application Artifact'} • {target.files.length} {target.files.length === 1 ? 'file/config' : 'files/configs'}
              </p>
            </div>
          </div>

          <button
            onClick={onOpenIntake}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-xl bg-[#1A1A1A] hover:bg-[#252525] border border-[#2A2A2A] text-gray-300 hover:text-white text-xs font-mono transition-all cursor-pointer"
          >
            <Upload className="h-3.5 w-3.5" />
            <span>Switch Target</span>
          </button>
        </div>

        {/* Audit Engine Readiness Checklist */}
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
          <div className="p-3 rounded-xl bg-[#0D1219] border border-blue-900/30 flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">SAST Engine</p>
              <p className="text-[10px] text-gray-400 truncate">Semgrep & Bandit</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D1219] border border-blue-900/30 flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">SCA & CVEs</p>
              <p className="text-[10px] text-gray-400 truncate">Trivy & OSV.dev</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D1219] border border-blue-900/30 flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">Secret Auditor</p>
              <p className="text-[10px] text-gray-400 truncate">Gitleaks & Entropy</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D1219] border border-blue-900/30 flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">DAST & Recon</p>
              <p className="text-[10px] text-gray-400 truncate">Nmap & HTTP Probe</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D1219] border border-blue-900/30 flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">Compliance</p>
              <p className="text-[10px] text-gray-400 truncate">OWASP & CWE</p>
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#0D1219] border border-blue-900/30 flex items-center space-x-2.5">
            <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            <div className="min-w-0">
              <p className="text-xs font-bold text-white truncate">Auto-Patching</p>
              <p className="text-[10px] text-gray-400 truncate">Remediation Hub</p>
            </div>
          </div>
        </div>

        {/* Live Tools Status Bar */}
        <div className="flex items-center justify-between pt-3 border-t border-[#1C1C1C] text-xs">
          <div className="flex items-center space-x-2 text-gray-400 font-mono">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Auditor Tools Verified: <span className="text-emerald-400 font-bold">{activeToolsCount}/{totalToolsCount} Active</span></span>
          </div>
          <button
            onClick={onOpenTools}
            className="text-blue-400 hover:text-blue-300 font-mono text-xs underline underline-offset-4 cursor-pointer"
          >
            Inspect Tools Dashboard →
          </button>
        </div>
      </div>

      {/* 4. Primary Scan Action Button */}
      <div className="flex flex-col sm:flex-row items-center gap-4">
        <button
          onClick={onStartScan}
          className="group relative flex items-center space-x-3 px-8 py-4 rounded-2xl bg-gradient-to-r from-blue-600 via-indigo-600 to-blue-500 hover:from-blue-500 hover:to-indigo-500 text-white font-bold text-base shadow-[0_0_25px_rgba(37,99,235,0.45)] hover:shadow-[0_0_35px_rgba(37,99,235,0.6)] transition-all cursor-pointer transform hover:-translate-y-0.5 active:translate-y-0"
        >
          <Play className="h-5 w-5 fill-current text-white group-hover:scale-110 transition-transform" />
          <span>Scan Vulnerability</span>
        </button>

        <button
          onClick={onOpenIntake}
          className="flex items-center space-x-2 px-6 py-4 rounded-2xl bg-[#141414] hover:bg-[#1E1E1E] border border-[#242424] text-gray-300 hover:text-white font-medium text-sm transition-all cursor-pointer"
        >
          <Upload className="h-4 w-4 text-gray-400" />
          <span>Upload Another App / Web URL</span>
        </button>
      </div>

    </div>
  );
};

