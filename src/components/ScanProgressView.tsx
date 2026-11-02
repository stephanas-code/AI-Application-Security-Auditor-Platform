import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal, 
  Cpu, 
  Search, 
  Lock, 
  Radio, 
  AlertCircle, 
  Layers, 
  Sparkles,
  Server,
  Code
} from 'lucide-react';
import { ScanTarget } from '../types';

interface ScanProgressViewProps {
  target: ScanTarget;
  activeToolsCount?: number;
  totalToolsCount?: number;
}

const SCAN_PHASES = [
  { label: 'Ingesting target artifacts & AST parsing', engine: 'Engine Core' },
  { label: 'Static Analysis (SAST) & pattern matching', engine: 'Semgrep & Bandit' },
  { label: 'Querying live CVE database & dependency tree', engine: 'Trivy & OSV' },
  { label: 'Auditing secrets, credentials & private keys', engine: 'Gitleaks & Entropy' },
  { label: 'Reconnaissance, SSL/TLS & security headers audit', engine: 'Nmap & HTTP Probe' },
  { label: 'Evaluating OWASP Top 10 & CWE compliance matrix', engine: 'Compliance Engine' },
  { label: 'Synthesizing verified auto-remediation patches', engine: 'AI Remediation Hub' }
];

export const ScanProgressView: React.FC<ScanProgressViewProps> = ({
  target,
  activeToolsCount = 12,
  totalToolsCount = 18
}) => {
  const [phaseIndex, setPhaseIndex] = useState(0);
  const [progress, setProgress] = useState(15);

  useEffect(() => {
    // Cycle phases every 900ms to produce dynamic rolling feedback
    const phaseInterval = setInterval(() => {
      setPhaseIndex(prev => (prev + 1) % SCAN_PHASES.length);
    }, 900);

    // Progress bar animation
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 92) return 92;
        return prev + Math.floor(Math.random() * 8) + 4;
      });
    }, 450);

    return () => {
      clearInterval(phaseInterval);
      clearInterval(progressInterval);
    };
  }, []);

  const currentPhase = SCAN_PHASES[phaseIndex] || SCAN_PHASES[0];

  return (
    <div className="flex flex-col items-center justify-center min-h-[68vh] px-4 py-8 max-w-4xl mx-auto">
      
      {/* 1. Radar & Rolling Gyroscope Scanner Animation */}
      <div className="relative flex items-center justify-center w-52 h-52 mb-8">
        {/* Pulsing Outer Glow */}
        <div className="absolute inset-0 rounded-full bg-blue-500/10 blur-2xl animate-pulse" />

        {/* Outer Ring with rotating dashed border */}
        <div className="absolute inset-0 rounded-full border-2 border-dashed border-blue-500/30 animate-[spin_10s_linear_infinite]" />

        {/* Middle Ring rotating reverse */}
        <div className="absolute inset-4 rounded-full border border-blue-400/20 border-t-blue-500 animate-[spin_4s_linear_infinite_reverse]" />

        {/* Inner Radar Sweep */}
        <div className="absolute inset-8 rounded-full border border-cyan-500/40 overflow-hidden bg-radial from-blue-950/40 to-transparent">
          <div className="absolute top-1/2 left-1/2 w-28 h-28 -translate-x-1/2 -translate-y-1/2 bg-[conic-gradient(from_0deg,transparent_0_300deg,rgba(59,130,246,0.6)_360deg)] rounded-full animate-[spin_1.8s_linear_infinite]" />
        </div>

        {/* Center Target Icon with Pulse */}
        <div className="relative z-10 flex items-center justify-center w-16 h-16 rounded-2xl bg-[#0F1420] border border-blue-500/50 shadow-[0_0_30px_rgba(59,130,246,0.35)]">
          <Shield className="h-8 w-8 text-blue-400 animate-pulse" />
        </div>

        {/* Orbiting Satellite Dots */}
        <div className="absolute inset-0 animate-[spin_6s_linear_infinite]">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-cyan-400 shadow-[0_0_12px_#38bdf8]" />
        </div>
        <div className="absolute inset-0 animate-[spin_8s_linear_infinite_reverse]">
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2 w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399]" />
        </div>
      </div>

      {/* 2. Exact Required Heading Message */}
      <div className="text-center space-y-2 mb-6">
        <h2 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight flex items-center justify-center gap-3">
          <span>Scan vulnerability , wait for the process to finish</span>
        </h2>
        <p className="text-sm font-mono text-gray-400 flex items-center justify-center gap-2">
          <span>Target:</span>
          <span className="text-blue-400 font-bold bg-[#141414] px-2.5 py-0.5 rounded border border-[#222]">
            {target.name}
          </span>
          <span className="uppercase text-[11px] font-bold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800/40">
            {target.platform || 'web'}
          </span>
        </p>
      </div>

      {/* 3. Rolling Step Indicator & Progress */}
      <div className="w-full max-w-xl bg-[#111111] border border-[#222222] rounded-2xl p-6 shadow-2xl space-y-4">
        
        {/* Progress Bar with Rolling Animated Striped Gradient */}
        <div className="space-y-1.5">
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-gray-400 flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full bg-blue-400 animate-ping" />
              <span>Analyzing Security Posture...</span>
            </span>
            <span className="text-blue-400 font-bold">{progress}%</span>
          </div>
          
          <div className="h-3 w-full bg-[#1A1A1A] rounded-full overflow-hidden border border-[#262626] p-0.5">
            <div 
              className="h-full bg-gradient-to-r from-blue-600 via-cyan-400 to-indigo-500 rounded-full transition-all duration-300 ease-out shadow-[0_0_12px_rgba(56,189,248,0.5)]"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Rolling Phase Ticker */}
        <div className="flex items-center justify-between pt-2 border-t border-[#1C1C1C]">
          <div className="flex items-center space-x-2.5 text-xs">
            <div className="p-1.5 rounded-lg bg-blue-950/60 border border-blue-800/50 text-blue-400">
              <Cpu className="h-4 w-4 animate-spin" />
            </div>
            <div>
              <p className="text-gray-200 font-semibold text-xs tracking-wide">
                {currentPhase.label}
              </p>
              <p className="text-[10px] font-mono text-gray-500">
                Engine: <span className="text-cyan-400">{currentPhase.engine}</span>
              </p>
            </div>
          </div>

          <span className="px-2.5 py-1 rounded-lg bg-[#181818] border border-[#262626] text-[11px] font-mono text-emerald-400 font-bold flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>{activeToolsCount}/{totalToolsCount} Tools Active</span>
          </span>
        </div>

        {/* Active Engine Tags */}
        <div className="pt-2 flex flex-wrap items-center justify-center gap-1.5 text-[10px] font-mono text-gray-400">
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">Nmap</span>
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">Semgrep</span>
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">Trivy</span>
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">Gitleaks</span>
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">Bandit</span>
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">Pip-Audit</span>
          <span className="px-2 py-0.5 rounded bg-[#161616] border border-[#222]">OWASP Top 10</span>
        </div>

      </div>

    </div>
  );
};

