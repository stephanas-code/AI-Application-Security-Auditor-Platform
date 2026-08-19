import React from 'react';
import { 
  ShieldCheck, 
  CheckCircle2, 
  AlertOctagon, 
  AlertTriangle, 
  Info, 
  Sparkles, 
  Wand2,
  TrendingUp,
  Award
} from 'lucide-react';
import { VulnerabilityFinding } from '../types';

interface SecurityScoreCardProps {
  scoreBefore: number;
  scoreCurrent: number;
  findings?: VulnerabilityFinding[];
  onAutoFixAll: () => void;
  isFixingAll: boolean;
}

export const SecurityScoreCard: React.FC<SecurityScoreCardProps> = ({
  scoreBefore,
  scoreCurrent,
  findings = [],
  onAutoFixAll,
  isFixingAll
}) => {
  const safeFindings = findings || [];
  const activeFindings = safeFindings.filter(f => f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE');
  const resolvedFindings = safeFindings.filter(f => f.status === 'VERIFIED_RESOLVED');

  const criticalCount = activeFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = activeFindings.filter(f => f.severity === 'HIGH').length;
  const mediumCount = activeFindings.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = activeFindings.filter(f => f.severity === 'LOW').length;
  const scaCount = activeFindings.filter(f => f.category === 'SCA').length;

  const total = safeFindings.length;
  const resolvedCount = resolvedFindings.length;
  const percentageResolved = total > 0 ? Math.round((resolvedCount / total) * 100) : 100;

  const getScoreColor = (score: number) => {
    if (score >= 85) return 'text-emerald-500';
    if (score >= 60) return 'text-orange-500';
    return 'text-[#FF3B30]';
  };

  const getScoreBarColor = (score: number) => {
    if (score >= 85) return 'bg-emerald-500';
    if (score >= 60) return 'bg-orange-500';
    return 'bg-[#FF3B30]';
  };

  return (
    <div className="space-y-4">
      {/* 4 Summary Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        
        {/* Card 1: Security Score */}
        <div className="bg-[#111111] border border-[#1F1F1F] p-4 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <p className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Security Score</p>
              {scoreCurrent > scoreBefore && (
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-1.5 py-0.5 rounded border border-emerald-900/60">
                  +{scoreCurrent - scoreBefore} PTS
                </span>
              )}
            </div>
            <div className="flex items-baseline gap-2 mt-1">
              <span className={`text-3xl font-light ${getScoreColor(scoreCurrent)}`}>
                {scoreCurrent < 10 && scoreCurrent > 0 ? `0${scoreCurrent}` : scoreCurrent}
              </span>
              <span className="text-xs text-gray-600 font-mono">/ 100</span>
            </div>
          </div>
          <div className="w-full h-1 bg-[#1F1F1F] mt-3 rounded-full overflow-hidden">
            <div 
              className={`h-full rounded-full transition-all duration-500 ${getScoreBarColor(scoreCurrent)}`}
              style={{ width: `${scoreCurrent}%` }}
            />
          </div>
        </div>

        {/* Card 2: Critical Issues */}
        <div className="bg-[#111111] border border-[#1F1F1F] p-4 rounded-xl flex flex-col justify-between">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Critical & High Issues</p>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-light text-[#FF3B30]">
                {criticalCount + highCount < 10 ? `0${criticalCount + highCount}` : criticalCount + highCount}
              </span>
              <span className="text-xs text-gray-600 font-mono">ACTIVE SINK(S)</span>
            </div>
          </div>
          <p className="text-[10px] text-red-400/80 font-mono mt-3 uppercase tracking-wider">
            {criticalCount} P0 CRITICAL • {highCount} HIGH
          </p>
        </div>

        {/* Card 3: Remediated & Verified */}
        <div className="bg-[#111111] border border-[#1F1F1F] p-4 rounded-xl flex flex-col justify-between">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Remediated & Verified</p>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-light text-emerald-500">
                {resolvedCount < 10 ? `0${resolvedCount}` : resolvedCount}
              </span>
              <span className="text-xs text-gray-600 font-mono">/ {total} FINDINGS</span>
            </div>
          </div>
          <p className="text-[10px] text-emerald-400 font-mono mt-3 uppercase tracking-wider">
            {percentageResolved}% VERIFIED CLEAN
          </p>
        </div>

        {/* Card 4: Dependencies & Scope */}
        <div className="bg-[#111111] border border-[#1F1F1F] p-4 rounded-xl flex flex-col justify-between">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold">Audit Surface & SCA</p>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-3xl font-light text-gray-300">
                {scaCount < 10 ? `0${scaCount}` : scaCount}
              </span>
              <span className="text-xs text-gray-600 font-mono">VULNERABLE PKGS</span>
            </div>
          </div>
          <p className="text-[10px] text-gray-500 font-mono mt-3 uppercase tracking-wider">
            SECRETS • SAST • CONFIG
          </p>
        </div>

      </div>

      {/* Verification Pipeline Visualizer & Batch CTA Bar */}
      <div className="bg-[#0D0D0D] border border-[#1F1F1F] rounded-xl p-3.5 flex flex-col sm:flex-row items-center justify-between gap-4">
        
        {/* Verification Pipeline Flow */}
        <div className="flex items-center gap-3 w-full sm:w-auto">
          <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest flex-shrink-0">
            Pipeline Flow:
          </span>
          <div className="flex items-center gap-1.5 flex-1 max-w-xs">
            <div className={`h-1 flex-1 rounded-full ${resolvedCount > 0 ? 'bg-emerald-500' : 'bg-[#1F1F1F]'}`}></div>
            <div className={`w-2 h-2 rounded-full ${resolvedCount > 0 ? 'bg-emerald-500' : 'bg-[#1F1F1F]'}`}></div>
            <div className={`h-1 flex-1 rounded-full ${resolvedCount > 1 ? 'bg-emerald-500' : 'bg-[#1F1F1F]'}`}></div>
            <div className={`w-2 h-2 rounded-full ${resolvedCount > 1 ? 'bg-emerald-500' : 'bg-[#1F1F1F]'}`}></div>
            <div className={`h-1 flex-1 rounded-full ${percentageResolved === 100 ? 'bg-emerald-500' : 'bg-blue-500'}`}></div>
            <div className={`w-2 h-2 rounded-full ${percentageResolved === 100 ? 'bg-emerald-500' : 'bg-blue-500'}`}></div>
          </div>
          <span className="text-[10px] text-blue-400 font-mono uppercase tracking-tight">
            {percentageResolved === 100 ? 'ALL PROOFS VERIFIED' : `STAGE: ${resolvedCount}/${total} VERIFIED`}
          </span>
        </div>

        {/* Primary Action Button */}
        {activeFindings.length > 0 ? (
          <button
            onClick={onAutoFixAll}
            disabled={isFixingAll}
            className="w-full sm:w-auto px-5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-md shadow-blue-900/30 flex items-center justify-center space-x-2 disabled:opacity-50"
          >
            <Wand2 className={`h-3.5 w-3.5 ${isFixingAll ? 'animate-spin' : ''}`} />
            <span>{isFixingAll ? 'EXECUTING RESCAN...' : 'APPLY & VERIFY ALL PATCHES'}</span>
          </button>
        ) : (
          <div className="flex items-center space-x-1.5 px-3 py-1.5 text-xs text-emerald-400 bg-emerald-950/40 rounded-lg border border-emerald-800/60 font-mono font-semibold">
            <Award className="h-3.5 w-3.5" />
            <span>ALL VULNERABILITIES RESOLVED</span>
          </div>
        )}

      </div>
    </div>
  );
};
