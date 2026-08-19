import React from 'react';
import { 
  ShieldAlert, 
  Sparkles, 
  FileCode2, 
  Download, 
  PlusCircle, 
  RefreshCw,
  Cpu,
  Radar
} from 'lucide-react';
import { ScanTarget } from '../types';

interface HeaderProps {
  currentTarget: ScanTarget | null;
  scoreBefore: number;
  scoreCurrent: number;
  isScanning: boolean;
  onNewScan: () => void;
  onRescan: () => void;
  onOpenReport: () => void;
  onOpenChat: () => void;
  onToggleDAST: () => void;
  activeView: 'dashboard' | 'code' | 'dast';
  setActiveView: (view: 'dashboard' | 'code' | 'dast') => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentTarget,
  scoreBefore,
  scoreCurrent,
  isScanning,
  onNewScan,
  onRescan,
  onOpenReport,
  onOpenChat,
  onToggleDAST,
  activeView,
  setActiveView
}) => {
  return (
    <header className="bg-[#0D0D0D] border-b border-[#1F1F1F] sticky top-0 z-40 text-[#E5E5E5]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Logo & Product Title */}
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-lg bg-[#FF3B30] flex items-center justify-center font-black text-black text-base shadow-sm">
              S
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-base tracking-tight text-white">
                  SHIELD<span className="text-[#FF3B30]">.AI</span>
                </span>
                <span className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded bg-[#1A1A1A] text-gray-400 border border-[#333333]">
                  AUDITOR & REMEDIATION
                </span>
              </div>
              <p className="text-[10px] text-gray-500 font-mono flex items-center gap-1.5 uppercase tracking-wider">
                <span>Find</span>
                <span className="text-gray-600">→</span>
                <span>Understand</span>
                <span className="text-gray-600">→</span>
                <span>Fix</span>
                <span className="text-gray-600">→</span>
                <span className="text-emerald-400 font-semibold">Verify</span>
              </p>
            </div>
          </div>

          {/* Navigation View Tabs */}
          <div className="hidden md:flex items-center bg-[#0F0F0F] p-1 rounded-lg border border-[#1F1F1F]">
            <button
              onClick={() => setActiveView('dashboard')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold tracking-tight transition-all ${
                activeView === 'dashboard'
                  ? 'bg-[#1A1A1A] text-white border border-[#333333] shadow-sm'
                  : 'text-gray-400 hover:text-white hover:bg-[#141414]'
              }`}
            >
              <Cpu className="h-3.5 w-3.5 text-[#FF3B30]" />
              <span>Overview & Audits</span>
            </button>

            <button
              onClick={() => setActiveView('code')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold tracking-tight transition-all ${
                activeView === 'code'
                  ? 'bg-[#1A1A1A] text-white border border-[#333333] shadow-sm'
                  : 'text-gray-400 hover:text-white hover:bg-[#141414]'
              }`}
            >
              <FileCode2 className="h-3.5 w-3.5 text-blue-400" />
              <span>Codebase Explorer</span>
            </button>

            <button
              onClick={() => setActiveView('dast')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold tracking-tight transition-all ${
                activeView === 'dast'
                  ? 'bg-[#1A1A1A] text-white border border-[#333333] shadow-sm'
                  : 'text-gray-400 hover:text-white hover:bg-[#141414]'
              }`}
            >
              <Radar className="h-3.5 w-3.5 text-orange-400" />
              <span>DAST Probe Sandbox</span>
            </button>
          </div>

          {/* Right Action Tools */}
          <div className="flex items-center space-x-2.5">
            {/* Live Monitor Status & Target Badge */}
            {currentTarget && (
              <div className="hidden lg:flex items-center space-x-2 px-2.5 py-1.5 rounded-md bg-[#111111] border border-[#1F1F1F] text-xs">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                <span className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">Target:</span>
                <span className="font-mono text-gray-200 truncate max-w-[130px]">
                  {currentTarget.name}
                </span>
                <span className="text-gray-600 font-mono text-[10px]">
                  ({currentTarget.files.length} files)
                </span>
              </div>
            )}

            {/* Quick Rescan */}
            <button
              onClick={onRescan}
              disabled={isScanning}
              title="Rescan project to verify resolved vulnerabilities"
              className="p-2 rounded-lg bg-[#111111] hover:bg-[#1A1A1A] text-gray-300 hover:text-white border border-[#1F1F1F] transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${isScanning ? 'animate-spin text-[#FF3B30]' : ''}`} />
            </button>

            {/* AI Analyst Chat Toggle */}
            <button
              onClick={onOpenChat}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#111111] hover:bg-[#1A1A1A] border border-[#1F1F1F] text-blue-400 hover:text-blue-300 text-xs font-semibold transition-all"
            >
              <Sparkles className="h-3.5 w-3.5 text-blue-400" />
              <span className="hidden sm:inline">AI Analyst</span>
            </button>

            {/* Export Audit Report */}
            <button
              onClick={onOpenReport}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#111111] hover:bg-[#1A1A1A] border border-[#1F1F1F] text-gray-300 text-xs font-semibold transition-colors"
            >
              <Download className="h-3.5 w-3.5 text-gray-500" />
              <span className="hidden sm:inline">Audit Report</span>
            </button>

            {/* New Project / Upload Intake */}
            <button
              onClick={onNewScan}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-[#FF3B30] hover:bg-[#D32F2F] text-black text-xs font-black uppercase tracking-wider transition-all shadow-sm"
            >
              <PlusCircle className="h-3.5 w-3.5 text-black" />
              <span>Intake App</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
