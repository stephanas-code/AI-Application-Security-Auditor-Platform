import React, { useState } from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Wrench,
  FileCheck2,
  Settings,
  Smartphone,
  Monitor,
  Apple,
  Terminal,
  PlusCircle,
  Sparkles,
  RefreshCw,
  FileText,
  Crosshair,
  Radio,
  Database,
  Cpu,
  ChevronDown,
  Trash2,
  Globe,
  Folder
} from 'lucide-react';
import { NavigationTab, ScanTarget, ScanResult } from '../types';
import { SavedScanHistoryItem } from './ProjectIntakeModal';
import { MgSecuraLogo } from './MgSecuraLogo';

interface SidebarProps {
  currentTab: NavigationTab;
  onSelectTab: (tab: NavigationTab) => void;
  target: ScanTarget;
  scanResult?: ScanResult | null;
  onOpenIntake: () => void;
  onOpenReport: () => void;
  onRescan: () => void;
  isRescanning?: boolean;
  activeToolsCount?: number;
  totalToolsCount?: number;
  scanHistory?: SavedScanHistoryItem[];
  onSwitchTarget?: (entry: SavedScanHistoryItem) => void;
  onDeleteTarget?: (targetId: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  target,
  scanResult,
  onOpenIntake,
  onOpenReport,
  onRescan,
  isRescanning,
  activeToolsCount,
  totalToolsCount,
  scanHistory = [],
  onSwitchTarget,
  onDeleteTarget
}) => {
  const [isTargetsDropdownOpen, setIsTargetsDropdownOpen] = useState(false);
  const unresolvedCount = scanResult?.findings
    ? scanResult.findings.filter(
      f => f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE'
    ).length
    : 0;

  const criticalCount = scanResult?.findings
    ? scanResult.findings.filter(
      f => f.severity === 'CRITICAL' && f.status !== 'VERIFIED_RESOLVED'
    ).length
    : 0;

  const navItems = [
    {
      id: 'overview' as NavigationTab,
      label: 'Overview',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'scans' as NavigationTab,
      label: 'Security Scans',
      icon: ShieldAlert,
      badge: unresolvedCount > 0 ? unresolvedCount : null,
      badgeColor: criticalCount > 0 ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-[#1F1F1F] text-gray-300'
    },
    {
      id: 'tools' as NavigationTab,
      label: 'Tools & Engines',
      icon: Cpu,
      badge: totalToolsCount ? `${activeToolsCount ?? 0}/${totalToolsCount} ACTIVE` : 'VERIFY',
      badgeColor: (activeToolsCount && totalToolsCount && activeToolsCount === totalToolsCount)
        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono text-[9px]'
        : 'bg-indigo-950 text-indigo-300 border border-indigo-700 font-mono text-[9px]'
    },
    {
      id: 'redteam' as NavigationTab,
      label: 'Red Team / Attack',
      icon: Crosshair,
      badge: criticalCount > 0 ? `${criticalCount} exploits` : 'Active',
      badgeColor: criticalCount > 0 ? 'bg-red-950 text-red-400 border border-red-800 font-mono text-[9px]' : 'bg-purple-950 text-purple-400 border border-purple-800 font-mono text-[9px]'
    },
    {
      id: 'threat_intel' as NavigationTab,
      label: 'Threat Intel & News',
      icon: Radio,
      badge: 'Live Feed',
      badgeColor: 'bg-red-950 text-red-400 border border-red-800 font-mono text-[9px]'
    },
    {
      id: 'remediation' as NavigationTab,
      label: 'Remediation Hub',
      icon: Wrench,
      badge: (scanResult?.metrics?.resolvedCount ?? 0) > 0 ? `${scanResult?.metrics?.resolvedCount} fixed` : null,
      badgeColor: 'bg-emerald-950 text-emerald-400 border border-emerald-800'
    },
    {
      id: 'datasets' as NavigationTab,
      label: 'AI Datasets & Training',
      icon: Database,
      badge: 'PrimeVul',
      badgeColor: 'bg-blue-950 text-blue-400 border border-blue-800 font-mono text-[9px]'
    },
    {
      id: 'compliance' as NavigationTab,
      label: 'Compliance Map',
      icon: FileCheck2,
      badge: null
    },
    {
      id: 'settings' as NavigationTab,
      label: 'Settings',
      icon: Settings,
      badge: null
    }
  ];

  return (
    <aside className="w-64 bg-[#0D0D0D] border-r border-[#1F1F1F] flex flex-col justify-between shrink-0 h-screen sticky top-0">
            {/* Brand Header */}
      <div className="p-4 border-b border-[#1F1F1F]">
        <MgSecuraLogo size="md" />

        {/* Current Active Target Card */}
        <div className="mt-4 p-2.5 rounded-xl bg-[#141414] border border-[#1F1F1F] hover:border-[#333333] transition-all">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 min-w-0">
              <div className="p-1 rounded bg-[#1C1C1C] text-gray-400">
                {target.platform === 'android' ? <Smartphone className="h-3.5 w-3.5 text-emerald-400" /> :
                  target.platform === 'windows' ? <Monitor className="h-3.5 w-3.5 text-blue-400" /> :
                    target.platform === 'ios' ? <Apple className="h-3.5 w-3.5 text-rose-400" /> :
                      <Terminal className="h-3.5 w-3.5 text-amber-400" />}
              </div>
              <div className="min-w-0">
                <span className="text-xs font-bold text-white block truncate">{target.name}</span>
                <span className="text-[10px] text-gray-500 font-mono block">
                  {target.platform?.toUpperCase() || 'WEB'} • {target.files?.length || 0} files
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-1.5 mt-2.5 pt-2 border-t border-[#1C1C1C]">
            <button
              onClick={onOpenIntake}
              className="flex-1 flex items-center justify-center space-x-1 py-1 px-2 rounded-lg bg-[#1F1F1F] hover:bg-[#2A2A2A] text-gray-300 hover:text-white text-[10px] font-mono font-semibold transition-all cursor-pointer"
            >
              <PlusCircle className="h-3 w-3" />
              <span>Switch / New Target ({scanHistory.length})</span>
            </button>
            <button
              onClick={onRescan}
              disabled={isRescanning}
              title="Rescan target"
              className="p-1 rounded-lg bg-[#1F1F1F] hover:bg-[#2A2A2A] text-gray-400 hover:text-white transition-all disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className={`h-3 w-3 ${isRescanning ? 'animate-spin text-blue-400' : ''}`} />
            </button>
          </div>

          {/* Scanned Targets Dropdown with Deletion */}
          {scanHistory.length > 0 && onSwitchTarget && (
            <div className="mt-2.5 pt-2 border-t border-[#1C1C1C]">
              <button
                type="button"
                onClick={() => setIsTargetsDropdownOpen(prev => !prev)}
                className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg bg-[#141414] hover:bg-[#1A1A1A] border border-[#222222] hover:border-[#333333] text-gray-300 transition-all cursor-pointer group"
              >
                <div className="flex items-center space-x-1.5 min-w-0">
                  <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse shrink-0" />
                  <span className="text-[10px] font-mono font-bold text-gray-300 group-hover:text-white uppercase tracking-wider truncate">
                    Scanned Targets ({scanHistory.length})
                  </span>
                </div>
                <ChevronDown className={`h-3.5 w-3.5 text-gray-400 transition-transform duration-200 shrink-0 ${isTargetsDropdownOpen ? 'rotate-180 text-blue-400' : ''}`} />
              </button>

              {isTargetsDropdownOpen && (
                <div className="mt-1.5 p-1 rounded-xl bg-[#0C0C0E] border border-[#262626] shadow-2xl space-y-1 max-h-52 overflow-y-auto scrollbar-thin">
                  {scanHistory.map((item) => {
                    const isCurrent = item.target.id === target.id || item.target.name === target.name;
                    return (
                      <div
                        key={item.target.id}
                        className={`group/item flex items-center justify-between p-1.5 rounded-lg text-[10px] font-mono transition-all ${
                          isCurrent
                            ? 'bg-blue-950/70 border border-blue-700/60 text-white'
                            : 'hover:bg-[#1A1A1A] text-gray-400 hover:text-gray-200'
                        }`}
                      >
                        <button
                          type="button"
                          onClick={() => {
                            onSwitchTarget(item);
                            setIsTargetsDropdownOpen(false);
                          }}
                          className="flex-1 text-left truncate flex items-center space-x-1.5 cursor-pointer pr-1"
                          title={`Switch to ${item.target.name}`}
                        >
                          {item.target.type === 'url' ? (
                            <Globe className="h-3 w-3 text-blue-400 shrink-0" />
                          ) : (
                            <Folder className="h-3 w-3 text-emerald-400 shrink-0" />
                          )}
                          <span className="truncate">{item.target.name}</span>
                          {isCurrent && (
                            <span className="text-[8px] font-bold px-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 shrink-0">
                              ACTIVE
                            </span>
                          )}
                        </button>

                        {onDeleteTarget && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onDeleteTarget(item.target.id);
                            }}
                            className="p-1 rounded text-gray-500 hover:text-red-400 hover:bg-red-950/50 transition-colors cursor-pointer shrink-0"
                            title={`Delete ${item.target.name} from history`}
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Main Navigation */}
      <nav className="p-3 space-y-1 flex-1 overflow-y-auto">
        <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-gray-500 font-bold">
          Navigation
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-semibold tracking-tight transition-all group cursor-pointer ${isActive
                  ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-[#141414] border border-transparent'
                }`}
            >
              <div className="flex items-center space-x-2.5">
                <Icon className={`h-4 w-4 transition-colors ${isActive ? 'text-blue-400' : 'text-gray-500 group-hover:text-gray-300'}`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== null && (
                <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded-full ${item.badgeColor || 'bg-[#1F1F1F] text-gray-300'}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Utility Actions */}
      <div className="p-4 border-t border-[#1F1F1F] bg-[#0A0A0A] space-y-2">
        <button
          onClick={onOpenReport}
          className="w-full flex items-center justify-center space-x-2 py-2 px-3 rounded-xl bg-[#141414] hover:bg-[#1C1C1C] border border-[#1F1F1F] text-gray-200 hover:text-white text-xs font-semibold transition-all cursor-pointer"
        >
          <FileText className="h-3.5 w-3.5 text-blue-400" />
          <span>Export Audit Report</span>
        </button>

        <div className="flex items-center justify-between text-[10px] font-mono text-gray-500 px-1 pt-1">
          <span>Engine v2.5.0</span>
          <span className="flex items-center space-x-1">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>{activeToolsCount !== undefined && totalToolsCount ? `${activeToolsCount}/${totalToolsCount} Tools Ready` : 'Online'}</span>
          </span>
        </div>
      </div>
    </aside>
  );
};
