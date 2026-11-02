import React, { useState, useEffect, useCallback } from 'react';
import {
  Wrench, CheckCircle2, XCircle, RefreshCw, Terminal, ShieldCheck,
  AlertTriangle, Cpu, Play, Copy, Check, Server, Layers, Search,
  Activity, Lock, Globe, FileCode, Package, Binary
} from 'lucide-react';
import { ToolVerificationItem } from '../../types';

interface ToolsDashboardViewProps {
  onToolsStatusUpdated?: (activeCount: number, totalCount: number) => void;
}

export const ToolsDashboardView: React.FC<ToolsDashboardViewProps> = ({ onToolsStatusUpdated }) => {
  const [tools, setTools] = useState<ToolVerificationItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [verifyingToolId, setVerifyingToolId] = useState<string | null>(null);
  const [hostInfo, setHostInfo] = useState<{
    platform: string;
    osRelease: string;
    arch: string;
    hostname: string;
    checkedAt: string;
    summary?: {
      readyForSAST: boolean;
      readyForSecrets: boolean;
      readyForSCA: boolean;
      readyForDAST: boolean;
      readyForGit: boolean;
      readyForBinary: boolean;
    };
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'ACTIVE' | 'INACTIVE'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [inlineApiKey, setInlineApiKey] = useState<string>('');
  const [savingApiKey, setSavingApiKey] = useState<boolean>(false);
  const [apiKeySavedMsg, setApiKeySavedMsg] = useState<string | null>(null);

  const handleSaveInlineApiKey = async () => {
    if (!inlineApiKey.trim()) return;
    setSavingApiKey(true);
    setApiKeySavedMsg(null);
    try {
      const res = await fetch('/api/settings/ai-config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ apiKey: inlineApiKey.trim(), aiModel: 'gemini-3.8' })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setInlineApiKey('');
        setApiKeySavedMsg(`✓ Gemini 3.8 Key Activated (${data.maskedKey})`);
        await handleVerifySingleTool('gemini_ai');
      }
    } catch (e: any) {
      setError(`Could not save Gemini API key: ${e.message}`);
    } finally {
      setSavingApiKey(false);
    }
  };

  const fetchAndVerifyTools = useCallback(async (deepVerify = true) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/tools/status?verify=${deepVerify ? 'true' : 'false'}`);
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to query backend tool verification endpoint');
      }
      const list: ToolVerificationItem[] = data.toolList || [];
      setTools(list);
      setHostInfo({
        platform: data.platform || 'linux',
        osRelease: data.osRelease || 'Linux Host',
        arch: data.arch || 'x64',
        hostname: data.hostname || 'kali',
        checkedAt: data.checkedAt || new Date().toISOString(),
        summary: data.summary
      });
      if (onToolsStatusUpdated) {
        onToolsStatusUpdated(list.filter(t => t.active).length, list.length);
      }
    } catch (err: any) {
      setError(err.message || 'Could not reach Linux auditor backend');
    } finally {
      setLoading(false);
    }
  }, [onToolsStatusUpdated]);

  useEffect(() => {
    fetchAndVerifyTools(true);
  }, [fetchAndVerifyTools]);

  const handleVerifySingleTool = async (toolId: string) => {
    setVerifyingToolId(toolId);
    try {
      const res = await fetch('/api/tools/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolId })
      });
      const data = await res.json();
      if (data.success && Array.isArray(data.toolList) && data.toolList.length > 0) {
        const updatedTool = data.toolList[0];
        setTools(prev => {
          const next = prev.map(t => t.id === toolId ? updatedTool : t);
          if (onToolsStatusUpdated) {
            onToolsStatusUpdated(next.filter(t => t.active).length, next.length);
          }
          return next;
        });
      }
    } catch (err: any) {
      setError(`Verification failed for ${toolId}: ${err.message}`);
    } finally {
      setVerifyingToolId(null);
    }
  };

  const handleCopyCommand = (id: string, cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const activeToolsCount = tools.filter(t => t.active).length;
  const inactiveToolsCount = tools.length - activeToolsCount;
  const inactiveCliCommands = tools
    .filter(t => !t.active && !t.installCommand.startsWith('Requires') && !t.installCommand.startsWith('Add') && !t.installCommand.startsWith('Check'))
    .map(t => t.installCommand);

  const filteredTools = tools.filter(tool => {
    const matchesCategory = selectedCategory === 'ALL' || tool.category === selectedCategory;
    const matchesStatus =
      statusFilter === 'ALL' ||
      (statusFilter === 'ACTIVE' && tool.active) ||
      (statusFilter === 'INACTIVE' && !tool.active);
    const matchesSearch =
      !searchQuery.trim() ||
      tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.binary.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCategory && matchesStatus && matchesSearch;
  });

  const categoryMeta: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    SAST: { label: 'SAST Engines', color: 'text-indigo-400 bg-indigo-950/60 border-indigo-700/50', icon: <FileCode className="w-3.5 h-3.5" /> },
    SECRETS: { label: 'Secret Scanners', color: 'text-rose-400 bg-rose-950/60 border-rose-700/50', icon: <Lock className="w-3.5 h-3.5" /> },
    SCA: { label: 'SCA & Dependency', color: 'text-amber-400 bg-amber-950/60 border-amber-700/50', icon: <Package className="w-3.5 h-3.5" /> },
    DAST: { label: 'DAST & Network Recon', color: 'text-cyan-400 bg-cyan-950/60 border-cyan-700/50', icon: <Globe className="w-3.5 h-3.5" /> },
    BINARY: { label: 'Binary & Mobile RE', color: 'text-purple-400 bg-purple-950/60 border-purple-700/50', icon: <Binary className="w-3.5 h-3.5" /> },
    RUNTIME: { label: 'Runtimes & Sandbox', color: 'text-emerald-400 bg-emerald-950/60 border-emerald-700/50', icon: <Terminal className="w-3.5 h-3.5" /> },
    THREAT_INTEL: { label: 'AI & Threat Intel APIs', color: 'text-blue-400 bg-blue-950/60 border-blue-700/50', icon: <Activity className="w-3.5 h-3.5" /> }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="p-2 rounded-lg bg-indigo-600/20 border border-indigo-500/40 text-indigo-400">
              <Wrench className="w-5 h-5" />
            </div>
            <span className="text-xs font-bold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-700/50">
              Live Execution Verification
            </span>
            {hostInfo && (
              <span className="text-xs font-mono text-slate-400 bg-slate-950/80 px-2.5 py-0.5 rounded border border-slate-800">
                Host: {hostInfo.hostname} ({hostInfo.osRelease} • {hostInfo.arch})
              </span>
            )}
          </div>
          <h2 className="text-xl font-bold text-white mt-2">
            Security Auditor Tools & Engines Verification Dashboard
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Every tool listed below is required by the Security Auditor for real-time SAST, SCA, Secret Detection, DAST Network Probing, Binary Reverse Engineering, and Closed-Loop Patch Verification. A tool is marked <span className="text-emerald-400 font-semibold">ACTIVE</span> only after the backend resolves its binary and passes a live functional execution self-test.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={() => fetchAndVerifyTools(true)}
            disabled={loading}
            className="flex items-center space-x-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 text-white rounded-lg text-xs font-bold transition-all shadow-lg shadow-indigo-600/25 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Running Self-Tests...' : 'Verify All Tools Now'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/80 rounded-xl p-4 flex items-center justify-between text-red-200 text-xs">
          <div className="flex items-center space-x-2.5">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => fetchAndVerifyTools(true)}
            className="px-3 py-1 bg-red-900/60 hover:bg-red-800 text-white rounded font-semibold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Executive Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Total Required Tools</span>
            <Layers className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-3xl font-black text-white mt-2">{tools.length}</div>
          <div className="text-[11px] text-slate-400 mt-1">
            Across 7 security auditing subsystems
          </div>
        </div>

        <div className="bg-slate-900/90 border border-emerald-900/60 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">Verified Active & Usable</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline space-x-2 mt-2">
            <span className="text-3xl font-black text-emerald-400">{activeToolsCount}</span>
            <span className="text-xs font-mono text-emerald-500">
              ({tools.length > 0 ? Math.round((activeToolsCount / tools.length) * 100) : 0}%)
            </span>
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Installed + passed functional execution self-test
          </div>
        </div>

        <div className={`bg-slate-900/90 border rounded-xl p-4 ${inactiveToolsCount > 0 ? 'border-amber-800/60' : 'border-slate-800'}`}>
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">Inactive / Missing</span>
            <XCircle className={`w-4 h-4 ${inactiveToolsCount > 0 ? 'text-amber-400' : 'text-slate-600'}`} />
          </div>
          <div className={`text-3xl font-black mt-2 ${inactiveToolsCount > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
            {inactiveToolsCount}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {inactiveToolsCount === 0 ? 'All tools verified operational!' : 'Install commands provided below'}
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-cyan-400">Subsystem Readiness</span>
            <Server className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="grid grid-cols-2 gap-1.5 mt-2.5 text-[11px]">
            <div className="flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${hostInfo?.summary?.readyForSAST ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className="text-slate-300">SAST Engine</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${hostInfo?.summary?.readyForSecrets ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className="text-slate-300">Secret Scan</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${hostInfo?.summary?.readyForSCA ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className="text-slate-300">SCA / CVE</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${hostInfo?.summary?.readyForDAST ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className="text-slate-300">DAST / Nmap</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${hostInfo?.summary?.readyForBinary ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className="text-slate-300">Binary / APK</span>
            </div>
            <div className="flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${hostInfo?.summary?.readyForGit ? 'bg-emerald-400' : 'bg-red-500'}`} />
              <span className="text-slate-300">Git Cloner</span>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Batch Remediation Banner if any CLI tools are missing */}
      {inactiveCliCommands.length > 0 && (
        <div className="bg-amber-950/30 border border-amber-800/60 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2 text-amber-300 text-xs font-bold">
              <Terminal className="w-4 h-4 text-amber-400" />
              <span>{inactiveCliCommands.length} CLI Tool(s) Currently Inactive on Linux Host</span>
            </div>
            <p className="text-xs text-slate-300">
              Run `./setup_linux.sh` in your Linux terminal or copy the one-line installer command to activate all missing tools.
            </p>
          </div>
          <button
            onClick={() => handleCopyCommand('batch-install', inactiveCliCommands.join(' && '))}
            className="flex items-center space-x-2 px-3.5 py-2 bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/40 text-amber-300 rounded-lg text-xs font-semibold shrink-0 cursor-pointer"
          >
            {copiedId === 'batch-install' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            <span>{copiedId === 'batch-install' ? 'Copied to Clipboard!' : 'Copy Missing Install Commands'}</span>
          </button>
        </div>
      )}

      {/* Filter & Search Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="flex flex-wrap items-center gap-1.5">
          {['ALL', 'SAST', 'SECRETS', 'SCA', 'DAST', 'BINARY', 'RUNTIME', 'THREAT_INTEL'].map(cat => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${selectedCategory === cat
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-slate-800/70 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
            >
              {cat === 'ALL' ? `All (${tools.length})` : cat}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs">
            {(['ALL', 'ACTIVE', 'INACTIVE'] as const).map(st => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded-md font-semibold transition-all cursor-pointer ${statusFilter === st
                    ? st === 'ACTIVE'
                      ? 'bg-emerald-600 text-white'
                      : st === 'INACTIVE'
                        ? 'bg-rose-600 text-white'
                        : 'bg-slate-800 text-white'
                    : 'text-slate-400 hover:text-slate-200'
                  }`}
              >
                {st === 'ALL' ? 'All Status' : st === 'ACTIVE' ? `Active (${activeToolsCount})` : `Inactive (${inactiveToolsCount})`}
              </button>
            ))}
          </div>

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter tool or binary..."
              className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>
      </div>

      {/* Tool Verification Grid */}
      {loading && tools.length === 0 ? (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-12 text-center space-y-3">
          <RefreshCw className="w-8 h-8 text-indigo-400 animate-spin mx-auto" />
          <div className="text-sm font-bold text-white">Executing Functional Self-Tests Across All Security Tools...</div>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            Resolving binaries in system PATH & `~/.appsec_venv`, executing sample AST/Secret/Network probes, and validating tool output...
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredTools.map(tool => {
            const cat = categoryMeta[tool.category] || {
              label: tool.category,
              color: 'text-slate-300 bg-slate-800 border-slate-700',
              icon: <Cpu className="w-3.5 h-3.5" />
            };
            const isVerifyingThis = verifyingToolId === tool.id;

            return (
              <div
                key={tool.id}
                className={`bg-slate-900/95 border rounded-xl p-5 flex flex-col justify-between transition-all ${tool.active
                    ? 'border-emerald-800/50 hover:border-emerald-700/80'
                    : tool.installed
                      ? 'border-amber-800/60'
                      : 'border-rose-900/50'
                  }`}
              >
                <div>
                  {/* Top Row: Tool Name, Category, Active Status Badge */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2 flex-wrap gap-y-1">
                        <span className={`inline-flex items-center space-x-1 text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${cat.color}`}>
                          {cat.icon}
                          <span>{cat.label}</span>
                        </span>
                        <code className="text-[11px] font-mono text-indigo-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                          {tool.binary}
                        </code>
                        <span className="text-[10px] font-mono text-slate-500">
                          {tool.latencyMs}ms
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-white pt-0.5">{tool.name}</h3>
                    </div>

                    {/* ACTIVE / INACTIVE Badge */}
                    <div className="shrink-0">
                      {tool.active ? (
                        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-emerald-950/90 text-emerald-400 border border-emerald-500/50 shadow-sm shadow-emerald-950">
                          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                          <span>ACTIVE</span>
                        </span>
                      ) : tool.installed ? (
                        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-amber-950/90 text-amber-300 border border-amber-500/50">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                          <span>INACTIVE (TEST FAILED)</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider bg-rose-950/90 text-rose-400 border border-rose-500/50">
                          <XCircle className="w-3.5 h-3.5 text-rose-400" />
                          <span>INACTIVE</span>
                        </span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                    {tool.description}
                  </p>

                  {/* Binary Path & Version Details */}
                  <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 bg-slate-950/80 border border-slate-800/80 rounded-lg p-2.5 text-[11px] font-mono">
                    <div className="truncate">
                      <span className="text-slate-500">Binary Path: </span>
                      <span className={tool.installed ? 'text-slate-200' : 'text-rose-400'}>
                        {tool.path || 'Not installed'}
                      </span>
                    </div>
                    <div className="truncate">
                      <span className="text-slate-500">Version: </span>
                      <span className="text-indigo-300">
                        {tool.version || 'N/A'}
                      </span>
                    </div>
                  </div>

                  {/* Functional Verification Proof Box */}
                  <div className="mt-3 bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-1.5">
                    <div className="flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider">
                      <span className="text-slate-400 flex items-center space-x-1.5">
                        <ShieldCheck className={`w-3.5 h-3.5 ${tool.active ? 'text-emerald-400' : 'text-rose-400'}`} />
                        <span>Auditor Usability Self-Test</span>
                      </span>
                      <span className={tool.active ? 'text-emerald-400' : 'text-rose-400'}>
                        {tool.active ? '✓ VERIFIED USABLE' : '✗ NOT VERIFIED'}
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 truncate">
                      <span className="text-slate-600">$ </span>
                      {tool.verificationTest}
                    </div>
                    <div className={`text-[11px] font-mono leading-relaxed break-words ${tool.active ? 'text-emerald-300/90' : 'text-rose-300/90'}`}>
                      {tool.verificationOutput}
                    </div>
                  </div>

                  {/* Used By Subsystems */}
                  <div className="mt-3 flex flex-wrap items-center gap-1.5">
                    <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-500 mr-1">
                      Used By:
                    </span>
                    {tool.usedBy.map((u, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] bg-slate-800/80 text-slate-300 px-2 py-0.5 rounded border border-slate-700/60"
                      >
                        {u}
                      </span>
                    ))}
                  </div>

                  {/* Inline Gemini 3.8 API Key Setup on @google/genai card */}
                  {tool.id === 'gemini_ai' && (
                    <div className="mt-3 p-3 rounded-lg bg-indigo-950/30 border border-indigo-700/50 space-y-2">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-indigo-300">
                        Configure Live Gemini 3.8 API Key (or edit data/.env)
                      </div>
                      <div className="flex items-center gap-2">
                        <input
                          type="password"
                          value={inlineApiKey}
                          onChange={(e) => setInlineApiKey(e.target.value)}
                          placeholder="Paste GEMINI_API_KEY (AIzaSy...)..."
                          className="flex-1 px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                        />
                        <button
                          onClick={handleSaveInlineApiKey}
                          disabled={savingApiKey || !inlineApiKey.trim()}
                          className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded text-xs font-bold cursor-pointer shrink-0"
                        >
                          {savingApiKey ? 'Saving...' : 'Save Key'}
                        </button>
                      </div>
                      {apiKeySavedMsg && (
                        <div className="text-[11px] font-mono text-emerald-400">{apiKeySavedMsg}</div>
                      )}
                    </div>
                  )}
                </div>

                {/* Bottom Action / Install Bar */}
                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                  {!tool.active ? (
                    <div className="flex items-center space-x-2 flex-1 min-w-0">
                      <code className="text-[11px] font-mono bg-amber-950/40 text-amber-300 px-2.5 py-1 rounded border border-amber-800/50 truncate flex-1">
                        {tool.installCommand}
                      </code>
                      <button
                        onClick={() => handleCopyCommand(tool.id, tool.installCommand)}
                        className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 shrink-0 cursor-pointer"
                        title="Copy install command"
                      >
                        {copiedId === tool.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ) : (
                    <span className="text-[11px] text-emerald-400/90 font-medium flex items-center space-x-1">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>Ready for real-time security auditing</span>
                    </span>
                  )}

                  <button
                    onClick={() => handleVerifySingleTool(tool.id)}
                    disabled={isVerifyingThis || loading}
                    className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-indigo-600/80 text-slate-200 hover:text-white rounded-lg text-xs font-semibold transition-all border border-slate-700 shrink-0 cursor-pointer disabled:opacity-50"
                  >
                    <Play className={`w-3 h-3 ${isVerifyingThis ? 'animate-spin' : ''}`} />
                    <span>{isVerifyingThis ? 'Testing...' : 'Run Self-Test'}</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

