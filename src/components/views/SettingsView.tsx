import React, { useState, useEffect } from 'react';
import { 
  Settings as SettingsIcon, 
  Cpu, 
  ShieldCheck, 
  Sliders, 
  Smartphone, 
  Monitor, 
  Lock, 
  Save, 
  CheckCircle2, 
  FileText,
  Key,
  RotateCcw,
  Terminal,
  RefreshCw,
  AlertTriangle,
  Server,
  Zap
} from 'lucide-react';
import { PlatformSettings } from '../../types';

interface SettingsViewProps {
  settings: PlatformSettings;
  onSaveSettings: (settings: PlatformSettings) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  settings,
  onSaveSettings
}) => {
  const [localSettings, setLocalSettings] = useState<PlatformSettings>(settings);
  const [savedSuccess, setSavedSuccess] = useState(false);

  // Linux AppSec Tools Diagnostic State
  const [toolsStatus, setToolsStatus] = useState<{
    platform: string;
    arch: string;
    tools: Record<string, { installed: boolean; version?: string; path?: string }>;
    summary?: any;
  } | null>(null);
  const [isLoadingTools, setIsLoadingTools] = useState(false);

  useEffect(() => {
    fetchToolsStatus();
  }, []);

  const fetchToolsStatus = async () => {
    setIsLoadingTools(true);
    try {
      const res = await fetch('/api/tools/status');
      if (res.ok) {
        const data = await res.json();
        setToolsStatus(data);
      }
    } catch (e) {
      console.warn('Could not fetch tools status:', e);
    } finally {
      setIsLoadingTools(false);
    }
  };

  const handleSave = () => {
    onSaveSettings(localSettings);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  const handleReset = () => {
    const defaults: PlatformSettings = {
      aiModel: 'gemini-2.5-pro',
      enableSAST: true,
      enableSCA: true,
      enableSecrets: true,
      enableConfig: true,
      enableMobileStatic: true,
      enableBinaryStatic: true,
      enableWebRecon: true,
      enableSecurityHeaders: true,
      autoGeneratePatches: true,
      autoVerifyPatches: true,
      complianceStandard: 'OWASP_TOP_10',
      minSeverityThreshold: 'LOW',
      strictMode: true
    };
    setLocalSettings(defaults);
    onSaveSettings(defaults);
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <SettingsIcon className="h-5 w-5 text-blue-400" />
            <h1 className="text-base font-black text-white uppercase tracking-wider">
              Auditor Platform Settings & Engine Config
            </h1>
          </div>
          <p className="text-xs text-gray-400 mt-1 max-w-2xl leading-relaxed">
            Configure autonomous AI reasoning models, Linux CLI security engines, DAST network probes, and compliance verification standards.
          </p>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={handleReset}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-xl bg-[#1A1A1A] hover:bg-[#242424] border border-[#2A2A2A] text-gray-300 hover:text-white text-xs font-mono transition-all"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            <span>Reset Defaults</span>
          </button>
          <button
            onClick={handleSave}
            className="flex items-center space-x-2 px-5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all shadow-lg"
          >
            <Save className="h-4 w-4" />
            <span>Save Configuration</span>
          </button>
        </div>
      </div>

      {savedSuccess && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-xs font-mono text-emerald-300 flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          <span>Platform configuration updated successfully. Applied to subsequent scan cycles.</span>
        </div>
      )}

      {/* Linux AppSec Tools Diagnostic Center */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="h-5 w-5 text-[#FF3B30]" />
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Linux AppSec Tools & Engine Diagnostics
              </h2>
              <p className="text-xs text-gray-400 mt-0.5">
                Status of command-line security binaries installed on the host system ({toolsStatus?.platform || 'Linux'} {toolsStatus?.arch || ''})
              </p>
            </div>
          </div>
          <button
            onClick={fetchToolsStatus}
            disabled={isLoadingTools}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#181818] hover:bg-[#222222] border border-[#262626] text-xs font-mono text-gray-300 hover:text-white transition-colors"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoadingTools ? 'animate-spin text-blue-400' : ''}`} />
            <span>Rescan Tools</span>
          </button>
        </div>

        {toolsStatus?.tools ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              { id: 'nmap', name: 'Nmap Network Scanner', role: 'DAST / Port & CVE NSE Scripts', installCmd: 'apt install nmap' },
              { id: 'semgrep', name: 'Semgrep SAST', role: 'Static Code Analysis & Taint Tracking', installCmd: 'pip3 install semgrep' },
              { id: 'gitleaks', name: 'Gitleaks Secrets', role: 'API Key & Token Discovery', installCmd: 'setup_linux.sh' },
              { id: 'trivy', name: 'Trivy Scanner', role: 'Container & IaC Security', installCmd: 'apt install trivy' },
              { id: 'bandit', name: 'Bandit Python SAST', role: 'Python AST Security Auditing', installCmd: 'pip3 install bandit' },
              { id: 'pipAudit', name: 'pip-audit SCA', role: 'Python Dependency CVE Auditing', installCmd: 'pip3 install pip-audit' },
              { id: 'git', name: 'Git CLI', role: 'Repository Ingestion & Cloning', installCmd: 'apt install git' },
              { id: 'python3', name: 'Python 3 Runtime', role: 'Script Execution & Virtualenvs', installCmd: 'apt install python3' },
              { id: 'docker', name: 'Docker Engine', role: 'Container Sandbox Environments', installCmd: 'apt install docker.io' }
            ].map(tool => {
              const status = toolsStatus.tools[tool.id];
              const isInstalled = Boolean(status?.installed);

              return (
                <div
                  key={tool.id}
                  className={`p-3.5 rounded-xl border font-mono text-xs space-y-1.5 transition-all ${
                    isInstalled
                      ? 'bg-emerald-950/20 border-emerald-800/60'
                      : 'bg-[#141414] border-[#222222]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white text-xs">{tool.name}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      isInstalled
                        ? 'bg-emerald-900/80 text-emerald-300 border border-emerald-700'
                        : 'bg-amber-950/80 text-amber-300 border border-amber-800'
                    }`}>
                      {isInstalled ? 'READY' : 'NOT FOUND'}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-400 font-sans">{tool.role}</p>
                  
                  {isInstalled ? (
                    <div className="pt-1 text-[10px] text-gray-500 truncate" title={status?.path}>
                      Path: {status?.path}
                    </div>
                  ) : (
                    <div className="pt-1 text-[10px] text-amber-400/80">
                      Install: <code className="bg-black/60 px-1 py-0.5 rounded text-gray-300">{tool.installCmd}</code>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="p-4 bg-[#141414] border border-[#222222] rounded-xl text-xs font-mono text-gray-400">
            Click 'Rescan Tools' to query system tool availability on the Linux host.
          </div>
        )}

        <div className="p-3 bg-[#161616] border border-[#222222] rounded-xl flex items-center justify-between text-xs text-gray-400">
          <span>Linux 1-Command Automated Toolchain Installer:</span>
          <code className="bg-black px-2.5 py-1 rounded text-emerald-400 font-mono text-xs border border-[#2A2A2A]">
            chmod +x setup_linux.sh && ./setup_linux.sh
          </code>
        </div>
      </div>

      {/* Grid: 2 Columns */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Card 1: AI Reasoning Model */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center space-x-2">
            <Cpu className="h-4 w-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">AI Reasoning & Synthesis Engine</h3>
          </div>

          <div className="space-y-3">
            {[
              {
                id: 'gemini-2.5-pro',
                name: 'Gemini 2.5 Pro (Security Specialist)',
                badge: 'RECOMMENDED',
                desc: 'Deep multi-file taint tracking, semantic AST reasoning, and zero-shot exploit chain synthesis.'
              },
              {
                id: 'gemini-2.5-flash',
                name: 'Gemini 2.5 Flash (Ultra High-Speed)',
                badge: 'FASTEST',
                desc: 'Optimized sub-second patch verification and rapid bulk vulnerability triage.'
              },
              {
                id: 'hybrid-sast-llm',
                name: 'Hybrid Deterministic SAST + GenAI',
                badge: 'HIGH ACCURACY',
                desc: 'Combines local regularized rule evaluation with LLM-guided root cause explanation.'
              }
            ].map((m) => (
              <label
                key={m.id}
                className={`p-3.5 rounded-xl border flex items-start space-x-3 cursor-pointer transition-all ${
                  localSettings.aiModel === m.id
                    ? 'bg-[#181818] border-blue-500 text-white'
                    : 'bg-[#141414] border-[#1F1F1F] text-gray-400 hover:border-[#333333]'
                }`}
              >
                <input
                  type="radio"
                  name="aiModel"
                  value={m.id}
                  checked={localSettings.aiModel === m.id}
                  onChange={(e) => setLocalSettings({ ...localSettings, aiModel: e.target.value })}
                  className="mt-1"
                />
                <div className="space-y-1 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{m.name}</span>
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800 font-bold">
                      {m.badge}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400 leading-relaxed">{m.desc}</p>
                </div>
              </label>
            ))}
          </div>
        </div>

        {/* Card 2: Security Scanners Enablement */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center space-x-2">
            <Sliders className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Active Analysis Engines</h3>
          </div>

          <div className="space-y-2.5">
            {[
              { key: 'enableSAST', label: 'Static Application Security Testing (SAST)', desc: 'SQLi, RCE, XSS, and broken access controls.' },
              { key: 'enableSecrets', label: 'Secret & API Credential Scanner', desc: 'AWS Keys, Stripe live secrets, JWT tokens, DB URIs.' },
              { key: 'enableSCA', label: 'Software Composition Analysis (SCA)', desc: 'Live OSV API and CVE audit on package.json & requirements.txt.' },
              { key: 'enableConfig', label: 'Cloud Config & Infrastructure as Code', desc: 'Dockerfile root execution, Kubernetes privileges, CORS.' },
              { key: 'enableWebRecon', label: 'Website Reconnaissance & Discovery', desc: 'DNS, SSL/TLS, GraphQL schemas, exposed routes, API portals.' },
              { key: 'enableSecurityHeaders', label: 'HTTP Security Headers & Cookies', desc: 'CSP, HSTS, X-Frame-Options, SameSite/HttpOnly cookie audit.' },
              { key: 'enableMobileStatic', label: 'Mobile APK & iOS Plist Static Analyzer', desc: 'TrustManager, debuggable flags, ATS bypass, Keychain.' },
              { key: 'enableBinaryStatic', label: 'Desktop Windows EXE & macOS DMG Analyzer', desc: 'PE ASLR/DEP headers, unquoted paths, Hardened Runtime.' }
            ].map((eng) => (
              <label
                key={eng.key}
                className="flex items-center justify-between p-3 rounded-xl bg-[#141414] border border-[#1F1F1F] cursor-pointer hover:border-[#333333] transition-all"
              >
                <div className="space-y-0.5 pr-4">
                  <span className="text-xs font-bold text-white block">{eng.label}</span>
                  <span className="text-[11px] text-gray-500 block">{eng.desc}</span>
                </div>
                <input
                  type="checkbox"
                  checked={(localSettings as any)[eng.key]}
                  onChange={(e) => setLocalSettings({ ...localSettings, [eng.key]: e.target.checked })}
                  className="h-4 w-4 rounded accent-blue-600"
                />
              </label>
            ))}
          </div>
        </div>

        {/* Card 3: Autonomous Remediation & Verification Rules */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="h-4 w-4 text-purple-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Automated Verification Guardrails</h3>
          </div>

          <div className="space-y-3">
            <label className="flex items-center justify-between p-3 rounded-xl bg-[#141414] border border-[#1F1F1F] cursor-pointer hover:border-[#333333]">
              <div>
                <span className="text-xs font-bold text-white block">Auto-Generate Syntactic Code Patches</span>
                <span className="text-[11px] text-gray-500 block">Synthesize unified diffs with parameterization and secret isolation.</span>
              </div>
              <input
                type="checkbox"
                checked={localSettings.autoGeneratePatches}
                onChange={(e) => setLocalSettings({ ...localSettings, autoGeneratePatches: e.target.checked })}
                className="h-4 w-4 rounded accent-blue-600"
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-xl bg-[#141414] border border-[#1F1F1F] cursor-pointer hover:border-[#333333]">
              <div>
                <span className="text-xs font-bold text-white block">Automated Test Execution & Rescan</span>
                <span className="text-[11px] text-gray-500 block">Execute unit assertions and generate cryptographic proof hashes.</span>
              </div>
              <input
                type="checkbox"
                checked={localSettings.autoVerifyPatches}
                onChange={(e) => setLocalSettings({ ...localSettings, autoVerifyPatches: e.target.checked })}
                className="h-4 w-4 rounded accent-blue-600"
              />
            </label>

            <label className="flex items-center justify-between p-3 rounded-xl bg-[#141414] border border-[#1F1F1F] cursor-pointer hover:border-[#333333]">
              <div>
                <span className="text-xs font-bold text-white block">Strict Mode (Fail Build on Critical Findings)</span>
                <span className="text-[11px] text-gray-500 block">Triggers CI/CD exit code 1 if unpatched Critical CVEs exist.</span>
              </div>
              <input
                type="checkbox"
                checked={localSettings.strictMode}
                onChange={(e) => setLocalSettings({ ...localSettings, strictMode: e.target.checked })}
                className="h-4 w-4 rounded accent-blue-600"
              />
            </label>
          </div>
        </div>

        {/* Card 4: Default Compliance Standard */}
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center space-x-2">
            <Lock className="h-4 w-4 text-amber-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">Default Regulatory Benchmark</h3>
          </div>

          <div className="space-y-2">
            <label className="block text-xs font-mono uppercase text-gray-400">Primary Audit Framework</label>
            <select
              value={localSettings.complianceStandard}
              onChange={(e) => setLocalSettings({ ...localSettings, complianceStandard: e.target.value as any })}
              className="w-full px-3 py-2.5 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white focus:outline-none focus:border-blue-500"
            >
              <option value="OWASP_TOP_10">OWASP Top 10 (2021) - Application Security</option>
              <option value="NIST_800_53">NIST SP 800-53 Rev 5 - Federal Security Controls</option>
              <option value="SOC2_TYPE_II">SOC 2 Type II - Trust Services Criteria</option>
              <option value="ISO_27001">ISO/IEC 27001:2022 - Global ISMS Controls</option>
              <option value="PCI_DSS_V4">PCI-DSS v4.0 - Payment Cardholder Security</option>
              <option value="HIPAA">HIPAA Security Rule - Protected Healthcare Data</option>
            </select>
          </div>

          <div className="pt-2">
            <label className="block text-xs font-mono uppercase text-gray-400 mb-1">Minimum Alert Threshold</label>
            <select
              value={localSettings.minSeverityThreshold}
              onChange={(e) => setLocalSettings({ ...localSettings, minSeverityThreshold: e.target.value as any })}
              className="w-full px-3 py-2.5 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white focus:outline-none focus:border-blue-500"
            >
              <option value="LOW">Low (Include all minor code style & warnings)</option>
              <option value="MEDIUM">Medium (Default - Exclude purely informational items)</option>
              <option value="HIGH">High (Alert only on High & Critical risks)</option>
              <option value="CRITICAL">Critical (Zero-day & urgent exploitable vectors only)</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
};
