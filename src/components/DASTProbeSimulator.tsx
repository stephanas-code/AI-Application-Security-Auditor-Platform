import React, { useState } from 'react';
import { 
  Radar, 
  CheckCircle2, 
  AlertTriangle, 
  Play, 
  RefreshCw,
  Terminal,
  Globe,
  Server,
  ShieldAlert,
  Loader2,
  Lock,
  Layers,
  Cpu
} from 'lucide-react';
import { VulnerabilityFinding } from '../types';

interface DASTProbeSimulatorProps {
  findings: VulnerabilityFinding[];
}

export const DASTProbeSimulator: React.FC<DASTProbeSimulatorProps> = ({ findings }) => {
  const [activeMode, setActiveMode] = useState<'nmap' | 'http_probe' | 'payload_test'>('nmap');
  
  // Real Nmap Scanner State
  const [nmapTarget, setNmapTarget] = useState('127.0.0.1');
  const [nmapProfile, setNmapProfile] = useState<'quick' | 'comprehensive' | 'vuln' | 'ports'>('quick');
  const [nmapPorts, setNmapPorts] = useState('80,443,3000,8080,5000,8000');
  const [isNmapRunning, setIsNmapRunning] = useState(false);
  const [nmapResult, setNmapResult] = useState<{
    target: string;
    command: string;
    nmapInstalled: boolean;
    openPorts: Array<{ port: number; protocol: string; state: string; service: string; version?: string }>;
    rawOutput: string;
    scannedAt: string;
  } | null>(null);

  // Real HTTP Web Probe State
  const [httpTargetUrl, setHttpTargetUrl] = useState('http://localhost:3000');
  const [isHttpProbing, setIsHttpProbing] = useState(false);
  const [httpProbeResult, setHttpProbeResult] = useState<{
    url: string;
    statusCode: number;
    responseTimeMs: number;
    headers: Record<string, string>;
    tls: any;
    headerAudit: Array<{ header: string; name: string; present: boolean; value: string | null; risk: string; recommendation: string }>;
  } | null>(null);

  // Custom Endpoint Payload Probe
  const [selectedEndpoint, setSelectedEndpoint] = useState<string>('sqli');
  const [customPayload, setCustomPayload] = useState<string>("1 OR 1=1 --");
  const [isProbing, setIsProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<{
    status: number;
    responseTimeMs: number;
    vulnerable: boolean;
    serverOutput: string;
    analysis: string;
  } | null>(null);

  const isSqlPatched = findings.find(f => f.id.includes('sast-sqli'))?.status === 'VERIFIED_RESOLVED';
  const isCmdPatched = findings.find(f => f.id.includes('sast-cmdi'))?.status === 'VERIFIED_RESOLVED';
  const isAdminPatched = findings.find(f => f.id.includes('sast-auth'))?.status === 'VERIFIED_RESOLVED';

  const endpoints = [
    {
      id: 'sqli',
      name: 'GET /api/transactions/search',
      type: 'SQL Injection Probe',
      defaultPayload: "1 OR 1=1 --",
      method: 'GET',
      isPatched: isSqlPatched,
      description: 'Tests parameterization against account ID SQL query injection.'
    },
    {
      id: 'cmdi',
      name: 'POST /diagnostics/network-probe',
      type: 'Command Injection Probe',
      defaultPayload: '{"host": "127.0.0.1; whoami; cat /etc/passwd"}',
      method: 'POST',
      isPatched: isCmdPatched,
      description: 'Tests shell argument escape delimiters in diagnostic ping service.'
    },
    {
      id: 'admin',
      name: 'GET /api/admin/dump-users',
      type: 'Broken Auth / Admin Exposure',
      defaultPayload: 'Anonymous request (No Authorization Header)',
      method: 'GET',
      isPatched: isAdminPatched,
      description: 'Tests role-based authorization guard on customer credentials dump.'
    }
  ];

  // Execute Real Nmap Scan
  const handleRunNmapScan = async () => {
    if (!nmapTarget.trim()) return;
    setIsNmapRunning(true);
    setNmapResult(null);

    try {
      const res = await fetch('/api/scan/dast/nmap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: nmapTarget.trim(),
          profile: nmapProfile,
          ports: nmapPorts.trim()
        })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setNmapResult(data);
      } else {
        throw new Error(data.error || 'Nmap scan failed');
      }
    } catch (err: any) {
      setNmapResult({
        target: nmapTarget,
        command: `nmap scan failed: ${err.message}`,
        nmapInstalled: false,
        openPorts: [],
        rawOutput: `[ERROR] Failed to execute network reconnaissance:\n${err.message}`,
        scannedAt: new Date().toISOString()
      });
    } finally {
      setIsNmapRunning(false);
    }
  };

  // Execute Real HTTP Web Security Probe
  const handleRunHttpProbe = async () => {
    if (!httpTargetUrl.trim()) return;
    setIsHttpProbing(true);
    setHttpProbeResult(null);

    try {
      const res = await fetch('/api/scan/dast/http-probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: httpTargetUrl.trim() })
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setHttpProbeResult(data);
      } else {
        throw new Error(data.error || 'HTTP probe failed');
      }
    } catch (err: any) {
      alert(`HTTP Probe failed: ${err.message}`);
    } finally {
      setIsHttpProbing(false);
    }
  };

  const handleSelectEndpoint = (id: string) => {
    setSelectedEndpoint(id);
    const ep = endpoints.find(e => e.id === id);
    if (ep) {
      setCustomPayload(ep.defaultPayload);
      setProbeResult(null);
    }
  };

  const handleRunPayloadProbe = async () => {
    setIsProbing(true);
    setProbeResult(null);

    const ep = endpoints.find(e => e.id === selectedEndpoint);
    const isPatched = ep?.isPatched;

    try {
      // Construct real target endpoint URL from httpUrl + endpoint path
      const baseOrigin = httpUrl.startsWith('http') ? httpUrl.replace(/\/$/, '') : `https://${httpUrl.replace(/\/$/, '')}`;
      const cleanPath = (ep?.path || '/').split('?')[0];
      const fullTargetUrl = `${baseOrigin}${cleanPath}`;

      const res = await fetch('/api/scan/dast/fuzz-endpoint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetUrl: fullTargetUrl,
          method: ep?.method || 'GET',
          paramName: selectedEndpoint === 'sqli' ? 'accountId' : selectedEndpoint === 'cmdi' ? 'host' : 'role',
          payload: customPayload
        })
      });
      const data = await res.json();

      if (res.ok && data.success) {
        const isVuln =
          data.analysisVerdict === 'VULNERABLE_SQL_ERROR' ||
          data.analysisVerdict === 'VULNERABLE_REFLECTED_PAYLOAD' ||
          data.analysisVerdict === 'SERVER_EXCEPTION_5XX' ||
          (!isPatched && data.statusCode === 200 && selectedEndpoint === 'auth');

        const headerLines = Object.entries(data.headers || {})
          .slice(0, 8)
          .map(([k, v]) => `${k}: ${v}`)
          .join('\n');

        setProbeResult({
          status: data.statusCode,
          responseTimeMs: data.elapsedMs,
          vulnerable: isVuln,
          serverOutput: `HTTP/1.1 ${data.statusCode}\nRequest-URL: ${data.requestUrl}\n${headerLines}\n\n${data.bodySnippet || '(Empty response body)'}`,
          analysis: data.analysisSummary
        });
      } else {
        setProbeResult({
          status: 0,
          responseTimeMs: 0,
          vulnerable: false,
          serverOutput: `Probe Error: ${data.error || 'Target host unreachable'}`,
          analysis: `Could not reach ${fullTargetUrl}. Ensure the target web server is running and reachable from the Linux host.`
        });
      }
    } catch (err: any) {
      setProbeResult({
        status: 0,
        responseTimeMs: 0,
        vulnerable: false,
        serverOutput: `Network Error: ${err.message}`,
        analysis: 'Failed to dispatch active DAST payload probe via backend.'
      });
    } finally {
      setIsProbing(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Mode Selector */}
      <div className="flex items-center justify-between bg-[#141414] p-1.5 rounded-xl border border-[#1F1F1F]">
        <div className="flex space-x-1">
          <button
            onClick={() => setActiveMode('nmap')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeMode === 'nmap'
                ? 'bg-[#FF3B30] text-black shadow-md'
                : 'text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
            }`}
          >
            <Radar className="h-4 w-4" />
            <span>Nmap Recon & Port Scanner</span>
          </button>

          <button
            onClick={() => setActiveMode('http_probe')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeMode === 'http_probe'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>Live HTTP & Header Auditor</span>
          </button>

          <button
            onClick={() => setActiveMode('payload_test')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-bold transition-all ${
              activeMode === 'payload_test'
                ? 'bg-purple-600 text-white shadow-md'
                : 'text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
            }`}
          >
            <Terminal className="h-4 w-4" />
            <span>Vulnerability Verification Fuzzer</span>
          </button>
        </div>

        <span className="text-[11px] font-mono text-gray-500 hidden md:inline-block pr-2">
          Linux Native DAST Execution
        </span>
      </div>

      {/* MODE 1: NMAP SCANNER */}
      {activeMode === 'nmap' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                  <Radar className="h-4 w-4 text-[#FF3B30]" />
                  <span>Real Nmap Network Reconnaissance & Vulnerability Scripting</span>
                </h3>
                <p className="text-xs text-gray-400 mt-1">
                  Executes real `nmap` commands against target hosts or containers to identify open ports, service versions, and run NSE vulnerability scripts.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div>
                <label className="block text-[10px] font-mono uppercase text-gray-400 mb-1">Target Host / IP / Domain</label>
                <input
                  type="text"
                  value={nmapTarget}
                  onChange={(e) => setNmapTarget(e.target.value)}
                  placeholder="127.0.0.1 or scanme.nmap.org"
                  className="w-full px-3 py-2 bg-black border border-[#222222] rounded-xl font-mono text-xs text-white focus:outline-none focus:border-[#FF3B30]"
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono uppercase text-gray-400 mb-1">Scan Profile</label>
                <select
                  value={nmapProfile}
                  onChange={(e: any) => setNmapProfile(e.target.value)}
                  className="w-full px-3 py-2 bg-black border border-[#222222] rounded-xl text-xs text-white focus:outline-none focus:border-[#FF3B30]"
                >
                  <option value="quick">Quick Discovery (-sV -T4)</option>
                  <option value="comprehensive">Comprehensive Audit (-sV -sC -T4)</option>
                  <option value="vuln">Vulnerability NSE Scripts (--script vuln,http-*)</option>
                  <option value="ports">Full Port Range (-p 1-65535)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] font-mono uppercase text-gray-400 mb-1">Target Ports</label>
                <input
                  type="text"
                  value={nmapPorts}
                  onChange={(e) => setNmapPorts(e.target.value)}
                  placeholder="80,443,3000,8080"
                  className="w-full px-3 py-2 bg-black border border-[#222222] rounded-xl font-mono text-xs text-white focus:outline-none focus:border-[#FF3B30]"
                />
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={handleRunNmapScan}
                disabled={isNmapRunning}
                className="flex items-center space-x-2 px-6 py-2.5 bg-[#FF3B30] hover:bg-[#D32F2F] text-black font-black uppercase text-xs tracking-wider rounded-xl transition-all shadow-lg disabled:opacity-50"
              >
                {isNmapRunning ? <Loader2 className="h-4 w-4 animate-spin text-black" /> : <Play className="h-4 w-4 fill-black" />}
                <span>{isNmapRunning ? 'Executing Nmap...' : 'Launch Nmap Scan'}</span>
              </button>
            </div>
          </div>

          {/* Nmap Results Console */}
          {nmapResult && (
            <div className="space-y-4 animate-in fade-in">
              {/* Discovered Ports Table */}
              <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F]">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span className="text-xs font-bold text-white uppercase font-mono">Discovered Open Ports ({nmapResult.openPorts.length})</span>
                  </div>
                  <span className="text-[11px] font-mono text-gray-500">Command: {nmapResult.command}</span>
                </div>

                {nmapResult.openPorts.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-[#222222] text-gray-400">
                          <th className="py-2">Port</th>
                          <th className="py-2">Protocol</th>
                          <th className="py-2">State</th>
                          <th className="py-2">Service</th>
                          <th className="py-2">Version Fingerprint</th>
                        </tr>
                      </thead>
                      <tbody>
                        {nmapResult.openPorts.map((p, idx) => (
                          <tr key={idx} className="border-b border-[#1A1A1A] hover:bg-[#161616]">
                            <td className="py-2.5 text-blue-400 font-bold">{p.port}</td>
                            <td className="py-2.5 text-gray-400 uppercase">{p.protocol}</td>
                            <td className="py-2.5">
                              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px]">
                                {p.state}
                              </span>
                            </td>
                            <td className="py-2.5 text-white font-semibold">{p.service}</td>
                            <td className="py-2.5 text-gray-400">{p.version || 'Standard daemon'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="py-4 text-center text-xs text-gray-500 font-mono">
                    Zero open ports reported on target for specified port range.
                  </div>
                )}
              </div>

              {/* Raw stdout/stderr terminal */}
              <div className="rounded-xl overflow-hidden border border-[#222222] bg-black">
                <div className="px-4 py-2 bg-[#161616] border-b border-[#222222] flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Terminal className="h-3.5 w-3.5 text-gray-400" />
                    <span className="text-[11px] font-mono text-gray-400">Nmap Console Output</span>
                  </div>
                  <span className="text-[10px] font-mono text-gray-600">{nmapResult.scannedAt}</span>
                </div>
                <pre className="p-4 text-xs font-mono text-gray-300 overflow-x-auto max-h-72 leading-relaxed">
                  {nmapResult.rawOutput}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}

      {/* MODE 2: HTTP PROBER */}
      {activeMode === 'http_probe' && (
        <div className="space-y-4">
          <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Globe className="h-4 w-4 text-blue-400" />
                <span>Live HTTP/TLS Security Header & CORS Prober</span>
              </h3>
              <p className="text-xs text-gray-400 mt-1">
                Directly connects to target web applications and APIs, performing deep audits on SSL/TLS ciphers, HSTS, CSP, and CORS policies.
              </p>
            </div>

            <div className="flex space-x-2">
              <input
                type="text"
                value={httpTargetUrl}
                onChange={(e) => setHttpTargetUrl(e.target.value)}
                placeholder="https://app.example.com"
                className="flex-1 px-3.5 py-2.5 bg-black border border-[#222222] rounded-xl font-mono text-xs text-white focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={handleRunHttpProbe}
                disabled={isHttpProbing}
                className="flex items-center space-x-2 px-6 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-bold uppercase text-xs tracking-wider rounded-xl transition-all shadow-lg disabled:opacity-50"
              >
                {isHttpProbing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Globe className="h-4 w-4" />}
                <span>{isHttpProbing ? 'Probing...' : 'Audit Endpoint'}</span>
              </button>
            </div>
          </div>

          {httpProbeResult && (
            <div className="space-y-4 animate-in fade-in">
              {/* Header Audit Cards */}
              <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F] space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white uppercase font-mono">
                    Security Headers & Policy Compliance (HTTP {httpProbeResult.statusCode} in {httpProbeResult.responseTimeMs}ms)
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {httpProbeResult.headerAudit.map((h, idx) => (
                    <div
                      key={idx}
                      className={`p-3.5 rounded-xl border ${
                        h.risk === 'HIGH'
                          ? 'bg-rose-950/20 border-rose-800/60'
                          : h.risk === 'MEDIUM'
                          ? 'bg-amber-950/20 border-amber-800/60'
                          : 'bg-emerald-950/20 border-emerald-800/60'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-bold text-white font-mono">{h.name}</span>
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                          h.risk === 'HIGH' ? 'bg-rose-900 text-rose-200' : h.risk === 'MEDIUM' ? 'bg-amber-900 text-amber-200' : 'bg-emerald-900 text-emerald-200'
                        }`}>
                          {h.risk === 'PASS' ? 'SECURE' : `${h.risk} RISK`}
                        </span>
                      </div>
                      <p className="text-[11px] text-gray-400 mt-1">{h.recommendation}</p>
                      {h.value && (
                        <div className="mt-2 p-2 bg-black/60 rounded font-mono text-[10px] text-gray-300 truncate">
                          Value: {h.value}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* MODE 3: PAYLOAD VERIFICATION FUZZER */}
      {activeMode === 'payload_test' && (
        <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
                <Terminal className="h-4 w-4 text-purple-400" />
                <span>Vulnerability Exploit & Rescan Verification Fuzzer</span>
              </h3>
              <p className="text-xs text-gray-400 mt-1">
                Dispatches targeted exploit payloads against audited endpoints before and after patch application to prove remediation correctness.
              </p>
            </div>
          </div>

          {/* Endpoint selection tabs */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            {endpoints.map((ep) => (
              <button
                key={ep.id}
                onClick={() => handleSelectEndpoint(ep.id)}
                className={`p-3 rounded-xl border text-left transition-all ${
                  selectedEndpoint === ep.id
                    ? 'bg-[#181818] border-purple-500 shadow-md'
                    : 'bg-[#141414] border-[#1F1F1F] hover:bg-[#1A1A1A]'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono font-bold uppercase text-purple-400">{ep.type}</span>
                  {ep.isPatched ? (
                    <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[9px] font-mono">
                      PATCH VERIFIED
                    </span>
                  ) : (
                    <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 border border-rose-800 text-[9px] font-mono">
                      VULNERABLE
                    </span>
                  )}
                </div>
                <div className="text-xs font-mono text-white truncate">{ep.name}</div>
              </button>
            ))}
          </div>

          <div className="space-y-2">
            <label className="block text-[10px] font-mono uppercase text-gray-400">Injected Security Payload</label>
            <div className="flex space-x-2">
              <input
                type="text"
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                className="flex-1 px-3.5 py-2 bg-black border border-[#222222] rounded-xl font-mono text-xs text-white focus:outline-none focus:border-purple-500"
              />
              <button
                onClick={handleRunPayloadProbe}
                disabled={isProbing}
                className="flex items-center space-x-2 px-5 py-2 bg-purple-600 hover:bg-purple-500 text-white font-bold uppercase text-xs tracking-wider rounded-xl transition-all shadow-lg disabled:opacity-50"
              >
                {isProbing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4 fill-white" />}
                <span>{isProbing ? 'Testing...' : 'Execute Payload'}</span>
              </button>
            </div>
          </div>

          {/* Probe result */}
          {probeResult && (
            <div className={`p-4 rounded-xl border font-mono text-xs space-y-2 animate-in fade-in ${
              probeResult.vulnerable
                ? 'bg-rose-950/20 border-rose-800/80 text-rose-200'
                : 'bg-emerald-950/20 border-emerald-800/80 text-emerald-200'
            }`}>
              <div className="flex items-center justify-between">
                <span className="font-bold uppercase tracking-wider">
                  {probeResult.vulnerable ? '🔴 Vulnerability Confirmed Exploitable' : '🟢 Defense Verified (Vulnerability Resolved)'}
                </span>
                <span className="text-[11px] text-gray-400">{probeResult.responseTimeMs}ms latency</span>
              </div>
              <p className="text-xs text-gray-300 leading-relaxed">{probeResult.analysis}</p>
              <pre className="p-3 rounded bg-black/70 border border-[#222222] text-[11px] text-gray-300 overflow-x-auto">
                {probeResult.serverOutput}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
