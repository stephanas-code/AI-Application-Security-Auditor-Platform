import React, { useState } from 'react';
import { 
  Radar, 
  CheckCircle2, 
  AlertTriangle, 
  Play, 
  RefreshCw
} from 'lucide-react';
import { VulnerabilityFinding } from '../types';

interface DASTProbeSimulatorProps {
  findings: VulnerabilityFinding[];
}

export const DASTProbeSimulator: React.FC<DASTProbeSimulatorProps> = ({ findings }) => {
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

  const handleSelectEndpoint = (id: string) => {
    setSelectedEndpoint(id);
    const ep = endpoints.find(e => e.id === id);
    if (ep) {
      setCustomPayload(ep.defaultPayload);
      setProbeResult(null);
    }
  };

  const handleRunProbe = () => {
    setIsProbing(true);
    setProbeResult(null);

    const ep = endpoints.find(e => e.id === selectedEndpoint);
    const isPatched = ep?.isPatched;

    setTimeout(() => {
      if (selectedEndpoint === 'sqli') {
        if (!isPatched) {
          setProbeResult({
            status: 200,
            responseTimeMs: 38,
            vulnerable: true,
            serverOutput: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "success": true,\n  "count": 4820,\n  "data": [\n    { "id": 1, "account_id": 1002, "amount": 9500.00, "memo": "VIP Payout" },\n    { "id": 2, "account_id": 9999, "amount": 142000.00, "memo": "Corp Reserve" },\n    { "id": 3, "account_id": 4012, "amount": 850.50, "memo": "Wire" }\n  ]\n}`,
            analysis: 'EXPLOIT SUCCESSFUL: The database executed the injected `OR 1=1` tautology, dumping cross-account customer transaction data without access control.'
          });
        } else {
          setProbeResult({
            status: 200,
            responseTimeMs: 22,
            vulnerable: false,
            serverOutput: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "success": true,\n  "count": 0,\n  "data": []\n}`,
            analysis: 'DEFENSE VERIFIED: Parameterized query placeholder handled payload safely as a literal string. Zero unintended rows exposed.'
          });
        }
      } else if (selectedEndpoint === 'cmdi') {
        if (!isPatched) {
          setProbeResult({
            status: 200,
            responseTimeMs: 64,
            vulnerable: true,
            serverOutput: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "status": "PROBE_EXECUTED",\n  "output": "PING 127.0.0.1 (127.0.0.1): 56 data bytes\\nroot\\nroot:x:0:0:root:/root:/bin/ash\\nmedi_app:x:1000:1000:app:/app:/bin/sh"\n}`,
            analysis: 'EXPLOIT SUCCESSFUL: Remote Command Execution (RCE) achieved. Injected shell commands executed as root.'
          });
        } else {
          setProbeResult({
            status: 400,
            responseTimeMs: 15,
            vulnerable: false,
            serverOutput: `HTTP/1.1 400 Bad Request\nContent-Type: application/json\n\n{\n  "error": "Invalid IP address or probe failure"\n}`,
            analysis: 'DEFENSE VERIFIED: Strict IP format validator rejected shell delimiters. Subprocess safely invoked with explicit argument vector without shell interpreter.'
          });
        }
      } else {
        if (!isPatched) {
          setProbeResult({
            status: 200,
            responseTimeMs: 41,
            vulnerable: true,
            serverOutput: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n[\n  { "id": 1, "username": "admin", "email": "admin@bank.com", "password_hash": "$2b$12$e8Y..." },\n  { "id": 2, "username": "cfo_user", "email": "cfo@bank.com", "password_hash": "$2b$12$a1K..." }\n]`,
            analysis: 'EXPLOIT SUCCESSFUL: Unauthenticated anonymous request dumped administrative user accounts and bcrypt password hashes.'
          });
        } else {
          setProbeResult({
            status: 401,
            responseTimeMs: 12,
            vulnerable: false,
            serverOutput: `HTTP/1.1 401 Unauthorized\nContent-Type: application/json\n\n{\n  "error": "Authentication token required"\n}`,
            analysis: 'DEFENSE VERIFIED: requireAuth middleware blocked unauthenticated request with 401 Unauthorized.'
          });
        }
      }

      setIsProbing(false);
    }, 600);
  };

  const activeEp = endpoints.find(e => e.id === selectedEndpoint);

  return (
    <div className="bg-[#111111] border border-[#1F1F1F] rounded-2xl p-6 shadow-2xl space-y-6">
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#1F1F1F] pb-4">
        <div className="flex items-center space-x-3">
          <div className="w-2.5 h-2.5 rounded-full bg-orange-500 animate-pulse"></div>
          <div>
            <h2 className="text-xs font-bold uppercase tracking-widest text-white">Dynamic Analysis (DAST) Probe Simulator</h2>
            <p className="text-[11px] text-gray-500">Test live simulated HTTP injection payloads against endpoints to prove exploitability before & after patch.</p>
          </div>
        </div>

        <span className="px-2.5 py-1 text-[10px] font-mono rounded bg-[#1A1A1A] text-gray-400 border border-[#333333]">
          SANDBOX PROBER
        </span>
      </div>

      {/* Target Selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {endpoints.map((ep) => (
          <div
            key={ep.id}
            onClick={() => handleSelectEndpoint(ep.id)}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              selectedEndpoint === ep.id 
                ? 'bg-[#181818] border-blue-500 shadow-md' 
                : 'bg-[#141414] border-[#1F1F1F] hover:border-[#333333]'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="px-1.5 py-0.5 text-[9px] font-mono bg-black text-gray-300 border border-[#1F1F1F] rounded font-bold">
                {ep.method}
              </span>
              <span className={`px-2 py-0.5 text-[9px] font-bold font-mono rounded-full ${
                ep.isPatched ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-900' : 'bg-red-950/60 text-[#FF3B30] border border-red-900'
              }`}>
                {ep.isPatched ? 'PATCH VERIFIED' : 'VULNERABLE'}
              </span>
            </div>
            <h4 className="text-xs font-bold text-white font-mono truncate">{ep.name}</h4>
            <p className="text-[11px] text-gray-400 mt-1">{ep.type}</p>
          </div>
        ))}
      </div>

      {/* Interactive Payload Runner */}
      <div className="p-4 bg-black rounded-xl border border-[#1F1F1F] space-y-3">
        <div className="flex items-center justify-between">
          <div className="text-[10px] font-bold uppercase tracking-widest text-gray-400">
            Simulated Probe Request Payload
          </div>
          <div className="text-xs font-mono">
            Status: <span className={activeEp?.isPatched ? 'text-emerald-500 font-bold' : 'text-[#FF3B30] font-bold'}>
              {activeEp?.isPatched ? 'SECURE (REMEDIATED)' : 'EXPLOITABLE (UNPATCHED)'}
            </span>
          </div>
        </div>

        <div className="flex space-x-2">
          <input
            type="text"
            value={customPayload}
            onChange={(e) => setCustomPayload(e.target.value)}
            className="flex-1 px-3 py-2 bg-[#111111] border border-[#1F1F1F] rounded-lg text-xs font-mono text-blue-400 focus:outline-none focus:border-[#333333]"
            placeholder="Enter injection payload..."
          />
          <button
            onClick={handleRunProbe}
            disabled={isProbing}
            className="flex items-center space-x-2 px-5 py-2 bg-[#FF3B30] hover:bg-[#D32F2F] text-black rounded-lg text-xs font-black uppercase tracking-wider transition-all disabled:opacity-50"
          >
            {isProbing ? <RefreshCw className="h-4 w-4 animate-spin text-black" /> : <Play className="h-4 w-4 fill-black text-black" />}
            <span>Fire Probe</span>
          </button>
        </div>
      </div>

      {/* Response & Proof Terminal */}
      {probeResult && (
        <div className="space-y-3 animate-in fade-in">
          <div className={`p-4 rounded-xl border flex items-start space-x-3 ${
            probeResult.vulnerable ? 'bg-red-950/20 border-red-900/60' : 'bg-emerald-950/20 border-emerald-900/60'
          }`}>
            {probeResult.vulnerable ? (
              <AlertTriangle className="h-5 w-5 text-[#FF3B30] flex-shrink-0 mt-0.5" />
            ) : (
              <CheckCircle2 className="h-5 w-5 text-emerald-500 flex-shrink-0 mt-0.5" />
            )}
            <div className="space-y-1">
              <h4 className={`text-xs font-bold uppercase tracking-wide ${probeResult.vulnerable ? 'text-red-400' : 'text-emerald-400'}`}>
                {probeResult.vulnerable ? 'Vulnerability Confirmed Exploitable' : 'Defense Guardrail Verified'}
              </h4>
              <p className="text-xs text-gray-300 leading-relaxed">
                {probeResult.analysis}
              </p>
            </div>
          </div>

          <div className="bg-black rounded-xl border border-[#1F1F1F] overflow-hidden font-mono text-xs">
            <div className="px-4 py-2 bg-[#161616] border-b border-[#1F1F1F] flex items-center justify-between text-[10px] text-gray-500 uppercase font-bold">
              <span>Server Response Inspection</span>
              <span>Latency: {probeResult.responseTimeMs}ms</span>
            </div>
            <pre className="p-4 text-[11px] text-gray-300 overflow-x-auto leading-relaxed">
              <code>{probeResult.serverOutput}</code>
            </pre>
          </div>
        </div>
      )}

    </div>
  );
};
