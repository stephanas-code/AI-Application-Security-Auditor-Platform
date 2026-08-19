import React from 'react';
import { 
  X, 
  Download, 
  Printer, 
  FileText, 
  Lock
} from 'lucide-react';
import { ScanResult } from '../types';

interface AuditReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  scanResult: ScanResult | null;
}

export const AuditReportModal: React.FC<AuditReportModalProps> = ({
  isOpen,
  onClose,
  scanResult
}) => {
  if (!isOpen || !scanResult) return null;

  const target = scanResult.target;
  const findings = scanResult.findings;
  const resolved = findings.filter(f => f.status === 'VERIFIED_RESOLVED');
  const unresolved = findings.filter(f => f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE');

  const handleExportSARIF = () => {
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "SHIELD.AI Security Auditor",
              version: "2.4.0",
              rules: findings.map(f => ({
                id: f.cwe,
                name: f.cweName,
                shortDescription: { text: f.title },
                fullDescription: { text: f.description },
                defaultConfiguration: {
                  level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning'
                }
              }))
            }
          },
          results: findings.map(f => ({
            ruleId: f.cwe,
            message: { text: f.title },
            level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: { startLine: f.line }
                }
              }
            ],
            properties: {
              status: f.status,
              verificationHash: f.verificationProof?.verificationHash
            }
          }))
        }
      ]
    };

    const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shield-audit-sarif-${Date.now()}.json`;
    a.click();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in">
      <div className="bg-[#111111] border border-[#1F1F1F] rounded-2xl w-full max-w-4xl overflow-hidden shadow-2xl flex flex-col max-h-[92vh]">
        
        {/* Header */}
        <div className="px-6 py-4 border-b border-[#1F1F1F] bg-[#161616] flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="h-8 w-8 rounded-lg bg-[#FF3B30] flex items-center justify-center font-bold text-black text-sm">
              S
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Security Audit & Verification Report</h2>
              <p className="text-xs text-gray-500">Official posture record & cryptographic remediation proofs.</p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleExportSARIF}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#1A1A1A] hover:bg-[#222222] text-blue-400 text-xs font-semibold border border-[#333333] transition-colors"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Export SARIF 2.1.0</span>
            </button>
            <button
              onClick={handlePrint}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#1A1A1A] hover:bg-[#222222] text-gray-300 text-xs font-semibold border border-[#333333] transition-colors"
            >
              <Printer className="h-3.5 w-3.5" />
              <span>Print</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-[#1F1F1F] transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Report Content */}
        <div className="p-8 overflow-y-auto flex-1 space-y-6 bg-[#0A0A0A] font-sans">
          
          {/* Certificate Card */}
          <div className="p-6 rounded-2xl bg-[#141414] border border-[#1F1F1F] shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#1F1F1F] pb-4">
              <div className="space-y-1">
                <span className="text-[10px] font-mono uppercase tracking-widest text-gray-500 font-bold">
                  Official Verification Record
                </span>
                <h3 className="text-xl font-bold text-white tracking-tight">{target.name}</h3>
                <p className="text-xs text-gray-400 font-mono">
                  Stack: {target.language} • {target.files.length} Files • {target.totalLines} LOC
                </p>
              </div>

              <div className="text-right">
                <div className="text-3xl font-light text-emerald-500 font-mono">
                  {scanResult.scoreCurrent} <span className="text-xs font-normal text-gray-600">/ 100</span>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-900">
                  Initial: {scanResult.scoreBefore}/100
                </span>
              </div>
            </div>

            {/* Metrics Row */}
            <div className="grid grid-cols-4 gap-4 text-center">
              <div className="p-3 bg-black rounded-xl border border-[#1F1F1F]">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">Total Findings</span>
                <div className="text-xl font-bold text-white mt-1">{findings.length}</div>
              </div>
              <div className="p-3 bg-black rounded-xl border border-[#1F1F1F]">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">Verified Clean</span>
                <div className="text-xl font-bold text-emerald-400 mt-1">{resolved.length}</div>
              </div>
              <div className="p-3 bg-black rounded-xl border border-[#1F1F1F]">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">Active Sinks</span>
                <div className="text-xl font-bold text-[#FF3B30] mt-1">{unresolved.length}</div>
              </div>
              <div className="p-3 bg-black rounded-xl border border-[#1F1F1F]">
                <span className="text-[10px] text-gray-500 uppercase tracking-wider">Success Rate</span>
                <div className="text-xl font-bold text-blue-400 mt-1">
                  {findings.length > 0 ? Math.round((resolved.length / findings.length) * 100) : 100}%
                </div>
              </div>
            </div>
          </div>

          {/* Detailed Findings Table */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-gray-400">Remediation & Verification Inventory</h4>
            
            <div className="divide-y divide-[#1F1F1F] border border-[#1F1F1F] rounded-xl overflow-hidden bg-[#111111]">
              {findings.map((f) => (
                <div key={f.id} className="p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 rounded text-[9px] font-bold font-mono ${
                        f.severity === 'CRITICAL' ? 'bg-red-950/60 text-[#FF3B30] border border-red-900' :
                        f.severity === 'HIGH' ? 'bg-orange-950/60 text-orange-400 border border-orange-900' :
                        'bg-amber-950/60 text-amber-400 border border-amber-900'
                      }`}>
                        {f.severity}
                      </span>
                      <span className="text-xs font-bold text-white">{f.title}</span>
                      <span className="text-[11px] font-mono text-gray-500">({f.cwe})</span>
                    </div>

                    <span className={`px-2.5 py-0.5 rounded-full text-[9px] font-bold font-mono ${
                      f.status === 'VERIFIED_RESOLVED' 
                        ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-900' 
                        : 'bg-red-950/60 text-[#FF3B30] border border-red-900'
                    }`}>
                      {f.status === 'VERIFIED_RESOLVED' ? 'VERIFIED RESOLVED' : 'UNRESOLVED'}
                    </span>
                  </div>

                  <p className="text-xs text-gray-300">
                    <span className="text-gray-500 font-mono">Location: {f.file}:{f.line}</span> — {f.description}
                  </p>

                  {f.verificationProof && (
                    <div className="p-2.5 bg-black rounded-lg text-[10px] font-mono text-emerald-400 border border-emerald-950 flex items-center justify-between">
                      <span>✓ Sandbox Test Passed</span>
                      <span>Hash: {f.verificationProof.verificationHash}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Verification Sign-off */}
          <div className="pt-4 border-t border-[#1F1F1F] flex items-center justify-between text-xs text-gray-600 font-mono">
            <div className="flex items-center space-x-1.5">
              <Lock className="h-3.5 w-3.5 text-blue-400" />
              <span>Audited by SHIELD.AI Platform & Gemini Engine</span>
            </div>
            <span>Timestamp: {new Date().toUTCString()}</span>
          </div>

        </div>

      </div>
    </div>
  );
};
