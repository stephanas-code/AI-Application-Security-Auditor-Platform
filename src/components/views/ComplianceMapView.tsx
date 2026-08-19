import React, { useState } from 'react';
import { 
  ComplianceFramework, 
  ScanResult, 
  VulnerabilityFinding, 
  NavigationTab 
} from '../../types';
import { SecurityEngine } from '../../services/securityEngine';
import { 
  FileCheck2, 
  ShieldCheck, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowRight, 
  Zap, 
  Lock, 
  FileText, 
  Sparkles 
} from 'lucide-react';

interface ComplianceMapViewProps {
  scanResult: ScanResult;
  onNavigate: (tab: NavigationTab) => void;
  onSelectFinding: (finding: VulnerabilityFinding) => void;
}

export const ComplianceMapView: React.FC<ComplianceMapViewProps> = ({
  scanResult,
  onNavigate,
  onSelectFinding
}) => {
  const [selectedFramework, setSelectedFramework] = useState<ComplianceFramework>('OWASP_TOP_10');

  const frameworks: Array<{ id: ComplianceFramework; name: string; tag: string; description: string }> = [
    { id: 'OWASP_TOP_10', name: 'OWASP Top 10 (2021)', tag: 'Web & API Standard', description: 'Ten most critical web and API security risks defined by the Open Web Application Security Project.' },
    { id: 'NIST_800_53', name: 'NIST SP 800-53 Rev 5', tag: 'Federal Security Controls', description: 'National Institute of Standards and Technology catalog of security and privacy controls.' },
    { id: 'SOC2_TYPE_II', name: 'SOC 2 Type II', tag: 'Trust Services Criteria', description: 'AICPA criteria for Security, Availability, Processing Integrity, and Confidentiality.' },
    { id: 'ISO_27001', name: 'ISO/IEC 27001:2022', tag: 'Global ISMS Standard', description: 'International standard for information security management systems and technical safeguards.' },
    { id: 'PCI_DSS_V4', name: 'PCI-DSS v4.0', tag: 'Payment Card Industry', description: 'Mandatory technical controls for protecting cardholder payment data and transaction environments.' },
    { id: 'HIPAA', name: 'HIPAA Security Rule', tag: 'Healthcare ePHI', description: 'Health Insurance Portability and Accountability Act safeguards for electronic protected health information.' }
  ];

  const requirements = SecurityEngine.getComplianceRequirements(selectedFramework, scanResult.findings);

  const compliantCount = requirements.filter(r => r.status === 'COMPLIANT' || r.status === 'REMEDIATED').length;
  const nonCompliantCount = requirements.filter(r => r.status === 'NON_COMPLIANT').length;
  const compliancePercentage = Math.round((compliantCount / requirements.length) * 100);

  const activeFrameworkMeta = frameworks.find(f => f.id === selectedFramework)!;

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Framework Selector */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <FileCheck2 className="h-5 w-5 text-blue-400" />
              <h1 className="text-base font-black text-white uppercase tracking-wider">
                Regulatory & Framework Compliance Map
              </h1>
            </div>
            <p className="text-xs text-gray-400 mt-1 max-w-2xl leading-relaxed">
              Continuous compliance mapping of software findings against industry security standards and audit requirements.
            </p>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={() => onNavigate('remediation')}
              className="flex items-center space-x-2 px-4 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow"
            >
              <Zap className="h-4 w-4" />
              <span>Remediate Violations</span>
            </button>
          </div>
        </div>

        {/* Framework Selector Pills */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 pt-2">
          {frameworks.map((fw) => {
            const isSelected = selectedFramework === fw.id;
            return (
              <button
                key={fw.id}
                onClick={() => setSelectedFramework(fw.id)}
                className={`p-3 rounded-xl text-left border transition-all ${
                  isSelected
                    ? 'bg-blue-600/15 border-blue-500 text-white shadow-md'
                    : 'bg-[#161616] border-[#1F1F1F] text-gray-400 hover:text-white hover:bg-[#1A1A1A]'
                }`}
              >
                <span className={`text-[10px] font-mono block uppercase font-bold ${isSelected ? 'text-blue-400' : 'text-gray-500'}`}>
                  {fw.tag}
                </span>
                <span className="text-xs font-bold block mt-0.5 truncate">{fw.name}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Compliance Score Gauge & Overview */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Compliance Gauge Card */}
        <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex items-center justify-between">
          <div className="space-y-1">
            <span className="text-xs font-mono font-bold text-gray-500 uppercase tracking-wider">
              {activeFrameworkMeta.name}
            </span>
            <div className="flex items-baseline space-x-2">
              <span className={`text-4xl font-black ${
                compliancePercentage >= 90 ? 'text-emerald-400' :
                compliancePercentage >= 70 ? 'text-blue-400' :
                'text-red-400'
              }`}>
                {compliancePercentage}%
              </span>
              <span className="text-xs font-mono text-gray-400">Readiness</span>
            </div>
            <p className="text-xs text-gray-400 mt-2">
              {nonCompliantCount === 0 
                ? 'All mandatory requirements currently pass audit assertions.' 
                : `${nonCompliantCount} requirement${nonCompliantCount > 1 ? 's' : ''} failing audit assertions.`}
            </p>
          </div>

          <div className="p-3 rounded-2xl bg-[#161616] border border-[#222222]">
            {compliancePercentage >= 90 ? (
              <ShieldCheck className="h-10 w-10 text-emerald-400" />
            ) : (
              <AlertTriangle className="h-10 w-10 text-red-400" />
            )}
          </div>
        </div>

        {/* Framework Description & Controls */}
        <div className="md:col-span-2 p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                {activeFrameworkMeta.name} Overview
              </h3>
              <span className="text-[10px] font-mono text-gray-500">
                {requirements.length} Evaluated Clauses
              </span>
            </div>
            <p className="text-xs text-gray-300 mt-2 leading-relaxed">
              {activeFrameworkMeta.description}
            </p>
          </div>

          <div className="grid grid-cols-3 gap-3 mt-4 pt-3 border-t border-[#1F1F1F] text-xs font-mono">
            <div className="p-2 rounded-lg bg-[#161616]">
              <span className="text-gray-500 text-[10px] block uppercase">Compliant</span>
              <span className="text-emerald-400 font-bold">{compliantCount} Clauses</span>
            </div>
            <div className="p-2 rounded-lg bg-[#161616]">
              <span className="text-gray-500 text-[10px] block uppercase">Violations</span>
              <span className="text-red-400 font-bold">{nonCompliantCount} Clauses</span>
            </div>
            <div className="p-2 rounded-lg bg-[#161616]">
              <span className="text-gray-500 text-[10px] block uppercase">Audit State</span>
              <span className={`font-bold ${nonCompliantCount === 0 ? 'text-emerald-400' : 'text-amber-400'}`}>
                {nonCompliantCount === 0 ? 'PASSED' : 'ACTION REQ.'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Compliance Clauses Breakdown */}
      <div className="space-y-3">
        <div className="flex items-center justify-between px-1">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider font-mono">
            Standard Clause & Control Breakdown
          </h3>
          <span className="text-xs font-mono text-gray-500">
            {requirements.length} Controls Evaluated
          </span>
        </div>

        <div className="space-y-3">
          {requirements.map((req) => {
            const isNonCompliant = req.status === 'NON_COMPLIANT';
            const isRemediated = req.status === 'REMEDIATED';

            const activeFindingObjects = scanResult.findings.filter(f => req.findingsAffected.includes(f.id));

            return (
              <div
                key={req.id}
                className={`p-5 rounded-2xl border transition-all ${
                  isNonCompliant
                    ? 'bg-[#151111] border-red-900/50'
                    : isRemediated
                    ? 'bg-[#0F1713] border-emerald-900/50'
                    : 'bg-[#111111] border-[#1F1F1F]'
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#1A1A1A]">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isNonCompliant ? 'bg-red-950 text-red-400 border border-red-800' :
                        isRemediated ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                        'bg-[#1C1C1C] text-emerald-400 border border-emerald-900/40'
                      }`}>
                        {isNonCompliant ? 'NON-COMPLIANT' : isRemediated ? 'REMEDIATED' : 'COMPLIANT'}
                      </span>
                      <span className="text-xs font-mono font-bold text-blue-400">{req.code}</span>
                      <span className="text-xs font-bold text-white">{req.name}</span>
                    </div>
                    <p className="text-xs text-gray-400 mt-1 leading-relaxed">{req.description}</p>
                  </div>

                  <div className="shrink-0 text-right">
                    <span className="px-2 py-0.5 rounded bg-[#1C1C1C] text-gray-400 text-[10px] font-mono border border-[#2A2A2A]">
                      {req.category}
                    </span>
                  </div>
                </div>

                {/* Linked Findings */}
                {activeFindingObjects.length > 0 && (
                  <div className="mt-3 pt-2 space-y-2">
                    <span className="text-[11px] font-mono text-gray-500 uppercase block font-bold">
                      Linked Vulnerabilities ({activeFindingObjects.length})
                    </span>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {activeFindingObjects.map((f) => (
                        <div
                          key={f.id}
                          onClick={() => onSelectFinding(f)}
                          className="p-2.5 rounded-xl bg-[#161616] border border-[#242424] hover:border-[#3A3A3A] cursor-pointer flex items-center justify-between gap-2 transition-all"
                        >
                          <div className="min-w-0">
                            <span className="text-xs font-bold text-white truncate block">{f.title}</span>
                            <span className="text-[10px] font-mono text-gray-500 truncate block">{f.file}:{f.line}</span>
                          </div>
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold shrink-0 ${
                            f.status === 'VERIFIED_RESOLVED' ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'
                          }`}>
                            {f.status === 'VERIFIED_RESOLVED' ? 'RESOLVED' : f.severity}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
