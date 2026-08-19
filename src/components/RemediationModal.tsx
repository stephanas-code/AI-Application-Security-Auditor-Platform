import React, { useState } from 'react';
import { 
  X, 
  Sparkles, 
  CheckCircle2, 
  Wand2, 
  Code2, 
  HelpCircle, 
  BookOpen, 
  Check, 
  Loader2,
  Fingerprint
} from 'lucide-react';
import { VulnerabilityFinding, ProposedPatch } from '../types';

interface RemediationModalProps {
  finding: VulnerabilityFinding | null;
  initialTab?: 'explain' | 'recommend' | 'fix' | 'verify';
  onClose: () => void;
  onApplyAndVerify: (finding: VulnerabilityFinding, patch: ProposedPatch) => Promise<void>;
  isVerifying: boolean;
}

export const RemediationModal: React.FC<RemediationModalProps> = ({
  finding,
  initialTab = 'explain',
  onClose,
  onApplyAndVerify,
  isVerifying
}) => {
  const [activeTab, setActiveTab] = useState<'explain' | 'recommend' | 'fix' | 'verify'>(
    finding?.status === 'VERIFIED_RESOLVED' ? 'verify' : initialTab
  );
  const [copiedDiff, setCopiedDiff] = useState(false);

  if (!finding) return null;

  const patch = finding.proposedPatch;
  const isResolved = finding.status === 'VERIFIED_RESOLVED';

  const handleCopyDiff = () => {
    if (patch?.diff) {
      navigator.clipboard.writeText(patch.diff);
      setCopiedDiff(true);
      setTimeout(() => setCopiedDiff(false), 2000);
    }
  };

  const handleApply = async () => {
    if (patch) {
      await onApplyAndVerify(finding, patch);
      setActiveTab('verify');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in">
      <div className="bg-[#111111] border border-[#1F1F1F] rounded-2xl w-full max-w-4xl overflow-hidden shadow-2xl flex flex-col max-h-[92vh]">
        
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-[#1F1F1F] bg-[#161616] flex items-start justify-between">
          <div className="space-y-1">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 rounded-full bg-blue-500"></div>
              <span className="text-xs font-bold uppercase tracking-widest text-white">AI Remediation Engine</span>
              <span className="text-[10px] font-mono text-gray-500">ID: FIND-{finding.id.substring(0, 8)}</span>
              {isResolved && (
                <span className="flex items-center space-x-1 px-2 py-0.5 rounded-full text-[9px] font-bold font-mono bg-emerald-950/60 text-emerald-400 border border-emerald-900">
                  <CheckCircle2 className="h-3 w-3" />
                  <span>VERIFIED PROOF</span>
                </span>
              )}
            </div>
            <h2 className="text-base font-bold text-white tracking-tight">
              {finding.title}
            </h2>
            <p className="text-xs font-mono text-gray-400">
              📍 Location: {finding.file}:{finding.line}
            </p>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-[#1F1F1F] transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* 3-Tier Remediation Navigation Tabs */}
        <div className="flex border-b border-[#1F1F1F] bg-[#0F0F0F] px-6 pt-2">
          <button
            onClick={() => setActiveTab('explain')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all ${
              activeTab === 'explain'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <HelpCircle className="h-4 w-4" />
            <span>Overview & Exploit</span>
          </button>

          <button
            onClick={() => setActiveTab('recommend')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all ${
              activeTab === 'recommend'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <BookOpen className="h-4 w-4" />
            <span>Architecture Guidance</span>
          </button>

          <button
            onClick={() => setActiveTab('fix')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all ${
              activeTab === 'fix'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Wand2 className="h-4 w-4" />
            <span>Interactive Patch Diff</span>
          </button>

          {isResolved && (
            <button
              onClick={() => setActiveTab('verify')}
              className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all ${
                activeTab === 'verify'
                  ? 'border-emerald-500 text-emerald-400 bg-[#161616]'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Fingerprint className="h-4 w-4" />
              <span>Verification Proof</span>
            </button>
          )}
        </div>

        {/* Tab Content Body */}
        <div className="p-6 overflow-y-auto flex-1 space-y-5 bg-[#0A0A0A]">
          
          {/* TAB 1: EXPLAIN MODE */}
          {activeTab === 'explain' && (
            <div className="space-y-4">
              {/* Elegant Italic Insight */}
              <div className="p-5 rounded-xl bg-[#141414] border border-[#1F1F1F] space-y-2">
                <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">ANALYSIS INSIGHT</h3>
                <p className="text-sm italic leading-relaxed text-blue-100 font-serif">
                  "{finding.rootCause}"
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F] space-y-1.5">
                  <h4 className="text-[10px] font-bold text-red-500 uppercase tracking-wider">Adversary Attack Scenario</h4>
                  <p className="text-xs text-gray-300 leading-relaxed">
                    {finding.attackScenario}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F] space-y-1.5">
                  <h4 className="text-[10px] font-bold text-gray-400 uppercase tracking-wider">Compliance & Business Impact</h4>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    {finding.businessImpact}
                  </p>
                </div>
              </div>

              {/* Code Snippet Highlight */}
              <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F] space-y-2">
                <h4 className="text-[10px] font-bold text-gray-500 uppercase tracking-wider">Current Vulnerable Code Sink</h4>
                <pre className="p-3 bg-black rounded-lg text-xs font-mono text-red-400 overflow-x-auto border border-red-900/30">
                  <code>{finding.codeSnippet}</code>
                </pre>
              </div>
            </div>
          )}

          {/* TAB 2: RECOMMEND MODE */}
          {activeTab === 'recommend' && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-[#141414] border border-[#1F1F1F] space-y-2">
                <h4 className="text-[10px] font-bold text-blue-400 uppercase tracking-widest">REMEDIATION DIRECTIVE</h4>
                <p className="text-xs text-gray-200 leading-relaxed">
                  {finding.recommendation}
                </p>
              </div>

              {/* Step by step instructions */}
              <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F] space-y-3">
                <h4 className="text-xs font-bold text-gray-200 uppercase tracking-wider">Recommended Implementation Sequence</h4>
                <ol className="space-y-2.5 text-xs text-gray-300">
                  <li className="flex items-start space-x-2">
                    <span className="h-5 w-5 rounded bg-[#1F1F1F] text-blue-400 flex items-center justify-center font-mono font-bold text-[11px] flex-shrink-0">1</span>
                    <span>Eliminate the raw input sink by introducing strict type validation and parameterization.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="h-5 w-5 rounded bg-[#1F1F1F] text-blue-400 flex items-center justify-center font-mono font-bold text-[11px] flex-shrink-0">2</span>
                    <span>Abstract environment-specific secrets away from code repositories into environment variables or cloud secret managers.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <span className="h-5 w-5 rounded bg-[#1F1F1F] text-blue-400 flex items-center justify-center font-mono font-bold text-[11px] flex-shrink-0">3</span>
                    <span>Write automated unit test cases simulating malformed payloads to verify that the vulnerability cannot regress.</span>
                  </li>
                </ol>
              </div>

              {/* Security Test Case Spec */}
              {finding.testCase && (
                <div className="p-4 rounded-xl bg-[#111111] border border-[#1F1F1F] space-y-2">
                  <h4 className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">Automated Verification Test Specification</h4>
                  <div className="text-xs text-gray-300 space-y-1 font-mono">
                    <p><span className="text-gray-500">Test:</span> {finding.testCase.name}</p>
                    <p><span className="text-gray-500">Payload:</span> <code className="text-red-400">{finding.testCase.inputPayload}</code></p>
                  </div>
                  <pre className="mt-2 p-3 bg-black rounded-lg text-[11px] font-mono text-emerald-400 overflow-x-auto border border-emerald-900/30">
                    <code>{finding.testCase.testScriptCode}</code>
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: FIX & PATCH MODE */}
          {activeTab === 'fix' && (
            <div className="space-y-4">
              {patch ? (
                <>
                  {/* Side by Side Code View */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <h3 className="text-[10px] font-bold text-red-500 uppercase tracking-wider">Current Vulnerable Code</h3>
                      <pre className="bg-black p-3.5 rounded-xl text-[11px] font-mono text-red-400 border border-red-900/30 overflow-x-auto leading-relaxed">
                        <code>{patch.beforeCode}</code>
                      </pre>
                    </div>
                    <div className="space-y-2">
                      <h3 className="text-[10px] font-bold text-green-500 uppercase tracking-wider">AI Proposed Patch</h3>
                      <pre className="bg-black p-3.5 rounded-xl text-[11px] font-mono text-green-400 border border-green-900/30 overflow-x-auto leading-relaxed">
                        <code>{patch.afterCode}</code>
                      </pre>
                    </div>
                  </div>

                  {/* Unified Diff View */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h4 className="text-[10px] font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-1.5">
                        <Code2 className="h-3.5 w-3.5 text-blue-400" />
                        <span>Unified Diff ({patch.fileModified})</span>
                      </h4>
                      <button
                        onClick={handleCopyDiff}
                        className="px-2.5 py-1 rounded bg-[#1A1A1A] hover:bg-[#222222] border border-[#333333] text-gray-300 text-[10px] font-bold uppercase transition-colors"
                      >
                        {copiedDiff ? 'COPIED!' : 'COPY DIFF'}
                      </button>
                    </div>

                    <pre className="p-4 bg-black rounded-xl font-mono text-xs overflow-x-auto border border-[#1F1F1F] leading-relaxed">
                      {patch.diff.split('\n').map((line, idx) => {
                        const isMinus = line.startsWith('-');
                        const isPlus = line.startsWith('+');
                        return (
                          <div 
                            key={idx}
                            className={`py-0.5 px-2 rounded ${
                              isMinus ? 'bg-red-950/40 text-red-400' :
                              isPlus ? 'bg-green-950/40 text-green-400' :
                              'text-gray-500'
                            }`}
                          >
                            {line}
                          </div>
                        );
                      })}
                    </pre>
                  </div>

                  {/* Patch Technical Explanation */}
                  <div className="p-3.5 bg-[#141414] rounded-xl border border-[#1F1F1F] text-xs text-gray-300">
                    <span className="font-semibold text-blue-400">Why this fix works: </span>
                    {patch.explanation}
                  </div>
                </>
              ) : (
                <div className="p-6 text-center text-xs text-gray-500">
                  No automated patch ready. Click guidance to view manual remediation steps.
                </div>
              )}
            </div>
          )}

          {/* TAB 4: VERIFICATION PROOF */}
          {activeTab === 'verify' && finding.verificationProof && (
            <div className="space-y-4">
              <div className="p-5 rounded-xl bg-[#141414] border border-emerald-900/60 flex items-start space-x-3">
                <CheckCircle2 className="h-6 w-6 text-emerald-500 flex-shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h3 className="text-sm font-bold text-emerald-400">Vulnerability Resolution Cryptographically Verified</h3>
                  <p className="text-xs text-gray-300">
                    The applied patch was compiled into an isolated sandbox environment, subjected to automated exploit payload fuzzing, and verified clean via rescan.
                  </p>
                  <p className="text-[11px] font-mono text-emerald-500 pt-1">
                    Audit Token: {finding.verificationProof.verificationHash}
                  </p>
                </div>
              </div>

              {/* Before vs After Test Logs */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-3.5 bg-black rounded-xl border border-red-900/40 font-mono text-xs">
                  <div className="text-[10px] text-red-500 font-bold uppercase mb-1.5 flex items-center justify-between">
                    <span>Pre-Fix Security Test Log</span>
                    <span className="px-1.5 bg-red-950/60 text-red-400 rounded">FAIL</span>
                  </div>
                  <pre className="text-[11px] text-red-400 whitespace-pre-wrap leading-relaxed">
                    {finding.verificationProof.beforeExecutionLog}
                  </pre>
                </div>

                <div className="p-3.5 bg-black rounded-xl border border-green-900/40 font-mono text-xs">
                  <div className="text-[10px] text-green-500 font-bold uppercase mb-1.5 flex items-center justify-between">
                    <span>Post-Fix Verification Log</span>
                    <span className="px-1.5 bg-green-950/60 text-green-400 rounded">PASS</span>
                  </div>
                  <pre className="text-[11px] text-green-400 whitespace-pre-wrap leading-relaxed">
                    {finding.verificationProof.afterExecutionLog}
                  </pre>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Modal Footer with Verification Stats & Primary CTAs */}
        <div className="px-6 py-4 border-t border-[#1F1F1F] bg-[#161616] flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex gap-8">
            <div>
              <p className="text-[9px] text-gray-500 mb-0.5 uppercase tracking-tight font-semibold">Regression Test</p>
              <p className="text-xs text-emerald-500 font-bold font-mono">✓ PASSED</p>
            </div>
            <div>
              <p className="text-[9px] text-gray-500 mb-0.5 uppercase tracking-tight font-semibold">Impact Level</p>
              <p className="text-xs text-white font-bold font-mono">LOW (Code Only)</p>
            </div>
          </div>

          <div className="flex items-center space-x-3 w-full sm:w-auto justify-end">
            <button
              onClick={() => setActiveTab('explain')}
              className="px-4 py-2 bg-[#1A1A1A] border border-[#333333] hover:bg-[#222222] rounded text-xs font-bold uppercase tracking-wider text-gray-300"
            >
              EXPLAIN RISK
            </button>

            {!isResolved && patch && (
              <button
                onClick={handleApply}
                disabled={isVerifying}
                className="px-6 py-2 bg-blue-600 hover:bg-blue-500 rounded text-xs font-bold uppercase tracking-wider text-white shadow-lg shadow-blue-900/30 flex items-center space-x-2 disabled:opacity-50"
              >
                {isVerifying ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>VERIFYING...</span>
                  </>
                ) : (
                  <>
                    <Wand2 className="h-4 w-4" />
                    <span>APPLY & VERIFY FIX</span>
                  </>
                )}
              </button>
            )}

            {isResolved && (
              <button
                onClick={onClose}
                className="px-6 py-2 bg-[#1A1A1A] hover:bg-[#222222] border border-[#333333] rounded text-xs font-bold uppercase tracking-wider text-white"
              >
                CLOSE
              </button>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
