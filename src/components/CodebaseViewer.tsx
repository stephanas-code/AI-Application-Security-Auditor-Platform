import React, { useState, useEffect } from 'react';
import { 
  VulnerabilityFinding, 
  ScanTarget 
} from '../types';
import { 
  FileCode2, 
  Folder, 
  AlertTriangle, 
  CheckCircle2, 
  Wand2, 
  FileCheck
} from 'lucide-react';

interface CodebaseViewerProps {
  target: ScanTarget;
  findings?: VulnerabilityFinding[];
  activeFinding?: VulnerabilityFinding | null;
  onOpenFinding?: (finding: VulnerabilityFinding) => void;
}

export const CodebaseViewer: React.FC<CodebaseViewerProps> = ({
  target,
  findings = [],
  activeFinding,
  onOpenFinding
}) => {
  const [selectedFilePath, setSelectedFilePath] = useState<string>(
    activeFinding?.file || target.files[0]?.path || ''
  );

  // If activeFinding changes, switch to that file
  useEffect(() => {
    if (activeFinding?.file) {
      const exists = target.files.some(f => f.path === activeFinding.file);
      if (exists) {
        setSelectedFilePath(activeFinding.file);
      }
    }
  }, [activeFinding, target]);

  const activeFile = target.files.find(f => f.path === selectedFilePath) || target.files[0];
  if (!activeFile) return null;

  const safeFindings = findings || [];
  const fileFindings = safeFindings.filter(f => f.file === activeFile.path);
  const lines = activeFile.content.split('\n');

  return (
    <div className="bg-[#111111] border border-[#1F1F1F] rounded-2xl overflow-hidden shadow-2xl flex flex-col md:flex-row h-[750px]">
      
      {/* File Tree Sidebar */}
      <div className="w-full md:w-64 bg-[#0F0F0F] border-b md:border-b-0 md:border-r border-[#1F1F1F] flex flex-col">
        <div className="p-4 border-b border-[#1F1F1F] flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs font-bold uppercase tracking-wider text-gray-400">
            <Folder className="h-4 w-4 text-blue-400" />
            <span>Files ({target.files.length})</span>
          </div>
          <span className="text-[10px] font-mono text-gray-500">
            {target.language}
          </span>
        </div>

        <div className="p-2 overflow-y-auto flex-1 space-y-1">
          {target.files.map((file) => {
            const vCount = safeFindings.filter(f => f.file === file.path && f.status !== 'VERIFIED_RESOLVED').length;
            const rCount = safeFindings.filter(f => f.file === file.path && f.status === 'VERIFIED_RESOLVED').length;
            const isSelected = file.path === activeFile.path;

            return (
              <button
                key={file.path}
                onClick={() => setSelectedFilePath(file.path)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono transition-all text-left ${
                  isSelected 
                    ? 'bg-[#1A1A1A] text-white border border-[#333333] font-bold' 
                    : 'text-gray-400 hover:text-gray-200 hover:bg-[#141414]'
                }`}
              >
                <div className="flex items-center space-x-2 truncate">
                  <FileCode2 className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
                  <span className="truncate">{file.path}</span>
                </div>

                <div className="flex items-center space-x-1 flex-shrink-0">
                  {vCount > 0 && (
                    <span className="px-1.5 py-0.2 rounded text-[10px] bg-red-950/60 text-[#FF3B30] border border-red-900/60 font-bold">
                      {vCount}
                    </span>
                  )}
                  {vCount === 0 && rCount > 0 && (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
                  )}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Code Editor View */}
      <div className="flex-1 flex flex-col bg-[#0A0A0A]">
        
        {/* Editor Toolbar */}
        <div className="px-5 py-3 bg-[#161616] border-b border-[#1F1F1F] flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold text-gray-200">
              {activeFile.path}
            </span>
            <span className="px-2 py-0.5 text-[10px] font-mono bg-[#111111] text-gray-400 border border-[#1F1F1F] rounded">
              {lines.length} lines
            </span>
            {fileFindings.length > 0 && (
              <span className="text-xs text-[#FF3B30] font-mono font-semibold flex items-center gap-1">
                <AlertTriangle className="h-3.5 w-3.5" />
                <span>{fileFindings.length} issue(s) identified</span>
              </span>
            )}
          </div>

          <div className="flex items-center space-x-2 text-xs">
            <span className="text-gray-500 font-mono text-[10px] uppercase">Syntax: {activeFile.language}</span>
          </div>
        </div>

        {/* Code Lines with Vulnerability Annotations */}
        <div className="flex-1 overflow-y-auto font-mono text-xs p-4 space-y-0.5 bg-[#0A0A0A]">
          {lines.map((lineText, idx) => {
            const lineNum = idx + 1;
            const findingOnLine = fileFindings.find(f => f.line === lineNum);
            const isResolved = findingOnLine?.status === 'VERIFIED_RESOLVED';

            return (
              <div key={idx} className="group">
                <div className={`flex items-start py-0.5 px-2 rounded transition-colors ${
                  findingOnLine && !isResolved ? 'bg-red-950/20 border-l-2 border-[#FF3B30]' :
                  findingOnLine && isResolved ? 'bg-emerald-950/20 border-l-2 border-emerald-500' :
                  'hover:bg-[#141414]'
                }`}>
                  {/* Line Number */}
                  <span className={`w-10 text-right pr-4 select-none font-mono text-[11px] ${
                    findingOnLine && !isResolved ? 'text-[#FF3B30] font-bold' :
                    findingOnLine && isResolved ? 'text-emerald-400 font-bold' :
                    'text-gray-700'
                  }`}>
                    {lineNum}
                  </span>

                  {/* Code Line */}
                  <span className={`flex-1 whitespace-pre overflow-x-auto ${
                    findingOnLine && !isResolved ? 'text-red-300' :
                    findingOnLine && isResolved ? 'text-emerald-300' :
                    'text-gray-300'
                  }`}>
                    {lineText || ' '}
                  </span>

                  {/* Inline Fix Action */}
                  {findingOnLine && onOpenFinding && (
                    <button
                      onClick={() => onOpenFinding(findingOnLine)}
                      className={`ml-2 px-2.5 py-0.5 rounded text-[9px] font-sans font-bold uppercase tracking-wider flex items-center space-x-1 transition-all ${
                        isResolved 
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-900'
                          : 'bg-[#FF3B30] hover:bg-[#D32F2F] text-black shadow-sm'
                      }`}
                    >
                      {isResolved ? <FileCheck className="h-3 w-3" /> : <Wand2 className="h-3 w-3 text-black" />}
                      <span>{isResolved ? 'Verified Clean' : 'Remediate'}</span>
                    </button>
                  )}
                </div>

                {/* Inline Finding Alert Card */}
                {findingOnLine && (
                  <div className={`my-1.5 mx-10 p-3 rounded-lg border font-sans text-xs flex items-start justify-between ${
                    isResolved 
                      ? 'bg-[#111111] border-emerald-900/60 text-emerald-300'
                      : 'bg-[#141414] border-l-4 border-l-[#FF3B30] border-[#1F1F1F] text-gray-200'
                  }`}>
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-white">[{findingOnLine.severity}] {findingOnLine.title}</span>
                        <span className="font-mono text-[10px] text-gray-500">({findingOnLine.cwe})</span>
                      </div>
                      <p className="text-[11px] text-gray-400 leading-relaxed">
                        {isResolved ? 'Remediated & verified in sandbox testing.' : findingOnLine.description}
                      </p>
                    </div>

                    {onOpenFinding && (
                      <button
                        onClick={() => onOpenFinding(findingOnLine)}
                        className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider flex-shrink-0 transition-colors ml-3"
                      >
                        Remediate →
                      </button>
                    )}
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
