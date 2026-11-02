import React, { useState, useEffect } from 'react';
import { 
  X, 
  Upload, 
  Github, 
  FileCode, 
  ShieldCheck, 
  AlertTriangle, 
  ArrowRight, 
  Loader2,
  Globe,
  Search,
  Lock,
  Server,
  Zap,
  CheckCircle2,
  Clock,
  Trash2,
  RefreshCw,
  PlusCircle
} from 'lucide-react';
import JSZip from 'jszip';
import { ScanTarget, ScanResult, ProjectFile, TargetPlatform } from '../types';
import { SecurityEngine } from '../services/securityEngine';

export interface SavedScanHistoryItem {
  target: ScanTarget;
  scanResult: ScanResult | null;
  updatedAt: string;
}

interface ProjectIntakeModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectTarget: (target: ScanTarget) => void;
  scanHistory?: SavedScanHistoryItem[];
  activeTargetId?: string;
  onSwitchToSavedTarget?: (entry: SavedScanHistoryItem) => void;
  onDeleteSavedTarget?: (targetId: string) => void;
}

export const ProjectIntakeModal: React.FC<ProjectIntakeModalProps> = ({
  isOpen,
  onClose,
  onSelectTarget,
  scanHistory = [],
  activeTargetId,
  onSwitchToSavedTarget,
  onDeleteSavedTarget
}) => {
  const [activeTab, setActiveTab] = useState<'history' | 'website_recon' | 'local_dir' | 'binary_upload' | 'github' | 'snippet'>(
    scanHistory.length > 0 ? 'history' : 'website_recon'
  );
  const [isProcessing, setIsProcessing] = useState(false);

  useEffect(() => {
    if (isOpen && scanHistory.length > 0) {
      setActiveTab('history');
    }
  }, [isOpen]);
  
  // Local Linux / Host Directory state
  const [localDirPath, setLocalDirPath] = useState('.');

  // Website Recon state
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [reconProgressStep, setReconProgressStep] = useState<string | null>(null);
  
  // Custom code snippet state
  const [customName, setCustomName] = useState('Custom Application Module');
  const [customPlatform, setCustomPlatform] = useState<TargetPlatform>('web');
  const [customLanguage, setCustomLanguage] = useState('JavaScript / Node.js & Express');
  const [customCode, setCustomCode] = useState(`const express = require('express');
const app = express();

app.get('/api/users', async (req, res) => {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + userId;
  const results = await db.query(sql);
  res.json(results);
});

app.listen(3000);`);

  const [githubUrl, setGithubUrl] = useState('https://github.com/OWASP/NodeGoat');
  const [uploadError, setUploadError] = useState<string | null>(null);

  if (!isOpen) return null;

  // Handle Real Website Recon Audit
  const handleWebsiteReconSubmit = async () => {
    if (!websiteUrl.trim()) return;

    setIsProcessing(true);
    setUploadError(null);
    setReconProgressStep('Resolving live DNS records, inspecting SSL/TLS certificate chain & auditing HTTP security headers...');

    try {
      let probeData: any = undefined;
      try {
        const res = await fetch('/api/scan/dast/http-probe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: websiteUrl.trim() })
        });
        const data = await res.json();
        if (res.ok && data.success) {
          probeData = data;
        }
      } catch {
        // Fallback to client-side dynamic target builder if probe endpoint is unreachable
      }

      const target = SecurityEngine.createDynamicWebsiteTarget(websiteUrl.trim(), probeData);
      setIsProcessing(false);
      setReconProgressStep(null);
      onSelectTarget(target);
      onClose();
    } catch (err: any) {
      setIsProcessing(false);
      setReconProgressStep(null);
      setUploadError(err.message || 'Live website probe failed. Verify target URL is reachable.');
    }
  };

  // Handle Real Local Linux / Host Directory Intake
  const handleLocalDirSubmit = async () => {
    if (!localDirPath.trim()) return;
    setIsProcessing(true);
    setUploadError(null);

    try {
      const res = await fetch('/api/intake/local-dir', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dirPath: localDirPath.trim() })
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to read local directory');
      }
      onSelectTarget(data.target);
      onClose();
    } catch (err: any) {
      setUploadError(err.message || 'Failed to scan local directory');
    } finally {
      setIsProcessing(false);
    }
  };

  // Handle Real Binary and Archive File Uploads (.apk, .exe, .ipa, .dmg, .zip)
  const handleUniversalUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsProcessing(true);
    setUploadError(null);

    const fileName = file.name;
    const ext = fileName.split('.').pop()?.toLowerCase() || '';

    try {
      if (['apk', 'ipa', 'exe', 'msi', 'dmg', 'pkg', 'elf', 'bin', 'so', 'dll'].includes(ext)) {
        const arrayBuffer = await file.arrayBuffer();
        const bytes = new Uint8Array(arrayBuffer);
        let binaryStr = '';
        const chunkSize = 0x8000;
        for (let i = 0; i < bytes.length; i += chunkSize) {
          binaryStr += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunkSize)));
        }
        const base64Data = btoa(binaryStr);

        const platform =
          ext === 'apk' ? 'android' :
          ext === 'ipa' ? 'ios' :
          ext === 'exe' || ext === 'msi' || ext === 'dll' ? 'windows' :
          ext === 'dmg' || ext === 'pkg' ? 'macos' : 'web';

        const res = await fetch('/api/intake/binary', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fileName, base64Data, platform })
        });
        const data = await res.json();
        if (!res.ok || !data.success) {
          throw new Error(data.error || `Binary analysis failed for ${fileName}`);
        }
        onSelectTarget(data.target);
        onClose();
      } else {
        const zip = new JSZip();
        const loadedZip = await zip.loadAsync(file);
        const projectFiles: ProjectFile[] = [];
        let totalLines = 0;

        for (const [relativePath, zipEntry] of Object.entries(loadedZip.files)) {
          if (!zipEntry.dir && !relativePath.includes('node_modules') && !relativePath.includes('.git')) {
            const content = await zipEntry.async('string');
            const fileExt = relativePath.split('.').pop()?.toLowerCase() || '';
            let language = 'text';
            if (['js', 'jsx', 'ts', 'tsx'].includes(fileExt)) language = 'javascript';
            else if (['py'].includes(fileExt)) language = 'python';
            else if (['json'].includes(fileExt)) language = 'json';
            else if (['yaml', 'yml'].includes(fileExt)) language = 'yaml';
            else if (['xml', 'plist'].includes(fileExt)) language = 'xml';
            else if (['java', 'kt'].includes(fileExt)) language = 'java';
            else if (['swift'].includes(fileExt)) language = 'swift';
            else if (['cpp', 'c', 'h'].includes(fileExt)) language = 'cpp';
            else if (['dockerfile'].includes(relativePath.toLowerCase())) language = 'dockerfile';

            const lines = content.split('\n').length;
            totalLines += lines;

            projectFiles.push({
              path: relativePath,
              content,
              language,
              size: content.length
            });
          }
        }

        if (projectFiles.length === 0) {
          throw new Error('No readable code or manifest files found in the uploaded archive.');
        }

        const newTarget: ScanTarget = {
          id: `zip-${Date.now()}`,
          name: file.name.replace(/\.zip$/i, ''),
          type: 'zip',
          platform: 'web',
          language: 'Multi-Language Project',
          description: `Uploaded archive with ${projectFiles.length} source code & config files.`,
          files: projectFiles,
          totalLines,
          scannedAt: new Date().toISOString()
        };

        onSelectTarget(newTarget);
        onClose();
      }
    } catch (err: any) {
      setUploadError(err.message || 'Failed to process the uploaded file');
    } finally {
      setIsProcessing(false);
    }
  };

  const handleCustomSnippetSubmit = () => {
    const lines = customCode.split('\n').length;
    const target: ScanTarget = {
      id: `snippet-${Date.now()}`,
      name: customName || 'Custom Application Snippet',
      type: 'snippet',
      platform: customPlatform,
      language: customLanguage,
      description: `User provided custom ${customPlatform} application code for auditing.`,
      totalLines: lines,
      scannedAt: new Date().toISOString(),
      files: [
        {
          path: customPlatform === 'android' ? 'AndroidManifest.xml' : customPlatform === 'ios' ? 'Info.plist' : customLanguage.includes('Python') ? 'app.py' : 'server.js',
          content: customCode,
          language: customLanguage.includes('Python') ? 'python' : customLanguage.includes('Swift') ? 'swift' : 'javascript',
          size: customCode.length
        }
      ]
    };

    onSelectTarget(target);
    onClose();
  };

  const handleGithubImport = async () => {
    if (!githubUrl.trim()) return;
    setIsProcessing(true);
    setUploadError(null);
    try {
      const res = await fetch('/api/intake/git', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: githubUrl.trim() })
      });
      const data = await res.json();
      if (!res.ok || !data.success) {
        throw new Error(data.error || 'Failed to clone repository from URL');
      }
      onSelectTarget(data.target);
      onClose();
    } catch (err: any) {
      setUploadError(err.message || 'Git clone failed. Verify the repository URL is public and reachable.');
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md animate-in fade-in">
      <div className="bg-[#111111] border border-[#1F1F1F] rounded-2xl w-full max-w-4xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1F1F1F] bg-[#161616]">
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-xl bg-blue-600 flex items-center justify-center text-white font-black text-base shadow-sm">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Target Intake Engine</h2>
              <p className="text-xs text-gray-500">Scan Real Local Workspaces, Live Websites, Binary Packages (.apk, .exe, .ipa, .dmg), and Git Repositories.</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-[#1F1F1F] transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-[#1F1F1F] bg-[#0F0F0F] px-6 pt-2 overflow-x-auto">
          <button
            onClick={() => setActiveTab('history')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all whitespace-nowrap cursor-pointer ${
              activeTab === 'history'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-400 hover:text-white'
            }`}
          >
            <Clock className="h-4 w-4 text-blue-400" />
            <span className="font-bold">Scanned Websites & Apps</span>
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-blue-950 text-blue-300 border border-blue-800/60">
              {scanHistory.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('website_recon')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all whitespace-nowrap cursor-pointer ${
              activeTab === 'website_recon'
                ? 'border-emerald-500 text-emerald-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Globe className="h-4 w-4 text-emerald-400" />
            <span className="font-bold">+ New Website URL</span>
          </button>

          <button
            onClick={() => setActiveTab('local_dir')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all whitespace-nowrap cursor-pointer ${
              activeTab === 'local_dir'
                ? 'border-emerald-500 text-emerald-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Server className="h-4 w-4 text-emerald-400" />
            <span className="font-bold">Local Directory</span>
          </button>

          <button
            onClick={() => setActiveTab('binary_upload')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all whitespace-nowrap cursor-pointer ${
              activeTab === 'binary_upload'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Upload className="h-4 w-4" />
            <span>Upload APK / EXE / IPA / DMG / ZIP</span>
          </button>

          <button
            onClick={() => setActiveTab('github')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all whitespace-nowrap cursor-pointer ${
              activeTab === 'github'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <Github className="h-4 w-4" />
            <span>Git / Remote Repo</span>
          </button>

          <button
            onClick={() => setActiveTab('snippet')}
            className={`flex items-center space-x-2 px-4 py-2.5 border-b-2 text-xs font-semibold tracking-tight transition-all whitespace-nowrap cursor-pointer ${
              activeTab === 'snippet'
                ? 'border-blue-500 text-blue-400 bg-[#161616]'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            <FileCode className="h-4 w-4" />
            <span>Paste Source Code</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="p-6 overflow-y-auto flex-1 bg-[#0A0A0A]">
          {uploadError && (
            <div className="mb-4 p-3 rounded-xl bg-red-950/40 border border-red-800 text-red-200 text-xs flex items-center space-x-2">
              <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}

          {activeTab === 'history' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-xl bg-[#141414] border border-[#1F1F1F]">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                    <Clock className="h-4 w-4 text-blue-400" />
                    <span>Previously Scanned Websites & Applications ({scanHistory.length})</span>
                  </h3>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Toggle between your saved websites and apps or launch a scan on a new target.
                  </p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => setActiveTab('website_recon')}
                    className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-wider transition-all cursor-pointer"
                  >
                    <PlusCircle className="h-3.5 w-3.5" />
                    <span>Scan New Website</span>
                  </button>
                  <button
                    onClick={() => setActiveTab('binary_upload')}
                    className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider transition-all cursor-pointer"
                  >
                    <Upload className="h-3.5 w-3.5" />
                    <span>Upload New App</span>
                  </button>
                </div>
              </div>

              {scanHistory.length === 0 ? (
                <div className="p-10 text-center rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3">
                  <Globe className="h-10 w-10 text-gray-600 mx-auto" />
                  <h4 className="text-sm font-bold text-gray-300">No Scanned Websites or Apps in History Yet</h4>
                  <p className="text-xs text-gray-500 max-w-md mx-auto">
                    Any website URL or application binary you scan is automatically saved in the persistent audit database so you can switch back to it anytime.
                  </p>
                  <button
                    onClick={() => setActiveTab('website_recon')}
                    className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold uppercase tracking-wider cursor-pointer"
                  >
                    <Globe className="h-4 w-4" />
                    <span>Scan Your First Website URL</span>
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  {scanHistory.map((item) => {
                    const isCurrent = item.target.id === activeTargetId;
                    const findingsCount = item.scanResult?.findings?.length ?? 0;
                    const resolvedCount = item.scanResult?.findings?.filter(f => f.status === 'VERIFIED_RESOLVED').length ?? 0;
                    const score = item.scanResult?.scoreCurrent ?? null;

                    return (
                      <div
                        key={item.target.id}
                        className={`p-4 rounded-xl border transition-all flex flex-col md:flex-row md:items-center justify-between gap-4 ${
                          isCurrent
                            ? 'bg-blue-950/20 border-blue-500/70 shadow-lg'
                            : 'bg-[#141414] border-[#1F1F1F] hover:border-[#333333]'
                        }`}
                      >
                        <div className="space-y-1.5 min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-blue-950 text-blue-400 border border-blue-800/50">
                              {item.target.type === 'url' ? 'LIVE WEBSITE' : (item.target.platform || 'WEB')}
                            </span>
                            {isCurrent && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-950 text-emerald-400 border border-emerald-800">
                                ● ACTIVE TARGET
                              </span>
                            )}
                            {score !== null && (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#1C1C1C] text-white border border-[#2C2C2C]">
                                Score: {score}/100
                              </span>
                            )}
                            <span className="text-[11px] font-mono text-gray-400">
                              {findingsCount} findings ({resolvedCount} fixed)
                            </span>
                          </div>

                          <h4 className="text-sm font-bold text-white truncate">{item.target.name}</h4>
                          <p className="text-[11px] font-mono text-gray-500">
                            Last audited: {new Date(item.updatedAt || item.target.scannedAt).toLocaleString()} • {item.target.files?.length || 0} files/configs
                          </p>
                        </div>

                        <div className="flex flex-wrap items-center gap-2 shrink-0">
                          <button
                            onClick={() => {
                              if (onSwitchToSavedTarget) {
                                onSwitchToSavedTarget(item);
                              } else {
                                onSelectTarget(item.target);
                              }
                              onClose();
                            }}
                            className={`px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider transition-all cursor-pointer flex items-center space-x-1.5 ${
                              isCurrent
                                ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                                : 'bg-blue-600 hover:bg-blue-500 text-white'
                            }`}
                          >
                            <CheckCircle2 className="h-3.5 w-3.5" />
                            <span>{isCurrent ? 'Active (Open)' : 'Switch to Target'}</span>
                          </button>

                          <button
                            onClick={() => {
                              onSelectTarget(item.target);
                              onClose();
                            }}
                            className="px-3 py-2 rounded-xl bg-[#1F1F1F] hover:bg-[#2A2A2A] border border-[#333333] text-gray-300 hover:text-white text-xs font-mono font-semibold transition-all cursor-pointer flex items-center space-x-1"
                            title="Re-run a fresh vulnerability scan on this target"
                          >
                            <RefreshCw className="h-3.5 w-3.5" />
                            <span>Re-Scan</span>
                          </button>

                          {onDeleteSavedTarget && (
                            <button
                              onClick={() => onDeleteSavedTarget(item.target.id)}
                              className="p-2 rounded-xl bg-[#1A1A1A] hover:bg-red-950/60 border border-[#2A2A2A] hover:border-red-800 text-gray-400 hover:text-red-400 transition-all cursor-pointer"
                              title="Remove from saved history"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {activeTab === 'local_dir' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1 font-mono uppercase text-[10px]">Host Workspace Directory Path</label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={localDirPath}
                    onChange={(e) => setLocalDirPath(e.target.value)}
                    className="flex-1 px-3.5 py-2.5 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white font-mono focus:outline-none focus:border-[#333333]"
                    placeholder="Enter directory path (e.g. . for current workspace, /app, or project path)"
                  />
                  <button
                    onClick={handleLocalDirSubmit}
                    disabled={isProcessing || !localDirPath.trim()}
                    className="flex items-center space-x-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {isProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Server className="h-4 w-4" />}
                    <span>Audit Directory</span>
                  </button>
                </div>
              </div>

              <div className="p-4 bg-[#141414] border border-[#1F1F1F] rounded-xl text-xs text-gray-400 leading-relaxed space-y-2">
                <span className="font-semibold text-emerald-400 block">Real-Time Filesystem Security Audit:</span>
                <p>
                  Directly inspects your live codebase. Executes native SAST scanners (Semgrep, Bandit), secrets detection (Gitleaks), container/config checks (Trivy), and dependency vulnerability auditing (pip-audit, npm audit, OSV.dev).
                </p>
              </div>
            </div>
          )}

          {activeTab === 'website_recon' && (
            <div className="space-y-5">
              <div className="p-5 rounded-2xl bg-[#0D0D0D] border border-[#1F1F1F] space-y-4">
                <div className="flex items-center space-x-3">
                  <div className="p-2.5 rounded-xl bg-emerald-950/40 border border-emerald-900/60 text-emerald-400">
                    <Globe className="h-6 w-6" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">Live Website & Web API Reconnaissance</h3>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Audits live DNS records, TLS certificates & ciphers, HTTP security response headers, cookies, and discovers exposed API routes in real-time.
                    </p>
                  </div>
                </div>

                <div className="space-y-3 pt-2">
                  <div>
                    <label className="block text-xs font-semibold text-gray-300 mb-1.5 font-mono uppercase text-[11px]">
                      Target URL
                    </label>
                    <div className="flex space-x-2">
                      <div className="relative flex-1">
                        <Globe className="h-4 w-4 text-gray-500 absolute left-3.5 top-3" />
                        <input
                          type="text"
                          value={websiteUrl}
                          onChange={(e) => setWebsiteUrl(e.target.value)}
                          placeholder="https://example.com or https://api.yourdomain.com"
                          className="w-full pl-10 pr-4 py-2.5 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white font-mono focus:outline-none focus:border-emerald-500 transition-colors"
                        />
                      </div>
                      <button
                        onClick={handleWebsiteReconSubmit}
                        disabled={isProcessing || !websiteUrl.trim()}
                        className="flex items-center space-x-2 px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-all shadow-lg disabled:opacity-50 cursor-pointer"
                      >
                        {isProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                        <span>Audit Website</span>
                      </button>
                    </div>
                  </div>
                </div>

                {isProcessing && reconProgressStep && (
                  <div className="mt-4 p-4 rounded-xl bg-emerald-950/30 border border-emerald-900/50 space-y-2 animate-in fade-in">
                    <div className="flex items-center space-x-2 text-xs font-mono text-emerald-300">
                      <Loader2 className="h-4 w-4 animate-spin text-emerald-400" />
                      <span>{reconProgressStep}</span>
                    </div>
                    <div className="w-full bg-emerald-950/60 rounded-full h-1.5 overflow-hidden">
                      <div className="bg-emerald-400 h-1.5 rounded-full animate-pulse w-3/4"></div>
                    </div>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="p-3.5 bg-[#141414] border border-[#1F1F1F] rounded-xl space-y-1.5">
                  <div className="flex items-center space-x-2 text-xs font-bold text-white">
                    <Lock className="h-3.5 w-3.5 text-blue-400" />
                    <span>Headers & TLS</span>
                  </div>
                  <p className="text-[11px] text-gray-500">
                    Live grading of CSP, HSTS, X-Frame-Options, CORS, and SSL/TLS cipher suites.
                  </p>
                </div>
                <div className="p-3.5 bg-[#141414] border border-[#1F1F1F] rounded-xl space-y-1.5">
                  <div className="flex items-center space-x-2 text-xs font-bold text-white">
                    <Zap className="h-3.5 w-3.5 text-emerald-400" />
                    <span>Endpoint Discovery</span>
                  </div>
                  <p className="text-[11px] text-gray-500">
                    Detects robots.txt, sitemaps, Swagger UI, GraphQL endpoints, and health probes.
                  </p>
                </div>
                <div className="p-3.5 bg-[#141414] border border-[#1F1F1F] rounded-xl space-y-1.5">
                  <div className="flex items-center space-x-2 text-xs font-bold text-white">
                    <CheckCircle2 className="h-3.5 w-3.5 text-purple-400" />
                    <span>Active DAST Prober</span>
                  </div>
                  <p className="text-[11px] text-gray-500">
                    Fuzz live endpoints with non-destructive SQLi and XSS payloads to test runtime defenses.
                  </p>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'binary_upload' && (
            <div className="space-y-4">
              <div className="border-2 border-dashed border-[#222222] hover:border-blue-500 rounded-2xl p-10 text-center transition-colors bg-[#0D0D0D] relative group">
                <input
                  type="file"
                  onChange={handleUniversalUpload}
                  accept=".apk,.exe,.msi,.ipa,.dmg,.pkg,.zip,.elf,.bin,.so,.dll"
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  disabled={isProcessing}
                />
                <div className="flex flex-col items-center space-y-3">
                  <div className="p-4 rounded-2xl bg-[#141414] group-hover:bg-blue-950/40 border border-[#1F1F1F] group-hover:border-blue-800 transition-colors">
                    {isProcessing ? (
                      <Loader2 className="h-8 w-8 text-blue-400 animate-spin" />
                    ) : (
                      <Upload className="h-8 w-8 text-gray-400 group-hover:text-blue-400" />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-bold text-white">
                      {isProcessing ? 'Analyzing Binary Package...' : 'Drop Binary or Package Here to Audit'}
                    </p>
                    <p className="text-xs text-gray-500 mt-1">
                      Supports Android (.apk), Windows (.exe, .msi), iOS (.ipa), macOS (.dmg), and ZIP archives
                    </p>
                  </div>
                  <span className="text-[11px] font-mono text-blue-400 bg-blue-950/40 border border-blue-900/60 px-3 py-1 rounded-full">
                    Real SHA-256 Digest • Magic Header Identification • String Extraction
                  </span>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'github' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1 font-mono uppercase text-[10px]">Public Git Repository URL</label>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={githubUrl}
                    onChange={(e) => setGithubUrl(e.target.value)}
                    className="flex-1 px-3.5 py-2.5 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white font-mono focus:outline-none focus:border-[#333333]"
                    placeholder="https://github.com/organization/project"
                  />
                  <button
                    onClick={handleGithubImport}
                    disabled={isProcessing || !githubUrl.trim()}
                    className="flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-colors disabled:opacity-50 cursor-pointer"
                  >
                    {isProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Github className="h-4 w-4" />}
                    <span>Clone & Audit</span>
                  </button>
                </div>
              </div>

              <div className="p-4 bg-[#141414] border border-[#1F1F1F] rounded-xl text-xs text-gray-400 leading-relaxed">
                <span className="font-semibold text-white block mb-1">Supported Git Repositories:</span>
                Clones the repository directly on the Linux host and executes full multi-engine SAST, SCA, and secrets scans across all source files.
              </div>
            </div>
          )}

          {activeTab === 'snippet' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1 font-mono uppercase text-[10px]">Module / Snippet Name</label>
                  <input
                    type="text"
                    value={customName}
                    onChange={(e) => setCustomName(e.target.value)}
                    className="w-full px-3 py-2 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white focus:outline-none focus:border-[#333333]"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-400 mb-1 font-mono uppercase text-[10px]">Platform & Language</label>
                  <select
                    value={customPlatform}
                    onChange={(e) => {
                      const p = e.target.value as TargetPlatform;
                      setCustomPlatform(p);
                      if (p === 'android') setCustomLanguage('Android / Kotlin & Java');
                      else if (p === 'ios') setCustomLanguage('iOS / Swift');
                      else if (p === 'windows') setCustomLanguage('Windows / C++');
                      else setCustomLanguage('JavaScript / Node.js & Express');
                    }}
                    className="w-full px-3 py-2 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white focus:outline-none focus:border-[#333333]"
                  >
                    <option value="web">Web Application / API</option>
                    <option value="android">Android Mobile (Java/Kotlin)</option>
                    <option value="ios">iOS Mobile (Swift)</option>
                    <option value="windows">Windows Desktop (C++)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1 font-mono uppercase text-[10px]">Source Code / Manifest</label>
                <textarea
                  value={customCode}
                  onChange={(e) => setCustomCode(e.target.value)}
                  rows={8}
                  className="w-full p-3 bg-black border border-[#1F1F1F] rounded-xl text-xs text-white font-mono focus:outline-none focus:border-[#333333]"
                  placeholder="// Paste your code or manifest XML here..."
                />
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleCustomSnippetSubmit}
                  className="flex items-center space-x-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold uppercase tracking-wider transition-colors shadow-lg cursor-pointer"
                >
                  <span>Start Audit</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer info */}
        <div className="px-6 py-3 border-t border-[#1F1F1F] bg-[#161616] flex items-center justify-between text-xs text-gray-600 font-mono">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
            <span>Multi-Engine Real-Time AppSec & DAST Engine</span>
          </div>
          <span>Native Sandboxed Execution</span>
        </div>
      </div>
    </div>
  );
};
