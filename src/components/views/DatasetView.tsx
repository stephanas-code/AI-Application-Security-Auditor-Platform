import React, { useState, useEffect } from 'react';
import { 
  Database, 
  Sparkles, 
  Code2, 
  CheckCircle2, 
  AlertTriangle, 
  ExternalLink, 
  Download, 
  Copy, 
  Check, 
  RefreshCw, 
  Terminal, 
  Cpu, 
  Flame, 
  Layers, 
  Filter, 
  BookOpen,
  ArrowRight,
  ShieldCheck,
  Zap,
  Play
} from 'lucide-react';

interface DatasetRecord {
  id: string;
  dataset: string;
  language: string;
  cwe: string;
  cwe_name: string;
  vulnerable: number;
  func: string;
  vuln_lines?: number[];
  root_cause?: string;
  fixed_func?: string | null;
  patch_diff?: string | null;
}

interface BenchmarkRecord {
  benchmark_id: string;
  cve: string;
  ecosystem: string;
  package: string;
  vulnerable_range: string;
  fixed_version: string;
  vulnerability_type: string;
  exploit_verification_harness: {
    exploit_poc_code: string;
    vulnerable_behavior: string;
    remediated_behavior: string;
  };
}

const PRIMEVUL_SAMPLES: DatasetRecord[] = [
  {
    id: "primevul-cwe89-01",
    dataset: "PrimeVul (ICSE 2025)",
    language: "python",
    cwe: "CWE-89",
    cwe_name: "SQL Injection",
    vulnerable: 1,
    func: `def get_user_transactions(user_id, status_filter):
    query = f"SELECT id, amount, memo FROM transactions WHERE user_id = '{user_id}' AND status = '{status_filter}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()`,
    vuln_lines: [2, 4],
    root_cause: "Dynamic f-string formatting interpolates raw user input into query string without prepared parameterization.",
    fixed_func: `def get_user_transactions(user_id, status_filter):
    query = "SELECT id, amount, memo FROM transactions WHERE user_id = %s AND status = %s"
    cursor = db.cursor()
    cursor.execute(query, (user_id, status_filter))
    return cursor.fetchall()`,
    patch_diff: `- query = f"SELECT id, amount, memo FROM transactions WHERE user_id = '{user_id}' AND status = '{status_filter}'"
- cursor.execute(query)
+ query = "SELECT id, amount, memo FROM transactions WHERE user_id = %s AND status = %s"
+ cursor.execute(query, (user_id, status_filter))`
  },
  {
    id: "primevul-cwe78-02",
    dataset: "PrimeVul (ICSE 2025)",
    language: "python",
    cwe: "CWE-78",
    cwe_name: "OS Command Injection",
    vulnerable: 1,
    func: `def check_network_host(hostname):
    cmd = 'ping -c 1 ' + hostname
    output = subprocess.check_output(cmd, shell=True)
    return output.decode('utf-8')`,
    vuln_lines: [2, 3],
    root_cause: "subprocess.check_output with shell=True permits command chaining metacharacters (; && |).",
    fixed_func: `def check_network_host(hostname):
    import re
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError('Invalid hostname format')
    output = subprocess.check_output(['ping', '-c', '1', hostname], shell=False)
    return output.decode('utf-8')`,
    patch_diff: `- cmd = 'ping -c 1 ' + hostname
- output = subprocess.check_output(cmd, shell=True)
+ if not re.match(r'^[a-zA-Z0-9.-]+$', hostname): raise ValueError('Invalid hostname')
+ output = subprocess.check_output(['ping', '-c', '1', hostname], shell=False)`
  },
  {
    id: "primevul-cwe798-03",
    dataset: "PrimeVul (ICSE 2025)",
    language: "python",
    cwe: "CWE-798",
    cwe_name: "Hardcoded Cryptographic Secret",
    vulnerable: 1,
    func: `def initialize_aws_client():
    AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
    AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)
    return client`,
    vuln_lines: [2, 3],
    root_cause: "High-entropy plaintext AWS IAM access credentials committed into codebase source constants.",
    fixed_func: `def initialize_aws_client():
    aws_key = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')
    if not aws_key or not aws_secret:
        raise EnvironmentError('AWS credentials missing in runtime environment')
    client = boto3.client('s3', aws_access_key_id=aws_key, aws_secret_access_key=aws_secret)
    return client`,
    patch_diff: `- AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
- AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
+ aws_key = os.getenv('AWS_ACCESS_KEY_ID')
+ aws_secret = os.getenv('AWS_SECRET_ACCESS_KEY')`
  },
  {
    id: "primevul-cwe306-04",
    dataset: "PrimeVul (ICSE 2025)",
    language: "javascript",
    cwe: "CWE-306",
    cwe_name: "Missing Authentication for Critical Function",
    vulnerable: 1,
    func: `app.get('/api/admin/dump-database', async (req, res) => {
  const data = await db.query('SELECT * FROM customer_vault');
  res.json(data);
});`,
    vuln_lines: [1],
    root_cause: "Privileged endpoint route mounted without authentication token and authorization check middleware.",
    fixed_func: `app.get('/api/admin/dump-database', requireAuth, requireRole('SUPER_ADMIN'), async (req, res) => {
  const data = await db.query('SELECT id, name, created_at FROM customer_vault');
  res.json(data);
});`,
    patch_diff: `- app.get('/api/admin/dump-database', async (req, res) => {
+ app.get('/api/admin/dump-database', requireAuth, requireRole('SUPER_ADMIN'), async (req, res) => {`
  },
  {
    id: "primevul-benign-05",
    dataset: "PrimeVul (ICSE 2025)",
    language: "python",
    cwe: "BENIGN",
    cwe_name: "Secure Parameterized Query",
    vulnerable: 0,
    func: `def get_item_by_sku(sku):
    with db.connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, price, stock FROM inventory WHERE sku = %s', (sku,))
        return cursor.fetchone()`,
    vuln_lines: [],
    root_cause: "None. Implementation utilizes parameterized arguments.",
    fixed_func: null,
    patch_diff: null
  }
];

const VULNREPAIREVAL_BENCHMARKS: BenchmarkRecord[] = [
  {
    benchmark_id: "VRE-PY-001",
    cve: "CVE-2023-32681",
    ecosystem: "PyPI",
    package: "requests",
    vulnerable_range: "<2.31.0",
    fixed_version: "2.31.0",
    vulnerability_type: "CWE-200 / Sensitive Header Leak",
    exploit_verification_harness: {
      exploit_poc_code: `def test_proxy_auth_leak_on_redirect(client):
    res = client.get('http://proxy.test/redirect-to-untrusted', headers={'Proxy-Authorization': 'SecretToken'})
    assert 'Proxy-Authorization' not in res.dest_headers`,
      vulnerable_behavior: "Proxy-Authorization header is forwarded to untrusted redirect destination (EXPLOIT SUCCESS)",
      remediated_behavior: "Proxy-Authorization header is stripped before redirect to foreign host (EXPLOIT BLOCKED)"
    }
  },
  {
    benchmark_id: "VRE-PY-002",
    cve: "CVE-2020-14343",
    ecosystem: "PyPI",
    package: "PyYAML",
    vulnerable_range: "<5.4",
    fixed_version: "5.4",
    vulnerability_type: "CWE-502 / Insecure YAML Deserialization",
    exploit_verification_harness: {
      exploit_poc_code: `def test_yaml_deserialization_blocked():
    payload = '!!python/object/apply:os.system ["touch /tmp/pwned"]'
    try:
        yaml.safe_load(payload)
    except yaml.constructor.ConstructorError:
        assert True # Secure`,
      vulnerable_behavior: "FullLoader evaluates object constructor and spawns subshell (EXPLOIT SUCCESS)",
      remediated_behavior: "SafeLoader rejects python/object constructor tags as unsafe (EXPLOIT BLOCKED)"
    }
  },
  {
    benchmark_id: "VRE-JS-003",
    cve: "CVE-2020-8203",
    ecosystem: "npm",
    package: "lodash",
    vulnerable_range: "<4.17.21",
    fixed_version: "4.17.21",
    vulnerability_type: "CWE-1321 / Prototype Pollution",
    exploit_verification_harness: {
      exploit_poc_code: `it('prevents Object.prototype pollution via zipObjectDeep', () => {
  _.zipObjectDeep(['__proto__.polluted'], ['yes']);
  expect({}.polluted).toBeUndefined();
});`,
      vulnerable_behavior: "Global Object.prototype is modified with property 'polluted': 'yes' (EXPLOIT SUCCESS)",
      remediated_behavior: "Keys containing '__proto__' or 'constructor' are sanitized (EXPLOIT BLOCKED)"
    }
  }
];

export const DatasetView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'stack' | 'samples' | 'benchmarks' | 'colab'>('stack');
  const [selectedSampleIndex, setSelectedSampleIndex] = useState(0);
  const [selectedBenchmarkIndex, setSelectedBenchmarkIndex] = useState(0);
  const [codeViewMode, setCodeViewMode] = useState<'diff' | 'vulnerable' | 'fixed'>('diff');
  const [copiedCode, setCopiedCode] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);
  const [filterCWE, setFilterCWE] = useState('ALL');

  const selectedSample = PRIMEVUL_SAMPLES[selectedSampleIndex] || PRIMEVUL_SAMPLES[0]!;
  const selectedBenchmark = VULNREPAIREVAL_BENCHMARKS[selectedBenchmarkIndex] || VULNREPAIREVAL_BENCHMARKS[0]!;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleSyncDatasets = async () => {
    setIsSyncing(true);
    try {
      await fetch('/api/datasets/summary');
    } catch {
      // ignore
    } finally {
      setTimeout(() => setIsSyncing(false), 600);
    }
  };

  const filteredSamples = PRIMEVUL_SAMPLES.filter(s => {
    if (filterCWE === 'ALL') return true;
    if (filterCWE === 'VULNERABLE') return s.vulnerable === 1;
    if (filterCWE === 'BENIGN') return s.vulnerable === 0;
    return s.cwe === filterCWE;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] flex flex-col lg:flex-row lg:items-center justify-between gap-5 relative overflow-hidden">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-blue-950/20 rounded-full blur-3xl pointer-events-none"></div>

        <div className="space-y-2 max-w-2xl relative z-10">
          <div className="flex items-center space-x-2">
            <span className="p-1 rounded bg-blue-950/60 border border-blue-800 text-blue-400 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center space-x-1">
              <Database className="h-3 w-3" />
              <span>CyberSecAI Multi-Dataset Stack</span>
            </span>
            <span className="p-1 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-mono text-[10px] font-bold uppercase tracking-wider flex items-center space-x-1">
              <Sparkles className="h-3 w-3" />
              <span>Fine-Tuning & Benchmarking Ready</span>
            </span>
          </div>

          <h2 className="text-xl font-black text-white tracking-tight flex items-center space-x-2.5">
            <span>AI Security Training & Evaluation Datasets</span>
          </h2>
          <p className="text-xs text-gray-400 leading-relaxed">
            Multi-dataset architecture powering vulnerability detection models, patch synthesis engines, and PoC exploit verification benchmarks (PrimeVul, VulnRepairEval, DiverseVul, HackerSignal).
          </p>
        </div>

        <div className="flex items-center space-x-3 relative z-10">
          <button
            onClick={handleSyncDatasets}
            disabled={isSyncing}
            className="flex items-center space-x-2 px-4 py-2 bg-[#1A1A1A] hover:bg-[#252525] border border-[#2F2F2F] text-gray-200 rounded-xl text-xs font-bold transition-all disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isSyncing ? 'animate-spin text-blue-400' : ''}`} />
            <span>{isSyncing ? 'Syncing...' : 'Sync Dataset Partitions'}</span>
          </button>

          <a
            href="https://colab.research.google.com/"
            target="_blank"
            rel="noreferrer"
            className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-black font-black rounded-xl text-xs uppercase tracking-wider transition-all shadow-lg shadow-amber-950/40"
          >
            <Zap className="h-3.5 w-3.5 fill-black" />
            <span>Open Google Colab</span>
          </a>
        </div>
      </div>

      {/* Navigation Sub-tabs */}
      <div className="flex items-center space-x-2 border-b border-[#1F1F1F] pb-3">
        <button
          onClick={() => setActiveTab('stack')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'stack'
              ? 'bg-blue-950/60 border border-blue-800 text-blue-400'
              : 'text-gray-400 hover:text-white hover:bg-[#161616]'
          }`}
        >
          <Layers className="h-4 w-4" />
          <span>Dataset Stack (5 Partitions)</span>
        </button>

        <button
          onClick={() => setActiveTab('samples')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'samples'
              ? 'bg-blue-950/60 border border-blue-800 text-blue-400'
              : 'text-gray-400 hover:text-white hover:bg-[#161616]'
          }`}
        >
          <Code2 className="h-4 w-4" />
          <span>PrimeVul Sample Explorer</span>
        </button>

        <button
          onClick={() => setActiveTab('benchmarks')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'benchmarks'
              ? 'bg-blue-950/60 border border-blue-800 text-blue-400'
              : 'text-gray-400 hover:text-white hover:bg-[#161616]'
          }`}
        >
          <ShieldCheck className="h-4 w-4" />
          <span>VulnRepairEval PoC Benchmarks</span>
        </button>

        <button
          onClick={() => setActiveTab('colab')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-bold transition-all ${
            activeTab === 'colab'
              ? 'bg-blue-950/60 border border-blue-800 text-blue-400'
              : 'text-gray-400 hover:text-white hover:bg-[#161616]'
          }`}
        >
          <Cpu className="h-4 w-4" />
          <span>Colab Training Pipeline</span>
        </button>
      </div>

      {/* Tab 1: Dataset Stack Architecture */}
      {activeTab === 'stack' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* PrimeVul */}
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3 hover:border-blue-900/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="p-1.5 rounded-lg bg-blue-950/60 border border-blue-800 text-blue-400 font-mono text-[10px] font-bold">
                  🥇 Core Detector
                </span>
                <span className="text-xs text-gray-500 font-mono">ICSE 2025</span>
              </div>
              <h3 className="text-base font-bold text-white">PrimeVul</h3>
              <p className="text-xs text-gray-400 leading-relaxed">
                236,000+ functions (7k vulnerable, 229k benign) across 140+ CWEs with chronological deduplication to prevent data leakage.
              </p>
              <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Task: Vulnerability Detection</span>
                <span className="text-emerald-400 font-bold">Ready ✓</span>
              </div>
            </div>

            {/* VulnRepairEval */}
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3 hover:border-emerald-900/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="p-1.5 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-mono text-[10px] font-bold">
                  🥈 Verification Benchmark
                </span>
                <span className="text-xs text-gray-500 font-mono">2025/2026</span>
              </div>
              <h3 className="text-base font-bold text-white">VulnRepairEval</h3>
              <p className="text-xs text-gray-400 leading-relaxed">
                Evaluates whether AI-generated patches actually block functional PoC exploits in sandboxes, rather than relying on LLM self-reporting.
              </p>
              <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Task: Exploit Verification</span>
                <span className="text-emerald-400 font-bold">Ready ✓</span>
              </div>
            </div>

            {/* DiverseVul */}
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3 hover:border-purple-900/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="p-1.5 rounded-lg bg-purple-950/60 border border-purple-800 text-purple-400 font-mono text-[10px] font-bold">
                  🥉 Generalization
                </span>
                <span className="text-xs text-gray-500 font-mono">Multi-Language</span>
              </div>
              <h3 className="text-base font-bold text-white">DiverseVul & Zenodo</h3>
              <p className="text-xs text-gray-400 leading-relaxed">
                330,000+ multi-source functions expanding language coverage across Python, JavaScript, Java, PHP, Go, C#, and C/C++.
              </p>
              <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Task: Multi-Lang Coverage</span>
                <span className="text-emerald-400 font-bold">Ready ✓</span>
              </div>
            </div>

            {/* HackerSignal */}
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3 hover:border-amber-900/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="p-1.5 rounded-lg bg-amber-950/60 border border-amber-800 text-amber-400 font-mono text-[10px] font-bold">
                  📊 Threat Intelligence
                </span>
                <span className="text-xs text-gray-500 font-mono">1990–2026</span>
              </div>
              <h3 className="text-base font-bold text-white">HackerSignal Graph</h3>
              <p className="text-xs text-gray-400 leading-relaxed">
                7.45 Million documents explicitly linking vulnerabilities, security discussions, CVEs, advisories, exploit PoCs, and fix commits.
              </p>
              <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Task: Analyst Reasoning</span>
                <span className="text-emerald-400 font-bold">Ready ✓</span>
              </div>
            </div>

            {/* CyberFixBench */}
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-3 hover:border-red-900/60 transition-all">
              <div className="flex items-center justify-between">
                <span className="p-1.5 rounded-lg bg-red-950/60 border border-red-800 text-red-400 font-mono text-[10px] font-bold">
                  🛡️ Proprietary Telemetry
                </span>
                <span className="text-xs text-gray-500 font-mono">Closed-Loop</span>
              </div>
              <h3 className="text-base font-bold text-white">CyberFixBench</h3>
              <p className="text-xs text-gray-400 leading-relaxed">
                Platform telemetry records: <i>Vulnerability → Real Sandbox Exploit Proof → Diff Patch → Verified Resolution</i>.
              </p>
              <div className="pt-2 border-t border-[#1C1C1C] flex items-center justify-between text-[11px] font-mono text-gray-400">
                <span>Task: Verification Loop</span>
                <span className="text-emerald-400 font-bold">Active Logging</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: PrimeVul Sample Explorer */}
      {activeTab === 'samples' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Sample List */}
          <div className="lg:col-span-4 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#1F1F1F]">
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Curated Samples</span>
              <div className="flex items-center space-x-1">
                <Filter className="h-3 w-3 text-gray-500" />
                <select
                  value={filterCWE}
                  onChange={e => setFilterCWE(e.target.value)}
                  className="bg-[#141414] border border-[#222222] text-[10px] text-gray-300 rounded px-2 py-0.5 focus:outline-none"
                >
                  <option value="ALL">All Samples</option>
                  <option value="VULNERABLE">Vulnerable Only</option>
                  <option value="BENIGN">Benign Only</option>
                  <option value="CWE-89">CWE-89 (SQLi)</option>
                  <option value="CWE-78">CWE-78 (Cmd Inj)</option>
                  <option value="CWE-798">CWE-798 (Secrets)</option>
                  <option value="CWE-306">CWE-306 (Auth)</option>
                </select>
              </div>
            </div>

            <div className="space-y-2 max-h-[560px] overflow-y-auto pr-1">
              {filteredSamples.map((sample, idx) => (
                <div
                  key={sample.id}
                  onClick={() => setSelectedSampleIndex(idx)}
                  className={`p-3 rounded-xl border cursor-pointer transition-all ${
                    selectedSampleIndex === idx
                      ? 'bg-[#181818] border-blue-600 shadow-md shadow-blue-950/30'
                      : 'bg-[#111111] border-[#1F1F1F] hover:bg-[#151515]'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white">{sample.cwe}</span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                      sample.vulnerable === 1 ? 'bg-red-950 text-red-400 border border-red-800' : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    }`}>
                      {sample.vulnerable === 1 ? 'VULNERABLE' : 'BENIGN'}
                    </span>
                  </div>
                  <p className="text-[11px] text-gray-400 truncate mt-1">{sample.cwe_name}</p>
                  <div className="flex items-center justify-between text-[9px] font-mono text-gray-500 mt-2">
                    <span className="uppercase">{sample.language}</span>
                    <span>{sample.id}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right Code Inspector */}
          <div className="lg:col-span-8 space-y-4">
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#1F1F1F]">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-bold text-white">{selectedSample.cwe_name}</span>
                    <span className="font-mono text-xs text-blue-400">({selectedSample.cwe})</span>
                  </div>
                  <p className="text-xs text-gray-400 mt-0.5">{selectedSample.root_cause || 'Secure AST query implementation.'}</p>
                </div>

                <div className="flex items-center space-x-2">
                  <div className="bg-[#181818] p-1 rounded-lg border border-[#262626] flex items-center space-x-1">
                    <button
                      onClick={() => setCodeViewMode('diff')}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all ${
                        codeViewMode === 'diff' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      Unified Diff
                    </button>
                    <button
                      onClick={() => setCodeViewMode('vulnerable')}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all ${
                        codeViewMode === 'vulnerable' ? 'bg-red-600 text-white' : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      Vulnerable Code
                    </button>
                    <button
                      onClick={() => setCodeViewMode('fixed')}
                      className={`px-2.5 py-1 rounded text-[10px] font-bold transition-all ${
                        codeViewMode === 'fixed' ? 'bg-emerald-600 text-white' : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      Fixed Code
                    </button>
                  </div>

                  <button
                    onClick={() => handleCopy(codeViewMode === 'diff' ? selectedSample.patch_diff || selectedSample.func : codeViewMode === 'fixed' ? selectedSample.fixed_func || '' : selectedSample.func)}
                    className="p-1.5 rounded-lg bg-[#181818] border border-[#2A2A2A] text-gray-400 hover:text-white"
                  >
                    {copiedCode ? <Check className="h-4 w-4 text-emerald-400" /> : <Copy className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {/* Code Box */}
              <div className="bg-[#0A0A0A] rounded-xl p-4 border border-[#1A1A1A] font-mono text-xs overflow-x-auto">
                <pre className="text-gray-200">
                  {codeViewMode === 'diff' && (
                    selectedSample.patch_diff ? (
                      selectedSample.patch_diff.split('\n').map((line, idx) => (
                        <div key={idx} className={line.startsWith('+') ? 'text-emerald-400 bg-emerald-950/20' : line.startsWith('-') ? 'text-red-400 bg-red-950/20' : 'text-gray-400'}>
                          {line}
                        </div>
                      ))
                    ) : (
                      <span className="text-emerald-400"># Benign Sample (No patch needed. Code is secure)</span>
                    )
                  )}

                  {codeViewMode === 'vulnerable' && selectedSample.func}
                  {codeViewMode === 'fixed' && (selectedSample.fixed_func || selectedSample.func)}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 3: VulnRepairEval Benchmarks */}
      {activeTab === 'benchmarks' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-4 space-y-2">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Automated Exploit PoC Benchmarks</h3>
            {VULNREPAIREVAL_BENCHMARKS.map((b, idx) => (
              <div
                key={b.benchmark_id}
                onClick={() => setSelectedBenchmarkIndex(idx)}
                className={`p-3 rounded-xl border cursor-pointer transition-all ${
                  selectedBenchmarkIndex === idx
                    ? 'bg-[#181818] border-emerald-600 shadow-md shadow-emerald-950/30'
                    : 'bg-[#111111] border-[#1F1F1F] hover:bg-[#151515]'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white">{b.cve}</span>
                  <span className="text-[10px] font-mono bg-blue-950 text-blue-400 border border-blue-800 px-1.5 py-0.5 rounded">
                    {b.package} ({b.ecosystem})
                  </span>
                </div>
                <p className="text-[11px] text-gray-400 truncate mt-1">{b.vulnerability_type}</p>
                <div className="flex items-center justify-between text-[9px] font-mono text-gray-500 mt-2">
                  <span>Vuln: {b.vulnerable_range}</span>
                  <span>Fixed: {b.fixed_version}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="lg:col-span-8 space-y-4">
            <div className="p-5 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-[#1F1F1F]">
                <div>
                  <span className="text-sm font-bold text-white">{selectedBenchmark.cve} - {selectedBenchmark.package}</span>
                  <p className="text-xs text-gray-400">{selectedBenchmark.vulnerability_type}</p>
                </div>
                <span className="px-2.5 py-1 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-mono text-[10px] font-bold">
                  Functional Sandbox Harness
                </span>
              </div>

              {/* Exploit PoC Code */}
              <div className="space-y-1">
                <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Functional Verification Test Assertion</span>
                <div className="bg-[#0A0A0A] p-3 rounded-xl border border-[#1A1A1A] font-mono text-xs text-emerald-300 overflow-x-auto">
                  <pre>{selectedBenchmark.exploit_verification_harness.exploit_poc_code}</pre>
                </div>
              </div>

              {/* Behavior Comparison */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                <div className="p-3 rounded-xl bg-red-950/20 border border-red-900/60 space-y-1">
                  <div className="text-[10px] font-bold text-red-400 uppercase">Vulnerable Target Behavior</div>
                  <p className="text-xs text-red-200">{selectedBenchmark.exploit_verification_harness.vulnerable_behavior}</p>
                </div>

                <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-900/60 space-y-1">
                  <div className="text-[10px] font-bold text-emerald-400 uppercase">Remediated Target Behavior</div>
                  <p className="text-xs text-emerald-200">{selectedBenchmark.exploit_verification_harness.remediated_behavior}</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Google Colab Training Pipeline */}
      {activeTab === 'colab' && (
        <div className="p-6 rounded-2xl bg-[#111111] border border-[#1F1F1F] space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#1F1F1F]">
            <div>
              <h3 className="text-base font-bold text-white">Google Colab Fine-Tuning Guide (QLoRA 4-bit)</h3>
              <p className="text-xs text-gray-400">Step-by-step instructions to train Qwen2.5-Coder-7B or DeepSeek-Coder on the CyberSecAI Stack.</p>
            </div>
            <a
              href="https://colab.research.google.com/"
              target="_blank"
              rel="noreferrer"
              className="flex items-center space-x-2 px-4 py-2 bg-gradient-to-r from-amber-500 to-amber-600 text-black font-black rounded-xl text-xs uppercase tracking-wider"
            >
              <ExternalLink className="h-3.5 w-3.5" />
              <span>Launch Google Colab</span>
            </a>
          </div>

          <div className="space-y-3">
            <div className="p-4 rounded-xl bg-[#0C0C0C] border border-[#1A1A1A] space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-gray-300">
                <span>1. Clone and Fetch Dataset Partitions</span>
                <button
                  onClick={() => handleCopy("git clone https://github.com/stephanas-code/AI-Application-Security-Auditor-Platform.git\npython AI-Application-Security-Auditor-Platform/data_pipeline/dataset_fetcher.py")}
                  className="text-gray-400 hover:text-white"
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
              </div>
              <pre className="text-[11px] font-mono text-emerald-400 bg-black/40 p-2.5 rounded">
                git clone https://github.com/stephanas-code/AI-Application-Security-Auditor-Platform.git
python AI-Application-Security-Auditor-Platform/data_pipeline/dataset_fetcher.py
              </pre>
            </div>

            <div className="p-4 rounded-xl bg-[#0C0C0C] border border-[#1A1A1A] space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-gray-300">
                <span>2. Install Unsloth & Transformers in Colab</span>
                <button
                  onClick={() => handleCopy('pip install "unsloth[colab-new]" trl peft bitsandbytes datasets')}
                  className="text-gray-400 hover:text-white"
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
              </div>
              <pre className="text-[11px] font-mono text-emerald-400 bg-black/40 p-2.5 rounded">
                pip install "unsloth[colab-new]" trl peft bitsandbytes datasets
              </pre>
            </div>

            <div className="p-4 rounded-xl bg-[#0C0C0C] border border-[#1A1A1A] space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-gray-300">
                <span>3. View Complete Training Notebook</span>
              </div>
              <p className="text-xs text-gray-400">
                Refer to <code className="text-blue-400 bg-blue-950/40 px-1 py-0.5 rounded">TRAINING_COLAB.md</code> in the repository root for all 7 runnable cells including model evaluation and GGUF quantization export.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
