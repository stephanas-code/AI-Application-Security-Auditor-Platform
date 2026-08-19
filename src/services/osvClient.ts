export interface DependencyPackage {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | 'Go' | 'Maven' | 'Packagist' | 'RubyGems' | 'crates.io';
}

export interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
    versions?: string[];
  }>;
}

export interface ResolvedVulnInfo {
  pkgName: string;
  version: string;
  ecosystem: string;
  vulnId: string;
  cve: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
  fixedVersion: string;
}

export class OSVClient {
  private static OSV_API_URL = 'https://api.osv.dev/v1/querybatch';

  /**
   * Query OSV.dev API for a batch of dependencies
   */
  static async queryBatch(packages: DependencyPackage[]): Promise<ResolvedVulnInfo[]> {
    if (!packages || packages.length === 0) return [];

    try {
      const queries = packages.map(pkg => ({
        package: {
          name: pkg.name,
          ecosystem: pkg.ecosystem
        },
        version: pkg.version.replace(/[\^~>=<]/g, '')
      }));

      const res = await fetch(this.OSV_API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ queries })
      });

      if (!res.ok) {
        console.warn(`OSV API returned HTTP ${res.status}`);
        return [];
      }

      const data = await res.json();
      const results: ResolvedVulnInfo[] = [];

      if (!data.results || !Array.isArray(data.results)) {
        return [];
      }

      data.results.forEach((item: { vulns?: OSVVulnerability[] }, index: number) => {
        const targetPkg = packages[index];
        if (!targetPkg || !item.vulns) return;

        for (const vuln of item.vulns) {
          const cves = (vuln.aliases || []).filter(a => a.startsWith('CVE-'));
          const mainId = vuln.id || (cves[0] || 'VULN-UNKNOWN');

          // Extract fixed version
          let fixedVer = '';
          if (vuln.affected) {
            for (const aff of vuln.affected) {
              if (aff.ranges) {
                for (const range of aff.ranges) {
                  for (const event of range.events) {
                    if (event.fixed) {
                      fixedVer = event.fixed;
                      break;
                    }
                  }
                  if (fixedVer) break;
                }
              }
              if (fixedVer) break;
            }
          }

          // Determine severity
          let severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
          const scoreStr = vuln.severity?.[0]?.score || '';
          if (scoreStr.startsWith('CVSS:3.')) {
            // Estimate or default
            severity = 'HIGH';
          }
          if (vuln.summary?.toLowerCase().includes('remote code execution') || vuln.summary?.toLowerCase().includes('prototype pollution') || vuln.summary?.toLowerCase().includes('sql injection')) {
            severity = 'CRITICAL';
          }

          results.push({
            pkgName: targetPkg.name,
            version: targetPkg.version,
            ecosystem: targetPkg.ecosystem,
            vulnId: mainId,
            cve: cves.length > 0 ? cves : [mainId],
            severity,
            title: vuln.summary || `${mainId} in ${targetPkg.name}`,
            description: vuln.details || vuln.summary || `Vulnerability identified in ${targetPkg.name}@${targetPkg.version}`,
            fixedVersion: fixedVer ? `>=${fixedVer}` : 'Latest Available'
          });
        }
      });

      return results;
    } catch (err) {
      console.warn('Failed to query OSV.dev API:', err);
      return [];
    }
  }
}
