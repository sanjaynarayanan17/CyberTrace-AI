// CyberTrace AI — Frontend Backend API Client
// =============================================================================
// Connects the React UI to the Express forensic backend:
//   - Live IP Geolocation (ip-api.com + ipinfo.io + geoip-lite)
//   - Linux CLI tool analysis (dig, whois, host, nslookup, traceroute, ping)
//   - DNS security checks (SPF, DMARC, MX, PTR)
//   - Domain WHOIS & age intelligence
//   - Threat reputation scoring
// =============================================================================

const API_BASE =
  import.meta.env.VITE_BACKEND_URL ||
  (import.meta.env.DEV ? 'http://localhost:3001/api' : '/api');

/**
 * Check if the forensic backend is online
 */
export async function checkBackendHealth() {
  try {
    const res = await fetch(`${API_BASE}/health`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { online: false, error: `HTTP ${res.status}` };
    const data = await res.json();
    return { online: true, ...data };
  } catch (err) {
    return { online: false, error: err.message };
  }
}

/**
 * Live IP Geolocation lookup
 * @param {string} ip
 */
export async function fetchIpGeo(ip) {
  if (!ip) return null;
  try {
    const res = await fetch(`${API_BASE}/geoip/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API] fetchIpGeo error for ${ip}:`, err.message);
    return null;
  }
}

/**
 * Batch IP Geolocation for multiple hops
 * @param {string[]} ips
 */
export async function fetchBatchGeo(ips) {
  if (!Array.isArray(ips) || ips.length === 0) return [];
  try {
    const res = await fetch(`${API_BASE}/geoip/batch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const json = await res.json();
    return json.data || [];
  } catch (err) {
    console.warn('[API] fetchBatchGeo error:', err.message);
    return [];
  }
}

/**
 * Query DNS records using Linux dig
 * @param {string} domain
 */
export async function fetchDnsAnalysis(domain) {
  if (!domain) return null;
  try {
    const res = await fetch(`${API_BASE}/dns/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API] fetchDnsAnalysis error for ${domain}:`, err.message);
    return null;
  }
}

/**
 * Reverse DNS / PTR query using Linux host
 * @param {string} ip
 */
export async function fetchReverseDns(ip) {
  if (!ip) return null;
  try {
    const res = await fetch(`${API_BASE}/dns/reverse/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API] fetchReverseDns error for ${ip}:`, err.message);
    return null;
  }
}

/**
 * Domain WHOIS and registration age using Linux whois / RDAP
 * @param {string} domain
 */
export async function fetchWhois(domain) {
  if (!domain) return null;
  try {
    const res = await fetch(`${API_BASE}/whois/${encodeURIComponent(domain)}`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API] fetchWhois error for ${domain}:`, err.message);
    return null;
  }
}

/**
 * IP threat reputation lookup
 * @param {string} ip
 */
export async function fetchThreatIntel(ip) {
  if (!ip) return null;
  try {
    const res = await fetch(`${API_BASE}/threat/ip/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn(`[API] fetchThreatIntel error for ${ip}:`, err.message);
    return null;
  }
}

/**
 * Full backend email header forensic analysis (hops + reverse DNS + GeoIP + SPF/DMARC)
 * @param {string} rawHeaders
 * @param {string} [senderDomain]
 */
export async function analyzeHeadersBackend(rawHeaders, senderDomain) {
  try {
    const res = await fetch(`${API_BASE}/headers/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rawHeaders, senderDomain }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API] analyzeHeadersBackend error:', err.message);
    return null;
  }
}

/**
 * Fetch backend Linux tool capabilities (WSL / native, available tools)
 */
export async function fetchToolCapabilities() {
  try {
    const res = await fetch(`${API_BASE}/tools/capabilities`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('[API] fetchToolCapabilities error:', err.message);
    return null;
  }
}

/**
 * Execute a Linux forensic tool on demand
 * @param {'dig'|'whois'|'host'|'traceroute'|'ping'} tool
 * @param {string} target Domain or IP
 * @param {string} [type] Record type (e.g. 'SPF', 'DMARC', 'MX', 'TXT', 'A')
 */
export async function executeLinuxTool(tool, target, type = 'A') {
  try {
    const res = await fetch(`${API_BASE}/tools/execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool, target, type }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      const errorJson = await res.json().catch(() => ({}));
      throw new Error(errorJson.error || `HTTP ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    return { success: false, error: err.message, target, tool };
  }
}
