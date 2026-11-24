/**
 * Pure Structural URL Parser for TRAPSHIELD
 * 
 * CRITICAL SAFETY REQUIREMENT:
 * This module performs 100% offline, structural and lexical inspection.
 * It NEVER performs network calls, DNS queries, HTTP requests, or socket connections.
 */

// Common high-risk TLDs frequently abused in ephemeral phishing & spam campaigns
export const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'buzz', 'fit', 'surf', 'tk', 'ml', 'ga', 'cf', 'gq',
  'work', 'click', 'rest', 'country', 'kim', 'link', 'icu', 'cam',
  'vip', 'monster', 'hair', 'quest', 'zip', 'mov', 'sbs'
]);

// Trusted major consumer and banking brands commonly impersonated via subdomain/path typosquatting
export const TARGETED_BRANDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook',
  'instagram', 'whatsapp', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
  'binance', 'coinbase', 'metamask', 'dhl', 'fedex', 'usps', 'ups', 'irs',
  'dropbox', 'adobe', 'steam', 'spotify', 'sbi', 'hdfc', 'icici'
];

// Verified official primary domains for targeted institutions
export const OFFICIAL_BRAND_DOMAINS = Object.freeze({
  sbi: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'statebankofindia.com', 'sbi'],
  hdfc: ['hdfcbank.com', 'hdfc.com'],
  icici: ['icicibank.com', 'icici.com'],
  paypal: ['paypal.com', 'paypal.me'],
  apple: ['apple.com', 'icloud.com'],
  google: ['google.com', 'gmail.com', 'google.co.in', 'googleblog.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'aws.amazon.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com', 'bofa.com'],
  citibank: ['citibank.com', 'citi.com'],
  dhl: ['dhl.com'],
  fedex: ['fedex.com'],
  usps: ['usps.com'],
  ups: ['ups.com'],
  irs: ['irs.gov'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  spotify: ['spotify.com'],
  dropbox: ['dropbox.com'],
  adobe: ['adobe.com'],
});

const SENSITIVE_ACTION_KEYWORDS = new Set([
  'kyc', 'verification', 'verify', 'login', 'signin', 'secure', 'security',
  'update', 'account', 'banking', 'service', 'support', 'portal', 'auth',
  'unlock', 'blocked', 'suspend', 'restore', 'ebanking', 'netbanking'
]);

// Suspicious executable or script file extensions
export const SUSPICIOUS_EXTENSIONS = [
  '.exe', '.scr', '.bat', '.cmd', '.vbs', '.apk', '.msi', '.ps1', '.iso', '.dmg', '.jar'
];

/**
 * Validates whether a hostname is an IPv4 or IPv6 address
 * @param {string} hostname 
 * @returns {boolean}
 */
export function isIpAddress(hostname) {
  if (!hostname) return false;
  
  // IPv4 regex (0.0.0.0 to 255.255.255.255)
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(hostname)) return true;

  // IPv6 check (enclosed in brackets or plain hex groups)
  const cleanIpv6 = hostname.replace(/^\[|\]$/g, '');
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?::(([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})?$/;
  return ipv6Regex.test(cleanIpv6);
}

/**
 * Checks if a URL structure exhibits brand impersonation patterns offline.
 * Distinguishes between legitimate official domains, non-brand domains, and suspicious subdomain/host mimicry.
 * NEVER visits, resolves, or queries the URL over the network.
 * @param {object} urlStructure 
 * @returns {{ isImpersonating: boolean, brand?: string, evidence?: string, reason?: string }}
 */
export function detectBrandImpersonationPattern(urlStructure) {
  if (!urlStructure || !urlStructure.hostname || urlStructure.isIp) {
    return { isImpersonating: false };
  }

  const hostname = urlStructure.hostname.toLowerCase();
  const registered = (urlStructure.registeredDomain || '').toLowerCase();
  const subdomains = (urlStructure.subdomains || []).map(s => s.toLowerCase());

  for (const [brand, officialDomains] of Object.entries(OFFICIAL_BRAND_DOMAINS)) {
    // 1. If registeredDomain itself is official for this brand, it is NOT an impersonation pattern
    const isOfficial = officialDomains.some(d => registered === d || registered.endsWith(`.${d}`) || hostname.endsWith(`.${d}`));
    if (isOfficial) continue;

    // 2. Check if brand name is present as a delimited token in hostname or subdomains
    // We split by standard domain delimiters (., -, _) to avoid substring false-positives
    const hostTokens = hostname.split(/[-._]/).filter(Boolean);
    const hasBrandToken = hostTokens.includes(brand);

    if (!hasBrandToken) continue;

    // 3. User requirement: "Do not treat a brand name alone or a generic domain as proof of impersonation."
    // Verify that the brand token is paired with:
    // a) Sensitive action keywords (kyc, verify, login, security, etc.) anywhere in host tokens
    // OR b) The brand token sits in an anomalous subdomain on an unrelated commercial/generic root domain
    const hasSensitiveKeyword = hostTokens.some(t => SENSITIVE_ACTION_KEYWORDS.has(t));
    const isSubdomainSpoof = subdomains.some(sub => sub.split(/[-._]/).includes(brand));

    if (hasSensitiveKeyword || isSubdomainSpoof) {
      return {
        isImpersonating: true,
        brand: brand.toUpperCase(),
        registeredDomain: registered,
        evidence: `${urlStructure.raw} (${brand.toUpperCase()} pattern on ${registered})`,
        reason: `Subdomain/host tokens contain brand identity '${brand.toUpperCase()}'${hasSensitiveKeyword ? ' paired with sensitive action keywords' : ''} on unrelated registered domain '${registered}'.`,
      };
    }
  }

  return { isImpersonating: false };
}

/**
 * Parses and returns structural breakdown of a URL string without network operations
 * @param {string} rawInput 
 * @returns {object|null}
 */
export function parseUrlStructure(rawInput) {
  if (typeof rawInput !== 'string' || !rawInput.trim()) return null;

  const trimmed = rawInput.trim();
  
  // Check for embedded basic auth / userinfo deception (e.g. https://legit.com@evil.com)
  const hasDeceptiveAt = trimmed.includes('@');
  
  // Ensure protocol is present for URL parser
  let normalizedInput = trimmed;
  if (!/^https?:\/\//i.test(normalizedInput)) {
    normalizedInput = `http://${normalizedInput}`;
  }

  let parsed;
  try {
    parsed = new URL(normalizedInput);
  } catch {
    return {
      raw: trimmed,
      isValid: false,
      hasDeceptiveAt,
      error: 'Malformed URL structure',
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname;
  const search = parsed.search;
  const port = parsed.port;
  const username = parsed.username;
  const password = parsed.password;

  // Host parts & subdomain nesting
  const hostParts = hostname.split('.').filter(Boolean);
  const isIp = isIpAddress(hostname);
  
  // TLD extraction (for non-IP hosts)
  let tld = '';
  let registeredDomain = '';
  let subdomains = [];

  if (!isIp && hostParts.length > 1) {
    tld = hostParts[hostParts.length - 1];
    
    // Simple 2-level ccTLD handling (e.g., .co.uk, .com.au, .co.in)
    const secondLevelTlds = ['co', 'com', 'org', 'net', 'gov', 'edu'];
    if (hostParts.length >= 3 && secondLevelTlds.includes(hostParts[hostParts.length - 2])) {
      tld = `${hostParts[hostParts.length - 2]}.${tld}`;
      registeredDomain = `${hostParts[hostParts.length - 3]}.${tld}`;
      subdomains = hostParts.slice(0, hostParts.length - 3);
    } else {
      registeredDomain = `${hostParts[hostParts.length - 2]}.${tld}`;
      subdomains = hostParts.slice(0, hostParts.length - 2);
    }
  } else if (!isIp && hostParts.length === 1) {
    registeredDomain = hostname;
  }

  // Punycode / IDN detection
  const isPunycode = hostname.startsWith('xn--') || hostname.includes('.xn--');
  const hasNonAscii = /[^\u0000-\u007F]/.test(hostname);

  return {
    raw: trimmed,
    isValid: true,
    protocol: parsed.protocol,
    hostname,
    port,
    pathname,
    search,
    hasDeceptiveAt: hasDeceptiveAt || !!(username || password),
    userInfo: username ? `${username}${password ? `:${password}` : ''}` : '',
    isIp,
    hostParts,
    tld,
    registeredDomain,
    subdomains,
    subdomainCount: subdomains.length,
    isPunycode,
    hasNonAscii,
  };
}
