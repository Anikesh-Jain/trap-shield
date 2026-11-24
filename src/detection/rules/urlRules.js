/**
 * Detection Rules for Suspicious URLs (Pure Structural Analysis)
 * 
 * CRITICAL SAFETY REQUIREMENT:
 * Offline, structural-only analysis. Never visit, fetch, or query submitted URLs.
 */

import { SEVERITY_LEVELS, RULE_CATEGORIES } from '../types.js';
import { parseUrlStructure, HIGH_RISK_TLDS, TARGETED_BRANDS, SUSPICIOUS_EXTENSIONS, detectBrandImpersonationPattern } from '../utils/urlParser.js';

export const urlRules = [
  {
    id: 'URL_IP_ADDRESS_HOST',
    category: RULE_CATEGORIES.HOST_ANOMALY,
    name: 'Raw IP Address Hostname',
    description: 'Uses a raw numerical IP address instead of a registered domain name, a hallmark of short-lived malicious infrastructure.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ urlStructure }) => {
      if (urlStructure && urlStructure.isIp) {
        return {
          matched: true,
          evidence: [urlStructure.hostname],
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_PUNYCODE_HOMOGLYPH',
    category: RULE_CATEGORIES.OBFUSCATION,
    name: 'Punycode or Homoglyph Domain Obfuscation',
    description: 'Uses internationalized domain name (IDN) punycode or Cyrillic/Greek lookalike characters to visually mimic legitimate brands.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ urlStructure }) => {
      if (urlStructure && (urlStructure.isPunycode || urlStructure.hasNonAscii)) {
        return {
          matched: true,
          evidence: [urlStructure.hostname],
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_EMBEDDED_USERINFO_DECEPTION',
    category: RULE_CATEGORIES.STRUCTURAL_DECEPTION,
    name: 'Embedded Userinfo / Deceptive Authority Symbol',
    description: 'Employs the "@" character in the authority segment to trick users into misidentifying the destination host.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 30,
    evaluate: ({ urlStructure }) => {
      if (urlStructure && urlStructure.hasDeceptiveAt) {
        return {
          matched: true,
          evidence: [urlStructure.userInfo || '@ authority segment'],
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_HIGH_RISK_TLD',
    category: RULE_CATEGORIES.REPUTATION,
    name: 'High-Abuse Top-Level Domain (TLD)',
    description: 'Hosted on a top-level domain frequently associated with automated phishing and disposable malicious sites.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 20,
    evaluate: ({ urlStructure }) => {
      if (urlStructure && urlStructure.tld) {
        const rootTld = urlStructure.tld.toLowerCase();
        // Check both simple and compound TLDs
        const matches = [...HIGH_RISK_TLDS].filter(t => rootTld === t || rootTld.endsWith(`.${t}`));
        if (matches.length > 0) {
          return {
            matched: true,
            evidence: [`.${urlStructure.tld}`],
          };
        }
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_BRAND_IMPERSONATION_SUBDOMAIN',
    category: RULE_CATEGORIES.BRAND_SPOOFING,
    name: 'Brand Spoofing in Subdomain or Hostname',
    description: 'Embeds a recognized brand name in subdomains or host tokens to mimic legitimate services while the root domain is unrelated.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 30,
    evaluate: ({ urlStructure }) => {
      const result = detectBrandImpersonationPattern(urlStructure);
      if (result && result.isImpersonating) {
        return {
          matched: true,
          evidence: [result.evidence || `${result.brand} pattern on ${result.registeredDomain}`],
          details: { brand: result.brand, reason: result.reason },
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_DEEP_SUBDOMAIN_NESTING',
    category: RULE_CATEGORIES.STRUCTURAL_ANOMALY,
    name: 'Excessive Subdomain Nesting',
    description: 'Features multiple nested subdomain levels commonly used by phishing toolkits to evade automated domain filters.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 15,
    evaluate: ({ urlStructure }) => {
      if (urlStructure && urlStructure.subdomainCount >= 3) {
        return {
          matched: true,
          evidence: [urlStructure.subdomains.join('.')],
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_CREDENTIAL_PATH_KEYWORDS',
    category: RULE_CATEGORIES.CREDENTIAL_HARVESTING,
    name: 'Credential Harvesting Path Signature on Anomalous Host',
    description: 'Authentication/verification keywords (login, verify, secure, otp) placed on anomalous or high-risk domain structures.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 20,
    evaluate: ({ urlStructure }) => {
      if (!urlStructure || !urlStructure.pathname) return { matched: false, evidence: [] };

      const path = urlStructure.pathname.toLowerCase();
      const authKeywords = ['/login', '/signin', '/verify', '/account-update', '/secure-login', '/auth/validate', '/update-password', '/session/reset'];
      const matchedKeywords = authKeywords.filter(kw => path.includes(kw));

      if (matchedKeywords.length === 0) return { matched: false, evidence: [] };

      // A credential path is a suspicious indicator when placed on anomalous hosts:
      // IP hosts, punycode, deceptive userinfo, high-risk TLDs, deep nesting, or known disposable phishing hosters
      const isAnomalousHost = urlStructure.isIp || 
        urlStructure.isPunycode || 
        urlStructure.hasNonAscii || 
        urlStructure.hasDeceptiveAt ||
        urlStructure.subdomainCount >= 3 ||
        HIGH_RISK_TLDS.has(urlStructure.tld) ||
        /(?:firebaseapp\.com|web\.app|pages\.dev|workers\.dev|glitch\.me|duckdns\.org|ngrok(?:-free)?\.app|000webhostapp\.com)$/i.test(urlStructure.hostname);

      if (isAnomalousHost) {
        return {
          matched: true,
          evidence: matchedKeywords.map(kw => `${kw} on anomalous host (${urlStructure.hostname})`),
        };
      }

      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_SUSPICIOUS_PORT',
    category: RULE_CATEGORIES.STRUCTURAL_ANOMALY,
    name: 'Non-Standard Service Port',
    description: 'Specifies an unusual network port (e.g., 8080, 8443, 8888, 4444) on a public web link.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 18,
    evaluate: ({ urlStructure }) => {
      if (!urlStructure || !urlStructure.port) return { matched: false, evidence: [] };

      const standardPorts = ['80', '443'];
      if (!standardPorts.includes(urlStructure.port) && !urlStructure.hostname.includes('localhost')) {
        return {
          matched: true,
          evidence: [`Port ${urlStructure.port}`],
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_SUSPICIOUS_FILE_DOWNLOAD',
    category: RULE_CATEGORIES.MALWARE_INDICATOR,
    name: 'Direct Executable or Script Download Extension',
    description: 'Points directly to an executable, script, or installer payload (.exe, .scr, .apk, .vbs, .bat).',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ urlStructure }) => {
      if (!urlStructure || !urlStructure.pathname) return { matched: false, evidence: [] };

      const path = urlStructure.pathname.toLowerCase();
      const matchedExts = SUSPICIOUS_EXTENSIONS.filter(ext => path.endsWith(ext) || path.includes(`${ext}?`));

      if (matchedExts.length > 0) {
        return {
          matched: true,
          evidence: matchedExts,
        };
      }
      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'URL_NESTED_REDIRECT_PARAM',
    category: RULE_CATEGORIES.REDIRECTION,
    name: 'Nested Open Redirect Parameter',
    description: 'Contains nested redirect parameters (e.g. ?url=http or ?next=https) used to bounce victims through open redirects.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 15,
    evaluate: ({ urlStructure }) => {
      if (!urlStructure || !urlStructure.search) return { matched: false, evidence: [] };

      const search = urlStructure.search.toLowerCase();
      const redirectPattern = /[?&](?:url|redirect|next|dest|target|return_to)=https?%3A%2F%2F|[?&](?:url|redirect|next|dest|target|return_to)=https?:\/\//i;
      const match = search.match(redirectPattern);

      if (match) {
        return {
          matched: true,
          evidence: [match[0]],
        };
      }
      return { matched: false, evidence: [] };
    },
  },
];
