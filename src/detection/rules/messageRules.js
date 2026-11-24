/**
 * Detection Rules for Suspicious Messages (SMS, WhatsApp, and Email)
 */

import { SEVERITY_LEVELS, RULE_CATEGORIES } from '../types.js';
import { extractMatches } from '../utils/textParser.js';
import { detectBrandImpersonationPattern, HIGH_RISK_TLDS } from '../utils/urlParser.js';

export const messageRules = [
  {
    id: 'MSG_URGENT_ACTION_DEADLINE',
    category: RULE_CATEGORIES.URGENCY,
    name: 'Artificial Urgency or Tight Deadline',
    description: 'Imposes an aggressive, artificial time limit to induce panic and bypass critical thinking.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 20,
    evaluate: ({ text }) => {
      const regex = /\b(?:urgent:|urgent\s+(?:notice|action|alert)|within\s+(?:12|24|48|2|1)\s*(?:hours?|hrs?)|immediately|action\s+required\s+immediately|final\s+(?:notice|warning|reminder)|before\s+midnight|valid\s+for\s+today\s+only)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_ACCOUNT_SUSPENSION_THREAT',
    category: RULE_CATEGORIES.THREAT,
    name: 'Account Suspension or Closure Threat',
    description: 'Threatens service termination, account freeze, or deactivation to provoke immediate compliance.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 25,
    evaluate: ({ text }) => {
      const regex = /\b(?:account\s+(?:will\s+be|has\s+been|is)\s+(?:permanently\s+)?(?:suspended|terminated|deactivated|locked|frozen|blocked)|prevent\s+account\s+(?:closure|suspension|deactivation)|avoid\s+suspension|access\s+(?:will\s+be|has\s+been)\s+(?:permanently\s+)?(?:suspended|restricted|blocked)|(?:account|access)\s+will\s+be\s+permanently\s+suspended)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_LEGAL_LAW_ENFORCEMENT_THREAT',
    category: RULE_CATEGORIES.THREAT,
    name: 'Legal or Law Enforcement Coercion',
    description: 'Impersonates legal authorities, police, or tax agencies threatening arrest or criminal prosecution.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ text }) => {
      const regex = /\b(?:arrest\s+warrant|law\s+enforcement|legal\s+action\s+will\s+be\s+taken|police\s+complaint|court\s+summons?|income\s+tax\s+department\s+(?:raid|penalty)|facing\s+prosecution)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_FINANCIAL_LURE_PRIZE',
    category: RULE_CATEGORIES.FINANCIAL_LURE,
    name: 'Unsolicited Financial Lure or Prize',
    description: 'Promises unexpected winnings, lottery prizes, inheritance, or crypto rewards to entice engagement.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 25,
    evaluate: ({ text }) => {
      const regex = /\b(?:you\s+have\s+won|lottery\s+winner|congratulations\s+you\s+won|claim\s+your\s+(?:prize|reward|cash|bonus|funds)|unclaimed\s+(?:funds|reward|lottery)|exclusive\s+crypto\s+airdrop|cash\s+prize\s+of\b)/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_CREDENTIAL_OTP_SOLICITATION',
    category: RULE_CATEGORIES.CREDENTIAL_HARVESTING,
    name: 'Sensitive Credential or OTP Request',
    description: 'Directly asks for one-time passwords (OTP), PINs, passwords, or CVV numbers, which legitimate services never do via message.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ text }) => {
      const regex = /\b(?:reply\s+with\s+(?:your\s+)?(?:otp|pin|password|cvv|code)|share\s+(?:your\s+)?(?:otp|one-time\s+password)|send\s+(?:us\s+)?(?:your\s+)?otp|verify\s+(?:your\s+)?otp\s+to\s+agent)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_UNOFFICIAL_MESSAGING_REDIRECT',
    category: RULE_CATEGORIES.COMMUNICATION_CHANNEL,
    name: 'Redirect to External Messaging Channel',
    description: 'Channels communication onto WhatsApp, Telegram, or Signal to evade enterprise monitoring and audit trails.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 20,
    evaluate: ({ text }) => {
      // Meaningful contextual redirect: directive to contact an officer/agent/support on WhatsApp/Telegram, or direct links
      const regex = /\b(?:(?:contact|reach\s+out(?:\s+to)?|chat(?:\s+with)?|message|connect(?:\s+with)?|send\s+(?:a\s+)?message\s+to)\s+(?:our|the|a|an)?\s*(?:verification|support|kyc|security|account|customer(?:\s+care)?|helpdesk|executive|fraud|compliance)?\s*(?:officer|agent|manager|team|desk|representative|executive|number|us)?\s*(?:on|via|through|at)\s*(?:whatsapp|telegram|signal)|join\s+(?:our\s+)?(?:telegram|whatsapp)\s+(?:group|channel)|(?:t\.me|wa\.me)\/[a-zA-Z0-9_+]+|api\.whatsapp\.com\/send\?|chat\s+on\s+whatsapp\s*(?::|\+)?\s*\+?\d{7,15}|whatsapp\s+(?:if\s+you\s+need\s+assistance|for\s+(?:verification|support|assistance|help|kyc)))\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_PAYMENT_APP_OR_CARD_DEMAND',
    category: RULE_CATEGORIES.PAYMENT_DEMAND,
    name: 'Irreversible Payment or Gift Card Demand',
    description: 'Demands payments via gift cards, cryptocurrency, or wire transfers to resolve an alleged problem.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 30,
    evaluate: ({ text }) => {
      const regex = /\b(?:pay\s+(?:via|with)\s+(?:gift\s+card|steam\s+card|apple\s+gift\s+card|bitcoin|crypto|wire\s+transfer|western\s+union)|purchase\s+(?:google\s+play|itunes)\s+cards?)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_DELIVERY_IMPOSTER',
    category: RULE_CATEGORIES.IMPERSONATION,
    name: 'Delivery Impersonation Pretext',
    description: 'Impersonates courier or postal services alleging address errors or unpaid customs fees to steal credentials.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 22,
    evaluate: ({ text }) => {
      const regex = /\b(?:package\s+(?:cannot\s+be\s+delivered|held\s+at\s+customs|pending\s+delivery)|incomplete\s+address\s+information|pay\s+(?:shipping|customs|redelivery)\s+fee|update\s+(?:your\s+)?address\s+to\s+receive\s+package)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_SUSPICIOUS_LINK_SHORTENER',
    category: RULE_CATEGORIES.REDIRECTION,
    name: 'Obfuscated Link Shortener in Message',
    description: 'Uses public link shorteners (bit.ly, tinyurl, t.co, is.gd) to conceal malicious target destinations.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 18,
    evaluate: ({ text }) => {
      const regex = /\b(?:https?:\/\/)?(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|tiny\.cc)\/[a-zA-Z0-9_\-]+\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'MSG_EMBEDDED_BRAND_SPOOF_URL',
    category: RULE_CATEGORIES.BRAND_SPOOFING,
    name: 'Brand Impersonation Pattern in Embedded Link',
    description: 'An embedded link mimics a recognized institution or service brand (e.g. in subdomains or host tokens) on an unrelated registered domain.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 30,
    evaluate: ({ embeddedUrlStructures }) => {
      if (!embeddedUrlStructures || embeddedUrlStructures.length === 0) {
        return { matched: false, evidence: [] };
      }
      const evidence = [];
      for (const { raw, structure } of embeddedUrlStructures) {
        const result = detectBrandImpersonationPattern(structure);
        if (result && result.isImpersonating) {
          evidence.push(raw);
        }
      }
      return {
        matched: evidence.length > 0,
        evidence: [...new Set(evidence)],
      };
    },
  },
  {
    id: 'MSG_EMBEDDED_SUSPICIOUS_URL',
    category: RULE_CATEGORIES.STRUCTURAL_DECEPTION,
    name: 'Suspicious Embedded Link Structure',
    description: 'An embedded link exhibits anomalous structural traits such as a raw IP address host, punycode/IDN homoglyph obfuscation, or a high-abuse disposable TLD.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 25,
    evaluate: ({ embeddedUrlStructures }) => {
      if (!embeddedUrlStructures || embeddedUrlStructures.length === 0) {
        return { matched: false, evidence: [] };
      }
      const evidence = [];
      for (const { raw, structure } of embeddedUrlStructures) {
        if (!structure) continue;
        const isIp = structure.isIp;
        const isPunycode = structure.isPunycode || structure.hasNonAscii;
        const hasDeceptiveAt = structure.hasDeceptiveAt;
        const hasHighRiskTld = structure.tld && HIGH_RISK_TLDS.has(structure.tld.toLowerCase());

        if (isIp || isPunycode || hasDeceptiveAt || hasHighRiskTld) {
          evidence.push(raw);
        }
      }
      return {
        matched: evidence.length > 0,
        evidence: [...new Set(evidence)],
      };
    },
  },
  {
    id: 'MSG_INSECURE_HTTP_VERIFICATION_LINK',
    category: RULE_CATEGORIES.STRUCTURAL_ANOMALY,
    name: 'Insecure (HTTP) Verification Link',
    description: 'The message provides an unencrypted HTTP link for account verification or KYC update, contrary to standard banking security practices.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 15,
    evaluate: ({ embeddedUrlStructures }) => {
      if (!embeddedUrlStructures || embeddedUrlStructures.length === 0) {
        return { matched: false, evidence: [] };
      }
      const evidence = [];
      for (const { raw, structure } of embeddedUrlStructures) {
        if (structure && structure.protocol === 'http:') {
          const fullPathAndHost = `${structure.hostname}${structure.pathname}`.toLowerCase();
          if (/(?:kyc|verif|login|signin|account|update|banking|secure)/i.test(fullPathAndHost)) {
            evidence.push(raw);
          }
        }
      }
      return {
        matched: evidence.length > 0,
        evidence: [...new Set(evidence)],
      };
    },
  },
  {
    id: 'MSG_GENERIC_SALUTATION_ANOMALY',
    category: RULE_CATEGORIES.EVASION,
    name: 'Generic Greeting in High-Stakes Notice',
    description: 'Uses generic salutations (e.g. "Dear Customer", "Dear Beneficiary") while demanding urgent account action or verification.',
    severity: SEVERITY_LEVELS.LOW,
    baseWeight: 10,
    evaluate: ({ text }) => {
      const greetingRegex = /\b(?:dear\s+(?:customer|user|client|beneficiary|account\s+holder|member))\b/gi;
      // High-stakes demand context: urgency, suspension, or credential verification
      const highStakesContextRegex = /\b(?:suspended|locked|blocked|frozen|verify|verification|update\s+kyc|action\s+required|unclaimed|lottery|arrest|penalty)\b/i;
      
      const greetingMatches = extractMatches(text, greetingRegex);
      if (greetingMatches.length > 0 && highStakesContextRegex.test(text)) {
        return {
          matched: true,
          evidence: greetingMatches,
        };
      }
      return { matched: false, evidence: [] };
    },
  },
];
