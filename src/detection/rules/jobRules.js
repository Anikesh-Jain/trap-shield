/**
 * Detection Rules for Fraudulent Job and Internship Offers
 */

import { SEVERITY_LEVELS, RULE_CATEGORIES } from '../types.js';
import { extractMatches } from '../utils/textParser.js';

export const jobRules = [
  {
    id: 'JOB_UPFRONT_FEE_OR_SECURITY_DEPOSIT',
    category: RULE_CATEGORIES.PAYMENT_DEMAND,
    name: 'Upfront Registration or Equipment Fee Demanded',
    description: 'Demands upfront payment for registration, training materials, background verification, or refundable equipment security deposit.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 40,
    evaluate: ({ text }) => {
      const regex = /\b(?:(?:pay|deposit|transfer|remit)\s+(?:a\s+)?(?:refundable\s+)?(?:security\s+deposit|registration\s+fee|training\s+fee|processing\s+charge|laptop\s+(?:deposit|fee)|equipment\s+insurance)|refundable\s+security\s+deposit\s+of\b)/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_UNREALISTIC_COMPENSATION',
    category: RULE_CATEGORIES.COMPENSATION_ANOMALY,
    name: 'Exorbitant Pay for Low-Effort or Entry-Level Work',
    description: 'Promises disproportionately large compensation for trivial, unskilled, or part-time tasks (e.g. $500/day for 1 hour).',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 25,
    evaluate: ({ text }) => {
      const regex = /\b(?:earn\s+(?:\$|₹|£|€)?\s*(?:[1-9]\d{2,4})\s*(?:per|\/)\s*(?:day|hour|daily|hr)\s*(?:for\s+[1-3]\s*(?:hours?|hrs?))?|daily\s+(?:payout|income)\s+of\s+(?:\$|₹|£|€)?\s*\d{3,5}|(?:make|earn)\s+\$(?:3|4|5|6|7|8|9|10),\d{3}\s*(?:weekly|a\s+week)|earn\s+₹(?:20|25|30|40|50),\d{3}\s*(?:daily|per\s+day))\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_NO_INTERVIEW_IMMEDIATE_OFFER',
    category: RULE_CATEGORIES.HIRING_PROCESS_ANOMALY,
    name: 'Guaranteed Hiring Without Interview or Screening',
    description: 'Issues an unconditional employment offer or selection notice without formal technical or behavioral evaluation.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 25,
    evaluate: ({ text }) => {
      const regex = /\b(?:selected\s+without\s+(?:an?\s+)?interview|no\s+interview\s+required|immediate\s+selection\s+confirmed|direct\s+hiring\s+without\s+(?:test|screening)|congratulations\s+you\s+are\s+hired\s+for)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_TASK_RATING_LIKE_SCAM',
    category: RULE_CATEGORIES.SCAM_MODEL,
    name: 'Task-Based Like/Rating/Crypto Model',
    description: 'Operates on classic task fraud mechanics: liking videos, reviewing hotels/apps, or performing crypto deposits for commissions.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ text }) => {
      const regex = /\b(?:like\s+(?:and\s+subscribe\s+to\s+)?youtube\s+videos?|hotel\s+rating\s+(?:task|job)|google\s+maps?\s+review\s+task|app\s+(?:store\s+)?rating\s+task|crypto\s+arbitrage\s+(?:task|commission)|complete\s+daily\s+tasks?\s+to\s+earn\s+commission)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_FREE_EMAIL_RECRUITER_SPOOF',
    category: RULE_CATEGORIES.IMPERSONATION,
    name: 'Corporate Brand Impersonated via Free Email Domain',
    description: 'Claims to represent a recognized global brand while recruiting via a free public email provider (gmail.com, yahoo.com, etc.).',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 30,
    evaluate: ({ text }) => {
      const majorBrands = ['google', 'microsoft', 'amazon', 'apple', 'meta', 'netflix', 'tesla', 'deloitte', 'accenture', 'infosys', 'tcs', 'wipro'];
      const freeProviders = ['gmail\\.com', 'yahoo\\.com', 'hotmail\\.com', 'outlook\\.com', 'mail\\.com', 'aol\\.com'];
      
      const emailRegex = new RegExp(`\\b([a-zA-Z0-9._%+-]+@(?:${freeProviders.join('|')}))\\b`, 'gi');
      const emailsFound = extractMatches(text, emailRegex);
      
      if (emailsFound.length === 0) return { matched: false, evidence: [] };

      const lowerText = text.toLowerCase();
      const claimedBrand = majorBrands.find(brand => lowerText.includes(brand));

      if (claimedBrand) {
        return {
          matched: true,
          evidence: emailsFound.map(e => `${claimedBrand} recruitment via ${e}`),
        };
      }

      return { matched: false, evidence: [] };
    },
  },
  {
    id: 'JOB_ENCRYPTED_MESSAGING_INTERVIEW',
    category: RULE_CATEGORIES.COMMUNICATION_CHANNEL,
    name: 'Recruitment Diverted to Telegram or WhatsApp',
    description: 'Directs applicants to communicate or interview solely through private messaging channels rather than formal company tools.',
    severity: SEVERITY_LEVELS.HIGH,
    baseWeight: 20,
    evaluate: ({ text }) => {
      const regex = /\b(?:interview\s+(?:will\s+be\s+conducted\s+)?(?:via|on|through)\s+(?:telegram|whatsapp)|contact\s+(?:our\s+)?hr\s+manager\s+on\s+(?:telegram|whatsapp)|send\s+resume\s+on\s+whatsapp\s*:\s*\+?\d+|connect\s+on\s+telegram\s+@\w+)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_SENSITIVE_FINANCIAL_INFO_REQUEST',
    category: RULE_CATEGORIES.CREDENTIAL_HARVESTING,
    name: 'Premature Financial or Banking Credentials Request',
    description: 'Requests sensitive bank account details, credit card numbers, or online banking passwords prior to employment verification.',
    severity: SEVERITY_LEVELS.CRITICAL,
    baseWeight: 35,
    evaluate: ({ text }) => {
      const regex = /\b(?:provide\s+(?:your\s+)?(?:bank\s+account\s+login|credit\s+card\s+number|net\s+banking\s+password|cvv\s+and\s+expiry)|share\s+otp\s+to\s+process\s+salary\s+account)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_URGENCY_LIMITED_SLOTS',
    category: RULE_CATEGORIES.URGENCY,
    name: 'Artificial Hiring Urgency or Scarcity',
    description: 'Pressures candidates to accept quickly under the threat of losing limited applicant slots or immediate expiry.',
    severity: SEVERITY_LEVELS.MEDIUM,
    baseWeight: 15,
    evaluate: ({ text }) => {
      const regex = /\b(?:offer\s+expires\s+in\s+(?:24|12|48)\s*hours?|only\s+[1-5]\s+(?:slots?|vacancies|positions)\s+(?:left|remaining)|accept\s+immediately\s+or\s+offer\s+will\s+be\s+cancelled)\b/gi;
      const matches = extractMatches(text, regex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
  {
    id: 'JOB_VAGUE_JOB_DESCRIPTION',
    category: RULE_CATEGORIES.JOB_SPEC_ANOMALY,
    name: 'Vague Generic Title with Exaggerated Freedom',
    description: 'Uses generic titles ("Online Assistant", "Data Typing", "Copy Paste Expert") with vague requirements and work-from-home promises.',
    severity: SEVERITY_LEVELS.LOW,
    baseWeight: 10,
    evaluate: ({ text }) => {
      const titleRegex = /\b(?:simple\s+(?:copy\s+paste|data\s+entry|sms\s+sending)\s+work|online\s+ad\s+posting\s+job|work\s+from\s+home\s+typing\s+job)\b/gi;
      const matches = extractMatches(text, titleRegex);
      return {
        matched: matches.length > 0,
        evidence: matches,
      };
    },
  },
];

