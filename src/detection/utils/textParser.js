/**
 * Text parsing utilities for TRAPSHIELD detection engine
 */

/**
 * Normalizes input text for case-insensitive matching while preserving original for evidence extraction
 * @param {string} text 
 * @returns {string}
 */
export function normalizeText(text) {
  if (typeof text !== 'string') return '';
  return text.trim();
}

/**
 * Extracts exact matched text or patterns from target string
 * @param {string} text 
 * @param {RegExp} regex 
 * @returns {string[]} unique matches
 */
export function extractMatches(text, regex) {
  if (!text || !regex) return [];
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const globalRegex = new RegExp(regex.source, flags);
  const matches = [];
  let match;
  while ((match = globalRegex.exec(text)) !== null) {
    matches.push(match[0].trim());
  }
  return [...new Set(matches)];
}

/**
 * Checks if text contains any of the specified keywords/phrases
 * @param {string} text 
 * @param {string[]} phrases 
 * @returns {{ matched: boolean, evidence: string[] }}
 */
export function findPhrases(text, phrases) {
  if (!text || !Array.isArray(phrases)) return { matched: false, evidence: [] };
  const lowerText = text.toLowerCase();
  const evidence = [];

  for (const phrase of phrases) {
    const lowerPhrase = phrase.toLowerCase();
    const idx = lowerText.indexOf(lowerPhrase);
    if (idx !== -1) {
      // Extract original casing from input
      evidence.push(text.slice(idx, idx + phrase.length));
    }
  }

  return {
    matched: evidence.length > 0,
    evidence: [...new Set(evidence)],
  };
}

/**
 * Extracts embedded URLs and web domain addresses from message text offline.
 * NEVER makes network requests or DNS resolutions.
 * @param {string} text 
 * @returns {string[]} Clean unique URLs found in text
 */
export function extractUrlsFromText(text) {
  if (typeof text !== 'string' || !text.trim()) return [];

  // Match URLs starting with http://, https://, or common web domain patterns
  const urlRegex = /\b(?:https?:\/\/)[^\s<>"{}|\\^`]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|in|xyz|top|biz|info|me|app|dev|sbi|bank)(?:\/[^\s<>"{}|\\^`]*)?/gi;
  const matches = [];
  let match;

  while ((match = urlRegex.exec(text)) !== null) {
    let raw = match[0].trim();
    // Strip trailing punctuation often appended in prose (e.g. "visit http://example.com.")
    raw = raw.replace(/[.,;:!?)]+$/, '');
    if (raw) matches.push(raw);
  }

  return [...new Set(matches)];
}
