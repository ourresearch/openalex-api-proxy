/**
 * OpenAlex work matching with multi-strategy fallback.
 *
 * Strategies (in order):
 *   1. DOI lookup (most reliable — exact match)
 *   2. Title search via title.search filter + fuzzy similarity
 *   3. Full-text search (default.search) + fuzzy similarity
 *   4. Keyword search with year filter (if year available)
 *   5. Short title / last-resort keyword search
 *
 * The apiBase parameter controls which URL to call. When running
 * inside the proxy's service binding, set OPENALEX_API_BASE to the
 * upstream backend so sub-requests don't loop back through the proxy.
 */

// ─── Types ───────────────────────────────────────────────────

export interface CvPublication {
  title: string;
  doi?: string | null;
  year?: number | null;
  authors?: string | null;
}

export interface MatchedWork {
  cvPublication: CvPublication;
  oaWork: {
    id: string;
    display_name: string;
    publication_year: number;
    authorships: any[];
    primary_location: any;
  };
  alreadyLinked: boolean;
}

// ─── Public API ──────────────────────────────────────────────

/**
 * Search OpenAlex for a single publication using fallback strategies.
 * Returns the matched work or null.
 */
export async function searchOpenAlex(
  publication: CvPublication,
  apiBase: string = 'https://api.openalex.org',
  apiKey?: string
): Promise<any | null> {
  // The DOI and year come from the model, which read them from the uploaded CV: untrusted, and spliced into URLs
  // fetched with our API key. Only a DOI-shaped DOI (each segment encoded) and a 4-digit year are used (oxjob #1762).
  const year = cleanYear(publication.year);

  // Strategy 1: DOI lookup (most reliable — exact match, no similarity needed)
  if (publication.doi) {
    const cleanDoi = cleanDOI(publication.doi);
    if (cleanDoi) {
      const parsed = await fetchJson(
        `${apiBase}/works/doi:${doiPath(cleanDoi)}`
      );
      if (parsed?.id) {
        console.log(`  DOI match: ${cleanDoi} → "${parsed.display_name?.substring(0, 60)}"`);
        return parsed;
      }
    }
  }

  if (!publication.title || publication.title.length < 10) return null;

  // Sanitize title for use in API filters — remove characters that break filter syntax
  const safeTitle = publication.title
    .substring(0, 200)
    .replace(/[:"'()[\]{}|\\]/g, ' ')  // strip chars that break filter syntax
    .replace(/\s+/g, ' ')
    .trim();
  const titleEncoded = encodeURIComponent(safeTitle);

  // Strategy 2: title.search filter — best for exact/near-exact titles
  console.log(`  Searching for: "${safeTitle.substring(0, 80)}"`);
  const result1 = await fetchJson(
    `${apiBase}/works?filter=title.search:${titleEncoded}&per_page=10`
  );
  const match1 = bestMatch(result1?.results, publication, 0.35);
  if (match1) return match1;

  // Strategy 3: Full-text search — catches partial title matches and subtitles
  await delay(200);
  const result2 = await fetchJson(
    `${apiBase}/works?search=${titleEncoded}&per_page=10`
  );
  const match2 = bestMatch(result2?.results, publication, 0.35);
  if (match2) return match2;

  // Strategy 4: Keywords + year filter (tighter constraint, different result set)
  const keyWords = extractKeyWords(publication.title);
  if (keyWords.split(' ').length >= 3) {
    await delay(200);
    const yearFilter = year !== null ? `&filter=publication_year:${year}` : '';
    const result3 = await fetchJson(
      `${apiBase}/works?search=${encodeURIComponent(keyWords)}${yearFilter}&per_page=10`
    );
    const match3 = bestMatch(result3?.results, publication, 0.3);
    if (match3) return match3;

    // Strategy 4b: Keywords without year (in case year is wrong or missing)
    if (yearFilter) {
      await delay(200);
      const result3b = await fetchJson(
        `${apiBase}/works?search=${encodeURIComponent(keyWords)}&per_page=10`
      );
      const match3b = bestMatch(result3b?.results, publication, 0.35);
      if (match3b) return match3b;
    }
  }

  // Strategy 5: First few significant words only — helps when Claude truncated or mangled the title
  const firstWords = keyWords.split(' ').slice(0, 4).join(' ');
  if (firstWords.length > 10 && firstWords !== keyWords) {
    await delay(200);
    const yearFilter = year !== null ? `&filter=publication_year:${year}` : '';
    const result5 = await fetchJson(
      `${apiBase}/works?search=${encodeURIComponent(firstWords)}${yearFilter}&per_page=10`
    );
    const match5 = bestMatch(result5?.results, publication, 0.4);
    if (match5) return match5;
  }

  console.log(`  No match found for: "${publication.title.substring(0, 80)}"`);
  return null;
}

// ─── DOI Cleaning ───────────────────────────────────────────

// 10.<registrant>/<suffix>: a numeric registrant (optionally dotted) and a suffix with no whitespace, no control
// characters, and no `?` or `#` (they would end the URL path).
const DOI_SHAPE = /^10\.\d{4,9}(?:\.\d+)*\/[^\s?#\u0000-\u001f\u007f-\u009f]+$/;

export function cleanDOI(doi: unknown): string | null {
  if (typeof doi !== 'string' || !doi) return null;
  let d = doi.trim();
  // Strip URL prefixes
  d = d.replace(/^https?:\/\/doi\.org\//i, '');
  d = d.replace(/^https?:\/\/dx\.doi\.org\//i, '');
  d = d.replace(/^doi:\s*/i, '');
  if (!DOI_SHAPE.test(d)) return null;
  // A "." or ".." segment would walk the request path out of /works/doi: (to /query/text, /text, ...).
  if (d.split('/').some((seg) => seg === '.' || seg === '..')) return null;
  return d;
}

/** A cleaned DOI as URL path text: each segment percent-encoded, so nothing in it can leave the path component. */
export function doiPath(cleanDoi: string): string {
  return cleanDoi.split('/').map(encodeURIComponent).join('/');
}

// ─── Year ────────────────────────────────────────────────────

export const MIN_YEAR = 1000;
export const MAX_YEAR = 2100;

/** A publication year: a 4-digit integer (or a string of exactly 4 digits) in [MIN_YEAR, MAX_YEAR], else null. */
export function cleanYear(year: unknown): number | null {
  const n = typeof year === 'number' ? year
    : typeof year === 'string' && /^\d{4}$/.test(year.trim()) ? Number(year.trim())
    : NaN;
  return Number.isInteger(n) && n >= MIN_YEAR && n <= MAX_YEAR ? n : null;
}

// ─── Title similarity ────────────────────────────────────────

const STOP_WORDS = new Set([
  'the', 'a', 'an', 'of', 'in', 'on', 'for', 'and', 'or', 'to',
  'is', 'are', 'was', 'were', 'by', 'from', 'with', 'at', 'its',
  'vs', 'between', 'that', 'this', 'not', 'do', 'does', 'did',
  'has', 'have', 'had', 'be', 'been', 'being', 'as', 'but',
  'if', 'about', 'into', 'through', 'during', 'before', 'after',
  'above', 'below', 'up', 'down', 'out', 'off', 'over', 'under',
  'again', 'further', 'then', 'once', 'here', 'there', 'when',
  'where', 'why', 'how', 'all', 'each', 'every', 'both', 'few',
  'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'can',
  'will', 'just', 'should', 'now', 'also', 'than', 'too', 'very',
]);

function tokenize(title: string): Set<string> {
  if (!title) return new Set();
  return new Set(
    title
      .toLowerCase()
      .replace(/<[^>]*>/g, '')        // strip HTML
      .replace(/[^\w\s]/g, ' ')       // remove punctuation
      .replace(/\s+/g, ' ')
      .trim()
      .split(' ')
      .filter((w) => w.length > 2 && !STOP_WORDS.has(w))
  );
}

/**
 * Fuzzy title similarity using word overlap (F1 score).
 * Also considers stem/prefix matching for partial word matches.
 */
export function titleSimilarity(title1: string, title2: string): number {
  const words1 = tokenize(title1);
  const words2 = tokenize(title2);

  if (words1.size === 0 || words2.size === 0) return 0;

  // Exact word overlap
  let exactOverlap = 0;
  for (const w of words1) {
    if (words2.has(w)) exactOverlap++;
  }

  // Fuzzy word matching: check if any word in set2 starts with or contains a word from set1
  let fuzzyOverlap = 0;
  for (const w1 of words1) {
    if (words2.has(w1)) continue; // already counted
    for (const w2 of words2) {
      if (w1.length >= 4 && w2.length >= 4) {
        if (w2.startsWith(w1) || w1.startsWith(w2)) {
          fuzzyOverlap += 0.8;
          break;
        }
      }
    }
  }

  const totalOverlap = exactOverlap + fuzzyOverlap;
  const recall = totalOverlap / words1.size;
  const precision = totalOverlap / words2.size;

  if (recall + precision === 0) return 0;
  return (2 * recall * precision) / (recall + precision);
}

/**
 * Pick the best matching result, considering title similarity + year bonus.
 */
export function bestMatch(
  results: any[] | undefined,
  publication: CvPublication,
  threshold: number = 0.35
): any | null {
  if (!results || results.length === 0) return null;

  let best: any = null;
  let bestScore = 0;

  for (const r of results) {
    let score = titleSimilarity(publication.title, r.display_name);

    // Year match bonus: boost score if years align
    if (publication.year && r.publication_year) {
      if (publication.year === r.publication_year) {
        score += 0.05;
      } else if (Math.abs(publication.year - r.publication_year) <= 1) {
        score += 0.02; // off by one year (common for preprint → published)
      }
    }

    if (score > bestScore) {
      bestScore = score;
      best = r;
    }
  }

  if (bestScore >= threshold) {
    console.log(
      `  Title match (${(bestScore * 100).toFixed(0)}%): "${publication.title.substring(0, 60)}" → "${best.display_name?.substring(0, 60)}"`
    );
    return best;
  }

  if (best) {
    console.log(
      `  Rejected (${(bestScore * 100).toFixed(0)}%): "${publication.title.substring(0, 50)}" ≠ "${best.display_name?.substring(0, 50)}"`
    );
  }
  return null;
}

// ─── Title cleaning ──────────────────────────────────────────

function cleanTitle(title: string): string {
  if (!title) return '';
  return title
    .replace(/<[^>]*>/g, '')             // Remove HTML tags
    .replace(/\s*\([^)]*\)\s*/g, ' ')    // Remove parenthetical text
    .replace(/[^\w\s]/g, ' ')            // Remove special chars
    .replace(/\s+/g, ' ')               // Collapse whitespace
    .trim();
}

export function extractKeyWords(title: string): string {
  return cleanTitle(title)
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 2 && !STOP_WORDS.has(w))
    .slice(0, 8)
    .join(' ');
}

// ─── Helpers ─────────────────────────────────────────────────

// Module-level API key — set once per request via setApiKey()
let _apiKey: string | undefined;
export function setApiKey(key?: string) { _apiKey = key; }

async function fetchJson(url: string): Promise<any | null> {
  try {
    // Add include_xpac and mailto to every request
    const separator = url.includes('?') ? '&' : '?';
    const fullUrl = `${url}${separator}include_xpac=true&mailto=team@ourresearch.org`;
    const headers: Record<string, string> = {
      'User-Agent': 'OpenAlex-CV-Parser/1.0 (mailto:team@ourresearch.org)',
    };
    if (_apiKey) {
      headers['Authorization'] = `Bearer ${_apiKey}`;
    }
    const resp = await fetch(fullUrl, { headers });
    if (!resp.ok) {
      console.log(`  API error ${resp.status} for: ${fullUrl.substring(0, 150)}`);
      return null;
    }
    return await resp.json();
  } catch (err: any) {
    console.error(`  Fetch error: ${err.message}`);
    return null;
  }
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
