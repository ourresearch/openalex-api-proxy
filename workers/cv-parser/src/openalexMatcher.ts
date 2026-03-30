/**
 * OpenAlex work matching with multi-strategy fallback.
 *
 * Strategies (in order):
 *   1. DOI lookup (most reliable)
 *   2. Title search with similarity validation (threshold 0.4)
 *   3. Cleaned title search (strip HTML/parentheticals)
 *   4. Keyword search with higher threshold (0.5)
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
  publication: CvPublication
): Promise<any | null> {
  // Strategy 1: DOI lookup (most reliable — no similarity check needed)
  if (publication.doi) {
    const parsed = await fetchJson(
      `https://api.openalex.org/works/doi:${publication.doi}`
    );
    if (parsed?.id) return parsed;
  }

  if (!publication.title) return null;

  // Strategy 2: Exact title.search filter — validate with similarity
  const titleEncoded = encodeURIComponent(publication.title);
  const result1 = await fetchJson(
    `https://api.openalex.org/works?filter=title.search:${titleEncoded}&per_page=5`
  );
  const match1 = bestMatch(result1?.results, publication.title, 0.4);
  if (match1) return match1;

  // Strategy 3: Cleaned title search
  const cleaned = cleanTitle(publication.title);
  if (cleaned !== publication.title && cleaned.length > 10) {
    await delay(200);
    const result2 = await fetchJson(
      `https://api.openalex.org/works?filter=title.search:${encodeURIComponent(cleaned)}&per_page=5`
    );
    const match2 = bestMatch(result2?.results, publication.title, 0.4);
    if (match2) return match2;
  }

  // Strategy 4: Key words search — use higher threshold since this is looser
  const keyWords = extractKeyWords(publication.title);
  if (keyWords.split(' ').length >= 3) {
    await delay(200);
    const result3 = await fetchJson(
      `https://api.openalex.org/works?search=${encodeURIComponent(keyWords)}&per_page=5`
    );
    const match3 = bestMatch(result3?.results, publication.title, 0.5);
    if (match3) return match3;
  }

  return null;
}

// ─── Title similarity ────────────────────────────────────────

const STOP_WORDS = new Set([
  'the', 'a', 'an', 'of', 'in', 'on', 'for', 'and', 'or', 'to',
  'is', 'are', 'was', 'were', 'by', 'from', 'with', 'at', 'its',
  'vs', 'between', 'that', 'this', 'not',
]);

function normalizeForComparison(title: string): string {
  if (!title) return '';
  return title
    .toLowerCase()
    .replace(/<[^>]*>/g, '')
    .replace(/[^\w\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Calculate word-overlap similarity between two titles (F1-like score).
 */
function titleSimilarity(title1: string, title2: string): number {
  const words1 = new Set(
    normalizeForComparison(title1)
      .split(' ')
      .filter((w) => w.length > 2 && !STOP_WORDS.has(w))
  );
  const words2 = new Set(
    normalizeForComparison(title2)
      .split(' ')
      .filter((w) => w.length > 2 && !STOP_WORDS.has(w))
  );

  if (words1.size === 0 || words2.size === 0) return 0;

  let overlap = 0;
  for (const w of words1) {
    if (words2.has(w)) overlap++;
  }

  const recall = overlap / words1.size;
  const precision = overlap / words2.size;

  if (recall + precision === 0) return 0;
  return (2 * recall * precision) / (recall + precision);
}

/**
 * Pick the best matching result from a list, above a similarity threshold.
 */
function bestMatch(
  results: any[] | undefined,
  cvTitle: string,
  threshold: number = 0.4
): any | null {
  if (!results || results.length === 0) return null;

  let best: any = null;
  let bestScore = 0;

  for (const r of results) {
    const score = titleSimilarity(cvTitle, r.display_name);
    if (score > bestScore) {
      bestScore = score;
      best = r;
    }
  }

  if (bestScore >= threshold) {
    console.log(
      `  Title match (${(bestScore * 100).toFixed(0)}%): "${cvTitle.substring(0, 60)}..." → "${best.display_name?.substring(0, 60)}..."`
    );
    return best;
  }

  if (best) {
    console.log(
      `  Rejected (${(bestScore * 100).toFixed(0)}%): "${cvTitle.substring(0, 50)}..." ≠ "${best.display_name?.substring(0, 50)}..."`
    );
  }
  return null;
}

// ─── Title cleaning ──────────────────────────────────────────

function cleanTitle(title: string): string {
  if (!title) return '';
  return title
    .replace(/<[^>]*>/g, '')             // Remove HTML tags
    .replace(/\s*\([^)]*\)\s*/g, ' ')    // Remove parenthetical names
    .replace(/[^\w\s]/g, ' ')            // Remove special chars
    .replace(/\s+/g, ' ')               // Collapse whitespace
    .trim();
}

function extractKeyWords(title: string): string {
  return cleanTitle(title)
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 2 && !STOP_WORDS.has(w))
    .slice(0, 8)
    .join(' ');
}

// ─── Helpers ─────────────────────────────────────────────────

async function fetchJson(url: string): Promise<any | null> {
  try {
    const resp = await fetch(url, {
      headers: { 'User-Agent': 'OpenAlex-CV-Parser/1.0 (mailto:team@ourresearch.org)' },
    });
    if (!resp.ok) return null;
    return await resp.json();
  } catch {
    return null;
  }
}

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
