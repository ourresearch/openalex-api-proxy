/**
 * OpenAlex work matching with multi-strategy fallback.
 *
 * Strategies (in order):
 *   1. DOI lookup (most reliable — exact match)
 *   2. Title search via title.search filter + fuzzy similarity
 *   3. Full-text search (default.search) + fuzzy similarity
 *   4. Keyword search with year filter (if year available)
 *   5. Short title / last-resort keyword search
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
  // Strategy 1: DOI lookup (most reliable — exact match, no similarity needed)
  if (publication.doi) {
    const cleanDoi = cleanDOI(publication.doi);
    if (cleanDoi) {
      const parsed = await fetchJson(
        `https://api.openalex.org/works/doi:${cleanDoi}`
      );
      if (parsed?.id) {
        console.log(`  DOI match: ${cleanDoi} → "${parsed.display_name?.substring(0, 60)}"`);
        return parsed;
      }
    }
  }

  if (!publication.title || publication.title.length < 10) return null;

  // Strategy 2: title.search filter — best for exact/near-exact titles
  const titleEncoded = encodeURIComponent(publication.title.substring(0, 200));
  const result1 = await fetchJson(
    `https://api.openalex.org/works?filter=title.search:${titleEncoded}&per_page=10`
  );
  const match1 = bestMatch(result1?.results, publication, 0.35);
  if (match1) return match1;

  // Strategy 3: Full-text search — catches partial title matches
  await delay(200);
  const result2 = await fetchJson(
    `https://api.openalex.org/works?search=${titleEncoded}&per_page=10`
  );
  const match2 = bestMatch(result2?.results, publication, 0.35);
  if (match2) return match2;

  // Strategy 4: Keywords + year filter (tighter constraint, but different results)
  const keyWords = extractKeyWords(publication.title);
  if (keyWords.split(' ').length >= 3) {
    await delay(200);
    const yearFilter = publication.year
      ? `&filter=publication_year:${publication.year}`
      : '';
    const result3 = await fetchJson(
      `https://api.openalex.org/works?search=${encodeURIComponent(keyWords)}${yearFilter}&per_page=10`
    );
    const match3 = bestMatch(result3?.results, publication, 0.3);
    if (match3) return match3;
  }

  // Strategy 5: Cleaned/simplified title — strip parentheticals, special chars
  const cleaned = cleanTitle(publication.title);
  if (cleaned !== publication.title && cleaned.length > 15) {
    await delay(200);
    const result4 = await fetchJson(
      `https://api.openalex.org/works?search=${encodeURIComponent(cleaned)}&per_page=10`
    );
    const match4 = bestMatch(result4?.results, publication, 0.3);
    if (match4) return match4;
  }

  console.log(`  No match found for: "${publication.title.substring(0, 80)}"`);
  return null;
}

// ─── DOI Cleaning ───────────────────────────────────────────

function cleanDOI(doi: string): string | null {
  if (!doi) return null;
  let d = doi.trim();
  // Strip URL prefixes
  d = d.replace(/^https?:\/\/doi\.org\//i, '');
  d = d.replace(/^https?:\/\/dx\.doi\.org\//i, '');
  d = d.replace(/^doi:\s*/i, '');
  // Basic validation
  if (d.startsWith('10.') && d.includes('/')) return d;
  return null;
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
 * Also considers character-level trigram overlap for partial word matches.
 */
function titleSimilarity(title1: string, title2: string): number {
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
function bestMatch(
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
