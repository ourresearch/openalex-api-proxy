/**
 * Is a CV publication one of these OpenAlex works? One Jev Choice (TypeSafe's decision model) over up to five
 * candidates plus "none" and "unknown" (oxjob #1330).
 *
 * The request shape and the 0.7 accept line come from oxjob #1318, which measured them on 473 Opus-judged references
 * and CV lines: at p >= 0.7 Jev was 97.6% precise with 93.9% recall, against 83.4% / 94.6% for the word-overlap
 * `bestMatch`, which also matched something for 17.5% of the items that had no true match.
 */

import type { CvPublication } from './openalexMatcher';

export const JEV_URL = 'https://api.typesafe.ai/v1/systemone';
const JEV_MODEL = 'jev-1.13.0'; // pinned: the version #1318 measured
/** Accept the chosen candidate at this probability or above; below it, the strategy found nothing. */
export const ACCEPT_P = 0.7;
export const MAX_CANDIDATES = 5;
const MAX_AUTHORS = 6;
const TIMEOUT_MS = 2500;
/** After any failed call, skip Jev for this long, so an outage costs one timeout, not one per search strategy. */
const PAUSE_MS = 60_000;
let pausedUntil = 0;
export function resetJevPause() { pausedUntil = 0; }

const INSTRUCTIONS =
  '`citation` is a reference-list entry or CV line written by a person. `candidates` are bibliographic records from a ' +
  'scholarly index. Which candidate is the work the citation refers to? A preprint, accepted manuscript or reprint of the ' +
  'same work counts as the same work. A different work with a similar title, or the same title by different authors or in a ' +
  'different venue/year, does not. Author names may be formatted differently (order, initials, diacritics), venues abbreviated, years off by one.';

interface Card {
  key: string;
  title: string;
  authors: string[];
  n_authors: number;
  year: number | null;
  venue: string | null;
  type: string | null;
}

/** The fields Jev sees for one OpenAlex work. */
export function card(work: any, key: string): Card {
  const authorships: any[] = Array.isArray(work?.authorships) ? work.authorships : [];
  return {
    key,
    title: work?.display_name ?? work?.title ?? '',
    authors: authorships
      .slice(0, MAX_AUTHORS)
      .map((a) => a?.author?.display_name ?? a?.raw_author_name ?? '')
      .filter(Boolean),
    n_authors: authorships.length,
    year: work?.publication_year ?? null,
    venue: work?.primary_location?.source?.display_name ?? null,
    type: work?.type ?? null,
  };
}

/** The publication as one CV line: "Authors (Year). Title." with whatever parts the CV gave. */
export function citationLine(pub: CvPublication, year: number | null): string {
  const authors = typeof pub.authors === 'string' ? pub.authors.trim() : '';
  const parts = [authors, year !== null ? `(${year})` : '', `${(pub.title || '').trim()}.`].filter(Boolean);
  return parts.join(' ').replace(/\.\./g, '.');
}

export function buildRequest(citation: string, citationYear: number | null, works: any[]) {
  const candidates = works.map((w, i) => card(w, `c${i + 1}`));
  const criteria: Record<string, string> = {};
  for (const c of candidates) criteria[c.key] = `candidate ${c.key}`;
  criteria.none = 'none of the candidates is the cited work';
  criteria.unknown = 'cannot tell from the information given';
  return {
    model: JEV_MODEL,
    state: { citation, citation_year: citationYear, candidates },
    questions: { cited_work: { type: 'choice', instructions: INSTRUCTIONS, criteria } },
  };
}

export interface JevPick {
  /** The chosen work when Jev picked a candidate at p >= ACCEPT_P, else null. */
  work: any | null;
  /** Jev's probability for its top answer (a candidate, "none" or "unknown"). */
  p: number;
  /** Jev's top answer: "c1".."c5", "none" or "unknown". */
  choice: string;
}

/**
 * Ask Jev which of `works` (at most MAX_CANDIDATES, in the order given) the citation names. Returns null when Jev
 * could not answer (no key, paused after a failure, timeout, HTTP error, unreadable body), so the caller can fall back
 * to the word-overlap rule.
 */
export async function jevPick(
  citation: string,
  citationYear: number | null,
  works: any[],
  apiKey: string | undefined,
  timeoutMs: number = TIMEOUT_MS
): Promise<JevPick | null> {
  if (!apiKey || works.length === 0 || Date.now() < pausedUntil) return null;
  const pick = await ask(citation, citationYear, works.slice(0, MAX_CANDIDATES), apiKey, timeoutMs);
  if (!pick) {
    pausedUntil = Date.now() + PAUSE_MS;
    console.log(`  Jev paused for ${PAUSE_MS / 1000} s; word-overlap matching meanwhile`);
  }
  return pick;
}

async function ask(citation: string, citationYear: number | null, shown: any[], apiKey: string, timeoutMs: number): Promise<JevPick | null> {
  const t0 = Date.now();
  try {
    const resp = await fetch(JEV_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(buildRequest(citation, citationYear, shown)),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!resp.ok) {
      console.log(`  Jev error ${resp.status} (${resp.headers.get('x-typesafe-request-id') ?? 'no request id'})`);
      return null;
    }
    const data: any = await resp.json();
    const probs: Record<string, number> | undefined = data?.answers?.cited_work?.probabilities;
    if (!probs || typeof probs !== 'object') {
      console.log('  Jev error: no probabilities in the answer');
      return null;
    }
    let choice = 'unknown';
    let p = -1;
    for (const [k, v] of Object.entries(probs)) {
      if (typeof v === 'number' && v > p) { choice = k; p = v; }
    }
    const m = /^c(\d+)$/.exec(choice);
    const idx = m ? Number(m[1]) - 1 : -1;
    const work = idx >= 0 && idx < shown.length && p >= ACCEPT_P ? shown[idx] : null;
    console.log(`  Jev ${choice} p=${p.toFixed(2)} over ${shown.length} (${Date.now() - t0} ms)`);
    return { work, p, choice };
  } catch (err: any) {
    console.log(`  Jev error: ${err?.name === 'TimeoutError' ? `timeout after ${timeoutMs} ms` : err?.message}`);
    return null;
  }
}
