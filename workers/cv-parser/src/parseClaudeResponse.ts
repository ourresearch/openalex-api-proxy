/**
 * Pure parsing of the Claude model's response text into CvPublication[].
 * Kept free of I/O so it can be unit-tested directly.
 */

import { cleanYear, type CvPublication } from './openalexMatcher';

/**
 * Parse the model's response text (a JSON array, possibly wrapped in
 * markdown code fences) into a list of publications.
 * Throws if the content is not valid JSON or not an array.
 *
 * The model read an uploaded CV, so its JSON is untrusted: each field is checked
 * for its type, and an element that isn't an object with a title or DOI string is
 * dropped (oxjob #1762). The DOI's shape is checked where it is used (cleanDOI).
 */
export function parsePublicationsJson(content: string): CvPublication[] {
  let jsonStr = content.trim();
  if (jsonStr.startsWith('```')) {
    jsonStr = jsonStr.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    throw new Error('Failed to parse publications from CV');
  }

  if (!Array.isArray(parsed)) {
    throw new Error('Failed to parse publications from CV');
  }

  return parsed.flatMap((p: unknown): CvPublication[] => {
    if (!p || typeof p !== 'object' || Array.isArray(p)) return [];
    const { title, doi, year, authors } = p as Record<string, unknown>;
    if (typeof title !== 'string' && typeof doi !== 'string') return [];
    return [{
      title: typeof title === 'string' ? title : '',
      doi: typeof doi === 'string' ? doi : null,
      year: cleanYear(year),
      authors: typeof authors === 'string' ? authors : null,
    }];
  });
}
