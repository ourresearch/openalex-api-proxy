/**
 * Pure parsing of the Claude model's response text into CvPublication[].
 * Kept free of I/O so it can be unit-tested directly.
 */

import type { CvPublication } from './openalexMatcher';

/**
 * Parse the model's response text (a JSON array, possibly wrapped in
 * markdown code fences) into a list of publications.
 * Throws if the content is not valid JSON or not an array.
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

  return parsed as CvPublication[];
}
