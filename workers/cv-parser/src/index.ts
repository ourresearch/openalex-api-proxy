/**
 * OpenAlex CV Parser — Cloudflare Worker
 *
 * Accepts file uploads (PDF, DOCX, DOC, TXT), extracts text,
 * sends to Claude API to identify publications, then matches
 * them against OpenAlex works.
 *
 * Ported from cv-parse-server.js (Express/Node.js) to CF Workers runtime.
 */

import Anthropic from '@anthropic-ai/sdk';
import { extractText } from './extractText';
import { parsePublicationsJson } from './parseClaudeResponse';
import {
  searchOpenAlex,
  setApiKey,
  type CvPublication,
  type MatchedWork,
} from './openalexMatcher';

export interface Env {
  ANTHROPIC_API_KEY: string;
  OPENALEX_API_BASE?: string; // Direct upstream URL to avoid proxy loop
  OPENALEX_API_KEY?: string;  // API key to avoid 429 rate limits
}

interface ParseCvResponse {
  totalParsed: number;
  matched: MatchedWork[];
  unmatched: CvPublication[];
}

// ─── Main Worker Entry ───────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(),
      });
    }

    // Only accept POST to /api/parse-cv
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '');

    if (request.method === 'POST' && path === '/api/parse-cv') {
      try {
        const result = await handleParseCv(request, env);
        return jsonResponse(200, result);
      } catch (err: any) {
        console.error('CV parse error:', err);
        return jsonResponse(500, { error: err.message || 'Internal error' });
      }
    }

    // Health check
    if (request.method === 'GET' && (path === '' || path === '/')) {
      return jsonResponse(200, { status: 'ok', service: 'openalex-cv-parser' });
    }

    return jsonResponse(404, { error: 'Not found' });
  },
};

// ─── Core Handler ────────────────────────────────────────────

async function handleParseCv(request: Request, env: Env): Promise<ParseCvResponse> {
  const formData = await request.formData();

  // workers-types declares formData.get() as string | null, but at runtime a
  // multipart file part arrives as a File — go through `unknown` so the
  // instanceof narrowing typechecks.
  const file = formData.get('file') as unknown;
  if (!(file instanceof File)) {
    throw new Error('No file uploaded');
  }

  const authorId = (formData.get('authorId') as string) || '';
  const authorName = (formData.get('authorName') as string) || '';

  console.log(`Processing CV: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);

  // Step 1: Extract text from the uploaded file
  console.log('Extracting text...');
  const buffer = await file.arrayBuffer();
  const text = await extractText(Buffer.from(buffer), file.name);
  console.log(`Extracted ${text.length} chars`);

  // Step 2: Parse publications with Claude
  console.log('Sending to Claude...');
  const publications = await parsePublicationsWithClaude(text, env.ANTHROPIC_API_KEY);
  console.log(`Claude found ${publications.length} publications`);

  // Step 3: Match against OpenAlex (with rate limiting)
  // Set API key for authenticated requests (avoids 429 rate limits)
  setApiKey(env.OPENALEX_API_KEY);
  console.log('Matching against OpenAlex...');
  const matched: MatchedWork[] = [];
  const unmatched: CvPublication[] = [];

  for (const pub of publications) {
    try {
      const apiBase = env.OPENALEX_API_BASE || 'https://api.openalex.org';
      const oaWork = await searchOpenAlex(pub, apiBase, env.OPENALEX_API_KEY);
      if (oaWork) {
        // Check if this work is already linked to the author
        const authorShortId = authorId
          .replace('https://openalex.org/', '')
          .toUpperCase();
        const isAlreadyLinked = oaWork.authorships?.some((a: any) => {
          const aid = (a.author?.id || '')
            .replace('https://openalex.org/', '')
            .toUpperCase();
          return aid === authorShortId;
        });

        matched.push({
          cvPublication: pub,
          oaWork: {
            id: oaWork.id,
            display_name: oaWork.display_name,
            publication_year: oaWork.publication_year,
            authorships: oaWork.authorships,
            primary_location: oaWork.primary_location,
          },
          alreadyLinked: !!isAlreadyLinked,
        });
      } else {
        unmatched.push(pub);
      }
      // Rate limit: ~5 requests per second
      await delay(200);
    } catch (err: any) {
      console.error(`Error matching "${pub.title}":`, err.message);
      unmatched.push(pub);
    }
  }

  console.log(`Done: ${matched.length} matched, ${unmatched.length} unmatched`);

  return {
    totalParsed: publications.length,
    matched,
    unmatched,
  };
}

// ─── Claude API ──────────────────────────────────────────────

async function parsePublicationsWithClaude(
  text: string,
  apiKey: string
): Promise<CvPublication[]> {
  const anthropic = new Anthropic({ apiKey });

  // Truncate very long CVs to ~100k chars
  const truncated = text.length > 100000 ? text.substring(0, 100000) : text;

  const response = await anthropic.messages.create({
    // claude-sonnet-4-20250514 was retired by Anthropic (API now 404s it);
    // claude-sonnet-5 is its successor. Sonnet 5 runs adaptive thinking by
    // default and uses a denser tokenizer, so max_tokens is raised and the
    // text block is located by type below (content[0] may be a thinking block).
    model: 'claude-sonnet-5',
    max_tokens: 16000,
    messages: [
      {
        role: 'user',
        content: `You are analyzing a CV or publication list. Extract all scholarly publications (journal articles, conference papers, book chapters, preprints, etc.) from the following text.

For each publication, return a JSON array where each element has:
- "title": the FULL title of the publication as plain text (no HTML tags, no superscripts, no formatting). Include subtitles after a colon if present.
- "doi": the DOI if present anywhere in the reference (just the DOI like "10.1234/example", not a URL). Look for patterns like "doi:", "DOI:", "https://doi.org/", or "dx.doi.org/". Return null if no DOI found.
- "year": the publication year (4-digit number), or null
- "authors": a string with the author names as they appear, or null

Important:
- Strip any HTML tags, superscript markers, or formatting from titles
- Use the exact scholarly title as it would appear in a citation — do NOT truncate or abbreviate
- Look carefully for DOIs — they are the most reliable way to match publications. Check the end of each reference, footnotes, and any URLs.
- Return ONLY valid JSON — an array of objects. No other text, no markdown code fences.
- If no publications are found, return an empty array [].

Here is the text:

${truncated}`,
      },
    ],
  });

  const textBlock = response.content.find((b: any) => b.type === 'text');
  if (!textBlock) {
    console.error('No text block in Claude response; stop_reason:', response.stop_reason);
    throw new Error('Failed to parse publications from CV');
  }
  const content = (textBlock as any).text.trim();

  try {
    return parsePublicationsJson(content);
  } catch (err) {
    console.error('Failed to parse Claude response:', content.substring(0, 500));
    throw err;
  }
}

// ─── Helpers ─────────────────────────────────────────────────

const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function jsonResponse(status: number, body: any): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(),
    },
  });
}
