import { isChangefilesBrowsePath } from "./changefilesPaths";

export type EndpointType = 'singleton' | 'list' | 'search' | 'content' | 'semantic' | 'text';

export interface EndpointClassification {
    type: EndpointType;
    creditCost: number;
}

const ENTITY_TYPES = ['works', 'authors', 'sources', 'institutions',
                      'topics', 'publishers', 'funders', 'concepts'];

// OpenAlex IDs: optional letter prefix followed by digits (e.g., W123, 123, A456)
const OPENALEX_ID_PATTERN = /^[A-Za-z]?\d+$/;

// External ID prefixes that indicate a singleton lookup (e.g., doi:10.1038/..., pmid:29456894)
const EXTERNAL_ID_PREFIXES = [
    'doi:', 'pmid:', 'pmcid:', 'mag:', 'openalex:',
    'orcid:', 'ror:', 'wikidata:', 'issn:', 'issn_l:', 'scopus:'
];

// Search-type filters in the filter= param that trigger 10-credit search pricing
const SEARCH_FILTERS = [
    'abstract.search',
    'default.search',
    'display_name.search',
    'fulltext.search',
    'keyword.search',
    'raw_affiliation_strings.search',
    'raw_author_name.search',
    'title.search',
    'title_and_abstract.search'
];

/**
 * Count Lucene boolean operators (OR / AND / NOT — uppercase, whole-word) across all
 * search inputs: the `search` param, any `search.<field>` param, and `<field>.search:`
 * clauses inside `filter`. Used to throttle very broad boolean searches (oxjob #521),
 * which hold an ES search thread for seconds and drive queue saturation.
 */
export function countBooleanOperators(searchParams?: URLSearchParams): number {
    if (!searchParams) return 0;
    let text = '';
    for (const [key, value] of searchParams.entries()) {
        if (key === 'search' || key.startsWith('search.')) {
            text += ' ' + value;
        } else if (key === 'filter') {
            for (const m of value.matchAll(/[a-z_]+\.search:([^,]*)/gi)) {
                text += ' ' + m[1];
            }
        }
    }
    const matches = text.match(/(?<!\w)(?:OR|AND|NOT)(?!\w)/g);
    return matches ? matches.length : 0;
}

/**
 * Filter fields where a single OR'd value matches tens of thousands of works, so an
 * OR-list's ES cost grows with every distinct term (oxjob #876, 2026-09-14). Measured on
 * works-v34: 1 topic 0.3s, 10 topics 0.5s, 25 topics 1.5s, 100 topics 2.0s — versus
 * 425 OR'd `ids.openalex` at 0.5s flat, because identifier terms match one document each.
 * Deliberately narrow to start (topics + concepts); institutions/sources/countries/etc.
 * are candidates if the same shape shows up on them.
 */
export const WIDE_OR_FILTER_FIELDS = new Set([
    'topics.id',
    'primary_topic.id',
    'concepts.id',
    'concept.id',
]);

export const WIDE_OR_MAX_TERMS = 10;

/**
 * Largest number of distinct OR'd values on any wide filter field across every
 * `filter` param. Negated lists (`topics.id:!T1|T2`) are not counted — the replay
 * showed a 325-term NOT list costs nothing. Returns {field, count} of the worst key
 * so the 429 body can name it.
 */
export function countWideOrTerms(searchParams?: URLSearchParams): { field: string; count: number } {
    let worst = { field: '', count: 0 };
    if (!searchParams) return worst;
    for (const value of searchParams.getAll('filter')) {
        for (const clause of value.split(',')) {
            const colon = clause.indexOf(':');
            if (colon < 0) continue;
            const field = clause.slice(0, colon).trim().toLowerCase();
            if (!WIDE_OR_FILTER_FIELDS.has(field)) continue;
            const terms = clause.slice(colon + 1).trim();
            if (terms.startsWith('!')) continue;
            const distinct = new Set(
                terms.split('|').map(t => t.trim().toLowerCase()).filter(t => t.length > 0)
            );
            if (distinct.size > worst.count) worst = { field, count: distinct.size };
        }
    }
    return worst;
}

export function classifyEndpoint(pathname: string, searchParams?: URLSearchParams): EndpointClassification {
    const normalized = pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
    const segments = normalized.split('/');

    // Text/Aboutness endpoint - ML inference (expensive)
    if (/^text\/?/.test(normalized)) {
        return { type: 'text', creditCost: 100 };
    }

    // Content downloads: /works/{work_id}.pdf or .grobid-xml (for content.openalex.org)
    // Match paths with file extensions, including /content/* prefix from api.openalex.org
    if (/^(content\/)?works\/[^/]+\.(pdf|grobid-xml)$/i.test(normalized)) {
        return { type: 'content', creditCost: 100 };
    }

    // Changefiles listing/browse: /changefiles and /changefiles/{date} are free,
    // keyless discovery endpoints (just JSON listing what's available) — 0 credits
    // so they can never hit a rate limit. The actual file downloads at
    // /changefiles/{date}/{filename} are NOT matched here; they stay metered and
    // plan-gated in index.ts.
    if (isChangefilesBrowsePath(normalized)) {
        return { type: 'list', creditCost: 0 };
    }

    // Entity endpoints
    if (segments.length >= 1 && ENTITY_TYPES.includes(segments[0])) {
        // Singleton: /entity/ID or /entity/ID/subpath (e.g., /works/W123/ngrams)
        // Matches OpenAlex IDs (W123, 123) and external ID prefixes (doi:..., pmid:..., etc.)
        if (segments.length >= 2 && isSingletonIdentifier(segments[1])) {
            return { type: 'singleton', creditCost: 0 };
        }

        // group_by requests are capped at 1 credit (list pricing) regardless of
        // other params, to keep GUI facet calls affordable
        if (searchParams && (searchParams.has('group_by') || searchParams.has('group-by'))) {
            return { type: 'list', creditCost: 1 };
        }

        // Autocomplete-style searches: search + per_page ≤ 10 + select present
        // These lightweight queries power the GUI search box autocomplete and
        // are free for everyone
        if (searchParams && isAutocompleteSearch(searchParams)) {
            return { type: 'list', creditCost: 0 };
        }

        // Semantic search (search.semantic=) → 10 credits
        if (searchParams && hasSemanticSearch(searchParams)) {
            return { type: 'semantic', creditCost: 10 };
        }

        // Check if request has search params → 10 credits
        if (searchParams && hasSearchParams(searchParams)) {
            return { type: 'search', creditCost: 10 };
        }

        // List: /entity or /entity?...
        return { type: 'list', creditCost: 1 };
    }

    // Autocomplete: free for everyone. These are cheap prefix queries (≤25 tiny
    // objects) that power the GUI search-box dropdown — the same intent as the
    // isAutocompleteSearch() exemption above. Charging them drained the anon
    // daily pool mid-typing (up to 2 credits per keystroke-pause, per IP), which
    // popped the "hit today's free limit" modal while the user was still typing.
    // The per-second limit still throttles abuse.
    if (segments[0] === 'autocomplete') {
        return { type: 'list', creditCost: 0 };
    }

    // Default: treat as list (safe default)
    return { type: 'list', creditCost: 1 };
}

/**
 * Detect autocomplete-style search requests: bare `search` param with small
 * per_page and a `select` projection.  These are cheap queries used by the
 * GUI's search-box autocomplete dropdown and are free for all callers.
 */
function isAutocompleteSearch(searchParams: URLSearchParams): boolean {
    if (!searchParams.has('search')) return false;
    const perPage = searchParams.get('per_page') || searchParams.get('per-page');
    if (!perPage || parseInt(perPage, 10) > 10) return false;
    if (searchParams.get('select') !== 'id,display_name,works_count') return false;
    return true;
}

/**
 * Check if the request contains search.semantic parameter (10-credit semantic search).
 */
function hasSemanticSearch(searchParams: URLSearchParams): boolean {
    for (const key of searchParams.keys()) {
        if (key === 'search.semantic') return true;
    }
    return false;
}

/**
 * Check if the request contains search parameters that trigger 10-credit pricing.
 *
 * This includes:
 * - search= (bare search param)
 * - search.exact= (exact search)
 * - Any search.* dot notation param (except search.semantic, which is 10 credits)
 * - Search-type filters in filter= (e.g., title.search:, abstract.search:)
 */
function hasSearchParams(searchParams: URLSearchParams): boolean {
    // Check for search or search.* params (excluding search.semantic)
    for (const key of searchParams.keys()) {
        if (key === 'search' || (key.startsWith('search.') && key !== 'search.semantic')) {
            return true;
        }
    }

    // Check for search-type filters in the filter= param
    const filterParam = searchParams.get('filter');
    if (filterParam) {
        if (SEARCH_FILTERS.some(f => filterParam.includes(f))) {
            return true;
        }
    }

    return false;
}

/**
 * Check if a URL path segment is a singleton entity identifier.
 * Matches OpenAlex IDs (W123, 123) and external ID prefixes (doi:..., pmid:..., etc.)
 */
function isSingletonIdentifier(segment: string): boolean {
    if (OPENALEX_ID_PATTERN.test(segment)) return true;
    const lower = segment.toLowerCase();
    return EXTERNAL_ID_PREFIXES.some(prefix => lower.startsWith(prefix));
}

/**
 * Credits actually owed once the origin has answered (oxjob #863).
 *
 * The limiter charges `creditCost` at /check, before the origin is called, and
 * the response path used to stamp that same number on every status. So a typo'd
 * `search=` paid full search price for a 400 that never reached Elasticsearch.
 * Any error response — 4xx (nothing served, and ~90% of 400s are rejected before
 * ES) or 5xx (our fault) — is now free; the caller refunds the difference.
 *
 * Abuse note: a free 400 is a free "is this filter key valid?" probe, but the
 * per-second bucket still runs at /check ahead of the charge, so probe rate is
 * bounded exactly as before.
 */
export function billableCreditCost(status: number, creditCost: number): number {
    return status >= 400 ? 0 : creditCost;
}
