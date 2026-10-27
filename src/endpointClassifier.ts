import { splitFilterString } from './f1Validation';
import { isChangefilesBrowsePath } from "./changefilesPaths";
import { normalizePath } from "./paths";

export type EndpointType = 'singleton' | 'list' | 'search' | 'content' | 'semantic' | 'text' | 'query_text';

/**
 * Natural language to OQL (oxjob #1494): /query/text writes the query with a model, so it costs what the model cost
 * us. It is let in for one credit (anyone with some budget left can ask) and then settled to the query writer's
 * X-Credits-Cost (settleCredits; typically 200-500 credits, $0.02-0.05). When a question costs more than the caller
 * had left, the overrun lands on the daily counter, never on prepaid, and we absorb it: simpler than a hold
 * (Jason, 2026-10-11). 10,000 credits = $1.
 */
export const QUERY_TEXT_ENTRY_CREDITS = 1;

/**
 * The /query/text gate: is one of the key's accounts (user id, org id) in the comma-separated allowlist? `*` lets in
 * every valid key (the caller has already checked the key), priced per call like any request (oxjob #1494, Jason
 * 2026-10-20: the chat is open to all behind the website's nl_search flag). Empty = nobody.
 */
export function queryTextAllowed(allowlist: string | undefined, accountIds: string[]): boolean {
    const allowed = new Set((allowlist ?? "").split(",").map((s) => s.trim()).filter(Boolean));
    return allowed.has("*") || accountIds.some((id) => allowed.has(id));
}

export interface EndpointClassification {
    type: EndpointType;
    creditCost: number;
}

// Entities whose records carry an OpenAlex id (W123) or an external id (doi:, orcid:, ror:...).
const ENTITY_TYPES = new Set(['works', 'authors', 'sources', 'institutions',
                              'topics', 'publishers', 'funders', 'concepts']);

// Every other documented endpoint (help api/endpoints.md). Their records are looked up by a name-like or namespaced
// id: /keywords/artificial-intelligence, /countries/US, /work-types/article, /fields/17, /awards/G123,
// /locations/doi:10.1/x. Until oxjob #1886 these fell to the default at 1 credit, so a lookup cost 1 (docs: free) and
// a search 1 (docs: 10). raw-affiliation-strings has a list but no lookup; a path under it is a free 404.
// Copied from the origin's routes (elastic-api ids/views.py): a new entity endpoint there needs a line here.
const NAMED_ID_FAMILIES = new Set(['keywords', 'awards', 'fields', 'subfields', 'domains', 'sdgs',
                                   'countries', 'continents', 'languages', 'work-types', 'source-types',
                                   'institution-types', 'licenses', 'study-designs', 'indexes', 'source-lists',
                                   'oa-statuses', 'locations', 'raw-affiliation-strings']);

// The origin's own routes under a family (/keywords/histogram/x runs an aggregation), answered before its
// /<family>/<path:id> lookup, so they are never a lookup; and /random runs a random-score query (priced as a list).
const FAMILY_SUBROUTES = new Set(['filters', 'histogram', 'valid_fields', 'flattened_schema',
                                  'filters_docstrings', 'config', 'stats', 'random']);

// Older spellings the origin still answers (elastic-api ids/views.py): /people = /authors, /journals = /sources,
// /types = /work-types, and /entities/<family>/... or /v2/<family>/... for any family.
const FAMILY_ALIASES: Record<string, string> = { people: 'authors', journals: 'sources', types: 'work-types' };

/**
 * The entity family a normalized path addresses, and whether the path looks up one record, or null for a path that
 * isn't an entity endpoint. Aliases and the /entities and /v2 prefixes resolve to the family they serve, so each
 * spelling costs the same (oxjob #1886: /entities/works?search= was a works search at 1 credit).
 * A lookup: on the main entities an OpenAlex id (W123, 123), an external id prefix (doi:..., pmid:...) or an id URL
 * (https://doi.org/...), read from everything after "/entity/", not one segment (/works/W123/ngrams counts); on the
 * named-id families any id the origin's /<family>/<path:id> route takes, outside its subroutes.
 */
export function entityFamily(normalized: string): { family: string; lookup: boolean } | null {
    const parts = normalized.split('/');
    if (parts[0] === 'entities' || parts[0] === 'v2') parts.shift();
    const family = FAMILY_ALIASES[parts[0]] ?? parts[0];
    const named = NAMED_ID_FAMILIES.has(family);
    if (!named && !ENTITY_TYPES.has(family)) return null;
    const rest = parts.slice(1).join('/');
    const lookup = rest !== '' && (named ? !FAMILY_SUBROUTES.has(parts[1]) : isSingletonIdentifier(rest));
    return { family, lookup };
}

/**
 * Does the request run a search on an entity list (search=, search.<x>=, or a .search filter)? The one definition
 * both the price and the routing to the search origin (SEARCH_API_URL) use (oxjob #1886: routing kept its own copy
 * of the old filter list, so text.search, the named-id families and the aliases ran on the main origin).
 */
export function isEntitySearch(pathname: string, searchParams: URLSearchParams): boolean {
    const entity = entityFamily(normalizePath(pathname));
    return !!entity && !entity.lookup && (hasSearchParams(searchParams) || hasSemanticSearch(searchParams));
}

// OpenAlex IDs: optional letter prefix followed by digits (e.g., W123, 123, A456)
const OPENALEX_ID_PATTERN = /^[A-Za-z]?\d+$/;

// External ID prefixes that indicate a singleton lookup (e.g., doi:10.1038/..., pmid:29456894)
const EXTERNAL_ID_PREFIXES = [
    'doi:', 'pmid:', 'pmcid:', 'mag:', 'openalex:',
    'orcid:', 'ror:', 'wikidata:', 'issn:', 'issn_l:', 'scopus:'
];

// The same external IDs written as URLs, which the origin's /<entity>/<path:id> routes also look up as one record
// (oxjob #1686): /works/https://doi.org/10.7717/peerj.4375, /works/doi.org/..., /works/https://dx.doi.org/...,
// /authors/https://orcid.org/..., /institutions/https://ror.org/..., /works/https://openalex.org/W123. Scheme
// optional, and "//" may arrive collapsed to "/". A form the origin doesn't resolve 404s, and errors are free, so
// matching a host here never makes a list free.
const EXTERNAL_ID_URL = /^(?:https?:\/\/?)?(?:www\.|dx\.)?(?:doi\.org|orcid\.org|ror\.org|openalex\.org|wikidata\.org|scopus\.com)\/./;

/**
 * Does a filter= value hold a search filter? Any key with a `.search` part is one (title.search, text.search,
 * description.search, keywords.search, display_name.search.exact, abstract.search.no_stem...), and the docs price
 * every one like the search parameter: "These filter-based searches cost the same $1 per 1,000 requests"
 * (help api/searching.md). A fixed list missed text.search, description.search and keywords.search (oxjob #1886).
 * Keys come from the API's own split, so a ".search" inside a filter's value is not a search.
 */
function hasSearchFilter(filterParam: string): boolean {
    return splitFilterString(filterParam).some(clause => {
        const colon = clause.indexOf(':');
        return colon > 0 && isSearchFilterKey(clause.slice(0, colon));
    });
}

/** A filter key with a `.search` part: title.search, text.search, display_name.search.exact, abstract.search.no_stem. */
function isSearchFilterKey(key: string): boolean {
    return /\.search(\.|$)/i.test(key.trim());
}

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
            // the API's own split, so a comma inside a search value can't hide its operators (#1883)
            for (const clause of splitFilterString(value)) {
                const colon = clause.indexOf(':');
                if (colon > 0 && isSearchFilterKey(clause.slice(0, colon))) text += ' ' + clause.slice(colon + 1);
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
        for (const clause of splitFilterString(value)) {
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

export function classifyEndpoint(
    pathname: string,
    searchParams?: URLSearchParams,
    opts: { websiteFacet?: boolean; method?: string } = {},
): EndpointClassification {
    const normalized = normalizePath(pathname);
    const segments = normalized.split('/');

    // Text/Aboutness endpoint - ML inference (expensive)
    if (/^text\/?/.test(normalized)) {
        return { type: 'text', creditCost: 100 };
    }

    // Content downloads: /works/{work_id}.pdf or .grobid-xml (for content.openalex.org)
    // Match paths with file extensions, including /content/* prefix from api.openalex.org
    // A HEAD sends the file's headers and no bytes, and the docs price downloads, so it is free (oxjob #1886: it was
    // charged the full 100). The content worker serves the bytes itself, never a signed link a HEAD could leak.
    if (/^(content\/)?works\/[^/]+\.(pdf|grobid-xml)$/i.test(normalized)) {
        return { type: 'content', creditCost: opts.method?.toUpperCase() === 'HEAD' ? 0 : 100 };
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
    const entity = entityFamily(normalized);
    if (entity) {
        // Singleton: one record by its id (see entityFamily)
        if (entity.lookup) {
            return { type: 'singleton', creditCost: 0 };
        }

        // A group_by costs what its query costs: 1 on a list, 10 on a search. The
        // website's facets (a group_by on the user's search, five a page) are the one
        // exception at list price, so browsing stays affordable: "cheap or free, but
        // ONLY in this facet context" (Jason, 2026-10-03, oxjob #1533). Until then any
        // group_by was 1 for every caller, which priced a search's counts at a tenth
        // of the search.
        // Decided here, before the free autocomplete shape, so a group_by can't ride it.
        if (searchParams && (searchParams.has('group_by') || searchParams.has('group-by'))) {
            if (hasSemanticSearch(searchParams) && !opts.websiteFacet) return { type: 'semantic', creditCost: 10 };
            if (hasSearchParams(searchParams) && !opts.websiteFacet) return { type: 'search', creditCost: 10 };
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

        // Check if request has search params → 10 credits (rerank adds RERANK_CREDITS on top, in index.ts)
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

    // Plain words to OQL (/query/text, /query/text/<q>; oxjob #1494): a model writes the query, so it enters at
    // QUERY_TEXT_ENTRY_CREDITS and is settled to the model's cost. Decided before the free translate rule below.
    if (segments[0] === 'query' && segments[1] === 'text') {
        return { type: 'query_text', creditCost: QUERY_TEXT_ENTRY_CREDITS };
    }

    // The translate resource and its free check (/query, /query/oql/<q>, /query/oqo/<q>,
    // /query/oxurl/<q>): it parses, validates and prices a query without running it, so
    // it's free (Jason, 2026-10-03, #1512 SYNTAX.md Decided; oxjob #1533).
    if (segments[0] === 'query') {
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
    // A multi-facet group_bys (either spelling) runs one terms aggregation per key next to the search, and the origin
    // refuses select only with group_by (elastic-api core/validate.py:110), so it ran as a free autocomplete (oxjob #1762).
    // It pays what the search costs; group_by is priced before this shape is tried.
    if (searchParams.has('group_bys') || searchParams.has('group-bys')) return false;
    // Every page-size spelling sent must be a whole number 1-10. The origin reads per-page before per_page, so judging
    // only per_page priced `per_page=1&per-page=100` free and ran 100 rows, the same gap as a repeated parameter
    // (oxjob #1762). parseInt also read "5abc" as 5, a value the origin can't take as 5.
    const perPages = [searchParams.get('per_page'), searchParams.get('per-page')].filter((v): v is string => v !== null);
    if (perPages.length === 0 || !perPages.every(v => /^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 10)) return false;
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
/** rerank=true: the origin asks Jev to reorder the top 100 of a works search (oxjob #1521). */
export function isRerank(searchParams: URLSearchParams): boolean {
    return searchParams.get('rerank') === 'true';
}

/** A POST body (the OQL door, POST /) that asks for rerank: {"rerank": true}. */
export function bodyAsksRerank(body: unknown): boolean {
    return !!body && typeof body === 'object' && ((body as any).rerank === true || (body as any).rerank === 'true');
}

/** What rerank adds to a request's price: 10 credits ($0.001) on any billable list or search request,
 *  whatever its base price (a URL search 10 → 20, an OQL query on the root 1 → 11, grandfathered search 1 → 11). */
export const RERANK_CREDITS = 10;
export function rerankCredits(type: EndpointType, rerankAsked: boolean): number {
    return rerankAsked && (type === 'search' || type === 'list') ? RERANK_CREDITS : 0;
}

function hasSearchParams(searchParams: URLSearchParams): boolean {
    // Check for search or search.* params (excluding search.semantic)
    for (const key of searchParams.keys()) {
        if (key === 'search' || (key.startsWith('search.') && key !== 'search.semantic')) {
            return true;
        }
    }

    const filterParam = searchParams.get('filter');
    return filterParam !== null && hasSearchFilter(filterParam);
}

/**
 * Is the path after "/entity/" a lookup of one record?
 * Matches OpenAlex IDs (W123, 123), external ID prefixes (doi:..., pmid:..., etc.) and the same IDs as URLs
 * (https://doi.org/...). Percent-encoded forms (https%3A%2F%2Fdoi.org%2F..., doi%3A10.1%2Fx) count too: the
 * origin decodes the path before it routes, so they are the same lookup.
 */
function isSingletonIdentifier(idPath: string): boolean {
    let id = idPath.toLowerCase();
    if (id.includes('%')) {
        try { id = decodeURIComponent(id); } catch { /* malformed escape: judge it as written */ }
    }
    if (OPENALEX_ID_PATTERN.test(id.split('/')[0])) return true;
    if (EXTERNAL_ID_PREFIXES.some(prefix => id.startsWith(prefix))) return true;
    return EXTERNAL_ID_URL.test(id);
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
