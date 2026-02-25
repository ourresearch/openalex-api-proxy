export type EndpointType = 'singleton' | 'list' | 'search' | 'content' | 'semantic' | 'text';

export interface EndpointClassification {
    type: EndpointType;
    creditCost: number;
}

const ENTITY_TYPES = ['works', 'authors', 'sources', 'institutions',
                      'topics', 'publishers', 'funders', 'concepts'];

// OpenAlex IDs: optional letter prefix followed by digits (e.g., W123, 123, A456)
const OPENALEX_ID_PATTERN = /^[A-Za-z]?\d+$/;

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

    // Entity endpoints
    if (segments.length >= 1 && ENTITY_TYPES.includes(segments[0])) {
        // Singleton: /entity/ID or /entity/ID/subpath (e.g., /works/W123/ngrams)
        if (segments.length >= 2 && OPENALEX_ID_PATTERN.test(segments[1])) {
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

    // Autocomplete
    if (segments[0] === 'autocomplete') {
        return { type: 'list', creditCost: 1 };
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
