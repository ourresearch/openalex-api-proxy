export type EndpointType = 'singleton' | 'list' | 'search' | 'content' | 'vector' | 'text';

export interface EndpointClassification {
    type: EndpointType;
    creditCost: number;
}

const ENTITY_TYPES = ['works', 'authors', 'sources', 'institutions',
                      'topics', 'publishers', 'funders', 'concepts'];

// OpenAlex IDs: optional letter prefix followed by digits (e.g., W123, 123, A456)
const OPENALEX_ID_PATTERN = /^[A-Za-z]?\d+$/;

// Search-type filters in the filter= param that trigger 10-credit pricing
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
        return { type: 'text', creditCost: 1000 };
    }

    // Vector search endpoints (legacy /vector/ and /search/ paths)
    if (/^(vector|search)\//.test(normalized)) {
        return { type: 'vector', creditCost: 1000 };
    }

    // Content downloads: /works/{work_id}.pdf or .grobid-xml (for content.openalex.org)
    // Match paths with file extensions or legacy /content/* paths
    if (/^works\/[^/]+\.(pdf|grobid-xml)$/i.test(normalized)) {
        return { type: 'content', creditCost: 100 };
    }

    // Entity endpoints
    if (segments.length >= 1 && ENTITY_TYPES.includes(segments[0])) {
        // Singleton: /entity/ID or /entity/ID/subpath (e.g., /works/W123/ngrams)
        if (segments.length >= 2 && OPENALEX_ID_PATTERN.test(segments[1])) {
            return { type: 'singleton', creditCost: 0 };
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
 * Check if the request contains any search parameters that trigger 10-credit pricing.
 *
 * This includes:
 * - search= (bare search param)
 * - search.semantic= (vector search)
 * - search.exact= (exact search)
 * - Any search.* dot notation param
 * - Search-type filters in filter= (e.g., title.search:, abstract.search:)
 */
function hasSearchParams(searchParams: URLSearchParams): boolean {
    // Check for search or search.* params
    for (const key of searchParams.keys()) {
        if (key === 'search' || key.startsWith('search.')) {
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
