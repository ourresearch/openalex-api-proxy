export type EndpointType = 'singleton' | 'list' | 'content' | 'vector' | 'text';

export interface EndpointClassification {
    type: EndpointType;
    creditCost: number;
}

const ENTITY_TYPES = ['works', 'authors', 'sources', 'institutions',
                      'topics', 'publishers', 'funders', 'concepts'];

// OpenAlex IDs: optional letter prefix followed by digits (e.g., W123, 123, A456)
const OPENALEX_ID_PATTERN = /^[A-Za-z]?\d+$/;

export function classifyEndpoint(pathname: string): EndpointClassification {
    const normalized = pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
    const segments = normalized.split('/');

    // Text/Aboutness endpoint - ML inference (expensive)
    if (/^text\/?/.test(normalized)) {
        return { type: 'text', creditCost: 1000 };
    }

    // Vector search endpoints (future)
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
