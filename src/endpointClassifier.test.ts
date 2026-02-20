import { describe, it, expect } from 'vitest';
import { classifyEndpoint } from './endpointClassifier';

describe('endpointClassifier', () => {
    describe('singleton endpoints', () => {
        it('classifies /works/W123 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/W123');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /works/123 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/123');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /works/W123/ngrams as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/W123/ngrams');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /authors/A123 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/authors/A123');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /institutions/I123 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/institutions/I123');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });
    });

    describe('list endpoints', () => {
        it('classifies /works as list (1 credit)', () => {
            const result = classifyEndpoint('/works');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies /works?filter=type:article as list (1 credit)', () => {
            const result = classifyEndpoint('/works?filter=type:article');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies /authors as list (1 credit)', () => {
            const result = classifyEndpoint('/authors');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies /autocomplete/works as list (1 credit)', () => {
            const result = classifyEndpoint('/autocomplete/works');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies /autocomplete/works?q=test as list (1 credit)', () => {
            const result = classifyEndpoint('/autocomplete/works?q=test');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });
    });

    describe('text endpoints', () => {
        it('classifies /text/topics as text (100 credits)', () => {
            const result = classifyEndpoint('/text/topics');
            expect(result.type).toBe('text');
            expect(result.creditCost).toBe(100);
        });

        it('classifies /text/topics?title=test as text (100 credits)', () => {
            const result = classifyEndpoint('/text/topics?title=test');
            expect(result.type).toBe('text');
            expect(result.creditCost).toBe(100);
        });

        it('classifies /text as text (100 credits)', () => {
            const result = classifyEndpoint('/text');
            expect(result.type).toBe('text');
            expect(result.creditCost).toBe(100);
        });
    });

    describe('content endpoints', () => {
        it('classifies /works/W123.pdf as content (100 credits)', () => {
            const result = classifyEndpoint('/works/W123.pdf');
            expect(result.type).toBe('content');
            expect(result.creditCost).toBe(100);
        });

        it('classifies /works/W123.grobid-xml as content (100 credits)', () => {
            const result = classifyEndpoint('/works/W123.grobid-xml');
            expect(result.type).toBe('content');
            expect(result.creditCost).toBe(100);
        });
    });

    describe('semantic search endpoints (10 credits)', () => {
        it('classifies ?search.semantic=ML as semantic (10 credits)', () => {
            const params = new URLSearchParams('search.semantic=machine+learning');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('semantic');
            expect(result.creditCost).toBe(10);
        });

        it('semantic takes priority when mixed with regular search', () => {
            const params = new URLSearchParams('search=cancer&search.semantic=ML');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('semantic');
            expect(result.creditCost).toBe(10);
        });
    });

    describe('legacy vector paths (no longer special)', () => {
        it('classifies /vector/search as default list (1 credit)', () => {
            const result = classifyEndpoint('/vector/search');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies /search/works as default list (1 credit)', () => {
            const result = classifyEndpoint('/search/works');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });
    });

    describe('group_by endpoints (1 credit override)', () => {
        it('classifies search + group_by as list (1 credit)', () => {
            const params = new URLSearchParams('search=frogs&group_by=type');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies search + group-by (hyphenated) as list (1 credit)', () => {
            const params = new URLSearchParams('search=frogs&group-by=type');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies group_by without search as list (1 credit)', () => {
            const params = new URLSearchParams('group_by=type');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });
    });

    describe('search endpoints (10 credits)', () => {
        it('classifies /works?search=cancer as search (10 credits)', () => {
            const params = new URLSearchParams('search=cancer');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('classifies /works?search.semantic=machine+learning as semantic (10 credits)', () => {
            const params = new URLSearchParams('search.semantic=machine+learning');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('semantic');
            expect(result.creditCost).toBe(10);
        });

        it('classifies /works?search.exact=running as search (10 credits)', () => {
            const params = new URLSearchParams('search.exact=running');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('classifies /works?filter=title.search:cancer as search (10 credits)', () => {
            const params = new URLSearchParams('filter=title.search:cancer');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('classifies /works?filter=abstract.search:climate as search (10 credits)', () => {
            const params = new URLSearchParams('filter=abstract.search:climate');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('classifies /works?filter=type:article (no search) as list (1 credit)', () => {
            const params = new URLSearchParams('filter=type:article');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies /authors?search=smith as search (10 credits)', () => {
            const params = new URLSearchParams('search=smith');
            const result = classifyEndpoint('/authors', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('still classifies singleton even with search params (0 credits)', () => {
            const params = new URLSearchParams('search=test');
            const result = classifyEndpoint('/works/W123', params);
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });
    });

    describe('edge cases', () => {
        it('handles leading/trailing slashes', () => {
            const result = classifyEndpoint('///works/W123///');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('handles uppercase paths', () => {
            const result = classifyEndpoint('/WORKS/W123');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('defaults unknown paths to list (1 credit)', () => {
            const result = classifyEndpoint('/unknown/path');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });
    });
});
