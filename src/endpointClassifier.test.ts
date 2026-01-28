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
        it('classifies /text/topics as text (1000 credits)', () => {
            const result = classifyEndpoint('/text/topics');
            expect(result.type).toBe('text');
            expect(result.creditCost).toBe(1000);
        });

        it('classifies /text/topics?title=test as text (1000 credits)', () => {
            const result = classifyEndpoint('/text/topics?title=test');
            expect(result.type).toBe('text');
            expect(result.creditCost).toBe(1000);
        });

        it('classifies /text as text (1000 credits)', () => {
            const result = classifyEndpoint('/text');
            expect(result.type).toBe('text');
            expect(result.creditCost).toBe(1000);
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

    describe('vector endpoints (future)', () => {
        it('classifies /vector/search as vector (1000 credits)', () => {
            const result = classifyEndpoint('/vector/search');
            expect(result.type).toBe('vector');
            expect(result.creditCost).toBe(1000);
        });

        it('classifies /search/works as vector (1000 credits)', () => {
            const result = classifyEndpoint('/search/works');
            expect(result.type).toBe('vector');
            expect(result.creditCost).toBe(1000);
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
