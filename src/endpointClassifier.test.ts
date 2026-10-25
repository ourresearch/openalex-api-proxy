import { describe, it, expect } from 'vitest';
import { classifyEndpoint, countBooleanOperators, countWideOrTerms, WIDE_OR_MAX_TERMS, billableCreditCost, rerankCredits, bodyAsksRerank, QUERY_TEXT_ENTRY_CREDITS, queryTextAllowed } from './endpointClassifier';
import { actualCreditCost } from './creditReconcile';

const ops = (qs: string) => countBooleanOperators(new URLSearchParams(qs));

describe('countBooleanOperators', () => {
    it('returns 0 with no search params', () => {
        expect(countBooleanOperators(undefined)).toBe(0);
        expect(ops('filter=publication_year:2020')).toBe(0);
    });

    it('counts OR/AND/NOT in the search param (whole-word, uppercase only)', () => {
        expect(ops('search=cancer')).toBe(0);
        expect(ops('search=cancer AND immunotherapy')).toBe(1);
        expect(ops('search=a OR b OR c AND d NOT e')).toBe(4);
    });

    it('does not count lowercase or substrings (e.g. "for", "brand")', () => {
        expect(ops('search=oranges and brandy for sale')).toBe(0);
    });

    it('counts operators in search.<field> and filter <field>.search clauses', () => {
        expect(ops('search.title=a OR b')).toBe(1);
        expect(ops('filter=title.search:a OR b OR c')).toBe(2);
    });

    it('flags a broad boolean query as >10', () => {
        const q = 'search=' + Array.from({ length: 12 }, (_, i) => `t${i}`).join(' OR ');
        expect(ops(q)).toBe(11);
        expect(ops(q) > 10).toBe(true);
    });
});

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

        // External ID formats
        it('classifies /works/doi:10.1038/s41586-024-07386-0 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/doi:10.1038/s41586-024-07386-0');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /works/pmid:29456894 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/pmid:29456894');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /works/pmcid:PMC6789 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/pmcid:PMC6789');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /works/mag:123456789 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/mag:123456789');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /works/openalex:W2741809807 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/works/openalex:W2741809807');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /authors/orcid:0000-0003-1613-5981 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/authors/orcid:0000-0003-1613-5981');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /institutions/ror:03vek6s52 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/institutions/ror:03vek6s52');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /institutions/wikidata:Q49108 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/institutions/wikidata:Q49108');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /sources/issn:0028-0836 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/sources/issn:0028-0836');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /sources/issn_l:0028-0836 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/sources/issn_l:0028-0836');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /authors/scopus:12345678 as singleton (0 credits)', () => {
            const result = classifyEndpoint('/authors/scopus:12345678');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });

        it('classifies external IDs case-insensitively (DOI: prefix)', () => {
            const result = classifyEndpoint('/works/DOI:10.1038/s41586-024-07386-0');
            expect(result.type).toBe('singleton');
            expect(result.creditCost).toBe(0);
        });
    });

    // oxjob #1686: the docs say lookups by DOI are free, and agents pass the DOI URL they have. Each form below
    // returned the record at the origin (probed 2026-10-15) but was billed as a 1-credit list.
    describe('external IDs written as URLs are singletons (oxjob #1686)', () => {
        const free = (path: string) => expect(classifyEndpoint(path, new URLSearchParams())).toEqual({ type: 'singleton', creditCost: 0 });

        it.each([
            '/works/https://doi.org/10.7717/peerj.4375',
            '/works/http://doi.org/10.7717/peerj.4375',
            '/works/doi.org/10.7717/peerj.4375',
            '/works/https://dx.doi.org/10.7717/peerj.4375',
            '/works/http://dx.doi.org/10.7717/peerj.4375',
            '/works/https:/doi.org/10.7717/peerj.4375',       // "//" collapsed by a client
            '/works/HTTPS://DOI.ORG/10.7717/PEERJ.4375',
            '/works/https://doi.org/10.7717/peerj.4375/',     // trailing slash
        ])('a DOI URL: %s', free);

        it.each([
            '/works/https%3A%2F%2Fdoi.org%2F10.7717%2Fpeerj.4375',
            '/works/https%3a%2f%2fdoi.org%2f10.7717%2fpeerj.4375',
            '/works/doi.org%2F10.7717%2Fpeerj.4375',
            '/works/doi%3A10.7717%2Fpeerj.4375',               // the prefixed form, encoded
            '/authors/https%3A%2F%2Forcid.org%2F0000-0001-6187-6610',
            '/works/W2741809807%2Fngrams',
        ])('a percent-encoded ID: %s', free);

        it.each([
            '/authors/https://orcid.org/0000-0001-6187-6610',
            '/institutions/https://ror.org/042nb2s44',
            '/institutions/ror.org/042nb2s44',
            '/funders/https://ror.org/021nxhr62',
            '/publishers/https://ror.org/02scfj030',
            '/works/https://openalex.org/W2741809807',
            '/institutions/https://www.wikidata.org/wiki/Q49108',
            '/authors/https://www.scopus.com/authid/detail.uri?authorId=12345678',
        ])('the other ID URLs the prefixed forms cover: %s', free);

        it('a DOI URL stays free whatever query params ride along', () => {
            expect(classifyEndpoint('/works/https://doi.org/10.7717/peerj.4375', new URLSearchParams('select=id,title&search=x')))
                .toEqual({ type: 'singleton', creditCost: 0 });
        });

        it.each([
            '/works',                                       // a list
            '/works/random',                                // a named route, not an ID
            '/works/https://example.org/10.7717/peerj.4375', // not an ID host
            '/works/https://doi.org.example.com/10.1/x',     // look-alike host
            '/works/doi.org',                               // a host with no ID
            '/works/https%3A%2F%2Fexample.org%2Fx',
            '/works/%E0%A4%A',                              // malformed escape: judged as written, no throw
        ])('still a list: %s', (path) => {
            expect(classifyEndpoint(path, new URLSearchParams()).type).toBe('list');
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

        it('classifies /autocomplete/works as list (0 credits)', () => {
            const result = classifyEndpoint('/autocomplete/works');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /autocomplete/works?q=test as list (0 credits)', () => {
            const result = classifyEndpoint('/autocomplete/works?q=test');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(0);
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

    describe('group_by endpoints (oxjob #1533: 1 credit only on a list or as a website facet)', () => {
        it('prices search + group_by as the search (10 credits)', () => {
            const params = new URLSearchParams('search=frogs&group_by=type');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('prices a search filter + group-by (hyphenated) as the search', () => {
            const params = new URLSearchParams('filter=title.search:frogs&group-by=type');
            expect(classifyEndpoint('/works', params).creditCost).toBe(10);
        });

        it('prices semantic search + group_by as semantic (10 credits)', () => {
            const result = classifyEndpoint('/works', new URLSearchParams('search.semantic=frogs&group_by=type'));
            expect(result.type).toBe('semantic');
            expect(result.creditCost).toBe(10);
        });

        it('keeps a website facet (group_by on a search) at 1 credit', () => {
            const params = new URLSearchParams('search=frogs&group_by=type&per_page=200');
            const result = classifyEndpoint('/works', params, { websiteFacet: true });
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(1);
        });

        it('classifies group_by without search as list (1 credit), website or not', () => {
            const params = new URLSearchParams('group_by=type');
            expect(classifyEndpoint('/works', params).creditCost).toBe(1);
            expect(classifyEndpoint('/works', params, { websiteFacet: true }).creditCost).toBe(1);
        });
    });

    describe('autocomplete-style search (0 credits)', () => {
        it('classifies search + per_page=10 + select as free', () => {
            const params = new URLSearchParams('search=einstein&per_page=10&select=id,display_name,works_count');
            const result = classifyEndpoint('/authors', params);
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(0);
        });

        it('classifies search + per_page=5 + exact select as free', () => {
            const params = new URLSearchParams('search=harvard&per_page=5&select=id,display_name,works_count');
            const result = classifyEndpoint('/institutions', params);
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(0);
        });

        it('does NOT classify as free with a different select', () => {
            const params = new URLSearchParams('search=harvard&per_page=10&select=id,display_name');
            const result = classifyEndpoint('/institutions', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('does NOT classify as free when per_page > 10', () => {
            const params = new URLSearchParams('search=cancer&per_page=25&select=id,display_name,works_count');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('does NOT classify as free when select is missing', () => {
            const params = new URLSearchParams('search=cancer&per_page=10');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('does NOT classify as free when per_page is missing', () => {
            const params = new URLSearchParams('search=cancer&select=id,display_name,works_count');
            const result = classifyEndpoint('/works', params);
            expect(result.type).toBe('search');
            expect(result.creditCost).toBe(10);
        });

        it('is free only when every page-size spelling is a whole 1-10 (the origin reads per-page first; oxjob #1762)', () => {
            const cost = (q: string) => classifyEndpoint('/works', new URLSearchParams(`search=x&select=id,display_name,works_count&${q}`)).creditCost;
            expect(cost('per-page=10')).toBe(0);
            expect(cost('per_page=1&per-page=100')).toBe(10);
            expect(cost('per-page=1&per_page=100')).toBe(10);
            expect(cost('per_page=5abc')).toBe(10);
            expect(cost('per_page=0')).toBe(10);
            expect(cost('per_page=')).toBe(10);
        });

        it('a group_bys (either spelling) never rides the free autocomplete shape (oxjob #1762)', () => {
            const cost = (q: string, websiteFacet = false) => classifyEndpoint('/works',
                new URLSearchParams(`search=frogs&per_page=10&select=id,display_name,works_count&${q}`), { websiteFacet }).creditCost;
            expect(cost('group_bys=type,publication_year,primary_topic.id')).toBe(10);
            expect(cost('group-bys=type')).toBe(10);
            expect(cost('group_bys=type', true)).toBe(10);  // no facet discount on this shape: it isn't a group_by
            expect(cost('group_bys=')).toBe(10);
            // Unchanged: the shape alone is free, and group_bys off this shape keeps its price.
            expect(cost('mailto=x@y.org')).toBe(0);
            expect(classifyEndpoint('/works', new URLSearchParams('group_bys=type,publication_year')).creditCost).toBe(1);
            expect(classifyEndpoint('/works', new URLSearchParams('search=frogs&group_bys=type')).creditCost).toBe(10);
        });

        it('a group_by never rides the free autocomplete shape', () => {
            const params = new URLSearchParams('search=frogs&per_page=10&select=id,display_name,works_count&group_by=type');
            expect(classifyEndpoint('/works', params).creditCost).toBe(10);
            expect(classifyEndpoint('/works', params, { websiteFacet: true }).creditCost).toBe(1);
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

    describe('changefiles listing (free, unlimited discovery)', () => {
        it('classifies /changefiles index as 0 credits', () => {
            const result = classifyEndpoint('/changefiles');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(0);
        });

        it('classifies /changefiles/{date} as 0 credits', () => {
            const result = classifyEndpoint('/changefiles/2026-06-05');
            expect(result.type).toBe('list');
            expect(result.creditCost).toBe(0);
        });

        it('handles trailing slash on the listing', () => {
            const result = classifyEndpoint('/changefiles/');
            expect(result.creditCost).toBe(0);
        });

        it('does NOT free-pass an actual changefile download', () => {
            const result = classifyEndpoint('/changefiles/2026-06-05/works_2026-06-05.jsonl.gz');
            expect(result.creditCost).not.toBe(0);
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

describe('countWideOrTerms (oxjob #876)', () => {
    const wide = (qs: string) => countWideOrTerms(new URLSearchParams(qs));
    const topics = (n: number) => Array.from({ length: n }, (_, i) => `T1${String(i).padStart(4, '0')}`).join('|');

    it('returns 0 with no filter', () => {
        expect(countWideOrTerms(undefined).count).toBe(0);
        expect(wide('search=cancer').count).toBe(0);
        expect(wide('filter=publication_year:2020').count).toBe(0);
    });

    it('counts distinct OR terms on topics.id and names the field', () => {
        expect(wide(`filter=topics.id:${topics(3)}`)).toEqual({ field: 'topics.id', count: 3 });
        expect(wide(`filter=topics.id:${topics(100)},language:en`)).toEqual({ field: 'topics.id', count: 100 });
        expect(wide(`filter=language:en,primary_topic.id:${topics(12)}`).count).toBe(12);
        expect(wide(`filter=concepts.id:C1|C2|C3`).count).toBe(3);
    });

    it('dedupes repeated terms and ignores case/whitespace', () => {
        expect(wide('filter=topics.id:T1|t1| T1 |T2').count).toBe(2);
    });

    it('ignores negated lists — a NOT list is free for ES', () => {
        expect(wide(`filter=topics.id:!${topics(325)}`).count).toBe(0);
        expect(wide(`filter=topics.id:${topics(4)},topics.id:!${topics(325)}`).count).toBe(4);
    });

    it('ignores identifier and other non-wide fields regardless of length', () => {
        const ids = Array.from({ length: 425 }, (_, i) => `W${i}`).join('|');
        expect(wide(`filter=openalex:${ids}`).count).toBe(0);
        expect(wide(`filter=ids.openalex:${ids}`).count).toBe(0);
        expect(wide(`filter=doi:${ids}`).count).toBe(0);
        expect(wide(`filter=authorships.institutions.id:${ids}`).count).toBe(0);
        expect(wide(`filter=topics.subfield.id:${ids}`).count).toBe(0);
    });

    it('takes the worst key across repeated filter params', () => {
        expect(wide(`filter=topics.id:${topics(2)}&filter=concepts.id:${topics(7)}`)).toEqual({ field: 'concepts.id', count: 7 });
    });

    it('the real 2026-09-14 shape trips the threshold, a 10-topic chunk does not', () => {
        expect(wide(`filter=topics.id:${topics(100)},language:en,topics.id:!${topics(325)}&per-page=200`).count).toBeGreaterThan(WIDE_OR_MAX_TERMS);
        expect(wide(`filter=topics.id:${topics(10)},language:en`).count).toBe(WIDE_OR_MAX_TERMS);
    });
});

describe('billableCreditCost (oxjob #863)', () => {
    it('charges the classified cost on success and redirects', () => {
        expect(billableCreditCost(200, 10)).toBe(10);
        expect(billableCreditCost(301, 1)).toBe(1);
        expect(billableCreditCost(304, 1)).toBe(1);
    });

    it('charges nothing for any 4xx or 5xx', () => {
        expect(billableCreditCost(400, 10)).toBe(0);
        expect(billableCreditCost(403, 1)).toBe(0);
        expect(billableCreditCost(404, 1)).toBe(0);
        expect(billableCreditCost(429, 10)).toBe(0);
        expect(billableCreditCost(500, 100)).toBe(0);
        expect(billableCreditCost(503, 10)).toBe(0);
    });

    it('is a no-op for free endpoints', () => {
        expect(billableCreditCost(200, 0)).toBe(0);
        expect(billableCreditCost(400, 0)).toBe(0);
    });
});

describe('rerank=true (oxjob #1521)', () => {
    it('prices a reranked search at 10 + 10 credits', () => {
        const r = classifyEndpoint('/works', new URLSearchParams('search.title_abstract_keywords=remote+work&rerank=true'));
        expect(r.type).toBe('search');
        expect(r.creditCost + rerankCredits(r.type, true)).toBe(20);
    });

    it('adds 10 credits to an OQL request on the root, and nothing to a free one', () => {
        const root = classifyEndpoint('/', new URLSearchParams('oql=works+where+title%2Fabstract%2Fkeywords+has+(kelp)'));
        expect(root.creditCost + rerankCredits(root.type, true)).toBe(11);
        expect(rerankCredits('singleton', true)).toBe(0);
        expect(rerankCredits('search', false)).toBe(0);
    });

    it('reads rerank from a POST body', () => {
        expect(bodyAsksRerank({ oql: 'works', rerank: true })).toBe(true);
        expect(bodyAsksRerank({ oql: 'works', rerank: 'true' })).toBe(true);
        expect(bodyAsksRerank({ oql: 'works' })).toBe(false);
        expect(bodyAsksRerank(null)).toBe(false);
    });

    it('keeps a plain search at 10 credits, and rerank=false is plain', () => {
        expect(classifyEndpoint('/works', new URLSearchParams('search=remote+work')).creditCost).toBe(10);
        expect(classifyEndpoint('/works', new URLSearchParams('search=remote+work&rerank=false')).creditCost).toBe(10);
    });

    it('counts the title_abstract_keywords.search filter as a search', () => {
        const r = classifyEndpoint('/works', new URLSearchParams('filter=title_abstract_keywords.search:coral+bleaching'));
        expect(r.type).toBe('search');
        expect(r.creditCost).toBe(10);
    });

    it('prices a list request with rerank at 1 + 10 (the origin 400s it, and errors are refunded)', () => {
        const r = classifyEndpoint('/works', new URLSearchParams('filter=publication_year:2020&rerank=true'));
        expect(r.creditCost + rerankCredits(r.type, true)).toBe(11);
    });
});

describe('/query/text enters at one credit, before the free /query rule (oxjob #1494)', () => {
    it.each([
        '/query/text',
        '/query/text/',
        '/query/text/open%20access%20articles%20about%20coffee',
        '/Query/Text/kelp',
    ])('%s is query_text at the entry price', (path) => {
        const r = classifyEndpoint(path, new URLSearchParams());
        expect(r.type).toBe('query_text');
        expect(r.creditCost).toBe(QUERY_TEXT_ENTRY_CREDITS);
    });

    it('needs only some budget: one credit to enter', () => {
        expect(QUERY_TEXT_ENTRY_CREDITS).toBe(1);
    });

    it('is behind a feature flag: only listed user or org ids get in', () => {
        expect(queryTextAllowed('user-TSamuHxDbnhn', ['user-TSamuHxDbnhn'])).toBe(true);
        expect(queryTextAllowed(' user-a , org-b ', ['user-x', 'org-b'])).toBe(true);
        expect(queryTextAllowed('user-TSamuHxDbnhn', ['user-4jkBZiWYK4YX'])).toBe(false);
        expect(queryTextAllowed('', ['user-TSamuHxDbnhn'])).toBe(false);
        expect(queryTextAllowed(undefined, ['user-TSamuHxDbnhn'])).toBe(false);
        expect(queryTextAllowed('user-a', [])).toBe(false);
    });

    it('opens to every valid key with *', () => {
        expect(queryTextAllowed('*', ['user-4jkBZiWYK4YX'])).toBe(true);
        expect(queryTextAllowed(' user-a , * ', ['org-b'])).toBe(true);
        expect(queryTextAllowed('*', [])).toBe(true);
    });

    it('settles to the query writer\'s price on an answer, free on an error', () => {
        expect(actualCreditCost(200, QUERY_TEXT_ENTRY_CREDITS, '516')).toBe(516);
        expect(actualCreditCost(422, QUERY_TEXT_ENTRY_CREDITS, '480')).toBe(0);
        expect(actualCreditCost(502, QUERY_TEXT_ENTRY_CREDITS, '0')).toBe(0);
        expect(actualCreditCost(200, QUERY_TEXT_ENTRY_CREDITS, null)).toBe(1);
    });

    it('leaves /query/textual and the top-level /text endpoint alone', () => {
        expect(classifyEndpoint('/query/textual', new URLSearchParams()).type).toBe('list');
        expect(classifyEndpoint('/text', new URLSearchParams()).type).toBe('text');
    });
});

describe('/query is free (oxjob #1533)', () => {
    it.each([
        '/query',
        '/query/oql/works%20where%20year%20%3E%20(2020)',
        '/query/oqo/%7B%7D',
        '/query/oxurl/works%3Ffilter%3Dpublication_year%3A2020',
        '/Query/OQL/works',
    ])('%s costs 0 credits', (path) => {
        expect(classifyEndpoint(path, new URLSearchParams()).creditCost).toBe(0);
    });

    it('stays free with a search in the query it checks', () => {
        expect(classifyEndpoint('/query', new URLSearchParams('oql=works+where+title+has+(kelp)')).creditCost).toBe(0);
    });

    it('leaves the OQL door on the root at list price', () => {
        expect(classifyEndpoint('/', new URLSearchParams('oql=works')).creditCost).toBe(1);
    });
});
