import { describe, it, expect } from 'vitest';
import { isCacheableCountProbe, mentionsCollection } from './countProbe';

const u = (qs: string) => new URL(`https://api.openalex.org/works?${qs}`);

describe('isCacheableCountProbe', () => {
    it('caches the anonymous corpus-count probe', () => {
        expect(isCacheableCountProbe(u('per-page=1&select=id'), 'GET', false, false)).toBe(true);
        expect(isCacheableCountProbe(u('per_page=1&select=id&filter=publication_year:2020'), 'GET', false, false)).toBe(true);
    });

    it('never caches a probe that names a collection (oxjob #646)', () => {
        expect(isCacheableCountProbe(u('per-page=1&select=id&filter=collection:col_abc123'), 'GET', false, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id&filter=primary_location.source.publisher_lineage:!col_abc123'), 'GET', false, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id&oql=' + encodeURIComponent('works where work is in collection (col_abc123)')), 'GET', false, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id&filter=collection%3Acol_abc123'), 'GET', false, false)).toBe(false);
    });

    it('keeps the existing exclusions', () => {
        expect(isCacheableCountProbe(u('per-page=1&select=id'), 'POST', false, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id'), 'GET', true, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id'), 'GET', false, true)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id&cursor=*'), 'GET', false, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=1&select=id&page=2'), 'GET', false, false)).toBe(false);
        expect(isCacheableCountProbe(u('per-page=2&select=id'), 'GET', false, false)).toBe(false);
    });
});

describe('mentionsCollection', () => {
    it('only matches col_ in values', () => {
        expect(mentionsCollection(u('filter=title.search:colour'))).toBe(false);
        expect(mentionsCollection(u('filter=authorships.author.id:col_X'))).toBe(true);
    });
});
