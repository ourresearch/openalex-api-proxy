import { describe, it, expect } from 'vitest';
import { splitFilterString, f1Reason } from './f1Validation';

const reason = (search: string) => f1Reason(new URL(`https://api.openalex.org/works${search}`));

describe('f1Validation', () => {
    describe('splitFilterString (port of elastic-api split_filter_string)', () => {
        it('splits on unquoted commas', () => {
            expect(splitFilterString('type:article,is_oa:true')).toEqual(['type:article', 'is_oa:true']);
        });
        it('keeps commas inside double quotes in one segment', () => {
            expect(splitFilterString('raw_affiliation_strings.search:"Dept of Chemistry, UCLA"'))
                .toEqual(['raw_affiliation_strings.search:"Dept of Chemistry, UCLA"']);
        });
        it('handles a single segment with no comma', () => {
            expect(splitFilterString('publication_year:2020')).toEqual(['publication_year:2020']);
        });
    });

    describe('limit_param shape (AutoRecruit)', () => {
        it('rejects ?limit=5', () => {
            expect(reason('?search=foo&limit=5')).toBe('limit_param');
        });
        it('rejects ?limit alone', () => {
            expect(reason('?limit=5')).toBe('limit_param');
        });
        it('does NOT reject the correct per-page param', () => {
            expect(reason('?search=foo&per-page=5')).toBeNull();
        });
    });

    describe('raw_comma_filter shape (Jenni)', () => {
        it('rejects a raw comma that yields a colonless segment', () => {
            // 'title.search:climate change, biodiversity loss' splits into
            // ['title.search:climate change', ' biodiversity loss'] -> 2nd has no colon
            expect(reason('?filter=title.search:climate change, biodiversity loss')).toBe('raw_comma_filter');
        });
        it('does NOT reject a valid multi-filter (colon in every segment)', () => {
            expect(reason('?filter=publication_year:2020,title.search:climate')).toBeNull();
        });
        it('does NOT reject a quoted comma (stays in one segment)', () => {
            expect(reason('?filter=raw_affiliation_strings.search:"Dept of Chemistry, UCLA"')).toBeNull();
        });
        it('does NOT reject a single valid filter', () => {
            expect(reason('?filter=publication_year:2020')).toBeNull();
        });
        it('does NOT reject when there is no filter param', () => {
            expect(reason('?search=climate')).toBeNull();
        });
    });

    describe('no false positives on clean requests', () => {
        it('returns null for a bare entity list', () => {
            expect(reason('')).toBeNull();
        });
        it('returns null for search + sort + per-page', () => {
            expect(reason('?search=foo&sort=cited_by_count:desc&per-page=25')).toBeNull();
        });
    });
});
