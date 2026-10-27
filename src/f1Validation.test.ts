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
        // oxjob #1883: a comma inside a search filter's value is text unless `key:` follows it
        it('keeps a comma inside a search value', () => {
            expect(splitFilterString('title.search:Music and British Culture, 1785'))
                .toEqual(['title.search:Music and British Culture, 1785']);
            expect(splitFilterString('abstract.search:3,4-methylenedioxymethamphetamine treatment'))
                .toEqual(['abstract.search:3,4-methylenedioxymethamphetamine treatment']);
        });
        it('still splits a search value from the next filter', () => {
            expect(splitFilterString('title.search:Music and British Culture, 1785,type:book'))
                .toEqual(['title.search:Music and British Culture, 1785', 'type:book']);
            expect(splitFilterString('title.search:cancer,publication-year:2020'))
                .toEqual(['title.search:cancer', 'publication-year:2020']);
        });
        it('still splits a non-search value at every comma', () => {
            expect(splitFilterString('type:article,book')).toEqual(['type:article', 'book']);
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
            // 'type:article,book' splits into ['type:article', 'book'] -> 2nd has no colon
            expect(reason('?filter=type:article,book')).toBe('raw_comma_filter');
        });
        it('does NOT reject a comma inside a search value, raw or %2C (oxjob #1883)', () => {
            expect(reason('?filter=title.search:climate change, biodiversity loss')).toBeNull();
            expect(reason('?filter=title.search:climate%2C+biodiversity')).toBeNull();
            expect(reason('?filter=title.search%3AMusic%20and%20British%20Culture%2C%201785%2Ctype%3Abook')).toBeNull();
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

describe('splitFilterString runs in linear time with the same output (oxjob #1886)', () => {
    // The splitter as #1883 shipped it (eedc2ee): it searched for the segment's colon and key at every comma.
    const NEXT = /[A-Za-z_][A-Za-z0-9_.\-]*:/y;
    function reference(f: string): string[] {
        const parts: string[] = [];
        let start = 0;
        let inQuotes = false;
        for (let i = 0; i < f.length; i++) {
            const c = f[i];
            if (c === '"') inQuotes = !inQuotes;
            else if (c === ',' && !inQuotes) {
                const colon = f.indexOf(':', start);
                const inSearchValue = colon >= 0 && colon < i && f.slice(start, colon).includes('search');
                NEXT.lastIndex = i + 1;
                if (inSearchValue && !NEXT.test(f)) continue;
                if (i > start) parts.push(f.slice(start, i));
                start = i + 1;
            }
        }
        if (f.length > start) parts.push(f.slice(start));
        return parts;
    }

    it('matches the old splitter on 20,000 random filters', () => {
        const atoms = ['title.search', 'text.search', 'type', ':', ',', ' ', '"', 'a', 'B c', 'search', '|', '1', '.', '-', '_x:'];
        let seed = 1886;
        const rand = (n: number) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
        for (let k = 0; k < 20_000; k++) {
            let f = '';
            const len = rand(14);
            for (let j = 0; j < len; j++) f += atoms[rand(atoms.length)];
            expect(splitFilterString(f), f).toEqual(reference(f));
        }
    });

    it.each([
        ['commas with no colon', 'a,'.repeat(8000)],
        ['a search key, then a value of commas', 'x'.repeat(4000) + 'search:' + ',a'.repeat(6000)],
        ['many short search filters', 'title.search:a,'.repeat(1100)],
    ])('a 16 KB hostile filter (%s) splits in well under a millisecond per KB', (_name, f) => {
        const t = performance.now();
        for (let r = 0; r < 5; r++) splitFilterString(f);
        expect((performance.now() - t) / 5).toBeLessThan(5);
        expect(splitFilterString(f)).toEqual(reference(f));
    });
});
