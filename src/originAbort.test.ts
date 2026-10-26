import { describe, it, expect } from 'vitest';
import { originAbortMs, ORIGIN_ABORT_MS, OQL_ORIGIN_ABORT_MS } from './originAbort';
import { requestOqlText } from './syncGate';

const params = (qs: string) => new URL(`https://api.openalex.org/${qs}`).searchParams;

describe('originAbortMs (oxjob #1598)', () => {
    it('keeps 9 s for plain requests', () => {
        expect(ORIGIN_ABORT_MS).toBe(9000);
        expect(originAbortMs(requestOqlText(params('works?filter=publication_year:2020'), null))).toBe(9000);
        expect(originAbortMs(requestOqlText(params('works?group_by=authorships.author.id'), null))).toBe(9000);
    });

    it('waits 12 s for OQL, past the engine\'s own 11 s deadline', () => {
        expect(OQL_ORIGIN_ABORT_MS).toBe(12000);
        expect(originAbortMs(requestOqlText(params(''), { oql: 'get the count of all works by author' }))).toBe(12000);
        expect(originAbortMs(requestOqlText(params('?format=csv&cursor=*'), { oql: 'get the count of all works by author' }))).toBe(12000);
        expect(originAbortMs(requestOqlText(params('?oql=' + encodeURIComponent('works where year is 2025')), null))).toBe(12000);
        expect(originAbortMs(requestOqlText(params('?oqo=' + encodeURIComponent('{"get_rows":"works"}')), null))).toBe(12000);
        expect(originAbortMs(requestOqlText(params(''), { oqo: { get_rows: 'works' } }))).toBe(12000);
    });

    it('a POST body without OQL keeps 9 s', () => {
        expect(originAbortMs(requestOqlText(params('works'), { filter: 'x' }))).toBe(9000);
    });
});
