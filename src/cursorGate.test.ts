import { describe, expect, it } from 'vitest';
import { isKeylessCursorPage } from './cursorGate';

const u = (q: string) => new URL(`https://api.openalex.org/works?${q}`);
const PAGE2 = 'IlsnLUluZmluaXR5JywgMCwgJ2h0dHBzOi8vb3BlbmFsZXgub3JnL1cxMjMnXSI=';

describe('isKeylessCursorPage (oxjob #1682)', () => {
    it('blocks a keyless page-2 cursor', () => {
        expect(isKeylessCursorPage(u(`search=x&cursor=${PAGE2}`), false, false)).toBe(true);
    });
    it('lets the first page (cursor=*) through keyless', () => {
        expect(isKeylessCursorPage(u('search=x&cursor=*'), false, false)).toBe(false);
        expect(isKeylessCursorPage(u('search=x&cursor=%2A'), false, false)).toBe(false);
    });
    it('lets requests without a cursor through', () => {
        expect(isKeylessCursorPage(u('search=x&page=2'), false, false)).toBe(false);
    });
    it('exempts keyed callers and the website', () => {
        expect(isKeylessCursorPage(u(`cursor=${PAGE2}`), true, false)).toBe(false);
        expect(isKeylessCursorPage(u(`cursor=${PAGE2}`), false, true)).toBe(false);
    });
    it('catches a page-2 cursor hidden behind a duplicate cursor=*', () => {
        expect(isKeylessCursorPage(u(`cursor=*&cursor=${PAGE2}`), false, false)).toBe(true);
    });
});
