// A repeated query parameter is priced, gated and forwarded on one value: the last, which is what the origin has
// always run (oxjob #1762). Before, pricing and gates read the first (URLSearchParams.get) while the forwarder sent
// the last, so a cheap-looking first value bought the expensive last one.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { lastValuePerParam } from './index';
import { RateLimiter } from './rateLimiter';
import { runWorker } from './testHarness';

// A keyed request looks its key up in api_keys_view: this fake database knows one free key.
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, [key]: string[]) {
            return { rows: key !== 'good-key' ? [] : [{
                max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
                onetime_credits_expires_at: null, plan: null, rate_throttled: false, throttle_scope: null,
                user_id: 'user-good', org_id: null,
            }] };
        }
        async end() {}
    },
}));

// A stub origin that records the URL it was asked for.
function origin() {
    const forwarded: string[] = [];
    const fetch = async (input: string | Request) => {
        forwarded.push(typeof input === 'string' ? input : input.url);
        return new Response('{"meta":{}}', { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    return { forwarded, fetch };
}
const query = (u: string) => new URL(u).searchParams;
const credits = (res: Response) => res.headers.get('X-RateLimit-Credits-Used');

describe('lastValuePerParam', () => {
    it('keeps the last value of a repeated key, in first-seen key order', () => {
        const u = new URL('https://api.openalex.org/works?per_page=1&search=x&per_page=100&rerank=false&rerank=true');
        lastValuePerParam(u);
        expect([...u.searchParams]).toEqual([['per_page', '100'], ['search', 'x'], ['rerank', 'true']]);
    });

    it('leaves a URL with no repeated key byte for byte', () => {
        const raw = 'https://api.openalex.org/works?filter=title.search:coral%20reef,publication_year:2020&mailto=a@b.org';
        const u = new URL(raw);
        lastValuePerParam(u);
        expect(u.toString()).toBe(raw);
    });
});

describe('a repeated parameter is priced and gated on the value the origin runs (oxjob #1762)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it('a leading autocomplete shape no longer makes a 100-row search free', async () => {
        const o = origin();
        const { res } = await runWorker(
            '/works?search=quantum&per_page=1&select=id,display_name,works_count&per_page=100&select=id,title,doi', { fetch: o.fetch });
        expect(res.status).toBe(200);
        expect(credits(res)).toBe('10');
        expect(query(o.forwarded[0]).get('per_page')).toBe('100');
        expect(query(o.forwarded[0]).get('select')).toBe('id,title,doi');
    });

    it('a leading plain filter no longer prices a title.search as a list', async () => {
        const o = origin();
        const { res } = await runWorker('/works?filter=type:article&filter=title.search:quantum', { fetch: o.fetch });
        expect(credits(res)).toBe('10');
        expect(query(o.forwarded[0]).getAll('filter')).toEqual(['title.search:quantum']);
    });

    it('rerank=false&rerank=true pays the rerank surcharge', async () => {
        const o = origin();
        const { res } = await runWorker('/works?search=quantum&rerank=false&rerank=true', { fetch: o.fetch });
        expect(credits(res)).toBe('20');
        expect(query(o.forwarded[0]).get('rerank')).toBe('true');
    });

    it('at YELLOW or above a repeated rerank is dropped like a single one', async () => {
        const o = origin();
        await runWorker('/works?filter=type:article&rerank=false&rerank=true', { fetch: o.fetch, env: { FORCE_HEALTH_STATE: 'YELLOW' } });
        expect(query(o.forwarded[0]).has('rerank')).toBe(false);
    });

    it('a keyless repeated-parameter search meets the anonymous-search shed', async () => {
        const o = origin();
        for (const path of ['/works?search=quantum&per_page=1&select=id,display_name,works_count&per_page=100',
                            '/works?filter=type:article&filter=title.search:quantum']) {
            const { res, checks } = await runWorker(path, { fetch: o.fetch, env: { FORCE_HEALTH_STATE: 'RED' } });
            expect(res.status).toBe(503);
            expect(checks).toEqual([]);
        }
        expect(o.forwarded).toEqual([]);
    });

    it('a broad boolean title.search behind a plain filter meets the boolean throttle', async () => {
        const limiters = new Map<string, RateLimiter>();
        const path = '/works?filter=type:article&filter=title.search:(a OR b OR c OR d OR e OR f OR g)';
        expect((await runWorker(path, { limiters })).res.status).toBe(200);
        const second = await runWorker(path, { limiters });
        expect(second.res.status).toBe(429);
        expect((await second.res.json() as { reason: string }).reason).toBe('broad_boolean_query');
    });

    it('a constant first search.semantic no longer passes different searches as one', async () => {
        const limiters = new Map<string, RateLimiter>();
        const env = { FORCE_SEMANTIC_HEALTH_STATE: 'GREEN' };
        expect((await runWorker('/works?search.semantic=x&search.semantic=real+query+0', { limiters, env })).res.status).toBe(200);
        expect((await runWorker('/works?search.semantic=x&search.semantic=real+query+1', { limiters, env })).res.status).toBe(429);
    });

    it('a repeated api_key is looked up, billed and forwarded as the last one', async () => {
        const o = origin();
        const { res, checks } = await runWorker('/works?api_key=not-a-key&api_key=good-key', { fetch: o.fetch, env: { HYPERDRIVE: { connectionString: 'postgres://test' } } });
        expect(res.status).toBe(200);
        expect(checks[0].bucket).toBe('credits:good-key');
        expect(query(o.forwarded[0]).get('api_key')).toBe('good-key');
    });

    it('gates that read every value (getAll) see the one the origin runs: keyless cursor paging', async () => {
        const page2 = 'IlsnLUluZmluaXR5JywgMCwgJ2h0dHBzOi8vb3BlbmFsZXgub3JnL1cxMjMnXSI=';
        expect((await runWorker(`/works?filter=publication_year:2020&cursor=*&cursor=${page2}`)).res.status).toBe(401);
        // The origin only ever saw the last cursor, so this is a first page and stays keyless.
        expect((await runWorker(`/works?filter=publication_year:2020&cursor=${page2}&cursor=*`)).res.status).toBe(200);
    });
});

// The page-size aliases and group_bys, end to end (oxjob #1762). The origin reads per-page before per_page
// (elastic-api core/utils.py set_number_param), and refuses select only with group_by (core/validate.py), so the
// free autocomplete shape must hold for every spelling the origin may run and never carry a group_bys.
describe('page-size aliases and group_bys are priced on what the origin runs (oxjob #1762)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
    const AUTO = 'search=quantum&select=id,display_name,works_count';

    it.each([
        ['per_page=1&per-page=100'],
        ['per-page=100&per_page=1'],
        ['per-page=1&per-page=100'],            // a repeated alias: the origin runs the last
        ['per_page=1&per-page=1&per-page=100'],
    ])('%s is a 10-credit search', async (q) => {
        const o = origin();
        const { res } = await runWorker(`/works?${AUTO}&${q}`, { fetch: o.fetch });
        expect(res.status).toBe(200);
        expect(credits(res)).toBe('10');
    });

    it.each([['per-page=10'], ['per_page=10'], ['per-page=2&per_page=3']])('%s stays free', async (q) => {
        const o = origin();
        const { res } = await runWorker(`/works?${AUTO}&${q}`, { fetch: o.fetch });
        expect(credits(res)).toBe('0');
    });

    it('a group_bys on the autocomplete shape pays for the search and reaches the origin unchanged', async () => {
        const o = origin();
        const { res } = await runWorker(`/works?${AUTO}&per_page=10&group_bys=type,publication_year`, { fetch: o.fetch });
        expect(credits(res)).toBe('10');
        expect(query(o.forwarded[0]).get('group_bys')).toBe('type,publication_year');
    });
});
