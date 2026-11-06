// The paid Profile Doctor (oxjob #2055): fix GETs and POSTs go through the credit limiter at 0 credits, reach the
// openalex-author-fixes app with the origin key and the caller's remaining credits, and are settled in either direction
// to what the app answers (X-Credits-Cost: holds; X-Credits-Refund: the rest of a hold once its fix is priced).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { classifyEndpoint } from './endpointClassifier';
import { authorFixesRequest, isBilledFixesRequest } from './authorFixes';
import { profileFixCredits } from './creditReconcile';
import { ORIGIN_KEY_HEADER } from './originKey';
import { runWorker } from './testHarness';
import { RateLimiter } from './rateLimiter';

vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, params: string[]) {
            if (params[0] !== 'CUSTKEY1') return { rows: [] };
            return { rows: [{ max_per_day: 10000, max_credits_per_day: 10000, is_grandfathered: false,
                onetime_credits_balance: 100000, plan: null, rate_throttled: false, throttle_scope: null,
                user_id: 'user-cust', org_id: null }] };
        }
        async end() {}
    },
}));

const FIXES = 'https://fixes.example.herokuapp.com';
const ENV = { HYPERDRIVE: { connectionString: 'postgres://test' }, AUTHOR_FIXES_URL: FIXES, ORIGIN_SHARED_SECRET: 'sekret' };
const KEY = { Authorization: 'Bearer CUSTKEY1' };

describe('which fix requests are billed', () => {
    it('GET, HEAD and POST on every fixes route; PATCH stays on the uncharged path', () => {
        for (const p of ['/authors/A5023888391/fixes', '/authors/A5023888391/fixes/F1001', '/authors/A5023888391/fix_estimate',
                         '/fixes', '/fixes/', '/fixes/estimate', '/fixes/queue']) {
            expect(isBilledFixesRequest(p, 'GET')).toBe(true);
            expect(isBilledFixesRequest(p, 'post')).toBe(true);
            expect(classifyEndpoint(p, new URLSearchParams(), { method: 'POST' })).toEqual({ type: 'profile_fix', creditCost: 0 });
        }
        expect(isBilledFixesRequest('/authors/A5023888391/fixes/F1001', 'PATCH')).toBe(false);
        for (const p of ['/authors/A5023888391', '/fixes/F1', '/fixesx', '/works/W1/fixes']) {
            expect(isBilledFixesRequest(p, 'GET')).toBe(false);
        }
    });
});

describe('profileFixCredits', () => {
    it('is cost less refund, nothing on an error, and ignores bad values', () => {
        expect(profileFixCredits(202, '5000', null)).toBe(5000);
        expect(profileFixCredits(200, '0', '3000')).toBe(-3000);
        expect(profileFixCredits(200, '700', '200')).toBe(500);
        expect(profileFixCredits(402, '5000', null)).toBe(0);
        expect(profileFixCredits(500, null, '3000')).toBe(0);
        expect(profileFixCredits(200, '-5', 'abc')).toBe(0);
        expect(profileFixCredits(200, null, null)).toBe(0);
    });
});

describe('authorFixesRequest', () => {
    it('sends the key as a header, the remaining credits and the origin key; drops a client copy of either', async () => {
        const req = new Request('https://api.openalex.org/fixes?batch=B1&api_key=CUSTKEY1', {
            method: 'POST', headers: { 'Content-Type': 'application/json', [ORIGIN_KEY_HEADER]: 'forged', 'X-Credits-Remaining': '999999999' },
            body: '{"authors":["A1"]}',
        });
        const out = await authorFixesRequest(req, FIXES, {
            authorization: 'Bearer CUSTKEY1', creditsRemaining: 1234.7,
            env: { OPENALEX_API_URL: 'https://origin.test', TEXT_API_URL: 'https://text.test', AUTHOR_FIXES_URL: FIXES, ORIGIN_SHARED_SECRET: 'sekret' },
        });
        expect(out.url).toBe(`${FIXES}/fixes?batch=B1`);
        expect(out.headers.get('Authorization')).toBe('Bearer CUSTKEY1');
        expect(out.headers.get('X-Credits-Remaining')).toBe('1234');
        expect(out.headers.get(ORIGIN_KEY_HEADER)).toBe('sekret');
        expect(await out.text()).toBe('{"authors":["A1"]}');
    });
    it('never sends the origin key to another host', async () => {
        const out = await authorFixesRequest(new Request('https://api.openalex.org/fixes'), 'https://elsewhere.example.com', {
            authorization: null, env: { OPENALEX_API_URL: 'https://origin.test', TEXT_API_URL: 'https://text.test', AUTHOR_FIXES_URL: FIXES, ORIGIN_SHARED_SECRET: 'sekret' },
        });
        expect(out.headers.get(ORIGIN_KEY_HEADER)).toBeNull();
    });
});

describe('settling through the whole Worker', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    const app = (status: number, headers: Record<string, string>, seen: Request[] = []) => async (url: string, init?: RequestInit) => {
        seen.push(new Request(url, init));
        return new Response('{"ok":true}', { status, headers: { 'Content-Type': 'application/json', ...headers } });
    };

    it('a submit holds what the app says, a later call gives the rest back, an error settles nothing', async () => {
        const limiters = new Map<string, RateLimiter>();
        const seen: Request[] = [];
        const submit = await runWorker('/fixes', {
            method: 'POST', body: '{"authors":["A5023888391"]}', headers: { ...KEY, 'Content-Type': 'application/json' },
            env: ENV, limiters, fetch: app(202, { 'X-Credits-Cost': '25000' }, seen),
        });
        expect(submit.res.status).toBe(202);
        expect(submit.checks[0]).toMatchObject({ bucket: 'credits:user:user-cust' });   // one budget per person (oxjob #1725)
        // 10,000 daily first, then 15,000 of the 100,000 prepaid
        expect(submit.res.headers.get('X-RateLimit-Remaining')).toBe('0');
        expect(submit.res.headers.get('X-RateLimit-Onetime-Remaining')).toBe('85000');
        expect(submit.res.headers.get('X-RateLimit-Credits-Used')).toBe('25000');
        expect(submit.res.headers.get('X-Credits-Cost')).toBeNull();
        const sent = seen[0];
        expect(sent.url).toBe(`${FIXES}/fixes`);
        expect(sent.headers.get(ORIGIN_KEY_HEADER)).toBe('sekret');
        expect(sent.headers.get('X-Credits-Remaining')).toBe('110000');
        expect(sent.headers.get('Authorization')).toBe('Bearer CUSTKEY1');

        const refused = await runWorker('/fixes', {
            method: 'POST', body: '{"authors":["A1"]}', headers: KEY, env: ENV, limiters,
            fetch: app(402, { 'X-Credits-Cost': '99999' }),
        });
        expect(refused.res.status).toBe(402);
        expect(refused.res.headers.get('X-RateLimit-Onetime-Remaining')).toBe('85000');

        const poll = await runWorker('/fixes?batch=B1', {
            headers: KEY, env: ENV, limiters, fetch: app(200, { 'X-Credits-Cost': '0', 'X-Credits-Refund': '18000' }),
        });
        expect(poll.res.status).toBe(200);
        expect(poll.res.headers.get('X-Credits-Refund')).toBeNull();
        expect(poll.res.headers.get('X-RateLimit-Credits-Used')).toBe('-18000');
        // The submit's prepaid spend was written back meanwhile (consumed reset to 0, the balance now 85,000). The refund still
        // returns all 15,000 prepaid first, then 3,000 to today's pool: the final 7,000 is paid from the daily pool.
        expect(poll.res.headers.get('X-RateLimit-Onetime-Remaining')).toBe('100000');
        expect(poll.res.headers.get('X-RateLimit-Remaining')).toBe('3000');
    });

    it('a PATCH goes straight to the app, uncharged, as before', async () => {
        const seen: Request[] = [];
        const { res, checks } = await runWorker('/authors/A5023888391/fixes/F1001', {
            method: 'PATCH', body: '{"state":"applied"}', headers: KEY, env: ENV, fetch: app(202, {}, seen),
        });
        expect(res.status).toBe(202);
        expect(checks).toEqual([]);
        expect(seen[0].url).toBe(`${FIXES}/authors/A5023888391/fixes/F1001`);
    });

    it('a failed call to the app is free', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {});
        const { res } = await runWorker('/fixes', {
            method: 'POST', body: '{}', headers: KEY, env: ENV, fetch: async () => { throw new Error('down'); },
        });
        expect(res.status).toBe(502);
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('0');
    });
});
