import { describe, it, expect, vi, afterEach } from 'vitest';
import { actualCreditCost, creditsRemainingForOrigin, settleCredits, splitCharge } from './creditReconcile';
import { RateLimiter } from './rateLimiter';
import worker from './index';

// An in-memory DurableObjectState: enough storage for RateLimiter, nothing else.
function fakeState(initial: Record<string, unknown> = {}) {
    const store = new Map<string, unknown>(Object.entries(initial));
    return {
        store,
        storage: {
            get: async (k: string) => store.get(k),
            put: async (k: string | Record<string, unknown>, v?: unknown) => {
                if (typeof k === 'string') store.set(k, v);
                else for (const [kk, vv] of Object.entries(k)) store.set(kk, vv);
            },
            setAlarm: async () => {},
        },
        blockConcurrencyWhile: async (fn: () => Promise<void>) => fn(),
    };
}

async function newLimiter(initial: Record<string, unknown> = {}) {
    const state = fakeState(initial);
    const limiter = new RateLimiter(state as any);
    await new Promise(r => setTimeout(r, 0)); // let loadFromStorage finish
    const call = (path: string, body: object) =>
        limiter.fetch(new Request(`http://internal${path}`, { method: 'POST', body: JSON.stringify(body) })).then(r => r.json() as Promise<any>);
    return { state, limiter, call };
}

const today = () => new Date().toISOString().split('T')[0];

describe('actualCreditCost (oxjob #1533)', () => {
    it('is the origin plan price on a success', () => {
        expect(actualCreditCost(200, 1, '31')).toBe(31);
        expect(actualCreditCost(200, 10, '0')).toBe(0);
    });

    it('is what /check charged when the origin sends no price', () => {
        expect(actualCreditCost(200, 10, null)).toBe(10);
    });

    it('makes errors free even with a price on them', () => {
        expect(actualCreditCost(429, 1, '31')).toBe(0);
        expect(actualCreditCost(400, 10, null)).toBe(0);
        expect(actualCreditCost(500, 1, '5')).toBe(0);
    });

    it('ignores a malformed price', () => {
        for (const bad of ['', ' ', 'abc', '-3', '2.5', 'NaN']) {
            expect(actualCreditCost(200, 10, bad)).toBe(10);
        }
    });
});

describe('creditsRemainingForOrigin', () => {
    it('adds the daily and prepaid pools', () => {
        expect(creditsRemainingForOrigin(99, 500)).toBe(599);
        expect(creditsRemainingForOrigin(undefined, undefined)).toBe(0);
    });
});

describe('splitCharge', () => {
    it('takes the daily pool first, then prepaid', () => {
        expect(splitCharge(30, 100, 0)).toEqual({ daily: 30, onetime: 0 });
        expect(splitCharge(30, 10, 100)).toEqual({ daily: 10, onetime: 20 });
        expect(splitCharge(30, 0, 100)).toEqual({ daily: 0, onetime: 30 });
    });

    it('puts what fits nowhere on the daily counter, never below zero prepaid', () => {
        expect(splitCharge(30, 5, 10)).toEqual({ daily: 20, onetime: 10 });
        expect(splitCharge(30, -4, 0)).toEqual({ daily: 30, onetime: 0 });
    });
});

describe('settleCredits', () => {
    const base = { dailyLimit: 1000, onetimeBalance: 0, remaining: 999, onetimeRemaining: 0 };

    it('does nothing when the price matches the charge', async () => {
        const limiter = { fetch: vi.fn() };
        expect(await settleCredits(limiter, { ...base, charged: 1, actual: 1 })).toEqual({ remaining: 999, onetimeRemaining: 0 });
        expect(limiter.fetch).not.toHaveBeenCalled();
    });

    it('charges the difference when the plan cost more', async () => {
        const limiter = { fetch: vi.fn(async () => Response.json({ remaining: 969, onetimeRemaining: 0 })) };
        expect(await settleCredits(limiter, { ...base, charged: 1, actual: 31 })).toEqual({ remaining: 969, onetimeRemaining: 0 });
        const [url, init] = limiter.fetch.mock.calls[0] as unknown as [string, RequestInit];
        expect(url).toBe('http://internal/charge');
        expect(JSON.parse(init.body as string).credits).toBe(30);
    });

    it('refunds the difference when the plan cost less', async () => {
        const limiter = { fetch: vi.fn(async () => Response.json({ remaining: 1000, onetimeRemaining: 0 })) };
        await settleCredits(limiter, { ...base, charged: 1, actual: 0 });
        const [url, init] = limiter.fetch.mock.calls[0] as unknown as [string, RequestInit];
        expect(url).toBe('http://internal/refund');
        expect(JSON.parse(init.body as string).credits).toBe(1);
    });

    it('keeps the /check balances when the limiter fails', async () => {
        const limiter = { fetch: vi.fn(async () => { throw new Error('DO down'); }) };
        vi.spyOn(console, 'error').mockImplementation(() => {});
        expect(await settleCredits(limiter, { ...base, charged: 1, actual: 31 })).toEqual({ remaining: 999, onetimeRemaining: 0 });
    });
});

describe('RateLimiter /charge (oxjob #1533)', () => {
    it('charges the daily pool and persists it at once', async () => {
        const { state, call } = await newLimiter({ counter: { count: 1, date: today() } });
        const r = await call('/charge', { dailyLimit: 1000, credits: 30, onetimeBalance: 0 });
        expect(r).toEqual({ charged: 30, remaining: 969, onetimeRemaining: 0 });
        expect(state.store.get('counter')).toEqual({ count: 31, date: today() });
    });

    it('spills into prepaid when the daily pool runs out', async () => {
        const { state, call } = await newLimiter({ counter: { count: 990, date: today() }, onetime: { consumed: 0 } });
        const r = await call('/charge', { dailyLimit: 1000, credits: 30, onetimeBalance: 500 });
        expect(r).toEqual({ charged: 30, remaining: 0, onetimeRemaining: 480 });
        expect(state.store.get('onetime')).toEqual({ consumed: 20 });
    });

    it('is undone by /refund', async () => {
        const { call } = await newLimiter();
        await call('/charge', { dailyLimit: 1000, credits: 30, onetimeBalance: 0 });
        const r = await call('/refund', { dailyLimit: 1000, credits: 30, onetimeBalance: 0 });
        expect(r.remaining).toBe(1000);
    });
});

// The whole API path: /check charges up front, the origin answers, the proxy settles.
describe('API path settles the origin plan price (oxjob #1533)', () => {
    afterEach(() => vi.unstubAllGlobals());

    async function run(path: string, origin: { status: number; headers?: Record<string, string> }, init?: RequestInit) {
        const { limiter, state } = await newLimiter();
        const originRequests: Request[] = [];
        vi.stubGlobal('fetch', vi.fn(async (input: Request | string, reqInit?: RequestInit) => {
            originRequests.push(input instanceof Request ? input : new Request(input, reqInit));
            return new Response('{"meta":{}}', { status: origin.status, headers: { 'Content-Type': 'application/json', ...origin.headers } });
        }));
        const env = {
            OPENALEX_API_URL: 'https://origin.test',
            FORCE_HEALTH_STATE: 'GREEN',
            RATE_LIMITER: {
                idFromName: (n: string) => n,
                get: () => ({ fetch: (u: string, i?: RequestInit) => limiter.fetch(new Request(u, i)) }),
            },
            ANALYTICS: { writeDataPoint: () => {} },
        };
        const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
        const res = await worker.fetch(new Request(`https://api.openalex.org${path}`, init), env as any, ctx as any);
        return { res, originRequests, state };
    }

    const OQL = '/works?oql=' + encodeURIComponent('get works where year >= (2010)');

    it('charges a 31-credit plan 30 more than the 1 credit taken up front', async () => {
        const { res, state } = await run(OQL, { status: 200, headers: { 'X-Credits-Cost': '31' } });
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('31');
        expect(res.headers.get('X-RateLimit-Cost-USD')).toBe('0.0031');
        expect((state.store.get('counter') as any).count).toBe(31);
        expect(res.headers.get('X-Credits-Cost')).toBeNull();
    });

    it('refunds the up-front charge when the plan is free', async () => {
        const { res, state } = await run(OQL, { status: 200, headers: { 'X-Credits-Cost': '0' } });
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('0');
        expect((state.store.get('counter') as any).count).toBe(0);
        expect(res.headers.get('X-Credits-Cost')).toBeNull();
    });

    it('makes a 4xx with a price on it free', async () => {
        const { res, state } = await run(OQL, { status: 429, headers: { 'X-Credits-Cost': '31' } });
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('0');
        expect((state.store.get('counter') as any).count).toBe(0);
        expect(res.headers.get('X-Credits-Cost')).toBeNull();
    });

    it('charges the up-front price when the origin sends none', async () => {
        const { res } = await run('/works?filter=publication_year:2020', { status: 200 });
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('1');
    });

    it('tells the origin what the caller has left after the up-front charge', async () => {
        const { originRequests } = await run(OQL, { status: 200 });
        // anonymous: 1,000 a day (no key, no prepaid), 1 taken up front
        expect(originRequests[0].headers.get('X-Credits-Remaining')).toBe('999');
        expect(originRequests[0].headers.get('X-Cost-USD')).toBe('0.0001');
        // only a grandfathered key is flagged; anonymous callers never are
        expect(originRequests[0].headers.get('X-Credits-Grandfathered')).toBeNull();
    });

    it('sends X-Credits-Remaining on a POST to the OQL door too', async () => {
        const { originRequests } = await run('/', { status: 200 }, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oql: 'works' }),
        });
        expect(originRequests[0].headers.get('X-Credits-Remaining')).not.toBeNull();
    });

    it('/query costs nothing', async () => {
        const { res, state } = await run('/query/oql/' + encodeURIComponent('works where year > (2020)'), { status: 200 });
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('0');
        expect((state.store.get('counter') as any)?.count ?? 0).toBe(0);
    });
});
