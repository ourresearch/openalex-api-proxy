// What a caller is told about per-second limits (oxjob #2374): /rate-limit lists them, every per-second 429 names its
// limit and leaves the day's budget as it is (oxjob #2301), and the boolean 429 states the rate a client can count on
// while the gate keeps its own.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { runWorker } from './testHarness';
import { RateLimiter } from './rateLimiter';

const rows: Record<string, Record<string, unknown>> = {
    'free-key': { user_id: 'user-free', org_id: null, plan: null, max_per_day: 10_000, max_credits_per_day: 10_000 },
    'partner-key': { user_id: null, org_id: 'org-partner', plan: 'partner', max_per_day: 2_000_000, max_credits_per_day: 2_000_000 },
    'member-key': { user_id: null, org_id: 'org-member', plan: 'member', max_per_day: 200_000, max_credits_per_day: 200_000 },
};
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, [key]: string[]) {
            const r = rows[key];
            return { rows: r ? [{ is_grandfathered: false, onetime_credits_balance: 0, onetime_credits_expires_at: null,
                rate_throttled: false, throttle_scope: null, budget_key: null, account_created: null, ...r }] : [] };
        }
        async end() {}
    },
}));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };
const bearer = (key: string) => ({ Authorization: `Bearer ${key}` });
const BOOLEAN = '/works?search=' + encodeURIComponent('a OR b OR c OR d OR e OR f OR g');

afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

describe('/rate-limit lists the per-second limits', () => {
    it.each([
        ['free-key', 30, 2],
        ['partner-key', 50, 5],
        ['member-key', 50, 2],
    ])('%s: %d a second, %d broad boolean searches a second', async (key, all, boolean) => {
        const { res } = await runWorker('/rate-limit', { headers: bearer(key), env: HD });
        const body = await res.json() as { rate_limit: { per_second_limits: Record<string, unknown> } };
        expect(body.rate_limit.per_second_limits).toEqual({
            all_requests: all,
            searches_with_more_than_5_boolean_operators: boolean,
            filters_with_more_than_10_topic_or_concept_ids: 1,
            semantic_search: 1,
            docs: 'https://help.openalex.org/api/authentication/#rate-limits',
        });
    });
});

describe('a per-second 429', () => {
    it('reports the day as it is, not as spent', async () => {
        vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-11-17T21:00:00Z') });
        const limiter = new RateLimiter({ storage: { get: async () => undefined, put: async () => {}, setAlarm: async () => {} },
            blockConcurrencyWhile: async (fn: () => Promise<void>) => fn() } as any);
        await new Promise(r => setTimeout(r, 0));
        const check = async () => (await limiter.fetch(new Request('http://internal/check', {
            method: 'POST', body: JSON.stringify({ dailyLimit: 10_000, perSecondLimit: 2, credits: 1, onetimeBalance: 500 }),
        }))).json() as Promise<Record<string, unknown>>;
        await check(); await check();
        expect(await check()).toMatchObject({ success: false, limitType: 'per_second', remaining: 9_998, onetimeRemaining: 500 });
    });

    it('names the limit and shows the budget left', async () => {
        vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-11-17T21:00:00Z') });
        const limiters = new Map();
        let res: Response | undefined;
        for (let i = 0; i <= 30; i++) {
            ({ res } = await runWorker('/works/W1', { headers: bearer('free-key'), env: HD, limiters }));
        }
        expect(res!.status).toBe(429);
        const body = await res!.json() as Record<string, unknown>;
        expect(body).toMatchObject({ reason: 'requests_per_second', perSecondLimit: 30, dailyRemainingUsd: 1 });
        expect(String(body.message)).toContain('30 requests per second');
        expect(res!.headers.get('X-RateLimit-Remaining')).toBe('10000');
    });
});

describe('the broad boolean search 429', () => {
    it('states 5 a second on a paid plan while the gate stays at one per 40 ms', async () => {
        vi.useFakeTimers({ toFake: ['Date'], now: new Date('2026-11-17T21:00:00.000Z') });
        const limiters = new Map();
        const send = () => runWorker(BOOLEAN, { headers: bearer('partner-key'), env: HD, limiters });
        expect((await send()).res.status).toBe(200);
        vi.setSystemTime(new Date('2026-11-17T21:00:00.020Z'));
        const { res } = await send();
        expect(res.status).toBe(429);
        const body = await res.json() as Record<string, unknown>;
        expect(body).toMatchObject({ reason: 'broad_boolean_query', perSecondLimit: 5 });
        expect(String(body.message)).toContain('limited to 5 a second');
        vi.setSystemTime(new Date('2026-11-17T21:00:00.041Z'));
        expect((await send()).res.status).toBe(200);
    });
});
