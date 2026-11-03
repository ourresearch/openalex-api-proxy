import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { RateLimiter } from './rateLimiter';
import { fakeState, runWorker } from './testHarness';
import { checkFirstDollar, firstDollarPaceFor, FIRST_DOLLAR_CREDITS, FIRST_DOLLAR_DEFAULT_PACE, FIRST_DOLLAR_SINCE } from './firstDollar';

// oxjob #1740: a free account made after the pace went live spends its first $1 at most 1,000 credits per 5 minutes.

const db = { keys: new Map<string, Record<string, unknown>>() };
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, [key]: string[]) { const row = db.keys.get(key); return { rows: row ? [row] : [] }; }
        async end() {}
    },
}));
const NEW = new Date(FIRST_DOLLAR_SINCE + 86_400_000).toISOString();   // made a day after the pace went live
const OLD = '2026-01-15T09:00:00.000Z';
const row = (user_id: string | null, account_created: string | null, o: Record<string, unknown> = {}) => ({
    max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
    onetime_credits_expires_at: null, plan: null, rate_throttled: false, throttle_scope: null, user_id, org_id: null,
    account_created, ...o,
});
db.keys.set('fd-new', row('user-fd-new', NEW));
db.keys.set('fd-new-rotated', row('user-fd-new', NEW));                 // the same person's other key
db.keys.set('fd-old', row('user-fd-old', OLD));
db.keys.set('fd-paid', row('user-fd-paid', NEW, { plan: 'member', max_per_day: 1_000_000, max_credits_per_day: 1_000_000 }));
db.keys.set('fd-prepaid', row('user-fd-prepaid', NEW, { onetime_credits_balance: 50_000, onetime_credits_expires_at: '2099-01-01' }));
db.keys.set('fd-org', row(null, null, { org_id: 'org-Acme', max_per_day: 100_000, max_credits_per_day: 100_000 }));
db.keys.set('fd-off', row('user-fd-off', NEW));

describe('firstDollarPaceFor', () => {
    it('paces only free accounts made after the pace went live', () => {
        expect(firstDollarPaceFor(true, FIRST_DOLLAR_SINCE)).toBe(FIRST_DOLLAR_DEFAULT_PACE);
        expect(firstDollarPaceFor(true, FIRST_DOLLAR_SINCE - 1)).toBe(0);
        expect(firstDollarPaceFor(false, FIRST_DOLLAR_SINCE)).toBe(0);
        expect(firstDollarPaceFor(true, null)).toBe(0);
    });
    it('reads FIRST_DOLLAR_PACE_CREDITS: unset = default, 0 = off', () => {
        expect(firstDollarPaceFor(true, FIRST_DOLLAR_SINCE, '')).toBe(FIRST_DOLLAR_DEFAULT_PACE);
        expect(firstDollarPaceFor(true, FIRST_DOLLAR_SINCE, '500')).toBe(500);
        expect(firstDollarPaceFor(true, FIRST_DOLLAR_SINCE, '0')).toBe(0);
        expect(firstDollarPaceFor(true, FIRST_DOLLAR_SINCE, 'nonsense')).toBe(0);
    });
});

describe('the first-dollar bucket', () => {
    it('lets a request dearer than the whole window through once full, then waits', () => {
        const s = { spent: 0, tokens: 1000, lastRefill: 0 };
        expect(checkFirstDollar(s, 1000, 1500, 0).ok).toBe(true);
        s.tokens -= 1500;
        expect(checkFirstDollar(s, 1000, 10, 1000).ok).toBe(false);
    });
});

const DAY = new Date('2026-11-05T12:00:00Z');

async function newLimiter(state = fakeState()) {
    const limiter = new RateLimiter(state as any);
    await vi.advanceTimersByTimeAsync(0);
    const call = async (path: string, credits: number, firstDollarPace = 1000) => (await limiter.fetch(new Request(`http://internal${path}`, {
        method: 'POST',
        body: JSON.stringify({ dailyLimit: 10_000, perSecondLimit: 1000, credits, firstDollarPace }),
    }))).json() as Promise<{ success: boolean; limitType?: string; retryAfter?: number }>;
    return { state, check: (credits: number, pace = 1000) => call('/check', credits, pace), charge: (credits: number) => call('/charge', credits) };
}

describe('RateLimiter first-dollar pace', () => {
    beforeEach(() => { vi.useFakeTimers({ now: DAY }); });
    afterEach(() => { vi.useRealTimers(); });

    it('allows 1,000 credits per 5 minutes, then asks the caller to wait', async () => {
        const { check } = await newLimiter();
        for (let i = 0; i < 10; i++) expect((await check(100)).success).toBe(true);
        const refused = await check(100);
        expect(refused).toMatchObject({ success: false, limitType: 'first_dollar' });
        expect(refused.retryAfter).toBe(30);   // 100 credits refill in 30 s at 1,000 per 300 s
        await vi.advanceTimersByTimeAsync(30_000);
        expect((await check(100)).success).toBe(true);
    });

    it('lifts once the account has spent its first $1', async () => {
        const { check } = await newLimiter();
        let spent = 0;
        while (spent < FIRST_DOLLAR_CREDITS) {      // spend at the pace: about 50 minutes for the first $1
            if ((await check(100)).success) spent += 100;
            else await vi.advanceTimersByTimeAsync(30_000);
        }
        expect(Date.now() - DAY.getTime()).toBeGreaterThanOrEqual(45 * 60_000);
        await vi.advanceTimersByTimeAsync(86_400_000);  // next day: a fresh daily budget, no pace
        for (let i = 0; i < 30; i++) expect((await check(100)).success).toBe(true);
    });

    it("can't be dodged by a tiny warm-up call and a burst a day later", async () => {
        const { check } = await newLimiter();
        expect((await check(1)).success).toBe(true);
        await vi.advanceTimersByTimeAsync(86_400_000);
        let ok = 0;
        for (let i = 0; i < 30; i++) if ((await check(100)).success) ok++;
        expect(ok).toBe(10);
    });

    it('counts a query priced after it ran (/charge) against the pace', async () => {
        const { check, charge } = await newLimiter();
        expect((await check(1)).success).toBe(true);
        await charge(999);                          // the rest of its price, settled after the origin answered
        expect((await check(1)).success).toBe(false);
    });

    it('stores spent in the daily counter and remembers it across an evicted object', async () => {
        const { state, check } = await newLimiter();
        await check(300);
        await vi.advanceTimersByTimeAsync(10_000);
        await check(100);   // past the write-behind window: this request triggers the write
        await vi.advanceTimersByTimeAsync(0);
        expect(state.store.get('counter')).toMatchObject({ count: 400, fd: 400 });
        expect(state.store.has('first_dollar')).toBe(false);   // no extra storage key

        const graduated = await newLimiter(fakeState({ counter: { count: 0, date: '2026-11-01', fd: FIRST_DOLLAR_CREDITS } }));
        for (let i = 0; i < 30; i++) expect((await graduated.check(100)).success).toBe(true);
    });

    it('does nothing without a pace', async () => {
        const { state, check } = await newLimiter();
        for (let i = 0; i < 100; i++) expect((await check(100, 0)).success).toBe(true);
        await vi.advanceTimersByTimeAsync(10_000);
        await check(0, 0);
        expect(state.store.get('counter')).not.toHaveProperty('fd');
    });
});

// The whole Worker: a search costs 10 credits, so a pace of 50 lets 5 through.
describe('first-dollar pace in the Worker', () => {
    const search = (key: string, limiters: Map<string, RateLimiter>, env: Record<string, unknown> = {}) =>
        runWorker(`/works?search=kelp&api_key=${key}`, { limiters, env: { HYPERDRIVE: { connectionString: 'postgres://test' }, FIRST_DOLLAR_PACE_CREDITS: '50', ...env } });
    const statuses = async (key: string, n: number, env: Record<string, unknown> = {}, limiters = new Map<string, RateLimiter>()) => {
        const out: number[] = [];
        for (let i = 0; i < n; i++) out.push((await search(key, limiters, env)).res.status);
        return out;
    };

    it('paces a new free account and says why', async () => {
        const limiters = new Map<string, RateLimiter>();
        for (let i = 0; i < 5; i++) expect((await search('fd-new', limiters)).res.status).toBe(200);
        const { res, rows } = await search('fd-new', limiters);
        expect(res.status).toBe(429);
        expect(Number(res.headers.get('Retry-After'))).toBeGreaterThan(0);
        expect((await res.json() as { message: string }).message).toMatch(/first \$1/);
        expect(rows.some(r => r.blobs.includes('first-dollar'))).toBe(true);
    });

    it("counts per person, so a rotated key shares the pace", async () => {
        const limiters = new Map<string, RateLimiter>();
        for (let i = 0; i < 3; i++) expect((await search('fd-new', limiters)).res.status).toBe(200);
        for (let i = 0; i < 2; i++) expect((await search('fd-new-rotated', limiters)).res.status).toBe(200);
        expect((await search('fd-new-rotated', limiters)).res.status).toBe(429);
    });

    it('never paces older accounts, paid plans, prepaid balances or org keys', async () => {
        for (const key of ['fd-old', 'fd-paid', 'fd-prepaid', 'fd-org']) {
            expect(await statuses(key, 8), key).toEqual(Array(8).fill(200));
        }
    });

    it('is off with FIRST_DOLLAR_PACE_CREDITS=0', async () => {
        expect(await statuses('fd-off', 8, { FIRST_DOLLAR_PACE_CREDITS: '0' })).toEqual(Array(8).fill(200));
    });
});
