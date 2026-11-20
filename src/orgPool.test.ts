// An org on a contracted daily budget spends one day across all its keys, then its monthly pool (users-api migration 132,
// oxjob #2471). users-api reports the pool's remainder as the org key's prepaid balance and names the org's bucket
// (budget_key `org:<id>`); the Worker spends it like a person's prepaid balance and bills it to the org.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { prepaidWriteback } from './index';
import { runWorker, today, fakeState } from './testHarness';
import { RateLimiter } from './rateLimiter';

const db = vi.hoisted(() => ({
    keys: new Map<string, Record<string, unknown>>(),
    writes: [] as { sql: string; params: unknown[] }[],
}));
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(sql: string, params: unknown[]) {
            if (!sql.includes('api_keys_view')) { db.writes.push({ sql, params }); return { rows: [] }; }
            const row = db.keys.get(params[0] as string);
            return { rows: row ? [row] : [] };
        }
        async end() {}
    },
}));
const orgRow = (o: Record<string, unknown> = {}) => ({
    max_per_day: 100_000, max_credits_per_day: 100_000, is_grandfathered: false, onetime_credits_balance: 0,
    onetime_credits_expires_at: null, plan: 'partner', rate_throttled: false, throttle_scope: null, user_id: null,
    org_id: 'org-Pool', budget_key: 'org:org-Pool', ...o,
});
const POOL = { onetime_credits_balance: 50_000, onetime_credits_expires_at: '2099-01-01T00:00:00' };
db.keys.set('pool-a', orgRow(POOL));
db.keys.set('pool-b', orgRow(POOL));
db.keys.set('pool-c', orgRow(POOL));
db.keys.set('pool-spent', orgRow({ org_id: 'org-Spent', budget_key: 'org:org-Spent', onetime_credits_balance: 0,
    onetime_credits_expires_at: '2099-01-01T00:00:00' }));   // a pool that reads 0 this month
db.keys.set('nopool-b', orgRow({ org_id: 'org-Day2', budget_key: 'org:org-Day2' }));   // used once: the writeback runs only when the key's lookup is fresh, not cached
db.keys.set('nopool-a', orgRow({ org_id: 'org-Day', budget_key: 'org:org-Day' }));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };
const key = (k: string) => ({ Authorization: `Bearer ${k}` });
const daySpent = (bucket: string, onetime = 0) => ({
    [bucket]: { counter: { count: 100_000, date: today() }, onetime: { consumed: onetime } },
});

afterEach(() => { db.writes.length = 0; });

describe('prepaidWriteback', () => {
    it("bills a person's keys to the person, as before", () => {
        expect(prepaidWriteback(700, 'k1', 'user-x', null)).toEqual([expect.stringMatching(/^UPDATE users .* WHERE id = \$2$/), [700, 'user-x']]);
        expect(prepaidWriteback(700, 'k1', 'user-x', 'org-y')).toEqual([expect.stringMatching(/WHERE id = \$2$/), [700, 'user-x']]);
        expect(prepaidWriteback(700, 'k1', null, null)).toEqual([expect.stringMatching(/WHERE api_key = \$2$/), [700, 'k1']]);
    });

    it("bills an org key to its org's monthly pool", () => {
        expect(prepaidWriteback(700, 'k1', null, 'org-y')).toEqual(['SELECT spend_org_monthly_pool($1, $2)', ['org-y', 700]]);
    });
});

describe('all keys of an org on a contracted budget spend one day', () => {
    it('both keys count in the org bucket, with the org budget', async () => {
        for (const k of ['pool-a', 'pool-b']) {
            const { res, checks } = await runWorker('/works', { headers: key(k), env: HD });
            expect(res.status).toBe(200);
            expect(checks[0]).toMatchObject({ bucket: 'credits:org:org-Pool', dailyLimit: 100_000 });
        }
    });

    it('once the day is spent, an org with no pool is refused on every key', async () => {
        const { res } = await runWorker('/works', { headers: key('nopool-a'), env: HD, buckets: daySpent('credits:org:org-Day') });
        expect(res.status).toBe(429);
    });
});

describe("then the org's monthly pool", () => {
    it('once the day is spent, either key keeps going on the pool', async () => {
        for (const k of ['pool-a', 'pool-b']) {
            const { res } = await runWorker('/works', { headers: key(k), env: HD, buckets: daySpent('credits:org:org-Pool') });
            expect(res.status).toBe(200);
            expect(res.headers.get('X-RateLimit-Prepaid-Remaining-USD')).not.toBeNull();
        }
    });

    it('with the day and the pool both spent, the key is refused', async () => {
        const { res } = await runWorker('/works', { headers: key('pool-b'), env: HD, buckets: daySpent('credits:org:org-Pool', 50_000) });
        expect(res.status).toBe(429);
    });

    it("the writeback claims the org bucket's pool spend and bills it to the org", async () => {
        const { res } = await runWorker('/works', { headers: key('pool-c'), env: HD, buckets: { 'credits:org:org-Pool': { onetime: { consumed: 700 } } } });
        expect(res.status).toBe(200);
        expect(db.writes).toEqual([{ sql: 'SELECT spend_org_monthly_pool($1, $2)', params: ['org-Pool', 700] }]);
    });
});

describe('spend let through after the pool reads 0 is still billed this month', () => {
    it('an org key whose pool reads 0 writes back what its bucket consumed', async () => {
        const buckets = { 'credits:org:org-Spent': { onetime: { consumed: 9 } } };
        await runWorker('/works', { headers: key('pool-spent'), env: HD, buckets });
        expect(db.writes).toEqual([{ sql: 'SELECT spend_org_monthly_pool($1, $2)', params: ['org-Spent', 9] }]);
    });

    it('an org with no pool writes nothing back', async () => {
        const buckets = { 'credits:org:org-Day2': { onetime: { consumed: 9 } } };
        await runWorker('/works', { headers: key('nopool-b'), env: HD, buckets });
        expect(db.writes).toEqual([]);
    });
});

describe('each key of the org keeps its own per-second limit inside the shared bucket', () => {
    it('the Worker names the key for an org bucket, and no key for a person', async () => {
        const { checks } = await runWorker('/works', { headers: key('pool-b'), env: HD });
        expect(checks[0]).toMatchObject({ bucket: 'credits:org:org-Pool', perSecondLimit: 50, rateKey: 'pool-b' });
        db.keys.set('person-key', orgRow({ user_id: 'user-q', org_id: null, budget_key: null }));
        const person = await runWorker('/works', { headers: key('person-key'), env: HD });
        expect(person.checks[0].rateKey).toBeUndefined();
    });

    it('one key spending its 50 a second leaves the other key its own 50', async () => {
        const limiter = new RateLimiter(fakeState() as any);
        await new Promise(r => setTimeout(r, 0));
        const check = async (rateKey?: string) => (await (await limiter.fetch(new Request('http://internal/check', {
            method: 'POST', body: JSON.stringify({ dailyLimit: 1_000_000, perSecondLimit: 50, credits: 1, rateKey }),
        }))).json()) as { success: boolean; limitType?: string };
        for (let i = 0; i < 50; i++) expect((await check('key-a')).success).toBe(true);
        expect(await check('key-a')).toMatchObject({ success: false, limitType: 'per_second' });
        expect((await check('key-b')).success).toBe(true);
        expect((await check()).success).toBe(true);   // no key named: the object's own tokens, as before
    });
});
