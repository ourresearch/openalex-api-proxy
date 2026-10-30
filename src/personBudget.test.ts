// One daily budget per person, whichever of their keys they use (oxjob #1725). On 30 Oct a farm rotated each free
// account's key every ~5 min (users-api /api-key/rotate) and the proxy, which named the bucket by the key string,
// gave every new string a fresh 10K: 5,140 keys, 44M credits in a day. Driven through the whole Worker.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { creditsBucketFor } from './index';
import { runWorker, today } from './testHarness';
import { RateLimiter } from './rateLimiter';

// api_keys_view rows by key: one person's current key, the key it replaced (still in its grace window) and an agent's
// key; an org key; a person with a prepaid balance.
const db = vi.hoisted(() => ({
    keys: new Map<string, Record<string, unknown>>(),
    writes: [] as { sql: string; params: unknown[] }[],
}));
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(sql: string, params: unknown[]) {
            if (sql.startsWith('UPDATE')) { db.writes.push({ sql, params }); return { rows: [] }; }
            const row = db.keys.get(params[0] as string);
            return { rows: row ? [row] : [] };
        }
        async end() {}
    },
}));
const row = (user_id: string | null, o: Record<string, unknown> = {}) => ({
    max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
    onetime_credits_expires_at: null, plan: null, rate_throttled: false, throttle_scope: null, user_id, org_id: null,
    budget_key: null, ...o,
});
db.keys.set('rot-new', row('user-r1'));
db.keys.set('rot-old', row('user-r1'));                                  // retired by the rotation, still served
db.keys.set('rot-agent', row('user-r1', { budget_key: 'rot-new' }));    // a key an agent asked for
db.keys.set('org-key', row(null, { org_id: 'org-Acme', max_per_day: 100_000, max_credits_per_day: 100_000 }));
db.keys.set('prepaid-key', row('user-p1', { onetime_credits_balance: 50_000, onetime_credits_expires_at: '2099-01-01' }));
db.keys.set('prepaid-old', row('user-p2', { onetime_credits_balance: 50_000, onetime_credits_expires_at: '2099-01-01' }));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };
const key = (k: string) => ({ Authorization: `Bearer ${k}` });
const spent = (bucket: string) => ({ [bucket]: { counter: { count: 10_000, date: today() } } });

afterEach(() => { vi.unstubAllGlobals(); db.writes.length = 0; });

describe('creditsBucketFor', () => {
    it("names a personal key's bucket by its person, else as before", () => {
        expect(creditsBucketFor('k1', null, 'user-x')).toBe('user:user-x');
        expect(creditsBucketFor('agent', 'k1', 'user-x')).toBe('user:user-x');
        expect(creditsBucketFor('org-key', null, null)).toBe('org-key');       // org keys: no person
        expect(creditsBucketFor('agent', 'k1', null)).toBe('k1');              // budgetKey without a person (not served today)
    });
});

describe("a person's keys share one day (oxjob #1725)", () => {
    it('the current key, the retired key and an agent key all count in the person bucket', async () => {
        for (const k of ['rot-new', 'rot-old', 'rot-agent']) {
            const { res, checks } = await runWorker('/works', { headers: key(k), env: HD });
            expect(res.status).toBe(200);
            expect(checks[0]).toMatchObject({ bucket: 'credits:user:user-r1', dailyLimit: 10_000 });
        }
    });

    it('a rotated key buys no fresh day: once the person spent it, the new key and the old one are both refused', async () => {
        for (const k of ['rot-new', 'rot-old', 'rot-agent']) {
            const { res } = await runWorker('/works', { headers: key(k), env: HD, buckets: spent('credits:user:user-r1') });
            expect(res.status).toBe(429);
        }
    });

    it("the day spent under the old per-key name doesn't refuse the person (the switch is at 00:00 UTC)", async () => {
        const { res } = await runWorker('/works', { headers: key('rot-new'), env: HD, buckets: spent('credits:rot-new') });
        expect(res.status).toBe(200);
    });

    it('an org key keeps its own bucket', async () => {
        const { checks } = await runWorker('/works', { headers: key('org-key'), env: HD });
        expect(checks[0]).toMatchObject({ bucket: 'credits:org-key', dailyLimit: 100_000 });
    });

    it('/rate-limit reports the person bucket, from any of their keys', async () => {
        const used = { 'credits:user:user-r1': { counter: { count: 4_000, date: today() } } };
        for (const k of ['rot-new', 'rot-old']) {
            const { res } = await runWorker('/rate-limit', { headers: key(k), env: HD, buckets: used });
            expect(res.status).toBe(200);
            const rl = (await res.json() as { rate_limit: { credits_used: number; credits_remaining: number } }).rate_limit;
            expect(rl).toMatchObject({ credits_used: 4_000, credits_remaining: 6_000 });
        }
    });
});

describe('prepaid credits are billed to the person (oxjob #1725)', () => {
    it('the writeback claims from the person bucket and updates the users row by id', async () => {
        const limiters = new Map<string, RateLimiter>();
        const buckets = { 'credits:user:user-p1': { onetime: { consumed: 700 } } };
        const { res } = await runWorker('/works', { headers: key('prepaid-key'), env: HD, buckets, limiters });
        expect(res.status).toBe(200);
        expect(db.writes).toEqual([{
            sql: expect.stringMatching(/WHERE id = \$2$/),
            params: [700, 'user-p1'],
        }]);
        // claimed: the bucket's consumed count is back to 0, so the next writeback can't bill it twice
        const status = await limiters.get('credits:user:user-p1')!.fetch(new Request('http://internal/status', {
            method: 'POST', body: JSON.stringify({ dailyLimit: 10_000, onetimeBalance: 50_000 }),
        }));
        expect((await status.json() as { onetime: { consumed: number } }).onetime.consumed).toBe(0);
    });

    it('spend left in the old per-key bucket is not claimed (at most a minute of one person, at the switch)', async () => {
        const buckets = { 'credits:prepaid-old': { onetime: { consumed: 300 } } };
        await runWorker('/works', { headers: key('prepaid-old'), env: HD, buckets });
        expect(db.writes).toEqual([]);
    });
});

describe('every logged request names its key\'s person (Analytics Engine blob9; oxjob #1725)', () => {
    it("a personal key's row carries its user id, whichever key it was; an org key's and a keyless row carry none", async () => {
        for (const [k, want] of [['rot-old', 'user-r1'], ['rot-agent', 'user-r1'], ['org-key', '']] as const) {
            const { rows } = await runWorker('/works', { headers: key(k), env: HD });
            expect(rows.map(r => r.blobs[8])).toEqual([want]);
        }
        const { rows } = await runWorker('/works');
        expect(rows.map(r => r.blobs[8])).toEqual(['']);
    });

    it('a refused request is traced too', async () => {
        const { res, rows } = await runWorker('/works', { headers: key('rot-new'), env: HD, buckets: spent('credits:user:user-r1') });
        expect(res.status).toBe(429);
        expect(rows.map(r => r.blobs[8])).toEqual(['user-r1']);
    });
});
