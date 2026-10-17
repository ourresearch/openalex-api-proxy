// The semantic ladder (oxjob #1433): the #521 health ladder run a second time for semantic search, rationing free and
// anonymous semantic searches while the vector cluster struggles. Paid keys and the website are never rationed.
import { describe, it, expect, vi, afterEach } from 'vitest';
import {
    bucketSeverity, checkBudget, newBucket, SEMANTIC_BOUNDS, SEMANTIC_REFILL, BUCKET_REFILL, SearchHealthController,
    PROFILE_HEADER, MIN_BUCKET_SAMPLES, resetHealthCachesForTests, observeSearchHealth,
} from './searchHealth';
import { isFreeSemanticCaller } from './index';
import { runWorker, fakeState } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, params: string[]) {
            const rows: Record<string, Record<string, unknown>> = {
                FREESEM1: { plan: null, max_credits_per_day: 10_000, onetime_credits_balance: 0, is_grandfathered: false },
                PAIDSEM1: { plan: 'premium-1M', max_credits_per_day: 1_000_000, onetime_credits_balance: 0, is_grandfathered: false },
                PREPAID1: { plan: null, max_credits_per_day: 10_000, onetime_credits_balance: 50_000, is_grandfathered: false },
            };
            const r = rows[params[0]];
            if (!r) return { rows: [] };
            return { rows: [{ max_per_day: r.max_credits_per_day, rate_throttled: false, throttle_scope: null,
                onetime_credits_expires_at: null, user_id: `user-${params[0]}`, org_id: null, ...r }] };
        }
        async end() {}
    },
}));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };
const SEMANTIC = '/works?search.semantic=coral+reef+bleaching&per_page=20';
const bucket = (n: number, avgMs: number, errN = 0) => ({ ...newBucket(0), n, sumMs: n * avgMs, errN });

afterEach(() => { vi.restoreAllMocks(); resetHealthCachesForTests(); });

describe('semantic bounds', () => {
    it('reads healthy semantic latency (≈ 1-2 s) as GREEN', () => {
        expect(bucketSeverity(bucket(20, 1200), SEMANTIC_BOUNDS)).toBe(0);
        expect(bucketSeverity(bucket(20, 2400), SEMANTIC_BOUNDS)).toBe(0);
    });
    it('climbs with average latency toward the 9 s aborts', () => {
        expect(bucketSeverity(bucket(20, 3000), SEMANTIC_BOUNDS)).toBe(1);
        expect(bucketSeverity(bucket(20, 4500), SEMANTIC_BOUNDS)).toBe(2);
        expect(bucketSeverity(bucket(20, 9000), SEMANTIC_BOUNDS)).toBe(3);
    });
    it('climbs with the share of 503/504s', () => {
        expect(bucketSeverity(bucket(20, 1000, 3), SEMANTIC_BOUNDS)).toBe(1);   // 15%: above YELLOW's 5%, not above 15%
        expect(bucketSeverity(bucket(20, 1000, 4), SEMANTIC_BOUNDS)).toBe(2);   // 20%
        expect(bucketSeverity(bucket(20, 1000, 9), SEMANTIC_BOUNDS)).toBe(3);   // 45%
    });
    it('needs the same sample floor as works search', () => {
        expect(bucketSeverity(bucket(MIN_BUCKET_SAMPLES - 1, 9000), SEMANTIC_BOUNDS)).toBe(0);
    });
    it("leaves the works-search ladder's bounds as they were", () => {
        expect(bucketSeverity(bucket(20, 1000))).toBe(1);   // works search: > 850 ms is YELLOW
    });
});

describe('semantic budget (rates below 1/s)', () => {
    it('YELLOW lets one a second through', () => {
        const b = { tokens: 0, lastRefill: 0 };
        expect(checkBudget(1, b, 10_000, SEMANTIC_REFILL).ok).toBe(true);
        expect(checkBudget(1, b, 10_001, SEMANTIC_REFILL).ok).toBe(false);
        expect(checkBudget(1, b, 11_001, SEMANTIC_REFILL).ok).toBe(true);
    });
    it('ORANGE lets one through about every 3.3 s', () => {
        const b = { tokens: 0, lastRefill: 0 };
        expect(checkBudget(2, b, 10_000, SEMANTIC_REFILL).ok).toBe(true);
        const r = checkBudget(2, b, 11_000, SEMANTIC_REFILL);
        expect(r.ok).toBe(false);
        expect(r.retryAfter).toBe(3);
        expect(checkBudget(2, b, 13_400, SEMANTIC_REFILL).ok).toBe(true);
    });
    it('RED refuses, GREEN never limits', () => {
        expect(checkBudget(3, { tokens: 5, lastRefill: 0 }, 1, SEMANTIC_REFILL)).toEqual({ ok: false, retryAfter: 60 });
        expect(checkBudget(0, { tokens: 0, lastRefill: 0 }, 1, SEMANTIC_REFILL).ok).toBe(true);
    });
    it("keeps works search's one-second cap at rates of 1/s and up", () => {
        const b = { tokens: 0, lastRefill: 0 };
        let ok = 0;
        for (let i = 0; i < 100; i++) if (checkBudget(1, b, 50_000, BUCKET_REFILL).ok) ok++;
        expect(ok).toBe(60);
    });
});

describe('isFreeSemanticCaller', () => {
    it('rations anonymous callers and free keys', () => {
        expect(isFreeSemanticCaller(false, null, 0, false, 1000)).toBe(true);
        expect(isFreeSemanticCaller(true, null, 0, false, 10_000)).toBe(true);
        expect(isFreeSemanticCaller(true, 'throttled', 0, false, 0)).toBe(true);
    });
    it('never rations a paying key', () => {
        expect(isFreeSemanticCaller(true, 'premium-1M', 0, false, 1_000_000)).toBe(false);
        expect(isFreeSemanticCaller(true, 'member-plus', 0, false, 100_000)).toBe(false);
        expect(isFreeSemanticCaller(true, null, 5_000, false, 10_000)).toBe(false);   // prepaid credit
        expect(isFreeSemanticCaller(true, null, 0, true, 10_000)).toBe(false);        // grandfathered
        expect(isFreeSemanticCaller(true, null, 0, false, 100_000)).toBe(false);      // a bigger daily allowance
    });
});

describe('the semantic controller instance', () => {
    const call = (dobj: SearchHealthController, path: string, body: unknown, semantic = true) =>
        dobj.fetch(new Request(`http://internal${path}`, {
            method: body === undefined ? 'GET' : 'POST',
            headers: semantic ? { [PROFILE_HEADER]: 'semantic' } : {},
            body: body === undefined ? undefined : JSON.stringify(body),
        })).then((r) => r.json<Record<string, any>>());

    it('learns its profile from the header, keeps it in storage, and rations at the semantic rates', async () => {
        const state = fakeState();
        const dobj = new SearchHealthController(state as any, {} as any);
        const first = await call(dobj, '/check-anon-budget', { force: 'YELLOW' });
        expect(first.ok).toBe(true);
        expect((await call(dobj, '/check-anon-budget', { force: 'YELLOW' })).ok).toBe(false);
        expect(state.store.get('profile')).toBe('semantic');
        const view = await call(dobj, '/state', undefined, false);
        expect(view.profile).toBe('semantic');
        expect(view.ladder).toEqual({ GREEN: 'no limit', YELLOW: '1/s', ORANGE: '0.3/s', RED: 'off (503)' });

        const restarted = new SearchHealthController(state as any, {} as any);
        await new Promise((r) => setTimeout(r, 0));
        expect((await call(restarted, '/state', undefined, false)).profile).toBe('semantic');
    });

    it('a works-search instance is unchanged', async () => {
        const dobj = new SearchHealthController(fakeState() as any, {} as any);
        let ok = 0;
        for (let i = 0; i < 70; i++) if ((await call(dobj, '/check-anon-budget', { force: 'YELLOW' }, false)).ok) ok++;
        expect(ok).toBe(60);
        expect((await call(dobj, '/state', undefined, false)).profile).toBe('search');
    });
});

describe('observeSearchHealth routes semantic responses to the semantic instance', () => {
    it('sends every semantic response, with the profile header, to its own instance', async () => {
        const seen: { name: string; profile: string | null }[] = [];
        const env = { SEARCH_HEALTH: {
            idFromName: (n: string) => n,
            get: (name: string) => ({ fetch: async (_u: string, init?: RequestInit) => {
                seen.push({ name, profile: new Headers(init?.headers).get(PROFILE_HEADER) });
                return Response.json({ ok: true, state: 'GREEN' });
            } }),
        } } as any;
        const pending: Promise<unknown>[] = [];
        const ctx = { waitUntil: (p: Promise<unknown>) => pending.push(p) } as any;
        for (let i = 0; i < 5; i++) observeSearchHealth(env, ctx, { endpointType: 'semantic', ms: 900, status: 200, anon: false });
        await Promise.all(pending);
        expect(seen).toHaveLength(5);
        expect(seen.every((s) => s.name === 'global:semantic-health-v1' && s.profile === 'semantic')).toBe(true);
    });
});

describe('the whole Worker', () => {
    const red = { ...HD, FORCE_SEMANTIC_HEALTH_STATE: 'RED' };
    it('at RED, refuses anonymous and free-key semantic searches before the origin, uncharged, with Retry-After', async () => {
        const callers: Record<string, string>[] = [{}, { Authorization: 'Bearer FREESEM1' }];
        for (const headers of callers) {
            const origin = vi.fn(async () => new Response('{"meta":{}}', { status: 200 }));
            const { res, rows } = await runWorker(SEMANTIC, { headers, env: red, fetch: origin });
            expect(res.status).toBe(503);
            expect(res.headers.get('Retry-After')).toBe('60');
            expect((await res.json<{ message: string }>()).message).toMatch(/Paid plans are not rationed/);
            expect(origin).not.toHaveBeenCalled();
            expect(rows.some((r) => r.blobs[4] === 'semantic-ladder')).toBe(true);
        }
    });
    it('at RED, lets paid and prepaid keys through', async () => {
        for (const k of ['PAIDSEM1', 'PREPAID1']) {
            const { res } = await runWorker(SEMANTIC, { headers: { Authorization: `Bearer ${k}` }, env: red });
            expect(res.status).toBe(200);
        }
    });
    it('leaves works search alone at a semantic RED', async () => {
        const { res } = await runWorker('/works?search=coral', { env: red });
        expect(res.status).toBe(200);
    });
    it('at GREEN, changes nothing', async () => {
        const { res } = await runWorker(SEMANTIC, { env: { ...HD, FORCE_SEMANTIC_HEALTH_STATE: 'GREEN' } });
        expect(res.status).toBe(200);
    });
});
