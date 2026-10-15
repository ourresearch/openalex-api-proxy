import { describe, it, expect, vi, afterEach } from 'vitest';
import { RateLimiter } from './rateLimiter';
import { mintUiToken } from './uiToken';
import { parseHighRpsAccounts, perSecondLimitFor, DEFAULT_HIGH_RPS, MAX_HIGH_RPS } from './highRps';
import worker from './index';

// A keyed request looks its key up in api_keys_view. This fake database answers from KEYS; a key it doesn't hold is
// "not found", and DB_DOWN makes connect() throw so the proxy takes its fail-open path.
const db = vi.hoisted(() => ({ keys: new Map<string, Record<string, unknown>>(), down: false }));
vi.mock('pg', () => ({
    Client: class {
        async connect() { if (db.down) throw new Error('no database'); }
        async query(_sql: string, [key]: string[]) { const row = db.keys.get(key); return { rows: row ? [row] : [] }; }
        async end() {}
    },
}));

const SSR_USER = 'user-SsrService01';
const row = (user_id: string | null, org_id: string | null = null, max_credits_per_day = 1_000_000) => ({
    max_per_day: max_credits_per_day, max_credits_per_day, is_grandfathered: false, onetime_credits_balance: 0,
    onetime_credits_expires_at: null, plan: 'premium', rate_throttled: false, throttle_scope: null, user_id, org_id,
});
db.keys.set('ssr-key', row(SSR_USER));
db.keys.set('other-key', row('user-SomeoneElse1'));
db.keys.set('org-key', row(null, 'org-SsrServiceOrg'));
db.keys.set('free-key', row('user-FreeAccount1', null, 10_000));

describe('parseHighRpsAccounts (oxjob #1689)', () => {
    it('reads `id` as the default cap and `id:rps` as its own', () => {
        expect([...parseHighRpsAccounts(`${SSR_USER}, org-b:800 ,user-c:1`)]).toEqual([
            [SSR_USER, DEFAULT_HIGH_RPS], ['org-b', 800], ['user-c', 1],
        ]);
    });

    it('is empty when unset or blank', () => {
        expect(parseHighRpsAccounts(undefined).size).toBe(0);
        expect(parseHighRpsAccounts('').size).toBe(0);
        expect(parseHighRpsAccounts(' , ,').size).toBe(0);
    });

    it('skips malformed entries and keeps the good ones', () => {
        const caps = parseHighRpsAccounts('user-a:, user-b:fast, user-c:0, user-d:-5, user-e:2.5, :300, user-f:300:4, user-ok:600');
        expect([...caps]).toEqual([['user-ok', 600]]);
    });

    it(`clamps a cap above ${MAX_HIGH_RPS}/s (one Durable Object's ceiling)`, () => {
        expect(parseHighRpsAccounts('user-a:5000').get('user-a')).toBe(MAX_HIGH_RPS);
    });
});

describe('perSecondLimitFor (oxjob #1689)', () => {
    const LIST = `${SSR_USER}, org-b:800`;

    it('gives a listed account its cap, whatever its daily credits', () => {
        expect(perSecondLimitFor(1_000_000, [SSR_USER], LIST)).toBe(DEFAULT_HIGH_RPS);
        expect(perSecondLimitFor(1000, [SSR_USER], LIST)).toBe(DEFAULT_HIGH_RPS);
        expect(perSecondLimitFor(1_000_000, ['org-b'], LIST)).toBe(800);
    });

    it('leaves everyone else on the 50/30/10 tiers', () => {
        for (const list of [LIST, '', undefined, 'garbage:::,:']) {
            expect(perSecondLimitFor(100_000, ['user-x'], list)).toBe(50);
            expect(perSecondLimitFor(10_000, ['user-x'], list)).toBe(30);
            expect(perSecondLimitFor(1000, [], list)).toBe(10);
            expect(perSecondLimitFor(0, ['user-x'], list)).toBe(10);
        }
    });

    it('rereads the list when it changes', () => {
        expect(perSecondLimitFor(100_000, ['user-x'], 'user-x:700')).toBe(700);
        expect(perSecondLimitFor(100_000, ['user-x'], 'user-y')).toBe(50);
    });
});

// An in-memory DurableObjectState: enough storage for RateLimiter, nothing else.
function fakeState() {
    const store = new Map<string, unknown>();
    return {
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

// The whole API path, `n` requests in one frozen millisecond (so no tokens refill), with one real RateLimiter per bucket.
async function burst(path: string, n: number, opts: { headers?: Record<string, string>; env?: Record<string, unknown> } = {}) {
    vi.stubGlobal('fetch', vi.fn(async () =>
        new Response('{"meta":{}}', { status: 200, headers: { 'Content-Type': 'application/json' } })));
    vi.spyOn(Date, 'now').mockReturnValue(1_760_000_000_000);
    const limiters = new Map<string, RateLimiter>();
    const checks: { bucket: string; dailyLimit: number; perSecondLimit: number }[] = [];
    const statuses: number[] = [];
    const env = {
        OPENALEX_API_URL: 'https://origin.test',
        FORCE_HEALTH_STATE: 'GREEN',
        UI_TOKEN_HMAC_SECRET: 'test-ui-hmac-secret',
        HYPERDRIVE: { connectionString: 'postgres://test' },
        HIGH_RPS_ACCOUNTS: `${SSR_USER}, org-SsrServiceOrg:800`,
        RATE_LIMITER: {
            idFromName: (name: string) => name,
            get: (name: string) => ({
                fetch: async (u: string, init?: RequestInit) => {
                    if (u.endsWith('/check')) {
                        const b = JSON.parse(String(init?.body));
                        checks.push({ bucket: name, dailyLimit: b.dailyLimit, perSecondLimit: b.perSecondLimit });
                    }
                    if (!limiters.has(name)) {
                        limiters.set(name, new RateLimiter(fakeState() as any));
                        await new Promise(r => setTimeout(r, 0)); // let loadFromStorage finish
                    }
                    return limiters.get(name)!.fetch(new Request(u, init));
                },
            }),
        },
        ANALYTICS: { writeDataPoint: () => {} },
        ...opts.env,
    };
    for (let i = 0; i < n; i++) {
        const pending: Promise<unknown>[] = [];
        const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException: () => {} };
        const req = new Request(`https://api.openalex.org${path}`, { headers: { 'CF-Connecting-IP': '203.0.113.9', ...opts.headers } });
        statuses.push((await worker.fetch(req, env as any, ctx as any)).status);
        await Promise.all(pending);
    }
    return { statuses, checks, count: (s: number) => statuses.filter(x => x === s).length };
}

const RECORD = '/works/W2741809807';
const key = (k: string) => ({ Authorization: `Bearer ${k}` });

describe('the per-second cap on the API path (oxjob #1689)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); db.down = false; });

    it("a listed user's key gets 500/s, with its daily credits unchanged", async () => {
        const { checks, count } = await burst(RECORD, 120, { headers: key('ssr-key') });
        expect(checks[0]).toEqual({ bucket: 'credits:ssr-key', dailyLimit: 1_000_000, perSecondLimit: 500 });
        expect(count(200)).toBe(120);
    });

    it("a listed org's key gets its own `id:rps` cap", async () => {
        const { checks } = await burst(RECORD, 1, { headers: key('org-key') });
        expect(checks[0].perSecondLimit).toBe(800);
    });

    it('an unlisted paid key keeps 50/s: the 51st request in the same instant is refused', async () => {
        const { checks, count } = await burst(RECORD, 60, { headers: key('other-key') });
        expect(checks[0]).toEqual({ bucket: 'credits:other-key', dailyLimit: 1_000_000, perSecondLimit: 50 });
        expect(count(200)).toBe(50);
        expect(count(429)).toBe(10);
    });

    it('an unlisted free key keeps 30/s', async () => {
        const { checks } = await burst(RECORD, 1, { headers: key('free-key') });
        expect(checks[0].perSecondLimit).toBe(30);
    });

    it('keyless traffic from the website (Referer, Origin, UI token) keeps 10/s', async () => {
        const uiToken = await mintUiToken('test-ui-hmac-secret', 1_760_000_000_000, 1800, '203.0.113.9');
        const { checks, count } = await burst(RECORD, 15, { headers: {
            Referer: 'https://openalex.org/works/W2741809807', Origin: 'https://openalex.org', 'X-OpenAlex-UI': uiToken,
        } });
        expect(checks[0]).toEqual({ bucket: 'credits:203.0.113.9', dailyLimit: 1000, perSecondLimit: 10 });
        expect(count(429)).toBe(5);
    });

    it('a key the database can\'t place (fail-open) keeps the tier', async () => {
        db.down = true;
        vi.spyOn(console, 'error').mockImplementation(() => {});
        const { checks } = await burst(RECORD, 1, { headers: key('ssr-key-uncached') });
        expect(checks[0].perSecondLimit).toBe(50);
    });

    it('a malformed list changes nothing', async () => {
        const { checks } = await burst(RECORD, 1, { headers: key('ssr-key'), env: { HIGH_RPS_ACCOUNTS: `${SSR_USER}:lots` } });
        expect(checks[0].perSecondLimit).toBe(50);
    });
});
