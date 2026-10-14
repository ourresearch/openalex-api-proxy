import { describe, it, expect, vi, afterEach } from 'vitest';
import { RateLimiter } from './rateLimiter';
import { mintUiToken } from './uiToken';
import { isVerifiedAssistant, VERIFIED_ASSISTANT_HEADER } from './verifiedAssistant';
import worker from './index';

// A keyed request looks its key up in Postgres. There is no database here, so checkApiKey fails open to a
// valid key at 100,000 credits a day, which is all the keyed test needs.
vi.mock('pg', () => ({
    Client: class {
        async connect() { throw new Error('no database in tests'); }
        async end() {}
    },
}));

const TOKEN = 'test-verified-assistant-token-0123456789abcdef';
const UI_SECRET = 'test-ui-hmac-secret';
const IP = '203.0.113.7';
const PAGE2 = 'IlsnLUluZmluaXR5JywgMCwgJ2h0dHBzOi8vb3BlbmFsZXgub3JnL1cxMjMnXSI=';
const today = () => new Date().toISOString().split('T')[0];

describe('isVerifiedAssistant (oxjob #1686)', () => {
    it('is true only for the exact secret on a keyless request', () => {
        expect(isVerifiedAssistant(null, TOKEN, TOKEN)).toBe(true);
    });

    it('is false when the header is absent or wrong', () => {
        expect(isVerifiedAssistant(null, null, TOKEN)).toBe(false);
        expect(isVerifiedAssistant(null, '', TOKEN)).toBe(false);
        expect(isVerifiedAssistant(null, 'yes', TOKEN)).toBe(false);
        expect(isVerifiedAssistant(null, TOKEN.slice(0, -1), TOKEN)).toBe(false);
        expect(isVerifiedAssistant(null, TOKEN + 'x', TOKEN)).toBe(false);
    });

    it('is false while the secret is unset (feature off)', () => {
        expect(isVerifiedAssistant(null, TOKEN, undefined)).toBe(false);
        expect(isVerifiedAssistant(null, '', '')).toBe(false);
    });

    it('is false for a keyed request: a key always means its own budget', () => {
        expect(isVerifiedAssistant('some-api-key', TOKEN, TOKEN)).toBe(false);
    });
});

// An in-memory DurableObjectState: enough storage for RateLimiter, nothing else.
function fakeState(initial: Record<string, unknown> = {}) {
    const store = new Map<string, unknown>(Object.entries(initial));
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

// The whole API path, with one real RateLimiter per bucket name, so separate buckets really are separate.
async function run(path: string, opts: {
    headers?: Record<string, string>;
    env?: Record<string, unknown>;
    buckets?: Record<string, Record<string, unknown>>;
} = {}) {
    vi.stubGlobal('fetch', vi.fn(async () =>
        new Response('{"meta":{}}', { status: 200, headers: { 'Content-Type': 'application/json' } })));
    const limiters = new Map<string, RateLimiter>();
    const checks: { bucket: string; dailyLimit: number; perSecondLimit: number }[] = [];
    const rows: { doubles: number[] }[] = [];
    const pending: Promise<unknown>[] = [];
    async function limiterFor(name: string): Promise<RateLimiter> {
        if (!limiters.has(name)) {
            limiters.set(name, new RateLimiter(fakeState(opts.buckets?.[name]) as any));
            await new Promise(r => setTimeout(r, 0)); // let loadFromStorage finish
        }
        return limiters.get(name)!;
    }
    const env = {
        OPENALEX_API_URL: 'https://origin.test',
        FORCE_HEALTH_STATE: 'GREEN',
        VERIFIED_ASSISTANT_TOKEN: TOKEN,
        UI_TOKEN_HMAC_SECRET: UI_SECRET,
        RATE_LIMITER: {
            idFromName: (n: string) => n,
            get: (name: string) => ({
                fetch: async (u: string, init?: RequestInit) => {
                    if (u.endsWith('/check')) {
                        const b = JSON.parse(String(init?.body));
                        checks.push({ bucket: name, dailyLimit: b.dailyLimit, perSecondLimit: b.perSecondLimit });
                    }
                    return (await limiterFor(name)).fetch(new Request(u, init));
                },
            }),
        },
        ANALYTICS: { writeDataPoint: (p: { doubles: number[] }) => { rows.push(p); } },
        ...opts.env,
    };
    const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException: () => {} };
    const req = new Request(`https://api.openalex.org${path}`, { headers: { 'CF-Connecting-IP': IP, ...opts.headers } });
    const res = await worker.fetch(req, env as any, ctx as any);
    await Promise.all(pending);
    return { res, checks, rows };
}

const SEARCH = '/works?search=coral+reefs';
const ASSISTANT = { [VERIFIED_ASSISTANT_HEADER]: TOKEN };
const DOUBLE7_TRUSTED_UI = 6;
const DOUBLE8_VERIFIED_ASSISTANT = 7;

describe('verified AI assistants on the API path (oxjob #1686)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it('header absent: the normal keyless budget, bucket and 10/s', async () => {
        const { res, checks, rows } = await run(SEARCH);
        expect(res.status).toBe(200);
        expect(checks).toEqual([{ bucket: `credits:${IP}`, dailyLimit: 1000, perSecondLimit: 10 }]);
        expect(res.headers.get('X-RateLimit-Limit')).toBe('1000');
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(0);
    });

    it('header with the wrong value: the normal keyless budget', async () => {
        const { checks, rows } = await run(SEARCH, { headers: { [VERIFIED_ASSISTANT_HEADER]: 'true' } });
        expect(checks).toEqual([{ bucket: `credits:${IP}`, dailyLimit: 1000, perSecondLimit: 10 }]);
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(0);
    });

    it('header with the right value: 5M credits a day in its own bucket, at 50/s', async () => {
        const { res, checks, rows } = await run(SEARCH, { headers: ASSISTANT });
        expect(res.status).toBe(200);
        expect(checks).toEqual([{ bucket: `credits:verified-assistant:${IP}`, dailyLimit: 5_000_000, perSecondLimit: 50 }]);
        expect(res.headers.get('X-RateLimit-Limit')).toBe('5000000');
        expect(res.headers.get('X-RateLimit-Remaining')).toBe('4999990'); // a search costs 10
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(1);
    });

    it("its budget is its own: an IP whose keyless budget is spent still serves the assistant", async () => {
        const spent = { [`credits:${IP}`]: { counter: { count: 1000, date: today() } } };
        expect((await run(SEARCH, { buckets: spent })).res.status).toBe(429);
        expect((await run(SEARCH, { buckets: spent, headers: ASSISTANT })).res.status).toBe(200);
    });

    it('secret unset: the header does nothing (feature off)', async () => {
        const { checks, rows } = await run(SEARCH, { headers: ASSISTANT, env: { VERIFIED_ASSISTANT_TOKEN: undefined } });
        expect(checks).toEqual([{ bucket: `credits:${IP}`, dailyLimit: 1000, perSecondLimit: 10 }]);
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(0);
    });

    it('keyed requests keep their own budget, even with the right header', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {}); // the fail-open DB lookup logs
        const { checks, rows } = await run(SEARCH, { headers: { ...ASSISTANT, Authorization: 'Bearer test-key-123' } });
        expect(checks).toEqual([{ bucket: 'credits:test-key-123', dailyLimit: 100000, perSecondLimit: 50 }]);
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(0);
    });

    it('the website (trustedUi) keeps the normal keyless budget', async () => {
        const uiToken = await mintUiToken(UI_SECRET, Date.now(), 1800);
        const { checks, rows } = await run(SEARCH, { headers: { 'X-OpenAlex-UI': uiToken } });
        expect(checks).toEqual([{ bucket: `credits:${IP}`, dailyLimit: 1000, perSecondLimit: 10 }]);
        expect(rows[0].doubles[DOUBLE7_TRUSTED_UI]).toBe(1);
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(0);
    });

    it('stays keyless: page 2 of a cursor still needs a key (oxjob #1682)', async () => {
        const { res, checks, rows } = await run(`/works?filter=publication_year:2020&cursor=${PAGE2}`, { headers: ASSISTANT });
        expect(res.status).toBe(401);
        expect(checks).toEqual([]);
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(1);
    });

    it('stays keyless: anonymous search shedding still applies', async () => {
        const { res, checks, rows } = await run(SEARCH, { headers: ASSISTANT, env: { FORCE_HEALTH_STATE: 'RED' } });
        expect(res.status).toBe(503);
        expect(checks).toEqual([]);
        expect(rows[0].doubles[DOUBLE8_VERIFIED_ASSISTANT]).toBe(1);
    });
});
