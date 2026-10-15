// The agent-legibility fixes (oxjob #1686) driven through the whole Worker: the API root served at the edge, and
// DOI URLs priced as singletons.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { RateLimiter } from './rateLimiter';
import { mintUiToken } from './uiToken';
import { VERIFIED_ASSISTANT_HEADER } from './verifiedAssistant';
import { API_ROOT, isApiRootRequest } from './apiRoot';
import worker from './index';

// Keyed requests look their key up in Postgres. 'bad-key' is unknown (401); any other key fails open to a valid
// key at 100,000 credits a day, which is all these tests need.
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, params: string[]) {
            if (params[0] === 'bad-key') return { rows: [] };
            throw new Error('no database in tests');
        }
        async end() {}
    },
}));

const TOKEN = 'test-verified-assistant-token-0123456789abcdef';
const UI_SECRET = 'test-ui-hmac-secret';
const IP = '203.0.113.9';
const today = () => new Date().toISOString().split('T')[0];
const SPENT = { [`credits:${IP}`]: { counter: { count: 1000, date: today() } } };

const LIST_BODY = '{"meta": {"count": 5, "db_response_time_ms": 12, "page": 1, "per_page": 1}, "results": [{"id": "https://openalex.org/W1"}]}';
const WORK_BODY = '{"id":"https://openalex.org/W2741809807","doi":"https://doi.org/10.7717/peerj.4375"}';

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

// The whole API path: a real RateLimiter per bucket, a stub origin, an Analytics Engine sink.
async function run(path: string, opts: {
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    buckets?: Record<string, Record<string, unknown>>;
    origin?: { body?: string | null; status?: number; headers?: Record<string, string> };
} = {}) {
    const originCalls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (input: Request | string) => {
        originCalls.push(typeof input === 'string' ? input : input.url);
        const o = opts.origin ?? {};
        const body = o.body === undefined ? LIST_BODY : o.body;
        return new Response(body, {
            status: o.status ?? 200,
            headers: { 'Content-Type': 'application/json', ...(body ? { 'Content-Length': String(new TextEncoder().encode(body).length) } : {}), ...o.headers },
        });
    }));
    const limiters = new Map<string, RateLimiter>();
    const checks: { bucket: string; credits: number }[] = [];
    const rows: { blobs: string[]; doubles: number[] }[] = [];
    const pending: Promise<unknown>[] = [];
    async function limiterFor(name: string) {
        if (!limiters.has(name)) {
            limiters.set(name, new RateLimiter(fakeState(opts.buckets?.[name]) as any));
            await new Promise(r => setTimeout(r, 0));  // let loadFromStorage finish
        }
        return limiters.get(name)!;
    }
    const env = {
        OPENALEX_API_URL: 'https://origin.test',
        HYPERDRIVE: { connectionString: 'postgres://test' },
        FORCE_HEALTH_STATE: 'GREEN',
        VERIFIED_ASSISTANT_TOKEN: TOKEN,
        UI_TOKEN_HMAC_SECRET: UI_SECRET,
        RATE_LIMITER: {
            idFromName: (n: string) => n,
            get: (name: string) => ({
                fetch: async (u: string, init?: RequestInit) => {
                    if (u.endsWith('/check')) checks.push({ bucket: name, credits: JSON.parse(String(init?.body)).credits });
                    return (await limiterFor(name)).fetch(new Request(u, init));
                },
            }),
        },
        ANALYTICS: { writeDataPoint: (p: { blobs: string[]; doubles: number[] }) => { rows.push(p); } },
    };
    const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException: () => {} };
    const req = new Request(`https://api.openalex.org${path}`, {
        method: opts.method ?? 'GET',
        body: opts.body,
        headers: { 'CF-Connecting-IP': IP, ...opts.headers },
    });
    const res = await worker.fetch(req, env as any, ctx as any);
    const text = await res.text();
    await Promise.all(pending);
    return { res, text, checks, rows, originCalls };
}

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('the API root, served by the Worker (oxjob #1686)', () => {
    it('GET /: the root document, free, without the origin or the credits bucket', async () => {
        const { res, text, checks, originCalls, rows } = await run('/');
        expect(res.status).toBe(200);
        expect(JSON.parse(text)).toEqual(API_ROOT);
        expect(res.headers.get('Content-Type')).toBe('application/json');
        expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('0');
        expect(originCalls).toEqual([]);
        expect(checks).toEqual([]);
        // Still logged: blob5 scope, blob3 URL, double2 status, double5 credits.
        expect(rows).toHaveLength(1);
        expect(rows[0].blobs[4]).toBe('root');
        expect(rows[0].blobs[2]).toBe('/');
        expect(rows[0].doubles[1]).toBe(200);
        expect(rows[0].doubles[4]).toBe(0);
    });

    it('served when the IP\'s keyless budget is spent', async () => {
        expect((await run('/works?per_page=1', { buckets: SPENT })).res.status).toBe(429);
        const { res, text } = await run('/', { buckets: SPENT });
        expect(res.status).toBe(200);
        expect(JSON.parse(text).quick_reference).toBe('https://help.openalex.org/api/llm-quick-reference/');
    });

    it('HEAD /: 200, no body', async () => {
        const { res, text, originCalls } = await run('/', { method: 'HEAD' });
        expect(res.status).toBe(200);
        expect(text).toBe('');
        expect(originCalls).toEqual([]);
    });

    it('keeps the fields the elastic-api smoke test asserts, and no dead /docs link', () => {
        expect(API_ROOT).toMatchObject({ version: '0.1', msg: "Don't panic" });
        expect(JSON.stringify(API_ROOT)).not.toContain('/docs');
    });

    it('a keyed request to / gets it free too; a bad key still gets its 401', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        const keyed = await run('/', { headers: { Authorization: 'Bearer test-key-123' } });
        expect(keyed.res.status).toBe(200);
        expect(keyed.checks).toEqual([]);
        expect((await run('/?api_key=bad-key')).res.status).toBe(401);
    });

    it('GET /?oql= and /?oqo= still run at the origin, charged', async () => {
        for (const q of ['/?oql=get%20works%20where%20year%20is%202024', '/?oqo=%7B%7D', '/?oql=']) {
            const { originCalls, checks } = await run(q);
            expect(originCalls).toHaveLength(1);
            expect(checks).toEqual([{ bucket: `credits:${IP}`, credits: 1 }]);
        }
    });

    it('only the bare root of the API host', () => {
        const at = (u: string, m = 'GET') => isApiRootRequest(new URL(u), m);
        expect(at('https://api.openalex.org/')).toBe(true);
        expect(at('https://api.openalex.org')).toBe(true);
        expect(at('https://api.openalex.org/?mailto=me@example.com')).toBe(true);
        expect(at('https://api.openalex.org/', 'HEAD')).toBe(true);
        expect(at('https://api.openalex.org/', 'POST')).toBe(false);
        expect(at('https://api.openalex.org/?oql=x')).toBe(false);
        expect(at('https://api.openalex.org/?oqo=%7B%7D')).toBe(false);
        expect(at('https://api.openalex.org/works')).toBe(false);
        expect(at('https://api.openalex.org//')).toBe(false);
        expect(at('https://content.openalex.org/')).toBe(false);
    });
});

describe('DOI URLs are free singletons through the Worker (oxjob #1686)', () => {
    it.each([
        '/works/https://doi.org/10.7717/peerj.4375',
        '/works/https%3A%2F%2Fdoi.org%2F10.7717%2Fpeerj.4375',
        '/works/doi.org/10.7717/peerj.4375',
    ])('%s: 0 credits, and served when the keyless budget is spent', async (path) => {
        const fresh = await run(path, { origin: { body: WORK_BODY } });
        expect(fresh.checks).toEqual([{ bucket: `credits:${IP}`, credits: 0 }]);
        expect(fresh.res.headers.get('X-RateLimit-Credits-Used')).toBe('0');
        const spent = await run(path, { origin: { body: WORK_BODY }, buckets: SPENT });
        expect(spent.res.status).toBe(200);
        expect(spent.text).toBe(WORK_BODY);
    });
});
