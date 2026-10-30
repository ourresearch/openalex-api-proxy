// Keys an AI agent asks for (oxjob #1697), driven through the whole Worker: GET explains, POST goes to users-api with
// the caller's IP after the enforcement list, a pending key hears how to activate, and every keyless way out names it.
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { runWorker, HARNESS_IP, today } from './testHarness';
import { _resetEnforcementForTests } from './enforcementList';
import { sha256Hex } from './contactBudget';
import { ASK_FOR_A_KEY, API_KEYS_ENFORCED_MESSAGE, KEY_NOT_ACTIVATED_MESSAGE } from './apiKeys';
import { keylessNoticeFor } from './keylessNotice';
import { API_ROOT } from './apiRoot';

// api_keys_view rows by key. 'PENDING*' and 'EXPIRED1' are agent keys not yet activated (two key states: 0 credits).
// SELECT * returns activation_pending only once users-api migration 106 is applied: 'OLDVIEW1' is a row without it.
const ROWS: Record<string, Record<string, unknown>> = {
    PENDING1: { max_per_day: 0, max_credits_per_day: 0, activation_pending: true, user_id: 'user-p1' },
    PENDING2: { max_per_day: 0, max_credits_per_day: 0, activation_pending: true, user_id: 'user-p2' },
    EXPIRED1: { max_per_day: 0, max_credits_per_day: 0, activation_pending: true, user_id: 'user-e1' },
    ACTIVE01: { max_per_day: 10000, max_credits_per_day: 10000, activation_pending: false, user_id: 'user-a1' },
    OLDVIEW1: { max_per_day: 10000, max_credits_per_day: 10000, user_id: 'user-o1' },
    AGENTKEY: { max_per_day: 10000, max_credits_per_day: 10000, activation_pending: false, user_id: 'user-g1', budget_key: 'ACCOUNTK' },
};
const queries: string[] = [];
vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query(sql: string, params: string[]) {
            queries.push(sql);
            const row = ROWS[params[0]];
            return { rows: row ? [{ is_grandfathered: false, onetime_credits_balance: 0, plan: null, rate_throttled: false, throttle_scope: null, org_id: null, ...row }] : [] };
        }
        async end() {}
    },
}));

const PROXY_KEY = 'proxy-secret-for-tests';
const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };  // keyed requests look their key up
const LIST = '{"meta": {"count": 5, "page": 1}, "results": []}';

beforeEach(() => _resetEnforcementForTests());
afterEach(() => { vi.unstubAllGlobals(); queries.length = 0; });

function usersApi(status = 201, body: unknown = { api_key: 'NEWKEY', status: 'pending_activation' }) {
    const calls: { url: string; headers: Headers; body: string; method: string }[] = [];
    const fetch = async (input: Request | string, init?: RequestInit) => {
        const r = typeof input === 'string' ? new Request(input, init) : input;
        calls.push({ url: r.url, headers: r.headers, body: await r.text(), method: r.method });
        return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
    };
    return { calls, fetch: fetch as any };
}

const ask = (opts: { body?: string; headers?: Record<string, string>; env?: Record<string, unknown>; fetch?: any; ip?: string } = {}) =>
    runWorker('/api-keys', {
        method: 'POST',
        body: opts.body ?? JSON.stringify({ email: 'ana.silva@usp.br' }),
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'claude-code/2.1', ...opts.headers },
        env: { COLLECTION_PROXY_KEY: PROXY_KEY, ...opts.env },
        fetch: opts.fetch,
        ip: opts.ip,
    });

describe('GET /api-keys explains the call, free', () => {
    it('answers at the edge with the method, URL and body', async () => {
        const api = usersApi();
        const { res, checks } = await runWorker('/api-keys', { fetch: api.fetch });
        expect(res.status).toBe(200);
        const how = await res.json() as any;
        expect(how.method).toBe('POST');
        expect(how.url).toBe('https://api.openalex.org/api-keys');
        expect(how.body.email).toContain('ask them');
        expect(res.headers.get('X-RateLimit-Cost-USD')).toBe('0');
        expect(api.calls).toHaveLength(0);
        expect(checks).toHaveLength(0);
    });

    it('refuses other methods with Allow', async () => {
        const { res } = await runWorker('/api-keys', { method: 'PUT', body: '{}' });
        expect(res.status).toBe(405);
        expect(res.headers.get('Allow')).toBe('GET, HEAD, POST');
    });
});

describe('POST /api-keys goes to users-api', () => {
    it('forwards the body with the caller IP under the shared secret, User-Agent and Idempotency-Key, and no key', async () => {
        const api = usersApi();
        const { res, checks } = await ask({
            fetch: api.fetch,
            headers: { 'Idempotency-Key': 'b5a0e1c2-0000-4000-8000-000000000001', Authorization: 'Bearer SOMEKEY' },
        });
        expect(res.status).toBe(201);
        expect((await res.json() as any).api_key).toBe('NEWKEY');
        expect(res.headers.get('Cache-Control')).toBe('no-store');
        expect(api.calls).toHaveLength(1);
        const c = api.calls[0];
        expect(c.url).toBe('https://user.openalex.org/api/api-keys');
        expect(c.method).toBe('POST');
        expect(JSON.parse(c.body)).toEqual({ email: 'ana.silva@usp.br' });
        expect(c.headers.get('X-Collection-Proxy-Key')).toBe(PROXY_KEY);
        expect(c.headers.get('X-Collection-Client-IP')).toBe(HARNESS_IP);
        expect(c.headers.get('User-Agent')).toBe('claude-code/2.1');
        expect(c.headers.get('Idempotency-Key')).toBe('b5a0e1c2-0000-4000-8000-000000000001');
        expect(c.headers.get('Authorization')).toBeNull();
        // No credits and no keyless budget: the only check is the per-network ask cap.
        expect(checks).toEqual([{ bucket: `apikeys:${HARNESS_IP}`, dailyLimit: 10, perSecondLimit: 1 }]);
    });

    it('works for a caller whose keyless budget is spent', async () => {
        const api = usersApi();
        const { res } = await ask({ fetch: api.fetch, env: {} , headers: {} });
        expect(res.status).toBe(201);
        const spent = await runWorker('/works', { buckets: { [`credits:${HARNESS_IP}`]: { counter: { count: 1000, date: today() } } } });
        expect(spent.res.status).toBe(429);
    });

    it("passes users-api's refusals through", async () => {
        const api = usersApi(409, { error: 'Conflict', code: 'account_exists', message: 'x' });
        const { res } = await ask({ fetch: api.fetch });
        expect(res.status).toBe(409);
        expect((await res.json() as any).code).toBe('account_exists');
    });

    it('refuses a body over 4 KB without calling users-api', async () => {
        const api = usersApi();
        const { res } = await ask({ fetch: api.fetch, body: JSON.stringify({ email: 'a@b.org', name: 'x'.repeat(5000) }) });
        expect(res.status).toBe(413);
        expect(api.calls).toHaveLength(0);
    });

    it('caps asks per network a day before users-api sees them, IPv6 by /64', async () => {
        const api = usersApi();
        const spentV6 = { 'apikeys:2001:db8:abcd:12::/64': { counter: { count: 10, date: today() } } };
        const { res } = await runWorker('/api-keys', {
            method: 'POST', body: JSON.stringify({ email: 'ana.silva@usp.br' }), ip: '2001:db8:abcd:12::99',
            env: { COLLECTION_PROXY_KEY: PROXY_KEY }, fetch: api.fetch, buckets: spentV6,
        });
        expect(res.status).toBe(429);
        expect((await res.json() as any).code).toBe('rate_limit_network');
        expect(api.calls).toHaveLength(0);
        const other = await runWorker('/api-keys', {
            method: 'POST', body: JSON.stringify({ email: 'ana.silva@usp.br' }), ip: '2001:db8:abcd:13::1',
            env: { COLLECTION_PROXY_KEY: PROXY_KEY }, fetch: api.fetch, buckets: spentV6,
        });
        expect(other.res.status).toBe(201);
    });

    it('says so when users-api is down', async () => {
        const { res } = await ask({ fetch: async () => { throw new Error('down'); } });
        expect(res.status).toBe(502);
    });
});

describe("oxjob #1692's enforcement list runs first", () => {
    const entry = (match: Record<string, unknown>, extra: Record<string, unknown> = {}) =>
        ({ id: 'pool-1', match, action: 'block', expires: Date.now() / 1000 + 3600, ...extra });
    const kv = (state: unknown) => ({ ENFORCEMENT: { get: async () => state }, ENFORCE_AE: { writeDataPoint: (p: any) => aeRows.push(p) } });
    let aeRows: any[] = [];
    beforeEach(() => { aeRows = []; });

    it('enforce: a listed network gets a 403 that points to the website sign-up', async () => {
        const api = usersApi();
        const { res } = await ask({ fetch: api.fetch, env: kv({ mode: 'enforce', entries: [entry({ ip_prefix: '203.0.113.' })] }) });
        expect(res.status).toBe(403);
        const body = await res.json() as any;
        expect(body.code).toBe('enforced');
        expect(body.message).toBe(API_KEYS_ENFORCED_MESSAGE);
        expect(body.message).toContain('https://openalex.org/signup');
        expect(api.calls).toHaveLength(0);
        expect(aeRows[0].blobs).toEqual(['pool-1', 'block', 'enforce', 'api_keys', 'refuse']);
    });

    it("enforce: the body's email matches a listed contact address", async () => {
        const api = usersApi();
        const sha = await sha256Hex('pooled@lab.org');
        const env = kv({ mode: 'enforce', entries: [entry({ mailto_sha: sha }, { action: 'shared_budget' })] });
        const { res } = await ask({ fetch: api.fetch, env, body: JSON.stringify({ email: ' Pooled@Lab.org ' }) });
        expect(res.status).toBe(403);
        const other = await ask({ fetch: api.fetch, env, body: JSON.stringify({ email: 'someone.else@lab.org' }) });
        expect(other.res.status).toBe(201);
    });

    it('shadow: recorded, let through', async () => {
        const api = usersApi();
        const { res } = await ask({ fetch: api.fetch, env: kv({ mode: 'shadow', entries: [entry({ ip_prefix: '203.0.113.' })] }) });
        expect(res.status).toBe(201);
        expect(aeRows[0].blobs).toEqual(['pool-1', 'block', 'shadow', 'api_keys', 'pass']);
    });
});

describe('two key states: a key an agent asked for works only once its person clicks (Jason 2026-10-15)', () => {
    it('an unactivated key gets a 403 with the way out, before any budget or origin call', async () => {
        let originCalls = 0;
        const { res, checks } = await runWorker('/works?api_key=PENDING1', {
            env: HD,
            fetch: async () => { originCalls++; return new Response(LIST, { status: 200, headers: { 'Content-Type': 'application/json' } }); },
        });
        expect(res.status).toBe(403);
        const body = await res.json() as any;
        expect(body.code).toBe('key_not_activated');
        expect(body.message).toBe(KEY_NOT_ACTIVATED_MESSAGE);
        expect(body.message).toContain('Activate your OpenAlex API key');
        expect(body.message).toContain('call without a key');
        expect(checks).toHaveLength(0);
        expect(originCalls).toBe(0);
        expect(queries[0]).toBe('SELECT * FROM api_keys_view WHERE api_key = $1');
    });

    it('so does one whose link has long expired', async () => {
        const { res } = await runWorker('/works?api_key=EXPIRED1', { env: HD });
        expect(res.status).toBe(403);
        expect((await res.json() as any).code).toBe('key_not_activated');
    });

    it('an activated key works, with no notice', async () => {
        const { res } = await runWorker('/works?api_key=ACTIVE01', {
            env: HD,
            fetch: async () => new Response(LIST, { status: 200, headers: { 'Content-Type': 'application/json' } }),
        });
        expect(res.status).toBe(200);
        expect((await res.json() as any).meta.notice).toBeUndefined();
    });

    it("a view without migration 106's column reads as activated", async () => {
        const { res, checks } = await runWorker('/works?api_key=OLDVIEW1', {
            env: HD,
            fetch: async () => new Response(LIST, { status: 200, headers: { 'Content-Type': 'application/json' } }),
        });
        expect(res.status).toBe(200);
        expect((await res.json() as any).meta.notice).toBeUndefined();
        expect(checks[0]).toMatchObject({ dailyLimit: 10000, perSecondLimit: 30 });
    });
});

describe("one free day per person: an agent's key spends from its person's bucket", () => {
    it('counts in the person bucket', async () => {
        const { res, checks } = await runWorker('/works?api_key=AGENTKEY', {
            env: HD, fetch: async () => new Response(LIST, { status: 200, headers: { 'Content-Type': 'application/json' } }),
        });
        expect(res.status).toBe(200);
        expect(checks[0]).toMatchObject({ bucket: 'credits:user:user-g1', dailyLimit: 10000 });
    });

    it('is refused when the account spent its day on its own key', async () => {
        const { res } = await runWorker('/works?api_key=AGENTKEY', {
            env: HD, buckets: { 'credits:user:user-g1': { counter: { count: 10000, date: today() } } },
        });
        expect(res.status).toBe(429);
    });
});

describe('every keyless way out names the call', () => {
    it('the keyless notice', () => {
        expect(keylessNoticeFor(new URLSearchParams(), 0.1)).toContain(ASK_FOR_A_KEY);
    });

    it('the keyless 429', async () => {
        const { res } = await runWorker('/works', { buckets: { [`credits:${HARNESS_IP}`]: { counter: { count: 1000, date: today() } } } });
        expect((await res.json() as any).message).toContain(ASK_FOR_A_KEY);
    });

    it('the 401 for an unknown key (YOUR_API_KEY and friends)', async () => {
        const { res } = await runWorker('/works?api_key=YOUR_API_KEY', { env: HD });
        expect(res.status).toBe(401);
        expect((await res.json() as any).message).toContain('POST https://api.openalex.org/api-keys');
    });

    it('the API root', () => {
        expect(API_ROOT.get_a_free_key_by_api.url).toBe('https://api.openalex.org/api-keys');
    });
});
