// /rate-limit says when it couldn't read usage (oxjob #1548). A failed lookup of the usage counter used to answer 200
// with zero used and the full daily allowance, which no client could tell from a real reading. Driven through the
// whole Worker.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { runWorker, today } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() {}
        async query() {
            return { rows: [{
                max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
                onetime_credits_expires_at: null, plan: null, rate_throttled: false, throttle_scope: null,
                user_id: 'user-s1', org_id: null, budget_key: null,
            }] };
        }
        async end() {}
    },
}));

const HD = { HYPERDRIVE: { connectionString: 'postgres://test' } };
const KEY = { Authorization: 'Bearer status-key' };
const BUCKET = 'credits:user:user-s1';

// A RATE_LIMITER whose /status answers with `status` (or throws when it is an Error).
function limiterAnswering(status: Error | (() => Response)) {
    return {
        RATE_LIMITER: {
            idFromName: (n: string) => n,
            get: () => ({
                fetch: async (u: string) => {
                    if (!u.endsWith('/status')) throw new Error(`unexpected limiter call ${u}`);
                    if (status instanceof Error) throw status;
                    return status();
                },
            }),
        },
    };
}

afterEach(() => { vi.unstubAllGlobals(); });

describe('/rate-limit reads the usage counter (oxjob #1548)', () => {
    it('reports real usage when the lookup works', async () => {
        const buckets = { [BUCKET]: { counter: { count: 4_000, date: today() } } };
        const { res } = await runWorker('/rate-limit', { headers: KEY, env: HD, buckets });
        expect(res.status).toBe(200);
        const rl = (await res.json() as { rate_limit: Record<string, number> }).rate_limit;
        expect(rl).toMatchObject({ credits_used: 4_000, credits_remaining: 6_000, daily_used_usd: 0.4, daily_remaining_usd: 0.6 });
    });

    it('costs nothing: checking it leaves the day as it was', async () => {
        const buckets = { [BUCKET]: { counter: { count: 4_000, date: today() } } };
        const limiters = new Map();
        for (let i = 0; i < 3; i++) await runWorker('/rate-limit', { headers: KEY, env: HD, buckets, limiters });
        const status = await limiters.get(BUCKET).fetch(new Request('http://internal/status', {
            method: 'POST', body: JSON.stringify({ dailyLimit: 10_000 }),
        }));
        expect((await status.json() as { daily: { used: number } }).daily.used).toBe(4_000);
    });
});

describe('/rate-limit when the usage lookup fails (oxjob #1548)', () => {
    const cases: [string, Error | (() => Response)][] = [
        ['the limiter throws', new Error('Durable Object reset because its code was updated')],
        ['the limiter answers 500', () => new Response('{"error":"boom"}', { status: 500 })],
        ['the limiter answers without usage numbers', () => Response.json({ onetime: { remaining: 0 } })],
        ['the limiter answers something that is not JSON', () => new Response('oops', { status: 200 })],
    ];
    for (const [name, status] of cases) {
        it(`${name}: 503 with a retryable body, never a made-up full allowance`, async () => {
            const { res } = await runWorker('/rate-limit', { headers: KEY, env: { ...HD, ...limiterAnswering(status) } });
            expect(res.status).toBe(503);
            expect(res.headers.get('Retry-After')).toBe('5');
            expect(res.headers.get('Access-Control-Allow-Origin')).toBe('*');
            const body = await res.json() as Record<string, unknown>;
            expect(body).toMatchObject({ error: 'Usage lookup failed', reason: 'usage_lookup_failed', retryAfter: 5 });
            expect(body.rate_limit).toBeUndefined();
            expect(JSON.stringify(body)).not.toMatch(/remaining_usd|credits_remaining/);
        });
    }
});
