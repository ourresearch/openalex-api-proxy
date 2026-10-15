// Test-only: run the whole Worker on one request, with a real RateLimiter per bucket name (in memory), a stub
// origin and an Analytics Engine sink. Imported only by *.test.ts files, so it never reaches the bundle.
// Each test file that sends keyed requests must vi.mock('pg') itself (vi.mock is hoisted per file).
import { vi } from 'vitest';
import { RateLimiter } from './rateLimiter';
import worker from './index';

export const HARNESS_IP = '203.0.113.7';
export const HARNESS_UI_SECRET = 'test-ui-hmac-secret';
export const HARNESS_ASSISTANT_TOKEN = 'test-verified-assistant-token-0123456789abcdef';
export const DOUBLE7_TRUSTED_UI = 6;  // analytics.ts doubles[6]
export const today = () => new Date().toISOString().split('T')[0];

// An in-memory DurableObjectState: enough storage for RateLimiter, nothing else.
export function fakeState(initial: Record<string, unknown> = {}) {
    const store = new Map<string, unknown>(Object.entries(initial));
    return {
        store,
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

export interface RunOptions {
    headers?: Record<string, string>;
    env?: Record<string, unknown>;
    buckets?: Record<string, Record<string, unknown>>;
    ip?: string;
    method?: string;
    body?: string;
    // Answers every outbound fetch (origin, siteverify). Default: a 200 `{"meta":{}}` origin.
    fetch?: (url: string, init?: RequestInit) => Promise<Response>;
}

export async function runWorker(path: string, opts: RunOptions = {}) {
    vi.stubGlobal('fetch', vi.fn(opts.fetch ?? (async () =>
        new Response('{"meta":{}}', { status: 200, headers: { 'Content-Type': 'application/json' } }))));
    const limiters = new Map<string, RateLimiter>();
    const checks: { bucket: string; dailyLimit: number; perSecondLimit: number }[] = [];
    const rows: { blobs: string[]; doubles: number[] }[] = [];
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
        VERIFIED_ASSISTANT_TOKEN: HARNESS_ASSISTANT_TOKEN,
        UI_TOKEN_HMAC_SECRET: HARNESS_UI_SECRET,
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
        ANALYTICS: { writeDataPoint: (p: { blobs: string[]; doubles: number[] }) => { rows.push(p); } },
        ...opts.env,
    };
    const ctx = { waitUntil: (p: Promise<unknown>) => { pending.push(p); }, passThroughOnException: () => {} };
    const req = new Request(`https://api.openalex.org${path}`, {
        method: opts.method ?? 'GET',
        body: opts.body,
        headers: { 'CF-Connecting-IP': opts.ip ?? HARNESS_IP, ...opts.headers },
    });
    const res = await worker.fetch(req, env as any, ctx as any);
    await Promise.all(pending);
    return { res, checks, rows };
}
