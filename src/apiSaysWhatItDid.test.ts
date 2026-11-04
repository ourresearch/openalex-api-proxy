// The API says what it did (oxjob #2003): a rerank the proxy drops under load is told to the origin and logged, and
// the proxy's own 504 is worded by what the request was and which clock fired.
import { describe, it, expect, afterEach, vi } from 'vitest';
import { gatewayTimeoutBody } from './gatewayTimeout';
import { mintUiToken } from './uiToken';
import { runWorker, HARNESS_IP as IP, HARNESS_UI_SECRET as UI_SECRET } from './testHarness';

const DOUBLE9_RERANK_SHED = 8;  // analytics.ts doubles[8]

afterEach(() => { vi.unstubAllGlobals(); });

async function run(path: string, health: string, init: { method?: string; body?: string; headers?: Record<string, string> } = {}) {
    const origin: Request[] = [];
    const uiToken = await mintUiToken(UI_SECRET, Date.now(), 1800, IP);
    const out = await runWorker(path, {
        ...init,
        headers: { 'X-OpenAlex-UI': uiToken, ...(init.headers ?? {}) },
        env: { FORCE_HEALTH_STATE: health },
        fetch: async (url, reqInit) => {
            origin.push(new Request(url, reqInit));
            return new Response('{"meta":{}}', { status: 200, headers: { 'Content-Type': 'application/json' } });
        },
    });
    return { ...out, origin };
}

describe('rerank shed under load (oxjob #2003)', () => {
    const SEARCH = '/works?search=coral%20reef%20bleaching&rerank=true';

    it('drops rerank at YELLOW, tells the origin, and logs it', async () => {
        const { origin, rows, res } = await run(SEARCH, 'YELLOW');
        expect(new URL(origin[0].url).searchParams.has('rerank')).toBe(false);
        expect(origin[0].headers.get('X-Rerank-Shed')).toBe('search_busy');
        expect(rows[0].doubles[DOUBLE9_RERANK_SHED]).toBe(1);
        expect(res.headers.get('X-RateLimit-Credits-Used')).toBe('10');  // the search price, no rerank surcharge
    });

    it('keeps rerank at GREEN, with no header and no flag', async () => {
        const { origin, rows } = await run(SEARCH, 'GREEN');
        expect(new URL(origin[0].url).searchParams.get('rerank')).toBe('true');
        expect(origin[0].headers.get('X-Rerank-Shed')).toBeNull();
        expect(rows[0].doubles[DOUBLE9_RERANK_SHED]).toBe(0);
    });

    it('drops a POST body rerank at YELLOW and tells the origin', async () => {
        const { origin } = await run('/', 'YELLOW', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ oql: 'works where title has (coral)', rerank: true }),
        });
        expect(JSON.parse(await origin[0].text())).toEqual({ oql: 'works where title has (coral)' });
        expect(origin[0].headers.get('X-Rerank-Shed')).toBe('search_busy');
    });

    it('drops rerank from both the URL and the body when both ask', async () => {
        const { origin } = await run('/?rerank=true', 'YELLOW', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ oql: 'works where title has (coral)', rerank: true }),
        });
        expect(new URL(origin[0].url).searchParams.has('rerank')).toBe(false);
        expect(JSON.parse(await origin[0].text()).rerank).toBeUndefined();
    });

    it('never forwards a client-sent X-Rerank-Shed', async () => {
        const { origin } = await run(SEARCH, 'GREEN', { headers: { 'X-Rerank-Shed': 'search_busy' } });
        expect(origin[0].headers.get('X-Rerank-Shed')).toBeNull();
    });
});

describe('gatewayTimeoutBody (oxjob #2003)', () => {
    it('tells a record lookup the API was slow, never to narrow a search', () => {
        const b = gatewayTimeoutBody('singleton', 9000, false);
        expect(b.reason).toBe('api_slow');
        expect(b.timeout_seconds).toBe(9);
        expect(b.message).not.toMatch(/broad|narrow/);
        expect(b.message).toMatch(/retry/);
    });

    it('keeps the broad-search advice for searches', () => {
        const b = gatewayTimeoutBody('search', 9000, false);
        expect(b.reason).toBe('query_timeout');
        expect(b.message).toMatch(/very broad search/);
    });

    it('names the 12 s OQL clock and the 25 s count-probe clock', () => {
        expect(gatewayTimeoutBody('list', 12000, true).message).toMatch(/OQL query didn't finish within 12 seconds/);
        expect(gatewayTimeoutBody('list', 25000, false).timeout_seconds).toBe(25);
    });

    it('tells semantic and other callers to retry', () => {
        for (const t of ['semantic', 'content', 'text', undefined] as const) {
            const b = gatewayTimeoutBody(t, 9000, false);
            expect(b.reason).toBe('api_slow');
            expect(b.message).not.toMatch(/broad/);
        }
    });

    it('says nobody was charged', () => {
        for (const t of ['singleton', 'search', 'list', 'semantic'] as const) {
            expect(gatewayTimeoutBody(t, 9000, false).message).toMatch(/not charged/);
        }
    });
});

describe('the 504 a timed-out record lookup gets (oxjob #2003)', () => {
    it('says the API was slow', async () => {
        const { res } = await runWorker('/works/W2741809807', {
            fetch: async () => { throw new DOMException('The operation timed out.', 'TimeoutError'); },
        });
        expect(res.status).toBe(504);
        const body = await res.json() as any;
        expect(body.reason).toBe('api_slow');
        expect(body.message).toMatch(/single record/);
    });
});
