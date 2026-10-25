// The origin key (oxjob #1782): X-OpenAlex-Origin-Key goes on every request to the env origins once
// ORIGIN_SHARED_SECRET is set, on no request while it isn't, never to another host, and a client's own
// X-OpenAlex-Origin-Key never reaches an origin.
import { describe, it, expect, afterEach, vi } from 'vitest';
import { ORIGIN_KEY_HEADER, setOriginKey } from './originKey';
import { runWorker } from './testHarness';

const SECRET = 'origin-secret-0123456789';
const ENV = { OPENALEX_API_URL: 'https://origin.test', SEARCH_API_URL: 'https://search.test', TEXT_API_URL: 'https://text.test' };

// A stub origin that records each outbound request's URL and origin-key header.
function origin() {
    const sent: { url: string; key: string | null }[] = [];
    const fetch = async (input: string | Request, init?: RequestInit) => {
        const headers = typeof input === 'string' ? new Headers(init?.headers) : input.headers;
        sent.push({ url: typeof input === 'string' ? input : input.url, key: headers.get(ORIGIN_KEY_HEADER) });
        return new Response('{"meta":{},"results":[]}', { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    return { sent, fetch };
}

afterEach(() => vi.unstubAllGlobals());

describe('setOriginKey', () => {
    it('sets the secret for each env origin', () => {
        for (const u of ['https://origin.test/works?x=1', 'https://search.test/authors', 'https://text.test/text/x']) {
            const h = new Headers();
            setOriginKey(h, { ...ENV, ORIGIN_SHARED_SECRET: SECRET }, u);
            expect(h.get(ORIGIN_KEY_HEADER)).toBe(SECRET);
        }
    });

    it('never sends it to another host, scheme or port', () => {
        for (const u of ['https://evil.example/works', 'http://origin.test/works', 'https://origin.test:8443/works',
                         'https://origin.test.evil.example/works', 'data:text/plain,x', 'not a url']) {
            const h = new Headers();
            setOriginKey(h, { ...ENV, ORIGIN_SHARED_SECRET: SECRET }, u);
            expect(h.get(ORIGIN_KEY_HEADER)).toBeNull();
        }
    });

    it('is inert when the secret is unset, empty or blank', () => {
        for (const secret of [undefined, '', '   ']) {
            const h = new Headers();
            setOriginKey(h, { ...ENV, ORIGIN_SHARED_SECRET: secret }, 'https://origin.test/works');
            expect(h.has(ORIGIN_KEY_HEADER)).toBe(false);
        }
    });

    it('drops a value already on the headers, set or not', () => {
        for (const secret of [undefined, SECRET]) {
            const h = new Headers({ [ORIGIN_KEY_HEADER]: 'client-guess' });
            setOriginKey(h, { ...ENV, ORIGIN_SHARED_SECRET: secret }, 'https://evil.example/');
            expect(h.has(ORIGIN_KEY_HEADER)).toBe(false);
        }
    });
});

describe('the proxy sends the origin key', () => {
    it('on a proxied request, to the API origin and the search origin', async () => {
        const o = origin();
        await runWorker('/works?filter=type:article', { fetch: o.fetch, env: { ...ENV, ORIGIN_SHARED_SECRET: SECRET } });
        await runWorker('/works?search=quantum', { fetch: o.fetch, env: { ...ENV, ORIGIN_SHARED_SECRET: SECRET } });
        expect(o.sent.map(s => [new URL(s.url).origin, s.key])).toEqual([
            ['https://origin.test', SECRET], ['https://search.test', SECRET]]);
    });

    it('on all four /gui/autocomplete lookups', async () => {
        const o = origin();
        const { res } = await runWorker('/gui/autocomplete?q=cancer', { fetch: o.fetch, env: { ...ENV, ORIGIN_SHARED_SECRET: SECRET } });
        expect(res.status).toBe(200);
        expect(o.sent).toHaveLength(4);
        expect(o.sent.every(s => s.key === SECRET)).toBe(true);
    });

    it('nowhere while the secret is unset or empty', async () => {
        for (const secret of [undefined, '']) {
            const o = origin();
            await runWorker('/works?search=quantum', { fetch: o.fetch, env: { ...ENV, ORIGIN_SHARED_SECRET: secret } });
            await runWorker('/gui/autocomplete?q=cancer', { fetch: o.fetch, env: { ...ENV, ORIGIN_SHARED_SECRET: secret } });
            expect(o.sent).toHaveLength(5);
            expect(o.sent.every(s => s.key === null)).toBe(true);
        }
    });

    it("never forwards a client's own X-OpenAlex-Origin-Key", async () => {
        for (const secret of [undefined, SECRET]) {
            const o = origin();
            const headers = { [ORIGIN_KEY_HEADER]: 'client-guess' };
            await runWorker('/works?filter=type:article', { fetch: o.fetch, headers, env: { ...ENV, ORIGIN_SHARED_SECRET: secret } });
            await runWorker('/gui/autocomplete?q=cancer', { fetch: o.fetch, headers, env: { ...ENV, ORIGIN_SHARED_SECRET: secret } });
            expect(o.sent).toHaveLength(5);
            expect(o.sent.every(s => s.key === (secret ?? null))).toBe(true);
        }
    });
});
