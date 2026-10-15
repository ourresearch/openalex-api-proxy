// The website's perks go to its token only, and the token works only on the network that minted it
// (oxjob #1691 drop the openalex.org challenge, #1692 keyless IP rotators).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { mintUiToken, signPayload, verifyUiToken } from './uiToken';
import { runWorker, today, DOUBLE7_TRUSTED_UI, HARNESS_IP, HARNESS_UI_SECRET } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() { throw new Error('no database in tests'); }
        async end() {}
    },
}));

const OTHER_IP = '198.51.100.9';
const FACET = '/works?search=coral+reefs&group_by=publication_year';
const SEARCH = '/works?search=coral+reefs';
const CURSOR_PAGE2 = '/works?filter=publication_year:2020&cursor=IlsnLUluZmluaXR5JywgMCwgJ2h0dHBzOi8vb3BlbmFsZXgub3JnL1cxMjMnXSI=';
const FORGED = { Referer: 'https://openalex.org/works?search=coral', Origin: 'https://openalex.org' };
const token = (ip: string = HARNESS_IP) => mintUiToken(HARNESS_UI_SECRET, Date.now(), 1800, ip);

describe('website perks need the website token, not an openalex.org Referer', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it('a search facet with a forged openalex.org Referer and Origin costs a search (10), like any keyless call', async () => {
        const { res, rows } = await runWorker(FACET, { headers: FORGED });
        expect(res.status).toBe(200);
        expect(res.headers.get('X-RateLimit-Remaining')).toBe('990');
        expect(rows[0].doubles[DOUBLE7_TRUSTED_UI]).toBe(0);
    });

    it('the same facet with a valid website token costs 1 (website facet price, oxjob #1533)', async () => {
        const { res, rows } = await runWorker(FACET, { headers: { 'X-OpenAlex-UI': await token() } });
        expect(res.headers.get('X-RateLimit-Remaining')).toBe('999');
        expect(rows[0].doubles[DOUBLE7_TRUSTED_UI]).toBe(1);
    });

    it('a forged Referer no longer skips the anonymous-search shed', async () => {
        const { res, checks } = await runWorker(SEARCH, { headers: FORGED, env: { FORCE_HEALTH_STATE: 'RED' } });
        expect(res.status).toBe(503);
        expect(checks).toEqual([]);
    });

    it('the website token still skips the shed', async () => {
        const { res } = await runWorker(SEARCH, { headers: { 'X-OpenAlex-UI': await token() }, env: { FORCE_HEALTH_STATE: 'RED' } });
        expect(res.status).toBe(200);
    });
});

describe('a website token only works on the network that minted it', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it('moved to another IP it earns nothing, and the response asks the website to re-mint', async () => {
        const { res, rows } = await runWorker(FACET, { headers: { 'X-OpenAlex-UI': await token() }, ip: OTHER_IP });
        expect(res.status).toBe(200);
        expect(res.headers.get('X-RateLimit-Remaining')).toBe('990');
        expect(res.headers.get('X-OpenAlex-UI-Token')).toBe('refresh');
        expect(res.headers.get('Access-Control-Expose-Headers')).toContain('X-OpenAlex-UI-Token');
        expect(rows[0].doubles[DOUBLE7_TRUSTED_UI]).toBe(0);
    });

    it('moved to another IP it no longer opens keyless cursor paging (oxjob #1682 gate)', async () => {
        expect((await runWorker(CURSOR_PAGE2, { headers: { 'X-OpenAlex-UI': await token() } })).res.status).toBe(200);
        const moved = await runWorker(CURSOR_PAGE2, { headers: { 'X-OpenAlex-UI': await token() }, ip: OTHER_IP });
        expect(moved.res.status).toBe(401);
        expect(moved.res.headers.get('X-OpenAlex-UI-Token')).toBe('refresh');
    });

    it('a forged, expired or garbage token gets the refresh signal too; no token gets nothing', async () => {
        const expired = await mintUiToken(HARNESS_UI_SECRET, Date.now() - 3600_000, 1800, HARNESS_IP);
        const forged = await mintUiToken('attacker-secret', Date.now(), 1800, HARNESS_IP);
        for (const t of [expired, forged, 'garbage']) {
            const { res } = await runWorker(SEARCH, { headers: { 'X-OpenAlex-UI': t } });
            expect(res.status).toBe(200);
            expect(res.headers.get('X-OpenAlex-UI-Token')).toBe('refresh');
        }
        expect((await runWorker(SEARCH)).res.headers.get('X-OpenAlex-UI-Token')).toBeNull();
        expect((await runWorker(SEARCH, { headers: { 'X-OpenAlex-UI': await token() } })).res.headers.get('X-OpenAlex-UI-Token')).toBeNull();
    });

    it('open tabs keep their perks across the deploy: an unbound v1 token still counts until it expires', async () => {
        const iat = Math.floor(Date.now() / 1000);
        const v1 = await signPayload(HARNESS_UI_SECRET, { v: 1, iat, exp: iat + 1800, nonce: 'v1' });
        const { res } = await runWorker(FACET, { headers: { 'X-OpenAlex-UI': v1 }, ip: OTHER_IP });
        expect(res.headers.get('X-RateLimit-Remaining')).toBe('999');
        expect(res.headers.get('X-OpenAlex-UI-Token')).toBeNull();
    });
});

describe('/ui-token minting', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
    const env = { TURNSTILE_SECRET: 'ts-secret' };
    const post = { method: 'POST', body: JSON.stringify({ turnstileResponse: 'solve' }), headers: { 'Content-Type': 'application/json' } };
    const siteverify = (hostname: string) => vi.fn(async () => new Response(JSON.stringify({ success: true, hostname })));

    it('mints a token bound to the caller: valid from the same IP, refused from another', async () => {
        const { res } = await runWorker('/ui-token', { ...post, env, fetch: siteverify('openalex.org') });
        expect(res.status).toBe(200);
        const { token: t } = await res.json() as { token: string };
        expect((await verifyUiToken(t, HARNESS_UI_SECRET, Date.now(), HARNESS_IP)).valid).toBe(true);
        expect((await verifyUiToken(t, HARNESS_UI_SECRET, Date.now(), OTHER_IP)).reason).toBe('wrong_network');
    });

    it('refuses a Turnstile solve made on another site', async () => {
        const { res } = await runWorker('/ui-token', { ...post, env, fetch: siteverify('scraper.example') });
        expect(res.status).toBe(403);
        expect(await res.json()).toMatchObject({ errorCodes: ['hostname-mismatch'] });
    });

    it('caps mints per IP per day, before calling siteverify', async () => {
        const verify = siteverify('openalex.org');
        const spent = { [`uimint:${HARNESS_IP}`]: { counter: { count: 500, date: today() } } };
        const { res } = await runWorker('/ui-token', { ...post, env, fetch: verify, buckets: spent });
        expect(res.status).toBe(429);
        expect(verify).not.toHaveBeenCalled();
        const elsewhere = await runWorker('/ui-token', { ...post, env, fetch: siteverify('openalex.org'), buckets: spent, ip: OTHER_IP });
        expect(elsewhere.res.status).toBe(200);
    });
});
