// The private enforcement list for keyless traffic (oxjob #1692).
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { parseState, matchEnforcement, _resetEnforcementForTests, type EnforceState } from './enforcementList';
import { sha256Hex } from './contactBudget';
import { mintUiToken } from './uiToken';
import { VERIFIED_ASSISTANT_HEADER } from './verifiedAssistant';
import { runWorker, today, HARNESS_ASSISTANT_TOKEN, HARNESS_IP, HARNESS_UI_SECRET } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() { throw new Error('no database in tests'); }
        async end() {}
    },
}));

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36';
const LATER = Math.floor(Date.now() / 1000) + 3600;
const facts = (o: Partial<{ ua: string; mailto: string | null; refererHost: string | null; ip: string | null; asn: number | null }> = {}) =>
    ({ ua: UA, mailto: null, refererHost: null, ip: '203.0.113.7', asn: 401560, ...o });

describe('parseState', () => {
    it('anything unreadable is off', () => {
        for (const raw of [null, 'x', 42, {}, { mode: 'loud', entries: [] }]) expect(parseState(raw).mode).toBe('off');
    });

    it('drops entries that are malformed or only partly understood (a half-read entry must match nothing)', () => {
        const s = parseState({ mode: 'shadow', entries: [
            { id: 'ok', match: { asn: 401560 }, action: 'block', expires: LATER },
            { id: 'bad-action', match: { asn: 1 }, action: 'ban', expires: LATER },
            { id: 'no-match', match: {}, action: 'block', expires: LATER },
            { id: 'half', match: { asn: 401560, ua_sha: 'not-a-hash' }, action: 'block', expires: LATER },
            { id: 'bad id!', match: { asn: 1 }, action: 'block', expires: LATER },
            { id: 'v6', match: { net64: '2001:db8:abcd:12::/64' }, action: 'shared_budget', daily_limit: 5000, expires: LATER },
        ] });
        expect(s.entries.map(e => e.id)).toEqual(['ok', 'v6']);
        expect(s.entries[1].daily_limit).toBe(5000);
    });
});

describe('matchEnforcement', () => {
    it('needs every field of an entry to match; skips expired entries; blocks win over budgets', async () => {
        const uaSha = await sha256Hex(UA);
        const state: EnforceState = { mode: 'enforce', entries: [
            { id: 'budget', match: { ua_sha: uaSha }, action: 'shared_budget', expires: LATER },
            { id: 'fleet', match: { ua_sha: uaSha, asn: 401560 }, action: 'block', expires: LATER },
            { id: 'old', match: { asn: 401560 }, action: 'block', expires: 1 },
        ] };
        expect((await matchEnforcement(state, facts(), Date.now()))?.entry.id).toBe('fleet');
        expect((await matchEnforcement(state, facts({ asn: 7922 }), Date.now()))?.entry.id).toBe('budget');
        expect(await matchEnforcement(state, facts({ ua: UA + ' x', asn: 7922 }), Date.now())).toBeNull();
    });

    it('IPv4 prefixes match only IPv4; /64s only IPv6; contact addresses by hash', async () => {
        const state: EnforceState = { mode: 'shadow', entries: [
            { id: 'v4', match: { ip_prefix: '198.51.100.' }, action: 'block', expires: LATER },
            { id: 'v6', match: { net64: '2001:db8:abcd:12::/64' }, action: 'block', expires: LATER },
            { id: 'addr', match: { mailto_sha: await sha256Hex('pool@scrape.example') }, action: 'block', expires: LATER },
        ] };
        expect((await matchEnforcement(state, facts({ ip: '198.51.100.20' }), Date.now()))?.entry.id).toBe('v4');
        expect((await matchEnforcement(state, facts({ ip: '2001:db8:abcd:12:1::9' }), Date.now()))?.entry.id).toBe('v6');
        expect((await matchEnforcement(state, facts({ mailto: ' Pool@Scrape.example ' }), Date.now()))?.entry.id).toBe('addr');
        expect(await matchEnforcement(state, facts(), Date.now())).toBeNull();
    });

    it('an entry marked shadow stays shadow while the list enforces; off matches nothing', async () => {
        const e = { id: 'trial', match: { asn: 401560 }, action: 'block' as const, expires: LATER, mode: 'shadow' as const };
        expect((await matchEnforcement({ mode: 'enforce', entries: [e] }, facts(), Date.now()))?.mode).toBe('shadow');
        expect(await matchEnforcement({ mode: 'off', entries: [e] }, facts(), Date.now())).toBeNull();
    });
});

describe('enforcement list on the API path', () => {
    beforeEach(() => _resetEnforcementForTests());
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    async function env(state: unknown, opts: { failKv?: boolean } = {}) {
        const points: { blobs: string[] }[] = [];
        return {
            points,
            env: {
                ENFORCEMENT: { get: async () => { if (opts.failKv) throw new Error('kv down'); return state; } },
                ENFORCE_AE: { writeDataPoint: (p: { blobs: string[] }) => { points.push(p); } },
            },
        };
    }
    const ua = { 'User-Agent': UA };
    const blockUa = async (mode: string, extra = {}) =>
        ({ mode, entries: [{ id: 'fleet146', match: { ua_sha: await sha256Hex(UA) }, action: 'block', expires: LATER, ...extra }] });
    const budgetUa = async (mode: string) =>
        ({ mode, entries: [{ id: 'pool1', match: { ua_sha: await sha256Hex(UA) }, action: 'shared_budget', daily_limit: 2000, expires: LATER }] });

    it('shadow: a block entry refuses nothing but records that it would have', async () => {
        const { env: e, points } = await env(await blockUa('shadow'));
        const { res } = await runWorker('/works?search=x', { headers: ua, env: e });
        expect(res.status).toBe(200);
        expect(points.map(p => p.blobs)).toEqual([['fleet146', 'block', 'shadow', 'search', 'refuse']]);
    });

    it('enforce: a block entry answers 403 before any budget is touched', async () => {
        const { env: e } = await env(await blockUa('enforce'));
        const { res, checks, rows } = await runWorker('/works?search=x', { headers: ua, env: e });
        expect(res.status).toBe(403);
        expect((await res.json() as { message: string }).message).toContain('free API key');
        expect(checks).toEqual([]);
        expect(rows[0].blobs[4]).toBe('enforce');
    });

    it('enforce: a shared budget is charged per request and refuses once spent', async () => {
        const { env: e, points } = await env(await budgetUa('enforce'));
        const first = await runWorker('/works?search=x', { headers: ua, env: e });
        expect(first.res.status).toBe(200);
        expect(first.checks.map(c => [c.bucket, c.dailyLimit])).toEqual([[`credits:${HARNESS_IP}`, 1000], ['credits:enforce:pool1', 2000]]);
        const spent = { 'credits:enforce:pool1': { counter: { count: 2000, date: today() } } };
        const second = await runWorker('/works?search=x', { headers: ua, env: e, buckets: spent, ip: '198.51.100.3' });
        expect(second.res.status).toBe(429);
        expect(points.map(p => p.blobs[4])).toEqual(['pass', 'refuse']);
    });

    it('shadow: a shared budget counts in its own bucket and only records the refusal', async () => {
        const { env: e, points } = await env(await budgetUa('shadow'));
        const spent = { 'credits:enforce:shadow:pool1': { counter: { count: 2000, date: today() } } };
        const { res, checks } = await runWorker('/works?search=x', { headers: ua, env: e, buckets: spent });
        expect(res.status).toBe(200);
        expect(checks.map(c => c.bucket)).toContain('credits:enforce:shadow:pool1');
        expect(points[0].blobs.slice(1)).toEqual(['shared_budget', 'shadow', 'search', 'refuse']);
    });

    it('an entry in shadow stays shadow while the list enforces', async () => {
        const { env: e, points } = await env(await blockUa('enforce', { mode: 'shadow' }));
        expect((await runWorker('/works?search=x', { headers: ua, env: e })).res.status).toBe(200);
        expect(points[0].blobs[2]).toBe('shadow');
    });

    it('never matches keys, the website or verified AI assistants', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {}); // the fail-open DB lookup logs
        const { env: e, points } = await env(await blockUa('enforce'));
        const tok = await mintUiToken(HARNESS_UI_SECRET, Date.now(), 1800, HARNESS_IP);
        const callers: Record<string, string>[] = [{ Authorization: 'Bearer test-key-123' }, { 'X-OpenAlex-UI': tok }, { [VERIFIED_ASSISTANT_HEADER]: HARNESS_ASSISTANT_TOKEN }];
        for (const h of callers) {
            expect((await runWorker('/works?search=x', { headers: { ...ua, ...h }, env: e })).res.status).toBe(200);
        }
        expect(points).toEqual([]);
    });

    it('fails open: list off, no KV binding, or a KV error changes nothing', async () => {
        for (const made of [await env(await blockUa('off')), await env(await blockUa('enforce'), { failKv: true })]) {
            _resetEnforcementForTests();
            expect((await runWorker('/works?search=x', { headers: ua, env: made.env })).res.status).toBe(200);
            expect(made.points).toEqual([]);
        }
        expect((await runWorker('/works?search=x', { headers: ua })).res.status).toBe(200);
    });
});
