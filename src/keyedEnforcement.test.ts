// The enforcement list's keyed entries: free accounts run as one client share one free day (oxjob #1725).
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { parseState, matchEnforcement, enforceDailyLimit, _resetEnforcementForTests,
         ENFORCE_KEY_BLOCK_MESSAGE, ENFORCE_KEY_BUDGET_MESSAGE, ENFORCE_KEY_SEMANTIC_MESSAGE } from './enforcementList';
import { sha256Hex } from './contactBudget';
import { mintUiToken } from './uiToken';
import { RateLimiter } from './rateLimiter';
import { runWorker, today, HARNESS_IP, HARNESS_UI_SECRET } from './testHarness';

// A keyed request looks its key up in api_keys_view: this fake database answers from KEYS (see highRps.test.ts).
const db = vi.hoisted(() => ({ keys: new Map<string, Record<string, unknown>>(), down: false }));
vi.mock('pg', () => ({
    Client: class {
        async connect() { if (db.down) throw new Error('no database'); }
        async query(_sql: string, [key]: string[]) { const row = db.keys.get(key); return { rows: row ? [row] : [] }; }
        async end() {}
    },
}));
const row = (user_id: string | null, o: Record<string, unknown> = {}) => ({
    max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
    onetime_credits_expires_at: null, plan: null, rate_throttled: false, throttle_scope: null, user_id, org_id: null, ...o,
});
// Free accounts of the farm, one key each; plus accounts that are on the list but must never be matched.
for (const k of ['farm-a', 'farm-b', 'farm-c', 'farm-d', 'farm-e', 'farm-f', 'farm-g']) db.keys.set(k, row(`user-${k}`));
db.keys.set('agent-of-farm-a', row('user-farm-a', { budget_key: 'farm-a' }));       // an agent key of a listed person
db.keys.set('farm-paid', row('user-farm-paid', { plan: 'member', max_per_day: 1_000_000, max_credits_per_day: 1_000_000 }));
db.keys.set('farm-prepaid', row('user-farm-prepaid', { onetime_credits_balance: 50_000, onetime_credits_expires_at: '2099-01-01' }));
db.keys.set('farm-org', row(null, { org_id: 'org-Acme' }));
db.keys.set('loner', row('user-loner'));
const FARM_USERS = ['farm-a', 'farm-b', 'farm-c', 'farm-d', 'farm-e', 'farm-f', 'farm-g', 'farm-paid', 'farm-prepaid'].map(k => `user-${k}`);

const UA = 'Go-http-client/2.0';
const LATER = Math.floor(Date.now() / 1000) + 3600;
const facts = (o: Partial<{ ua: string; ip: string | null }> = {}) =>
    ({ ua: UA, mailto: null, refererHost: null, ip: '203.0.113.7', asn: 401560, ...o });
const shas = (...xs: string[]) => Promise.all(xs.map(x => sha256Hex(x)));

describe('parseState: keyed entries', () => {
    it('reads keyed_mode (default off) and a keyed entry with its accounts', async () => {
        const [a, b] = await shas('user-farm-a', 'user-farm-b');
        expect(parseState({ mode: 'enforce', entries: [] }).keyed_mode).toBe('off');
        const s = parseState({ mode: 'enforce', keyed_mode: 'shadow', entries: [
            { id: 'grp', applies_to: 'free_keys', match: { account_shas: [a, b] }, action: 'shared_budget', expires: LATER },
        ] });
        expect(s.keyed_mode).toBe('shadow');
        expect(s.entries[0].applies_to).toBe('free_keys');
        expect([...s.entries[0].match.account_shas!]).toEqual([a, b]);
        expect(enforceDailyLimit(s.entries[0])).toBe(10_000);
    });

    it('drops keyed entries that could catch strangers or are only partly understood', async () => {
        const [a] = await shas('user-farm-a');
        const s = parseState({ mode: 'enforce', keyed_mode: 'shadow', entries: [
            { id: 'net-only', applies_to: 'free_keys', match: { asn: 401560 }, action: 'block', expires: LATER },
            { id: 'addr', applies_to: 'free_keys', match: { account_shas: [a], mailto_sha: a }, action: 'block', expires: LATER },
            { id: 'bad-hash', applies_to: 'free_keys', match: { account_shas: [a, 'nope'] }, action: 'block', expires: LATER },
            { id: 'keyless-accounts', match: { account_shas: [a] }, action: 'block', expires: LATER },
            { id: 'other-scope', applies_to: 'paid_keys', match: { account_shas: [a] }, action: 'block', expires: LATER },
            { id: 'ua-net', applies_to: 'free_keys', match: { ua_sha: a, ip_prefix: '198.51.100.' }, action: 'shared_budget', expires: LATER },
        ] });
        expect(s.entries.map(e => e.id)).toEqual(['ua-net']);
    });
});

describe('matchEnforcement with an account', () => {
    it('keyed entries never match keyless requests, and keyless entries never match free keys', async () => {
        const uaSha = await sha256Hex(UA);
        const keyed = parseState({ mode: 'enforce', keyed_mode: 'enforce', entries: [
            { id: 'keyed-ua', applies_to: 'free_keys', match: { ua_sha: uaSha }, action: 'block', expires: LATER }] });
        expect(await matchEnforcement(keyed, facts(), Date.now())).toBeNull();
        expect((await matchEnforcement(keyed, facts(), Date.now(), 'user-loner'))?.entry.id).toBe('keyed-ua');
        const keyless = parseState({ mode: 'enforce', keyed_mode: 'enforce', entries: [
            { id: 'keyless-ua', match: { ua_sha: uaSha }, action: 'block', expires: LATER }] });
        expect(await matchEnforcement(keyless, facts(), Date.now(), 'user-loner')).toBeNull();
    });

    it('its own switch: off matches nothing; shadow stays shadow while the list enforces; the list off is off', async () => {
        const [a] = await shas('user-farm-a');
        const entry = { id: 'grp', applies_to: 'free_keys', match: { account_shas: [a] }, action: 'block', expires: LATER };
        const at = (mode: string, keyed_mode?: string, extra = {}) =>
            matchEnforcement(parseState({ mode, keyed_mode, entries: [{ ...entry, ...extra }] }), facts(), Date.now(), 'user-farm-a');
        expect(await at('enforce')).toBeNull();
        expect(await at('enforce', 'off')).toBeNull();
        expect((await at('enforce', 'shadow'))?.mode).toBe('shadow');
        expect((await at('enforce', 'enforce'))?.mode).toBe('enforce');
        expect((await at('shadow', 'enforce'))?.mode).toBe('shadow');
        expect((await at('enforce', 'enforce', { mode: 'shadow' }))?.mode).toBe('shadow');
        expect(await at('off', 'enforce')).toBeNull();
    });

    it('matches the listed accounts only, or a user agent on a network', async () => {
        const state = parseState({ mode: 'enforce', keyed_mode: 'shadow', entries: [
            { id: 'grp', applies_to: 'free_keys', match: { account_shas: await shas('user-farm-a', 'user-farm-b') }, action: 'shared_budget', expires: LATER },
            { id: 'sig', applies_to: 'free_keys', match: { ua_sha: await sha256Hex('Chrome/124 farm'), ip_prefix: '198.51.100.' }, action: 'shared_budget', expires: LATER },
        ] });
        expect((await matchEnforcement(state, facts(), Date.now(), 'user-farm-b'))?.entry.id).toBe('grp');
        expect(await matchEnforcement(state, facts(), Date.now(), 'user-loner')).toBeNull();
        expect((await matchEnforcement(state, facts({ ua: 'Chrome/124 farm', ip: '198.51.100.9' }), Date.now(), 'user-loner'))?.entry.id).toBe('sig');
        expect(await matchEnforcement(state, facts({ ua: 'Chrome/124 farm', ip: '203.0.113.9' }), Date.now(), 'user-loner')).toBeNull();
    });
});

describe('keyed entries on the API path', () => {
    beforeEach(() => { _resetEnforcementForTests(); db.down = false; });
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    async function env(state: unknown) {
        const points: { blobs: string[] }[] = [];
        return { points, env: { HYPERDRIVE: { connectionString: 'postgres://test' }, ENFORCEMENT: { get: async () => state },
                                ENFORCE_AE: { writeDataPoint: (p: { blobs: string[] }) => { points.push(p); } } } };
    }
    const farm = async (keyed_mode: string, action = 'shared_budget') =>
        ({ mode: 'enforce', keyed_mode, entries: [{ id: 'grp', applies_to: 'free_keys', match: { account_shas: await shas(...FARM_USERS) }, action, expires: LATER }] });
    const key = (k: string) => ({ Authorization: `Bearer ${k}`, 'User-Agent': UA });

    it('shadow: the group counts in its own bucket and only records the refusal', async () => {
        const { env: e, points } = await env(await farm('shadow'));
        const first = await runWorker('/works?search=x', { headers: key('farm-a'), env: e });
        expect(first.res.status).toBe(200);
        expect(first.checks.map(c => [c.bucket, c.dailyLimit])).toEqual([['credits:farm-a', 10_000], ['credits:enforce:shadow:grp', 10_000]]);
        const spent = { 'credits:enforce:shadow:grp': { counter: { count: 10_000, date: today() } } };
        expect((await runWorker('/works?search=x', { headers: key('farm-b'), env: e, buckets: spent })).res.status).toBe(200);
        expect(points.map(p => p.blobs)).toEqual([['grp', 'shared_budget', 'shadow', 'search', 'pass'], ['grp', 'shared_budget', 'shadow', 'search', 'refuse']]);
    });

    it('enforce: every key spends its own day AND the group one; once the group day is spent its keys get 429', async () => {
        const { env: e, points } = await env(await farm('enforce'));
        const first = await runWorker('/works?search=x', { headers: key('farm-a'), env: e });
        expect(first.res.status).toBe(200);
        expect(first.checks.map(c => [c.bucket, c.dailyLimit])).toEqual([['credits:farm-a', 10_000], ['credits:enforce:grp', 10_000]]);
        const spent = { 'credits:enforce:grp': { counter: { count: 10_000, date: today() } } };
        const second = await runWorker('/works?search=x', { headers: key('farm-c'), env: e, buckets: spent });
        expect(second.res.status).toBe(429);
        expect((await second.res.json() as { message: string }).message).toBe(ENFORCE_KEY_BUDGET_MESSAGE);
        expect(second.res.headers.get('Retry-After')).toBeTruthy();
        expect(points.map(p => p.blobs[4])).toEqual(['pass', 'refuse']);
    });

    it('entries naming one budget share one day: a second entry for the same client starts no fresh day', async () => {
        const [a, b] = await shas('user-farm-a', 'user-farm-b');
        const { env: e } = await env({ mode: 'enforce', keyed_mode: 'enforce', entries: [
            { id: 'grp-ua', applies_to: 'free_keys', match: { ua_sha: await sha256Hex(UA) }, action: 'shared_budget', expires: LATER, budget: 'grp' },
            { id: 'grp', applies_to: 'free_keys', match: { account_shas: [a, b] }, action: 'shared_budget', expires: LATER },
            { id: 'bad', applies_to: 'free_keys', match: { account_shas: [a] }, action: 'shared_budget', expires: LATER, budget: 'no spaces' },
        ] });
        const first = await runWorker('/works?search=x', { headers: key('farm-c'), env: e });
        expect(first.checks.map(c => c.bucket)).toEqual(['credits:farm-c', 'credits:enforce:grp']);
        const spent = { 'credits:enforce:grp': { counter: { count: 10_000, date: today() } } };
        expect((await runWorker('/works?search=x', { headers: key('farm-d'), env: e, buckets: spent })).res.status).toBe(429);
        expect(parseState({ mode: 'enforce', entries: [
            { id: 'bad', applies_to: 'free_keys', match: { account_shas: [a] }, action: 'shared_budget', expires: LATER, budget: 'no spaces' },
        ] }).entries[0].budget).toBeUndefined();
    });

    it('an agent key of a listed person is matched too (entries name accounts, not keys)', async () => {
        const { env: e } = await env(await farm('enforce', 'block'));
        expect((await runWorker('/works?search=x', { headers: key('agent-of-farm-a'), env: e })).res.status).toBe(403);
    });

    it('enforce: block answers 403 with the paid plans and support@, before any budget', async () => {
        const { env: e } = await env(await farm('enforce', 'block'));
        const { res, checks } = await runWorker('/works?search=x', { headers: key('farm-d'), env: e });
        expect(res.status).toBe(403);
        const msg = (await res.json() as { message: string }).message;
        expect(msg).toBe(ENFORCE_KEY_BLOCK_MESSAGE);
        expect(msg).toContain('openalex.org/pricing');
        expect(msg).toContain('support@openalex.org');
        expect(checks).toEqual([]);
    });

    it('semantic: the group shares one search a second (enforce refuses, shadow records it once)', async () => {
        for (const mode of ['enforce', 'shadow']) {
            _resetEnforcementForTests();
            const { env: e, points } = await env(await farm(mode));
            const limiters = new Map<string, RateLimiter>();
            const one = await runWorker('/works?search.semantic=heart+failure', { headers: key('farm-e'), env: e, limiters });
            const two = await runWorker('/works?search.semantic=kidney+stones', { headers: key('farm-f'), env: e, limiters });
            expect(one.res.status).toBe(200);
            if (mode === 'enforce') {
                expect(two.res.status).toBe(429);
                expect((await two.res.json() as { message: string }).message).toBe(ENFORCE_KEY_SEMANTIC_MESSAGE);
            } else {
                expect(two.res.status).toBe(200);
            }
            expect(points.map(p => p.blobs[4])).toEqual(['pass', 'refuse_semantic']);
        }
    });

    it('never matches paid plans, prepaid balances, org keys, unlisted keys, the website, or a key when the DB is down', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {});  // the fail-open DB lookup logs
        const { env: e, points } = await env(await farm('enforce', 'block'));
        for (const k of ['farm-paid', 'farm-prepaid', 'farm-org', 'loner']) {
            expect((await runWorker('/works?search=x', { headers: key(k), env: e })).res.status, k).toBe(200);
        }
        const tok = await mintUiToken(HARNESS_UI_SECRET, Date.now(), 1800, HARNESS_IP);
        expect((await runWorker('/works?search=x', { headers: { ...key('farm-a'), 'X-OpenAlex-UI': tok }, env: e })).res.status).toBe(200);
        db.down = true;  // farm-g is listed and not yet cached: its lookup fails open, as no one's free key
        expect((await runWorker('/works?search=x', { headers: key('farm-g'), env: e })).res.status).toBe(200);
        expect(points).toEqual([]);
    });

    it("a refused group takes no semantic-ladder token at a forced ORANGE (#1433's note)", async () => {
        const ladder: string[] = [];
        const health = { FORCE_SEMANTIC_HEALTH_STATE: 'ORANGE', SEARCH_HEALTH: { idFromName: (n: string) => n, get: () => ({
            fetch: async (u: string) => { if (u.endsWith("/check-anon-budget")) ladder.push(u); return Response.json({ ok: true, state: "ORANGE" }); } }) } };
        const SEM = '/works?search.semantic=coral+reef';
        const blocked = await env(await farm('enforce', 'block'));
        expect((await runWorker(SEM, { headers: key('farm-a'), env: { ...blocked.env, ...health } })).res.status).toBe(403);
        expect(ladder).toEqual([]);
        _resetEnforcementForTests();
        const budget = await env(await farm('enforce'));
        const spent = { 'credits:enforce:grp': { counter: { count: 10_000, date: today() } } };
        for (let i = 0; i < 2; i++) {  // the first refusal teaches this isolate the day is spent; then no token at all
            expect((await runWorker(SEM, { headers: key('farm-b'), env: { ...budget.env, ...health }, buckets: spent })).res.status).toBe(429);
        }
        expect(ladder.length).toBe(1);
        expect((await runWorker(SEM, { headers: key('loner'), env: { ...budget.env, ...health } })).res.status).toBe(200);
        expect(ladder.length).toBe(2);  // an unlisted free key does go through the ladder
    });

    it('keyless requests are untouched by keyed entries', async () => {
        const { env: e, points } = await env({ mode: 'enforce', keyed_mode: 'enforce', entries: [
            { id: 'sig', applies_to: 'free_keys', match: { ua_sha: await sha256Hex(UA) }, action: 'block', expires: LATER }] });
        expect((await runWorker('/works?search=x', { headers: { 'User-Agent': UA }, env: e })).res.status).toBe(200);
        expect(points).toEqual([]);
    });
});
