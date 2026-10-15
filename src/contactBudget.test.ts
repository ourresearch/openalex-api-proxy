// One keyless budget per contact address, across every IP that sends it (oxjob #1692).
import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { contactBudgetFor, _resetContactSpent } from './contactBudget';
import { mintUiToken } from './uiToken';
import { VERIFIED_ASSISTANT_HEADER } from './verifiedAssistant';
import { runWorker, today, HARNESS_ASSISTANT_TOKEN, HARNESS_IP, HARNESS_UI_SECRET } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() { throw new Error('no database in tests'); }
        async end() {}
    },
}));

const keyless = { apiKey: null, trustedUi: false, verifiedAssistant: false };
const p = (mailto: string) => new URLSearchParams({ search: 'x', mailto });

describe('contactBudgetFor', () => {
    it('a real-looking address gets a free key day, shared; the bucket name holds a hash, not the address', async () => {
        const c = await contactBudgetFor(p('Ana.Silva@Uni-Example.edu '), keyless);
        expect(c).toMatchObject({ dailyLimit: 10_000, placeholder: false });
        expect(c!.bucket).toMatch(/^credits:contact:[0-9a-f]{32}$/);
        expect((await contactBudgetFor(p('ana.silva@uni-example.edu'), keyless))!.bucket).toBe(c!.bucket);
    });

    it('placeholders get one keyless budget', async () => {
        for (const m of ['someone@example.org', 'x@example.com', 'you@gmail.com', 'test@lab.org']) {
            expect(await contactBudgetFor(p(m), keyless)).toMatchObject({ dailyLimit: 1_000, placeholder: true });
        }
    });

    it('nothing for keys, the website, verified assistants, openalex.org addresses, or non-addresses', async () => {
        expect(await contactBudgetFor(p('a@lab.edu'), { ...keyless, apiKey: 'k' })).toBeNull();
        expect(await contactBudgetFor(p('a@lab.edu'), { ...keyless, trustedUi: true })).toBeNull();
        expect(await contactBudgetFor(p('a@lab.edu'), { ...keyless, verifiedAssistant: true })).toBeNull();
        for (const m of ['ui@openalex.org', 'support@openalex.org', 'not-an-address', '@lab.edu', 'a@', '']) {
            expect(await contactBudgetFor(p(m), keyless)).toBeNull();
        }
        expect(await contactBudgetFor(new URLSearchParams({ search: 'x' }), keyless)).toBeNull();
    });
});

describe('contact budget on the API path', () => {
    beforeEach(() => _resetContactSpent());
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
    const URL_ = '/works?search=coral&mailto=ana@lab.edu';

    it('a keyless request with an address is charged to its IP and to the address', async () => {
        const { res, checks } = await runWorker(URL_);
        expect(res.status).toBe(200);
        expect(checks.map(c => [c.bucket.replace(/[0-9a-f]{32}$/, 'H'), c.dailyLimit])).toEqual([
            [`credits:${HARNESS_IP}`, 1000], ['credits:contact:H', 10_000]]);
    });

    it('two IPs naming the same address share its bucket', async () => {
        const a = await runWorker(URL_, { ip: '198.51.100.1' });
        const b = await runWorker(URL_, { ip: '198.51.100.2' });
        expect(a.checks[1].bucket).toBe(b.checks[1].bucket);
    });

    it("refuses once the address's day is spent, then refuses at the edge without touching any budget", async () => {
        const c = await contactBudgetFor(p('ana@lab.edu'), keyless);
        const spentDay = { [c!.bucket]: { counter: { count: 10_000, date: today() } } };
        const first = await runWorker(URL_, { buckets: spentDay, ip: '198.51.100.1' });
        expect(first.res.status).toBe(429);
        expect((await first.res.json() as { message: string }).message).toContain('mailto');
        const second = await runWorker(URL_, { ip: '198.51.100.2' });
        expect(second.res.status).toBe(429);
        expect(second.checks).toEqual([]);
        expect(second.rows[0].blobs[4]).toBe('contact');
    });

    it('a placeholder address is spent after one keyless budget', async () => {
        const c = await contactBudgetFor(p('bot@example.org'), keyless);
        const spentDay = { [c!.bucket]: { counter: { count: 1_000, date: today() } } };
        expect((await runWorker('/works?search=coral&mailto=bot@example.org', { buckets: spentDay })).res.status).toBe(429);
    });

    it('keys, the website and verified assistants are never charged to an address', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {}); // the fail-open DB lookup logs
        const keyed = await runWorker(URL_, { headers: { Authorization: 'Bearer test-key-123' } });
        const web = await runWorker(URL_, { headers: { 'X-OpenAlex-UI': await mintUiToken(HARNESS_UI_SECRET, Date.now(), 1800, HARNESS_IP) } });
        const va = await runWorker(URL_, { headers: { [VERIFIED_ASSISTANT_HEADER]: HARNESS_ASSISTANT_TOKEN } });
        for (const r of [keyed, web, va]) {
            expect(r.res.status).toBe(200);
            expect(r.checks.some(c => c.bucket.startsWith('credits:contact:'))).toBe(false);
        }
    });
});
