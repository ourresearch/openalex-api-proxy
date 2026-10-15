// Keyless budgets are per network: an IPv6 /64 shares one budget, as an IPv4 address (or a NAT behind one) does
// (oxjob #1692: on 14 Oct, 1,123 /64s took 3.33M keyless credits by spreading over 39K addresses).
import { describe, it, expect, vi, afterEach } from 'vitest';
import { VERIFIED_ASSISTANT_HEADER } from './verifiedAssistant';
import { runWorker, today, HARNESS_ASSISTANT_TOKEN } from './testHarness';

vi.mock('pg', () => ({
    Client: class {
        async connect() { throw new Error('no database in tests'); }
        async end() {}
    },
}));

const SEARCH = '/works?search=coral+reefs';
const V6_A = '2001:db8:abcd:12::1';
const V6_B = '2001:db8:abcd:12:9f2e:1:2:3';   // same /64
const V6_OTHER = '2001:db8:abcd:13::1';       // next /64
const NET = '2001:db8:abcd:12::/64';

describe('keyless budget per network (oxjob #1692)', () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it('IPv4: one budget per address, as before', async () => {
        const { checks } = await runWorker(SEARCH, { ip: '203.0.113.7' });
        expect(checks).toEqual([{ bucket: 'credits:203.0.113.7', dailyLimit: 1000, perSecondLimit: 10 }]);
    });

    it('IPv6: every address in a /64 spends the same budget', async () => {
        for (const ip of [V6_A, V6_B]) {
            const { checks } = await runWorker(SEARCH, { ip });
            expect(checks).toEqual([{ bucket: `credits:${NET}`, dailyLimit: 1000, perSecondLimit: 10 }]);
        }
    });

    it('a /64 whose budget is spent is refused on a fresh address; the next /64 is not', async () => {
        const spent = { [`credits:${NET}`]: { counter: { count: 1000, date: today() } } };
        expect((await runWorker(SEARCH, { ip: V6_B, buckets: spent })).res.status).toBe(429);
        expect((await runWorker(SEARCH, { ip: V6_OTHER, buckets: spent })).res.status).toBe(200);
    });

    it('verified AI assistants keep their per-address budget (oxjob #1686)', async () => {
        const { checks } = await runWorker(SEARCH, { ip: V6_A, headers: { [VERIFIED_ASSISTANT_HEADER]: HARNESS_ASSISTANT_TOKEN } });
        expect(checks).toEqual([{ bucket: `credits:verified-assistant:${V6_A}`, dailyLimit: 5_000_000, perSecondLimit: 50 }]);
    });

    it('a key is its own budget wherever it comes from', async () => {
        vi.spyOn(console, 'error').mockImplementation(() => {}); // the fail-open DB lookup logs
        const { checks } = await runWorker(SEARCH, { ip: V6_A, headers: { Authorization: 'Bearer test-key-123' } });
        expect(checks).toEqual([{ bucket: 'credits:test-key-123', dailyLimit: 100000, perSecondLimit: 50 }]);
    });
});
