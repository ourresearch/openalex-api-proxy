import { describe, it, expect } from 'vitest';
import { RateLimiter } from './rateLimiter';
import { fakeState } from './testHarness';

// oxjob #2055: a Profile Doctor refund comes 10-30 minutes after its hold, after the prepaid spend was written back to users-api
// (/begin-writeback resets consumed to 0). It must still return the prepaid part, and must never turn daily credits into prepaid.

const DAILY = 10_000;

async function limiter(initial: Record<string, unknown> = {}) {
    const state = fakeState(initial);
    const l = new RateLimiter(state as any);
    await new Promise(r => setTimeout(r, 0));
    const call = async (path: string, body: Record<string, unknown>) =>
        (await l.fetch(new Request(`http://internal${path}`, { method: 'POST', body: JSON.stringify({ dailyLimit: DAILY, ...body }) }))).json() as any;
    return { state, call };
}

describe('Profile Doctor refunds (oxjob #2055)', () => {
    it('return the prepaid part after a writeback, then the rest to today\'s pool', async () => {
        const { state, call } = await limiter();
        let r = await call('/charge', { credits: 25_000, onetimeBalance: 100_000, fix: true });   // 10,000 daily + 15,000 prepaid
        expect([r.remaining, r.onetimeRemaining]).toEqual([0, 85_000]);
        expect((await call('/begin-writeback', { onetimeBalance: 100_000 })).consumed).toBe(15_000);   // users-api now holds 85,000
        r = await call('/refund', { credits: 18_000, onetimeBalance: 85_000, fix: true });
        expect([r.remaining, r.onetimeRemaining]).toEqual([3_000, 100_000]);   // all 15,000 prepaid back; the price came from the day
        expect(state.store.get('onetime')).toEqual({ consumed: -15_000 });   // a credit the next spend uses first; nothing left to return
        r = await call('/check', { credits: 50_000, perSecondLimit: 1000, onetimeBalance: 85_000 });
        expect(r.success).toBe(true);
        expect(r.onetimeRemaining ?? r.onetime?.remaining).toBe(50_000);
        expect((await call('/begin-writeback', { onetimeBalance: 85_000 })).consumed).toBe(35_000);   // net prepaid spend so far
    });

    it('never turn a daily-paid hold into prepaid credit', async () => {
        const { call } = await limiter();
        await call('/charge', { credits: 8_000, onetimeBalance: 50_000, fix: true });   // all from the daily pool
        const r = await call('/refund', { credits: 6_000, onetimeBalance: 50_000, fix: true });
        expect([r.remaining, r.onetimeRemaining]).toEqual([8_000, 50_000]);
    });

    it('a daily-paid hold refunded the next day comes back as that day\'s credits', async () => {
        const { call } = await limiter({ counter: { count: 0, date: '2001-01-01' } });   // yesterday's spend is gone at midnight
        const r = await call('/refund', { credits: 6_000, onetimeBalance: 0, fix: true });
        expect(r.remaining).toBe(DAILY + 6_000);
    });

    it('keep what may still come back across a restart', async () => {
        const first = await limiter();
        await first.call('/charge', { credits: 25_000, onetimeBalance: 100_000, fix: true });
        expect(first.state.store.get('onetime')).toEqual({ consumed: 15_000, fix: 15_000 });
        const again = await limiter(Object.fromEntries(first.state.store));
        const r = await again.call('/refund', { credits: 5_000, onetimeBalance: 100_000, fix: true });
        expect(r.onetimeRemaining).toBe(90_000);
    });

    it('leave every other refund as it was', async () => {
        const { call } = await limiter();
        await call('/charge', { credits: 25_000, onetimeBalance: 100_000 });
        await call('/begin-writeback', { onetimeBalance: 100_000 });
        const r = await call('/refund', { credits: 18_000, onetimeBalance: 85_000 });
        expect([r.remaining, r.onetimeRemaining]).toEqual([10_000, 85_000]);   // daily first; nothing to give back on prepaid
    });
});
