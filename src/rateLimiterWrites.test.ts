import { describe, it, expect, vi, afterEach } from 'vitest';
import { RateLimiter } from './rateLimiter';
import { fakeState } from './testHarness';

// oxjob #1698: the daily counter is meant to be written behind, at most once per 10 s window.
// The write-behind check used min(daily.lastPersisted, onetime.lastPersisted), and the onetime
// counter's timestamp never moves for keys without prepaid credits, so once a limiter was 10 s
// old every request wrote storage (most of the ~$1.9K/month Durable Object write bill).

async function newLimiter() {
    const state = fakeState();
    const puts = vi.spyOn(state.storage, 'put');
    const alarms = vi.spyOn(state.storage, 'setAlarm');
    const limiter = new RateLimiter(state as any);
    await vi.advanceTimersByTimeAsync(0); // let loadFromStorage finish
    const check = () => limiter.fetch(new Request('http://internal/check', {
        method: 'POST',
        body: JSON.stringify({ dailyLimit: 1_000_000, perSecondLimit: 1000 }),
    }));
    return { state, puts, alarms, check };
}

describe('RateLimiter write-behind (oxjob #1698)', () => {
    afterEach(() => { vi.useRealTimers(); });

    it('writes the daily counter about once per 10 s window, not once per request', async () => {
        vi.useFakeTimers({ now: new Date('2026-10-16T12:00:00Z') });
        const { puts, alarms, check } = await newLimiter();
        for (let i = 0; i < 600; i++) {  // 60 s of traffic at 10 requests a second
            await check();
            await vi.advanceTimersByTimeAsync(100);
        }
        expect(puts.mock.calls.length).toBeLessThanOrEqual(7);
        expect(alarms.mock.calls.length).toBeLessThanOrEqual(7);
    });

    it('still persists every request once the window passes', async () => {
        vi.useFakeTimers({ now: new Date('2026-10-16T12:00:00Z') });
        const { state, check } = await newLimiter();
        for (let i = 0; i < 50; i++) {
            await check();
            await vi.advanceTimersByTimeAsync(100);
        }
        await vi.advanceTimersByTimeAsync(10_000);
        await check();  // the 51st request is the one past the window, so it triggers the write
        await vi.advanceTimersByTimeAsync(0);
        expect((state.store.get('counter') as { count: number }).count).toBe(51);
    });
});
