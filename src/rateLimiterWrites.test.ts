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

// oxjob #2039: a failed storage read started the object at 0, and its next write overwrote the stored count, so the
// caller got its day (or its unbilled prepaid spend) back. Now the read failure resets the object, as the runtime does
// when blockConcurrencyWhile's callback throws, and the next instance reads again.
describe('RateLimiter read failure (oxjob #2039)', () => {
    const today = () => new Date().toISOString().split('T')[0];

    async function failFirstLoad(stored: Record<string, unknown>, failing: string) {
        const state = fakeState(stored);
        const get = state.storage.get;
        let load: Promise<void> | undefined;
        state.storage.get = async (k: string) => { if (k === failing) throw new Error('internal error; reference = test'); return get(k); };
        state.blockConcurrencyWhile = (fn: () => Promise<void>) => (load = fn());
        new RateLimiter(state as any);
        await expect(load).rejects.toThrow('internal error');
        state.storage.get = get;
        state.blockConcurrencyWhile = async (fn: () => Promise<void>) => fn();
        const limiter = new RateLimiter(state as any);
        await new Promise(r => setTimeout(r, 0)); // let loadFromStorage finish
        return { state, limiter };
    }

    it('keeps the day: the next instance continues from the stored count', async () => {
        const { state, limiter } = await failFirstLoad({ counter: { count: 700, date: today() } }, 'counter');
        expect((state.store.get('counter') as { count: number }).count).toBe(700);
        await limiter.fetch(new Request('http://internal/check', {
            method: 'POST', body: JSON.stringify({ dailyLimit: 1_000_000, perSecondLimit: 1000 }),
        }));
        await limiter.alarm();
        expect((state.store.get('counter') as { count: number }).count).toBe(701);
    });

    it('keeps the prepaid spend not yet written back', async () => {
        const { limiter } = await failFirstLoad({ onetime: { consumed: 300 } }, 'onetime');
        const status = await limiter.fetch(new Request('http://internal/status', {
            method: 'POST', body: JSON.stringify({ dailyLimit: 10_000, onetimeBalance: 1_000 }),
        })).then(r => r.json() as Promise<{ onetime: { consumed: number } }>);
        expect(status.onetime.consumed).toBe(300);
    });
});
