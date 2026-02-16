interface TokenBucket {
    tokens: number;
    lastRefill: number;
}

interface DailyCounter {
    count: number;
    date: string;
    lastPersisted: number;
    dirty: boolean;
}

interface OnetimeCounter {
    consumed: number;
    lastPersisted: number;
    dirty: boolean;
}

const PERSIST_INTERVAL_MS = 10000; // 10 seconds

export class RateLimiter implements DurableObject {
    private perSecondBucket: TokenBucket | null = null;
    private dailyCounter: DailyCounter | null = null;
    private onetimeCounter: OnetimeCounter | null = null;

    constructor(private readonly state: DurableObjectState) {
        this.state.blockConcurrencyWhile(async () => {
            await this.loadFromStorage();
        });
    }

    private async loadFromStorage(): Promise<void> {
        const today = new Date().toISOString().split('T')[0];
        try {
            const stored = await this.state.storage.get<{ count: number; date: string }>('counter');
            this.dailyCounter = {
                count: (stored?.date === today) ? stored.count : 0,
                date: today,
                lastPersisted: Date.now(),
                dirty: false
            };
        } catch {
            this.dailyCounter = { count: 0, date: today, lastPersisted: Date.now(), dirty: false };
        }

        try {
            const storedOnetime = await this.state.storage.get<{ consumed: number }>('onetime');
            this.onetimeCounter = {
                consumed: storedOnetime?.consumed ?? 0,
                lastPersisted: Date.now(),
                dirty: false
            };
        } catch {
            this.onetimeCounter = { consumed: 0, lastPersisted: Date.now(), dirty: false };
        }
    }

    private async persist(): Promise<void> {
        const writes: Array<{ key: string; value: unknown; counter: { dirty: boolean; lastPersisted: number } }> = [];

        if (this.dailyCounter?.dirty) {
            writes.push({
                key: 'counter',
                value: { count: this.dailyCounter.count, date: this.dailyCounter.date },
                counter: this.dailyCounter
            });
        }

        if (this.onetimeCounter?.dirty) {
            writes.push({
                key: 'onetime',
                value: { consumed: this.onetimeCounter.consumed },
                counter: this.onetimeCounter
            });
        }

        if (writes.length === 0) return;

        // Snapshot values before write
        const snapshots = writes.map(w => ({ key: w.key, value: JSON.stringify(w.value) }));

        const entries: Record<string, unknown> = {};
        for (const w of writes) {
            entries[w.key] = w.value;
        }
        await this.state.storage.put(entries);

        // Mark clean only if values haven't changed during the write
        let needsReschedule = false;
        for (let i = 0; i < writes.length; i++) {
            if (JSON.stringify(writes[i].value) === snapshots[i].value) {
                writes[i].counter.dirty = false;
                writes[i].counter.lastPersisted = Date.now();
            } else {
                needsReschedule = true;
            }
        }

        if (needsReschedule) {
            await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
        }
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const body = await request.json<{
            dailyLimit: number;
            perSecondLimit?: number;
            credits?: number;
            onetimeBalance?: number;
            consumedWriteback?: number;
        }>();
        const { dailyLimit, perSecondLimit, credits = 1, onetimeBalance = 0 } = body;

        const now = Date.now();
        const today = new Date().toISOString().split('T')[0];

        // Handle day rollover
        if (this.dailyCounter!.date !== today) {
            if (this.dailyCounter!.dirty) {
                await this.persist();
            }
            this.dailyCounter = {
                count: 0,
                date: today,
                lastPersisted: now,
                dirty: false
            };
        }

        // Status endpoint - returns current usage without incrementing
        if (url.pathname === '/status') {
            const onetimeConsumed = this.onetimeCounter!.consumed;
            const onetimeRemaining = Math.max(0, onetimeBalance - onetimeConsumed);
            return Response.json({
                daily: {
                    used: this.dailyCounter!.count,
                    remaining: Math.max(0, dailyLimit - this.dailyCounter!.count)
                },
                onetime: {
                    consumed: onetimeConsumed,
                    remaining: onetimeRemaining,
                    balance: onetimeBalance
                },
                // Legacy fields for backward compatibility
                used: this.dailyCounter!.count,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count)
            });
        }

        // Sync endpoint - called after writeback to DB to reconcile consumed counter
        if (url.pathname === '/sync') {
            const consumedWriteback = body.consumedWriteback ?? 0;
            if (consumedWriteback > 0 && this.onetimeCounter) {
                // Subtract what was written back, preserving any credits consumed during the sync window
                this.onetimeCounter.consumed = Math.max(0, this.onetimeCounter.consumed - consumedWriteback);
                this.onetimeCounter.dirty = true;
                if (!this.onetimeCounter.dirty) {
                    await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
                }
            }
            return Response.json({
                onetimeConsumed: this.onetimeCounter!.consumed,
            });
        }

        // Refund endpoint - returns credits (LIFO: one-time first, then daily)
        if (url.pathname === '/refund') {
            let refundRemaining = credits;

            // Refund to one-time pool first (LIFO)
            if (this.onetimeCounter && this.onetimeCounter.consumed > 0 && refundRemaining > 0) {
                const onetimeRefund = Math.min(refundRemaining, this.onetimeCounter.consumed);
                if (onetimeRefund > 0) {
                    this.onetimeCounter.consumed -= onetimeRefund;
                    this.onetimeCounter.dirty = true;
                    refundRemaining -= onetimeRefund;
                }
            }

            // Refund remainder to daily pool
            if (refundRemaining > 0) {
                const dailyRefund = Math.min(refundRemaining, this.dailyCounter!.count);
                if (dailyRefund > 0) {
                    this.dailyCounter!.count -= dailyRefund;
                    this.dailyCounter!.dirty = true;
                }
            }

            const onetimeRemaining = Math.max(0, onetimeBalance - this.onetimeCounter!.consumed);
            return Response.json({
                refunded: credits,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count),
                onetimeRemaining
            });
        }

        // --- 1. Per-Second Limit (Memory Only) ---
        if (!this.perSecondBucket) {
            this.perSecondBucket = { tokens: perSecondLimit!, lastRefill: now };
        }

        const elapsedSeconds = (now - this.perSecondBucket.lastRefill) / 1000;
        if (elapsedSeconds > 0) {
            this.perSecondBucket.tokens = Math.min(
                perSecondLimit!,
                this.perSecondBucket.tokens + (elapsedSeconds * perSecondLimit!)
            );
            this.perSecondBucket.lastRefill = now;
        }

        if (this.perSecondBucket.tokens < 1) {
            const retryAfter = (1 - this.perSecondBucket.tokens) / perSecondLimit!;
            return Response.json({
                success: false,
                remaining: 0,
                retryAfter,
                limitType: 'per_second'
            });
        }

        // --- 2. Dual-Pool Draw-Down ---
        const dailyRemaining = dailyLimit - this.dailyCounter!.count;
        const onetimeAvailable = Math.max(0, onetimeBalance - this.onetimeCounter!.consumed);
        let fromOnetime = false;

        if (dailyRemaining >= credits) {
            // Daily pool has enough — use daily
            this.dailyCounter!.count += credits;
        } else if (onetimeAvailable >= credits) {
            // Daily exhausted, use one-time pool
            this.onetimeCounter!.consumed += credits;
            this.onetimeCounter!.dirty = true;
            fromOnetime = true;
        } else {
            // Both pools exhausted
            const tomorrow = new Date();
            tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
            tomorrow.setUTCHours(0, 0, 0, 0);
            return Response.json({
                success: false,
                remaining: Math.max(0, dailyRemaining),
                onetimeRemaining: onetimeAvailable,
                retryAfter: Math.ceil((tomorrow.getTime() - now) / 1000),
                limitType: 'daily',
                creditsRequired: credits
            });
        }

        // Decrement per-second token
        this.perSecondBucket.tokens -= 1;

        // --- 3. Persistence Strategy ---
        // Mark daily dirty and schedule alarm if needed
        if (!fromOnetime && !this.dailyCounter!.dirty) {
            this.dailyCounter!.dirty = true;
            await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
        }

        if (fromOnetime && !this.onetimeCounter!.dirty) {
            // Already set dirty above, just ensure alarm
            await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
        }

        // Write-behind: If it's been a while, save now
        const oldestPersist = Math.min(
            this.dailyCounter!.lastPersisted,
            this.onetimeCounter!.lastPersisted
        );
        if (now - oldestPersist >= PERSIST_INTERVAL_MS) {
            this.persist();
        }

        const newDailyRemaining = Math.max(0, dailyLimit - this.dailyCounter!.count);
        const newOnetimeRemaining = Math.max(0, onetimeBalance - this.onetimeCounter!.consumed);

        return Response.json({
            success: true,
            remaining: newDailyRemaining,
            onetimeRemaining: newOnetimeRemaining,
            creditsUsed: credits,
            fromOnetime
        });
    }

    async alarm(): Promise<void> {
        await this.persist();
    }
}
