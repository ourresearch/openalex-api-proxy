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

const PERSIST_INTERVAL_MS = 10000; // 10 seconds

export class RateLimiter implements DurableObject {
    private perSecondBucket: TokenBucket | null = null;
    private dailyCounter: DailyCounter | null = null;

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
    }

    private async persist(): Promise<void> {
        if (!this.dailyCounter || !this.dailyCounter.dirty) return;

        const dataToWrite = {
            count: this.dailyCounter.count,
            date: this.dailyCounter.date
        };

        await this.state.storage.put('counter', dataToWrite);

        if (this.dailyCounter.count === dataToWrite.count && this.dailyCounter.date === dataToWrite.date) {
            this.dailyCounter.dirty = false;
            this.dailyCounter.lastPersisted = Date.now();
        } else {
            // State changed during the write (race condition).
            // If this persist() was triggered by the alarm, that alarm is now gone.
            // Reschedule to ensure the new data is saved.
            await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
        }
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const body = await request.json<{
            dailyLimit: number;
            perSecondLimit?: number;
            credits?: number;
        }>();
        const { dailyLimit, perSecondLimit, credits = 1 } = body;

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
            return Response.json({
                used: this.dailyCounter!.count,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count)
            });
        }

        // Refund endpoint - returns credits when actual cost < charged cost
        if (url.pathname === '/refund') {
            const refundAmount = Math.min(credits, this.dailyCounter!.count);
            if (refundAmount > 0) {
                this.dailyCounter!.count -= refundAmount;
                this.dailyCounter!.dirty = true;
            }
            return Response.json({
                refunded: refundAmount,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count)
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

        if (this.dailyCounter!.count + credits > dailyLimit) {
            const tomorrow = new Date();
            tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
            tomorrow.setUTCHours(0, 0, 0, 0);
            return Response.json({
                success: false,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count),
                retryAfter: Math.ceil((tomorrow.getTime() - now) / 1000),
                limitType: 'daily',
                creditsRequired: credits
            });
        }

        // Increment by credits consumed
        this.perSecondBucket.tokens -= 1;
        this.dailyCounter!.count += credits;

        // --- 3. Persistence Strategy ---

        // Safety net: If transitioning to dirty, schedule backup save
        if (!this.dailyCounter!.dirty) {
            this.dailyCounter!.dirty = true;
            await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
        }

        // Write-behind: If it's been a while, save now (fire and forget)
        if (now - this.dailyCounter!.lastPersisted >= PERSIST_INTERVAL_MS) {
            this.persist();
        }

        return Response.json({
            success: true,
            remaining: dailyLimit - this.dailyCounter!.count,
            creditsUsed: credits
        });
    }

    async alarm(): Promise<void> {
        await this.persist();
    }
}
