import { splitCharge } from "./creditReconcile";
import { reportError, withErrorReporting, Invocation, SentryEnv } from './sentry';
import { checkSemanticGate, newSemanticGateState } from "./semanticGate";
import { checkFirstDollar, FirstDollarState, FIRST_DOLLAR_CREDITS } from "./firstDollar";

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
    // Prepaid credits that Profile Doctor charges took and its refunds may still return (oxjob #2055; see /refund). Rides in the
    // 'onetime' value as `fix`, like `fd` in 'counter'.
    fix: number;
    lastPersisted: number;
    dirty: boolean;
}

const PERSIST_INTERVAL_MS = 10000; // 10 seconds

export class RateLimiter implements DurableObject {
    private perSecondBucket: TokenBucket | null = null;
    private dailyCounter: DailyCounter | null = null;
    private onetimeCounter: OnetimeCounter | null = null;
    // A new free account's first $1 (oxjob #1740; firstDollar.ts). `spent` rides in the 'counter' value as `fd` (no extra
    // storage key, read or write); tokens start full (the refill caps them at the pace).
    private firstDollar: FirstDollarState = { spent: 0, tokens: Infinity, lastRefill: 0 };
    private firstDollarPace = 0;  // the pace the last /check applied; /charge's settle-ups count against it too
    private semanticGate = newSemanticGateState(); // one semantic search a second (semanticGate.ts)
    private lastThrottleTime: number = 0; // oxjob #166: admin rate-throttle
    private lastBooleanTime: number = 0; // oxjob #521/#677: rate limit for >5-operator boolean searches
    private lastWideOrTime: number = 0; // oxjob #876: rate limit for >10-term OR lists on wide filter fields

    constructor(private readonly state: DurableObjectState, private readonly env: SentryEnv = {}) {
        this.state.blockConcurrencyWhile(async () => {
            await this.loadFromStorage();
        });
    }

    private async loadFromStorage(): Promise<void> {
        const today = new Date().toISOString().split('T')[0];
        try {
            const stored = await this.state.storage.get<{ count: number; date: string; fd?: number }>('counter');
            this.firstDollar.spent = stored?.fd ?? 0;  // never resets at midnight
            this.dailyCounter = {
                count: (stored?.date === today) ? stored.count : 0,
                date: today,
                lastPersisted: Date.now(),
                dirty: false
            };
        } catch (error) {
            // Rethrown, so blockConcurrencyWhile resets the object and the next request reads again. Starting at 0 here
            // gave the caller its day back once the next write overwrote the stored count (oxjob #2039).
            reportError(error, { site: 'rate_limiter_load_counter', inv: this.sentryInvocation() });
            throw error;
        }

        try {
            const storedOnetime = await this.state.storage.get<{ consumed: number; fix?: number }>('onetime');
            this.onetimeCounter = {
                consumed: storedOnetime?.consumed ?? 0,
                fix: storedOnetime?.fix ?? 0,
                lastPersisted: Date.now(),
                dirty: false
            };
        } catch (error) {
            // Likewise: 0 here dropped the prepaid spend not yet written back.
            reportError(error, { site: 'rate_limiter_load_onetime', inv: this.sentryInvocation() });
            throw error;
        }
    }

    // The stored 'counter' value. `fd` (first-dollar spend) appears only for paced accounts.
    private counterValue(): { count: number; date: string; fd?: number } {
        const { count, date } = this.dailyCounter!;
        return this.firstDollar.spent > 0 ? { count, date, fd: this.firstDollar.spent } : { count, date };
    }

    // The stored 'onetime' value. `fix` appears only while Profile Doctor holds can still come back.
    private onetimeValue(): { consumed: number; fix?: number } {
        const { consumed, fix } = this.onetimeCounter!;
        return fix > 0 ? { consumed, fix } : { consumed };
    }

    private async persist(): Promise<void> {
        const writes: Array<{ key: string; value: unknown; counter: { dirty: boolean; lastPersisted: number } }> = [];

        if (this.dailyCounter?.dirty) {
            writes.push({
                key: 'counter',
                value: this.counterValue(),
                counter: this.dailyCounter
            });
        }

        if (this.onetimeCounter?.dirty) {
            writes.push({
                key: 'onetime',
                value: this.onetimeValue(),
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

    // Settle writes (/refund, /charge) persist at once: a DO eviction before the next
    // /check would otherwise lose them, and prepaid credits are real money.
    private async persistDailyNow(): Promise<void> {
        await this.state.storage.put('counter', this.counterValue());
        this.dailyCounter!.dirty = false;
        this.dailyCounter!.lastPersisted = Date.now();
    }

    private async persistOnetimeNow(): Promise<void> {
        await this.state.storage.put('onetime', this.onetimeValue());
        this.onetimeCounter!.dirty = false;
        this.onetimeCounter!.lastPersisted = Date.now();
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);
        const body = await request.json<{
            dailyLimit: number;
            perSecondLimit?: number;
            credits?: number;
            onetimeBalance?: number;
            consumedWriteback?: number;
            intervalMs?: number;
            search?: string;
            firstDollarPace?: number;  // credits per 5 minutes while a new free account spends its first $1 (oxjob #1740)
            fix?: boolean;             // a Profile Doctor settlement (oxjob #2055): see /refund
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

        // One semantic search a second per client (in-memory only). Counts searches,
        // not requests: a refetch of the same search within the second passes.
        if (url.pathname === '/check-semantic') {
            return Response.json(checkSemanticGate(this.semanticGate, now, body.search ?? ''));
        }

        // Mirrors /check-semantic: in-memory 1 req/s gate, no daily side-effects.
        // DO is keyed by 'throttle:user|org:{id}' (oxjob #166).
        if (url.pathname === '/check-throttle') {
            const THROTTLE_INTERVAL_MS = 1000;
            const elapsed = now - this.lastThrottleTime;
            if (this.lastThrottleTime > 0 && elapsed < THROTTLE_INTERVAL_MS) {
                const retryAfter = (THROTTLE_INTERVAL_MS - elapsed) / 1000;
                return Response.json({ success: false, retryAfter });
            }
            this.lastThrottleTime = now;
            return Response.json({ success: true });
        }

        // oxjob #521: per-client rate limit for very broad boolean searches
        // (>5 OR/AND/NOT operators). In-memory only, same shape as /check-semantic.
        // Caller sets intervalMs per tier: 40ms (25/s) for paid plans (#677),
        // 200ms (5/s) for other valid-key clients, 1000ms (1/s) for anonymous.
        if (url.pathname === '/check-boolean') {
            const BOOLEAN_INTERVAL_MS = body.intervalMs ?? 1000;
            const elapsed = now - this.lastBooleanTime;
            if (this.lastBooleanTime > 0 && elapsed < BOOLEAN_INTERVAL_MS) {
                const retryAfter = (BOOLEAN_INTERVAL_MS - elapsed) / 1000;
                return Response.json({ success: false, retryAfter });
            }
            this.lastBooleanTime = now;
            return Response.json({ success: true });
        }

        // oxjob #876: 1 req/s for filter OR-lists with >10 distinct terms on a wide
        // field (topics/concepts). Same shape as /check-boolean, separate timer so
        // the two throttles don't share a clock.
        if (url.pathname === '/check-wide-or') {
            const WIDE_OR_INTERVAL_MS = body.intervalMs ?? 1000;
            const elapsed = now - this.lastWideOrTime;
            if (this.lastWideOrTime > 0 && elapsed < WIDE_OR_INTERVAL_MS) {
                const retryAfter = (WIDE_OR_INTERVAL_MS - elapsed) / 1000;
                return Response.json({ success: false, retryAfter });
            }
            this.lastWideOrTime = now;
            return Response.json({ success: true });
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

        // Atomic writeback: read consumed AND reset to 0 in one serialized call.
        // This prevents concurrent writebacks from reading the same consumed value.
        if (url.pathname === '/begin-writeback') {
            const consumed = this.onetimeCounter!.consumed;
            if (consumed <= 0) return Response.json({ consumed: 0 });
            // Atomically claim: reset consumed, preserving 0 for concurrent callers
            this.onetimeCounter!.consumed = 0;
            // Persist immediately so DO eviction doesn't revert to stale value
            await this.state.storage.put('onetime', this.onetimeValue());
            this.onetimeCounter!.dirty = false;
            this.onetimeCounter!.lastPersisted = Date.now();
            return Response.json({ consumed });
        }

        // Restore consumed credits to the DO after a failed DB writeback.
        // This re-adds credits that /begin-writeback claimed but couldn't write to DB.
        if (url.pathname === '/restore-consumed') {
            const restoreAmount = body.consumedWriteback ?? 0;
            if (restoreAmount > 0 && this.onetimeCounter) {
                this.onetimeCounter.consumed += restoreAmount;
                await this.state.storage.put('onetime', this.onetimeValue());
                this.onetimeCounter.dirty = false;
                this.onetimeCounter.lastPersisted = Date.now();
            }
            return Response.json({ consumed: this.onetimeCounter!.consumed });
        }

        // Sync endpoint - called after writeback to DB to reconcile consumed counter
        // DEPRECATED: prefer /begin-writeback for atomic claim-and-reset
        if (url.pathname === '/sync') {
            const consumedWriteback = body.consumedWriteback ?? 0;
            if (consumedWriteback > 0 && this.onetimeCounter) {
                // Subtract what was written back, preserving any credits consumed during the sync window
                this.onetimeCounter.consumed = Math.max(0, this.onetimeCounter.consumed - consumedWriteback);
                // Persist immediately so DO eviction doesn't revert to stale consumed value
                await this.state.storage.put('onetime', this.onetimeValue());
                this.onetimeCounter.dirty = false;
                this.onetimeCounter.lastPersisted = Date.now();
            }
            return Response.json({
                onetimeConsumed: this.onetimeCounter!.consumed,
            });
        }

        // A Profile Doctor refund (oxjob #2055) comes 10-30 minutes after its hold, by when the prepaid part has almost always been
        // written back to users-api (the auth cache refreshes every 60 s, and /begin-writeback resets consumed to 0), so the refund
        // below would find nothing to give back and a prepaid customer would lose it. Here the prepaid part goes back first, and may
        // take consumed below 0: a credit the next spend uses first (/begin-writeback leaves it alone). Only what fix charges took from
        // prepaid (`fix`) can return there, so a hold paid from the daily pool never turns into prepaid credit; the rest returns to
        // today's daily pool, which may go below 0 for the day (daily credits back as daily credits).
        if (url.pathname === '/refund' && body.fix) {
            const toOnetime = Math.min(credits, Math.max(0, this.onetimeCounter!.fix));
            if (toOnetime > 0) {
                this.onetimeCounter!.consumed -= toOnetime;
                this.onetimeCounter!.fix -= toOnetime;
                await this.persistOnetimeNow();
            }
            if (credits - toOnetime > 0) {
                this.dailyCounter!.count -= credits - toOnetime;
                await this.persistDailyNow();
            }
            return Response.json({
                refunded: credits,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count),
                onetimeRemaining: Math.max(0, onetimeBalance - this.onetimeCounter!.consumed)
            });
        }

        // Refund endpoint - returns credits (daily first, matching charge order)
        if (url.pathname === '/refund') {
            let refundRemaining = credits;

            // Refund to daily pool first (matches charge order: daily is charged first)
            if (refundRemaining > 0) {
                const dailyRefund = Math.min(refundRemaining, this.dailyCounter!.count);
                if (dailyRefund > 0) {
                    this.dailyCounter!.count -= dailyRefund;
                    await this.persistDailyNow();
                    refundRemaining -= dailyRefund;
                }
            }

            // Refund remainder to one-time pool
            if (this.onetimeCounter && this.onetimeCounter.consumed > 0 && refundRemaining > 0) {
                const onetimeRefund = Math.min(refundRemaining, this.onetimeCounter.consumed);
                if (onetimeRefund > 0) {
                    this.onetimeCounter.consumed -= onetimeRefund;
                    await this.persistOnetimeNow();
                }
            }

            const onetimeRemaining = Math.max(0, onetimeBalance - this.onetimeCounter!.consumed);
            return Response.json({
                refunded: credits,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count),
                onetimeRemaining
            });
        }

        // Charge endpoint - the mirror of /refund (oxjob #1533): a query priced from its plan
        // can cost more than /check charged up front. Daily pool first, then one-time; no
        // limit test, since the origin has already answered (see splitCharge).
        if (url.pathname === '/charge') {
            const onetimeAvailable = Math.max(0, onetimeBalance - this.onetimeCounter!.consumed);
            const split = splitCharge(credits, dailyLimit - this.dailyCounter!.count, onetimeAvailable);

            if (this.firstDollarPace > 0 && this.firstDollar.spent < FIRST_DOLLAR_CREDITS) {
                this.firstDollar.spent += credits;   // a query priced after it ran (oxjob #1740): its bucket goes into debt
                this.firstDollar.tokens -= credits;
            }
            if (split.daily > 0) {
                this.dailyCounter!.count += split.daily;
                await this.persistDailyNow();
            }
            if (split.onetime > 0) {
                this.onetimeCounter!.consumed += split.onetime;
                if (body.fix) this.onetimeCounter!.fix += split.onetime;   // what a Profile Doctor refund may return to prepaid
                await this.persistOnetimeNow();
            }

            return Response.json({
                charged: credits,
                remaining: Math.max(0, dailyLimit - this.dailyCounter!.count),
                onetimeRemaining: Math.max(0, onetimeBalance - this.onetimeCounter!.consumed)
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

        // --- 2. A new free account's first $1 (oxjob #1740) ---
        // Refunded requests stay counted (spent and bucket): the pace still bounds the rate, so failing on purpose can
        // only lift it as slowly as spending would.
        const pace = body.firstDollarPace ?? 0;
        const paced = pace > 0 && this.firstDollar.spent < FIRST_DOLLAR_CREDITS;
        this.firstDollarPace = paced ? pace : 0;
        if (paced) {
            const verdict = checkFirstDollar(this.firstDollar, pace, credits, now);
            if (!verdict.ok) {
                return Response.json({
                    success: false,
                    remaining: Math.max(0, dailyLimit - this.dailyCounter!.count),
                    onetimeRemaining: Math.max(0, onetimeBalance - this.onetimeCounter!.consumed),
                    retryAfter: verdict.retryAfter,
                    limitType: 'first_dollar'
                });
            }
        }

        // --- 3. Dual-Pool Draw-Down ---
        const dailyRemaining = dailyLimit - this.dailyCounter!.count;
        const onetimeAvailable = Math.max(0, onetimeBalance - this.onetimeCounter!.consumed);
        let fromOnetime = false;

        if (dailyRemaining >= credits) {
            // Daily pool has enough — use daily
            this.dailyCounter!.count += credits;
        } else if (onetimeAvailable >= credits) {
            // Daily exhausted, use one-time pool
            this.onetimeCounter!.consumed += credits;
            // Persist immediately — prepaid credits are real money.
            // The old dirty-flag + alarm pattern was dead code (dirty already true
            // when the alarm check ran), so onetime consumption was never persisted
            // via alarm. DO eviction = lost consumption = free API calls.
            await this.state.storage.put('onetime', this.onetimeValue());
            this.onetimeCounter!.dirty = false;
            this.onetimeCounter!.lastPersisted = Date.now();
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

        if (paced) {  // paced accounts draw from the daily pool, so the counter write below carries `fd`
            this.firstDollar.spent += credits;
            this.firstDollar.tokens -= credits;
        }

        // --- 4. Persistence Strategy ---
        // Mark daily dirty and schedule alarm if needed
        if (!fromOnetime && !this.dailyCounter!.dirty) {
            this.dailyCounter!.dirty = true;
            await this.state.storage.setAlarm(Date.now() + PERSIST_INTERVAL_MS);
        }

        // Onetime counter is now persisted immediately in the consumption path above.
        // No alarm scheduling needed for onetime.

        // Write-behind: if the daily counter hasn't been saved this window, save now. Only the
        // daily counter is written behind (onetime persists immediately above); taking the min
        // with onetime.lastPersisted, which never moves for keys without prepaid credits, made
        // every request write storage once the object was 10 s old (oxjob #1698).
        if (now - this.dailyCounter!.lastPersisted >= PERSIST_INTERVAL_MS) {
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
        return withErrorReporting(this.sentryInvocation(), 'rate_limiter_alarm', () => this.persist());
    }

    private sentryInvocation(): Invocation {
        return { env: this.env, waitUntil: (p) => this.state.waitUntil(p) };
    }
}
