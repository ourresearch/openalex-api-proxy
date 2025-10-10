interface TokenBucket {
    tokens: number;
    lastRefill: number;
    capacity: number;
    refillRate: number;
}

export class RateLimiter implements DurableObject {
    private static readonly BUCKET_KEY = "bucket";

    constructor(private state: DurableObjectState) {}

    async fetch(request: Request): Promise<Response> {
        const { limit, burstCapacity } = await request.json<{
            limit: number;           // Tokens per second
            burstCapacity?: number;  // Max burst size (defaults to limit * 2)
        }>();

        // Input validation
        const rate = Math.max(1, limit);
        const cap = Math.max(1, burstCapacity ?? limit * 2);

        const now = Date.now();

        // Get current bucket state
        let bucket = await this.state.storage.get<TokenBucket>(RateLimiter.BUCKET_KEY);

        if (!bucket) {
            // First request - initialize with full capacity
            bucket = {
                tokens: cap,
                lastRefill: now,
                capacity: cap,
                refillRate: rate
            };
        }

        // Refill tokens based on time passed
        const elapsedSeconds = (now - bucket.lastRefill) / 1000;
        const tokensToAdd = elapsedSeconds * bucket.refillRate;
        bucket.tokens = Math.min(bucket.capacity, bucket.tokens + tokensToAdd);
        bucket.lastRefill = now;

        // Check if request can proceed
        if (bucket.tokens < 1) {
            // Save state and return rate limit error
            await this.state.storage.put(RateLimiter.BUCKET_KEY, bucket);

            return Response.json({
                success: false,
                retryAfter: (1 - bucket.tokens) / bucket.refillRate
            });
        }

        // Consume a token and save (clamp to prevent negatives)
        bucket.tokens = Math.max(0, bucket.tokens - 1);
        await this.state.storage.put(RateLimiter.BUCKET_KEY, bucket);

        // Schedule cleanup alarm if not set
        const alarmAt = await this.state.storage.getAlarm();
        if (!alarmAt || alarmAt < now) {
            await this.state.storage.setAlarm(now + 300_000); // 5 minutes
        }

        return Response.json({
            success: true,
            tokensRemaining: Math.floor(bucket.tokens)
        });
    }

    async alarm(): Promise<void> {
        // Clean up after 10 minutes of inactivity
        const bucket = await this.state.storage.get<TokenBucket>(RateLimiter.BUCKET_KEY);
        if (!bucket) return;

        const now = Date.now();
        const inactivityPeriod = now - bucket.lastRefill;

        if (inactivityPeriod > 600_000) {
            await this.state.storage.delete(RateLimiter.BUCKET_KEY);
        }
    }
}
