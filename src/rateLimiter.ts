interface TokenBucket {
    tokens: number;
    lastRefill: number;
    capacity: number;
    refillRate: number;
}

export class RateLimiter implements DurableObject {
    private static readonly BUCKET_KEY = "bucket";
    private bucket: TokenBucket | null = null;
    private lastSave: number = 0;
    private static readonly SAVE_INTERVAL = 5000; // Save every 5 seconds

    constructor(private readonly state: DurableObjectState) {
        // Load bucket from storage on startup
        this.state.blockConcurrencyWhile(async () => {
            this.bucket = await this.state.storage.get<TokenBucket>(RateLimiter.BUCKET_KEY) ?? null;
        });
    }

    async fetch(request: Request): Promise<Response> {
        const { limit, burstCapacity } = await request.json<{
            limit: number;           // Tokens per second
            burstCapacity?: number;  // Max burst size (defaults to limit * 2)
        }>();

        // Input validation
        const rate = Math.max(1, limit);
        const cap = Math.max(1, burstCapacity ?? limit * 2);

        const now = Date.now();

        // Initialize bucket if needed
        if (!this.bucket) {
            this.bucket = {
                tokens: cap,
                lastRefill: now,
                capacity: cap,
                refillRate: rate
            };
        }

        // Refill tokens based on time passed
        const elapsedSeconds = (now - this.bucket.lastRefill) / 1000;
        const tokensToAdd = elapsedSeconds * this.bucket.refillRate;
        this.bucket.tokens = Math.min(this.bucket.capacity, this.bucket.tokens + tokensToAdd);
        this.bucket.lastRefill = now;

        // Update bucket if rate limits changed (e.g., API key tier upgraded in D1)
        if (this.bucket.capacity !== cap || this.bucket.refillRate !== rate) {
            this.bucket.capacity = cap;
            this.bucket.refillRate = rate;
            this.bucket.tokens = Math.min(this.bucket.tokens, cap); // clamp to new capacity
        }

        // Check if request can proceed
        if (this.bucket.tokens < 1) {
            return Response.json({
                success: false,
                retryAfter: (1 - this.bucket.tokens) / this.bucket.refillRate
            });
        }

        // Consume a token (clamp to prevent negatives)
        this.bucket.tokens = Math.max(0, this.bucket.tokens - 1);

        // Periodically save to storage (not every request)
        if (now - this.lastSave > RateLimiter.SAVE_INTERVAL) {
            this.state.storage.put(RateLimiter.BUCKET_KEY, this.bucket); // Non-blocking
            this.lastSave = now;

            // Schedule cleanup alarm if not set
            const alarmAt = await this.state.storage.getAlarm();
            if (!alarmAt || alarmAt < now) {
                await this.state.storage.setAlarm(now + 300_000); // 5 minutes
            }
        }

        return Response.json({
            success: true,
            tokensRemaining: Math.floor(this.bucket.tokens)
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
