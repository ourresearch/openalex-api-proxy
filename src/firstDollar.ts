// A new free account spends its first $1 slowly (oxjob #1740).
//
// A free key's day is $1 (10,000 credits). A script with many fresh accounts could spend each one's day in under a
// minute, before anything that groups accounts by behaviour has had a chance to look. So a free account made after
// FIRST_DOLLAR_SINCE spends its first 10,000 credits at most FIRST_DOLLAR_PACE_CREDITS per 5 minutes; after that it is
// an ordinary key. Nothing is withheld: the day's budget is the same, only its first dollar is paced.
//
// The clock is credits actually spent, not time: waiting a day, or starting the account with a tiny call, doesn't lift
// it. It counts per person (the credits:user:<id> bucket), so rotating a key neither resets it nor starts it again.
// Paid plans, prepaid balances, org keys, the website and verified AI assistants are never paced (the caller decides).

export const FIRST_DOLLAR_CREDITS = 10_000;
export const FIRST_DOLLAR_DEFAULT_PACE = 1_000;   // credits per window
export const FIRST_DOLLAR_WINDOW_SECONDS = 300;
// Accounts made at or after this moment are paced; older accounts never are. users.created is UTC.
export const FIRST_DOLLAR_SINCE = Date.UTC(2026, 10, 3, 17, 0, 0);  // 3 Nov 2026 17:00 UTC (11:00 CT)

/**
 * Credits per 5 minutes this request's account is paced at, or 0 for none. `free` is the caller's verdict (a valid
 * key of a person with no plan, prepaid balance or org, not the website or a verified assistant); `accountCreated`
 * comes from api_keys_view.account_created (ms since epoch; null for org keys or an older view). `envPace` is the
 * FIRST_DOLLAR_PACE_CREDITS variable: unset = the default, "0" = off (the revert).
 */
export function firstDollarPaceFor(free: boolean, accountCreated: number | null | undefined, envPace?: string): number {
    if (!free || accountCreated == null || !Number.isFinite(accountCreated) || accountCreated < FIRST_DOLLAR_SINCE) return 0;
    if (envPace === undefined || envPace.trim() === "") return FIRST_DOLLAR_DEFAULT_PACE;
    const pace = Number(envPace);
    return Number.isFinite(pace) && pace > 0 ? Math.floor(pace) : 0;
}

/** The pace's state in the person's rate-limiter object: `spent` is stored with the daily counter; the bucket lives in
 * memory, so an evicted object starts its next window full (at most one extra window's worth). */
export interface FirstDollarState {
    spent: number;
    tokens: number;
    lastRefill: number;
}

/**
 * Whether a request costing `credits` may go now, refilling the bucket first (the caller checks spent < $1). A request
 * dearer than the whole window goes once the bucket is full and leaves it in debt, so none is refused forever.
 */
export function checkFirstDollar(s: FirstDollarState, pace: number, credits: number, now: number):
        { ok: true } | { ok: false; retryAfter: number } {
    const perMs = pace / (FIRST_DOLLAR_WINDOW_SECONDS * 1000);
    s.tokens = Math.min(pace, s.tokens + Math.max(0, now - s.lastRefill) * perMs);
    s.lastRefill = now;
    const need = Math.min(credits, pace);
    if (s.tokens >= need) return { ok: true };
    return { ok: false, retryAfter: Math.ceil((need - s.tokens) / perMs / 1000) };
}

export function firstDollarMessage(paceUsd: number, retryAfter: number): string {
    return `New accounts spend their first $1 at up to $${paceUsd.toFixed(2)} every ${FIRST_DOLLAR_WINDOW_SECONDS / 60} `
        + `minutes, so a new key can't be emptied in a minute. Your daily budget is unchanged: retry in `
        + `${Math.max(1, Math.ceil(retryAfter))} seconds. Once the account has spent its first $1, this limit no longer applies. `
        + `https://help.openalex.org/api/authentication/#new-accounts`;
}
