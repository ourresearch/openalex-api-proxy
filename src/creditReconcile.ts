// Plan pricing (oxjob #1533). The limiter charges a fixed price at /check, before the
// origin runs. A pipeline-language query (oxjob #1530) is priced by the API from its
// query plan (10 credits a listed search, 1 a lookup) and says so in `X-Credits-Cost`,
// so once the origin answers the proxy settles the difference in either direction:
// /refund when the plan cost less than the up-front charge, /charge when it cost more.

import { billableCreditCost } from "./endpointClassifier";

/** The origin's actual price for a request, in credits; internal, never sent to clients. */
export const ORIGIN_COST_HEADER = "X-Credits-Cost";

/** What the caller has left after the up-front charge (daily + prepaid), sent to the origin so it
 *  can refuse a plan it can't pay for before running it. */
export const CREDITS_REMAINING_HEADER = "X-Credits-Remaining";

/**
 * Credits actually owed once the origin has answered. Errors are free (oxjob #863); a
 * success carrying `X-Credits-Cost` costs that; anything else costs what /check charged.
 * A malformed header is ignored, so a bad origin value can't zero a bill or inflate one.
 */
export function actualCreditCost(status: number, charged: number, originCost: string | null): number {
    const raw = originCost?.trim() ?? "";
    const n = Number(raw);
    const price = raw !== "" && Number.isInteger(n) && n >= 0 ? n : charged;
    return billableCreditCost(status, price);
}

/** Sent as "1" for a grandfathered key, whose searches cost 1 credit instead of 10, so an origin
 *  that prices OQL like the URL API can price their searches the same way. */
export const GRANDFATHERED_HEADER = "X-Credits-Grandfathered";

export function creditsRemainingForOrigin(remaining?: number, onetimeRemaining?: number): number {
    return Math.max(0, remaining ?? 0) + Math.max(0, onetimeRemaining ?? 0);
}

/**
 * How the limiter's /charge splits an extra charge: the daily pool first, then the
 * prepaid one-time pool. The origin has already answered, so there's no limit test;
 * whatever fits in neither pool (only in a race, since the origin refuses plans that
 * don't fit X-Credits-Remaining) goes on the daily counter, which then reads as spent
 * until midnight UTC. Prepaid balance is never driven below zero.
 */
export function splitCharge(credits: number, dailyRemaining: number, onetimeAvailable: number): { daily: number; onetime: number } {
    const fromDaily = Math.min(credits, Math.max(0, dailyRemaining));
    const onetime = Math.min(credits - fromDaily, Math.max(0, onetimeAvailable));
    return { daily: credits - onetime, onetime };
}

interface Limiter {
    fetch(input: string, init?: RequestInit): Promise<Response>;
}

/**
 * Settle the difference between what /check charged and what the request actually cost,
 * and return the balances to report. Fails open (logs, keeps the /check balances), the
 * same way the refund paths always have.
 */
export async function settleCredits(
    limiter: Limiter,
    opts: { charged: number; actual: number; dailyLimit: number; onetimeBalance: number; remaining: number; onetimeRemaining: number },
): Promise<{ remaining: number; onetimeRemaining: number }> {
    const { charged, actual, dailyLimit, onetimeBalance } = opts;
    const unchanged = { remaining: opts.remaining, onetimeRemaining: opts.onetimeRemaining };
    const delta = actual - charged;
    if (delta === 0) return unchanged;
    const path = delta < 0 ? "/refund" : "/charge";
    try {
        const result = await limiter.fetch(`http://internal${path}`, {
            method: "POST",
            body: JSON.stringify({ dailyLimit, credits: Math.abs(delta), onetimeBalance })
        }).then(res => res.json() as Promise<{ remaining: number; onetimeRemaining: number }>);
        return { remaining: result.remaining, onetimeRemaining: result.onetimeRemaining };
    } catch (error) {
        console.error(`Failed to settle credits (${path}):`, error);
        return unchanged;
    }
}
