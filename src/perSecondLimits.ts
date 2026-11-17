// The per-second limits a caller is told, in one place, so the 429s, /rate-limit and the help page say the same numbers
// (oxjob #2374).

export const RATE_LIMITS_DOCS = "https://help.openalex.org/api/authentication/#rate-limits";

export const WIDE_OR_PER_SECOND = 1;
export const SEMANTIC_PER_SECOND = 1;

/**
 * Searches with more than 5 AND/OR/NOT. `gateRate` sets /check-boolean: a search reaching it within 1/gateRate s of the
 * last one let through is refused, with no room for a burst. Searches reach it bunched, so the steady rate a client can
 * count on is lower; that is `rate`, the number we state. Measured 17 Nov 2026 over 20 s with no refusals: paid 5/s
 * (6/s: 5% refused, 8/s: 40%), free key 2/s (3/s: 2%), no key 1/s.
 */
export function booleanSearchLimit(paidPlan: boolean, validKey: boolean): { gateRate: number; rate: number } {
    if (paidPlan) return { gateRate: 25, rate: 5 };
    if (validKey) return { gateRate: 5, rate: 2 };
    return { gateRate: 1, rate: 1 };
}

/** The `per_second_limits` block of /rate-limit. */
export function perSecondLimitsBody(allRequests: number, paidPlan: boolean, validKey: boolean) {
    return {
        all_requests: allRequests,
        searches_with_more_than_5_boolean_operators: booleanSearchLimit(paidPlan, validKey).rate,
        filters_with_more_than_10_topic_or_concept_ids: WIDE_OR_PER_SECOND,
        semantic_search: SEMANTIC_PER_SECOND,
        docs: RATE_LIMITS_DOCS,
    };
}
