// Search-text VOLUME gate (oxjob #340).
//
// Rejects free-tier requests whose `search=` (or `search.semantic=`) value is
// pathologically long. Replay + a 7d regression (#340) showed intrinsic ES
// `took` is driven by scored-text VOLUME (total decoded search-value length),
// NOT by Boolean/OR count — `filter=…:a|b|c` OR-of-IDs is cheap and is the
// #191.3 protected class, so this gate keys ONLY on the `search` value length.
//
// This is a deliberate PROXY-LEVEL POLICY gate, NOT an F1 subset-invariant
// mirror: the elastic-api origin currently *accepts* these for everyone, so we
// are adding a new free-tier-scoped reject (closer to checkProtectedParams than
// to f1Validation). Enforced at the proxy because:
//   - the proxy already knows the plan + the #338 trustedUi token; the origin
//     does not (no plumbing gap to forward), and
//   - rejecting here avoids the ES request entirely (no gunicorn worker spun).
//
// Sizing (#340 evidence/gate_sizing_and_design_2026-06-08.md): human anon
// searches are tiny (p99.9 = 524 chars). At a 1500-char cap collateral is
// ~0.02% of anon search requests, and every sampled anon search >1000 chars was
// a pasted abstract / citation dump / LLM-agent prompt — not a real query. The
// universal extreme-shape backstop (>3 long quoted phrases) still lives at the
// origin in core/search.py:validate_search_terms (it rejects ALL tiers).

// Max decoded length of a `search=` value before the free-tier gate trips.
export const SEARCH_VOLUME_CAP = 1500;

// Params whose value is scored free text against the index (the expensive path).
const SCORED_TEXT_PARAMS = ["search", "search.semantic"] as const;

/**
 * Longest decoded scored-text search value on the URL (0 if none). URLSearchParams
 * already percent-decodes, so `.length` is the decoded char count — matching how
 * the #340 sizing measured lengths.
 */
export function searchValueLength(url: URL): number {
    let max = 0;
    for (const param of SCORED_TEXT_PARAMS) {
        for (const value of url.searchParams.getAll(param)) {
            if (value && value.length > max) max = value.length;
        }
    }
    return max;
}

export interface SearchVolumeContext {
    hasValidApiKey: boolean;
    plan: string | null;
    trustedUi: boolean;
    paidPlans: Set<string>;
    cap?: number;
}

/**
 * Exempt = real openalex.org UI (unforgeable #338 Turnstile token) OR a valid
 * API key on a paid plan. NB: a free key with no paid plan (the 2026-05-05 "ray"
 * abuser shape) is NOT exempt — that is the point of scoping to paid plans.
 */
export function isSearchVolumeExempt(ctx: SearchVolumeContext): boolean {
    if (ctx.trustedUi) return true;
    if (ctx.hasValidApiKey && ctx.plan !== null && ctx.paidPlans.has(ctx.plan)) return true;
    return false;
}

export interface SearchVolumeResult {
    gated: boolean;
    length: number;
}

/** Decide whether this request trips the free-tier search-volume gate. */
export function checkSearchVolume(url: URL, ctx: SearchVolumeContext): SearchVolumeResult {
    const cap = ctx.cap ?? SEARCH_VOLUME_CAP;
    const length = searchValueLength(url);
    if (length <= cap) return { gated: false, length };
    if (isSearchVolumeExempt(ctx)) return { gated: false, length };
    return { gated: true, length };
}

/** Actionable, client-facing rejection message. */
export function searchVolumeMessage(length: number, cap: number = SEARCH_VOLUME_CAP): string {
    return (
        `Your search is too long (${length} characters; the limit is ${cap}). ` +
        "Very long pasted-text or Boolean searches are disproportionately expensive. " +
        "Get an API key on a paid plan for large searches, or split the text into " +
        "several shorter requests. See https://openalex.org/pricing"
    );
}
