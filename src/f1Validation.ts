// F1 edge validation (oxjob #194 Phase 2, shipped 2026-06-02).
//
// Fast-fail two high-volume client-bug request shapes at the Worker, BEFORE
// they reach Heroku. Both shapes are *guaranteed* `APIQueryParamsError` 400s
// at the elastic-api origin, so rejecting them here returns the exact same 400
// ~175ms sooner and without burning a gunicorn worker slot (~101K wallsec/7d).
//
// SUBSET INVARIANT (read before adding anything here):
// Edge validation may ONLY reject what the origin would also reject. Both
// shapes below are verified guaranteed-400s in elastic-api. NEVER add a rule
// that could reject a request the origin would *accept* — that creates the
// "mysterious failure nobody thinks to look for in the proxy" failure mode.
// When in doubt, UNDER-reject: a missed bad request just forwards to origin
// and 400s there (lose the wallsec saving, no harm). OVER-rejection is harm.
//
// Mirrors elastic-api:
//   - `limit` param: core/validate.py:validate_params (unknown param -> 400)
//   - raw comma:     core/utils.py:split_filter_string + map_filter_params
// elastic-api carries a back-pointer comment to this file. That `valid_params`
// allowlist is the source of truth and WILL drift from here; we deliberately
// special-case only the one documented high-volume offender (`limit`) rather
// than mirror the whole list (mirroring = the drift hazard we're avoiding).

export type F1Reason = "limit_param" | "raw_comma_filter";

/**
 * Exact TS port of elastic-api core/utils.py:split_filter_string.
 * Splits a filter string on commas, but commas inside double quotes are kept
 * inside their segment. Quote state toggles on every `"`.
 */
export function splitFilterString(filterString: string): string[] {
    const parts: string[] = [];
    let current = "";
    let inQuotes = false;

    for (const char of filterString) {
        if (char === '"') {
            inQuotes = !inQuotes;
            current += char;
        } else if (char === "," && !inQuotes) {
            if (current) parts.push(current);
            current = "";
        } else {
            current += char;
        }
    }
    if (current) parts.push(current);
    return parts;
}

/**
 * Returns the F1 rejection reason for a request URL, or null if F1 does not
 * apply. Inspects only query params, so it is safe for any method (callers
 * gate on method separately, matching the request-line guard).
 */
export function f1Reason(url: URL): F1Reason | null {
    // Shape 1: `limit=` typo for `per-page=`. `limit` is not in elastic-api's
    // valid_params allowlist and is read nowhere, so it is an unconditional
    // 400 on every route.
    if (url.searchParams.has("limit")) {
        return "limit_param";
    }

    // Shape 2: raw (unquoted) comma inside a filter value. After the quote-aware
    // split, elastic-api does `param.split(":", 1)` per segment; a segment with
    // no colon raises ValueError -> 400. A valid multi-filter request
    // (`filter=a:1,b:2`) has a colon in every segment; a quoted comma stays
    // inside one segment. Only the raw-comma bug yields a colonless segment.
    const filterValue = url.searchParams.get("filter");
    if (filterValue) {
        const segments = splitFilterString(filterValue);
        for (const segment of segments) {
            if (!segment.includes(":")) {
                return "raw_comma_filter";
            }
        }
    }

    return null;
}

/** Actionable, client-facing message for each rejection reason. */
export function f1Message(reason: F1Reason): string {
    switch (reason) {
        case "limit_param":
            return "The 'limit' parameter is not valid. Did you mean 'per-page'? " +
                "e.g. /works?search=foo&per-page=5";
        case "raw_comma_filter":
            return "A filter value contains an unescaped comma. Commas separate " +
                "filters, so a literal comma inside a value must be percent-encoded " +
                "as %2C (or the whole value wrapped in double quotes). " +
                "e.g. filter=title.search:climate%2C+biodiversity";
    }
}
