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
//   - raw comma:     core/filter_split.py:split_filter_string + core/utils.py:map_filter_params
// elastic-api carries a back-pointer comment to this file. That `valid_params`
// allowlist is the source of truth and WILL drift from here; we deliberately
// special-case only the one documented high-volume offender (`limit`) rather
// than mirror the whole list (mirroring = the drift hazard we're avoiding).

export type F1Reason = "limit_param" | "raw_comma_filter";

// What follows a comma that separates two filters: a filter key, then its colon.
const NEXT_FILTER_RE = /[A-Za-z_][A-Za-z0-9_.\-]*:/y;

/**
 * Exact TS port of elastic-api core/filter_split.py:split_filter_string.
 * Splits a filter string on commas, but commas inside double quotes are kept
 * inside their segment (quote state toggles on every `"`), and so is a comma
 * inside a search filter's value unless another filter (`key:`) starts right
 * after it: a pasted title keeps its commas (oxjob #1883).
 */
export function splitFilterString(filterString: string): string[] {
    const parts: string[] = [];
    let start = 0;
    let inQuotes = false;
    // The segment's first colon at or after `start` (-1: none), and whether its key names a search, each found once
    // per segment rather than at every comma, so a hostile filter of thousands of commas splits in linear time
    // (oxjob #1886; it cost ~1.3 ms per split at 16 KB, and a request splits its filter up to four times).
    let colon = filterString.indexOf(":");
    let keyCheckedAt = -1;
    let searchKey = false;

    for (let i = 0; i < filterString.length; i++) {
        const char = filterString[i];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === "," && !inQuotes) {
            if (colon >= 0 && colon < start) colon = filterString.indexOf(":", start);
            if (colon >= 0 && colon < i && keyCheckedAt !== start) {
                searchKey = filterString.slice(start, colon).includes("search");
                keyCheckedAt = start;
            }
            const inSearchValue = colon >= 0 && colon < i && searchKey;
            NEXT_FILTER_RE.lastIndex = i + 1;
            if (inSearchValue && !NEXT_FILTER_RE.test(filterString)) continue;
            if (i > start) parts.push(filterString.slice(start, i));
            start = i + 1;
        }
    }
    if (filterString.length > start) parts.push(filterString.slice(start));
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
        // Not %2C: clients that encode the whole value send every separator as %2C
        // too, so the API can't tell the two apart (oxjob #1883).
        case "raw_comma_filter":
            return "A filter value contains a comma, and commas separate filters " +
                "(filter=type:article,is_oa:true). For several values of one filter use | " +
                "(type:article|book). To keep a comma inside a value, wrap the value in " +
                "double quotes: filter=doi:\"10.1000/a,b\". Search filters " +
                "(title.search:...) keep their commas with no quotes.";
    }
}
