// Semantic search: one search per second per client (Kyle's report, 2026-10-16).
//
// The gate counts SEARCHES, not requests. openalex.org refetches the same search
// within a second when the results view settles (list at 10 rows, then table at 50),
// so a strict one-request-a-second gate turned one click into a 429 ("only one
// allowed per second"). A request for the search already let through this second
// (same path, semantic text and filter; page, per_page and sort may differ) passes,
// up to SAME_SEARCH_REPEATS times, and does not restart the clock. A different
// search still waits out the second.

export const SEMANTIC_INTERVAL_MS = 1000;
export const SAME_SEARCH_REPEATS = 3;

export interface SemanticGateState {
    lastTime: number;     // when the current window's search was let through (0 = never)
    lastSearch: string;   // that search's key
    repeats: number;      // same-search requests let through since then
}

export function newSemanticGateState(): SemanticGateState {
    return { lastTime: 0, lastSearch: "", repeats: 0 };
}

// What makes two requests "the same search": the path, the semantic text (case and
// spacing folded) and the filter. Everything else is paging or presentation.
export function semanticSearchKey(url: URL): string {
    const text = (url.searchParams.get("search.semantic") || "").trim().replace(/\s+/g, " ").toLowerCase();
    const filter = url.searchParams.get("filter") || "";
    return `${url.pathname.toLowerCase()}|${text}|${filter}`;
}

// Mutates `state` when the request is let through.
export function checkSemanticGate(
    state: SemanticGateState,
    now: number,
    search: string,
): { success: true } | { success: false; retryAfter: number } {
    const elapsed = now - state.lastTime;
    if (state.lastTime > 0 && elapsed < SEMANTIC_INTERVAL_MS) {
        if (search && search === state.lastSearch && state.repeats < SAME_SEARCH_REPEATS) {
            state.repeats++;
            return { success: true };
        }
        return { success: false, retryAfter: (SEMANTIC_INTERVAL_MS - elapsed) / 1000 };
    }
    state.lastTime = now;
    state.lastSearch = search;
    state.repeats = 0;
    return { success: true };
}
