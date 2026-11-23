import { ASK_FOR_A_KEY } from "./apiKeys";

// Keyless cursor paging past the first page needs a free API key (oxjob #1682, Jason's yes 2026-10-14).
// On 14 Oct 2026 keyless cursor pages 2+ were ~15% of Elasticsearch CPU, ~13% from one scraper (placeholder
// mailto, ~36K rotating IPs, 85% already 429'd) that per-IP budgets can't stop. `cursor=*` (the first page)
// stays keyless; the website (trustedUi) and every keyed caller are exempt.

export function isKeylessCursorPage(url: URL, hasValidApiKey: boolean, trustedUi: boolean): boolean {
    if (hasValidApiKey || trustedUi) return false;
    // getAll: a duplicate `cursor` must not slip a page-2 cursor past a leading `cursor=*`.
    return url.searchParams.getAll('cursor').some((c) => c !== '' && c !== '*');
}

// The message names the agent route (oxjob #2565): an assistant hitting this mid-answer should ask its user for an
// email and get a key, not send the person to a settings page; and it says how to keep going without one.
export const KEYLESS_CURSOR_ERROR = {
    error: "API key required for cursor paging",
    message: `Paging past the first page with cursor= needs a free API key. ${ASK_FOR_A_KEY} Or your user can copy their key from https://openalex.org/settings/api-key. Without a key, page=2, page=3 and so on reach the first 10,000 results.`,
};
