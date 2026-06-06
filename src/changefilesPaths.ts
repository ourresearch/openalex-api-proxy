// Single source of truth for matching changefiles URL paths.
//
// There are two very different things under /changefiles, with different
// access levels and pricing — keeping their path matching in one tested place
// stops the call sites (endpointClassifier credit cost, index.ts auth/cache,
// index.ts download gate) from drifting apart. Drift here is security-relevant:
// if a download path were ever matched as "browse", downloads would silently
// become free and keyless (zd#8865).

// Strip leading/trailing slashes and lowercase, matching endpointClassifier's
// normalization so both operate on the same canonical form.
function normalizePath(pathname: string): string {
    return pathname.replace(/^\/+|\/+$/g, '').toLowerCase();
}

// The free, keyless, 0-credit *listing/browse* endpoints:
//   /changefiles          — index of available dates
//   /changefiles/{date}   — files available for one date
// NOT a download (/changefiles/{date}/{filename}) and not any other path.
export function isChangefilesBrowsePath(pathname: string): boolean {
    return /^changefiles(\/\d{4}-\d{2}-\d{2})?$/.test(normalizePath(pathname));
}

// An actual changefile *download*: /changefiles/{date}/{filename}. These stay
// metered and plan-gated (Premium/Institutional/Partner) in index.ts.
export function isChangefileDownloadPath(pathname: string): boolean {
    return /^changefiles\/\d{4}-\d{2}-\d{2}\/[^/]+$/.test(normalizePath(pathname));
}
