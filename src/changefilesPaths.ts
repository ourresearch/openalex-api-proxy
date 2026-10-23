import { normalizePath } from "./paths";

// Single source of truth for matching changefiles URL paths.
//
// There are two very different things under /changefiles, with different
// access levels and pricing — keeping their path matching in one tested place
// stops the call sites (endpointClassifier credit cost, index.ts auth/cache,
// index.ts download gate) from drifting apart. Drift here is security-relevant:
// if a download path were ever matched as "browse", downloads would silently
// become free and keyless (zd#8865).

// Paths are compared in normalizePath's form (paths.ts: no leading/trailing slashes, lowercase), the same one
// endpointClassifier and index.ts use, so every matcher operates on the same canonical form.

// The free, keyless, 0-credit *listing/browse* endpoints:
//   /changefiles          — index of available dates
//   /changefiles/{date}   — files available for one date
// NOT a download (/changefiles/{date}/{filename}) and not any other path.
export function isChangefilesBrowsePath(pathname: string): boolean {
    return /^changefiles(\/\d{4}-\d{2}-\d{2})?$/.test(normalizePath(pathname));
}

// The forms a plan-gated (daily-sync) path is judged in: as written, and with encoded separators (%2F, %5C, any case)
// decoded and runs of slashes merged. The origin decodes %2F before it routes, so /snapshots%2Fcredentials reached
// the credentials route past a gate that compared the encoded text (oxjob #1762). Only the two gated matchers below
// use this: an encoded slash is legitimate elsewhere (/works/https%3A%2F%2Fdoi.org%2F...), and the free browse
// matcher must never match more than it says.
function dailySyncForms(pathname: string): string[] {
    const decoded = pathname.replace(/%2f|%5c/gi, '/').replace(/\/{2,}/g, '/');
    return decoded === pathname ? [normalizePath(pathname)] : [normalizePath(pathname), normalizePath(decoded)];
}

// An actual changefile *download*: /changefiles/{date}/{filename}. These stay
// metered and plan-gated (daily sync: Member+, Partner and legacy plans) in index.ts.
export function isChangefileDownloadPath(pathname: string): boolean {
    return dailySyncForms(pathname).some(p => /^changefiles\/\d{4}-\d{2}-\d{2}\/[^/]+$/.test(p));
}

// The daily-snapshot credentials endpoint (/snapshots/credentials): daily sync too, plan-gated in index.ts with the
// same normalization as the download gate.
export function isSnapshotCredentialsPath(pathname: string): boolean {
    return dailySyncForms(pathname).some(p => p === 'snapshots/credentials');
}
