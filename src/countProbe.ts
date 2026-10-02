// Which anonymous requests the proxy may cache as a corpus-count probe (2026-08-24
// incident; the reasoning lives at the call site in index.ts).
//
// A count probe is `per-page=1&select=id` with no paging and no credentials: the body
// is the same for every caller, so caching it for 5 minutes is safe and removes most
// of its ES load.
//
// EXCEPT when the query names a collection (`col_…`, in `filter=` or `oql=`). Then the
// body depends on the collection's members and on whether its owner shares it by link
// (oxjob #646): a cached count would keep answering for up to 5 minutes after the owner
// edits the members or makes the collection private again. Those probes are cheap
// (filtered) and rare, so they always go to the origin.
export function isCacheableCountProbe(url: URL, method: string, hasApiKey: boolean, hasAuthorization: boolean): boolean {
    const perPage = url.searchParams.get('per-page') ?? url.searchParams.get('per_page');
    return method === "GET"
        && perPage === '1'
        && url.searchParams.get('select') === 'id'
        && !url.searchParams.has('cursor')
        && !url.searchParams.has('page')
        && !hasApiKey
        && !hasAuthorization
        && !mentionsCollection(url);
}

// `col_` anywhere in the decoded query string (filter values, `!col_…`, OQL text).
export function mentionsCollection(url: URL): boolean {
    for (const value of url.searchParams.values()) {
        if (/col_/i.test(value)) return true;
    }
    return false;
}
