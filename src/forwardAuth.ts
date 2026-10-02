// The Authorization header the proxy sends to elastic-api.
//
// elastic-api relays it to users-api to resolve `col_` filters, so it decides whether a
// caller's private collections resolve (oxjob #228 QA-040). The proxy accepts a key as
// `Authorization: Bearer`, `?api_key=`/`?api-key=` or an `api_key` header, but used to
// forward only the first, so a `?api_key=` caller filtering by their own collection got
// zero results, and after #646 "Collection not found or not shared" (#283, oxjob #1505).
//
// A key from anywhere else is forwarded as a Bearer header, but only once the proxy has
// validated it: changefiles browsing lets an invalid key through as anonymous, and that
// one must stay anonymous downstream too.
export function authorizationToForward(
    incomingAuthorization: string | null,
    apiKey: string | null,
    hasValidApiKey: boolean,
): string | null {
    if (incomingAuthorization) return incomingAuthorization;
    if (apiKey && hasValidApiKey) return `Bearer ${apiKey}`;
    return null;
}
