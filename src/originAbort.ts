/**
 * How long the proxy waits for the origin before answering its own 504 (oxjob #1598).
 *
 * Most requests: 9 s (see the 2026-08-24 note in index.ts: a shorter abort frees nothing on the origin).
 *
 * Requests that carry OQL or an OQO (a POST body or `?oql=` / `?oqo=`): 12 s. The OQL engine keeps its own clock: it
 * stops its Elasticsearch calls at 11 s and answers with the result or a message saying how to narrow the query
 * (elastic-api `analytics.QUERY_DEADLINE_S`, under gunicorn's 12 s). At 9 s the proxy cut off both, so a calculation
 * that took 9-11 s got a generic "took too long" instead (measured 2026-10-26: all works by author, 504 at 9.1 s).
 */
export const ORIGIN_ABORT_MS = 9000;
export const OQL_ORIGIN_ABORT_MS = 12000;

export function originAbortMs(oqlText: string | null): number {
    return oqlText !== null ? OQL_ORIGIN_ABORT_MS : ORIGIN_ABORT_MS;
}
