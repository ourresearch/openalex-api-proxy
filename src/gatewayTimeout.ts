import type { EndpointType } from "./endpointClassifier";

/**
 * The body of the proxy's own 504, sent when its clock runs out before the origin answers (oxjob #2003).
 *
 * Every 504 used to say "a very broad search... narrow the query", single-record lookups included. A lookup is never
 * broad: when one times out the API was slow, and the fix is to wait and retry. So the wording follows what the request
 * was (the classifier's type, or OQL) and which clock fired (9 s for most requests, 12 s for OQL, 25 s for the cached
 * count probe and metadata paths; originAbort.ts and index.ts).
 *
 * `reason` stays "query_timeout" where narrowing the query can help, and is "api_slow" where only a retry can;
 * clients branch on it (the MCP server does).
 */
export interface GatewayTimeoutBody {
    error: "Gateway timeout";
    message: string;
    reason: "query_timeout" | "api_slow";
    timeout_seconds: number;
}

const NOT_CHARGED = " You were not charged for this request.";

export function gatewayTimeoutBody(type: EndpointType | undefined, timeoutMs: number, isOql: boolean): GatewayTimeoutBody {
    const s = Math.round(timeoutMs / 1000);
    const slow = (message: string): GatewayTimeoutBody =>
        ({ error: "Gateway timeout", message: message + NOT_CHARGED, reason: "api_slow", timeout_seconds: s });
    const broad = (message: string): GatewayTimeoutBody =>
        ({ error: "Gateway timeout", message: message + NOT_CHARGED, reason: "query_timeout", timeout_seconds: s });

    if (isOql) {
        return broad(`Your OQL query didn't finish within ${s} seconds and was stopped. The query engine normally ` +
            "answers within 11 seconds, with advice on narrowing a query that is too big, so the API was probably busy. " +
            "Retry in a minute; if it times out again, narrow the query (fewer OR terms, a year or type filter).");
    }
    switch (type) {
        case "singleton":
            return slow(`This lookup of a single record didn't get an answer within ${s} seconds. Lookups normally take ` +
                "well under a second, so the API was slow, not your request. Please retry in a minute.");
        case "search":
            return broad(`Your query took longer than ${s} seconds and was stopped before completing. This usually means ` +
                "a very broad search (e.g. many OR/AND/NOT terms). Please narrow the query and try again.");
        case "semantic":
            return slow(`Semantic search didn't answer within ${s} seconds. It is busy when this happens; ` +
                "please retry in a minute.");
        case "list":
            return broad(`Your query took longer than ${s} seconds and was stopped before completing. Long lists of ` +
                "filter values and group_by over a very large set take longest: narrow the query and try again. If a " +
                "simple query also times out, the API is busy; retry in a minute.");
        default:
            return slow(`The API didn't answer within ${s} seconds. Please retry in a minute.`);
    }
}
