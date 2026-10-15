// The API root, GET https://api.openalex.org/ (oxjob #1686). Agents start here. It used to go to the origin, cost a
// keyless caller a list credit (and 429 once the IP's budget was spent), and point at /docs, which 404s. The Worker
// now answers it itself: free, never refused for budget, with the links an agent needs next. Every URL below
// returned 200 on 2026-10-15 (help.openalex.org pages take the trailing slash; without it they 308).
//
// Only a bare GET or HEAD of "/" on the API host: GET /?oql= and /?oqo= (and POST /) run a query at the origin,
// and content.openalex.org/ is the content worker's own root.

export const API_ROOT = {
    name: "OpenAlex API",
    description: "Free, open data on the world's research: hundreds of millions of scholarly works, and the authors, sources, institutions, topics and funders connected to them (CC0).",
    documentation: "https://help.openalex.org",
    llms_txt: "https://help.openalex.org/llms.txt",
    quick_reference: "https://help.openalex.org/api/llm-quick-reference/",
    authentication: "https://help.openalex.org/api/authentication/",
    get_a_free_key: "https://openalex.org/settings/api",
    // oxjob #1697: a coding agent gets one for its user in one call (apiKeys.ts); GET that URL for the details.
    get_a_free_key_by_api: {
        method: "POST",
        url: "https://api.openalex.org/api-keys",
        body: { email: "<your user's email address>" },
        note: "We email your user a link; the key works once they click it ($1 a day). GET the URL for details.",
    },
    pricing: "https://openalex.org/pricing",
    examples: {
        search: "https://api.openalex.org/works?search=coral%20reef%20bleaching",
        filter: "https://api.openalex.org/works?filter=publication_year:2024,is_oa:true&sort=cited_by_count:desc",
        work_by_doi: "https://api.openalex.org/works/doi:10.7717/peerj.4375",
    },
    // Kept from the origin's old answer: openalex-elastic-api's post-deploy smoke test asserts both on this URL.
    version: "0.1",
    msg: "Don't panic",
};

const API_ROOT_BODY = JSON.stringify(API_ROOT, null, 2) + "\n";

export function isApiRootRequest(url: URL, method: string): boolean {
    return (method === "GET" || method === "HEAD")
        && url.pathname === "/"
        && url.hostname !== "content.openalex.org"
        && !url.searchParams.has("oql")
        && !url.searchParams.has("oqo");
}

export function apiRootResponse(method: string): Response {
    return new Response(method === "HEAD" ? null : API_ROOT_BODY, {
        status: 200,
        headers: {
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600",
            // The root is free: say so on the same headers a priced request carries.
            "X-RateLimit-Credits-Used": "0",
            "X-RateLimit-Cost-USD": "0",
        },
    });
}
