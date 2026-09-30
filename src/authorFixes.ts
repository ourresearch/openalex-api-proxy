// Author fixes (oxjob #1430): /authors/{id}/fixes[/{fix}] and /authors/{id}/fix_estimate
// are served by the openalex-author-fixes Heroku app. They sit next to the author they
// belong to, but they are writes and long jobs, not entity reads: the app authenticates
// the caller's API key itself (site-wide users only for now), and the proxy charges no
// credits for them.
export const AUTHOR_FIXES_PATH = /^\/authors\/(?:https?:\/\/openalex\.org\/)?[Aa]?\d+\/(?:fixes(?:\/[A-Za-z0-9]+)?|fix_estimate)\/?$/;

export function isAuthorFixesPath(pathname: string): boolean {
    return AUTHOR_FIXES_PATH.test(pathname);
}

export async function authorFixesRequest(req: Request, originBase: string): Promise<Request> {
    const url = new URL(req.url);
    const target = new URL(url.pathname + url.search, originBase);
    const headers = new Headers();
    for (const h of ["Authorization", "Content-Type", "Accept"]) {
        const v = req.headers.get(h);
        if (v) headers.set(h, v);
    }
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    return new Request(target.toString(), { method: req.method, headers, body: hasBody ? await req.arrayBuffer() : undefined });
}
