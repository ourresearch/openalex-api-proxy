// The whole Worker charges what help.openalex.org's price list says, for the shapes oxjob #1886 found priced against
// it: lookups on the named-id families, their searches, the .search filters, a HEAD on a content file.
import { describe, it, expect, vi, afterEach } from "vitest";
import { runWorker } from "./testHarness";

vi.mock("pg", () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, [key]: string[]) {
            return { rows: key !== "free-key" ? [] : [{
                max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
                onetime_credits_expires_at: null, plan: null, rate_throttled: false, throttle_scope: null,
                user_id: "user-free-key", org_id: null,
            }] };
        }
        async end() {}
    },
}));

const HD = { HYPERDRIVE: { connectionString: "postgres://test" } };
const used = (res: Response) => res.headers.get("X-RateLimit-Credits-Used");

describe("the Worker charges the price list (oxjob #1886)", () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    it.each([
        ["/keywords/artificial-intelligence", "0"],
        ["/awards/G3618239412", "0"],
        ["/countries/US", "0"],
        ["/entities/works/W2741809807", "0"],
        ["/keywords?search=climate", "10"],
        ["/awards?search=cancer", "10"],
        ["/entities/works?search=coral", "10"],
        ["/institutions?filter=text.search:harvard", "10"],
        ["/funders?filter=description.search:cancer", "10"],
        ["/keywords?per_page=5", "1"],
        ["/works/random", "1"],
    ])("keyless %s costs %s", async (path, credits) => {
        const { res } = await runWorker(path);
        expect(res.status).toBe(200);
        expect(used(res)).toBe(credits);
    });

    it.each([
        ["/authors?filter=text.search:smith", "https://search.test"],
        ["/keywords?search=climate", "https://search.test"],
        ["/entities/works?search=coral", "https://search.test"],
        ["/works?search=coral", "https://search.test"],
        ["/keywords/artificial-intelligence", "https://origin.test"],
        ["/works?filter=publication_year:2020", "https://origin.test"],
    ])("%s runs on %s", async (path, host) => {
        const called: string[] = [];
        await runWorker(path, {
            env: { SEARCH_API_URL: "https://search.test" },
            fetch: async (u: string | Request) => {
                called.push(new URL(typeof u === "string" ? u : u.url).origin);
                return new Response('{"meta":{}}', { status: 200, headers: { "Content-Type": "application/json" } });
            },
        });
        expect(called).toEqual([host]);
    });

    function contentWorker() {
        const methods: string[] = [];
        return {
            methods,
            CONTENT_WORKER: { fetch: async (r: Request) => {
                methods.push(r.method);
                // what openalex-content-api sends for a stored file, HEAD or GET
                return new Response(r.method === "HEAD" ? null : "%PDF-1.4", {
                    status: 200, headers: { "Content-Type": "application/pdf", "X-Credits-Cost": "100" },
                });
            } },
        };
    }

    it.each(["/content/works/W3038568908.pdf", "/content/works/W3038568908.grobid-xml"])(
        "HEAD %s is free and says so; GET still costs 100", async (path) => {
            const w = contentWorker();
            const env = { ...HD, CONTENT_WORKER: w.CONTENT_WORKER };
            const headers = { Authorization: "Bearer free-key" };
            const head = await runWorker(path, { env, headers, method: "HEAD" });
            expect(head.res.status).toBe(200);
            expect(used(head.res)).toBe("0");
            expect(head.res.headers.get("X-RateLimit-Cost-USD")).toBe("0");
            const get = await runWorker(path, { env, headers });
            expect(used(get.res)).toBe("100");
            expect(w.methods).toEqual(["HEAD", "GET"]);
        });
});
