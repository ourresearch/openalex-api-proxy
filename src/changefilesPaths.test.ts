import { describe, it, expect, vi, afterEach } from "vitest";
import { isChangefilesBrowsePath, isChangefileDownloadPath, isSnapshotCredentialsPath } from "./changefilesPaths";
import { runWorker } from "./testHarness";

// Keyed requests look their key up in api_keys_view: a free key and a daily-sync (Member+) key.
vi.mock("pg", () => ({
    Client: class {
        async connect() {}
        async query(_sql: string, [key]: string[]) {
            const plan = key === "free-key" ? null : key === "sync-key" ? "member-plus" : undefined;
            return { rows: plan === undefined ? [] : [{
                max_per_day: 10_000, max_credits_per_day: 10_000, is_grandfathered: false, onetime_credits_balance: 0,
                onetime_credits_expires_at: null, plan, rate_throttled: false, throttle_scope: null, user_id: `user-${key}`, org_id: null,
            }] };
        }
        async end() {}
    },
}));

describe("isChangefilesBrowsePath", () => {
    it("matches the changefiles index", () => {
        expect(isChangefilesBrowsePath("/changefiles")).toBe(true);
    });

    it("matches a single date listing", () => {
        expect(isChangefilesBrowsePath("/changefiles/2026-06-05")).toBe(true);
    });

    it("tolerates a trailing slash", () => {
        expect(isChangefilesBrowsePath("/changefiles/")).toBe(true);
        expect(isChangefilesBrowsePath("/changefiles/2026-06-05/")).toBe(true);
    });

    it("tolerates an already-normalized (no leading slash) path", () => {
        expect(isChangefilesBrowsePath("changefiles")).toBe(true);
        expect(isChangefilesBrowsePath("changefiles/2026-06-05")).toBe(true);
    });

    it("is case-insensitive", () => {
        expect(isChangefilesBrowsePath("/Changefiles/2026-06-05")).toBe(true);
    });

    // SECURITY BOUNDARY: a download must never be treated as free/keyless browse.
    it("does NOT match an actual file download", () => {
        expect(isChangefilesBrowsePath("/changefiles/2026-06-05/works_2026-06-05.jsonl.gz")).toBe(false);
        expect(isChangefilesBrowsePath("/changefiles/2026-06-05/authors_2026-06-05.parquet")).toBe(false);
    });

    it("does NOT match a malformed date", () => {
        expect(isChangefilesBrowsePath("/changefiles/2026-6-5")).toBe(false);
        expect(isChangefilesBrowsePath("/changefiles/latest")).toBe(false);
    });

    it("does NOT match unrelated or look-alike paths", () => {
        expect(isChangefilesBrowsePath("/works")).toBe(false);
        expect(isChangefilesBrowsePath("/changefiles-extra")).toBe(false);
        expect(isChangefilesBrowsePath("/snapshots")).toBe(false);
    });
});

describe("isChangefileDownloadPath", () => {
    it("matches a real download (jsonl.gz and parquet)", () => {
        expect(isChangefileDownloadPath("/changefiles/2026-06-05/works_2026-06-05.jsonl.gz")).toBe(true);
        expect(isChangefileDownloadPath("/changefiles/2026-06-05/authors_2026-06-05.parquet")).toBe(true);
    });

    it("is case-insensitive and tolerates leading-slash-free input", () => {
        expect(isChangefileDownloadPath("changefiles/2026-06-05/works.jsonl.gz")).toBe(true);
    });

    // SECURITY BOUNDARY: the browse/listing paths must never be gated as downloads
    // (and vice-versa) — the two predicates must be mutually exclusive.
    it("does NOT match the listing endpoints", () => {
        expect(isChangefileDownloadPath("/changefiles")).toBe(false);
        expect(isChangefileDownloadPath("/changefiles/2026-06-05")).toBe(false);
        expect(isChangefileDownloadPath("/changefiles/2026-06-05/")).toBe(false);
    });

    it("does NOT match a nested path below the filename", () => {
        expect(isChangefileDownloadPath("/changefiles/2026-06-05/works/extra")).toBe(false);
    });
});

describe("the two predicates are mutually exclusive", () => {
    const paths = [
        "/changefiles",
        "/changefiles/2026-06-05",
        "/changefiles/2026-06-05/",
        "/changefiles/2026-06-05/works_2026-06-05.jsonl.gz",
        "/changefiles/2026-06-05/works/extra",
        "/changefiles/latest",
        "/works",
    ];
    for (const p of paths) {
        it(`never classifies "${p}" as both browse and download`, () => {
            expect(isChangefilesBrowsePath(p) && isChangefileDownloadPath(p)).toBe(false);
        });
    }
});

describe("isSnapshotCredentialsPath", () => {
    it("matches /snapshots/credentials with the download gate's normalization", () => {
        expect(isSnapshotCredentialsPath("/snapshots/credentials")).toBe(true);
        expect(isSnapshotCredentialsPath("/snapshots/credentials/")).toBe(true);
        expect(isSnapshotCredentialsPath("//SNAPSHOTS/Credentials")).toBe(true);
        expect(isSnapshotCredentialsPath("/snapshots")).toBe(false);
        expect(isSnapshotCredentialsPath("/snapshots/credentials/x")).toBe(false);
    });
});

// Every way to a changefile download is plan-gated alike, including api.openalex.org/content/..., which the content
// branch forwards to the content worker as /changefiles/... (oxjob #1762).
describe("daily-sync gates judge the path the content worker is asked for", () => {
    afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

    const FILE = "/changefiles/2026-10-20/works_2026-10-20.jsonl.gz";
    const HD = { HYPERDRIVE: { connectionString: "postgres://test" } };
    function contentWorker() {
        const paths: string[] = [];
        return {
            paths,
            CONTENT_WORKER: { fetch: async (r: Request) => {
                paths.push(new URL(r.url).pathname);
                return new Response(null, { status: 302, headers: { Location: "https://s3.test/signed", "X-Credits-Cost": "0" } });
            } },
        };
    }

    for (const path of [`/content${FILE}`, `/CONTENT${FILE}`, `/Content${FILE}`, `/content/${FILE}`, `/content${FILE}/`]) {
        it(`${path}: no key 401, a free key 403, neither reaching the content worker or the limiter`, async () => {
            const w = contentWorker();
            const keyless = await runWorker(path, { env: { ...HD, CONTENT_WORKER: w.CONTENT_WORKER } });
            expect(keyless.res.status).toBe(401);
            expect(keyless.checks).toEqual([]);
            const free = await runWorker(path, { env: { ...HD, CONTENT_WORKER: w.CONTENT_WORKER }, headers: { Authorization: "Bearer free-key" } });
            expect(free.res.status).toBe(403);
            expect(free.checks).toEqual([]);
            expect(w.paths).toEqual([]);
        });
    }

    it("a daily-sync key still gets its download through /content", async () => {
        const w = contentWorker();
        const { res } = await runWorker(`/content${FILE}`, { env: { ...HD, CONTENT_WORKER: w.CONTENT_WORKER }, headers: { Authorization: "Bearer sync-key" } });
        expect(res.status).toBe(302);
        expect(w.paths).toEqual([FILE]);
    });

    it("snapshot credentials are gated through /content too", async () => {
        const w = contentWorker();
        expect((await runWorker("/content/snapshots/credentials", { env: { ...HD, CONTENT_WORKER: w.CONTENT_WORKER } })).res.status).toBe(401);
        expect(w.paths).toEqual([]);
    });

    it("an upper-case /CONTENT prefix is stripped like /content, so a PDF download needs a key", async () => {
        const w = contentWorker();
        expect((await runWorker("/CONTENT/works/W2741809807.pdf", { env: { ...HD, CONTENT_WORKER: w.CONTENT_WORKER } })).res.status).toBe(401);
        expect(w.paths).toEqual([]);
    });
});
