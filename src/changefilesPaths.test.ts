import { describe, it, expect } from "vitest";
import { isChangefilesBrowsePath, isChangefileDownloadPath } from "./changefilesPaths";

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
