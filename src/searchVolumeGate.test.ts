import { describe, it, expect } from "vitest";
import {
    SEARCH_VOLUME_CAP,
    searchValueLength,
    isSearchVolumeExempt,
    checkSearchVolume,
    searchVolumeMessage,
} from "./searchVolumeGate";

const PAID = new Set(["premium-1M", "premium-2M", "institutional", "partner"]);

function u(qs: string): URL {
    return new URL("https://api.openalex.org/works?" + qs);
}

// "a" repeated n times, then URL-encoded into a search= param.
function longSearch(n: number, param = "search"): string {
    return `${param}=${"a".repeat(n)}`;
}

describe("searchValueLength", () => {
    it("returns 0 when no search param", () => {
        expect(searchValueLength(u("filter=type:article&per-page=200"))).toBe(0);
    });

    it("measures the DECODED length of search=", () => {
        // 5 spaces -> %20; decoded length is the human length, not the encoded one
        const url = u("search=" + encodeURIComponent("a b c d e f"));
        expect(searchValueLength(url)).toBe("a b c d e f".length);
    });

    it("counts search.semantic too", () => {
        expect(searchValueLength(u(longSearch(800, "search.semantic")))).toBe(800);
    });

    it("takes the max across duplicate params", () => {
        const url = u("search=short&search=" + "a".repeat(900));
        expect(searchValueLength(url)).toBe(900);
    });

    it("ignores filter pipe OR-of-IDs (the cheap protected class)", () => {
        const ids = Array.from({ length: 100 }, (_, i) => `S${4306400000 + i}`).join("|");
        expect(searchValueLength(u("filter=" + encodeURIComponent("primary_location.source.id:" + ids)))).toBe(0);
    });
});

describe("isSearchVolumeExempt", () => {
    const base = { hasValidApiKey: false, plan: null, trustedUi: false, paidPlans: PAID };

    it("exempts trusted UI (unforgeable #338 token)", () => {
        expect(isSearchVolumeExempt({ ...base, trustedUi: true })).toBe(true);
    });

    it("exempts a valid key on a paid plan", () => {
        expect(isSearchVolumeExempt({ ...base, hasValidApiKey: true, plan: "premium-2M" })).toBe(true);
    });

    it("does NOT exempt a free key with no paid plan (the ray abuser shape)", () => {
        expect(isSearchVolumeExempt({ ...base, hasValidApiKey: true, plan: null })).toBe(false);
    });

    it("does NOT exempt a key on a non-paid plan value", () => {
        expect(isSearchVolumeExempt({ ...base, hasValidApiKey: true, plan: "free" })).toBe(false);
    });

    it("does NOT exempt anonymous traffic", () => {
        expect(isSearchVolumeExempt(base)).toBe(false);
    });
});

describe("checkSearchVolume", () => {
    const anon = { hasValidApiKey: false, plan: null, trustedUi: false, paidPlans: PAID };

    it("passes a normal short search", () => {
        const r = checkSearchVolume(u("search=climate+change"), anon);
        expect(r.gated).toBe(false);
    });

    it("passes a search exactly at the cap", () => {
        const r = checkSearchVolume(u(longSearch(SEARCH_VOLUME_CAP)), anon);
        expect(r.gated).toBe(false);
        expect(r.length).toBe(SEARCH_VOLUME_CAP);
    });

    it("gates an anon search just over the cap", () => {
        const r = checkSearchVolume(u(longSearch(SEARCH_VOLUME_CAP + 1)), anon);
        expect(r.gated).toBe(true);
        expect(r.length).toBe(SEARCH_VOLUME_CAP + 1);
    });

    it("does NOT gate the same long search for a paid-plan key", () => {
        const r = checkSearchVolume(u(longSearch(3000)), {
            ...anon, hasValidApiKey: true, plan: "institutional",
        });
        expect(r.gated).toBe(false);
    });

    it("does NOT gate the same long search for trusted UI", () => {
        const r = checkSearchVolume(u(longSearch(3000)), { ...anon, trustedUi: true });
        expect(r.gated).toBe(false);
    });

    it("gates a long search for a free key (no paid plan)", () => {
        const r = checkSearchVolume(u(longSearch(3000)), {
            ...anon, hasValidApiKey: true, plan: null,
        });
        expect(r.gated).toBe(true);
    });

    it("never gates a request with no search param, however long the URL", () => {
        const ids = Array.from({ length: 500 }, (_, i) => `S${i}`).join("|");
        const r = checkSearchVolume(u("filter=" + encodeURIComponent("source.id:" + ids) + "&per-page=200"), anon);
        expect(r.gated).toBe(false);
    });

    it("honors a custom cap", () => {
        expect(checkSearchVolume(u(longSearch(600)), { ...anon, cap: 500 }).gated).toBe(true);
        expect(checkSearchVolume(u(longSearch(600)), { ...anon, cap: 1000 }).gated).toBe(false);
    });
});

describe("searchVolumeMessage", () => {
    it("names the length, the cap, and the remedy", () => {
        const m = searchVolumeMessage(2847);
        expect(m).toContain("2847");
        expect(m).toContain(String(SEARCH_VOLUME_CAP));
        expect(m).toContain("pricing");
    });
});
