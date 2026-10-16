import { describe, it, expect } from "vitest";
import { checkSemanticGate, newSemanticGateState, semanticSearchKey, SAME_SEARCH_REPEATS } from "./semanticGate";

const key = (qs: string) => semanticSearchKey(new URL(`https://api.openalex.org/works?${qs}`));

describe("semanticSearchKey", () => {
    it("ignores page, per_page, sort and other presentation params", () => {
        expect(key("search.semantic=deep+learning&per_page=10&page=1&sort=relevance_score:desc"))
            .toBe(key("search.semantic=deep+learning&per_page=50&apc_sum=false"));
    });
    it("folds case and spacing in the semantic text", () => {
        expect(key("search.semantic=Deep%20%20Learning%20")).toBe(key("search.semantic=deep+learning"));
    });
    it("tells different texts and filters apart", () => {
        expect(key("search.semantic=frogs")).not.toBe(key("search.semantic=toads"));
        expect(key("search.semantic=frogs&filter=publication_year:2020"))
            .not.toBe(key("search.semantic=frogs"));
    });
});

describe("checkSemanticGate", () => {
    it("lets the website's list-then-table refetch of one search through (Kyle, 2026-10-16)", () => {
        const s = newSemanticGateState();
        const k = key("search.semantic=antibiotic+resistance");
        expect(checkSemanticGate(s, 1000, k).success).toBe(true);   // per_page=10
        expect(checkSemanticGate(s, 1040, k).success).toBe(true);   // per_page=50, 40 ms later
    });

    it("still holds a different search to one a second", () => {
        const s = newSemanticGateState();
        expect(checkSemanticGate(s, 1000, key("search.semantic=frogs")).success).toBe(true);
        const r = checkSemanticGate(s, 1300, key("search.semantic=toads"));
        expect(r.success).toBe(false);
        if (!r.success) expect(r.retryAfter).toBeCloseTo(0.7);
        expect(checkSemanticGate(s, 2000, key("search.semantic=toads")).success).toBe(true);
    });

    it("lets one search a second through indefinitely", () => {
        const s = newSemanticGateState();
        for (let i = 0; i < 10; i++) {
            expect(checkSemanticGate(s, 1000 + i * 1000, key(`search.semantic=q${i}`)).success).toBe(true);
        }
    });

    it("caps same-search repeats within the second", () => {
        const s = newSemanticGateState();
        const k = key("search.semantic=frogs");
        expect(checkSemanticGate(s, 1000, k).success).toBe(true);
        for (let i = 0; i < SAME_SEARCH_REPEATS; i++) expect(checkSemanticGate(s, 1001 + i, k).success).toBe(true);
        expect(checkSemanticGate(s, 1100, k).success).toBe(false);
    });

    it("repeats don't restart the clock", () => {
        const s = newSemanticGateState();
        const k = key("search.semantic=frogs");
        checkSemanticGate(s, 1000, k);
        checkSemanticGate(s, 1900, k);   // repeat
        expect(checkSemanticGate(s, 2000, key("search.semantic=toads")).success).toBe(true);
    });

    it("an empty key never counts as a repeat", () => {
        const s = newSemanticGateState();
        expect(checkSemanticGate(s, 1000, "").success).toBe(true);
        expect(checkSemanticGate(s, 1100, "").success).toBe(false);
    });
});
