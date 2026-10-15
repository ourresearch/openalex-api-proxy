// Keyless callers hear about keys in the response they got (oxjob #1686, Jason 2026-10-15).
//
// 75% of model-written OpenAlex code passes mailto= (the retired "polite pool") and 74% sends no API key. The API
// takes both silently, so an agent learns only when its IP's shared keyless budget runs out, and AI fetch tools
// often drop the 429's body. So a keyless 200 JSON answer now carries a one-line meta.notice that says so.
//
// Not for: keyed requests (their budget is their own), the website (trustedUi), verified AI assistants (their
// budget is their own too, so the notice would mislead), errors, HEAD, non-JSON (CSV) or encoded bodies.
//
// Cost: no JSON.parse. Bodies run to several MB and this runs on most keyless traffic, so the notice is spliced
// into the byte stream: the transform holds bytes only until it has seen the first 11, inserts the notice after
// the origin's exact opening `{"meta": {`, and passes every later chunk through as is. A body that opens any other
// way (a singleton record: `{"id":...`, which has no meta) goes through unchanged: adding a top-level key to an
// entity record would change the record's shape for every client that maps it, and singletons are free anyway.
// Singleton routes skip the transform altogether, so they keep their Content-Length.
//
// shortcut: matching exact bytes ties the notice to the origin's json.dumps style (", " and ": " separators). If
// the origin moves to compact JSON (orjson, separators=(",", ":")), the notice stops silently; match `{"meta":`
// plus optional whitespace then, or have the origin add meta.notice itself on a header from this Worker.


import { API_ROOT } from "./apiRoot";
import { ASK_FOR_A_KEY } from "./apiKeys";

/** The notice for a keyless caller whose shared budget is `dailyBudgetUsd` a day ($0.10 today). */
export function keylessNoticeFor(searchParams: URLSearchParams, dailyBudgetUsd: number): string {
    return `No API key, so this request shares one free daily budget ($${dailyBudgetUsd.toFixed(2)}) with everyone on your network's IP address.`
        + (searchParams.has("mailto") ? " The mailto parameter doesn't raise this limit." : "")
        // $1/day is a free key's budget, set by users-api's plans, not here.
        + ` Get a free key with its own $1/day at ${API_ROOT.get_a_free_key} and add api_key=YOUR_KEY to your requests.`
        + ` ${ASK_FOR_A_KEY}`
        + ` Docs for agents: ${API_ROOT.llms_txt}`;
}

export interface NoticeFacts {
    method: string;
    endpointType: string;
    status: number;
    headers: Headers;
    apiKey: string | null;
    trustedUi: boolean;
    verifiedAssistant: boolean;
}

export function wantsKeylessNotice(p: NoticeFacts): boolean {
    if (p.apiKey || p.trustedUi || p.verifiedAssistant) return false;
    return noticeFits(p);
}

function noticeFits(p: NoticeFacts): boolean {
    if (p.status !== 200 || p.endpointType === "singleton" || (p.method !== "GET" && p.method !== "POST")) return false;
    if (!(p.headers.get("Content-Type") || "").toLowerCase().includes("application/json")) return false;
    // The origin sends identity today. An encoded body is left alone rather than re-encoded: if the origin ever
    // starts compressing, the notice stops (and this line is where to look), but no body is ever mislabelled.
    // (Workers' fetch() decodes a gzip body but keeps its Content-Encoding header; checked under workerd.)
    const encoding = (p.headers.get("Content-Encoding") || "identity").trim().toLowerCase();
    return encoding === "identity";
}

const encoder = new TextEncoder();
const PREFIX = encoder.encode('{"meta": {');
const NEED = PREFIX.length + 1;  // the opening plus the byte after it
const QUOTE = 0x22;  // `"`: meta's first key follows, so the notice needs a comma after it
const CLOSE = 0x7d;  // `}`: meta is empty, so no comma
const COMMA = encoder.encode(", ");

/**
 * A TransformStream that adds `"notice": <notice>` as meta's first key when the body opens with `{"meta": {`
 * followed by a key or `}`, and otherwise passes the body through byte for byte. Only the opening bytes are
 * ever held or copied; the opening may arrive split across chunks.
 */
export function metaNoticeTransform(notice: string): TransformStream<Uint8Array, Uint8Array> {
    const field = encoder.encode(`"notice": ${JSON.stringify(notice)}`);
    const head = new Uint8Array(NEED);  // the opening, gathered here only when the first chunk is shorter than it
    let have = 0;
    let decided = false;

    function sendOpening(controller: TransformStreamDefaultController<Uint8Array>, bytes: Uint8Array) {
        const next = bytes[PREFIX.length];
        if (PREFIX.every((b, i) => bytes[i] === b) && (next === QUOTE || next === CLOSE)) {
            controller.enqueue(bytes.subarray(0, PREFIX.length));
            controller.enqueue(field);
            if (next === QUOTE) controller.enqueue(COMMA);
            controller.enqueue(bytes.subarray(PREFIX.length));
        } else {
            controller.enqueue(bytes);
        }
    }

    return new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            if (decided) {
                controller.enqueue(chunk);
                return;
            }
            if (have === 0 && chunk.length >= NEED) {  // the usual case: the whole opening in the first chunk, no copy
                decided = true;
                sendOpening(controller, chunk);
                return;
            }
            const take = Math.min(NEED - have, chunk.length);
            head.set(chunk.subarray(0, take), have);
            have += take;
            if (have < NEED) return;
            decided = true;
            sendOpening(controller, head);
            if (take < chunk.length) controller.enqueue(chunk.subarray(take));
        },
        flush(controller) {
            if (!decided && have > 0) controller.enqueue(head.subarray(0, have));  // shorter than the opening: as it came
        },
    });
}
