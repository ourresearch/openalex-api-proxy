// Sync filters are a paid feature (oxjob #1689). Filtering or sorting by when a record was created or last updated
// is how a client keeps its own copy of OpenAlex in sync, so only paid plans (ENTERPRISE_PLANS in index.ts) may.
//
// A classic URL names these fields in its filter= and sort= params, and checkProtectedParams refuses it before the
// request is charged. OQL and OQO name the same fields in many wordings ("updated since", "added since", "created date
// >= ...", a column_id), and the grammar keeps changing, so a regex over OQL text would be brittle. Instead the proxy
// reads the engine's own translation: every executed OQL/OQO answer carries meta.x_query, with the classic URL (`url`,
// null when a URL can't say the query, e.g. a nested AND/OR or a pipeline summary) and the canonical OQO (`oqo`).
// OQL's date axes (#407, June 2026) assumed the engine enforced the plan; it didn't, so until this gate the same
// queries answered with no key at all (verified 2026-10-16: 40.9M works "updated since" 2026-10-15, keyless).

const SYNC_FIELD = '(?:from[_-]|to[_-])?(?:updated|created)[_-]date';
// Any value: the plan gates the field, not a date format. Hyphenated names count, since the API reads
// `from-updated-date` as `from_updated_date` (both answered a free key on 2026-10-16, past the old underscore-only rule).
const FILTER_RE = new RegExp(`(${SYNC_FIELD}):[^,]*`, 'i');
const SORT_RE = new RegExp(`(${SYNC_FIELD})(?::(?:asc|desc))?`, 'i');
const COLUMN_RE = new RegExp(`^${SYNC_FIELD}$`, 'i');

export interface SyncHit {
    kind: 'filter' | 'sort';
    field: string;   // from_updated_date
    clause: string;  // from_updated_date:2026-10-15, or updated_date:desc
}

/** A sync field in a URL's filter= or sort= params; the one rule for classic URLs and the engine's x_query.url. */
export function syncFieldInParams(params: URLSearchParams): SyncHit | null {
    // getAll: a duplicate param (?filter=safe&filter=from_updated_date:...) must not hide the second value.
    for (const value of params.getAll('filter')) {
        const m = value.match(FILTER_RE);
        if (m) return { kind: 'filter', field: m[1], clause: m[0] };
    }
    for (const value of params.getAll('sort')) {
        const m = value.match(SORT_RE);
        if (m) return { kind: 'sort', field: m[1], clause: m[0] };
    }
    return null;
}

/** A sync field in a relative classic URL such as x_query.url (`/works?filter=from_created_date:2026-10-15`). */
export function syncFieldInUrl(url: unknown): SyncHit | null {
    if (typeof url !== 'string' || url === '') return null;
    try {
        return syncFieldInParams(new URL(url, 'https://api.openalex.org').searchParams);
    } catch {
        return null;
    }
}

/** A sync column anywhere in an OQO: filter leaves, nested AND/OR branches, subqueries, sort_by. */
export function syncColumnInOqo(oqo: unknown, depth = 0): string | null {
    if (oqo === null || typeof oqo !== 'object' || depth > 64) return null;
    for (const [key, value] of Object.entries(oqo)) {
        if ((key === 'column_id' || key === 'sort_by_column') && typeof value === 'string' && COLUMN_RE.test(value)) {
            return value;
        }
        const hit = syncColumnInOqo(value, depth + 1);
        if (hit) return hit;
    }
    return null;
}

/** The sync field an executed query used, from the engine's meta.x_query: its classic URL, or its OQO when the URL
 *  can't say the query (url is null for nested AND/OR and pipeline summaries). Null when neither names one. */
export function syncFieldInXQuery(xQuery: unknown): string | null {
    if (xQuery === null || typeof xQuery !== 'object') return null;
    const { url, oqo } = xQuery as { url?: unknown; oqo?: unknown };
    return syncFieldInUrl(url)?.field ?? syncColumnInOqo(oqo);
}

// JSON-escaped text (`updated`) re-serialized plain, so the prefilter reads what the engine will.
function plainJson(value: unknown): string {
    try {
        const parsed = typeof value === 'string' ? JSON.parse(value) : value;
        return JSON.stringify(parsed) ?? '';
    } catch {
        return typeof value === 'string' ? value : '';
    }
}

/**
 * The OQL/OQO a request carries, as one text for the prefilter: a GET `oql` or `oqo` param on any path (only the
 * root executes today), or a POST JSON body's `oql` string or `oqo`. A `sort` sibling rides along, since the engine
 * folds it into the query. Null when the request carries no OQL/OQO.
 */
export function requestOqlText(params: URLSearchParams, postBody: unknown): string | null {
    const parts: string[] = [...params.getAll('oql'), ...params.getAll('oqo').map(plainJson)];
    const body = (postBody !== null && typeof postBody === 'object' && !Array.isArray(postBody))
        ? postBody as { oql?: unknown; oqo?: unknown; sort?: unknown }
        : {};
    if (typeof body.oql === 'string') parts.push(body.oql);
    if (body.oqo !== undefined && body.oqo !== null) parts.push(plainJson(body.oqo));
    if (parts.length === 0) return null;
    parts.push(...params.getAll('sort'));
    if (typeof body.sort === 'string') parts.push(body.sort);
    return parts.join('\n');
}

/**
 * Cheap prefilter, so only a query that could name a sync field has its answer read. Every wording the grammar has
 * today contains one of these words ("updated since", "added since", "created date", from_updated_date).
 * shortcut: a future OQL wording without them ("modified since") would skip the check; drop this filter then.
 */
export function mightNameSyncField(text: string): boolean {
    return /updated|created|added|_date/i.test(text);
}

/** How every sync refusal ends: the current plans that include daily sync, and a page agents can read
 * (openalex.org itself challenges scripts). Legacy Premium/Institutional plans still pass the gate, so
 * nobody who holds one ever sees this. */
export const DAILY_SYNC_PLANS = 'part of daily sync, which comes with the Member+ and Partner plans. See https://help.openalex.org/access/sync/ for details.';

/** The 429 message for an OQL/OQO query refused here (the classic URL's messages live in index.ts). */
export function oqlSyncMessage(field: string): string {
    return `OQL that filters or sorts by "${field}" is ${DAILY_SYNC_PLANS}`;
}

/**
 * Finds the top-level "meta" object of a JSON body as it streams in, so the answer is read only as far as meta's
 * closing brace: results can be megabytes, and meta comes first (x_query sat ~95 bytes in on 2026-10-16).
 * push() returns true once meta is parsed (in `meta`) or the body is known not to have one.
 */
export class MetaScanner {
    meta: unknown = undefined;
    private buf = '';
    private pos = 0;
    private depth = 0;
    private inString = false;
    private escaped = false;
    private stringStart = -1;
    private lastString: string | null = null;  // the last string closed at depth 1 (a key, if a ':' follows)
    private metaStart = -1;
    private done = false;

    push(text: string): boolean {
        if (this.done) return true;
        this.buf += text;
        for (; this.pos < this.buf.length; this.pos++) {
            const c = this.buf[this.pos];
            if (this.inString) {
                if (this.escaped) this.escaped = false;
                else if (c === '\\') this.escaped = true;
                else if (c === '"') {
                    this.inString = false;
                    if (this.depth === 1) this.lastString = this.buf.slice(this.stringStart + 1, this.pos);
                }
                continue;
            }
            if (c === '"') {
                this.inString = true;
                this.stringStart = this.pos;
            } else if (c === '{' || c === '[') {
                if (this.depth === 0 && c !== '{') return this.finish();  // not a JSON object: no meta
                if (this.depth === 1 && c === '{' && this.lastString === 'meta') this.metaStart = this.pos;
                this.depth++;
            } else if (c === '}' || c === ']') {
                this.depth--;
                if (this.depth === 1 && this.metaStart >= 0) {
                    try { this.meta = JSON.parse(this.buf.slice(this.metaStart, this.pos + 1)); } catch { /* fail open */ }
                    return this.finish();
                }
                if (this.depth <= 0) return this.finish();  // the body closed with no meta object
            } else if (c === ',' && this.depth === 1) {
                this.lastString = null;
            }
        }
        return false;
    }

    private finish(): true {
        this.done = true;
        this.buf = '';
        return true;
    }
}

// shortcut: past this much body, give up and let the answer through (fail open). A meta this big needs a POSTed
// query of a few hundred KB; raise it, or fail closed, if Analytics Engine ever shows sync-word queries that size.
export const META_SCAN_MAX_BYTES = 2_000_000;

/** meta.x_query from a JSON answer's stream (pass a clone's body; this cancels it when done). Undefined when the
 *  answer has no meta.x_query, isn't JSON, or meta isn't found within maxBytes: the caller fails open. */
export async function readXQuery(body: ReadableStream<Uint8Array>, maxBytes = META_SCAN_MAX_BYTES): Promise<unknown> {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    const scanner = new MetaScanner();
    let bytes = 0;
    try {
        while (bytes < maxBytes) {
            const { done, value } = await reader.read();
            if (done) {
                scanner.push(decoder.decode());
                break;
            }
            bytes += value.byteLength;
            if (scanner.push(decoder.decode(value, { stream: true }))) break;
        }
    } catch {
        /* a broken stream fails open */
    } finally {
        reader.cancel().catch(() => {});
    }
    const meta = scanner.meta;
    return meta !== null && typeof meta === 'object' ? (meta as { x_query?: unknown }).x_query : undefined;
}
