// Slash trimming for request paths, in linear time (oxjob #1762).
//
// `p.replace(/^\/+|\/+$/g, '')` and `/\/+$/` look cheap, but V8's backtracking engine retries `\/+$` from every
// position inside a run of slashes that doesn't end the string, so a path like '/works' + '/'.repeat(16000) + 'x'
// cost O(n²): about 0.6 s of CPU across the six trims a request made before any key check or rate gate. These scan
// only the leading and trailing runs and return exactly what those regexes returned.

const SLASH = 47;  // '/'

/** `p` without its leading and trailing slashes; same output as p.replace(/^\/+|\/+$/g, '') and /^\/*|\/*$/g. */
export function trimSlashes(p: string): string {
    let start = 0;
    let end = p.length;
    while (start < end && p.charCodeAt(start) === SLASH) start++;
    while (end > start && p.charCodeAt(end - 1) === SLASH) end--;
    return p.slice(start, end);
}

/** `p` without its trailing slashes; same output as p.replace(/\/+$/, ''). */
export function trimTrailingSlashes(p: string): string {
    let end = p.length;
    while (end > 0 && p.charCodeAt(end - 1) === SLASH) end--;
    return p.slice(0, end);
}

/** The canonical form every path matcher compares: no leading or trailing slashes, lowercase. */
export function normalizePath(pathname: string): string {
    return trimSlashes(pathname).toLowerCase();
}
