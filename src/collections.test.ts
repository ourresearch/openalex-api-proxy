import { describe, it, expect } from 'vitest';
import { isCollectionsPath, collectionsRequest, USERS_API_URL } from './collections';

describe('collections routing', () => {
    it('matches the collections resource and everything under it', () => {
        for (const p of ['/collections', '/collections/', '/collections/col_abc', '/collections/col_abc/members',
                         '/collections/col_abc/members/W1', '/collections/col_abc/members/https://openalex.org/W1']) {
            expect(isCollectionsPath(p)).toBe(true);
        }
    });
    it('leaves everything else alone', () => {
        for (const p of ['/works', '/collectionsx', '/works/collections', '/', '/me/collections']) {
            expect(isCollectionsPath(p)).toBe(false);
        }
    });
    it('forwards to /api on users-api with method, query, auth and body', async () => {
        const req = new Request('https://api.openalex.org/collections/col_a/members?page=2', {
            method: 'POST', headers: { Authorization: 'Bearer k', 'Content-Type': 'application/json', Cookie: 'c' },
            body: '{"member_ids":["W1"]}',
        });
        const out = await collectionsRequest(req, USERS_API_URL);
        expect(out.url).toBe('https://user.openalex.org/api/collections/col_a/members?page=2');
        expect(out.method).toBe('POST');
        expect(out.headers.get('Authorization')).toBe('Bearer k');
        expect(out.headers.get('Cookie')).toBeNull();
        expect(await out.text()).toBe('{"member_ids":["W1"]}');
    });
    it('moves ?api_key= into a Bearer header and out of the URL', async () => {
        const req = new Request('https://api.openalex.org/collections?api_key=sekret&per_page=5');
        const out = await collectionsRequest(req, USERS_API_URL);
        expect(out.url).toBe('https://user.openalex.org/api/collections?per_page=5');
        expect(out.headers.get('Authorization')).toBe('Bearer sekret');
    });
    it('names the caller IP only with the proxy key', async () => {
        const req = new Request('https://api.openalex.org/collections/col_a', { headers: { 'CF-Connecting-IP': '203.0.113.9' } });
        const without = await collectionsRequest(req, USERS_API_URL);
        expect(without.headers.get('X-Collection-Client-IP')).toBeNull();
        const withKey = await collectionsRequest(req, USERS_API_URL, 'pk');
        expect(withKey.headers.get('X-Collection-Client-IP')).toBe('203.0.113.9');
        expect(withKey.headers.get('X-Collection-Proxy-Key')).toBe('pk');
    });
    it('never forwards a client-sent IP header', async () => {
        const req = new Request('https://api.openalex.org/collections/col_a', { headers: { 'X-Collection-Client-IP': '1.2.3.4', 'X-Collection-Proxy-Key': 'guess' } });
        const out = await collectionsRequest(req, USERS_API_URL);
        expect(out.headers.get('X-Collection-Client-IP')).toBeNull();
        expect(out.headers.get('X-Collection-Proxy-Key')).toBeNull();
    });
});
