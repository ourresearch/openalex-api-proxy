import { describe, it, expect } from 'vitest';
import { isAuthorFixesPath, authorFixesRequest } from './authorFixes';

describe('author fixes routing', () => {
    it('matches the fix resources', () => {
        for (const p of ['/authors/A5023888391/fixes', '/authors/A5023888391/fixes/', '/authors/a5023888391/fixes/F1001',
                         '/authors/5023888391/fix_estimate', '/authors/https://openalex.org/A5023888391/fixes']) {
            expect(isAuthorFixesPath(p)).toBe(true);
        }
    });
    it('leaves ordinary author reads alone', () => {
        for (const p of ['/authors/A5023888391', '/authors', '/authors/A5023888391/works', '/authors/A1/fixes/F1/extra', '/works/W1/fixes']) {
            expect(isAuthorFixesPath(p)).toBe(false);
        }
    });
    it('forwards method, path, query, auth and body', async () => {
        const req = new Request('https://api.openalex.org/authors/A1/fixes/F2?x=1', {
            method: 'PATCH', headers: { Authorization: 'Bearer k', 'Content-Type': 'application/json', Cookie: 'c' },
            body: '{"state":"applied"}',
        });
        const out = await authorFixesRequest(req, 'https://fixes.example.com');
        expect(out.url).toBe('https://fixes.example.com/authors/A1/fixes/F2?x=1');
        expect(out.method).toBe('PATCH');
        expect(out.headers.get('Authorization')).toBe('Bearer k');
        expect(out.headers.get('Cookie')).toBeNull();
        expect(await out.text()).toBe('{"state":"applied"}');
    });
});
