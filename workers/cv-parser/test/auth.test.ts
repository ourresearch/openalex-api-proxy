import { afterEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';

const env = { ANTHROPIC_API_KEY: 'test' };

function parseRequest(headers: Record<string, string> = {}) {
  return new Request('https://cv.example/api/parse-cv', { method: 'POST', headers, body: 'x' });
}

afterEach(() => vi.unstubAllGlobals());

describe('parse-cv sign-in gate (oxjob #1782)', () => {
  it('refuses a request with no Authorization header without calling users-api', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const resp = await worker.fetch(parseRequest(), env);
    expect(resp.status).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('refuses a key that users-api rejects', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 401 })));
    const resp = await worker.fetch(parseRequest({ Authorization: 'Bearer bad' }), env);
    expect(resp.status).toBe(401);
  });

  it('checks the caller against users-api /users/me with their own header', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchSpy);
    // Signed in, so the request reaches the parser, which fails on the non-multipart body.
    const resp = await worker.fetch(parseRequest({ Authorization: 'Bearer good' }), env);
    expect(fetchSpy).toHaveBeenCalledWith(
      'https://user.openalex.org/users/me',
      expect.objectContaining({ headers: { Authorization: 'Bearer good' } }),
    );
    expect(resp.status).toBe(500);
  });

  it('refuses an oversized upload before checking sign-in', async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);
    const resp = await worker.fetch(parseRequest({ 'Content-Length': String(11 * 1024 * 1024) }), env);
    expect(resp.status).toBe(413);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('still matches the route with trailing slashes, and a long slash run is cheap', async () => {
    vi.stubGlobal('fetch', vi.fn());
    const trailing = new Request('https://cv.example/api/parse-cv///', { method: 'POST', body: 'x' });
    expect((await worker.fetch(trailing, env)).status).toBe(401);
    const started = Date.now();
    const slashes = new Request('https://cv.example/' + '/'.repeat(16000) + 'x', { method: 'GET' });
    expect((await worker.fetch(slashes, env)).status).toBe(404);
    expect(Date.now() - started).toBeLessThan(200);
  });
});
