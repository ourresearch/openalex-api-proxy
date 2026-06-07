import { describe, it, expect } from 'vitest';
import { mintUiToken, verifyUiToken, verifyTurnstile } from './uiToken';

const SECRET = 'test-hmac-secret-do-not-use-in-prod';
const TTL = 1800; // 30 min
const NOW = 1_700_000_000_000; // fixed epoch ms for determinism

describe('uiToken mint/verify', () => {
    it('mints a token that verifies as valid within its TTL', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL);
        const res = await verifyUiToken(tok, SECRET, NOW + 1000);
        expect(res.valid).toBe(true);
        expect(res.payload?.v).toBe(1);
        expect(res.payload?.exp).toBe(Math.floor(NOW / 1000) + TTL);
    });

    it('rejects an expired token', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL);
        const res = await verifyUiToken(tok, SECRET, NOW + (TTL + 1) * 1000);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('expired');
    });

    it('rejects a token signed with a different secret (forgery)', async () => {
        const tok = await mintUiToken('attacker-secret', NOW, TTL);
        const res = await verifyUiToken(tok, SECRET, NOW + 1000);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('bad_signature');
    });

    it('rejects a tampered payload (signature no longer matches)', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL);
        const [body, sig] = tok.split('.');
        // Flip a char in the body; the original signature won't match.
        const tampered = body.slice(0, -1) + (body.slice(-1) === 'A' ? 'B' : 'A') + '.' + sig;
        const res = await verifyUiToken(tampered, SECRET, NOW + 1000);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('bad_signature');
    });

    it('treats malformed / empty / null tokens as untrusted, never throws', async () => {
        for (const bad of [null, undefined, '', 'no-dot', '.', 'a.', '.b']) {
            const res = await verifyUiToken(bad as string, SECRET, NOW);
            expect(res.valid).toBe(false);
            expect(res.reason).toBe('malformed');
        }
    });

    it('reports no_secret when the server secret is unset (fail-safe, not crash)', async () => {
        const res = await verifyUiToken('whatever.sig', undefined, NOW);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('no_secret');
    });

    it('each mint is unique (random nonce) but all verify', async () => {
        const a = await mintUiToken(SECRET, NOW, TTL);
        const b = await mintUiToken(SECRET, NOW, TTL);
        expect(a).not.toBe(b);
        expect((await verifyUiToken(a, SECRET, NOW)).valid).toBe(true);
        expect((await verifyUiToken(b, SECRET, NOW)).valid).toBe(true);
    });
});

describe('verifyTurnstile', () => {
    const okFetch = (async () =>
        new Response(JSON.stringify({ success: true }), { status: 200 })) as unknown as typeof fetch;
    const failFetch = (async () =>
        new Response(JSON.stringify({ success: false, 'error-codes': ['invalid-input-response'] }), { status: 200 })) as unknown as typeof fetch;
    const throwFetch = (async () => { throw new Error('network'); }) as unknown as typeof fetch;

    it('returns success when siteverify says success', async () => {
        const r = await verifyTurnstile('ts-response', 'secret', '1.2.3.4', okFetch);
        expect(r.success).toBe(true);
    });

    it('returns failure when siteverify rejects', async () => {
        const r = await verifyTurnstile('ts-response', 'secret', '1.2.3.4', failFetch);
        expect(r.success).toBe(false);
        expect(r.errorCodes).toContain('invalid-input-response');
    });

    it('fails closed (no throw) on a missing turnstile response or secret', async () => {
        expect((await verifyTurnstile(null, 'secret', null, okFetch)).success).toBe(false);
        expect((await verifyTurnstile('ts', undefined, null, okFetch)).success).toBe(false);
    });

    it('fails closed on a network error', async () => {
        const r = await verifyTurnstile('ts', 'secret', null, throwFetch);
        expect(r.success).toBe(false);
        expect(r.errorCodes).toContain('verify-failed');
    });
});
