import { describe, it, expect } from 'vitest';
import { mintUiToken, mintLegacyUnboundUiToken, networkOf, verifyUiToken, verifyTurnstile } from './uiToken';

const SECRET = 'test-hmac-secret-do-not-use-in-prod';
const TTL = 1800; // 30 min
const NOW = 1_700_000_000_000; // fixed epoch ms for determinism
const IP = '203.0.113.7';

describe('uiToken mint/verify', () => {
    it('mints a token that verifies as valid within its TTL', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, IP);
        const res = await verifyUiToken(tok, SECRET, NOW + 1000, IP);
        expect(res.valid).toBe(true);
        expect(res.payload?.v).toBe(2);
        expect(res.payload?.exp).toBe(Math.floor(NOW / 1000) + TTL);
    });

    it('rejects an expired token', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, IP);
        const res = await verifyUiToken(tok, SECRET, NOW + (TTL + 1) * 1000, IP);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('expired');
    });

    it('rejects a token signed with a different secret (forgery)', async () => {
        const tok = await mintUiToken('attacker-secret', NOW, TTL, IP);
        const res = await verifyUiToken(tok, SECRET, NOW + 1000, IP);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('bad_signature');
    });

    it('rejects a tampered payload (signature no longer matches)', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, IP);
        const [body, sig] = tok.split('.');
        // Flip a char in the body; the original signature won't match.
        const tampered = body.slice(0, -1) + (body.slice(-1) === 'A' ? 'B' : 'A') + '.' + sig;
        const res = await verifyUiToken(tampered, SECRET, NOW + 1000, IP);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('bad_signature');
    });

    it('treats malformed / empty / null tokens as untrusted, never throws', async () => {
        for (const bad of [null, undefined, '', 'no-dot', '.', 'a.', '.b']) {
            const res = await verifyUiToken(bad as string, SECRET, NOW, IP);
            expect(res.valid).toBe(false);
            expect(res.reason).toBe('malformed');
        }
    });

    it('reports no_secret when the server secret is unset (fail-safe, not crash)', async () => {
        const res = await verifyUiToken('whatever.sig', undefined, NOW, IP);
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('no_secret');
    });

    it('each mint is unique (random nonce) but all verify', async () => {
        const a = await mintUiToken(SECRET, NOW, TTL, IP);
        const b = await mintUiToken(SECRET, NOW, TTL, IP);
        expect(a).not.toBe(b);
        expect((await verifyUiToken(a, SECRET, NOW, IP)).valid).toBe(true);
        expect((await verifyUiToken(b, SECRET, NOW, IP)).valid).toBe(true);
    });
});

// oxjob #1691/#1692: one headless browser must not mint a token and share it across a proxy pool.
describe('uiToken is bound to the network that minted it', () => {
    it('refuses a token presented from another IPv4 address', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, IP);
        const res = await verifyUiToken(tok, SECRET, NOW + 1000, '198.51.100.9');
        expect(res.valid).toBe(false);
        expect(res.reason).toBe('wrong_network');
    });

    it('refuses a token from a neighbouring IPv4 address in the same /24', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, '203.0.113.7');
        expect((await verifyUiToken(tok, SECRET, NOW, '203.0.113.8')).reason).toBe('wrong_network');
    });

    it('accepts any address in the same IPv6 /64 (privacy addresses rotate inside it)', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, '2001:db8:abcd:12::1');
        expect((await verifyUiToken(tok, SECRET, NOW, '2001:0db8:abcd:0012:9f2e:1:2:3')).valid).toBe(true);
        expect((await verifyUiToken(tok, SECRET, NOW, '2001:db8:abcd:13::1')).reason).toBe('wrong_network');
    });

    it('refuses everything when the request has no IP (no network to match)', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, IP);
        expect((await verifyUiToken(tok, SECRET, NOW, null)).reason).toBe('wrong_network');
        const unbound = await mintUiToken(SECRET, NOW, TTL, null);
        expect((await verifyUiToken(unbound, SECRET, NOW, IP)).reason).toBe('wrong_network');
    });

    it('keeps the IP out of the token: the payload holds only a keyed hash', async () => {
        const tok = await mintUiToken(SECRET, NOW, TTL, IP);
        expect(atob(tok.split('.')[0].replace(/-/g, '+').replace(/_/g, '/'))).not.toContain('203.0.113');
    });

    it('still accepts legacy unbound v1 tokens from any IP until they expire (deploy cutover)', async () => {
        const v1 = await mintLegacyUnboundUiToken(SECRET, NOW, TTL);
        expect((await verifyUiToken(v1, SECRET, NOW + 1000, '198.51.100.9')).valid).toBe(true);
        expect((await verifyUiToken(v1, SECRET, NOW + (TTL + 1) * 1000, IP)).reason).toBe('expired');
    });
});

describe('networkOf', () => {
    it('keeps IPv4 whole and IPv6 to its /64, normalized', () => {
        expect(networkOf('203.0.113.7')).toBe('203.0.113.7');
        expect(networkOf('2001:0DB8:ABCD:0012:0000:0000:0000:0001')).toBe('2001:db8:abcd:12::/64');
        expect(networkOf('2001:db8:abcd:12::1')).toBe('2001:db8:abcd:12::/64');
        expect(networkOf('2001:db8::1')).toBe('2001:db8:0:0::/64');
        expect(networkOf('::ffff:203.0.113.7')).toBe('203.0.113.7');
    });

    it('returns null for nothing or garbage, never throws', () => {
        for (const bad of [null, undefined, '', 'unknown', '1.2.3', '1:2:3:4:5:6:7:8:9', '1::2::3', 'zz::1', '1:2:3:4:5:6:7::8:9']) {
            expect(networkOf(bad as string)).toBeNull();
        }
    });
});

describe('verifyTurnstile', () => {
    const okFetch = (async () =>
        new Response(JSON.stringify({ success: true, hostname: 'openalex.org' }), { status: 200 })) as unknown as typeof fetch;
    const offSiteFetch = (async () =>
        new Response(JSON.stringify({ success: true, hostname: 'scraper.example' }), { status: 200 })) as unknown as typeof fetch;
    const noHostFetch = (async () =>
        new Response(JSON.stringify({ success: true }), { status: 200 })) as unknown as typeof fetch;

    it('refuses a solve made on another hostname, or one with no hostname (oxjob #1691)', async () => {
        expect(await verifyTurnstile('ts', 'secret', null, offSiteFetch)).toEqual({ success: false, errorCodes: ['hostname-mismatch'] });
        expect((await verifyTurnstile('ts', 'secret', null, noHostFetch)).success).toBe(false);
        const www = (async () => new Response(JSON.stringify({ success: true, hostname: 'www.openalex.org' }))) as unknown as typeof fetch;
        expect((await verifyTurnstile('ts', 'secret', null, www)).success).toBe(true);
    });
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
