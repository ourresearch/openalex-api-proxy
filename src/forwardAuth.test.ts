import { describe, it, expect } from 'vitest';
import { authorizationToForward } from './forwardAuth';

describe('authorizationToForward (#283, oxjob #1505)', () => {
    it('passes an inbound Authorization header through unchanged', () => {
        expect(authorizationToForward('Bearer abc', 'abc', true)).toBe('Bearer abc');
    });

    it('forwards a validated ?api_key= as a Bearer header', () => {
        expect(authorizationToForward(null, 'abc', true)).toBe('Bearer abc');
    });

    it('never forwards a key the proxy did not validate', () => {
        // changefiles browsing lets "YOUR_API_KEY" through as anonymous
        expect(authorizationToForward(null, 'YOUR_API_KEY', false)).toBeNull();
    });

    it('anonymous stays anonymous', () => {
        expect(authorizationToForward(null, null, false)).toBeNull();
    });
});
