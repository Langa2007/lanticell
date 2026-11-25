import test from 'node:test';
import assert from 'node:assert/strict';
import { createApiClient } from './client.js';

test('createApiClient attaches bearer token and parses JSON', async () => {
  let seenAuth = '';
  const mockFetch = async (url, opts) => {
    seenAuth = opts.headers.Authorization;
    return {
      ok: true,
      status: 200,
      json: async () => ({ sites: [{ id: 's1', domain: 'api.example.co.ke' }] })
    };
  };

  const api = createApiClient({
    baseUrl: 'http://localhost:8080',
    fetchImpl: mockFetch,
    getToken: () => 'jwt-123'
  });

  const data = await api.listSites();
  assert.equal(seenAuth, 'Bearer jwt-123');
  assert.equal(data.sites.length, 1);
  assert.equal(data.sites[0].domain, 'api.example.co.ke');
});

test('createApiClient throws API error message on non-OK status', async () => {
  const mockFetch = async () => ({
    ok: false,
    status: 400,
    json: async () => ({ error: 'invalid domain format' })
  });

  const api = createApiClient({ baseUrl: 'http://localhost:8080', fetchImpl: mockFetch });
  await assert.rejects(() => api.createSite({ domain: 'bad' }), /invalid domain format/);
});

test('createApiClient calls WAF policy and exclusion endpoints', async () => {
  const calls = [];
  const mockFetch = async (url, opts) => {
    calls.push({ url, method: opts.method });
    return { ok: true, status: 200, json: async () => ({ status: 'ok' }) };
  };

  const api = createApiClient({ baseUrl: 'http://localhost:8080', fetchImpl: mockFetch });
  await api.upsertWafPolicy('s1', { mode: 'block' });
  await api.addWafExclusion('s1', { route_prefix: '/api/webhooks/mpesa', rule_id: '942100', reason: 'test' });
  await api.listSecurityEvents();

  assert.deepEqual(calls, [
    { url: 'http://localhost:8080/api/v1/sites/s1/waf', method: 'PUT' },
    { url: 'http://localhost:8080/api/v1/sites/s1/waf/exclusions', method: 'POST' },
    { url: 'http://localhost:8080/api/v1/security-events', method: 'GET' }
  ]);
});
