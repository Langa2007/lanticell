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
