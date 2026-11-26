const DEFAULT_BASE =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
  'http://localhost:8080';

export function createApiClient({ baseUrl = DEFAULT_BASE, fetchImpl = fetch, getToken = () => '' } = {}) {
  async function request(path, { method = 'GET', body } = {}) {
    const headers = { 'Content-Type': 'application/json' };
    const token = getToken();
    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }
    const res = await fetchImpl(`${baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  }

  return {
    register: (payload) => request('/api/v1/auth/register', { method: 'POST', body: payload }),
    login: (payload) => request('/api/v1/auth/login', { method: 'POST', body: payload }),
    listSites: () => request('/api/v1/sites'),
    createSite: (payload) => request('/api/v1/sites', { method: 'POST', body: payload }),
    verifyDns: (siteId) => request(`/api/v1/sites/${siteId}/verify-dns`, { method: 'POST' }),
    upsertOrigin: (siteId, payload) =>
      request(`/api/v1/sites/${siteId}/origin`, { method: 'PUT', body: payload }),
    verifyLockdown: (siteId) => request(`/api/v1/sites/${siteId}/verify-lockdown`, { method: 'POST' }),
    getWafPolicy: (siteId) => request(`/api/v1/sites/${siteId}/waf`),
    upsertWafPolicy: (siteId, payload) =>
      request(`/api/v1/sites/${siteId}/waf`, { method: 'PUT', body: payload }),
    getBotPolicy: (siteId) => request(`/api/v1/sites/${siteId}/bot-policy`),
    upsertBotPolicy: (siteId, payload) =>
      request(`/api/v1/sites/${siteId}/bot-policy`, { method: 'PUT', body: payload }),
    listRoutePolicies: (siteId) => request(`/api/v1/sites/${siteId}/route-policies`),
    addRoutePolicy: (siteId, payload) =>
      request(`/api/v1/sites/${siteId}/route-policies`, { method: 'POST', body: payload }),
    deleteRoutePolicy: (siteId, policyId) =>
      request(`/api/v1/sites/${siteId}/route-policies/${policyId}`, { method: 'DELETE' }),
    listApiSchemas: (siteId) => request(`/api/v1/sites/${siteId}/api-schemas`),
    importApiSchema: (siteId, openapiJson) =>
      request(`/api/v1/sites/${siteId}/api-schemas`, { method: 'POST', body: { openapi: openapiJson } }),
    rollbackApiSchema: (siteId, version) =>
      request(`/api/v1/sites/${siteId}/api-schemas/${version}/rollback`, { method: 'POST' }),
    listApiInventory: (siteId) => request(`/api/v1/sites/${siteId}/api-inventory`),
    listWafExclusions: (siteId) => request(`/api/v1/sites/${siteId}/waf/exclusions`),
    addWafExclusion: (siteId, payload) =>
      request(`/api/v1/sites/${siteId}/waf/exclusions`, { method: 'POST', body: payload }),
    deleteWafExclusion: (siteId, exclusionId) =>
      request(`/api/v1/sites/${siteId}/waf/exclusions/${exclusionId}`, { method: 'DELETE' }),
    listSecurityEvents: () => request('/api/v1/security-events'),
    listAuditLogs: () => request('/api/v1/audit-logs')
  };
}
