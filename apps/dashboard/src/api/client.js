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
    listAuditLogs: () => request('/api/v1/audit-logs')
  };
}
