<template>
  <main class="container">
    <header class="topbar">
      <div>
        <h1>Lanticell</h1>
        <p class="subtitle">Web, API &amp; Bot Security Console</p>
      </div>
      <button v-if="token" class="btn-secondary" @click="logout">Sign out</button>
    </header>

    <section v-if="!token" class="card auth-card">
      <h2>{{ mode === 'login' ? 'Sign in' : 'Create tenant account' }}</h2>
      <form @submit.prevent="submitAuth">
        <label v-if="mode === 'register'">
          Organization / Tenant
          <input v-model="authForm.tenant_name" required placeholder="Nairobi Pay Ltd" />
        </label>
        <label>
          Email
          <input v-model="authForm.email" type="email" required placeholder="security@company.co.ke" />
        </label>
        <label>
          Password
          <input v-model="authForm.password" type="password" required minlength="8" />
        </label>
        <p v-if="error" class="error">{{ error }}</p>
        <button type="submit" class="btn-primary">
          {{ mode === 'login' ? 'Sign in' : 'Create account' }}
        </button>
      </form>
      <button class="btn-link" @click="mode = mode === 'login' ? 'register' : 'login'">
        {{ mode === 'login' ? 'Need a tenant account? Register' : 'Already have an account? Sign in' }}
      </button>
    </section>

    <section v-else class="grid">
      <div class="card">
        <h2>Onboard Site</h2>
        <form @submit.prevent="addSite" class="row-form">
          <input v-model="newDomain" required placeholder="api.example.co.ke" />
          <select v-model="newTlsMode">
            <option value="acme">ACME TLS</option>
            <option value="dev_self_signed">Dev Self-Signed</option>
          </select>
          <button type="submit" class="btn-primary">Add Site</button>
        </form>
        <p v-if="error" class="error">{{ error }}</p>

        <ul class="site-list">
          <li v-for="site in sites" :key="site.id" class="site-item">
            <div>
              <strong>{{ site.domain }}</strong>
              <span class="badge" :class="site.status">{{ site.status }}</span>
              <div class="meta">TXT: <code>_lanticell-verify.{{ site.domain }}</code> → <code>{{ site.txt_verification_token }}</code></div>
            </div>
            <div class="actions">
              <button v-if="site.status === 'pending_verification'" class="btn-secondary" @click="verifySite(site.id)">
                Verify DNS
              </button>
              <button class="btn-secondary" @click="selectedSiteId = site.id">Configure Origin</button>
            </div>
          </li>
        </ul>
      </div>

      <div v-if="selectedSiteId" class="card">
        <h2>Origin Configuration</h2>
        <form @submit.prevent="saveOrigin">
          <label>
            Upstream URL
            <input v-model="originForm.upstream_url" required placeholder="https://origin.example.co.ke:8443" />
          </label>
          <label>
            Rate limit (req/s)
            <input v-model.number="originForm.rate_limit_rps" type="number" min="1" max="100000" />
          </label>
          <button type="submit" class="btn-primary">Save Origin</button>
          <button type="button" class="btn-secondary" @click="checkLockdown">Verify Origin Lockdown</button>
        </form>
        <p v-if="lockdownResult" class="meta">{{ lockdownResult }}</p>
      </div>
    </section>
  </main>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { createApiClient } from './api/client.js';

const token = ref(localStorage.getItem('lanticell_token') || '');
const mode = ref('login');
const error = ref('');
const sites = ref([]);
const newDomain = ref('');
const newTlsMode = ref('acme');
const selectedSiteId = ref('');
const lockdownResult = ref('');

const authForm = ref({ tenant_name: '', email: '', password: '' });
const originForm = ref({ upstream_url: '', rate_limit_rps: 50 });

const api = createApiClient({ getToken: () => token.value });

async function loadSites() {
  if (!token.value) return;
  try {
    const res = await api.listSites();
    sites.value = res.sites || [];
  } catch (err) {
    error.value = err.message;
  }
}

async function submitAuth() {
  error.value = '';
  try {
    const res =
      mode.value === 'login'
        ? await api.login({ email: authForm.value.email, password: authForm.value.password })
        : await api.register(authForm.value);
    token.value = res.token;
    localStorage.setItem('lanticell_token', res.token);
    await loadSites();
  } catch (err) {
    error.value = err.message;
  }
}

async function addSite() {
  error.value = '';
  try {
    await api.createSite({ domain: newDomain.value, tls_mode: newTlsMode.value });
    newDomain.value = '';
    await loadSites();
  } catch (err) {
    error.value = err.message;
  }
}

async function verifySite(siteId) {
  error.value = '';
  try {
    await api.verifyDns(siteId);
    await loadSites();
  } catch (err) {
    error.value = err.message;
  }
}

async function saveOrigin() {
  error.value = '';
  try {
    await api.upsertOrigin(selectedSiteId.value, originForm.value);
    lockdownResult.value = 'Origin saved and secret encrypted.';
  } catch (err) {
    error.value = err.message;
  }
}

async function checkLockdown() {
  error.value = '';
  try {
    const res = await api.verifyLockdown(selectedSiteId.value);
    lockdownResult.value = res.locked_down
      ? `Locked down: ${res.detail}`
      : `Warning: origin responded (${res.status_code}) without Lanticell secret.`;
  } catch (err) {
    error.value = err.message;
  }
}

function logout() {
  token.value = '';
  localStorage.removeItem('lanticell_token');
  sites.value = [];
}

onMounted(loadSites);
</script>

<style scoped>
.container { max-width: 960px; margin: 2rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; color: #0f172a; }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
.subtitle { margin: 0.25rem 0 0; color: #475569; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 1.25rem; margin-bottom: 1rem; }
.auth-card { max-width: 420px; margin: 2rem auto; }
label { display: block; margin-bottom: 0.75rem; font-size: 0.9rem; }
input, select { width: 100%; padding: 0.5rem; margin-top: 0.25rem; border: 1px solid #cbd5e1; border-radius: 6px; box-sizing: border-box; }
.row-form { display: grid; grid-template-columns: 1fr 160px auto; gap: 0.5rem; align-items: center; }
.btn-primary { background: #0f766e; color: #fff; border: none; padding: 0.55rem 1rem; border-radius: 6px; cursor: pointer; }
.btn-secondary { background: #f1f5f9; color: #0f172a; border: 1px solid #cbd5e1; padding: 0.5rem 0.9rem; border-radius: 6px; cursor: pointer; margin-left: 0.4rem; }
.btn-link { background: none; border: none; color: #0f766e; cursor: pointer; margin-top: 0.75rem; padding: 0; }
.site-list { list-style: none; padding: 0; margin: 1rem 0 0; }
.site-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-top: 1px solid #e2e8f0; }
.badge { margin-left: 0.5rem; padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.75rem; background: #e2e8f0; }
.badge.active { background: #dcfce7; color: #166534; }
.meta { font-size: 0.82rem; color: #475569; margin-top: 0.25rem; }
.error { color: #b91c1c; font-size: 0.88rem; }
</style>
