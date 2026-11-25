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
              <button class="btn-secondary" @click="selectSite(site.id)">Configure</button>
            </div>
          </li>
        </ul>
      </div>

      <div v-if="selectedSiteId" class="card">
        <h2>Origin &amp; WAF Policy</h2>
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

        <hr class="divider" />
        <h3>WAF Mode (Coraza + OWASP CRS {{ wafForm.crs_version }})</h3>
        <form @submit.prevent="saveWaf" class="row-form">
          <select v-model="wafForm.mode">
            <option value="monitor">Monitor (Log Only)</option>
            <option value="block">Block</option>
            <option value="off">Off</option>
          </select>
          <input v-model.number="wafForm.max_inspect_body_bytes" type="number" min="1024" max="10485760" />
          <button type="submit" class="btn-primary">Update WAF</button>
        </form>

        <h3>Scoped Rule Exclusions</h3>
        <form @submit.prevent="addExclusion" class="row-form">
          <input v-model="exclusionForm.route_prefix" placeholder="/api/webhooks/mpesa" required />
          <input v-model="exclusionForm.rule_id" placeholder="Rule ID (e.g. 942100)" required />
          <button type="submit" class="btn-secondary">Add Exclusion</button>
        </form>
        <input v-model="exclusionForm.reason" placeholder="Reason for exclusion (audit required)" class="mt-sm" />
        <ul class="site-list">
          <li v-for="ex in exclusions" :key="ex.id" class="site-item">
            <span><code>{{ ex.route_prefix }}</code> — Rule <code>{{ ex.rule_id }}</code> ({{ ex.reason }})</span>
            <button class="btn-secondary" @click="removeExclusion(ex.id)">Remove</button>
          </li>
        </ul>
      </div>

      <div class="card">
        <h2>Recent Security Events</h2>
        <ul class="site-list">
          <li v-for="ev in securityEvents" :key="ev.id" class="site-item">
            <span>
              <span class="badge" :class="ev.action">{{ ev.action }}</span>
              <code>{{ ev.route }}</code> — Rule <code>{{ ev.rule_id }}</code> ({{ ev.reason_code }})
            </span>
            <span class="meta">{{ ev.correlation_id }}</span>
          </li>
        </ul>
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
const wafForm = ref({ mode: 'monitor', crs_version: '4.10.0', max_inspect_body_bytes: 131072 });
const exclusionForm = ref({ route_prefix: '/', rule_id: '', reason: '' });
const exclusions = ref([]);
const securityEvents = ref([]);

const api = createApiClient({ getToken: () => token.value });

async function loadSites() {
  if (!token.value) return;
  try {
    const [siteRes, evRes] = await Promise.all([api.listSites(), api.listSecurityEvents()]);
    sites.value = siteRes.sites || [];
    securityEvents.value = evRes.events || [];
  } catch (err) {
    error.value = err.message;
  }
}

async function selectSite(siteId) {
  selectedSiteId.value = siteId;
  error.value = '';
  try {
    const [waf, exRes] = await Promise.all([api.getWafPolicy(siteId), api.listWafExclusions(siteId)]);
    wafForm.value = {
      mode: waf.mode || 'monitor',
      crs_version: waf.crs_version || '4.10.0',
      max_inspect_body_bytes: waf.max_inspect_body_bytes || 131072
    };
    exclusions.value = exRes.exclusions || [];
  } catch (err) {
    error.value = err.message;
  }
}

async function saveWaf() {
  error.value = '';
  try {
    await api.upsertWafPolicy(selectedSiteId.value, wafForm.value);
    lockdownResult.value = `WAF updated to ${wafForm.value.mode} mode.`;
  } catch (err) {
    error.value = err.message;
  }
}

async function addExclusion() {
  error.value = '';
  try {
    await api.addWafExclusion(selectedSiteId.value, exclusionForm.value);
    exclusionForm.value = { route_prefix: '/', rule_id: '', reason: '' };
    const exRes = await api.listWafExclusions(selectedSiteId.value);
    exclusions.value = exRes.exclusions || [];
  } catch (err) {
    error.value = err.message;
  }
}

async function removeExclusion(exclusionId) {
  error.value = '';
  try {
    await api.deleteWafExclusion(selectedSiteId.value, exclusionId);
    exclusions.value = exclusions.value.filter((x) => x.id !== exclusionId);
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
.badge.block { background: #fee2e2; color: #991b1b; }
.badge.observe { background: #fef9c3; color: #854d0e; }
.divider { border: none; border-top: 1px solid #e2e8f0; margin: 1.25rem 0; }
.mt-sm { margin-top: 0.5rem; }
.meta { font-size: 0.82rem; color: #475569; margin-top: 0.25rem; }
.error { color: #b91c1c; font-size: 0.88rem; }
</style>
