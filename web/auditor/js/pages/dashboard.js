// VAOL Auditor — Dashboard Page

import * as state from '../state.js';
import * as api from '../api.js';
import { connectToServer, startHealthPoll } from '../app.js';
import { formatNumber, formatTimestamp, truncHash } from '../utils.js';

let unsubs = [];

export function renderDashboard(container) {
  const serverUrl = state.get('serverUrl') || 'http://localhost:8080';
  const tenantId = state.get('tenantId') || '';
  const connected = state.get('connected');
  const health = state.get('health');
  const checkpoint = state.get('checkpoint');

  container.innerHTML = `
    <div class="connect-form">
      <input type="text" id="server-url" placeholder="VAOL Server URL" value="${serverUrl}">
      <input type="text" id="tenant-id" placeholder="Tenant ID (optional)" value="${tenantId}" style="max-width:250px">
      <button id="connect-btn">${connected ? 'Reconnect' : 'Connect'}</button>
    </div>

    <div class="cards" id="stat-cards">
      <div class="card">
        <div class="card-label">Status</div>
        <div class="card-value" id="dash-status" style="color: ${connected ? 'var(--green)' : 'var(--red)'}">
          ${connected ? 'Online' : 'Offline'}
        </div>
        <div class="card-sub" id="dash-version">${health?.version ? 'v' + health.version : '--'}</div>
      </div>
      <div class="card">
        <div class="card-label">Total Records</div>
        <div class="card-value" id="dash-records">${formatNumber(health?.record_count)}</div>
      </div>
      <div class="card">
        <div class="card-label">Tree Size</div>
        <div class="card-value" id="dash-tree">${formatNumber(health?.tree_size)}</div>
      </div>
      <div class="card">
        <div class="card-label">Checkpoint Root</div>
        <div class="card-value" id="dash-root" style="font-size: 0.9rem">${truncHash(checkpoint?.root_hash, 12)}</div>
        <div class="card-sub" id="dash-cp-time">${formatTimestamp(checkpoint?.timestamp)}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Quick Actions</div>
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap">
        <a href="#/records" class="btn btn-secondary" style="text-decoration:none">Browse Records</a>
        <a href="#/verify" class="btn btn-secondary" style="text-decoration:none">Verify Envelope</a>
        <a href="#/bundles" class="btn btn-secondary" style="text-decoration:none">Export Bundle</a>
        <a href="#/merkle" class="btn btn-secondary" style="text-decoration:none">Inspect Merkle Proofs</a>
        <a href="#/chain" class="btn btn-secondary" style="text-decoration:none">View Hash Chain</a>
      </div>
    </div>
  `;

  // Connect button
  document.getElementById('connect-btn').addEventListener('click', async () => {
    const btn = document.getElementById('connect-btn');
    const url = document.getElementById('server-url').value.trim();
    const tenant = document.getElementById('tenant-id').value.trim();
    if (!url) return;

    btn.disabled = true;
    btn.textContent = 'Connecting...';
    await connectToServer(url, tenant);
    btn.disabled = false;
    btn.textContent = state.get('connected') ? 'Reconnect' : 'Connect';
  });

  // Subscribe to state changes to update cards
  unsubs.push(state.subscribe('health', updateCards));
  unsubs.push(state.subscribe('checkpoint', updateCards));
  unsubs.push(state.subscribe('connected', updateCards));

  // If already connected, start polling
  if (connected) startHealthPoll();
}

function updateCards() {
  const health = state.get('health');
  const checkpoint = state.get('checkpoint');
  const connected = state.get('connected');

  const statusEl = document.getElementById('dash-status');
  const versionEl = document.getElementById('dash-version');
  const recordsEl = document.getElementById('dash-records');
  const treeEl = document.getElementById('dash-tree');
  const rootEl = document.getElementById('dash-root');
  const cpTimeEl = document.getElementById('dash-cp-time');

  if (statusEl) {
    statusEl.textContent = connected ? 'Online' : 'Offline';
    statusEl.style.color = connected ? 'var(--green)' : 'var(--red)';
  }
  if (versionEl) versionEl.textContent = health?.version ? 'v' + health.version : '--';
  if (recordsEl) recordsEl.textContent = formatNumber(health?.record_count);
  if (treeEl) treeEl.textContent = formatNumber(health?.tree_size);
  if (rootEl) rootEl.textContent = truncHash(checkpoint?.root_hash, 12);
  if (cpTimeEl) cpTimeEl.textContent = formatTimestamp(checkpoint?.timestamp);
}

export function destroyDashboard() {
  unsubs.forEach(fn => fn());
  unsubs = [];
}
