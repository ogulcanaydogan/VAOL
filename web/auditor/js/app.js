// VAOL Auditor — Application Entry Point

import * as router from './router.js';
import * as state from './state.js';
import * as api from './api.js';
import { renderDashboard, destroyDashboard } from './pages/dashboard.js';
import { renderRecords, destroyRecords } from './pages/records.js';
import { renderRecordDetail, destroyRecordDetail } from './pages/record-detail.js';
import { renderVerify, destroyVerify } from './pages/verify.js';
import { renderMerkle, destroyMerkle } from './pages/merkle.js';
import { renderBundles, destroyBundles } from './pages/bundles.js';
import { renderChain, destroyChain } from './pages/chain.js';
import { showToast } from './components/toast.js';

// Register routes
router.register('/dashboard', renderDashboard, destroyDashboard);
router.register('/records', renderRecords, destroyRecords);
router.register('/records/:id', renderRecordDetail, destroyRecordDetail);
router.register('/verify', renderVerify, destroyVerify);
router.register('/merkle', renderMerkle, destroyMerkle);
router.register('/bundles', renderBundles, destroyBundles);
router.register('/chain', renderChain, destroyChain);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('app-content');
  router.init(container);
  initStatusBar();
});

// Status bar — connection indicator
function initStatusBar() {
  const el = document.getElementById('connection-status');
  const treeEl = document.getElementById('tree-status');
  const recordEl = document.getElementById('record-count');

  state.subscribe('connected', (connected) => {
    el.innerHTML = connected
      ? '<span class="dot dot-green"></span>Connected'
      : '<span class="dot dot-red"></span>Disconnected';
  });

  state.subscribe('health', (h) => {
    if (h) {
      recordEl.textContent = `Records: ${h.record_count ?? '--'}`;
    }
  });

  state.subscribe('checkpoint', (cp) => {
    if (cp) {
      treeEl.textContent = `Tree: ${cp.tree_size ?? '--'}`;
    }
  });
}

// Health polling
let pollId = null;

export function startHealthPoll() {
  stopHealthPoll();
  poll();
  pollId = setInterval(poll, 10000);
}

export function stopHealthPoll() {
  if (pollId) {
    clearInterval(pollId);
    pollId = null;
  }
}

async function poll() {
  if (!state.get('serverUrl')) return;
  try {
    const h = await api.health();
    state.set('health', h);
    state.set('connected', true);

    const cp = await api.getCheckpoint();
    state.set('checkpoint', cp);
  } catch {
    state.set('connected', false);
  }
}

// Connect to server (called from dashboard)
export async function connectToServer(url, tenantId) {
  url = url.replace(/\/$/, '');
  state.set('serverUrl', url);
  state.set('tenantId', tenantId);

  try {
    const h = await api.health();
    state.set('health', h);
    state.set('connected', true);

    try {
      const cp = await api.getCheckpoint();
      state.set('checkpoint', cp);
    } catch { /* checkpoint may not exist yet */ }

    startHealthPoll();
    showToast(`Connected to ${url}`, 'success');
    return true;
  } catch (err) {
    state.set('connected', false);
    showToast(`Connection failed: ${err.message}`, 'error');
    return false;
  }
}
