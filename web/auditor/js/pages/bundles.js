// VAOL Auditor — Audit Bundle Manager Page

import * as api from '../api.js';
import * as state from '../state.js';
import { showToast } from '../components/toast.js';
import { escapeHtml, formatTimestamp, formatNumber, truncHash } from '../utils.js';

export function renderBundles(container) {
  container.innerHTML = `
    <div class="section-title">Audit Bundles</div>

    <div class="two-col">
      <div>
        <div class="panel">
          <div class="panel-title">Export Bundle</div>
          <div class="filter-bar" style="margin-bottom:0;background:transparent;border:none;padding:0">
            <div class="filter-group">
              <label>Tenant ID</label>
              <input type="text" id="export-tenant" placeholder="acme-corp" value="${escapeHtml(state.get('tenantId') || '')}">
            </div>
            <div class="filter-group">
              <label>After</label>
              <input type="datetime-local" id="export-after">
            </div>
            <div class="filter-group">
              <label>Before</label>
              <input type="datetime-local" id="export-before">
            </div>
            <div class="filter-group">
              <label>Limit</label>
              <input type="number" id="export-limit" value="1000" style="width:100px">
            </div>
          </div>
          <button id="export-btn" style="margin-top:var(--spacing-md)">Export Bundle</button>
        </div>

        <div id="export-result" class="hidden panel" style="margin-top:var(--spacing-md)"></div>
      </div>

      <div>
        <div class="panel">
          <div class="panel-title">Upload & Verify Bundle</div>
          <div class="upload-area" id="bundle-upload-zone">
            <p style="font-size:1.5rem">&#128230;</p>
            <p>Drag & drop an audit bundle JSON file</p>
            <input type="file" id="bundle-file" accept=".json" class="hidden">
          </div>

          <div style="margin-top:var(--spacing-md)">
            <label>Verification Profile</label>
            <div class="radio-group" style="margin-top:var(--spacing-xs)">
              <label><input type="radio" name="bundle-profile" value="basic" checked><span>Basic</span></label>
              <label><input type="radio" name="bundle-profile" value="strict"><span>Strict</span></label>
              <label><input type="radio" name="bundle-profile" value="fips"><span>FIPS</span></label>
            </div>
          </div>

          <button id="bundle-verify-btn" style="margin-top:var(--spacing-md)" disabled>Verify Bundle</button>
        </div>

        <div id="bundle-verify-result" class="hidden"></div>
      </div>
    </div>
  `;

  // Export
  document.getElementById('export-btn').addEventListener('click', handleExport);

  // Upload
  const zone = document.getElementById('bundle-upload-zone');
  const fileInput = document.getElementById('bundle-file');
  let uploadedBundle = null;

  zone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    if (e.target.files[0]) loadBundle(e.target.files[0]);
    e.target.value = '';
  });

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) loadBundle(e.dataTransfer.files[0]);
  });

  async function loadBundle(file) {
    try {
      const text = await file.text();
      uploadedBundle = JSON.parse(text);
      zone.querySelector('p:first-child').textContent = '&#9989;';
      zone.querySelector('p:last-of-type').textContent = `Loaded: ${file.name}`;
      document.getElementById('bundle-verify-btn').disabled = false;
    } catch (err) {
      showToast(`Failed to parse: ${err.message}`, 'error');
    }
  }

  // Verify
  document.getElementById('bundle-verify-btn').addEventListener('click', async () => {
    if (!uploadedBundle) return;
    if (!state.get('serverUrl')) return showToast('Connect to a server first', 'error');

    const profile = document.querySelector('input[name="bundle-profile"]:checked').value;
    const btn = document.getElementById('bundle-verify-btn');
    btn.disabled = true;
    btn.textContent = 'Verifying...';

    try {
      const result = await api.verifyBundle(uploadedBundle, profile);
      renderBundleVerifyResult(result);
    } catch (err) {
      showToast(`Verification failed: ${err.message}`, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Verify Bundle';
    }
  });
}

async function handleExport() {
  if (!state.get('serverUrl')) return showToast('Connect to a server first', 'error');

  const btn = document.getElementById('export-btn');
  btn.disabled = true;
  btn.textContent = 'Exporting...';

  const tenant = document.getElementById('export-tenant').value.trim();
  const after = document.getElementById('export-after').value
    ? new Date(document.getElementById('export-after').value).toISOString() : undefined;
  const before = document.getElementById('export-before').value
    ? new Date(document.getElementById('export-before').value).toISOString() : undefined;
  const limit = parseInt(document.getElementById('export-limit').value) || 1000;

  try {
    const bundle = await api.exportBundle({ tenant_id: tenant, after, before, limit });

    // Display summary
    const resultEl = document.getElementById('export-result');
    resultEl.classList.remove('hidden');

    const meta = bundle.metadata || {};
    const manifest = bundle.manifest || {};

    resultEl.innerHTML = `
      <div class="panel-title">Export Complete</div>
      <dl class="detail-grid">
        <dt>Version</dt><dd>${bundle.version || '--'}</dd>
        <dt>Exported At</dt><dd>${formatTimestamp(bundle.exported_at)}</dd>
        <dt>Total Records</dt><dd>${formatNumber(meta.total_records)}</dd>
        <dt>Seq Range</dt><dd>${meta.first_sequence ?? '--'} → ${meta.last_sequence ?? '--'}</dd>
        <dt>Tree Size</dt><dd>${formatNumber(meta.merkle_tree_size)}</dd>
        <dt>Root Hash</dt><dd class="hash">${escapeHtml(meta.merkle_root_hash || '--')}</dd>
        <dt>Checkpoints</dt><dd>${(bundle.checkpoints || []).length}</dd>
        <dt>Manifest Hash</dt><dd class="hash">${truncHash(manifest.evidence_hash)}</dd>
      </dl>
      <button id="download-bundle" class="btn-sm" style="margin-top:var(--spacing-md)">Download JSON</button>
    `;

    // Download
    document.getElementById('download-bundle').addEventListener('click', () => {
      const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vaol-bundle-${tenant || 'all'}-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Bundle downloaded', 'success');
    });
  } catch (err) {
    showToast(`Export failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Export Bundle';
  }
}

function renderBundleVerifyResult(result) {
  const el = document.getElementById('bundle-verify-result');
  el.classList.remove('hidden');

  const allValid = result.invalid_records === 0 && result.chain_intact && result.merkle_valid;
  const boolChecks = [
    ['Chain Intact', result.chain_intact],
    ['Merkle Valid', result.merkle_valid],
    ['Signatures Valid', result.signatures_valid],
    ['Schema Valid', result.schema_valid],
    ['Checkpoint Valid', result.checkpoint_valid],
    ['Manifest Valid', result.manifest_valid],
  ];

  el.innerHTML = `
    <div class="verdict ${allValid ? 'verdict-pass' : 'verdict-fail'}" style="margin-top:var(--spacing-md)">
      ${allValid ? '&#10003; PASSED' : '&#10007; FAILED'}
    </div>
    <div class="panel" style="margin-top:var(--spacing-sm)">
      <div style="display:flex;gap:var(--spacing-lg);margin-bottom:var(--spacing-md);font-size:var(--font-size-sm)">
        <span>Total: <strong>${result.total_records ?? '--'}</strong></span>
        <span style="color:var(--green)">Valid: <strong>${result.valid_records ?? '--'}</strong></span>
        <span style="color:var(--red)">Invalid: <strong>${result.invalid_records ?? '--'}</strong></span>
      </div>
      <ul class="checks">
        ${boolChecks.map(([name, passed]) => `
          <li>
            <span class="check-icon" style="color:${passed ? 'var(--green)' : 'var(--red)'}">${passed ? '&#10003;' : '&#10007;'}</span>
            <span class="check-name">${escapeHtml(name)}</span>
          </li>
        `).join('')}
      </ul>
    </div>
  `;
}

export function destroyBundles() {}
