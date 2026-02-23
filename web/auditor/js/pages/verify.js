// VAOL Auditor — Verification Page

import * as api from '../api.js';
import * as state from '../state.js';
import { showToast } from '../components/toast.js';
import { escapeHtml } from '../utils.js';

export function renderVerify(container) {
  container.innerHTML = `
    <div class="section-title">Verify</div>

    <div class="panel" style="margin-bottom:var(--spacing-xl)">
      <div class="panel-title">Upload Envelope or Bundle</div>
      <div class="upload-area" id="upload-zone">
        <p style="font-size:1.5rem">&#128196;</p>
        <p>Drag & drop a JSON file here, or click to browse</p>
        <p style="font-size:var(--font-size-xs);margin-top:0.5rem;color:var(--text-muted)">
          Auto-detects: DSSE envelope (has signatures) or audit bundle (has records)
        </p>
        <input type="file" id="verify-file" accept=".json" class="hidden">
      </div>

      <div style="margin-top:var(--spacing-lg)">
        <label style="margin-bottom:var(--spacing-sm)">Verification Profile</label>
        <div class="radio-group">
          <label>
            <input type="radio" name="profile" value="basic" checked>
            <span>Basic</span>
          </label>
          <label>
            <input type="radio" name="profile" value="strict">
            <span>Strict</span>
          </label>
          <label>
            <input type="radio" name="profile" value="fips">
            <span>FIPS</span>
          </label>
        </div>
        <div class="profile-desc" id="profile-desc">Signature, schema, record hash checks</div>
      </div>

      <button id="verify-btn" style="margin-top:var(--spacing-md)" disabled>Verify</button>
    </div>

    <div id="verify-results" class="hidden"></div>
  `;

  const zone = document.getElementById('upload-zone');
  const fileInput = document.getElementById('verify-file');
  const verifyBtn = document.getElementById('verify-btn');
  let uploadedData = null;
  let uploadedType = null; // 'envelope' or 'bundle'

  // Profile descriptions
  const profileDescs = {
    basic: 'Signature, schema, record hash checks',
    strict: 'All basic + policy fields, Merkle inclusion, all-signatures verification',
    fips: 'All strict + rejects Ed25519 (requires ECDSA P-256 or better)',
  };

  document.querySelectorAll('input[name="profile"]').forEach(radio => {
    radio.addEventListener('change', () => {
      document.getElementById('profile-desc').textContent = profileDescs[radio.value] || '';
    });
  });

  // File upload via click
  zone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    if (e.target.files[0]) handleFile(e.target.files[0]);
    e.target.value = '';
  });

  // Drag and drop
  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('dragover');
    if (e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
  });

  async function handleFile(file) {
    try {
      const text = await file.text();
      const json = JSON.parse(text);

      // Auto-detect type
      if (json.payloadType && json.signatures) {
        uploadedType = 'envelope';
        uploadedData = json;
        zone.querySelector('p:first-child').textContent = '&#9989;';
        zone.querySelector('p:nth-child(2)').textContent = `Loaded: DSSE Envelope (${file.name})`;
      } else if (json.records || json.version) {
        uploadedType = 'bundle';
        uploadedData = json;
        zone.querySelector('p:first-child').textContent = '&#9989;';
        zone.querySelector('p:nth-child(2)').textContent = `Loaded: Audit Bundle (${file.name})`;
      } else {
        showToast('Unrecognized JSON format', 'error');
        return;
      }

      verifyBtn.disabled = false;
    } catch (err) {
      showToast(`Failed to parse file: ${err.message}`, 'error');
    }
  }

  // Verify button
  verifyBtn.addEventListener('click', async () => {
    if (!uploadedData) return;
    if (!state.get('serverUrl')) {
      showToast('Connect to a server first', 'error');
      return;
    }

    const profile = document.querySelector('input[name="profile"]:checked').value;
    verifyBtn.disabled = true;
    verifyBtn.textContent = 'Verifying...';

    try {
      let result;
      if (uploadedType === 'envelope') {
        result = await api.verifyEnvelope(uploadedData, profile);
        renderEnvelopeResult(result);
      } else {
        result = await api.verifyBundle(uploadedData, profile);
        renderBundleResult(result);
      }
    } catch (err) {
      showToast(`Verification failed: ${err.message}`, 'error');
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.textContent = 'Verify';
    }
  });
}

function renderEnvelopeResult(result) {
  const el = document.getElementById('verify-results');
  el.classList.remove('hidden');

  const valid = result.valid;
  const checks = result.checks || [];

  el.innerHTML = `
    <div class="verdict ${valid ? 'verdict-pass' : 'verdict-fail'}">
      ${valid ? '&#10003; VERIFICATION PASSED' : '&#10007; VERIFICATION FAILED'}
    </div>

    <div class="panel">
      <div class="panel-title">Check Results</div>
      <ul class="checks">
        ${checks.map(c => `
          <li>
            <span class="check-icon" style="color:${c.passed ? 'var(--green)' : 'var(--red)'}">
              ${c.passed ? '&#10003;' : '&#10007;'}
            </span>
            <span class="check-name">${escapeHtml(c.name)}</span>
            <span class="check-details">${escapeHtml(c.details || c.error || '')}</span>
          </li>
        `).join('')}
      </ul>
      ${result.revocation_policy ? `
        <div style="margin-top:var(--spacing-md);padding-top:var(--spacing-md);border-top:1px solid var(--border);font-size:var(--font-size-xs);color:var(--text-muted)">
          Revocation Policy: ${escapeHtml(result.revocation_policy.source || '--')}
          | Rules: ${result.revocation_policy.rule_count ?? '--'}
        </div>
      ` : ''}
    </div>
  `;
}

function renderBundleResult(result) {
  const el = document.getElementById('verify-results');
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
    <div class="verdict ${allValid ? 'verdict-pass' : 'verdict-fail'}">
      ${allValid ? '&#10003; BUNDLE VERIFICATION PASSED' : '&#10007; BUNDLE VERIFICATION FAILED'}
    </div>

    <div class="bundle-summary">
      <div class="bundle-stat">
        <span>Total: <strong>${result.total_records ?? '--'}</strong></span>
      </div>
      <div class="bundle-stat" style="color:var(--green)">
        <span>Valid: <strong>${result.valid_records ?? '--'}</strong></span>
      </div>
      <div class="bundle-stat" style="color:var(--red)">
        <span>Invalid: <strong>${result.invalid_records ?? '--'}</strong></span>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">Bundle Checks</div>
      <ul class="checks">
        ${boolChecks.map(([name, passed]) => `
          <li>
            <span class="check-icon" style="color:${passed ? 'var(--green)' : 'var(--red)'}">
              ${passed ? '&#10003;' : '&#10007;'}
            </span>
            <span class="check-name">${escapeHtml(name)}</span>
          </li>
        `).join('')}
      </ul>
    </div>

    ${result.results && result.results.length > 0 ? `
      <div class="panel" style="margin-top:var(--spacing-md)">
        <div class="panel-title">Per-Record Results (${result.results.length})</div>
        <div style="max-height:400px;overflow-y:auto">
          ${result.results.filter(r => !r.valid).map(r => `
            <div class="accordion-header" style="color:var(--red)">
              &#10007; Record ${escapeHtml(r.request_id || '--')}
              <span style="font-size:var(--font-size-xs)">${(r.checks || []).filter(c => !c.passed).map(c => c.name).join(', ')}</span>
            </div>
          `).join('') || '<p style="padding:var(--spacing-md);color:var(--text-muted)">All records passed verification.</p>'}
        </div>
      </div>
    ` : ''}
  `;
}

export function destroyVerify() {}
