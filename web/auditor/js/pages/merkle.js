// VAOL Auditor — Merkle Proof Inspector Page

import * as api from '../api.js';
import * as state from '../state.js';
import { showToast } from '../components/toast.js';
import { escapeHtml, truncHash, formatTimestamp } from '../utils.js';

export function renderMerkle(container) {
  // Check for query param from record detail link
  const urlParams = new URLSearchParams(window.location.hash.split('?')[1] || '');
  const prefilledRecord = urlParams.get('record') || '';

  container.innerHTML = `
    <div class="section-title">Merkle Proof Inspector</div>

    <div class="two-col">
      <div>
        <div class="panel">
          <div class="panel-title">Inclusion Proof</div>
          <div style="display:flex;gap:var(--spacing-sm);margin-bottom:var(--spacing-md)">
            <input type="text" id="merkle-record-id" placeholder="Record ID (UUID)" style="flex:1" value="${escapeHtml(prefilledRecord)}">
            <button id="merkle-fetch">Fetch Proof</button>
          </div>
          <div id="merkle-proof-info" class="hidden">
            <dl class="detail-grid" id="proof-metadata"></dl>
            <div style="margin-top:var(--spacing-md)">
              <button id="merkle-verify-local" class="btn-sm btn-secondary">Verify Locally</button>
              <span id="merkle-verify-result" style="margin-left:var(--spacing-sm);font-size:var(--font-size-sm)"></span>
            </div>
          </div>
        </div>

        <div class="panel" style="margin-top:var(--spacing-md)">
          <div class="panel-title">Consistency Proof</div>
          <div style="display:flex;gap:var(--spacing-sm);margin-bottom:var(--spacing-md)">
            <input type="number" id="consist-from" placeholder="From tree size" style="width:120px">
            <input type="number" id="consist-to" placeholder="To tree size" style="width:120px">
            <button id="consist-fetch" class="btn-sm">Fetch</button>
          </div>
          <div id="consist-result" class="hidden"></div>
        </div>
      </div>

      <div>
        <div class="panel">
          <div class="panel-title">Current Checkpoint</div>
          <div id="checkpoint-info">
            <p style="color:var(--text-muted)">Connect to server to view checkpoint.</p>
          </div>
        </div>

        <div class="panel" style="margin-top:var(--spacing-md)">
          <div class="panel-title">Proof Visualization</div>
          <div id="merkle-svg" class="svg-container" style="min-height:200px">
            <p style="color:var(--text-muted);text-align:center;padding:var(--spacing-xl)">
              Fetch a proof to see the visualization.
            </p>
          </div>
        </div>
      </div>
    </div>
  `;

  // Fetch proof
  document.getElementById('merkle-fetch').addEventListener('click', fetchProof);

  // Consistency proof
  document.getElementById('consist-fetch').addEventListener('click', fetchConsistency);

  // Load checkpoint
  if (state.get('connected')) loadCheckpoint();

  // Auto-fetch if prefilled
  if (prefilledRecord) fetchProof();
}

let currentProof = null;

async function fetchProof() {
  const id = document.getElementById('merkle-record-id').value.trim();
  if (!id) return showToast('Enter a record ID', 'error');
  if (!state.get('serverUrl')) return showToast('Connect to a server first', 'error');

  try {
    const proof = await api.getRecordProof(id);
    currentProof = proof;
    displayProof(proof);
    drawProofSvg(proof);
  } catch (err) {
    showToast(`Failed to fetch proof: ${err.message}`, 'error');
  }
}

function displayProof(proof) {
  const infoEl = document.getElementById('merkle-proof-info');
  infoEl.classList.remove('hidden');

  const meta = document.getElementById('proof-metadata');
  const leafIndex = proof.leaf_index ?? proof.LeafIndex ?? '--';
  const treeSize = proof.tree_size ?? proof.TreeSize ?? '--';
  const rootHash = proof.root_hash ?? proof.RootHash ?? '--';
  const hashes = proof.hashes ?? proof.Hashes ?? [];

  meta.innerHTML = `
    <dt>Leaf Index</dt><dd>${leafIndex}</dd>
    <dt>Tree Size</dt><dd>${treeSize}</dd>
    <dt>Root Hash</dt><dd class="hash">${escapeHtml(String(rootHash))}</dd>
    <dt>Proof Length</dt><dd>${hashes.length} hash(es)</dd>
  `;

  // Wire local verify button
  document.getElementById('merkle-verify-local').onclick = () => verifyLocally(proof);
}

async function verifyLocally(proof) {
  const resultEl = document.getElementById('merkle-verify-result');
  resultEl.textContent = 'Verifying...';
  resultEl.style.color = 'var(--text-muted)';

  try {
    const hashes = proof.hashes ?? proof.Hashes ?? [];
    const leafIndex = proof.leaf_index ?? proof.LeafIndex;
    const treeSize = proof.tree_size ?? proof.TreeSize;
    const expectedRoot = proof.root_hash ?? proof.RootHash;

    if (hashes.length === 0) {
      resultEl.textContent = 'No proof hashes to verify';
      resultEl.style.color = 'var(--amber)';
      return;
    }

    // Client-side RFC 6962 verification
    // Start with the leaf hash (first proof hash at leaf level)
    // Walk up the tree using proof hashes
    let computedHash = hexToBytes(stripPrefix(hashes[0]));
    let idx = leafIndex;

    for (let i = 1; i < hashes.length; i++) {
      const sibling = hexToBytes(stripPrefix(hashes[i]));
      if (idx % 2 === 0) {
        computedHash = await merkleNodeHash(computedHash, sibling);
      } else {
        computedHash = await merkleNodeHash(sibling, computedHash);
      }
      idx = Math.floor(idx / 2);
    }

    const computedHex = 'sha256:' + bytesToHex(computedHash);
    const match = computedHex === expectedRoot;

    resultEl.textContent = match ? 'Proof valid' : 'Proof INVALID — root mismatch';
    resultEl.style.color = match ? 'var(--green)' : 'var(--red)';
  } catch (err) {
    resultEl.textContent = `Verification error: ${err.message}`;
    resultEl.style.color = 'var(--red)';
  }
}

async function fetchConsistency() {
  const from = parseInt(document.getElementById('consist-from').value);
  const to = parseInt(document.getElementById('consist-to').value);
  if (!from || !to) return showToast('Enter both tree sizes', 'error');
  if (!state.get('serverUrl')) return showToast('Connect to a server first', 'error');

  try {
    const proof = await api.getConsistencyProof(from, to);
    const el = document.getElementById('consist-result');
    el.classList.remove('hidden');
    const hashes = proof.hashes ?? proof.Hashes ?? [];
    el.innerHTML = `
      <dl class="detail-grid">
        <dt>From → To</dt><dd>${from} → ${to}</dd>
        <dt>Proof Hashes</dt><dd>${hashes.length}</dd>
      </dl>
      <div style="margin-top:0.5rem;font-size:var(--font-size-xs);color:var(--text-muted)">
        ${hashes.map((h, i) => `[${i}] ${escapeHtml(h)}`).join('<br>')}
      </div>
    `;
  } catch (err) {
    showToast(`Failed: ${err.message}`, 'error');
  }
}

async function loadCheckpoint() {
  try {
    const cp = await api.getCheckpoint();
    const el = document.getElementById('checkpoint-info');
    if (!el) return;
    el.innerHTML = `
      <dl class="detail-grid">
        <dt>Tree Size</dt><dd>${cp.tree_size ?? '--'}</dd>
        <dt>Root Hash</dt><dd class="hash">${escapeHtml(cp.root_hash || '--')}</dd>
        <dt>Timestamp</dt><dd>${formatTimestamp(cp.timestamp)}</dd>
        <dt>Signed</dt><dd>${cp.signature ? 'Yes' : 'No'}</dd>
      </dl>
    `;
  } catch { /* silent */ }
}

// SVG visualization of the audit path
function drawProofSvg(proof) {
  const svgEl = document.getElementById('merkle-svg');
  const hashes = proof.hashes ?? proof.Hashes ?? [];
  const leafIndex = proof.leaf_index ?? proof.LeafIndex ?? 0;

  if (hashes.length === 0) {
    svgEl.innerHTML = '<p style="color:var(--text-muted);text-align:center;padding:var(--spacing-xl)">No proof hashes to visualize.</p>';
    return;
  }

  const levels = hashes.length;
  const nodeR = 20;
  const levelH = 70;
  const svgW = Math.max(400, levels * 120);
  const svgH = levels * levelH + 60;

  let svg = `<svg width="${svgW}" height="${svgH}" viewBox="0 0 ${svgW} ${svgH}" xmlns="http://www.w3.org/2000/svg">`;

  // Draw from bottom (leaf) to top (root)
  const nodes = [];
  let idx = leafIndex;

  for (let i = 0; i < levels; i++) {
    const y = svgH - 40 - i * levelH;
    const isTarget = (i === 0);
    const color = isTarget ? '#3b82f6' : '#f59e0b'; // blue for leaf, amber for proof hashes
    const cx = svgW / 2 - (levels - 1 - i) * 30;

    nodes.push({ x: cx, y, hash: hashes[i], level: i });

    // Node circle
    svg += `<circle cx="${cx}" cy="${y}" r="${nodeR}" fill="${color}" opacity="0.8"/>`;

    // Hash label
    const shortHash = truncHash(hashes[i], 8);
    svg += `<text x="${cx}" y="${y + nodeR + 14}" text-anchor="middle" fill="#94a3b8" font-size="10" font-family="monospace">${shortHash}</text>`;

    // Level label
    const levelLabel = i === 0 ? 'Leaf' : `L${i}`;
    svg += `<text x="${cx - nodeR - 8}" y="${y + 4}" text-anchor="end" fill="#64748b" font-size="10">${levelLabel}</text>`;

    // Connection line to next level
    if (i > 0) {
      const prevNode = nodes[i - 1];
      svg += `<line x1="${prevNode.x}" y1="${prevNode.y - nodeR}" x2="${cx}" y2="${y + nodeR}" stroke="#334155" stroke-width="2"/>`;
    }

    idx = Math.floor(idx / 2);
  }

  // Root indicator
  if (nodes.length > 0) {
    const topNode = nodes[nodes.length - 1];
    svg += `<text x="${topNode.x}" y="${topNode.y - nodeR - 8}" text-anchor="middle" fill="#22c55e" font-size="12" font-weight="bold">Root</text>`;
  }

  svg += '</svg>';
  svgEl.innerHTML = svg;
}

// Crypto helpers
function stripPrefix(hash) {
  return hash.startsWith('sha256:') ? hash.slice(7) : hash;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function merkleNodeHash(left, right) {
  const buffer = new Uint8Array(1 + left.length + right.length);
  buffer[0] = 0x01; // RFC 6962 node prefix
  buffer.set(left, 1);
  buffer.set(right, 1 + left.length);
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return new Uint8Array(hash);
}

export function destroyMerkle() {
  currentProof = null;
}
