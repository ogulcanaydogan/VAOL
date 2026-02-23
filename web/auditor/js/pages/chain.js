// VAOL Auditor — Hash Chain Viewer Page

import * as api from '../api.js';
import * as state from '../state.js';
import { showToast } from '../components/toast.js';
import { escapeHtml, truncHash, formatNumber } from '../utils.js';

let chainRecords = [];

export function renderChain(container) {
  container.innerHTML = `
    <div class="section-title">Hash Chain</div>

    <div class="filter-bar">
      <div class="filter-group">
        <label>Window Size</label>
        <select id="chain-window">
          <option value="10">10</option>
          <option value="20" selected>20</option>
          <option value="50">50</option>
        </select>
      </div>
      <div class="filter-group" style="align-self:flex-end">
        <button id="chain-load">Load Chain</button>
      </div>
      <div class="filter-group" style="align-self:flex-end">
        <button id="chain-older" class="btn-sm btn-secondary" disabled>&#9664; Older</button>
      </div>
      <div class="filter-group" style="align-self:flex-end">
        <button id="chain-newer" class="btn-sm btn-secondary" disabled>Newer &#9654;</button>
      </div>
    </div>

    <div id="chain-integrity" class="hidden" style="margin-bottom:var(--spacing-md)"></div>

    <div id="chain-svg" class="svg-container" style="min-height:200px">
      <div class="empty-state">
        <p>Load the hash chain to visualize record linkage.</p>
      </div>
    </div>
  `;

  document.getElementById('chain-load').addEventListener('click', loadChain);
  document.getElementById('chain-older').addEventListener('click', loadOlder);
  document.getElementById('chain-newer').addEventListener('click', loadNewer);

  if (state.get('connected')) loadChain();
}

async function loadChain(cursor) {
  if (!state.get('serverUrl')) return showToast('Connect to a server first', 'error');

  const limit = parseInt(document.getElementById('chain-window').value) || 20;
  try {
    const data = await api.listRecords({ limit, cursor });
    const records = data.records || data || [];
    chainRecords = records;
    drawChain(records);
    checkIntegrity(records);

    document.getElementById('chain-older').disabled = records.length < limit;
    document.getElementById('chain-newer').disabled = !cursor;
  } catch (err) {
    showToast(`Failed to load chain: ${err.message}`, 'error');
  }
}

function loadOlder() {
  if (chainRecords.length === 0) return;
  const last = chainRecords[chainRecords.length - 1];
  loadChain(last.sequence_number);
}

function loadNewer() {
  // Go back to the beginning
  loadChain();
}

function checkIntegrity(records) {
  const el = document.getElementById('chain-integrity');
  el.classList.remove('hidden');

  let intact = true;
  let breakAt = -1;

  for (let i = 1; i < records.length; i++) {
    const prevHash = records[i].previous_record_hash;
    const expectedHash = records[i - 1].record_hash;
    if (prevHash && expectedHash && prevHash !== expectedHash) {
      intact = false;
      breakAt = records[i].sequence_number;
      break;
    }
  }

  if (intact) {
    el.innerHTML = `<div class="verdict verdict-pass" style="padding:var(--spacing-sm) var(--spacing-md)">&#10003; Chain intact (${records.length} records)</div>`;
  } else {
    el.innerHTML = `<div class="verdict verdict-fail" style="padding:var(--spacing-sm) var(--spacing-md)">&#10007; Chain break detected at sequence ${breakAt}</div>`;
  }
}

function drawChain(records) {
  const svgEl = document.getElementById('chain-svg');

  if (records.length === 0) {
    svgEl.innerHTML = '<div class="empty-state"><p>No records found.</p></div>';
    return;
  }

  const blockW = 140;
  const blockH = 70;
  const gap = 60;
  const svgW = records.length * (blockW + gap) + 40;
  const svgH = 160;
  const y = (svgH - blockH) / 2;

  let svg = `<svg width="${svgW}" height="${svgH}" viewBox="0 0 ${svgW} ${svgH}" xmlns="http://www.w3.org/2000/svg">`;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    const x = 20 + i * (blockW + gap);

    // Check chain link
    let linkValid = true;
    if (i > 0) {
      const prevHash = rec.previous_record_hash;
      const expectedHash = records[i - 1].record_hash;
      linkValid = !prevHash || !expectedHash || prevHash === expectedHash;
    }

    // Genesis check
    const isGenesis = rec.previous_record_hash?.endsWith('0'.repeat(64));

    // Block rectangle
    const fillColor = isGenesis ? '#1e3a5f' : '#1e293b';
    const strokeColor = isGenesis ? '#3b82f6' : '#334155';
    svg += `<rect x="${x}" y="${y}" width="${blockW}" height="${blockH}" rx="6" fill="${fillColor}" stroke="${strokeColor}" stroke-width="1.5" class="chain-block" data-id="${escapeHtml(rec.request_id || '')}"/>`;

    // Sequence number
    svg += `<text x="${x + blockW / 2}" y="${y + 18}" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="bold" font-family="monospace">`;
    svg += isGenesis ? 'GENESIS' : `#${rec.sequence_number ?? i}`;
    svg += '</text>';

    // Record hash (truncated)
    const hashStr = truncHash(rec.record_hash, 10);
    svg += `<text x="${x + blockW / 2}" y="${y + 36}" text-anchor="middle" fill="#94a3b8" font-size="9" font-family="monospace">${hashStr}</text>`;

    // Previous hash (truncated)
    const prevStr = truncHash(rec.previous_record_hash, 10);
    svg += `<text x="${x + blockW / 2}" y="${y + 50}" text-anchor="middle" fill="#64748b" font-size="8" font-family="monospace">prev: ${prevStr}</text>`;

    // Arrow to next block
    if (i < records.length - 1) {
      const arrowColor = linkValid ? '#22c55e' : '#ef4444';
      const ax = x + blockW;
      const ay = y + blockH / 2;
      const bx = x + blockW + gap;
      svg += `<line x1="${ax}" y1="${ay}" x2="${bx - 8}" y2="${ay}" stroke="${arrowColor}" stroke-width="2"/>`;
      svg += `<polygon points="${bx - 8},${ay - 5} ${bx},${ay} ${bx - 8},${ay + 5}" fill="${arrowColor}"/>`;

      if (!linkValid) {
        svg += `<text x="${ax + gap / 2}" y="${ay - 12}" text-anchor="middle" fill="#ef4444" font-size="10" font-weight="bold">BREAK</text>`;
      }
    }
  }

  svg += '</svg>';
  svgEl.innerHTML = svg;

  // Click handler for blocks
  svgEl.querySelectorAll('.chain-block').forEach(block => {
    block.addEventListener('click', () => {
      const id = block.getAttribute('data-id');
      if (id) window.location.hash = `/records/${id}`;
    });
    block.style.cursor = 'pointer';
  });
}

export function destroyChain() {
  chainRecords = [];
}
