// VAOL Auditor — Records Browser Page

import * as api from '../api.js';
import * as state from '../state.js';
import { navigate } from '../router.js';
import { showToast } from '../components/toast.js';
import {
  truncHash, formatTimestamp, shortId,
  policyBadgeClass, modeBadgeClass, decodeEnvelopePayload, escapeHtml,
} from '../utils.js';

let cursorStack = [];
let currentCursor = null;
let currentRecords = [];

export function renderRecords(container) {
  container.innerHTML = `
    <div class="section-title">Records</div>

    <div class="filter-bar">
      <div class="filter-group">
        <label>After</label>
        <input type="datetime-local" id="filter-after">
      </div>
      <div class="filter-group">
        <label>Before</label>
        <input type="datetime-local" id="filter-before">
      </div>
      <div class="filter-group">
        <label>Page Size</label>
        <select id="filter-limit">
          <option value="10">10</option>
          <option value="25" selected>25</option>
          <option value="50">50</option>
          <option value="100">100</option>
        </select>
      </div>
      <div class="filter-group" style="align-self:flex-end">
        <button id="filter-apply">Apply</button>
      </div>
    </div>

    <div id="records-content">
      <div class="empty-state" id="records-empty">
        <p style="font-size:1.5rem">&#128274;</p>
        <p>Connect to a VAOL server from the Dashboard to browse records.</p>
      </div>
      <table id="records-table" class="hidden">
        <thead>
          <tr>
            <th>Seq</th>
            <th>Request ID</th>
            <th>Tenant</th>
            <th>Model</th>
            <th>Policy</th>
            <th>Mode</th>
            <th>Hash</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody id="records-tbody"></tbody>
      </table>
    </div>

    <div class="pagination" id="records-pagination" style="display:none">
      <span id="page-info"></span>
      <div class="pagination-controls">
        <button class="btn-sm btn-secondary" id="page-prev" disabled>Previous</button>
        <button class="btn-sm btn-secondary" id="page-next">Next</button>
      </div>
    </div>
  `;

  document.getElementById('filter-apply').addEventListener('click', () => {
    cursorStack = [];
    currentCursor = null;
    loadRecords();
  });
  document.getElementById('page-prev').addEventListener('click', pagePrev);
  document.getElementById('page-next').addEventListener('click', pageNext);

  // Auto-load if connected
  if (state.get('connected')) loadRecords();
}

async function loadRecords() {
  if (!state.get('serverUrl')) {
    showToast('Not connected to a server', 'error');
    return;
  }

  const limit = parseInt(document.getElementById('filter-limit').value) || 25;
  const after = document.getElementById('filter-after').value
    ? new Date(document.getElementById('filter-after').value).toISOString()
    : undefined;
  const before = document.getElementById('filter-before').value
    ? new Date(document.getElementById('filter-before').value).toISOString()
    : undefined;

  try {
    const data = await api.listRecords({ limit, cursor: currentCursor, after, before });
    const records = data.records || data || [];
    currentRecords = records;
    renderTable(records, limit);
  } catch (err) {
    showToast(`Failed to load records: ${err.message}`, 'error');
  }
}

function renderTable(records, limit) {
  const emptyEl = document.getElementById('records-empty');
  const tableEl = document.getElementById('records-table');
  const tbody = document.getElementById('records-tbody');
  const paginationEl = document.getElementById('records-pagination');

  if (records.length === 0) {
    emptyEl.classList.remove('hidden');
    emptyEl.querySelector('p:last-child').textContent = 'No records found.';
    tableEl.classList.add('hidden');
    paginationEl.style.display = 'none';
    return;
  }

  emptyEl.classList.add('hidden');
  tableEl.classList.remove('hidden');
  paginationEl.style.display = 'flex';
  tbody.innerHTML = '';

  for (const rec of records) {
    const payload = decodeEnvelopePayload(rec.dsse_envelope);
    const tr = document.createElement('tr');
    tr.className = 'clickable';
    tr.addEventListener('click', () => navigate(`/records/${rec.request_id}`));

    const seq = rec.sequence_number ?? '--';
    const reqId = shortId(rec.request_id);
    const tenant = rec.tenant_id || payload?.identity?.tenant_id || '--';
    const model = payload?.model?.name || '--';
    const policy = payload?.policy_context?.policy_decision || '--';
    const mode = payload?.output?.mode || '--';
    const hash = truncHash(rec.record_hash, 12);
    const ts = formatTimestamp(rec.timestamp);

    tr.innerHTML = `
      <td>${seq}</td>
      <td class="hash hash-short" title="${escapeHtml(rec.request_id || '')}">${reqId}</td>
      <td>${escapeHtml(tenant)}</td>
      <td>${escapeHtml(model)}</td>
      <td><span class="badge ${policyBadgeClass(policy)}">${escapeHtml(policy)}</span></td>
      <td><span class="badge ${modeBadgeClass(mode)}">${escapeHtml(mode)}</span></td>
      <td class="hash hash-short" title="${escapeHtml(rec.record_hash || '')}">${hash}</td>
      <td style="color:var(--text-muted)">${ts}</td>
    `;
    tbody.appendChild(tr);
  }

  // Pagination
  document.getElementById('page-prev').disabled = cursorStack.length === 0;
  document.getElementById('page-next').disabled = records.length < limit;
  document.getElementById('page-info').textContent =
    `Showing ${records.length} record${records.length !== 1 ? 's' : ''}`;
}

function pageNext() {
  if (currentRecords.length === 0) return;
  const last = currentRecords[currentRecords.length - 1];
  cursorStack.push(currentCursor);
  currentCursor = last.sequence_number;
  loadRecords();
}

function pagePrev() {
  if (cursorStack.length === 0) return;
  currentCursor = cursorStack.pop();
  loadRecords();
}

export function destroyRecords() {
  cursorStack = [];
  currentCursor = null;
  currentRecords = [];
}
