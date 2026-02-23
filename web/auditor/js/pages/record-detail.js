// VAOL Auditor — Record Detail Page

import * as api from '../api.js';
import * as state from '../state.js';
import { showToast } from '../components/toast.js';
import { renderJsonViewer } from '../components/json-viewer.js';
import {
  truncHash, formatTimestamp, escapeHtml, decodeEnvelopePayload, copyToClipboard,
} from '../utils.js';

export function renderRecordDetail(container, params) {
  const id = params.id;

  container.innerHTML = `
    <div class="breadcrumb">
      <a href="#/records">Records</a>
      <span>&#9656;</span>
      <span>${escapeHtml(id.slice(0, 12))}...</span>
    </div>
    <div class="section-title">Record Detail</div>
    <div id="detail-loading" class="empty-state"><p>Loading...</p></div>
    <div id="detail-content" class="hidden"></div>
  `;

  loadDetail(id);
}

async function loadDetail(id) {
  if (!state.get('serverUrl')) {
    showToast('Not connected to a server', 'error');
    return;
  }

  try {
    const rec = await api.getRecord(id);
    const payload = decodeEnvelopePayload(rec.dsse_envelope);

    let proof = null;
    try { proof = await api.getRecordProof(id); } catch { /* proof may not exist */ }

    document.getElementById('detail-loading')?.classList.add('hidden');
    const content = document.getElementById('detail-content');
    if (!content) return;
    content.classList.remove('hidden');

    content.innerHTML = buildDetailHtml(rec, payload, proof);

    // Wire up copy buttons
    content.querySelectorAll('[data-copy]').forEach(el => {
      el.addEventListener('click', async () => {
        const text = el.getAttribute('data-copy');
        if (await copyToClipboard(text)) {
          showToast('Copied to clipboard', 'success');
        }
      });
    });

    // Wire up raw JSON toggle
    const toggleBtn = document.getElementById('toggle-raw');
    const rawEl = document.getElementById('raw-json');
    if (toggleBtn && rawEl) {
      toggleBtn.addEventListener('click', () => {
        rawEl.classList.toggle('hidden');
        toggleBtn.textContent = rawEl.classList.contains('hidden') ? 'Show Raw JSON' : 'Hide Raw JSON';
      });
      renderJsonViewer(rawEl, payload || rec);
    }
  } catch (err) {
    document.getElementById('detail-loading').innerHTML =
      `<p style="color:var(--red)">Failed to load record: ${escapeHtml(err.message)}</p>`;
  }
}

function buildDetailHtml(rec, payload, proof) {
  const env = rec.dsse_envelope;
  const p = payload || {};
  const sections = [];

  // Core metadata
  sections.push(buildSection('Record Metadata', [
    ['Request ID', rec.request_id, true],
    ['Sequence', rec.sequence_number],
    ['Tenant', rec.tenant_id],
    ['Timestamp', formatTimestamp(rec.timestamp)],
    ['Record Hash', rec.record_hash, true],
    ['Previous Hash', rec.previous_record_hash, true],
    ['Schema Version', p.schema_version],
  ]));

  // Identity
  if (p.identity) {
    sections.push(buildSection('Identity', [
      ['Tenant ID', p.identity.tenant_id],
      ['Subject', p.identity.subject],
      ['Subject Type', p.identity.subject_type],
      ['Claims', p.identity.claims ? JSON.stringify(p.identity.claims) : null],
    ]));
  }

  // Auth context
  if (p.auth_context) {
    sections.push(buildSection('Auth Context', [
      ['Issuer', p.auth_context.issuer],
      ['Subject', p.auth_context.subject],
      ['Authenticated', p.auth_context.authenticated ? 'Yes' : 'No'],
      ['Source', p.auth_context.source],
      ['Token Hash', p.auth_context.token_hash, true],
    ]));
  }

  // Model
  if (p.model) {
    sections.push(buildSection('Model', [
      ['Provider', p.model.provider],
      ['Name', p.model.name],
      ['Version', p.model.version],
      ['Endpoint', p.model.endpoint],
      ['Deployment ID', p.model.deployment_id],
    ]));
  }

  // Parameters
  if (p.parameters) {
    sections.push(buildSection('Parameters', [
      ['Temperature', p.parameters.temperature],
      ['Top P', p.parameters.top_p],
      ['Max Tokens', p.parameters.max_tokens],
      ['Seed', p.parameters.seed],
      ['Tools Enabled', p.parameters.tools_enabled != null ? String(p.parameters.tools_enabled) : null],
      ['Response Format', p.parameters.response_format],
    ]));
  }

  // Prompt context
  if (p.prompt_context) {
    sections.push(buildSection('Prompt Context', [
      ['System Prompt Hash', p.prompt_context.system_prompt_hash, true],
      ['User Prompt Hash', p.prompt_context.user_prompt_hash, true],
      ['Template ID', p.prompt_context.user_prompt_template_id],
      ['Template Hash', p.prompt_context.user_prompt_template_hash, true],
      ['Tool Schema Hash', p.prompt_context.tool_schema_hash, true],
      ['Message Count', p.prompt_context.message_count],
      ['Total Input Tokens', p.prompt_context.total_input_tokens],
    ]));
  }

  // Policy context
  if (p.policy_context) {
    sections.push(buildSection('Policy Context', [
      ['Decision', p.policy_context.policy_decision],
      ['Reason Code', p.policy_context.decision_reason_code],
      ['Bundle ID', p.policy_context.policy_bundle_id],
      ['Policy Hash', p.policy_context.policy_hash, true],
      ['Rule IDs', p.policy_context.rule_ids?.join(', ')],
      ['Engine Version', p.policy_context.policy_engine_version],
      ['Eval Duration (ms)', p.policy_context.evaluation_duration_ms],
    ]));
  }

  // RAG context
  if (p.rag_context) {
    sections.push(buildSection('RAG Context', [
      ['Connector IDs', p.rag_context.connector_ids?.join(', ')],
      ['Document IDs', p.rag_context.document_ids?.join(', ')],
      ['Chunk Hashes', p.rag_context.chunk_hashes?.length + ' hash(es)'],
      ['Citation Hashes', p.rag_context.citation_hashes?.length + ' hash(es)'],
      ['Retrieval Decision', p.rag_context.retrieval_policy_decision],
      ['Injection Check', p.rag_context.prompt_injection_check?.result],
    ]));
  }

  // Output
  if (p.output) {
    sections.push(buildSection('Output', [
      ['Output Hash', p.output.output_hash, true],
      ['Mode', p.output.mode],
      ['Output Tokens', p.output.output_tokens],
      ['Finish Reason', p.output.finish_reason],
      ['Latency (ms)', p.output.latency_ms],
    ]));
  }

  // Trace
  if (p.trace) {
    sections.push(buildSection('Trace', [
      ['OTel Trace ID', p.trace.otel_trace_id],
      ['OTel Span ID', p.trace.otel_span_id],
      ['Parent Request ID', p.trace.parent_request_id],
      ['Session ID', p.trace.session_id],
    ]));
  }

  // DSSE Envelope
  if (env) {
    const sigs = env.signatures || [];
    let sigHtml = sigs.map((s, i) => `
      <div style="margin-top:0.5rem;padding:0.5rem;background:var(--bg);border-radius:var(--radius-md)">
        <div style="font-weight:600;margin-bottom:0.25rem">Signature ${i + 1}</div>
        <dl class="detail-grid">
          <dt>Key ID</dt><dd class="hash">${escapeHtml(s.keyid || '--')}</dd>
          <dt>Timestamp</dt><dd>${formatTimestamp(s.timestamp)}</dd>
          ${s.cert ? '<dt>Certificate</dt><dd style="color:var(--green)">Present</dd>' : ''}
          ${s.rekor_entry_id ? `<dt>Rekor Entry</dt><dd class="hash">${escapeHtml(s.rekor_entry_id)}</dd>` : ''}
        </dl>
      </div>
    `).join('');

    sections.push(`
      <div class="record-section">
        <div class="record-section-title">DSSE Envelope</div>
        <dl class="detail-grid">
          <dt>Payload Type</dt><dd>${escapeHtml(env.payloadType || env.payload_type || '--')}</dd>
          <dt>Signatures</dt><dd>${sigs.length} signature(s)</dd>
        </dl>
        ${sigHtml}
      </div>
    `);
  }

  // Inclusion proof
  if (proof) {
    sections.push(`
      <div class="record-section">
        <div class="record-section-title">Merkle Inclusion Proof</div>
        <dl class="detail-grid">
          <dt>Leaf Index</dt><dd>${proof.leaf_index ?? proof.LeafIndex ?? '--'}</dd>
          <dt>Tree Size</dt><dd>${proof.tree_size ?? proof.TreeSize ?? '--'}</dd>
          <dt>Root Hash</dt><dd class="hash">${escapeHtml(proof.root_hash ?? proof.RootHash ?? '--')}</dd>
          <dt>Proof Hashes</dt><dd>${(proof.hashes ?? proof.Hashes ?? []).length} hash(es)</dd>
        </dl>
        <div style="margin-top:0.75rem">
          <a href="#/merkle?record=${rec.request_id}" class="btn btn-sm btn-secondary" style="text-decoration:none">
            Visualize in Merkle Inspector
          </a>
        </div>
      </div>
    `);
  }

  // Chain navigation
  const prevHash = rec.previous_record_hash || p.integrity?.previous_record_hash;
  if (prevHash && !prevHash.endsWith('0'.repeat(64))) {
    sections.push(`
      <div class="record-section">
        <div class="record-section-title">Chain Navigation</div>
        <a href="#/chain" class="btn btn-sm btn-secondary" style="text-decoration:none">
          View in Hash Chain
        </a>
      </div>
    `);
  }

  // Raw JSON
  sections.push(`
    <div class="record-section">
      <button id="toggle-raw" class="btn-sm btn-secondary">Show Raw JSON</button>
      <div id="raw-json" class="hidden" style="margin-top:0.75rem"></div>
    </div>
  `);

  return sections.join('');
}

function buildSection(title, fields) {
  const rows = fields
    .filter(([_, v]) => v !== undefined && v !== null && v !== '')
    .map(([label, value, copyable]) => {
      const copyAttr = copyable ? `data-copy="${escapeHtml(String(value))}" class="hash-copy"` : '';
      return `<dt>${escapeHtml(label)}</dt><dd ${copyAttr}>${escapeHtml(String(value))}</dd>`;
    })
    .join('');

  if (!rows) return '';

  return `
    <div class="record-section">
      <div class="record-section-title">${escapeHtml(title)}</div>
      <dl class="detail-grid">${rows}</dl>
    </div>
  `;
}

export function destroyRecordDetail() {}
