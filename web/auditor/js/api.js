// VAOL Auditor — API Client

import * as state from './state.js';

function baseUrl() {
  return state.get('serverUrl') || '';
}

function headers() {
  const h = { 'Content-Type': 'application/json' };
  const tenant = state.get('tenantId');
  if (tenant) h['X-VAOL-Tenant-ID'] = tenant;
  return h;
}

async function request(method, path, body = null) {
  const url = baseUrl() + path;
  const opts = { method, headers: headers() };
  if (body) opts.body = JSON.stringify(body);

  const resp = await fetch(url, opts);
  if (!resp.ok) {
    let detail = '';
    try { detail = (await resp.json()).error || ''; } catch { /* empty */ }
    throw new Error(`${resp.status}: ${detail || resp.statusText}`);
  }
  return resp.json();
}

// Health

export async function health() {
  return request('GET', '/v1/health');
}

// Records

export async function listRecords({ limit = 25, cursor, after, before } = {}) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  if (cursor) params.set('cursor', String(cursor));
  if (after) params.set('after', after);
  if (before) params.set('before', before);
  return request('GET', `/v1/records?${params}`);
}

export async function getRecord(id) {
  return request('GET', `/v1/records/${encodeURIComponent(id)}`);
}

export async function getRecordProof(id) {
  return request('GET', `/v1/records/${encodeURIComponent(id)}/proof`);
}

// Verification

export async function verifyEnvelope(envelope, profile = 'basic') {
  return request('POST', '/v1/verify', { envelope, verification_profile: profile });
}

export async function verifyBundle(bundle, profile = 'basic') {
  return request('POST', '/v1/verify/bundle', { bundle, verification_profile: profile });
}

// Ledger

export async function getCheckpoint() {
  return request('GET', '/v1/ledger/checkpoint');
}

export async function getConsistencyProof(from, to) {
  const params = new URLSearchParams({ from: String(from), to: String(to) });
  return request('GET', `/v1/ledger/consistency?${params}`);
}

// Export

export async function exportBundle({ tenant_id, after, before, limit = 1000 } = {}) {
  const body = {};
  if (tenant_id) body.tenant_id = tenant_id;
  if (after) body.after = after;
  if (before) body.before = before;
  if (limit) body.limit = limit;
  return request('POST', '/v1/export', body);
}
