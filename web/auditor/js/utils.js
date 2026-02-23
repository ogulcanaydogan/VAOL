// VAOL Auditor — Utility Functions

export function truncHash(hash, len = 16) {
  if (!hash) return '--';
  if (hash.startsWith('sha256:')) {
    return 'sha256:' + hash.slice(7, 7 + len) + '...';
  }
  return hash.slice(0, len) + '...';
}

export function formatTimestamp(ts) {
  if (!ts) return '--';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch {
    return ts;
  }
}

export function shortId(id, len = 8) {
  if (!id) return '--';
  return id.slice(0, len);
}

export function policyBadgeClass(decision) {
  switch (decision) {
    case 'allow': return 'badge-allow';
    case 'deny': return 'badge-deny';
    case 'allow_with_transform': return 'badge-info';
    case 'log_only': return 'badge-hash';
    default: return 'badge-hash';
  }
}

export function modeBadgeClass(mode) {
  switch (mode) {
    case 'hash_only': return 'badge-hash';
    case 'encrypted': return 'badge-encrypted';
    case 'plaintext': return 'badge-info';
    default: return 'badge-hash';
  }
}

export function decodeEnvelopePayload(envelope) {
  if (!envelope || !envelope.payload) return null;
  try {
    return JSON.parse(atob(envelope.payload));
  } catch {
    return null;
  }
}

export function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

export async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function formatNumber(n) {
  if (n === null || n === undefined) return '--';
  return Number(n).toLocaleString();
}
