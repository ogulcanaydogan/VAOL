// VAOL Auditor — Minimal Reactive State Store

const _state = {
  connected: false,
  serverUrl: '',
  tenantId: '',
  health: null,
  checkpoint: null,
  pollInterval: null,
};

const _listeners = new Map();

export function get(key) {
  return _state[key];
}

export function set(key, value) {
  _state[key] = value;
  const cbs = _listeners.get(key);
  if (cbs) cbs.forEach(cb => cb(value));
}

export function subscribe(key, callback) {
  if (!_listeners.has(key)) _listeners.set(key, new Set());
  _listeners.get(key).add(callback);
  return () => _listeners.get(key).delete(callback);
}

export function getAll() {
  return { ..._state };
}
