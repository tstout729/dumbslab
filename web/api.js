// Thin client for the DumbSlab REST API (/api/v1). Every request carries the CSRF header.

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/** Encodes a value for a path segment. */
export const enc = (v) => encodeURIComponent(String(v));

function toQuery(query) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query || {})) {
    if (v === undefined || v === null || v === '') continue;
    params.set(k, Array.isArray(v) ? v.join(',') : String(v));
  }
  return params.toString();
}

let redirecting = false;

/** Sends the user to the sign-in page, remembering where they were. */
export function goToLogin() {
  if (redirecting || location.pathname === '/login') return;
  redirecting = true;
  const next = location.pathname + location.search + location.hash;
  location.href = '/login?next=' + encodeURIComponent(next);
}

export async function request(method, path, { query, body, redirectOn401 = true, signal } = {}) {
  let url = '/api/v1' + path;
  const qs = toQuery(query);
  if (qs) url += '?' + qs;
  const headers = { 'x-dumbslab-client': 'web', accept: 'application/json' };
  const init = { method, headers, credentials: 'same-origin', signal };
  if (body !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    throw new ApiError(0, 'network', 'Could not reach the server. Check your connection and try again.');
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = null;
    }
  }
  if (!res.ok) {
    const err = (data && data.error) || {};
    if (res.status === 401 && redirectOn401) goToLogin();
    throw new ApiError(res.status, err.code || `http_${res.status}`, err.message || res.statusText || 'Request failed', err.details);
  }
  return data;
}

export const api = {
  get: (path, query, opts) => request('GET', path, { ...opts, query }),
  post: (path, body, opts) => request('POST', path, { ...opts, body: body ?? {} }),
  patch: (path, body, opts) => request('PATCH', path, { ...opts, body: body ?? {} }),
  del: (path, body, opts) => request('DELETE', path, { ...opts, body }),
};
