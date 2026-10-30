// Session recordings (Quill, a PostHog-compatible server) and error reports (Sentry's browser
// SDK). Both are off unless the host configures them: GET /auth/state names where they go, or
// says null. The SDKs in /vendor load only for a signed-in person, after sign-in, so the setup and
// sign-in pages never load them, and self-hosted servers never report anywhere.
//
// What leaves the browser, and what doesn't:
// - Every URL and path becomes its route template (`/p/:id`, `/t/:id`, `/u/:handle`), so titles,
//   ids, file names and anything typed into the address bar stay home. Query strings keep only the
//   app's own harmless parameters (never search text, tokens or OAuth codes); hashes go. Another
//   site's URL keeps only its origin. Pageview titles are dropped.
// - Recordings mask all text, every input and words in attributes, and template links' and images'
//   URLs. No canvas, console or network capture. While an excluded page (setup, sign-in) is on
//   screen nothing is recorded, and anything recorded during that time is dropped before sending.
// - posthog-js never calls /flags (feature flags are off), so no request carries person
//   properties it hasn't passed through `before_send`.
// - Sentry gets errors only: no replay, tracing, sessions, console or click breadcrumbs. Exception
//   and breadcrumb text is replaced with "[redacted]"; error types, function names and line
//   numbers stay. API errors are left out; the server reports its own failures.

import { ApiError } from '/api.js';

/** Pages that never send anything: setup, sign-in, and the OAuth and connected-app hand-offs. */
const PRIVATE_PATH = /^\/(setup|login|oauth|connect)(\/|$)/;

/** Query parameters the app's pages read, none secret. Every other parameter is dropped. */
const KEPT_PARAMS = new Set(['topic', 'template', 'as', 'filter', 'stale', 'type', 'archived', 'event', 'actor', 'checkout', 'look']);

const FIXED_PATHS = new Set([
  '/', '/search', '/new', '/topics', '/drafts', '/templates', '/archive', '/trash', '/notifications', '/activity', '/insights',
  '/settings', '/setup', '/login', '/welcome', '/oauth/authorize', '/connect/callback', '/llms.txt', '/robots.txt', '/healthz', '/mcp',
]);
const SETTINGS_SECTIONS = new Set(['profile', 'agents', 'tokens', 'connections', 'people', 'webhooks', 'workspace', 'plan']);
/** Literal segments of API paths (`/api/v1/posts/{id}/comments`); anything else is an id or a name. */
const API_WORDS = new Set([
  'v1', 'activity', 'address', 'auth', 'billing', 'comments', 'connected', 'connections', 'content', 'diff', 'duplicate', 'edit',
  'export', 'files', 'follows', 'import', 'insights', 'login', 'logout', 'me', 'members', 'notifications', 'openapi.json',
  'operations', 'password', 'pins', 'plan', 'posts', 'preview', 'reactions', 'read', 'recent', 'render', 'restore', 'search',
  'settings', 'setup', 'state', 'tokens', 'topics', 'upgrade', 'users', 'verify', 'versions', 'webhooks',
]);
/** The app's own scripts and images, which name only code (Sentry's stack frames point at them). */
const STATIC_FILE = /^\/(?:[\w-]+\/)*[\w.-]+\.(?:js|mjs|css|svg|png|ico|webmanifest)$/;

/** Attributes that carry people's words. `maskTextSelector` masks text nodes only. */
const TEXT_ATTRIBUTES = new Set([
  'title', 'alt', 'aria-label', 'aria-description', 'aria-valuetext', 'aria-placeholder', 'aria-roledescription',
  'placeholder', 'label', 'download', 'summary', 'id', 'for', 'name', 'data-title', 'data-anchor', 'data-prefix',
]);
const URL_ATTRIBUTES = new Set(['href', 'src', 'rr_src', 'action', 'poster', 'cite', 'xlink:href', 'background']);
/** $current_url, $referrer, $pathname, $initial_referrer, $session_entry_url, $external_click_url… */
const URL_PROPERTY = /(url|referrer|pathname|href)$/i;
/** Properties that hold page titles. */
const DROPPED_PROPERTIES = new Set(['title', '$title']);
/**
 * Search-engine keywords and campaign parameters, under any prefix (`$initial_`,
 * `$session_entry_`): they're words from the address bar.
 */
const DROPPED_PROPERTY = /keyword|utm_|clid$|_cid$|fat_id$|igshid$|_kx$|epik$/i;
const REDACTED = '[redacted]';

let tracking = false;
let posthog = null;
let sentry = null;
/** [start, end] times (ms) an excluded page was on screen; `end` is Infinity while it still is. */
const excludedWindows = [];
/** Identifying waits for an allowed page: everything sent from an excluded one is dropped. */
let pendingIdentify = null;

/** A path as its route template: `/p/:id`, `/t/:id`, `/u/:handle`, `/files/:id`, `/:other`. */
export function templatePath(pathname) {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  if (FIXED_PATHS.has(path)) return path;
  const s = path.split('/');
  switch (s[1]) {
    case 'p': {
      const action = s[s.length - 1];
      if ((s.length === 4 || s.length === 5) && (action === 'edit' || action === 'history')) return `/p/:id/${action}`;
      if (s.length === 3 || s.length === 4) return '/p/:id';
      break;
    }
    case 't':
      if (s.length === 3 || s.length === 4) return '/t/:id';
      break;
    case 'u':
      if (s.length === 3) return '/u/:handle';
      break;
    case 'files':
      return '/files/:id';
    case 'settings':
      if (s.length === 3) return SETTINGS_SECTIONS.has(s[2]) ? path : '/settings/:section';
      break;
    case 'api':
      return '/' + s.slice(1).map((seg, i) => (i === 0 || API_WORDS.has(seg) ? seg : ':id')).join('/');
    default:
      if (STATIC_FILE.test(path)) return path;
  }
  return '/:other';
}

/**
 * A URL as it may leave the browser: the route template, only the app's own harmless query
 * parameters, no hash. Another site's URL becomes its origin, and other schemes (mailto:, data:)
 * just the scheme. Anything that isn't a URL or a path (`$direct`) comes back unchanged.
 */
export function sanitizeUrl(value) {
  if (typeof value !== 'string') return value;
  const absolute = /^[a-z][a-z0-9+.-]*:/i.test(value) || value.startsWith('//');
  if (!absolute && !value.startsWith('/')) return value;
  let url;
  try {
    url = new URL(value, location.origin);
  } catch {
    return '';
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return url.protocol;
  if (url.origin !== location.origin) return url.origin;
  const kept = new URLSearchParams();
  for (const [k, v] of url.searchParams) if (KEPT_PARAMS.has(k)) kept.append(k, v);
  const query = kept.toString();
  const path = templatePath(url.pathname) + (query ? `?${query}` : '');
  return absolute ? url.origin + path : path;
}

/** rrweb's `maskAttributeFn`: masks words in attributes and templates URLs. */
export function maskAttribute(name, value) {
  const key = String(name).toLowerCase();
  if (TEXT_ATTRIBUTES.has(key)) return String(value).replace(/\S/g, '*');
  if (URL_ATTRIBUTES.has(key)) return sanitizeUrl(value);
  if (key === 'srcset') return '';
  return value;
}

function sanitizeProperties(properties) {
  const out = {};
  for (const [key, value] of Object.entries(properties || {})) {
    if (DROPPED_PROPERTIES.has(key) || DROPPED_PROPERTY.test(key)) continue;
    if (typeof value === 'string' && URL_PROPERTY.test(key)) out[key] = sanitizeUrl(value);
    else if ((key === '$set' || key === '$set_once') && value && typeof value === 'object') out[key] = sanitizeProperties(value);
    else out[key] = value;
  }
  return out;
}

function excludedAt(ms) {
  return excludedWindows.some(([start, end]) => ms >= start && ms <= end);
}

/** posthog-js's `before_send`. */
export function prepareEvent(event) {
  if (!event || !tracking || PRIVATE_PATH.test(location.pathname)) return null;
  const at = event.timestamp ? new Date(event.timestamp).getTime() : Date.now();
  const out = { ...event, properties: sanitizeProperties(event.properties) };
  if (event.event === '$snapshot') {
    // Recordings are sent in batches, after the fact: drop what was on screen during an excluded page.
    const data = out.properties.$snapshot_data;
    if (Array.isArray(data)) {
      const kept = data.filter((e) => !(e && typeof e.timestamp === 'number' && excludedAt(e.timestamp)));
      if (!kept.length) return null;
      out.properties.$snapshot_data = kept;
    }
  } else if (excludedAt(at)) {
    return null;
  }
  if (event.$set) out.$set = sanitizeProperties(event.$set);
  if (event.$set_once) out.$set_once = sanitizeProperties(event.$set_once);
  return out;
}

/** posthog-js remembers the first page and referrer for $initial_* person properties. */
function scrubStoredPersonInfo(ph) {
  try {
    const p = ph.persistence;
    const info = p && p.props && p.props.$initial_person_info;
    if (info) p.register({ $initial_person_info: { r: sanitizeUrl(info.r), u: info.u && sanitizeUrl(info.u) } });
    if (p && p.props && typeof p.props.$referrer === 'string') p.register({ $referrer: sanitizeUrl(p.props.$referrer) });
  } catch {
    /* before_send still templates them on every event */
  }
}

/** Templates URL-shaped strings anywhere in a value (for Sentry's tags and contexts). */
function scrubUrls(value) {
  if (typeof value === 'string') return /^(https?:)?\//i.test(value) ? sanitizeUrl(value) : value;
  if (Array.isArray(value)) return value.map(scrubUrls);
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) value[k] = scrubUrls(value[k]);
  }
  return value;
}

function scrubFrames(stacktrace) {
  for (const f of (stacktrace && stacktrace.frames) || []) {
    if (f.filename) f.filename = sanitizeUrl(f.filename);
    if (f.abs_path) f.abs_path = sanitizeUrl(f.abs_path);
    delete f.vars;
    delete f.pre_context;
    delete f.context_line;
    delete f.post_context;
  }
}

const CRUMB_DATA = new Set(['method', 'status_code', 'url', 'from', 'to', 'request_body_size', 'response_body_size']);

/** Sentry's `beforeBreadcrumb`: no text, templated URLs. */
export function prepareCrumb(crumb) {
  if (!crumb) return crumb;
  if (crumb.message) crumb.message = REDACTED;
  if (crumb.data) {
    const data = {};
    for (const [k, v] of Object.entries(crumb.data)) {
      if (!CRUMB_DATA.has(k)) continue;
      data[k] = typeof v === 'string' && (k === 'url' || k === 'from' || k === 'to') ? sanitizeUrl(v) : v;
    }
    crumb.data = data;
  }
  return crumb;
}

/**
 * Sentry's `beforeSend`: the error's type, function names and line numbers, without its message
 * (which can quote a title or a token) or any URL beyond a route template.
 */
export function prepareError(event, hint) {
  if (PRIVATE_PATH.test(location.pathname)) return null;
  // The app shows API errors to the person; the server reports its own failures.
  if (hint && hint.originalException instanceof ApiError) return null;
  for (const v of (event.exception && event.exception.values) || []) {
    if (v.value) v.value = REDACTED;
    if (v.mechanism) delete v.mechanism.data;
    scrubFrames(v.stacktrace);
  }
  for (const t of (event.threads && event.threads.values) || []) scrubFrames(t.stacktrace);
  if (event.message) event.message = REDACTED;
  if (event.logentry) event.logentry = { message: REDACTED };
  const ua = event.request && event.request.headers && event.request.headers['User-Agent'];
  event.request = { url: sanitizeUrl((event.request && event.request.url) || location.href), headers: ua ? { 'User-Agent': ua } : {} };
  if (event.transaction) event.transaction = sanitizeUrl(event.transaction);
  if (event.tags) scrubUrls(event.tags);
  if (event.contexts) scrubUrls(event.contexts);
  delete event.extra;
  event.user = event.user && event.user.id ? { id: event.user.id } : undefined;
  event.breadcrumbs = (event.breadcrumbs || []).map(prepareCrumb);
  return event;
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.async = false;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error(`couldn't load ${src}`));
    document.head.append(s);
  });
}

async function startSentry(config, user, workspace) {
  await loadScript('/vendor/sentry/bundle.min.js');
  const S = window.Sentry;
  if (!S || !tracking) return;
  S.init({
    dsn: config.sentry.dsn,
    release: config.release || undefined,
    environment: /(^|\.)localhost$/.test(location.hostname) ? 'development' : 'production',
    sendDefaultPii: false,
    integrations: (defaults) => [
      ...defaults.filter((i) => i.name !== 'Breadcrumbs' && i.name !== 'BrowserSession'),
      S.breadcrumbsIntegration({ console: false, dom: false, sentry: false }),
    ],
    beforeSend: prepareError,
    beforeBreadcrumb: prepareCrumb,
    initialScope: { tags: { runtime: 'browser', workspace }, user: { id: user.id } },
  });
  sentry = S;
}

async function startQuill(quill, user, workspace) {
  // With external loading off posthog-js can't fetch its recorder, so it loads first.
  await loadScript('/vendor/posthog/posthog-recorder.js');
  await loadScript('/vendor/posthog/array.no-external.js');
  const ph = window.posthog;
  if (!ph || !tracking) return;
  ph.init(quill.token, {
    api_host: quill.host,
    disable_external_dependency_loading: true,
    capture_pageview: 'history_change',
    person_profiles: 'identified_only',
    // No /flags requests: they carry person properties that never pass through before_send.
    // Recording settings still come from the project's remote config (GET /array/{token}/config).
    advanced_disable_feature_flags: true,
    advanced_disable_feature_flags_on_first_load: true,
    // Each workspace keeps its own visitor id: no cookie for every *.dumbslab.com.
    cross_subdomain_cookie: false,
    disable_capture_url_hashes: true,
    // Campaign parameters are words from the address bar; captured URLs drop them as well.
    save_campaign_params: false,
    disable_surveys: true,
    disable_product_tours: true,
    disable_conversations: true,
    disable_web_experiments: true,
    // Autocapture records which element was used, never its text or attributes.
    mask_all_text: true,
    mask_all_element_attributes: true,
    mask_personal_data_properties: true,
    // An excluded page on screen when the SDK starts: wait for an allowed one.
    disable_session_recording: excludedAt(Date.now()),
    session_recording: {
      maskAllInputs: true,
      maskTextSelector: '*',
      maskAttributeFn: maskAttribute,
      // The recorder passes the page addresses it stores through this.
      maskCapturedNetworkRequestFn: (request) => ({ ...request, name: sanitizeUrl(request.name) }),
      captureCanvas: { recordCanvas: false },
      recordHeaders: false,
      recordBody: false,
    },
    // Off whatever Quill's remote config says: each can carry page data past the masks.
    enable_recording_console_log: false,
    capture_performance: false,
    capture_exceptions: false,
    capture_heatmaps: false,
    before_send: prepareEvent,
  });
  scrubStoredPersonInfo(ph);
  posthog = ph;
  pendingIdentify = () => {
    // Someone else was identified on this browser and never signed out.
    if (ph.get_distinct_id() !== user.id) ph.reset();
    ph.identify(user.id, { email: user.email, name: user.name, workspace });
    scrubStoredPersonInfo(ph);
  };
  if (!excludedAt(Date.now())) identifyNow();
}

function identifyNow() {
  const identify = pendingIdentify;
  pendingIdentify = null;
  if (identify) identify();
}

/**
 * Call before a page renders. On an excluded page recording stops at once, and whatever the
 * recorder still holds from then on is dropped when it's sent.
 */
export function pageChanging(path) {
  if (!PRIVATE_PATH.test(path)) return;
  const last = excludedWindows[excludedWindows.length - 1];
  if (!last || last[1] !== Infinity) excludedWindows.push([Date.now(), Infinity]);
  try {
    if (posthog) posthog.stopSessionRecording();
  } catch {
    /* telemetry never breaks navigation */
  }
}

/** Call after a page rendered. Back on an allowed page, recording starts again from a fresh snapshot. */
export function pageShown(path) {
  if (PRIVATE_PATH.test(path)) return;
  const last = excludedWindows[excludedWindows.length - 1];
  if (!last || last[1] !== Infinity) return;
  last[1] = Date.now();
  try {
    if (posthog && tracking) {
      identifyNow();
      posthog.startSessionRecording();
    }
  } catch {
    /* telemetry never breaks navigation */
  }
}

/**
 * Starts recordings and error reports for the signed-in person, if the host configured them.
 * `config` is auth state's `telemetry`; `user` is `/me`'s user. Never throws: telemetry must not
 * break the app.
 */
export async function startTelemetry(config, user) {
  if (!config || !user || tracking) return;
  tracking = true;
  pageChanging(location.pathname);
  const workspace = config.workspace || location.hostname;
  const jobs = [];
  if (config.sentry && config.sentry.dsn) jobs.push(startSentry(config, user, workspace));
  if (config.quill && config.quill.host && config.quill.token) jobs.push(startQuill(config.quill, user, workspace));
  for (const result of await Promise.allSettled(jobs)) {
    if (result.status === 'rejected') console.warn('telemetry:', result.reason);
  }
}

/** Reports an error the app caught (and showed), unless it's an API error. */
export function reportError(err) {
  if (sentry && !(err instanceof ApiError)) sentry.captureException(err);
}

/** On sign-out, before leaving: stops recording and forgets the person on this browser. */
export function stopTelemetry() {
  tracking = false;
  pendingIdentify = null;
  try {
    if (posthog) {
      posthog.stopSessionRecording();
      posthog.reset();
    }
    if (sentry) sentry.setUser(null);
  } catch {
    /* telemetry never breaks sign-out */
  }
}
