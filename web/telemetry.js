// Session recordings (Quill, a PostHog-compatible server) and error reports (Sentry's browser
// SDK). Both are off unless the host configures them: GET /auth/state names where they go, or
// says null. The SDKs in /vendor load only for a signed-in person, after sign-in, so the setup and
// sign-in pages never load them, and self-hosted servers never report anywhere.
//
// What leaves the browser, and what doesn't:
// - Recordings mask all text, every input, text-bearing attributes (titles, labels, alt text,
//   heading ids) and cut links' and images' URLs down like captured URLs. No canvas, console or
//   network capture.
// - Captured URLs lose post and topic slugs (titles), file names, the search text, the hash and
//   every query parameter the app doesn't read, so tokens and OAuth codes never leave. Pageview
//   titles (post titles) are dropped. Other sites' URLs keep only their origin.
// - Sentry gets errors only: no replay, tracing, sessions, console or click breadcrumbs. API
//   errors are left out; the server reports its own failures.

import { ApiError } from '/api.js';

/** Pages that never send anything, should an SDK be running there. */
const PRIVATE_PATH = /^\/(setup|login|oauth|connect)(\/|$)/;

/** Query parameters the app's pages read, none secret. Every other parameter is dropped. */
const KEPT_PARAMS = new Set(['topic', 'template', 'as', 'filter', 'stale', 'type', 'archived', 'event', 'actor', 'checkout', 'look']);

/** Attributes that carry people's words. `maskTextSelector` masks text nodes only. */
const TEXT_ATTRIBUTES = new Set([
  'title', 'alt', 'aria-label', 'aria-description', 'aria-valuetext', 'aria-placeholder', 'aria-roledescription',
  'placeholder', 'label', 'download', 'summary', 'id', 'data-title', 'data-anchor', 'data-prefix',
]);
const URL_ATTRIBUTES = new Set(['href', 'src', 'rr_src', 'action', 'poster', 'cite', 'xlink:href', 'background']);
/** $current_url, $referrer, $pathname, $initial_referrer, $session_entry_url, $external_click_url… */
const URL_PROPERTY = /(url|referrer|pathname|href)$/i;

let tracking = false;
let posthog = null;
let sentry = null;

/**
 * A URL as it may leave the browser. Paths keep their shape (`/p/{id}`, `/t/{id}`, `/files/{id}`)
 * without titles or file names; only the app's own harmless query parameters survive; the hash
 * goes. Another site's URL becomes its origin, and other schemes (mailto:, data:) just the scheme.
 * Anything that isn't a URL or a path (`$direct`) comes back unchanged.
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
  const parts = url.pathname.split('/');
  // /p/{id}/{slug}[/edit|/history] and /t/{id}/{slug}: a slug is a title.
  if ((parts[1] === 'p' || parts[1] === 't') && parts.length > 3 && parts[3] !== 'edit' && parts[3] !== 'history') parts.splice(3, 1);
  // /files/{id}/{name}: the name is the uploader's.
  if (parts[1] === 'files' && parts.length > 3) parts.length = 3;
  const kept = new URLSearchParams();
  for (const [k, v] of url.searchParams) if (KEPT_PARAMS.has(k)) kept.append(k, v);
  const query = kept.toString();
  const path = parts.join('/') + (query ? `?${query}` : '');
  return absolute ? url.origin + path : path;
}

/** rrweb's `maskAttributeFn`: masks words in attributes and cuts URLs down. */
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
    if (key === 'title') continue; // a pageview's document.title: the post's title
    if (typeof value === 'string' && URL_PROPERTY.test(key)) out[key] = sanitizeUrl(value);
    else if ((key === '$set' || key === '$set_once') && value && typeof value === 'object') out[key] = sanitizeProperties(value);
    else out[key] = value;
  }
  return out;
}

/** posthog-js's `before_send`. */
export function prepareEvent(event) {
  if (!event || !tracking || PRIVATE_PATH.test(location.pathname)) return null;
  const out = { ...event, properties: sanitizeProperties(event.properties) };
  if (event.$set) out.$set = sanitizeProperties(event.$set);
  if (event.$set_once) out.$set_once = sanitizeProperties(event.$set_once);
  return out;
}

function sanitizeCrumb(crumb) {
  const data = crumb && crumb.data;
  if (data) for (const key of ['url', 'from', 'to']) if (typeof data[key] === 'string') data[key] = sanitizeUrl(data[key]);
  return crumb;
}

/** Sentry's `beforeSend`. */
export function prepareError(event, hint) {
  if (PRIVATE_PATH.test(location.pathname)) return null;
  // The app shows API errors to the person; the server reports its own failures.
  if (hint && hint.originalException instanceof ApiError) return null;
  const ua = event.request && event.request.headers && event.request.headers['User-Agent'];
  event.request = { url: sanitizeUrl((event.request && event.request.url) || location.href), headers: ua ? { 'User-Agent': ua } : {} };
  for (const crumb of event.breadcrumbs || []) sanitizeCrumb(crumb);
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
      S.breadcrumbsIntegration({ console: false, dom: false }),
    ],
    beforeSend: prepareError,
    beforeBreadcrumb: sanitizeCrumb,
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
    // Each workspace keeps its own visitor id: no cookie for every *.dumbslab.com.
    cross_subdomain_cookie: false,
    disable_capture_url_hashes: true,
    disable_surveys: true,
    disable_product_tours: true,
    disable_conversations: true,
    disable_web_experiments: true,
    // Autocapture records which element was used, never its text or attributes.
    mask_all_text: true,
    mask_all_element_attributes: true,
    mask_personal_data_properties: true,
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
  // Someone else was identified on this browser and never signed out.
  if (ph.get_distinct_id() !== user.id) ph.reset();
  ph.identify(user.id, { email: user.email, name: user.name, workspace });
  posthog = ph;
}

/**
 * Starts recordings and error reports for the signed-in person, if the host configured them.
 * `config` is auth state's `telemetry`; `user` is `/me`'s user. Never throws: telemetry must not
 * break the app.
 */
export async function startTelemetry(config, user) {
  if (!config || !user || tracking || PRIVATE_PATH.test(location.pathname)) return;
  tracking = true;
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
