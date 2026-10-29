// DOM helpers shared by every view: element builder, icons, toasts, dialogs, menus, time.
// Text is always inserted as text. Only `trustedHtml` sets innerHTML, and it is reserved for
// HTML the server has already sanitized (rendered posts, comments, search snippets).

const SVG_NS = 'http://www.w3.org/2000/svg';

function applyProps(el, props) {
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.setAttribute('class', Array.isArray(v) ? v.filter(Boolean).join(' ') : v);
    else if (k === 'text') el.textContent = String(v);
    else if (k === 'trustedHtml') el.innerHTML = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style' && typeof v === 'object') {
      for (const [sk, sv] of Object.entries(v)) {
        if (sk.startsWith('--')) el.style.setProperty(sk, sv);
        else el.style[sk] = sv;
      }
    } else if (k === 'on') {
      for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    } else if (k.startsWith('on') && typeof v === 'function') {
      el.addEventListener(k.slice(2).toLowerCase(), v);
    } else if (k === 'value' || k === 'checked' || k === 'selected' || k === 'indeterminate') {
      el[k] = v;
    } else if (k === 'ref' && typeof v === 'function') {
      v(el);
    } else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, String(v));
  }
}

function append(el, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false || c === true) continue;
    if (Array.isArray(c)) append(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

/** Creates an element: h('a', { href, class }, 'text', child). */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props && (typeof props !== 'object' || props instanceof Node || Array.isArray(props))) {
    children.unshift(props);
  } else if (props) {
    applyProps(el, props);
  }
  append(el, children);
  return el;
}

export function frag(...children) {
  const f = document.createDocumentFragment();
  append(f, children);
  return f;
}

// ---------------------------------------------------------------------------
// Icons (24px grid, stroked; geometry in the style of Lucide, ISC licensed).

const P = (d) => ['path', { d }];
const C = (cx, cy, r) => ['circle', { cx, cy, r }];
const R = (x, y, width, height, rx = 2) => ['rect', { x, y, width, height, rx }];

const ICONS = {
  search: [C(11, 11, 8), P('m21 21-4.3-4.3')],
  home: [P('M15 21v-8a1 1 0 0 0-1-1h-4a1 1 0 0 0-1 1v8'), P('M3 10a2 2 0 0 1 .709-1.528l7-5.999a2 2 0 0 1 2.582 0l7 5.999A2 2 0 0 1 21 10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z')],
  draft: [P('M12.5 22H18a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v9.5'), P('M14 2v4a2 2 0 0 0 2 2h4'), P('M13.378 15.626a1 1 0 1 0-3.004-3.004l-5.01 5.012a2 2 0 0 0-.506.854l-.837 2.87a.5.5 0 0 0 .62.62l2.87-.837a2 2 0 0 0 .854-.506z')],
  file: [P('M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z'), P('M14 2v4a2 2 0 0 0 2 2h4'), P('M16 13H8'), P('M16 17H8'), P('M10 9H8')],
  bell: [P('M10.268 21a2 2 0 0 0 3.464 0'), P('M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326')],
  activity: [P('M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.24 2.18a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.49 12H2')],
  chart: [P('M3 3v16a2 2 0 0 0 2 2h16'), P('M18 17V9'), P('M13 17V5'), P('M8 17v-3')],
  plus: [P('M5 12h14'), P('M12 5v14')],
  settings: [P('M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z'), C(12, 12, 3)],
  chevronRight: [P('m9 18 6-6-6-6')],
  chevronDown: [P('m6 9 6 6 6-6')],
  chevronLeft: [P('m15 18-6-6 6-6')],
  lock: [R(3, 11, 18, 11), P('M7 11V7a5 5 0 0 1 10 0v4')],
  check: [P('M20 6 9 17l-5-5')],
  more: [C(12, 12, 1), C(19, 12, 1), C(5, 12, 1)],
  pencil: [P('M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z'), P('m15 5 4 4')],
  trash: [P('M3 6h18'), P('M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6'), P('M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2')],
  history: [P('M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8'), P('M3 3v5h5'), P('M12 7v5l4 2')],
  restore: [P('M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8'), P('M3 3v5h5')],
  link: [P('M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'), P('M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71')],
  copy: [R(8, 8, 14, 14), P('M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2')],
  pin: [P('M12 17v5'), P('M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z')],
  archive: [R(2, 3, 20, 5, 1), P('M4 8v11a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8'), P('M10 12h4')],
  verified: [P('M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z'), P('m9 12 2 2 4-4')],
  alert: [P('m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3'), P('M12 9v4'), P('M12 17h.01')],
  info: [C(12, 12, 10), P('M12 16v-4'), P('M12 8h.01')],
  x: [P('M18 6 6 18'), P('m6 6 12 12')],
  menu: [P('M4 12h16'), P('M4 6h16'), P('M4 18h16')],
  sun: [C(12, 12, 4), P('M12 2v2'), P('M12 20v2'), P('m4.93 4.93 1.41 1.41'), P('m17.66 17.66 1.41 1.41'), P('M2 12h2'), P('M20 12h2'), P('m6.34 17.66-1.41 1.41'), P('m19.07 4.93-1.41 1.41')],
  moon: [P('M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z')],
  monitor: [R(2, 3, 20, 14), P('M8 21h8'), P('M12 17v4')],
  logout: [P('M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4'), P('m16 17 5-5-5-5'), P('M21 12H9')],
  user: [P('M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2'), C(12, 7, 4)],
  users: [P('M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'), C(9, 7, 4), P('M22 21v-2a4 4 0 0 0-3-3.87'), P('M16 3.13a4 4 0 0 1 0 7.75')],
  bot: [P('M12 8V4H8'), R(4, 8, 16, 12), P('M2 14h2'), P('M20 14h2'), P('M15 13v2'), P('M9 13v2')],
  comment: [P('M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z')],
  smilePlus: [P('M22 11v1a10 10 0 1 1-9-10'), P('M8 14s1.5 2 4 2 4-2 4-2'), P('M9 9h.01'), P('M15 9h.01'), P('M16 5h6'), P('M19 2v6')],
  reply: [P('m9 17-5-5 5-5'), P('M20 18v-2a4 4 0 0 0-4-4H4')],
  external: [P('M15 3h6v6'), P('M10 14 21 3'), P('M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6')],
  template: [R(3, 3, 18, 7, 1), R(3, 14, 9, 7, 1), R(16, 14, 5, 7, 1)],
  zap: [P('M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z')],
  key: [P('m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4'), P('m21 2-9.6 9.6'), C(7.5, 15.5, 5.5)],
  plug: [P('M12 22v-5'), P('M9 8V2'), P('M15 8V2'), P('M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z')],
  folder: [P('M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z')],
  hash: [P('M4 9h16'), P('M4 15h16'), P('M10 3 8 21'), P('M16 3l-2 18')],
  eye: [P('M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0'), C(12, 12, 3)],
  clock: [C(12, 12, 10), P('M12 6v6l4 2')],
  bold: [P('M6 12h9a4 4 0 0 1 0 8H7a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h7a4 4 0 0 1 0 8')],
  italic: [P('M19 4h-9'), P('M14 20H5'), P('M15 4 9 20')],
  heading: [P('M6 12h12'), P('M6 20V4'), P('M18 20V4')],
  list: [P('M3 12h.01'), P('M3 18h.01'), P('M3 6h.01'), P('M8 12h13'), P('M8 18h13'), P('M8 6h13')],
  listOrdered: [P('M10 12h11'), P('M10 18h11'), P('M10 6h11'), P('M4 10h2'), P('M4 6h1v4'), P('M6 18H4c0-1 2-2 2-3s-1-1.5-2-1')],
  listChecks: [P('m3 17 2 2 4-4'), P('m3 7 2 2 4-4'), P('M13 6h8'), P('M13 12h8'), P('M13 18h8')],
  quote: [P('M16 3a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2 1 1 0 0 1 1 1v1a2 2 0 0 1-2 2 1 1 0 0 0-1 1v2a1 1 0 0 0 1 1 6 6 0 0 0 6-6V5a2 2 0 0 0-2-2z'), P('M5 3a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2 1 1 0 0 1 1 1v1a2 2 0 0 1-2 2 1 1 0 0 0-1 1v2a1 1 0 0 0 1 1 6 6 0 0 0 6-6V5a2 2 0 0 0-2-2z')],
  code: [P('m16 18 6-6-6-6'), P('m8 6-6 6 6 6')],
  table: [P('M12 3v18'), R(3, 3, 18, 18), P('M3 9h18'), P('M3 15h18')],
  minus: [P('M5 12h14')],
  compare: [C(18, 18, 3), C(6, 6, 3), P('M13 6h3a2 2 0 0 1 2 2v7'), P('M11 18H8a2 2 0 0 1-2-2V9')],
  refresh: [P('M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8'), P('M21 3v5h-5'), P('M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16'), P('M8 16H3v5')],
  download: [P('M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'), P('m7 10 5 5 5-5'), P('M12 15V3')],
  keyboard: [P('M10 8h.01'), P('M12 12h.01'), P('M14 8h.01'), P('M16 12h.01'), P('M18 8h.01'), P('M6 8h.01'), P('M7 16h10'), P('M8 12h.01'), R(2, 4, 20, 16)],
  checkCircle: [C(12, 12, 10), P('m9 12 2 2 4-4')],
  circleDashed: [P('M10.1 2.182a10 10 0 0 1 3.8 0'), P('M13.9 21.818a10 10 0 0 1-3.8 0'), P('M17.609 3.721a10 10 0 0 1 2.69 2.7'), P('M2.182 13.9a10 10 0 0 1 0-3.8'), P('M20.279 17.609a10 10 0 0 1-2.7 2.69'), P('M21.818 10.1a10 10 0 0 1 0 3.8'), P('M3.721 6.391a10 10 0 0 1 2.7-2.69'), P('M6.391 20.279a10 10 0 0 1-2.69-2.7')],
  layers: [P('M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z'), P('M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12'), P('M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17')],
};

/** An inline SVG icon. Decorative unless `label` is given. */
export function icon(name, { size = 16, label, cls } = {}) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('class', 'icon' + (cls ? ' ' + cls : ''));
  if (label) {
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', label);
  } else {
    svg.setAttribute('aria-hidden', 'true');
  }
  for (const [tag, attrs] of ICONS[name] || ICONS.info) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.appendChild(el);
  }
  return svg;
}

// ---------------------------------------------------------------------------
// Small building blocks.

/** A button. `variant`: primary, ghost, danger, subtle. */
export function button(label, { icon: iconName, variant, size, onClick, title, type = 'button', cls, ...rest } = {}) {
  const classes = ['btn', variant && `btn-${variant}`, size && `btn-${size}`, !label && 'btn-icon', cls];
  const b = h('button', { type, class: classes, title: title || (!label ? rest['aria-label'] : undefined), ...rest });
  if (iconName) b.appendChild(icon(iconName));
  if (label) b.appendChild(h('span', null, label));
  if (onClick) b.addEventListener('click', onClick);
  return b;
}

/** Runs an async action while showing a busy state on a button. */
export async function busy(btn, fn) {
  if (btn.disabled) return undefined;
  btn.disabled = true;
  btn.setAttribute('aria-busy', 'true');
  try {
    return await fn();
  } finally {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
  }
}

export function badge(label, variant, { title, iconName } = {}) {
  return h('span', { class: ['badge', variant && `badge-${variant}`], title }, iconName ? icon(iconName, { size: 12 }) : null, label);
}

export function kbd(...keys) {
  return h('span', { class: 'kbds' }, keys.map((k) => h('kbd', null, k)));
}

export const isMac = /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);
export const modKey = isMac ? '⌘' : 'Ctrl';

function hueFor(s) {
  let x = 0;
  for (const ch of String(s || '')) x = (x * 31 + ch.charCodeAt(0)) >>> 0;
  return x % 360;
}

function initials(name) {
  const parts = String(name || '?').trim().split(/\s+/).filter(Boolean);
  const first = parts[0] ? [...parts[0]][0] : '?';
  const last = parts.length > 1 ? [...parts[parts.length - 1]][0] : '';
  return (first + last).toUpperCase();
}

/** A user avatar: their image, or initials on a color derived from their id. */
export function avatar(user, size = 'sm') {
  const u = user || { name: '?' };
  const wrap = h('span', { class: ['avatar', `avatar-${size}`, u.is_bot && 'avatar-bot'], style: { '--h': String(hueFor(u.id || u.name)) }, 'aria-hidden': 'true' });
  if (u.avatar_url) {
    const img = h('img', { src: u.avatar_url, alt: '', loading: 'lazy', referrerpolicy: 'no-referrer' });
    img.addEventListener('error', () => img.replaceWith(document.createTextNode(initials(u.name))));
    wrap.appendChild(img);
  } else {
    wrap.textContent = initials(u.name);
  }
  return wrap;
}

/** Avatar plus linked name, with a bot badge for agent accounts. */
export function userLink(user, { withAvatar = true, size = 'xs' } = {}) {
  if (!user) return h('span', { class: 'muted' }, 'Unknown');
  return h('a', { class: 'user-link', href: `/u/${encodeURIComponent(user.handle)}` },
    withAvatar ? avatar(user, size) : null,
    h('span', { class: 'user-link-name' }, user.name),
    user.is_bot ? badge('Bot', 'bot', { title: 'Agent or integration account' }) : null);
}

/** Path (plus search and hash) of an absolute URL from the API, so links route in-app. */
export function urlPath(url) {
  if (!url) return '/';
  try {
    const u = new URL(url, location.origin);
    return u.pathname + u.search + u.hash;
  } catch {
    return url;
  }
}

export function topicIcon(topic, size = 'sm') {
  if (topic.icon) return h('span', { class: ['topic-icon', `topic-icon-${size}`], 'aria-hidden': 'true' }, topic.icon);
  return h('span', { class: ['topic-icon', 'topic-dot', `topic-icon-${size}`], style: topic.color ? { '--c': topic.color } : undefined, 'aria-hidden': 'true' });
}

export function topicChip(topic) {
  return h('a', { class: 'chip', href: urlPath(topic.url) || `/t/${topic.id}` }, topicIcon(topic, 'xs'), h('span', null, topic.name));
}

export function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + 's'}`;
}

// ---------------------------------------------------------------------------
// Time.

const dateFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
const dateYearFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
const absFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });

export function absTime(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '' : absFmt.format(d);
}

export function relTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const diff = (Date.now() - d.getTime()) / 1000;
  const abs = Math.abs(diff);
  const fmt = (n, unit) => (diff >= 0 ? `${n}${unit} ago` : `in ${n}${unit}`);
  if (abs < 45) return diff >= 0 ? 'just now' : 'in a moment';
  if (abs < 3600) return fmt(Math.max(1, Math.round(abs / 60)), 'm');
  if (abs < 86400) return fmt(Math.round(abs / 3600), 'h');
  if (abs < 86400 * 7) return fmt(Math.round(abs / 86400), 'd');
  return d.getFullYear() === new Date().getFullYear() ? dateFmt.format(d) : dateYearFmt.format(d);
}

/** A <time> element showing relative time, with the absolute time on hover. */
export function timeEl(iso, { prefix } = {}) {
  if (!iso) return null;
  return h('time', { datetime: iso, title: absTime(iso), dataset: { rel: '1', prefix: prefix || '' } }, (prefix || '') + relTime(iso));
}

setInterval(() => {
  for (const t of document.querySelectorAll('time[data-rel]')) {
    t.textContent = (t.dataset.prefix || '') + relTime(t.getAttribute('datetime'));
  }
}, 60_000);

// ---------------------------------------------------------------------------
// Feedback: toasts, empty states, loading.

export function toast(message, { type = 'success', action, duration } = {}) {
  const host = document.getElementById('toasts');
  if (!host) return;
  const iconName = type === 'error' ? 'alert' : type === 'info' ? 'info' : 'checkCircle';
  const el = h('div', { class: ['toast', `toast-${type}`], role: type === 'error' ? 'alert' : 'status' },
    icon(iconName, { size: 16 }),
    h('span', { class: 'toast-msg' }, message));
  let timer;
  const close = () => {
    clearTimeout(timer);
    el.classList.add('toast-out');
    setTimeout(() => el.remove(), 180);
  };
  if (action) {
    el.appendChild(button(action.label, { variant: 'link', size: 'sm', onClick: () => { close(); action.onClick(); } }));
  }
  el.appendChild(button('', { icon: 'x', variant: 'ghost', size: 'xs', 'aria-label': 'Dismiss', onClick: close }));
  host.appendChild(el);
  timer = setTimeout(close, duration || (type === 'error' ? 7000 : action ? 6500 : 4000));
  el.addEventListener('mouseenter', () => clearTimeout(timer));
  el.addEventListener('mouseleave', () => { timer = setTimeout(close, 2500); });
}

export function toastError(err, prefix) {
  const msg = err && err.message ? err.message : String(err);
  toast(prefix ? `${prefix}: ${msg}` : msg, { type: 'error' });
}

export function emptyState({ iconName = 'file', title, body, action } = {}) {
  return h('div', { class: 'empty' },
    h('div', { class: 'empty-icon' }, icon(iconName, { size: 22 })),
    title ? h('p', { class: 'empty-title' }, title) : null,
    body ? h('p', { class: 'empty-body' }, body) : null,
    action || null);
}

export function spinner(label = 'Loading') {
  return h('span', { class: 'spinner', role: 'status', 'aria-label': label });
}

export function loadingView() {
  return h('div', { class: 'page page-loading', 'aria-busy': 'true' },
    h('div', { class: 'skeleton skeleton-title' }),
    h('div', { class: 'skeleton skeleton-line' }),
    h('div', { class: 'skeleton skeleton-line short' }),
    h('div', { class: 'skeleton skeleton-line' }));
}

// ---------------------------------------------------------------------------
// Dialogs (native <dialog>, so focus trapping and Escape come for free).

/**
 * Opens a modal. `actions`: [{ label, variant, onClick(close) }]. The action marked `primary`
 * (or the first with variant primary/danger) is the form's submit, so Enter triggers it.
 * An onClick that returns false keeps the dialog open.
 */
export function modal({ title, content, actions = [], size, onClose, cls } = {}) {
  const dialog = h('dialog', { class: ['modal', size && `modal-${size}`, cls], 'aria-labelledby': 'modal-title-' + Math.random().toString(36).slice(2) });
  const titleId = dialog.getAttribute('aria-labelledby');
  const form = h('form', { class: 'modal-form', method: 'dialog', novalidate: true });
  const closeBtn = button('', { icon: 'x', variant: 'ghost', size: 'sm', 'aria-label': 'Close', onClick: () => close() });
  form.appendChild(h('header', { class: 'modal-head' }, h('h2', { id: titleId, class: 'modal-title' }, title || ''), closeBtn));
  const body = h('div', { class: 'modal-body' }, content);
  form.appendChild(body);
  const footer = h('footer', { class: 'modal-foot' });
  let submitAction = actions.find((a) => a.primary) || actions.find((a) => a.variant === 'primary' || a.variant === 'danger');
  for (const a of actions) {
    const isSubmit = a === submitAction;
    const b = button(a.label, { variant: a.variant || 'ghost', type: isSubmit ? 'submit' : 'button', icon: a.icon });
    if (!isSubmit) b.addEventListener('click', () => run(a, b));
    else submitAction = { ...a, btn: b };
    footer.appendChild(b);
  }
  if (actions.length) form.appendChild(footer);
  dialog.appendChild(form);

  let closed = false;
  function close(result) {
    if (closed) return;
    closed = true;
    dialog.close();
    dialog.remove();
    if (onClose) onClose(result);
  }
  async function run(a, b) {
    if (!a.onClick) return close();
    try {
      const r = await busy(b, () => a.onClick(close));
      if (r !== false) close(r);
    } catch (e) {
      toastError(e);
    }
  }
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!submitAction) return;
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    run(submitAction, submitAction.btn);
  });
  dialog.addEventListener('cancel', (e) => {
    e.preventDefault();
    close();
  });
  dialog.addEventListener('mousedown', (e) => {
    if (e.target === dialog) close();
  });
  document.body.appendChild(dialog);
  dialog.showModal();
  // Focus the first field; with no fields, the safe primary action (or Cancel before a destructive one).
  const first = body.querySelector('input:not([type=hidden]):not([disabled]), textarea, select');
  if (first) first.focus();
  else if (submitAction && submitAction.btn && submitAction.variant !== 'danger') submitAction.btn.focus();
  else {
    const safe = footer.querySelector('.btn-ghost');
    if (safe) safe.focus();
  }
  return { dialog, body, close };
}

export function confirmDialog({ title, message, confirmLabel = 'Confirm', danger = false, cancelLabel = 'Cancel' }) {
  return new Promise((resolve) => {
    let result = false;
    modal({
      title,
      size: 'sm',
      content: h('p', { class: 'modal-text' }, message),
      actions: [
        { label: cancelLabel, variant: 'ghost' },
        { label: confirmLabel, variant: danger ? 'danger' : 'primary', onClick: () => { result = true; } },
      ],
      onClose: () => resolve(result),
    });
  });
}

/** Shows a secret exactly once, with a copy button. */
export function secretDialog({ title, intro, secret, extra }) {
  return new Promise((resolve) => {
    modal({
      title,
      content: frag(
        intro ? h('p', { class: 'modal-text' }, intro) : null,
        copyField(secret, { label: 'Secret' }),
        h('p', { class: 'callout callout-warn' }, icon('alert', { size: 15 }), h('span', null, 'Copy it now. It won’t be shown again.')),
        extra || null,
      ),
      actions: [{ label: 'Done', variant: 'primary' }],
      onClose: resolve,
    });
  });
}

// ---------------------------------------------------------------------------
// Floating layers: menus and popovers anchored to an element.

let openLayer = null;

export function closeLayers() {
  if (openLayer) openLayer.close();
}

function positionLayer(layer, anchor, { align = 'start', placement = 'bottom', rect } = {}) {
  const r = rect || anchor.getBoundingClientRect();
  layer.style.visibility = 'hidden';
  layer.style.left = '0px';
  layer.style.top = '0px';
  const lw = layer.offsetWidth;
  const lh = layer.offsetHeight;
  const vw = document.documentElement.clientWidth;
  const vh = window.innerHeight;
  let left = align === 'end' ? r.right - lw : align === 'center' ? r.left + r.width / 2 - lw / 2 : r.left;
  left = Math.max(8, Math.min(left, vw - lw - 8));
  let top = placement === 'top' ? r.top - lh - 6 : r.bottom + 6;
  if (placement !== 'top' && top + lh > vh - 8 && r.top - lh - 6 > 8) top = r.top - lh - 6;
  if (placement === 'top' && top < 8) top = r.bottom + 6;
  layer.style.left = `${left + window.scrollX}px`;
  layer.style.top = `${top + window.scrollY}px`;
  layer.style.visibility = '';
}

/** Opens a floating panel next to `anchor`. Returns { el, close }. */
export function openPopover(anchor, content, { align, placement, cls, onClose, rect, label } = {}) {
  closeLayers();
  const el = h('div', { class: ['popover', cls], role: 'dialog', 'aria-label': label }, content);
  document.body.appendChild(el);
  positionLayer(el, anchor, { align, placement, rect });
  if (anchor && anchor.setAttribute) anchor.setAttribute('aria-expanded', 'true');
  const onDown = (e) => {
    if (!el.contains(e.target) && !(anchor && anchor.contains && anchor.contains(e.target))) close();
  };
  const onKey = (e) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      close();
      if (anchor && anchor.focus) anchor.focus();
    }
  };
  const onResize = () => close();
  setTimeout(() => document.addEventListener('mousedown', onDown), 0);
  document.addEventListener('keydown', onKey, true);
  window.addEventListener('resize', onResize);
  let closed = false;
  function close() {
    if (closed) return;
    closed = true;
    document.removeEventListener('mousedown', onDown);
    document.removeEventListener('keydown', onKey, true);
    window.removeEventListener('resize', onResize);
    if (anchor && anchor.setAttribute) anchor.setAttribute('aria-expanded', 'false');
    el.remove();
    if (openLayer && openLayer.el === el) openLayer = null;
    if (onClose) onClose();
  }
  openLayer = { el, close, reposition: () => positionLayer(el, anchor, { align, placement, rect }) };
  return openLayer;
}

/**
 * Opens a menu. Items: { label, icon, onClick, danger, checked, disabled, hint } | 'separator' | { heading }.
 */
export function openMenu(anchor, items, { align = 'start', placement } = {}) {
  const list = h('div', { class: 'menu', role: 'menu' });
  const buttons = [];
  for (const it of items) {
    if (!it) continue;
    if (it === 'separator') {
      list.appendChild(h('div', { class: 'menu-sep', role: 'separator' }));
      continue;
    }
    if (it.heading) {
      list.appendChild(h('div', { class: 'menu-heading' }, it.heading));
      continue;
    }
    const b = h('button', {
      type: 'button',
      class: ['menu-item', it.danger && 'menu-item-danger'],
      role: it.checked !== undefined ? 'menuitemradio' : 'menuitem',
      'aria-checked': it.checked !== undefined ? String(!!it.checked) : undefined,
      disabled: it.disabled,
      tabindex: '-1',
    },
    h('span', { class: 'menu-icon' }, it.icon ? icon(it.icon) : it.checked ? icon('check') : null),
    h('span', { class: 'menu-label' }, it.label),
    it.hint ? h('span', { class: 'menu-hint' }, it.hint) : null);
    b.addEventListener('click', () => {
      layer.close();
      if (anchor && anchor.focus) anchor.focus({ preventScroll: true });
      if (it.onClick) Promise.resolve(it.onClick()).catch(toastError);
    });
    buttons.push(b);
    list.appendChild(b);
  }
  const layer = openPopover(anchor, list, { align, placement, cls: 'popover-menu' });
  layer.el.setAttribute('role', 'presentation');
  layer.el.removeAttribute('aria-label');
  if (anchor && anchor.setAttribute) anchor.setAttribute('aria-haspopup', 'menu');
  const enabled = () => buttons.filter((b) => !b.disabled);
  const focusAt = (i) => {
    const e = enabled();
    if (!e.length) return;
    e[(i + e.length) % e.length].focus();
  };
  list.addEventListener('keydown', (e) => {
    const e2 = enabled();
    const i = e2.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); focusAt(i + 1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); focusAt(i - 1); }
    else if (e.key === 'Home') { e.preventDefault(); focusAt(0); }
    else if (e.key === 'End') { e.preventDefault(); focusAt(-1); }
    else if (e.key === 'Tab') layer.close();
  });
  focusAt(0);
  return layer;
}

/** A button that opens a menu built on demand. */
export function menuButton(items, { label = '', iconName = 'more', variant = 'ghost', size, align = 'end', ariaLabel = 'More actions', cls } = {}) {
  const b = button(label, { icon: iconName, variant, size, 'aria-label': label ? undefined : ariaLabel, 'aria-haspopup': 'menu', 'aria-expanded': 'false', cls });
  b.addEventListener('click', () => {
    if (b.getAttribute('aria-expanded') === 'true') return closeLayers();
    openMenu(b, typeof items === 'function' ? items() : items, { align });
  });
  return b;
}

// ---------------------------------------------------------------------------
// Forms and clipboard.

let fieldSeq = 0;

/** A labelled form field. `control` is an input/select/textarea element. */
export function field(label, control, { hint, cls } = {}) {
  const id = control.id || `f${++fieldSeq}`;
  control.id = id;
  const hintId = hint ? `${id}-hint` : undefined;
  if (hintId) control.setAttribute('aria-describedby', hintId);
  return h('div', { class: ['field', cls] },
    h('label', { class: 'field-label', for: id }, label),
    control,
    hint ? h('p', { class: 'field-hint', id: hintId }, hint) : null);
}

export function input(props = {}) {
  return h('input', { class: 'input', type: 'text', autocomplete: 'off', ...props });
}

export function textarea(props = {}) {
  return h('textarea', { class: 'input textarea', ...props });
}

export function select(options, props = {}) {
  const s = h('select', { class: 'input select', ...props });
  for (const o of options) {
    const opt = h('option', { value: o.value }, o.label);
    if (o.selected) opt.selected = true;
    if (o.disabled) opt.disabled = true;
    s.appendChild(opt);
  }
  return s;
}

export function checkbox(label, props = {}) {
  return h('label', { class: 'check' }, h('input', { type: 'checkbox', ...props }), h('span', null, label));
}

export async function copyText(text, what = 'Copied to clipboard') {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = h('textarea', { class: 'sr-only', 'aria-hidden': 'true' });
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
    } finally {
      ta.remove();
    }
  }
  toast(what);
}

/** A read-only value with a copy button. */
export function copyField(value, { label = 'Value', multiline = false } = {}) {
  const valueEl = multiline ? h('pre', { class: 'copy-value copy-pre' }, value) : h('code', { class: 'copy-value' }, value);
  const b = button('Copy', { icon: 'copy', size: 'sm', variant: 'subtle', 'aria-label': `Copy ${label.toLowerCase()}` });
  b.addEventListener('click', () => copyText(typeof value === 'function' ? value() : valueEl.textContent));
  return h('div', { class: ['copy-field', multiline && 'copy-field-multi'] }, valueEl, b);
}

export function debounce(fn, ms) {
  let t;
  const d = (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
  d.cancel = () => clearTimeout(t);
  d.flush = (...args) => {
    clearTimeout(t);
    fn(...args);
  };
  return d;
}

/** True when keyboard focus is in a text field, so single-key shortcuts should stay quiet. */
export function isTyping(el = document.activeElement) {
  if (!el) return false;
  const tag = el.tagName;
  if (tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if (tag === 'INPUT') return !['checkbox', 'radio', 'button', 'submit'].includes(el.type);
  return el.isContentEditable;
}

export function setTheme(pref) {
  try {
    localStorage.setItem('ds-theme', pref);
  } catch {
    /* storage unavailable */
  }
  if (window.__dsApplyTheme) window.__dsApplyTheme();
}

export function themePref() {
  return document.documentElement.dataset.themePref || 'system';
}

/** Page header with a serif title, optional description and actions. */
export function pageHeader(title, { description, actions, eyebrow } = {}) {
  return h('header', { class: 'page-head' },
    h('div', { class: 'page-head-text' },
      eyebrow || null,
      h('h1', { class: 'page-title' }, title),
      description ? h('p', { class: 'page-desc' }, description) : null),
    actions ? h('div', { class: 'page-actions' }, actions) : null);
}
