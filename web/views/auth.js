// First-run setup and sign-in. These render without the app shell.

import { api } from '/api.js';
import { h, icon, field, input, button, busy } from '/ui.js';
import { safeNext } from '/state.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

/** A provider's own mark, as its sign-in buttons should show it: Google's "G", Microsoft's squares. */
export function providerMark(provider, size = 18) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', 'provider-mark');
  const add = (tag, attrs) => {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    svg.appendChild(el);
  };
  if (provider === 'google') {
    svg.setAttribute('viewBox', '0 0 48 48');
    add('path', { fill: '#EA4335', d: 'M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z' });
    add('path', { fill: '#4285F4', d: 'M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z' });
    add('path', { fill: '#FBBC05', d: 'M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z' });
    add('path', { fill: '#34A853', d: 'M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z' });
  } else if (provider === 'microsoft') {
    svg.setAttribute('viewBox', '0 0 21 21');
    add('rect', { x: 1, y: 1, width: 9, height: 9, fill: '#F25022' });
    add('rect', { x: 11, y: 1, width: 9, height: 9, fill: '#7FBA00' });
    add('rect', { x: 1, y: 11, width: 9, height: 9, fill: '#00A4EF' });
    add('rect', { x: 11, y: 11, width: 9, height: 9, fill: '#FFB900' });
  } else {
    return icon('lock', { size: 15 });
  }
  return svg;
}

/** "Continue with Google": a link when `href` is given, otherwise a button that runs `onClick`. */
function providerButton(option, { href, onClick } = {}) {
  const content = [providerMark(option.provider), h('span', null, `Continue with ${option.name}`)];
  if (href) return h('a', { class: 'btn btn-provider btn-block', href }, ...content);
  const b = h('button', { type: 'button', class: 'btn btn-provider btn-block' }, ...content);
  b.addEventListener('click', onClick);
  return b;
}

/** The provider a sign-in that came back with an error was with (`?with=`), for its message. */
function providerName(params, options) {
  const w = params.get('with');
  const o = (options || []).find((x) => x.provider === w);
  return o ? o.name : { google: 'Google', microsoft: 'Microsoft' }[w] || null;
}

function card(title, sub, form, foot) {
  return h('div', { class: 'auth-wrap' },
    h('main', { class: 'auth-card', id: 'main', tabindex: '-1' },
      h('img', { src: '/favicon.svg', alt: '', width: 40, height: 40, class: 'auth-mark' }),
      h('h1', { class: 'auth-title' }, title),
      sub ? h('p', { class: 'auth-sub' }, sub) : null,
      form,
      foot || null));
}

function errorBox() {
  return h('p', { class: 'form-error', role: 'alert', hidden: true });
}

function showError(box, err) {
  box.hidden = false;
  box.replaceChildren(icon('alert', { size: 15 }), h('span', null, err.message || String(err)));
}

export function renderSetup(root, authState) {
  document.title = 'Set up DumbSlab';
  const params = new URLSearchParams(location.search);
  // On hosted DumbSlab, an address nobody has signed up for has nothing to set up.
  if (authState.exists === false && !params.get('token')) {
    const link = h('a', { class: 'btn btn-primary btn-block', href: authState.signup_url || '/' }, 'Create a workspace');
    root.replaceChildren(card('There’s no workspace here', `Nobody has created ${location.hostname} yet. You can claim it for free.`, link));
    return;
  }
  const ws = input({ name: 'workspace_name', required: true, value: params.get('name') || 'DumbSlab', autocomplete: 'organization' });
  // Creating it with Google or Microsoft instead of a password, when the server has their apps.
  const providers = authState.sign_up_with || [];
  const name = input({ name: 'name', required: true, autocomplete: 'name' });
  const email = input({ name: 'email', type: 'email', required: true, autocomplete: 'email' });
  const password = input({ name: 'password', type: 'password', required: true, minlength: 8, autocomplete: 'new-password' });
  const token = input({ name: 'setup_token', value: params.get('token') || '', autocomplete: 'off', spellcheck: 'false' });
  const err = errorBox();
  const submit = button('Create workspace', { variant: 'primary', type: 'submit', cls: 'btn-block' });
  const form = h('form', { class: 'auth-form', novalidate: true },
    providers.length ? null : field('Workspace name', ws),
    field('Your name', name),
    field('Email', email),
    field('Password', password, { hint: 'At least 8 characters.' }),
    // A sign-up link carries its token; only self-hosted setups ask for one.
    authState.setup_requires_token && !params.get('token')
      ? field('Setup token', token, { hint: 'Printed in the server log when it started, or your deployment’s SETUP_TOKEN secret.' })
      : null,
    err,
    submit);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    err.hidden = true;
    busy(submit, async () => {
      try {
        await api.post('/auth/setup', {
          workspace_name: ws.value.trim(),
          name: name.value.trim(),
          email: email.value.trim(),
          password: password.value,
          setup_token: authState.setup_requires_token ? token.value.trim() : undefined,
        }, { redirectOn401: false });
        location.href = '/';
      } catch (ex) {
        showError(err, ex);
      }
    });
  });
  let body = form;
  if (providers.length) {
    const top = errorBox();
    const code = params.get('sso_error');
    if (code) showError(top, ssoMessage(code, providerName(params, providers), { signup: true }));
    const start = (p) => () => {
      if (!ws.value.trim()) {
        ws.reportValidity();
        ws.focus();
        return;
      }
      const q = new URLSearchParams({ signup: '1', with: p.provider, token: params.get('token') || token.value.trim(), name: ws.value.trim() });
      location.assign(`/sso/start?${q}`);
    };
    body = h('div', { class: 'auth-sso' },
      top,
      field('Workspace name', ws),
      ...providers.map((p) => providerButton(p, { onClick: start(p) })),
      h('p', { class: 'auth-or' }, 'or use email and a password'),
      form);
  }
  root.replaceChildren(card('Set up your knowledge base', 'Create the first admin account. You can invite people and connect agents afterwards.', body));
  ws.focus();
  ws.select();
}

/**
 * What a single sign-on that didn't work comes back with: `?sso_error=` holds only a code, and
 * the message is ours, so a link to the sign-in page can't make it say anything else.
 */
export function ssoMessage(code, name, { signup = false } = {}) {
  const p = name || 'single sign-on';
  if (signup && code === 'unverified_email') return `${p} didn’t confirm that account’s email address. Use another account, or set up with email and a password.`;
  if (signup && code === 'expired') return 'This sign-up link expired or was already used. Start again from the sign-up page.';
  const messages = {
    not_configured: 'Single sign-on isn’t set up for this workspace.',
    expired: 'That sign-in link expired or was already used. Sign in again.',
    other_browser: 'Start signing in from this browser’s sign-in page, then try again.',
    denied: `You didn’t finish signing in with ${p}.`,
    provider_error: `${p} couldn’t sign you in. Try again; if it keeps happening, a workspace admin can check Settings › Single sign-on.`,
    invalid_token: `${p}’s answer didn’t check out. Sign in again.`,
    not_in_org: `Use your organization’s ${p} account.`,
    unverified_email: `${p} didn’t confirm your email address, so it can’t be matched to an account here. Sign in with your password and link ${p} in Settings › Profile, or ask a workspace admin.`,
    domain_not_allowed: 'Your email address isn’t at one of this workspace’s sign-in domains. Ask a workspace admin to add you.',
    no_account: 'No one here has your email address. Ask a workspace admin to add you.',
    deactivated: 'Your account here is deactivated. Ask a workspace admin to reactivate it.',
    bot: 'Bot accounts sign in with API tokens, not single sign-on.',
    email_linked: `Your email address is linked to a different ${p} account here. Ask a workspace admin to unlink it.`,
    other_session: 'Finish linking in the same signed-in browser you started in. Start again from Settings › Profile.',
    already_linked: `That ${p} account is already linked to someone else here.`,
    admin_consent: `Your organization needs an administrator to approve DumbSlab in ${p} before you can sign in with it. Ask your IT admin, or sign in with your password.`,
    personal_account: `Use your organization’s ${p} account, not a personal one.`,
    not_admin: 'Only workspace admins can set up single sign-on.',
    unavailable: 'Signing in with that provider isn’t available on this server any more.',
    already_set_up: 'This workspace is already set up. Sign in instead.',
  };
  return Object.hasOwn(messages, code) ? messages[code] : `Signing in with ${p} didn’t work. Try again or use your password.`;
}

export function renderLogin(root, authState) {
  document.title = `Sign in - ${authState.workspace_name}`;
  const params = new URLSearchParams(location.search);
  // Signing in with the workspace's identity provider, when it's set up.
  const sso = authState.sso;
  const email = input({ name: 'email', type: 'email', required: true, autocomplete: 'username' });
  const password = input({ name: 'password', type: 'password', required: true, autocomplete: 'current-password' });
  const err = errorBox();
  const submit = button('Sign in', { variant: sso ? 'subtle' : 'primary', type: 'submit', cls: 'btn-block' });
  const form = h('form', { class: 'auth-form', novalidate: true }, field('Email', email), field('Password', password), err, submit);
  // A sign-in with the provider that didn't work comes back here with a code saying why.
  // Signing in with your own Google or Microsoft account, when the workspace has no SSO of its own.
  const providers = sso ? [] : (authState.sign_in_with || []);
  const ssoError = params.get('sso_error') ? ssoMessage(params.get('sso_error'), sso ? sso.name : providerName(params, providers)) : null;
  if (ssoError && !sso) showError(err, ssoError);
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    err.hidden = true;
    busy(submit, async () => {
      try {
        await api.post('/auth/login', { email: email.value.trim(), password: password.value }, { redirectOn401: false });
        // A full navigation: `next` may be a server route such as /oauth/authorize.
        location.href = safeNext(params.get('next')) || '/';
      } catch (ex) {
        showError(err, ex);
        password.select();
      }
    });
  });
  const isOauth = (params.get('next') || '').startsWith('/oauth/');
  let body = form;
  let first = email;
  if (providers.length) {
    const next = safeNext(params.get('next'));
    const buttons = providers.map((p) => providerButton(p, { href: p.url + (next ? `&next=${encodeURIComponent(next)}` : '') }));
    body = h('div', { class: 'auth-sso' }, ...buttons, h('p', { class: 'auth-or' }, 'or'), form);
  }
  if (sso) {
    const next = safeNext(params.get('next'));
    const ssoLink = h('a', { class: 'btn btn-primary btn-block', href: sso.url + (next ? `?next=${encodeURIComponent(next)}` : '') },
      icon('lock', { size: 15 }), h('span', null, `Sign in with ${sso.name}`));
    const ssoBox = errorBox();
    if (ssoError) showError(ssoBox, ssoError);
    if (sso.required) {
      // Only admins sign in with a password here, in case the provider is down.
      form.hidden = true;
      const reveal = button('Admins: sign in with a password', { variant: 'ghost', size: 'sm', cls: 'btn-block' });
      reveal.addEventListener('click', () => { form.hidden = false; reveal.remove(); email.focus(); });
      body = h('div', { class: 'auth-sso' }, ssoBox, ssoLink, reveal, form);
    } else {
      body = h('div', { class: 'auth-sso' }, ssoBox, ssoLink, h('p', { class: 'auth-or' }, 'or'), form);
    }
    first = ssoLink;
  }
  root.replaceChildren(card(
    `Sign in to ${authState.workspace_name}`,
    isOauth ? 'Sign in to let an app connect to your knowledge base.' : null,
    body,
    h('p', { class: 'auth-foot' }, sso && sso.required
      ? `Sign in with ${sso.name}. Admins can also use their password.`
      : 'Forgot your password? Ask a workspace admin to set a new one.')));
  first.focus();
}
