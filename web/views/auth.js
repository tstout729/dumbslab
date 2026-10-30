// First-run setup and sign-in. These render without the app shell.

import { api } from '/api.js';
import { h, icon, field, input, button, busy } from '/ui.js';
import { safeNext } from '/state.js';

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
  const name = input({ name: 'name', required: true, autocomplete: 'name' });
  const email = input({ name: 'email', type: 'email', required: true, autocomplete: 'email' });
  const password = input({ name: 'password', type: 'password', required: true, minlength: 8, autocomplete: 'new-password' });
  const token = input({ name: 'setup_token', value: params.get('token') || '', autocomplete: 'off', spellcheck: 'false' });
  const err = errorBox();
  const submit = button('Create workspace', { variant: 'primary', type: 'submit', cls: 'btn-block' });
  const form = h('form', { class: 'auth-form', novalidate: true },
    field('Workspace name', ws),
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
  root.replaceChildren(card('Set up your knowledge base', 'Create the first admin account. You can invite people and connect agents afterwards.', form));
  ws.focus();
  ws.select();
}

/**
 * What a single sign-on that didn't work comes back with: `?sso_error=` holds only a code, and
 * the message is ours, so a link to the sign-in page can't make it say anything else.
 */
export function ssoMessage(code, name) {
  const p = name || 'single sign-on';
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
  const ssoError = params.get('sso_error') ? ssoMessage(params.get('sso_error'), sso && sso.name) : null;
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
