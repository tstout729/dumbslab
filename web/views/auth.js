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

export function renderLogin(root, authState) {
  document.title = `Sign in - ${authState.workspace_name}`;
  const params = new URLSearchParams(location.search);
  const email = input({ name: 'email', type: 'email', required: true, autocomplete: 'username' });
  const password = input({ name: 'password', type: 'password', required: true, autocomplete: 'current-password' });
  const err = errorBox();
  const submit = button('Sign in', { variant: 'primary', type: 'submit', cls: 'btn-block' });
  const form = h('form', { class: 'auth-form', novalidate: true }, field('Email', email), field('Password', password), err, submit);
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
  root.replaceChildren(card(
    `Sign in to ${authState.workspace_name}`,
    isOauth ? 'Sign in to let an app connect to your knowledge base.' : null,
    form,
    h('p', { class: 'auth-foot' }, 'Forgot your password? Ask a workspace admin to set a new one.')));
  email.focus();
}
