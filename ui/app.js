'use strict';

// Web interface for the data server. It is a plain client of the HTTP API: every
// request carries the token in an Authorization header (no cookies, so no CSRF).
// All data is put into the page with textContent, never innerHTML.

const TOKEN_KEY = 'data-server-token';
const KEY_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;

const $ = (id) => document.getElementById(id);

let token = null;
let me = null;                          // answer of /api/whoami
let app = null;                         // the selected app
let rows = [];                          // last listing of the selected app
let sort = { col: 'key', dir: 'asc' };
let uploading = false;

function store(value) {
  try {
    if (value === null) sessionStorage.removeItem(TOKEN_KEY);
    else sessionStorage.setItem(TOKEN_KEY, value);
  } catch (e) { /* storage blocked: the token just won't survive a reload */ }
}

function savedToken() {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
}

function api(path, options) {
  const opts = options || {};
  const headers = Object.assign({}, opts.headers, { Authorization: 'Bearer ' + token });
  return fetch(path, Object.assign({}, opts, { headers }));
}

function keyPath(name, key) {
  return '/api/' + encodeURIComponent(name) + '/' + key.split('/').map(encodeURIComponent).join('/');
}

function formatSize(n) {
  if (n < 1024) return n + ' B';
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(v < 10 ? 1 : 0) + ' ' + units[i];
}

function toast(text, kind) {
  const el = document.createElement('div');
  el.className = 'toast' + (kind ? ' ' + kind : '');
  el.textContent = text;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), kind === 'error' ? 9000 : 4500);
}

// ----- login -----

async function signIn(candidate) {
  const res = await fetch('/api/whoami', { headers: { Authorization: 'Bearer ' + candidate } });
  if (!res.ok) return false;
  token = candidate;
  me = await res.json();
  store(candidate);
  showMain();
  return true;
}

function showLogin(message) {
  token = null;
  me = null;
  app = null;
  store(null);
  $('main-view').hidden = true;
  $('who').hidden = true;
  $('login-view').hidden = false;
  $('token').value = '';
  const err = $('login-error');
  err.hidden = !message;
  err.textContent = message || '';
}

function showMain() {
  $('login-view').hidden = true;
  $('main-view').hidden = false;
  $('who').hidden = false;
  $('who-badge').textContent = me.admin ? 'Admin' : 'App: ' + me.app;
  $('max-size').textContent = formatSize(me.max_body);
  app = me.apps.length > 0 ? me.apps[0] : null;
  renderTabs();
  $('system').hidden = !me.admin;
  if (me.admin) loadSystem();
  refresh();
}

function sessionExpired() { showLogin('The token is no longer accepted.'); }

// Apps can appear after sign-in (a token added to the apps file, a first upload), so
// Refresh re-reads the app list too.
async function reloadApps() {
  const res = await api('/api/whoami');
  if (res.status === 401) { sessionExpired(); return; }
  if (!res.ok) return;
  me = await res.json();
  if (!me.apps.includes(app)) app = me.apps.length > 0 ? me.apps[0] : null;
  renderTabs();
}

// ----- storage panel (admin) -----

async function loadSystem() {
  const res = await api('/api/system');
  if (res.status === 401) { sessionExpired(); return; }
  if (!res.ok) return;
  const info = await res.json();
  $('stored-text').textContent = formatSize(info.stored_bytes) + ' in ' + info.stored_files + (info.stored_files === 1 ? ' file' : ' files');

  const meter = $('disk-meter');
  meter.className = '';
  if (!info.disk) {
    $('disk-text').textContent = 'not available on this system';
    $('disk-free').textContent = '–';
    meter.value = 0;
    return;
  }
  const used = info.disk.total - info.disk.free;
  const percent = info.disk.total > 0 ? Math.round((used / info.disk.total) * 100) : 0;
  $('disk-text').textContent = formatSize(used) + ' used of ' + formatSize(info.disk.total) + ' (' + percent + '%)';
  $('disk-free').textContent = formatSize(info.disk.free);
  meter.value = percent;
  if (percent >= 95) meter.className = 'full';
  else if (percent >= 85) meter.className = 'warn';
}

// ----- apps and listing -----

function renderTabs() {
  const tabs = $('apps');
  tabs.textContent = '';
  for (const name of me.apps) {
    const tab = document.createElement('button');
    tab.type = 'button';
    tab.className = 'tab';
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', String(name === app));
    tab.textContent = name;
    tab.addEventListener('click', () => { app = name; renderTabs(); refresh(); });
    tabs.appendChild(tab);
  }
}

async function refresh() {
  rows = [];
  render();
  if (!app) { $('summary').textContent = 'No apps are configured yet.'; return; }
  $('summary').textContent = 'Loading…';
  const res = await api('/api/' + encodeURIComponent(app) + '?prefix=' + encodeURIComponent($('prefix').value));
  if (res.status === 401) { sessionExpired(); return; }
  if (!res.ok) { toast('Could not load the list (' + res.status + ').', 'error'); return; }
  rows = await res.json();
  render();
}

function sortedRows() {
  const { col, dir } = sort;
  const factor = dir === 'asc' ? 1 : -1;
  return rows.slice().sort((a, b) => {
    const x = a[col];
    const y = b[col];
    const order = typeof x === 'number' ? x - y : String(x).localeCompare(String(y));
    return order * factor || a.key.localeCompare(b.key);
  });
}

function cell(text, className) {
  const td = document.createElement('td');
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function button(label, className, onClick) {
  const b = document.createElement('button');
  b.type = 'button';
  b.textContent = label;
  b.className = 'btn small ' + className;
  b.addEventListener('click', onClick);
  return b;
}

function render() {
  for (const b of document.querySelectorAll('.sort')) {
    if (b.dataset.col === sort.col) b.dataset.dir = sort.dir;
    else delete b.dataset.dir;
  }
  const tbody = $('rows');
  tbody.textContent = '';
  for (const row of sortedRows()) tbody.appendChild(renderRow(row));

  $('empty').hidden = !app || rows.length > 0;
  if (app && rows.length > 0) {
    const total = rows.reduce((sum, r) => sum + r.size, 0);
    $('summary').textContent = rows.length + (rows.length === 1 ? ' file, ' : ' files, ') + formatSize(total);
  } else if (app) {
    $('summary').textContent = '';
  }
}

function renderRow(row) {
  const tr = document.createElement('tr');
  tr.appendChild(cell(row.key, 'key'));
  tr.appendChild(cell(formatSize(row.size), 'num'));
  tr.appendChild(cell(row.content_type, 'muted col-type'));
  tr.appendChild(cell(new Date(row.modified).toLocaleString(), 'muted col-date'));
  const actions = document.createElement('td');
  actions.className = 'actions';
  actions.appendChild(button('Download', 'ghost', () => download(row)));
  actions.appendChild(button('Delete', 'danger', () => remove(row)));
  tr.appendChild(actions);
  return tr;
}

// ----- download / delete -----

async function download(row) {
  const res = await api(keyPath(app, row.key));
  if (!res.ok) { toast('Download failed (' + res.status + ').', 'error'); return; }
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement('a');
  a.href = url;
  a.download = row.key.split('/').pop();
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function remove(row) {
  if (!window.confirm('Delete "' + row.key + '" from ' + app + '? This cannot be undone.')) return;
  // If-Match makes sure we only delete the version we are looking at.
  const res = await api(keyPath(app, row.key), { method: 'DELETE', headers: { 'If-Match': row.etag } });
  if (res.status === 412) {
    toast('"' + row.key + '" changed since the list was loaded; nothing was deleted.', 'error');
  } else if (!res.ok && res.status !== 404) {
    toast('Delete failed (' + res.status + ').', 'error');
    return;
  } else {
    toast('Deleted ' + row.key, 'ok');
  }
  await Promise.all([refresh(), me.admin ? loadSystem() : null]);
}

// ----- upload -----

function sendFile(name, key, file, headers, onProgress) {
  return new Promise((resolve) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', keyPath(name, key));
    xhr.setRequestHeader('Authorization', 'Bearer ' + token);
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
    for (const h of Object.keys(headers)) xhr.setRequestHeader(h, headers[h]);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onload = () => resolve(xhr.status);
    xhr.onerror = () => resolve(0);
    xhr.send(file);
  });
}

async function uploadOne(name, key, file) {
  const progress = $('progress');
  progress.hidden = false;
  progress.value = 0;
  const onProgress = (f) => { progress.value = Math.round(f * 100); };

  // Create-only first, so an upload can never silently replace something.
  let status = await sendFile(name, key, file, { 'If-None-Match': '*' }, onProgress);
  if (status === 412) {
    const head = await api(keyPath(name, key), { method: 'HEAD' });
    const etag = head.headers.get('ETag');
    if (!etag || !window.confirm('"' + key + '" already exists in ' + name + '. Overwrite it?')) {
      return 'skipped';
    }
    status = await sendFile(name, key, file, { 'If-Match': etag }, onProgress);
  }
  if (status === 200 || status === 201) return 'ok';
  if (status === 401) return 'auth';
  if (status === 413) return 'too large';
  if (status === 412) return 'changed meanwhile';
  if (status === 400) return 'invalid key';
  if (status === 409) return 'key clashes with another key';
  return status === 0 ? 'network error' : 'error ' + status;
}

function suggestKey(name) {
  return $('prefix').value + name.replace(/[^A-Za-z0-9._-]/g, '_');
}

function renderQueue() {
  const files = Array.from($('files').files);
  const list = $('queue');
  list.textContent = '';
  for (const file of files) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = file.name;
    const size = document.createElement('span');
    size.textContent = formatSize(file.size);
    li.appendChild(name);
    li.appendChild(size);
    list.appendChild(li);
  }
  const keyInput = $('key');
  keyInput.disabled = files.length > 1;
  keyInput.value = files.length === 1 ? suggestKey(files[0].name) : '';
}

async function upload() {
  if (uploading) return;
  const files = Array.from($('files').files);
  if (!app || files.length === 0) { toast('Choose an app tab and at least one file.', 'error'); return; }

  uploading = true;
  $('upload').disabled = true;
  let okCount = 0;
  const problems = [];
  for (const file of files) {
    const key = files.length === 1 && $('key').value ? $('key').value : suggestKey(file.name);
    if (!KEY_RE.test(key) || key.length > 512) { problems.push(key + ': invalid key'); continue; }
    if (file.size > me.max_body) { problems.push(key + ': larger than ' + formatSize(me.max_body)); continue; }
    const outcome = await uploadOne(app, key, file);
    if (outcome === 'auth') { uploading = false; $('upload').disabled = false; sessionExpired(); return; }
    if (outcome === 'ok') okCount++;
    else problems.push(key + ': ' + outcome);
  }
  uploading = false;
  $('upload').disabled = false;
  $('progress').hidden = true;
  $('files').value = '';
  renderQueue();
  if (okCount > 0) toast('Uploaded ' + okCount + (okCount === 1 ? ' file' : ' files'), 'ok');
  for (const p of problems) toast(p, 'error');
  await Promise.all([refresh(), me.admin ? loadSystem() : null]);
}

// ----- wiring -----

$('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const ok = await signIn($('token').value.trim());
  if (!ok) showLogin('That token was not accepted. (The admin token only works from allowed networks.)');
});

$('logout').addEventListener('click', () => showLogin(''));
$('refresh').addEventListener('click', async () => {
  await reloadApps();
  if (!me) return; // the token stopped working: back at the login page
  refresh();
  if (me.admin) loadSystem();
});
$('prefix').addEventListener('change', refresh);
$('upload').addEventListener('click', upload);
$('files').addEventListener('change', renderQueue);

for (const b of document.querySelectorAll('.sort')) {
  b.addEventListener('click', () => {
    const col = b.dataset.col;
    sort = { col, dir: sort.col === col && sort.dir === 'asc' ? 'desc' : 'asc' };
    render();
  });
}

const drop = $('drop');
for (const type of ['dragenter', 'dragover']) {
  drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.add('over'); });
}
for (const type of ['dragleave', 'drop']) {
  drop.addEventListener(type, (e) => { e.preventDefault(); drop.classList.remove('over'); });
}
drop.addEventListener('drop', (e) => {
  if (!e.dataTransfer || e.dataTransfer.files.length === 0) return;
  $('files').files = e.dataTransfer.files;
  renderQueue();
});

(async function start() {
  const saved = savedToken();
  if (saved && (await signIn(saved))) return;
  showLogin('');
})();
