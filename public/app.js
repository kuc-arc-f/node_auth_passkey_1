const { startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser;
const $ = (id) => document.getElementById(id);
const msg = (t) => ($('msg').textContent = t || '');

async function api(url, body) {
  const r = await fetch(url, {
    method: body === undefined && !url.includes('logout') ? 'GET' : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
  return data;
}

async function register(username) {
  const optionsJSON = await api('/api/register/options', { username });
  const att = await startRegistration({ optionsJSON }); // ← Windows Hello のダイアログが出る
  await api('/api/register/verify', att);
}

async function refresh() {
  try {
    const me = await api('/api/me');
    $('guest').hidden = true; $('member').hidden = false;
    $('who').textContent = me.username;
    $('credList').innerHTML = me.credentials
      .map((c) => `<li>${c.deviceType}${c.backedUp ? '(同期済み)' : ''} - ${c.createdAt}</li>`).join('');
    window._me = me;
  } catch {
    $('guest').hidden = false; $('member').hidden = true;
  }
}

$('btnRegister').onclick = async () => {
  msg();
  try { await register($('regName').value.trim()); await refresh(); }
  catch (e) { msg(e.name === 'NotAllowedError' ? 'キャンセルされました' : e.message); }
};

$('btnLogin').onclick = async () => {
  msg();
  try {
    const optionsJSON = await api('/api/login/options', { username: $('loginName').value.trim() });
    const asr = await startAuthentication({ optionsJSON });
    await api('/api/login/verify', asr);
    await refresh();
  } catch (e) { msg(e.name === 'NotAllowedError' ? 'キャンセルされました' : e.message); }
};

$('btnAdd').onclick = async () => {
  msg();
  try { await register(window._me.username); await refresh(); }
  catch (e) { msg(e.message); }
};

$('btnLogout').onclick = async () => { await api('/api/logout', {}); await refresh(); };

if (!browserSupportsWebAuthn()) msg('このブラウザは WebAuthn に対応していません');
refresh();
