import express from 'express';
import session from 'express-session';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { db, q } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ===== 設定 =====
// 本番では rpID を実ドメイン (例: example.com)、origin を https://example.com に変更
const PORT = process.env.PORT || 3000;
const RP_NAME = 'Passkey Demo';
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const app = express();
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: ORIGIN.startsWith('https://'),
      maxAge: 1000 * 60 * 60 * 8,
    },
  })
);

app.use(express.static(path.join(__dirname, 'public')));
app.use(
  '/vendor/simplewebauthn-browser.js',
  express.static(
    path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')
  )
);

const requireAuth = (req, res, next) =>
  req.session.userId ? next() : res.status(401).json({ error: '未ログインです' });

// ===== 登録 (Passkey 作成: Windows Hello) =====
app.post('/api/register/options', async (req, res) => {
  const username = String(req.body.username || '').trim();
  if (!/^[\w.@-]{3,64}$/.test(username))
    return res.status(400).json({ error: 'ユーザー名は3〜64文字の英数字と . _ @ - が使えます' });

  const existing = q.userByName.get(username);
  let userId;
  let excludeCredentials = [];

  if (existing) {
    // 既存ユーザーへの Passkey 追加は、そのユーザーでログイン済みの場合のみ許可
    if (req.session.userId !== existing.id)
      return res.status(409).json({ error: 'このユーザー名は使用されています' });
    userId = existing.id;
    excludeCredentials = q.credsByUser.all(userId).map((c) => ({
      id: c.id,
      transports: c.transports ? JSON.parse(c.transports) : undefined,
    }));
  } else {
    userId = crypto.randomBytes(32).toString('base64url');
  }

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID: Buffer.from(userId, 'base64url'),
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'required',        // 探索可能な Passkey (ユーザー名入力なしログイン用)
      userVerification: 'required',   // Windows Hello (PIN/顔/指紋) を必須化
    },
  });

  req.session.reg = { challenge: options.challenge, userId, username, isNew: !existing };
  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const reg = req.session.reg;
  if (!reg) return res.status(400).json({ error: '登録セッションがありません' });

  try {
    const v = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: reg.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
    if (!v.verified) return res.status(400).json({ error: '検証に失敗しました' });

    const { credential, credentialDeviceType, credentialBackedUp } = v.registrationInfo;

    db.transaction(() => {
      if (reg.isNew) q.insertUser.run(reg.userId, reg.username);
      q.insertCred.run({
        id: credential.id,
        user_id: reg.userId,
        public_key: Buffer.from(credential.publicKey),
        counter: credential.counter,
        transports: JSON.stringify(credential.transports || []),
        device_type: credentialDeviceType,
        backed_up: credentialBackedUp ? 1 : 0,
      });
    })();

    delete req.session.reg;
    req.session.userId = reg.userId; // 登録後そのままログイン
    res.json({ verified: true });
  } catch (e) {
    console.error(e);
    res.status(400).json({ error: e.message });
  }
});

// ===== ログイン =====
app.post('/api/login/options', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  let allowCredentials; // 未指定 = ブラウザ/OS がパスキー一覧を表示
  if (username) {
    const user = q.userByName.get(username);
    if (user) {
      allowCredentials = q.credsByUser.all(user.id).map((c) => ({
        id: c.id,
        transports: c.transports ? JSON.parse(c.transports) : undefined,
      }));
    }
  }
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials,
  });
  req.session.authChallenge = options.challenge;
  res.json(options);
});

app.post('/api/login/verify', async (req, res) => {
  const challenge = req.session.authChallenge;
  if (!challenge) return res.status(400).json({ error: 'ログインセッションがありません' });

  const cred = q.credById.get(req.body.id);
  if (!cred) return res.status(400).json({ error: '未登録のパスキーです' });

  try {
    const v = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: {
        id: cred.id,
        publicKey: new Uint8Array(cred.public_key),
        counter: cred.counter,
        transports: cred.transports ? JSON.parse(cred.transports) : undefined,
      },
    });
    if (!v.verified) return res.status(401).json({ error: '認証に失敗しました' });

    q.updateCounter.run(v.authenticationInfo.newCounter, cred.id);
    delete req.session.authChallenge;

    // セッション固定化攻撃対策: セッションID再生成
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'セッションエラー' });
      req.session.userId = cred.user_id;
      res.json({ verified: true });
    });
  } catch (e) {
    console.error(e);
    res.status(401).json({ error: e.message });
  }
});

// ===== ログイン後 API =====
app.get('/api/me', requireAuth, (req, res) => {
  const user = q.userById.get(req.session.userId);
  const creds = q.credsByUser.all(user.id).map((c) => ({
    id: c.id, deviceType: c.device_type, backedUp: !!c.backed_up, createdAt: c.created_at,
  }));
  res.json({ username: user.username, credentials: creds });
});

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.listen(PORT, () => console.log(`http://localhost:${PORT}  (RP_ID=${RP_ID})`));
