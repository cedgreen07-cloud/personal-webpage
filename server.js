require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

const TOKEN_FILE  = path.join(__dirname, 'tokens.json');
const WHOOP_AUTH  = 'https://api.prod.whoop.com/oauth/oauth2/auth';
const WHOOP_TOKEN = 'https://api.prod.whoop.com/oauth/oauth2/token';
const WHOOP_API   = 'https://api.prod.whoop.com/developer/v2';
const BASE_URL    = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT    = `${BASE_URL}/auth/whoop/callback`;
const SCOPES      = 'read:recovery read:sleep read:workout read:profile read:cycles read:body_measurement offline';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Token helpers ────────────────────────────────────────────────────────────
function loadTokens() {
  try { return JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')); }
  catch { return null; }
}

function saveTokens(t) {
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(t, null, 2));
}

async function getValidToken() {
  const t = loadTokens();
  if (!t) return null;
  // Refresh if expiring within 5 minutes
  if (t.expires_at && Date.now() > t.expires_at - 300_000) {
    try {
      const res = await axios.post(WHOOP_TOKEN, new URLSearchParams({
        grant_type:    'refresh_token',
        refresh_token: t.refresh_token,
        client_id:     process.env.WHOOP_CLIENT_ID,
        client_secret: process.env.WHOOP_CLIENT_SECRET,
      }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
      const fresh = { ...res.data, expires_at: Date.now() + res.data.expires_in * 1000 };
      saveTokens(fresh);
      return fresh.access_token;
    } catch (e) {
      console.error('Token refresh failed:', e.response?.data || e.message);
      return null;
    }
  }
  return t.access_token;
}

async function whoopGet(path) {
  const token = await getValidToken();
  if (!token) throw new Error('Not authenticated');
  const res = await axios.get(`${WHOOP_API}${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return res.data;
}

// ─── OAuth routes ─────────────────────────────────────────────────────────────
app.get('/auth/whoop', (req, res) => {
  if (!process.env.WHOOP_CLIENT_ID) {
    return res.status(500).send('WHOOP_CLIENT_ID not set in .env');
  }
  const state = crypto.randomBytes(16).toString('hex');
  const url = `${WHOOP_AUTH}?client_id=${process.env.WHOOP_CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&scope=${encodeURIComponent(SCOPES)}&state=${state}`;
  res.redirect(url);
});

app.get('/auth/whoop/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect('/?whoop_error=' + encodeURIComponent(error));
  if (!code)  return res.redirect('/?whoop_error=no_code');
  try {
    const r = await axios.post(WHOOP_TOKEN, new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      redirect_uri:  REDIRECT,
      client_id:     process.env.WHOOP_CLIENT_ID,
      client_secret: process.env.WHOOP_CLIENT_SECRET,
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    saveTokens({ ...r.data, expires_at: Date.now() + r.data.expires_in * 1000 });
    res.redirect('/?whoop_connected=1');
  } catch (e) {
    console.error('OAuth exchange failed:', e.response?.data || e.message);
    res.redirect('/?whoop_error=exchange_failed');
  }
});

app.post('/auth/whoop/disconnect', (req, res) => {
  try { fs.unlinkSync(TOKEN_FILE); } catch {}
  res.json({ ok: true });
});

// ─── Whoop API proxies ────────────────────────────────────────────────────────
app.get('/api/whoop/status', async (req, res) => {
  const token = await getValidToken();
  if (!token) return res.json({ connected: false });
  try {
    const profile = await whoopGet('/user/profile/basic');
    res.json({ connected: true, name: `${profile.first_name} ${profile.last_name}`, email: profile.email });
  } catch {
    res.json({ connected: false });
  }
});

app.get('/api/whoop/recovery', async (req, res) => {
  try {
    // Last 7 days
    const start = new Date(Date.now() - 7 * 86400_000).toISOString();
    const data = await whoopGet(`/recovery?start=${start}&limit=7`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/whoop/sleep', async (req, res) => {
  try {
    const start = new Date(Date.now() - 7 * 86400_000).toISOString();
    const data = await whoopGet(`/activity/sleep?start=${start}&limit=7`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/whoop/workouts', async (req, res) => {
  try {
    const start = new Date(Date.now() - 7 * 86400_000).toISOString();
    const data = await whoopGet(`/activity/workout?start=${start}&limit=20`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/whoop/cycles', async (req, res) => {
  try {
    const start = new Date(Date.now() - 7 * 86400_000).toISOString();
    const data = await whoopGet(`/cycle?start=${start}&limit=7`);
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Live market quotes ───────────────────────────────────────────────────────
app.get('/api/quote', async (req, res) => {
  const symbols = (req.query.symbols || '').split(',').map(s => s.trim()).filter(Boolean);
  const out = {};
  await Promise.all(symbols.map(async sym => {
    try {
      const r = await axios.get(`https://query1.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(sym)}`, {
        headers: { 'User-Agent': 'Mozilla/5.0' }
      });
      const price = r.data?.chart?.result?.[0]?.meta?.regularMarketPrice;
      if (typeof price === 'number') out[sym] = price;
    } catch (e) {
      console.error(`Quote fetch failed for ${sym}:`, e.message);
    }
  }));
  res.json(out);
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✅  Tracker running at ${BASE_URL}`);
  console.log(`\n   Whoop setup:`);
  console.log(`   1. Copy .env.example → .env`);
  console.log(`   2. Add your Whoop Client ID + Secret from https://developer.whoop.com`);
  console.log(`   3. Set Redirect URI to: ${REDIRECT}\n`);
});
