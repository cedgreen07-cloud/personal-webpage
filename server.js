require('dotenv').config();
const express = require('express');
const axios   = require('axios');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { Redis } = require('@upstash/redis');

const app  = express();
const PORT = process.env.PORT || 3000;

const TOKEN_KEY   = 'whoop_tokens';
const WHOOP_AUTH  = 'https://api.prod.whoop.com/oauth/oauth2/auth';
const WHOOP_TOKEN = 'https://api.prod.whoop.com/oauth/oauth2/token';
const WHOOP_API   = 'https://api.prod.whoop.com/developer/v2';
const BASE_URL    = process.env.BASE_URL || `http://localhost:${PORT}`;
const REDIRECT    = `${BASE_URL}/auth/whoop/callback`;
const SCOPES      = 'read:recovery read:sleep read:workout read:profile read:cycles read:body_measurement offline';

const FATSECRET_TOKEN_URL = 'https://oauth.fatsecret.com/connect/token';
const FATSECRET_API_URL   = 'https://platform.fatsecret.com/rest/server.api';

const redis = (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN)
  ? new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN })
  : null;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Token helpers ────────────────────────────────────────────────────────────
// Uses Upstash Redis when configured (persists across Render restarts/redeploys);
// falls back to a local JSON file per service for local development.
function tokenFile(key) { return path.join(__dirname, `${key}.json`); }

async function loadTokens(key) {
  if (redis) return await redis.get(key);
  try { return JSON.parse(fs.readFileSync(tokenFile(key), 'utf8')); }
  catch { return null; }
}

async function saveTokens(key, t) {
  if (redis) { await redis.set(key, t); return; }
  fs.writeFileSync(tokenFile(key), JSON.stringify(t, null, 2));
}

async function clearTokens(key) {
  if (redis) { await redis.del(key); return; }
  try { fs.unlinkSync(tokenFile(key)); } catch {}
}

async function getValidToken() {
  const t = await loadTokens(TOKEN_KEY);
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
      await saveTokens(TOKEN_KEY, fresh);
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

// FatSecret uses a simple app-level OAuth 2.0 client-credentials token (no user login)
// for food database access. Cached in memory and refreshed when expired.
let fatsecretToken = null;

async function getFatsecretToken() {
  if (fatsecretToken && Date.now() < fatsecretToken.expires_at - 60_000) {
    return fatsecretToken.access_token;
  }
  const basic = Buffer.from(`${process.env.FATSECRET_CLIENT_ID}:${process.env.FATSECRET_CLIENT_SECRET}`).toString('base64');
  const res = await axios.post(FATSECRET_TOKEN_URL, new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'basic',
  }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` } });
  fatsecretToken = { access_token: res.data.access_token, expires_at: Date.now() + res.data.expires_in * 1000 };
  return fatsecretToken.access_token;
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
    await saveTokens(TOKEN_KEY, { ...r.data, expires_at: Date.now() + r.data.expires_in * 1000 });
    res.redirect('/?whoop_connected=1');
  } catch (e) {
    console.error('OAuth exchange failed:', e.response?.data || e.message);
    res.redirect('/?whoop_error=exchange_failed');
  }
});

app.post('/auth/whoop/disconnect', async (req, res) => {
  await clearTokens(TOKEN_KEY);
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

// ─── FatSecret food search/autofill ──────────────────────────────────────────
app.get('/api/fatsecret/search', async (req, res) => {
  const query = (req.query.q || '').trim();
  if (!query) return res.json({ foods: [] });
  try {
    const token = await getFatsecretToken();
    const r = await axios.get(FATSECRET_API_URL, {
      params: {
        method: 'foods.search',
        search_expression: query,
        format: 'json',
        max_results: 10,
      },
      headers: { Authorization: `Bearer ${token}` },
    });
    const foods = r.data?.foods?.food || [];
    res.json({ foods: Array.isArray(foods) ? foods : [foods] });
  } catch (e) {
    console.error('FatSecret search failed:', e.response?.data || e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/fatsecret/food/:id', async (req, res) => {
  try {
    const token = await getFatsecretToken();
    const r = await axios.get(FATSECRET_API_URL, {
      params: { method: 'food.get.v2', food_id: req.params.id, format: 'json' },
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json(r.data?.food || {});
  } catch (e) {
    console.error('FatSecret food lookup failed:', e.response?.data || e.message);
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
  console.log(`   FatSecret setup:`);
  console.log(`   1. Add your FatSecret Client ID + Secret from https://platform.fatsecret.com\n`);
});
