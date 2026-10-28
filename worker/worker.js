// CLASH PHOTO — сервер рейтинга (Cloudflare Worker)
// Хранит победы игроков по их Telegram-аккаунтам в KV-хранилище.
//
// Настройки Worker'а (Settings):
//   Variables and Secrets → BOT_TOKEN  = токен бота из @BotFather (тип Secret)
//   Bindings → KV namespace → имя переменной LB, пространство "clash-photo"
//
// Маршруты:
//   GET  /top                     → топ-10: [{name, wins, runs}]
//   POST /win  {initData,fullRun} → +1 победа игроку (initData проверяется подписью бота)

const ALLOWED_ORIGINS = ['https://myfemfamily-lang.github.io'];
const KEY = 'leaderboard';

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0],
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Content-Type': 'application/json; charset=utf-8',
    };
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const url = new URL(request.url);
    try {
      if (request.method === 'GET' && url.pathname === '/top') {
        const data = await load(env);
        const rows = Object.values(data)
          .sort((a, b) => b.wins - a.wins || b.runs - a.runs || a.last - b.last)
          .slice(0, 10)
          .map(r => ({ name: r.name, wins: r.wins, runs: r.runs }));
        return new Response(JSON.stringify(rows), { headers: cors });
      }

      if (request.method === 'POST' && url.pathname === '/win') {
        const body = await request.json().catch(() => ({}));
        const user = await verifyInitData(body.initData || '', env.BOT_TOKEN);
        if (!user) return new Response(JSON.stringify({ error: 'bad initData' }), { status: 401, headers: cors });

        const data = await load(env);
        const id = String(user.id);
        const rec = data[id] || { wins: 0, runs: 0, first: Date.now() };
        rec.name = user.username ? '@' + user.username : (user.first_name || 'Игрок');
        rec.wins += 1;
        if (body.fullRun) rec.runs += 1;
        rec.last = Date.now();
        data[id] = rec;
        await env.LB.put(KEY, JSON.stringify(data));
        return new Response(JSON.stringify({ ok: true, wins: rec.wins, runs: rec.runs }), { headers: cors });
      }

      return new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: cors });
    } catch (e) {
      return new Response(JSON.stringify({ error: String(e) }), { status: 500, headers: cors });
    }
  },
};

async function load(env) {
  const raw = await env.LB.get(KEY);
  return raw ? JSON.parse(raw) : {};
}

// Проверка подписи Telegram Mini App:
// secret = HMAC_SHA256(key="WebAppData", msg=BOT_TOKEN)
// hash   = HMAC_SHA256(key=secret, msg=data_check_string)
async function verifyInitData(initData, botToken) {
  if (!initData || !botToken) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');
  const dcs = [...params.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\n');
  const secret = await hmac('WebAppData', botToken, true);
  const calc = await hmac(secret, dcs, false);
  if (calc !== hash) return null;
  const authDate = Number(params.get('auth_date') || 0);
  if (Date.now() / 1000 - authDate > 60 * 60 * 24) return null; // старше суток — не принимаем
  try { return JSON.parse(params.get('user') || 'null'); } catch { return null; }
}

async function hmac(key, msg, rawKey) {
  const enc = new TextEncoder();
  const keyData = rawKey ? enc.encode(key) : key;
  const k = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return rawKey ? sig : [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
